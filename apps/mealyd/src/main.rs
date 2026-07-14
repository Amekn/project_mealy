//! Mealy's trusted daemon composition root.

mod agent;
mod anthropic_provider;
mod backend;
mod config;
mod effect_runtime;
#[path = "../../../crates/mealy-infrastructure/src/bin/mealy-fixture-worker.rs"]
mod fixture_worker_process;
mod responses_provider;

use agent::{
    AgentDriverPolicy, RuntimeModelProvider, RuntimeReadTools, RuntimeSkillContext,
    drive_one_agent_run, phase_two_read_tool,
};
use backend::{
    DrainController, RuntimeBackend, RuntimeChannelConfig, RuntimeDiscordConfig,
    RuntimeOperationalConfig, RuntimeTelegramConfig,
};
use clap::Parser;
use config::{
    ProviderConfig, acquire_instance_lock, archive_effective_daemon_config,
    load_forced_shutdown_marker, load_or_create_daemon_config, load_or_create_identity,
    remove_forced_shutdown_marker, write_connection_info, write_forced_shutdown_marker,
};
use effect_runtime::{PhaseThreeRuntime, ProcessCommandBinding};
use mealy_api::{ApiAuth, ApiConfig, AuthenticatedIdentity, router_with_shutdown};
use mealy_application::{
    AdmitInputCommand, BeginDaemonRunCommit, ClaimScheduleRunCommit, CompleteDaemonRunCommit,
    CompleteDiscordMessageCommit, CompleteScheduleRunCommit, CompleteTelegramUpdateCommit,
    DaemonRunStatus, DiscordChannelStore, DiscordChannelStoreError, DiscordMessageDisposition,
    DiscordMessageReservation, DiscordPollTarget, EffectLedgerStore, EffectLedgerStoreError,
    IdGenerator, InitialTaskProfile, InputAdmissionLimits, OperationalStore, OutboundDiscordTarget,
    OutboundTelegramTarget, OutboundWebhookTarget, OutboxClaimOutcome, OutboxDelivery,
    OutboxUseCaseError, OwnershipContext, PromotionDefaults, ProviderCredentialReference,
    RecordDiscordPollCommit, RecordTelegramPollCommit, ReserveDiscordMessageCommit,
    ReserveTelegramUpdateCommit, ResolveApprovalCommit, ScheduleClaimOutcome, ScheduleDueDecision,
    ScheduleOverlapPolicy, ScheduleRunIntent, ScheduleRunStatus, ScheduleStore, SessionStoreError,
    SessionUseCaseError, TelegramChannelStore, TelegramChannelStoreError, TelegramPollTarget,
    TelegramUpdateDisposition, TelegramUpdateReservation, WebhookChannelStore,
    WebhookChannelStoreError, admit_input, canonical_arguments_digest, claim_next_outbox,
    complete_outbox, discord_input_dedupe_key, exponential_retry_delay, is_sha256_digest,
    pending_promotion_sessions, plan_due_schedule, promote_next_input, recover_expired_leases,
    recover_extension_invocations, recover_startup, retry_outbox, sha256_digest, sign_webhook,
    telegram_input_dedupe_key, validate_discord_snowflake,
};
use mealy_domain::{
    ApprovalDecision, ApprovalId, CapabilityGrant, CorrelationId, DeliveryMode, EffectClass,
    PolicyProfile, ScheduleRunId, WorkerId,
};
use mealy_infrastructure::{
    BrowserReadTool, FileArtifactBlobStore, FileChannelSecretStore, FileProviderSecretStore,
    LATEST_SCHEMA_VERSION, ProviderSecretStoreError, SqliteStore, StoreError, SystemClock,
    SystemIdGenerator, WebReadTool, WorkspaceGrant, WorkspaceReadTool, browser_worker_main,
    create_pre_migration_backup, inspect_existing_schema_version, load_mcp_read_tools,
    mcp_stdio_launcher_main, preserve_forensic_database,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use thiserror::Error as ThisError;
use tokio::sync::watch;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(version, about = "Reliable local-first Mealy agent daemon")]
struct Arguments {
    /// Private state directory containing `SQLite` and the local connection descriptor.
    #[arg(long, env = "MEALY_HOME", default_value = ".mealy")]
    home: PathBuf,
    /// Loopback listener address; port zero chooses an available port.
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: SocketAddr,
    /// Start query-only: reject mutation and do not run dispatch/promotion workers.
    #[arg(long)]
    safe_mode: bool,
    /// Override the validated configuration's bounded graceful-drain deadline.
    #[arg(long)]
    drain_deadline_ms: Option<u64>,
    /// Testable delay before the first durable inbox promotion scan.
    #[arg(long, default_value_t = 0)]
    promotion_delay_ms: u64,
    /// Interval between durable promotion scans.
    #[arg(long, default_value_t = 100)]
    promotion_interval_ms: u64,
    /// Testable delay before the first durable outbox delivery scan.
    #[arg(long, default_value_t = 0)]
    outbox_delay_ms: u64,
    /// Test-only signed offset applied to the recurring-schedule driver clock.
    #[arg(long, default_value_t = 0, hide = true)]
    schedule_clock_offset_ms: i64,
    /// Telegram Bot API origin; HTTPS or literal-loopback HTTP for a local/test Bot API server.
    #[arg(long, default_value = "https://api.telegram.org")]
    telegram_api_base_url: String,
    /// Discord REST API v10 base; exact official endpoint or literal-loopback HTTP for tests.
    #[arg(long, default_value = "https://discord.com/api/v10")]
    discord_api_base_url: String,
    /// Delay before the first provider/read-tool worker claim.
    #[arg(long, default_value_t = 250)]
    agent_delay_ms: u64,
    /// Test-only delay inside each deterministic fake-provider call.
    #[arg(long, default_value_t = 0)]
    fake_provider_delay_ms: u64,
    /// Test-only pause after each committed agent-loop boundary.
    #[arg(long, default_value_t = 0)]
    agent_boundary_delay_ms: u64,
    /// Test-only pause after the sandbox returns and before effect outcome evidence commits.
    #[arg(long, default_value_t = 0, hide = true)]
    effect_outcome_delay_ms: u64,
    /// Test-only pause after effect preparation and before the dispatch boundary.
    #[arg(long, default_value_t = 0, hide = true)]
    effect_dispatch_delay_ms: u64,
    /// Test-only pause after effect outcome commit and before model observation.
    #[arg(long, default_value_t = 0, hide = true)]
    effect_observation_delay_ms: u64,
    /// Test-only lifetime of a fixture-write approval request.
    #[arg(long, default_value_t = 300_000, hide = true)]
    effect_approval_ttl_ms: u64,
    /// Print the maximum state-schema version understood by this binary and exit.
    #[arg(long, hide = true)]
    print_supported_schema_version: bool,
}

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    if std::env::args().nth(1).as_deref() == Some("--browser-worker") {
        let code = browser_worker_main();
        if code == ExitCode::SUCCESS {
            return Ok(());
        }
        std::process::exit(70);
    }
    if std::env::args().nth(1).as_deref() == Some("--mcp-stdio-launcher") {
        let _code = mcp_stdio_launcher_main();
        std::process::exit(70);
    }
    if std::env::args().nth(1).as_deref() == Some("--bootstrap-empty-environment") {
        let _code = fixture_worker_process::main();
        std::process::exit(71);
    }
    if std::env::args().nth(1).as_deref() == Some("--protocol-worker") {
        let code = fixture_worker_process::main();
        if code == ExitCode::SUCCESS {
            return Ok(());
        }
        std::process::exit(64);
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run_daemon())
}

#[allow(clippy::too_many_lines)]
async fn run_daemon() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init()?;
    let arguments = Arguments::parse();
    if arguments.print_supported_schema_version {
        println!("{LATEST_SCHEMA_VERSION}");
        return Ok(());
    }
    backend::validate_telegram_api_base_url(&arguments.telegram_api_base_url)?;
    backend::validate_discord_api_base_url(&arguments.discord_api_base_url)?;
    let _instance_lock = acquire_instance_lock(&arguments.home)?;
    let started_at = SystemTime::now();
    let mut daemon_config = load_or_create_daemon_config(&arguments.home)?;
    daemon_config.set_drain_deadline_override(arguments.drain_deadline_ms)?;
    let config_digest = daemon_config.digest()?;
    let config_history_path =
        archive_effective_daemon_config(&arguments.home, &daemon_config, &config_digest)?;
    tracing::info!(
        config_history_path = %config_history_path.display(),
        %config_digest,
        "effective configuration archived for rollback"
    );
    let drain_deadline = Duration::from_millis(daemon_config.drain_deadline_ms());
    let api_config = ApiConfig::new(
        arguments.bind,
        1024 * 1024,
        Vec::new(),
        32,
        16,
        Duration::from_millis(200),
    )?;
    let identity = load_or_create_identity(&arguments.home)?;
    let now_ms = epoch_milliseconds(SystemTime::now())?;
    let database_path = arguments.home.join("mealy.sqlite3");
    let supported_schema_version =
        u64::try_from(LATEST_SCHEMA_VERSION).map_err(|_| "supported schema version is invalid")?;
    match inspect_existing_schema_version(&database_path) {
        Ok(Some(version)) if version != 0 && version < supported_schema_version => {
            let report = create_pre_migration_backup(
                &arguments.home,
                &database_path,
                version,
                supported_schema_version,
                SystemTime::now(),
            )?;
            tracing::warn!(
                from_schema_version = report.from_schema_version,
                to_schema_version = report.to_schema_version,
                migration_backup_path = %report.path.display(),
                manifest_digest = %report.manifest_digest,
                "pre-migration rollback snapshot published"
            );
        }
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(
                %error,
                "read-only schema inspection failed; normal open will preserve corrupt evidence"
            );
        }
    }
    let mut store = match SqliteStore::open(&database_path, now_ms) {
        Ok(store) => store,
        Err(error) => {
            if daemon_config.forensic_backup_on_open_failure()
                && database_path.exists()
                && matches!(
                    &error,
                    StoreError::Sqlite(_) | StoreError::InvalidSchemaVersion(_)
                )
            {
                tracing::error!(%error, "canonical database open failed; preserving forensic evidence");
                let report = preserve_forensic_database(
                    &arguments.home,
                    &database_path,
                    &error.to_string(),
                    SystemTime::now(),
                )?;
                tracing::error!(
                    forensic_path = %report.path.display(),
                    forensic_files = report.file_count,
                    forensic_bytes = report.total_bytes,
                    manifest_digest = %report.manifest_digest,
                    "corrupt database and sidecars preserved without replacement"
                );
            }
            return Err(error.into());
        }
    };
    store.register_local_identity(
        OwnershipContext::new(identity.principal_id, identity.channel_binding_id),
        now_ms,
    )?;
    if let Some(marker) = load_forced_shutdown_marker(&arguments.home)? {
        let ownership = OwnershipContext::new(identity.principal_id, identity.channel_binding_id);
        match store.complete_daemon_run(CompleteDaemonRunCommit {
            start_id: marker.start_id,
            status: DaemonRunStatus::Forced,
            reason: marker.reason.clone(),
            completed_at: marker.completed_at,
        }) {
            Ok(()) => {}
            Err(mealy_application::OperationalStoreError::Conflict) => {
                let snapshot = store.operational_snapshot(ownership)?;
                if snapshot.start_id != marker.start_id
                    || snapshot.run_status != DaemonRunStatus::Forced
                {
                    return Err("forced-shutdown marker conflicts with daemon history".into());
                }
            }
            Err(error) => return Err(error.into()),
        }
        store.checkpoint_for_shutdown()?;
        remove_forced_shutdown_marker(&arguments.home)?;
        tracing::warn!(
            start_id = %marker.start_id,
            reason = %marker.reason,
            "reconciled durable forced-shutdown evidence"
        );
    }
    let recovery = recover_startup(&mut store, &SystemClock, &SystemIdGenerator, 256)?;
    let abandoned_extension_invocations =
        recover_extension_invocations(&mut store, &SystemClock, &SystemIdGenerator, 256)?;
    let start_id = SystemIdGenerator.generate_correlation_id();
    let policy_bundle_digest = sha256_digest(
        b"mealy.release1.policy.bundle:fixture.v1:memory.v1:extension.v1:validation.v1",
    );
    store.begin_daemon_run(BeginDaemonRunCommit {
        start_id,
        principal_id: identity.principal_id,
        config_digest: config_digest.clone(),
        policy_bundle_digest: policy_bundle_digest.clone(),
        safe_mode: arguments.safe_mode,
        recovery_counts: BTreeMap::from([
            ("expired_leases".to_owned(), recovery.expired_leases),
            ("requeued_runs".to_owned(), recovery.requeued_runs),
            ("waiting_runs".to_owned(), recovery.waiting_runs),
            ("pending_outbox".to_owned(), recovery.pending_outbox),
            (
                "abandoned_extension_invocations".to_owned(),
                abandoned_extension_invocations,
            ),
        ]),
        started_at,
        ready_at: SystemTime::now(),
    })?;
    tracing::info!(
        expired_leases = recovery.expired_leases,
        requeued_runs = recovery.requeued_runs,
        waiting_runs = recovery.waiting_runs,
        pending_outbox = recovery.pending_outbox,
        abandoned_extension_invocations,
        start_id = %start_id,
        %config_digest,
        %policy_bundle_digest,
        safe_mode = arguments.safe_mode,
        "startup recovery complete"
    );

    let artifacts = Arc::new(FileArtifactBlobStore::new(
        arguments.home.join("artifacts"),
        4 * 1024 * 1024,
    )?);
    if !arguments.safe_mode {
        let referenced_digests = store.referenced_artifact_digests()?;
        let minimum_age = Duration::from_secs(
            daemon_config
                .artifact_gc_minimum_age_hours()
                .checked_mul(60 * 60)
                .ok_or("artifact GC age overflowed")?,
        );
        let collection =
            artifacts.garbage_collect(&referenced_digests, minimum_age, SystemTime::now())?;
        tracing::info!(
            removed_blobs = collection.removed_blob_count,
            removed_blob_bytes = collection.removed_blob_bytes,
            removed_temporary_files = collection.removed_temporary_file_count,
            retained_young_files = collection.retained_young_file_count,
            retained_referenced_blobs = collection.retained_referenced_blob_count,
            "artifact retention pass completed"
        );
    }
    let channel_secrets = Arc::new(FileChannelSecretStore::new(
        arguments.home.join("channel-secrets"),
    )?);
    let webhook_client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .build()?;
    let telegram_client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .build()?;
    let discord_client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .build()?;
    let discord_rate_limits = Arc::new(DiscordRateLimitGate::new());
    let safe_mode_provider = ProviderConfig::BuiltinFixture;
    let effective_provider_config = if arguments.safe_mode {
        if !daemon_config.provider().is_builtin_fixture() {
            tracing::warn!(
                "safe mode does not resolve or initialize the configured external provider"
            );
        }
        &safe_mode_provider
    } else {
        daemon_config.provider()
    };
    let provider_config = effective_provider_config.clone();
    let provider_fallbacks = if arguments.safe_mode {
        Vec::new()
    } else {
        daemon_config.provider_fallbacks().to_vec()
    };
    let provider_secret_store = (!arguments.safe_mode)
        .then(|| FileProviderSecretStore::new(arguments.home.join("provider-secrets")))
        .transpose()?;
    let fake_provider_delay = Duration::from_millis(arguments.fake_provider_delay_ms);
    let maximum_provider_requests = daemon_config.maximum_provider_requests();
    let provider_requests_per_minute = daemon_config.provider_requests_per_minute();
    let provider = Arc::new(
        tokio::task::spawn_blocking(move || {
            if provider_fallbacks.is_empty() {
                RuntimeModelProvider::from_config(
                    &provider_config,
                    provider_secret_store.as_ref(),
                    fake_provider_delay,
                    maximum_provider_requests,
                    provider_requests_per_minute,
                )
            } else {
                RuntimeModelProvider::from_chain(
                    &provider_config,
                    &provider_fallbacks,
                    provider_secret_store.as_ref(),
                    fake_provider_delay,
                    maximum_provider_requests,
                    provider_requests_per_minute,
                )
            }
        })
        .await
        .map_err(|_| "provider initialization worker failed")??,
    );
    let workspace_tools = if arguments.safe_mode || daemon_config.workspace_roots().is_empty() {
        Vec::new()
    } else {
        let grants = daemon_config
            .workspace_roots()
            .iter()
            .map(|workspace| WorkspaceGrant {
                workspace_id: workspace.workspace_id().to_owned(),
                root: workspace.root().to_path_buf(),
            })
            .collect::<Vec<_>>();
        let tools = WorkspaceReadTool::suite(grants)?;
        tracing::info!(
            workspace_count = daemon_config.workspace_roots().len(),
            "read-only workspace tools enabled"
        );
        tools
    };
    let web_tools = if arguments.safe_mode
        || daemon_config.provider().is_builtin_fixture()
        || !daemon_config.web_access().enabled
    {
        Vec::new()
    } else {
        let credential = daemon_config
            .web_access()
            .search
            .as_ref()
            .map(|search| match search.credential() {
                ProviderCredentialReference::Broker { secret_id } => {
                    FileProviderSecretStore::new(arguments.home.join("provider-secrets"))?
                        .read(secret_id)
                        .map_err(Box::<dyn Error + Send + Sync>::from)
                }
                ProviderCredentialReference::Environment { variable } => {
                    std::env::var(variable).map(Zeroizing::new).map_err(|_| {
                        "web search credential environment variable is unavailable".into()
                    })
                }
            })
            .transpose()?;
        let tools = WebReadTool::suite(daemon_config.web_access().clone(), credential)?;
        tracing::info!(
            web_tool_count = tools.len(),
            "bounded web read tools enabled"
        );
        tools
    };
    let skill_context = RuntimeSkillContext::load(&arguments.home, daemon_config.skills())?;
    if skill_context.enabled_count() != 0 {
        tracing::info!(
            enabled_skill_count = skill_context.enabled_count(),
            "data-only skill instructions enabled"
        );
    }
    let mcp_tools = if arguments.safe_mode || daemon_config.mcp_servers().is_empty() {
        Vec::new()
    } else {
        let launcher = fs::canonicalize(std::env::current_exe()?)?;
        let tools = load_mcp_read_tools(
            &arguments.home,
            Path::new("/usr/bin/bwrap"),
            &launcher,
            daemon_config.mcp_servers(),
        )?;
        tracing::info!(
            mcp_server_count = daemon_config
                .mcp_servers()
                .iter()
                .filter(|server| server.enabled())
                .count(),
            mcp_tool_count = tools.len(),
            "schema-pinned isolated MCP tools enabled"
        );
        tools
    };
    let browser_tool = if arguments.safe_mode
        || daemon_config.provider().is_builtin_fixture()
        || daemon_config
            .browser()
            .is_none_or(|browser| !browser.enabled())
    {
        None
    } else {
        let launcher = fs::canonicalize(std::env::current_exe()?)?;
        let tool = BrowserReadTool::load(
            &arguments.home,
            Path::new("/usr/bin/bwrap"),
            &launcher,
            daemon_config
                .browser()
                .ok_or("browser configuration disappeared")?
                .clone(),
            daemon_config.web_access().clone(),
        )?;
        tracing::info!(
            product = daemon_config
                .browser()
                .map(mealy_application::BrowserConfig::product)
                .unwrap_or_default(),
            "isolated rendered-browser read tool enabled"
        );
        Some(tool)
    };
    let read_tool = Arc::new(RuntimeReadTools::new(
        phase_two_read_tool()?,
        workspace_tools,
        web_tools,
        mcp_tools,
        browser_tool,
        skill_context,
    )?);
    let effect_runtime = if arguments.safe_mode {
        tracing::warn!("safe mode enabled; mutation and background dispatch are disabled");
        None
    } else if provider.is_builtin_fixture() {
        match PhaseThreeRuntime::discover(
            &arguments.home,
            Duration::from_millis(arguments.effect_outcome_delay_ms),
            Duration::from_millis(arguments.effect_dispatch_delay_ms),
            Duration::from_millis(arguments.effect_observation_delay_ms),
            Duration::from_millis(arguments.effect_approval_ttl_ms.max(1)),
        ) {
            Ok(runtime) => {
                tracing::info!(
                    workspace = runtime.workspace_root(),
                    "sandboxed fixture-write runtime available"
                );
                Some(Arc::new(runtime))
            }
            Err(error) => {
                tracing::warn!(%error, "sandboxed fixture-write runtime unavailable; mutating tool omitted");
                None
            }
        }
    } else {
        let writable_workspaces = daemon_config
            .workspace_roots()
            .iter()
            .filter(|workspace| workspace.writable())
            .map(|workspace| {
                (
                    workspace.workspace_id().to_owned(),
                    workspace.root().to_path_buf(),
                )
            })
            .collect::<Vec<_>>();
        if writable_workspaces.is_empty() {
            match PhaseThreeRuntime::discover(
                &arguments.home,
                Duration::from_millis(arguments.effect_outcome_delay_ms),
                Duration::from_millis(arguments.effect_dispatch_delay_ms),
                Duration::from_millis(arguments.effect_observation_delay_ms),
                Duration::from_millis(arguments.effect_approval_ttl_ms.max(1)),
            ) {
                Ok(runtime) => {
                    tracing::info!(
                        "sandbox process boundary available; no production mutation authority configured"
                    );
                    Some(Arc::new(runtime))
                }
                Err(error) => {
                    tracing::warn!(%error, "sandbox process boundary unavailable; sandboxed capabilities omitted");
                    None
                }
            }
        } else {
            match PhaseThreeRuntime::discover_workspace(
                writable_workspaces,
                daemon_config
                    .command_tools()
                    .iter()
                    .map(|command| ProcessCommandBinding {
                        command_id: command.command_id().to_owned(),
                        executable: command.executable().to_path_buf(),
                        executable_digest: command.executable_digest().to_owned(),
                    })
                    .collect::<Vec<_>>(),
                Duration::from_millis(arguments.effect_outcome_delay_ms),
                Duration::from_millis(arguments.effect_dispatch_delay_ms),
                Duration::from_millis(arguments.effect_observation_delay_ms),
                Duration::from_millis(arguments.effect_approval_ttl_ms.max(1)),
            ) {
                Ok(runtime) => {
                    tracing::info!(
                        workspace_count = runtime.workspace_ids().len(),
                        "approval-gated workspace mutation runtime available"
                    );
                    Some(Arc::new(runtime))
                }
                Err(error) => {
                    tracing::warn!(%error, "workspace mutation runtime unavailable; mutating tools omitted");
                    None
                }
            }
        }
    };
    let store = Arc::new(Mutex::new(store));
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let drain_controller = Arc::new(DrainController::new(
        shutdown_sender.clone(),
        start_id,
        daemon_config.drain_deadline_ms(),
    ));
    let sandbox_available = effect_runtime.is_some();
    let enabled_read_tools = if arguments.safe_mode {
        Vec::new()
    } else {
        read_tool
            .descriptors(provider.is_builtin_fixture())
            .into_iter()
            .map(|descriptor| descriptor.tool_id)
            .collect()
    };
    let enabled_action_tools = effect_runtime
        .as_deref()
        .filter(|runtime| !arguments.safe_mode && !runtime.is_fixture())
        .map(|runtime| {
            runtime
                .descriptors()
                .into_iter()
                .map(|descriptor| descriptor.tool_id.clone())
                .collect()
        })
        .unwrap_or_default();
    let telegram_credentials = (!arguments.safe_mode)
        .then(|| {
            FileProviderSecretStore::new(arguments.home.join("provider-secrets")).map(Arc::new)
        })
        .transpose()?;
    let discord_credentials = (!arguments.safe_mode)
        .then(|| {
            FileProviderSecretStore::new(arguments.home.join("provider-secrets")).map(Arc::new)
        })
        .transpose()?;
    let backend = Arc::new(RuntimeBackend::new(
        Arc::clone(&store),
        Arc::clone(&artifacts),
        Arc::clone(&channel_secrets),
        RuntimeChannelConfig {
            telegram: RuntimeTelegramConfig {
                credentials: telegram_credentials.clone(),
                api_base_url: arguments.telegram_api_base_url.clone(),
            },
            discord: RuntimeDiscordConfig {
                credentials: discord_credentials.clone(),
                api_base_url: arguments.discord_api_base_url.clone(),
            },
        },
        Arc::clone(&provider),
        RuntimeOperationalConfig {
            home: arguments.home.clone(),
            artifact_gc_minimum_age_hours: daemon_config.artifact_gc_minimum_age_hours(),
            maximum_pending_inputs_per_session: daemon_config.maximum_pending_inputs_per_session(),
            maximum_extension_invocations: daemon_config.maximum_extension_invocations(),
            enabled_read_tools,
            enabled_action_tools,
            sandbox_available,
            safe_mode: arguments.safe_mode,
        },
        drain_controller,
    ));
    let auth = ApiAuth::new(
        identity.token,
        AuthenticatedIdentity {
            principal_id: identity.principal_id.to_string(),
            channel_binding_id: identity.channel_binding_id.to_string(),
        },
    );
    let listener = tokio::net::TcpListener::bind(api_config.bind()).await?;
    let address = listener.local_addr()?;
    let base_url = format!("http://{address}");
    let connection_path = write_connection_info(&arguments.home, base_url.clone(), &identity)?;
    let app = router_with_shutdown(&api_config, auth, backend, shutdown_receiver.clone());
    let initial_task_profile = if daemon_config.provider().is_builtin_fixture() {
        InitialTaskProfile::FixtureProof
    } else {
        InitialTaskProfile::GeneralAssistant
    };
    let mut promotion_defaults =
        PromotionDefaults::new("assistant", daemon_config.agent_loop_limits())?
            .with_initial_task_profile(initial_task_profile);
    if initial_task_profile == InitialTaskProfile::GeneralAssistant {
        let mut tool_ids = read_tool
            .descriptors(false)
            .into_iter()
            .map(|descriptor| descriptor.tool_id)
            .collect::<BTreeSet<_>>();
        let write_runtime = effect_runtime
            .as_deref()
            .filter(|runtime| !runtime.is_fixture());
        if let Some(runtime) = write_runtime {
            tool_ids.extend(
                runtime
                    .descriptors()
                    .into_iter()
                    .map(|descriptor| descriptor.tool_id.clone()),
            );
        }
        let has_read_tools = tool_ids.iter().any(|tool_id| {
            if tool_id.starts_with("mcp.") {
                return true;
            }
            matches!(
                tool_id.as_str(),
                "workspace.list"
                    | "workspace.stat"
                    | "workspace.read"
                    | "workspace.search"
                    | mealy_application::AGENT_DELEGATE_TOOL_ID
                    | "skill.read_resource"
                    | "web.fetch"
                    | "web.search"
                    | mealy_application::BROWSER_SNAPSHOT_TOOL_ID
            )
        });
        let has_write_tool = tool_ids.contains(mealy_application::WORKSPACE_CREATE_FILE_TOOL_ID)
            || tool_ids.contains(mealy_application::WORKSPACE_REPLACE_FILE_TOOL_ID);
        let has_manage_tool = tool_ids.contains(mealy_application::WORKSPACE_MANAGE_PATH_TOOL_ID);
        let has_process_tool = tool_ids.contains(mealy_application::PROCESS_RUN_TOOL_ID);
        let mut effect_classes = BTreeSet::new();
        let mut profiles = BTreeSet::new();
        if has_read_tools {
            effect_classes.insert(EffectClass::ReadOnly);
            profiles.insert(PolicyProfile::Observe);
        }
        if has_write_tool {
            effect_classes.insert(EffectClass::Idempotent);
            profiles.insert(PolicyProfile::WorkspaceWrite);
        }
        if has_manage_tool || has_process_tool {
            effect_classes.insert(EffectClass::NonIdempotent);
            profiles.insert(PolicyProfile::WorkspaceWrite);
        }
        promotion_defaults =
            promotion_defaults.with_general_assistant_capability_ceiling(CapabilityGrant {
                tools: tool_ids,
                effect_classes,
                workspace_roots: read_tool
                    .workspace_ids()
                    .iter()
                    .map(|workspace_id| format!("workspace://{workspace_id}/"))
                    .collect(),
                writable_workspace_roots: write_runtime
                    .into_iter()
                    .flat_map(PhaseThreeRuntime::workspace_ids)
                    .map(|workspace_id| format!("workspace://{workspace_id}/"))
                    .collect(),
                network_destinations: daemon_config.web_access().capability_network_destinations(),
                executable_identity_digests: write_runtime
                    .into_iter()
                    .flat_map(PhaseThreeRuntime::command_ids)
                    .filter_map(|command_id| {
                        write_runtime
                            .and_then(|runtime| runtime.command_identity_digest(&command_id))
                            .map(str::to_owned)
                    })
                    .collect(),
                secret_references: daemon_config.web_access().capability_secret_references(),
                profiles,
                maximum_delegated_runs: daemon_config.agent_loop_limits().maximum_delegated_runs,
            })?;
    }
    let promotion = (!arguments.safe_mode).then(|| {
        tokio::spawn(promotion_driver(
            Arc::clone(&store),
            promotion_defaults,
            Duration::from_millis(arguments.promotion_delay_ms),
            Duration::from_millis(arguments.promotion_interval_ms.max(1)),
            shutdown_receiver.clone(),
        ))
    });
    let schedules = (!arguments.safe_mode).then(|| {
        tokio::spawn(schedule_driver(
            Arc::clone(&store),
            WorkerId::new(),
            daemon_config.maximum_pending_inputs_per_session(),
            arguments.schedule_clock_offset_ms,
            Duration::from_millis(250),
            shutdown_receiver.clone(),
        ))
    });
    let telegram = telegram_credentials.as_ref().map(|credentials| {
        tokio::spawn(telegram_driver(
            Arc::clone(&store),
            Arc::clone(credentials),
            telegram_client.clone(),
            arguments.telegram_api_base_url.clone(),
            daemon_config.maximum_pending_inputs_per_session(),
            Duration::from_millis(250),
            shutdown_receiver.clone(),
        ))
    });
    let discord = discord_credentials.as_ref().map(|credentials| {
        tokio::spawn(discord_driver(
            Arc::clone(&store),
            DiscordDriverRuntime {
                credentials: Arc::clone(credentials),
                client: discord_client.clone(),
                rate_limits: Arc::clone(&discord_rate_limits),
                api_base_url: arguments.discord_api_base_url.clone(),
                maximum_pending_inputs_per_session: daemon_config
                    .maximum_pending_inputs_per_session(),
            },
            Duration::from_millis(250),
            shutdown_receiver.clone(),
        ))
    });
    let outbox = (!arguments.safe_mode).then(|| {
        tokio::spawn(outbox_driver(
            Arc::clone(&store),
            OutboxChannelRuntime {
                channel_secrets: Arc::clone(&channel_secrets),
                telegram_credentials: telegram_credentials
                    .as_ref()
                    .map(Arc::clone)
                    .expect("non-safe mode has a Telegram credential broker"),
                webhook_client,
                telegram_client,
                telegram_api_base_url: arguments.telegram_api_base_url.clone(),
                discord_credentials: discord_credentials
                    .as_ref()
                    .map(Arc::clone)
                    .expect("non-safe mode has a Discord credential broker"),
                discord_client,
                discord_rate_limits,
                discord_api_base_url: arguments.discord_api_base_url.clone(),
            },
            WorkerId::new(),
            Duration::from_millis(arguments.outbox_delay_ms),
            Duration::from_millis(25),
            shutdown_receiver.clone(),
        ))
    });
    let lease_reaper = (!arguments.safe_mode).then(|| {
        tokio::spawn(lease_reaper_driver(
            Arc::clone(&store),
            Duration::from_millis(100),
            shutdown_receiver.clone(),
        ))
    });
    let agent_workers = if arguments.safe_mode {
        Vec::new()
    } else {
        (0..daemon_config.maximum_daemon_agent_runs())
            .map(|_| {
                tokio::spawn(agent_driver(
                    Arc::clone(&store),
                    WorkerId::new(),
                    Arc::clone(&provider),
                    Arc::clone(&read_tool),
                    effect_runtime.clone(),
                    Arc::clone(&artifacts),
                    daemon_config.lease_concurrency_limits(),
                    daemon_config.maximum_resource_class_invocations(),
                    Duration::from_millis(arguments.agent_delay_ms),
                    Duration::from_millis(arguments.agent_boundary_delay_ms),
                    Duration::from_millis(25),
                    shutdown_receiver.clone(),
                ))
            })
            .collect::<Vec<_>>()
    };
    println!("MEALY_READY {base_url} {}", connection_path.display());
    tracing::info!(%address, "mealyd ready");

    let mut server_shutdown = shutdown_receiver.clone();
    let server = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            if *server_shutdown.borrow() {
                return;
            }
            while server_shutdown.changed().await.is_ok() {
                if *server_shutdown.borrow() {
                    return;
                }
            }
        })
        .into_future();
    tokio::pin!(server);
    let server_completed = tokio::select! {
        result = &mut server => {
            result?;
            true
        },
        signal = tokio::signal::ctrl_c() => {
            signal?;
            let _ = shutdown_sender.send(true);
            false
        }
    };
    let _ = shutdown_sender.send(true);
    let drain_store = Arc::clone(&store);
    let drain_work = async move {
        if !server_completed {
            (&mut server).await?;
        }
        if let Some(worker) = promotion {
            let _ = worker.await;
        }
        if let Some(worker) = schedules {
            let _ = worker.await;
        }
        if let Some(worker) = telegram {
            let _ = worker.await;
        }
        if let Some(worker) = discord {
            let _ = worker.await;
        }
        if let Some(worker) = outbox {
            let _ = worker.await;
        }
        if let Some(worker) = lease_reaper {
            let _ = worker.await;
        }
        for worker in agent_workers {
            let _ = worker.await;
        }
        tokio::task::spawn_blocking(move || {
            let mut guard = drain_store
                .lock()
                .map_err(|_| "store lock poisoned during graceful drain")?;
            recover_startup(&mut *guard, &SystemClock, &SystemIdGenerator, 256)
                .map_err(|_| "final recovery classification failed")?;
            guard
                .complete_daemon_run(CompleteDaemonRunCommit {
                    start_id,
                    status: DaemonRunStatus::Clean,
                    reason: "bounded graceful drain completed".to_owned(),
                    completed_at: SystemTime::now(),
                })
                .map_err(|_| "clean shutdown evidence failed")?;
            guard
                .checkpoint_for_shutdown()
                .map_err(|_| "shutdown checkpoint failed")?;
            Ok::<(), &'static str>(())
        })
        .await
        .map_err(|_| "graceful drain worker failed")??;
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    };
    let drain_result = tokio::select! {
        result = tokio::time::timeout(drain_deadline, drain_work) => result,
        second = tokio::signal::ctrl_c() => {
            second?;
            tracing::warn!("second shutdown signal forced termination");
            record_forced_shutdown(
                &store,
                &arguments.home,
                start_id,
                "second shutdown signal",
            );
            let _ = std::fs::remove_file(&connection_path);
            std::process::exit(2);
        }
    };
    if let Ok(result) = drain_result {
        result?;
    } else {
        tracing::error!(
            deadline_ms = daemon_config.drain_deadline_ms(),
            "graceful drain deadline elapsed; forcing process termination"
        );
        record_forced_shutdown(
            &store,
            &arguments.home,
            start_id,
            "graceful drain deadline elapsed",
        );
        let _ = std::fs::remove_file(&connection_path);
        std::process::exit(2);
    }
    let _ = std::fs::remove_file(connection_path);
    Ok(())
}

fn record_forced_shutdown(
    store: &Arc<Mutex<SqliteStore>>,
    home: &std::path::Path,
    start_id: CorrelationId,
    reason: &str,
) {
    let completed_at = SystemTime::now();
    if let Err(error) = write_forced_shutdown_marker(home, start_id, reason, completed_at) {
        tracing::error!(%error, "could not persist forced-shutdown marker");
    }
    if let Ok(mut guard) = store.try_lock() {
        let completed = guard.complete_daemon_run(CompleteDaemonRunCommit {
            start_id,
            status: DaemonRunStatus::Forced,
            reason: reason.to_owned(),
            completed_at,
        });
        let checkpointed = guard.checkpoint_for_shutdown();
        if completed.is_ok() && checkpointed.is_ok() {
            let _ = remove_forced_shutdown_marker(home);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn agent_driver(
    store: Arc<Mutex<SqliteStore>>,
    worker_id: WorkerId,
    provider: Arc<RuntimeModelProvider>,
    tool: Arc<RuntimeReadTools>,
    effect_runtime: Option<Arc<PhaseThreeRuntime>>,
    artifacts: Arc<FileArtifactBlobStore>,
    lease_concurrency_limits: mealy_application::LeaseConcurrencyLimits,
    maximum_resource_class_invocations: u32,
    initial_delay: Duration,
    boundary_delay: Duration,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    tokio::select! {
        () = tokio::time::sleep(initial_delay) => {}
        _ = shutdown.changed() => return,
    }
    loop {
        let worker_store = Arc::clone(&store);
        let worker_provider = Arc::clone(&provider);
        let worker_tool = Arc::clone(&tool);
        let worker_effect_runtime = effect_runtime.clone();
        let worker_artifacts = Arc::clone(&artifacts);
        match tokio::task::spawn_blocking(move || {
            drive_one_agent_run(
                &worker_store,
                worker_id,
                &worker_provider,
                &worker_tool,
                worker_effect_runtime.as_deref(),
                &worker_artifacts,
                AgentDriverPolicy::new(
                    boundary_delay,
                    lease_concurrency_limits,
                    maximum_resource_class_invocations,
                ),
            )
        })
        .await
        {
            Ok(Ok(true)) => tracing::debug!(
                provider_calls = provider.invocation_count(),
                tool_calls = tool.invocation_count(),
                "bounded agent run completed"
            ),
            Ok(Ok(false)) => {}
            Ok(Err(error)) => tracing::error!(%error, "bounded agent run failed"),
            Err(error) => tracing::error!(%error, "agent worker task failed"),
        }
        tokio::select! {
            () = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => return,
        }
    }
}

async fn promotion_driver(
    store: Arc<Mutex<SqliteStore>>,
    defaults: PromotionDefaults,
    initial_delay: Duration,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    tokio::select! {
        () = tokio::time::sleep(initial_delay) => {}
        _ = shutdown.changed() => return,
    }
    loop {
        let scan_store = Arc::clone(&store);
        let scan_defaults = defaults.clone();
        match tokio::task::spawn_blocking(move || drive_promotions(&scan_store, &scan_defaults))
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::error!(%error, "durable promotion scan failed"),
            Err(error) => tracing::error!(%error, "durable promotion task failed"),
        }
        tokio::select! {
            () = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => return,
        }
    }
}

fn drive_promotions(
    store: &Arc<Mutex<SqliteStore>>,
    defaults: &PromotionDefaults,
) -> Result<(), mealy_application::PromotionUseCaseError> {
    let candidates = {
        let guard = store.lock().map_err(|_| {
            mealy_application::PromotionStoreError::Unavailable("store lock poisoned".to_owned())
        })?;
        pending_promotion_sessions(&*guard, 64)?
    };
    for candidate in candidates {
        let mut guard = store.lock().map_err(|_| {
            mealy_application::PromotionStoreError::Unavailable("store lock poisoned".to_owned())
        })?;
        let outcome = promote_next_input(
            &mut *guard,
            &SystemClock,
            &SystemIdGenerator,
            candidate.session_id,
            candidate.ownership,
            defaults,
        );
        match outcome {
            Ok(outcome) => tracing::debug!(?outcome, "promotion scan outcome"),
            Err(error) => {
                tracing::error!(session_id = %candidate.session_id, %error, "session promotion failed");
            }
        }
    }
    Ok(())
}

async fn schedule_driver(
    store: Arc<Mutex<SqliteStore>>,
    worker_id: WorkerId,
    maximum_pending_inputs_per_session: u64,
    clock_offset_ms: i64,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let worker_store = Arc::clone(&store);
        match tokio::task::spawn_blocking(move || {
            drive_schedule_batch(
                &worker_store,
                worker_id,
                maximum_pending_inputs_per_session,
                clock_offset_ms,
            )
        })
        .await
        {
            Ok(Ok(count)) if count != 0 => {
                tracing::info!(
                    occurrences = count,
                    "durable schedule occurrences processed"
                );
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => tracing::error!(%error, "durable schedule scan failed"),
            Err(error) => tracing::error!(%error, "durable schedule task failed"),
        }
        tokio::select! {
            () = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => return,
        }
    }
}

#[allow(clippy::too_many_lines)]
fn drive_schedule_batch(
    store: &Arc<Mutex<SqliteStore>>,
    worker_id: WorkerId,
    maximum_pending_inputs_per_session: u64,
    clock_offset_ms: i64,
) -> Result<usize, ScheduleDriverError> {
    let now_ms = schedule_now_ms(clock_offset_ms)?;
    let due = store
        .lock()
        .map_err(|_| ScheduleDriverError::Lock)?
        .due_schedules(now_ms, 32)?;
    let mut completed = 0;
    for schedule in due {
        let decision = plan_due_schedule(&schedule, now_ms)
            .map_err(|error| ScheduleDriverError::Contract(error.to_string()))?;
        let (scheduled_for_ms, next_due_at_ms, coalesced, mut intent) = match decision {
            ScheduleDueDecision::Fire {
                scheduled_for_ms,
                next_due_at_ms,
                coalesced,
            } => (
                scheduled_for_ms,
                next_due_at_ms,
                coalesced,
                ScheduleRunIntent::Fire,
            ),
            ScheduleDueDecision::SkipMisfire {
                scheduled_for_ms,
                next_due_at_ms,
                coalesced,
            } => (
                scheduled_for_ms,
                next_due_at_ms,
                coalesced,
                ScheduleRunIntent::SkipMisfire,
            ),
        };
        let mut guard = store.lock().map_err(|_| ScheduleDriverError::Lock)?;
        if intent == ScheduleRunIntent::Fire
            && schedule.overlap_policy == ScheduleOverlapPolicy::SkipIfRunning
            && guard.schedule_has_active_run(schedule.schedule_id)?
        {
            intent = ScheduleRunIntent::SkipOverlap;
        }
        let claim = guard.claim_schedule_run(ClaimScheduleRunCommit {
            schedule_id: schedule.schedule_id,
            expected_revision: schedule.revision,
            expected_next_due_at_ms: schedule
                .next_due_at_ms
                .ok_or_else(|| ScheduleDriverError::Contract("due cursor is absent".to_owned()))?,
            proposed_schedule_run_id: ScheduleRunId::new(),
            scheduled_for_ms,
            coalesced,
            intent,
            owner_id: worker_id,
            claimed_at_ms: now_ms,
            claim_expires_at_ms: now_ms + 30_000,
        })?;
        let ScheduleClaimOutcome::Claimed(run) = claim else {
            continue;
        };
        match run.intent {
            ScheduleRunIntent::SkipMisfire => {
                guard.complete_schedule_run(CompleteScheduleRunCommit {
                    schedule_id: schedule.schedule_id,
                    schedule_run_id: run.schedule_run_id,
                    owner_id: worker_id,
                    status: ScheduleRunStatus::Skipped,
                    inbox_entry_id: None,
                    reason: Some("missed_run_outside_grace".to_owned()),
                    next_due_at_ms,
                    completed_at_ms: schedule_now_ms(clock_offset_ms)?,
                })?;
            }
            ScheduleRunIntent::SkipOverlap => {
                guard.complete_schedule_run(CompleteScheduleRunCommit {
                    schedule_id: schedule.schedule_id,
                    schedule_run_id: run.schedule_run_id,
                    owner_id: worker_id,
                    status: ScheduleRunStatus::Skipped,
                    inbox_entry_id: None,
                    reason: Some("overlap_policy_skip_if_running".to_owned()),
                    next_due_at_ms,
                    completed_at_ms: schedule_now_ms(clock_offset_ms)?,
                })?;
            }
            ScheduleRunIntent::Fire => {
                let admission = admit_input(
                    &mut *guard,
                    &SystemClock,
                    &SystemIdGenerator,
                    InputAdmissionLimits::new(
                        256,
                        mealy_application::MAXIMUM_SCHEDULE_PROMPT_BYTES,
                        maximum_pending_inputs_per_session,
                    ),
                    AdmitInputCommand {
                        session_id: schedule.session_id,
                        ownership: schedule.ownership,
                        dedupe_key: format!(
                            "schedule:{}:{}",
                            schedule.schedule_id, run.scheduled_for_ms
                        ),
                        delivery_mode: DeliveryMode::Queue,
                        content: schedule.prompt.clone(),
                    },
                );
                match admission {
                    Ok(outcome) => {
                        guard.complete_schedule_run(CompleteScheduleRunCommit {
                            schedule_id: schedule.schedule_id,
                            schedule_run_id: run.schedule_run_id,
                            owner_id: worker_id,
                            status: ScheduleRunStatus::Admitted,
                            inbox_entry_id: Some(outcome.receipt().inbox_entry_id),
                            reason: None,
                            next_due_at_ms,
                            completed_at_ms: schedule_now_ms(clock_offset_ms)?,
                        })?;
                    }
                    Err(SessionUseCaseError::Store(SessionStoreError::Unavailable(message))) => {
                        return Err(ScheduleDriverError::SessionUnavailable(message));
                    }
                    Err(error) => {
                        guard.complete_schedule_run(CompleteScheduleRunCommit {
                            schedule_id: schedule.schedule_id,
                            schedule_run_id: run.schedule_run_id,
                            owner_id: worker_id,
                            status: ScheduleRunStatus::Failed,
                            inbox_entry_id: None,
                            reason: Some(schedule_admission_failure(&error).to_owned()),
                            next_due_at_ms,
                            completed_at_ms: schedule_now_ms(clock_offset_ms)?,
                        })?;
                    }
                }
            }
        }
        completed += 1;
    }
    Ok(completed)
}

fn schedule_admission_failure(error: &SessionUseCaseError) -> &'static str {
    match error {
        SessionUseCaseError::Store(SessionStoreError::Backpressure) => "session_backpressure",
        SessionUseCaseError::Store(SessionStoreError::SessionNotFound) => "session_not_found",
        SessionUseCaseError::Store(SessionStoreError::Unauthorized) => "session_unauthorized",
        SessionUseCaseError::Store(SessionStoreError::IdempotencyConflict) => {
            "schedule_idempotency_conflict"
        }
        SessionUseCaseError::Store(SessionStoreError::Conflict) => "session_admission_conflict",
        SessionUseCaseError::Store(SessionStoreError::InvariantViolation(_)) => {
            "session_invariant_violation"
        }
        SessionUseCaseError::Store(SessionStoreError::Unavailable(_)) => {
            "session_store_unavailable"
        }
        SessionUseCaseError::EmptyDedupeKey
        | SessionUseCaseError::DedupeKeyTooLarge { .. }
        | SessionUseCaseError::EmptyContent
        | SessionUseCaseError::ContentTooLarge { .. }
        | SessionUseCaseError::InvalidQueueCapacity => "scheduled_input_invalid",
    }
}

fn schedule_now_ms(clock_offset_ms: i64) -> Result<i64, ScheduleDriverError> {
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| ScheduleDriverError::Time)?;
    i64::try_from(duration.as_millis())
        .map_err(|_| ScheduleDriverError::Time)?
        .checked_add(clock_offset_ms)
        .ok_or(ScheduleDriverError::Time)
}

#[derive(Debug, ThisError)]
enum ScheduleDriverError {
    #[error("schedule store lock is unavailable")]
    Lock,
    #[error("schedule time is outside the supported epoch range")]
    Time,
    #[error("schedule contract failed: {0}")]
    Contract(String),
    #[error("scheduled session admission is unavailable: {0}")]
    SessionUnavailable(String),
    #[error(transparent)]
    Store(#[from] mealy_application::ScheduleStoreError),
}

async fn telegram_driver(
    store: Arc<Mutex<SqliteStore>>,
    credentials: Arc<FileProviderSecretStore>,
    client: reqwest::Client,
    api_base_url: String,
    maximum_pending_inputs_per_session: u64,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        match drive_telegram_batch(
            &store,
            &credentials,
            &client,
            &api_base_url,
            maximum_pending_inputs_per_session,
        )
        .await
        {
            Ok(processed) if processed != 0 => {
                tracing::info!(processed, "Telegram updates processed durably");
            }
            Ok(_) => {}
            Err(error) => tracing::error!(%error, "Telegram polling batch failed"),
        }
        tokio::select! {
            () = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => return,
        }
    }
}

async fn drive_telegram_batch(
    store: &Arc<Mutex<SqliteStore>>,
    credentials: &Arc<FileProviderSecretStore>,
    client: &reqwest::Client,
    api_base_url: &str,
    maximum_pending_inputs_per_session: u64,
) -> Result<usize, TelegramDriverError> {
    let target_store = Arc::clone(store);
    let targets = tokio::task::spawn_blocking(move || {
        target_store
            .lock()
            .map_err(|_| TelegramDriverError::Lock)?
            .active_telegram_poll_targets(16)
            .map_err(TelegramDriverError::Store)
    })
    .await
    .map_err(|_| TelegramDriverError::Join)??;
    let mut tasks = tokio::task::JoinSet::new();
    for target in targets {
        let credentials = Arc::clone(credentials);
        let client = client.clone();
        let api_base_url = api_base_url.to_owned();
        tasks.spawn(async move {
            let result =
                fetch_telegram_updates(&credentials, &client, &api_base_url, &target).await;
            (target, result)
        });
    }
    let mut processed = 0;
    while let Some(joined) = tasks.join_next().await {
        let (target, fetched) = joined.map_err(|_| TelegramDriverError::Join)?;
        let worker_store = Arc::clone(store);
        match fetched {
            Ok(updates) => {
                processed += tokio::task::spawn_blocking(move || {
                    let mut guard = worker_store.lock().map_err(|_| TelegramDriverError::Lock)?;
                    guard.record_telegram_poll(RecordTelegramPollCommit {
                        binding_id: target.binding_id,
                        succeeded: true,
                        error_code: None,
                        observed_at: SystemTime::now(),
                    })?;
                    process_telegram_updates(
                        &mut guard,
                        &target,
                        updates,
                        maximum_pending_inputs_per_session,
                    )
                })
                .await
                .map_err(|_| TelegramDriverError::Join)??;
            }
            Err(error) => {
                let error_code = error.code().to_owned();
                tracing::warn!(
                    binding_id = %target.binding_id,
                    error_code,
                    "Telegram Bot API poll failed"
                );
                tokio::task::spawn_blocking(move || {
                    worker_store
                        .lock()
                        .map_err(|_| TelegramDriverError::Lock)?
                        .record_telegram_poll(RecordTelegramPollCommit {
                            binding_id: target.binding_id,
                            succeeded: false,
                            error_code: Some(error_code),
                            observed_at: SystemTime::now(),
                        })
                        .map_err(TelegramDriverError::Store)
                })
                .await
                .map_err(|_| TelegramDriverError::Join)??;
            }
        }
    }
    Ok(processed)
}

async fn fetch_telegram_updates(
    credentials: &Arc<FileProviderSecretStore>,
    client: &reqwest::Client,
    api_base_url: &str,
    target: &TelegramPollTarget,
) -> Result<Vec<FetchedTelegramUpdate>, TelegramFetchError> {
    const MAXIMUM_RESPONSE_BYTES: usize = 1024 * 1024;
    let credential_store = Arc::clone(credentials);
    let secret_id = target.token_secret_id.clone();
    let token = tokio::task::spawn_blocking(move || credential_store.read(&secret_id))
        .await
        .map_err(|_| TelegramFetchError::CredentialUnavailable)?
        .map_err(TelegramFetchError::Credential)?;
    if sha256_digest(token.as_bytes()) != target.token_digest
        || backend::validate_telegram_bot_token(&token).is_err()
    {
        return Err(TelegramFetchError::CredentialMismatch);
    }
    let url = format!(
        "{}/bot{}/getUpdates",
        api_base_url.trim_end_matches('/'),
        token.as_str()
    );
    let response = client
        .post(url)
        .json(&json!({
            "offset": target.next_update_id,
            "limit": 100,
            "timeout": 5,
            "allowed_updates": ["message"],
        }))
        .send()
        .await
        .map_err(|_| TelegramFetchError::Transport)?;
    let status = response.status();
    if !status.is_success() {
        return Err(match status.as_u16() {
            401 => TelegramFetchError::Unauthorized,
            409 => TelegramFetchError::WebhookConflict,
            429 => TelegramFetchError::RateLimited,
            500..=599 => TelegramFetchError::Server,
            _ => TelegramFetchError::Http,
        });
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAXIMUM_RESPONSE_BYTES as u64)
    {
        return Err(TelegramFetchError::Oversized);
    }
    let body = read_telegram_response(response, MAXIMUM_RESPONSE_BYTES).await?;
    let envelope: TelegramUpdatesEnvelope =
        serde_json::from_slice(&body).map_err(|_| TelegramFetchError::Malformed)?;
    if !envelope.ok || envelope.result.len() > 100 {
        return Err(TelegramFetchError::Malformed);
    }
    let mut updates = Vec::with_capacity(envelope.result.len());
    for raw in envelope.result {
        let attachment =
            fetch_telegram_attachment(client, api_base_url, &token, target, &raw).await?;
        updates.push(FetchedTelegramUpdate { raw, attachment });
    }
    Ok(updates)
}

async fn read_telegram_response(
    mut response: reqwest::Response,
    maximum_bytes: usize,
) -> Result<Vec<u8>, TelegramFetchError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum_bytes as u64)
    {
        return Err(TelegramFetchError::Oversized);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| TelegramFetchError::Transport)?
    {
        if body.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(TelegramFetchError::Oversized);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Serialize)]
struct FetchedTelegramUpdate {
    raw: Value,
    attachment: Option<FetchedTelegramAttachment>,
}

#[derive(Serialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
enum FetchedTelegramAttachment {
    Text {
        file_name: String,
        media_type: String,
        digest: String,
        content: String,
    },
    Ignored {
        reason: &'static str,
    },
}

const TELEGRAM_MAXIMUM_ATTACHMENT_BYTES: u64 = 256 * 1024;

struct TelegramDocumentMetadata {
    file_id: String,
    file_name: String,
    media_type: String,
    file_size: u64,
}

async fn fetch_telegram_attachment(
    client: &reqwest::Client,
    api_base_url: &str,
    token: &str,
    target: &TelegramPollTarget,
    update: &Value,
) -> Result<Option<FetchedTelegramAttachment>, TelegramFetchError> {
    let Some(message) = update.get("message").and_then(Value::as_object) else {
        return Ok(None);
    };
    if message
        .get("from")
        .and_then(Value::as_object)
        .and_then(|sender| sender.get("id"))
        .and_then(Value::as_i64)
        != Some(target.telegram_user_id)
        || message
            .get("chat")
            .and_then(Value::as_object)
            .and_then(|chat| chat.get("id"))
            .and_then(Value::as_i64)
            != Some(target.telegram_chat_id)
    {
        return Ok(None);
    }
    let metadata = match telegram_document_metadata(message) {
        Ok(None) => return Ok(None),
        Ok(Some(metadata)) => metadata,
        Err(reason) => return Ok(Some(FetchedTelegramAttachment::Ignored { reason })),
    };
    download_telegram_text_attachment(client, api_base_url, token, metadata).await
}

fn telegram_document_metadata(
    message: &serde_json::Map<String, Value>,
) -> Result<Option<TelegramDocumentMetadata>, &'static str> {
    let Some(document) = message.get("document").and_then(Value::as_object) else {
        return if [
            "photo",
            "video",
            "audio",
            "voice",
            "animation",
            "sticker",
            "video_note",
        ]
        .iter()
        .any(|kind| message.contains_key(*kind))
        {
            Err("unsupported_attachment_type")
        } else {
            Ok(None)
        };
    };
    let file_size = document
        .get("file_size")
        .and_then(Value::as_u64)
        .unwrap_or(TELEGRAM_MAXIMUM_ATTACHMENT_BYTES + 1);
    if file_size == 0 || file_size > TELEGRAM_MAXIMUM_ATTACHMENT_BYTES {
        return Err("attachment_size_out_of_bounds");
    }
    let Some(file_id) = document
        .get("file_id")
        .and_then(Value::as_str)
        .filter(|value| valid_telegram_file_field(value, 512))
    else {
        return Err("attachment_identity_invalid");
    };
    let Some(file_name) = document
        .get("file_name")
        .and_then(Value::as_str)
        .filter(|value| valid_telegram_file_field(value, 255))
    else {
        return Err("attachment_name_invalid");
    };
    let Some(media_type) = document
        .get("mime_type")
        .and_then(Value::as_str)
        .filter(|value| telegram_text_media_type(value))
    else {
        return Err("attachment_media_type_unsupported");
    };
    Ok(Some(TelegramDocumentMetadata {
        file_id: file_id.to_owned(),
        file_name: file_name.to_owned(),
        media_type: media_type.to_owned(),
        file_size,
    }))
}

async fn download_telegram_text_attachment(
    client: &reqwest::Client,
    api_base_url: &str,
    token: &str,
    metadata: TelegramDocumentMetadata,
) -> Result<Option<FetchedTelegramAttachment>, TelegramFetchError> {
    let get_file_url = format!(
        "{}/bot{}/getFile",
        api_base_url.trim_end_matches('/'),
        token
    );
    let response = client
        .post(get_file_url)
        .json(&json!({"file_id": metadata.file_id}))
        .send()
        .await
        .map_err(|_| TelegramFetchError::Transport)?;
    if !response.status().is_success() {
        return telegram_attachment_http_failure(response.status());
    }
    let body = read_telegram_response(response, 64 * 1024).await?;
    let envelope: Value =
        serde_json::from_slice(&body).map_err(|_| TelegramFetchError::Malformed)?;
    let Some(file_path) = envelope
        .get("ok")
        .and_then(Value::as_bool)
        .filter(|ok| *ok)
        .and_then(|_| envelope.get("result"))
        .and_then(|result| result.get("file_path"))
        .and_then(Value::as_str)
        .filter(|path| valid_telegram_file_path(path))
    else {
        return Ok(Some(FetchedTelegramAttachment::Ignored {
            reason: "attachment_path_invalid",
        }));
    };
    let download_url = format!(
        "{}/file/bot{}/{}",
        api_base_url.trim_end_matches('/'),
        token,
        file_path
    );
    let response = client
        .get(download_url)
        .send()
        .await
        .map_err(|_| TelegramFetchError::Transport)?;
    if !response.status().is_success() {
        return telegram_attachment_http_failure(response.status());
    }
    let response_media_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .unwrap_or("application/octet-stream");
    if response_media_type != metadata.media_type
        && response_media_type != "application/octet-stream"
    {
        return Ok(Some(FetchedTelegramAttachment::Ignored {
            reason: "attachment_response_type_mismatch",
        }));
    }
    let content = read_telegram_response(
        response,
        usize::try_from(TELEGRAM_MAXIMUM_ATTACHMENT_BYTES).unwrap_or(usize::MAX),
    )
    .await?;
    if u64::try_from(content.len()).unwrap_or(u64::MAX) != metadata.file_size {
        return Ok(Some(FetchedTelegramAttachment::Ignored {
            reason: "attachment_size_mismatch",
        }));
    }
    let digest = sha256_digest(&content);
    let content = String::from_utf8(content).map_err(|_| TelegramFetchError::Malformed)?;
    if content.contains('\0') {
        return Ok(Some(FetchedTelegramAttachment::Ignored {
            reason: "attachment_text_invalid",
        }));
    }
    Ok(Some(FetchedTelegramAttachment::Text {
        file_name: metadata.file_name,
        media_type: metadata.media_type,
        digest,
        content,
    }))
}

fn telegram_attachment_http_failure(
    status: reqwest::StatusCode,
) -> Result<Option<FetchedTelegramAttachment>, TelegramFetchError> {
    match status.as_u16() {
        401 => Err(TelegramFetchError::Unauthorized),
        429 => Err(TelegramFetchError::RateLimited),
        500..=599 => Err(TelegramFetchError::Server),
        _ => Ok(Some(FetchedTelegramAttachment::Ignored {
            reason: "attachment_fetch_rejected",
        })),
    }
}

fn valid_telegram_file_field(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_telegram_file_path(value: &str) -> bool {
    valid_telegram_file_field(value, 1_024)
        && !value.starts_with('/')
        && !value.contains(['?', '#', '\\'])
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && !matches!(segment, "." | ".."))
}

fn telegram_text_media_type(value: &str) -> bool {
    matches!(
        value,
        "text/plain" | "text/markdown" | "text/csv" | "application/json"
    )
}

fn process_telegram_updates(
    store: &mut SqliteStore,
    target: &TelegramPollTarget,
    mut updates: Vec<FetchedTelegramUpdate>,
    maximum_pending_inputs_per_session: u64,
) -> Result<usize, TelegramDriverError> {
    updates.sort_by_key(|update| update.raw.get("update_id").and_then(Value::as_i64));
    let mut processed = 0;
    for update in updates {
        let update_id = update
            .raw
            .get("update_id")
            .and_then(Value::as_i64)
            .filter(|value| *value >= 0)
            .ok_or(TelegramDriverError::MalformedUpdate)?;
        let body = serde_json::to_vec(&update).map_err(|_| TelegramDriverError::MalformedUpdate)?;
        if body.len() > 512 * 1024 {
            return Err(TelegramDriverError::MalformedUpdate);
        }
        let reservation = store.reserve_telegram_update(ReserveTelegramUpdateCommit {
            binding_id: target.binding_id,
            update_id,
            body_digest: sha256_digest(&body),
            received_at: SystemTime::now(),
        })?;
        if reservation == TelegramUpdateReservation::ExistingCompleted {
            continue;
        }
        match telegram_update_action(target, &update) {
            TelegramInboundAction::Input {
                delivery_mode,
                content,
            } => {
                let outcome = admit_input(
                    store,
                    &SystemClock,
                    &SystemIdGenerator,
                    InputAdmissionLimits::new(256, 1024 * 1024, maximum_pending_inputs_per_session),
                    AdmitInputCommand {
                        session_id: target.session_id,
                        ownership: target.ownership,
                        dedupe_key: telegram_input_dedupe_key(target.binding_id, update_id)?,
                        delivery_mode,
                        content,
                    },
                )?;
                store.complete_telegram_update(CompleteTelegramUpdateCommit {
                    binding_id: target.binding_id,
                    update_id,
                    disposition: TelegramUpdateDisposition::Admitted(outcome.receipt().clone()),
                    completed_at: SystemTime::now(),
                })?;
            }
            TelegramInboundAction::Approval {
                approval_id,
                subject_digest,
                decision,
            } => {
                let result = store.resolve_approval(ResolveApprovalCommit {
                    approval_id,
                    ownership: target.ownership,
                    expected_subject_digest: subject_digest,
                    decision,
                    idempotency_key: format!("telegram-approval:{}:{update_id}", target.binding_id),
                    approval_event_id: SystemIdGenerator.generate_event_id(),
                    effect_event_id: SystemIdGenerator.generate_event_id(),
                    correlation_id: SystemIdGenerator.generate_correlation_id(),
                    decided_at: SystemTime::now(),
                });
                let reason = match result {
                    Ok(receipt) if receipt.decision == ApprovalDecision::Approve => {
                        "approval_approved"
                    }
                    Ok(_) => "approval_denied",
                    Err(
                        error @ (EffectLedgerStoreError::Unavailable(_)
                        | EffectLedgerStoreError::InvariantViolation(_)
                        | EffectLedgerStoreError::InvalidEvidence(_)),
                    ) => return Err(TelegramDriverError::Approval(error)),
                    Err(_) => "approval_resolution_rejected",
                };
                store.complete_telegram_update(CompleteTelegramUpdateCommit {
                    binding_id: target.binding_id,
                    update_id,
                    disposition: TelegramUpdateDisposition::Ignored(reason.to_owned()),
                    completed_at: SystemTime::now(),
                })?;
            }
            TelegramInboundAction::Ignore(reason) => {
                store.complete_telegram_update(CompleteTelegramUpdateCommit {
                    binding_id: target.binding_id,
                    update_id,
                    disposition: TelegramUpdateDisposition::Ignored(reason.to_owned()),
                    completed_at: SystemTime::now(),
                })?;
            }
        }
        processed += 1;
    }
    Ok(processed)
}

#[derive(Debug, Eq, PartialEq)]
enum TelegramInboundAction {
    Input {
        delivery_mode: DeliveryMode,
        content: String,
    },
    Approval {
        approval_id: ApprovalId,
        subject_digest: String,
        decision: ApprovalDecision,
    },
    Ignore(&'static str),
}

fn telegram_update_action(
    target: &TelegramPollTarget,
    update: &FetchedTelegramUpdate,
) -> TelegramInboundAction {
    let Some(message) = update.raw.get("message").and_then(Value::as_object) else {
        return TelegramInboundAction::Ignore("unsupported_update");
    };
    let Some(sender) = message.get("from").and_then(Value::as_object) else {
        return TelegramInboundAction::Ignore("missing_sender");
    };
    if sender.get("id").and_then(Value::as_i64) != Some(target.telegram_user_id)
        || sender.get("is_bot").and_then(Value::as_bool) == Some(true)
    {
        return TelegramInboundAction::Ignore("sender_not_allowed");
    }
    if message
        .get("chat")
        .and_then(Value::as_object)
        .and_then(|chat| chat.get("id"))
        .and_then(Value::as_i64)
        != Some(target.telegram_chat_id)
    {
        return TelegramInboundAction::Ignore("chat_not_allowed");
    }
    let caption = message
        .get("text")
        .or_else(|| message.get("caption"))
        .and_then(Value::as_str);
    let content = match &update.attachment {
        Some(FetchedTelegramAttachment::Ignored { reason }) => {
            return TelegramInboundAction::Ignore(reason);
        }
        Some(FetchedTelegramAttachment::Text {
            file_name,
            media_type,
            digest,
            content,
        }) => {
            let request = caption.unwrap_or("Review the attached untrusted text file.");
            let name = serde_json::to_string(file_name).unwrap_or_else(|_| "null".to_owned());
            format!(
                "{request}\n\n[Untrusted Telegram attachment: name={name}, media_type={media_type}, sha256={digest}]\n{content}\n[End untrusted Telegram attachment]"
            )
        }
        None => {
            let Some(content) = caption else {
                return TelegramInboundAction::Ignore("unsupported_attachment");
            };
            content.to_owned()
        }
    };
    if content.is_empty() || content.contains('\0') {
        return TelegramInboundAction::Ignore("invalid_text");
    }
    if let Some(action) = telegram_approval_action(&content) {
        return action;
    }
    match telegram_delivery_mode(&content) {
        Ok((delivery_mode, content)) => TelegramInboundAction::Input {
            delivery_mode,
            content,
        },
        Err(reason) => TelegramInboundAction::Ignore(reason),
    }
}

fn telegram_approval_action(content: &str) -> Option<TelegramInboundAction> {
    let mut fields = content.split_whitespace();
    let command = fields.next()?;
    let command = command.split_once('@').map_or(command, |value| value.0);
    let decision = match command {
        "/approve" => ApprovalDecision::Approve,
        "/deny" => ApprovalDecision::Deny,
        _ => return None,
    };
    let Some(approval_id) = fields
        .next()
        .and_then(|value| value.parse::<ApprovalId>().ok())
    else {
        return Some(TelegramInboundAction::Ignore("invalid_approval_command"));
    };
    let Some(subject_digest) = fields.next().filter(|value| is_sha256_digest(value)) else {
        return Some(TelegramInboundAction::Ignore("invalid_approval_command"));
    };
    if fields.next().is_some() {
        return Some(TelegramInboundAction::Ignore("invalid_approval_command"));
    }
    Some(TelegramInboundAction::Approval {
        approval_id,
        subject_digest: subject_digest.to_owned(),
        decision,
    })
}

fn telegram_delivery_mode(content: &str) -> Result<(DeliveryMode, String), &'static str> {
    let Some((command, remainder)) = content.split_once(char::is_whitespace) else {
        return match content.split_once('@').map_or(content, |value| value.0) {
            "/queue" | "/steer" | "/interrupt" => Err("empty_delivery_control"),
            "/start" | "/help" => Err("help_command"),
            _ => Ok((DeliveryMode::Queue, content.to_owned())),
        };
    };
    let command = command.split_once('@').map_or(command, |value| value.0);
    let remainder = remainder.trim_start();
    if remainder.is_empty() {
        return Err("empty_delivery_control");
    }
    match command {
        "/queue" => Ok((DeliveryMode::Queue, remainder.to_owned())),
        "/steer" => Ok((DeliveryMode::SteerAtBoundary, remainder.to_owned())),
        "/interrupt" => Ok((DeliveryMode::InterruptThenQueue, remainder.to_owned())),
        _ => Ok((DeliveryMode::Queue, content.to_owned())),
    }
}

#[derive(Deserialize)]
struct TelegramUpdatesEnvelope {
    ok: bool,
    #[serde(default)]
    result: Vec<Value>,
}

#[derive(Debug, ThisError)]
enum TelegramFetchError {
    #[error("Telegram credential broker is unavailable")]
    CredentialUnavailable,
    #[error("Telegram credential is unavailable")]
    Credential(#[source] ProviderSecretStoreError),
    #[error("Telegram credential digest changed")]
    CredentialMismatch,
    #[error("Telegram transport is unavailable")]
    Transport,
    #[error("Telegram token was rejected")]
    Unauthorized,
    #[error("Telegram getUpdates conflicts with a configured webhook")]
    WebhookConflict,
    #[error("Telegram rate limit was reached")]
    RateLimited,
    #[error("Telegram server failed")]
    Server,
    #[error("Telegram returned an unsuccessful response")]
    Http,
    #[error("Telegram response exceeded the byte limit")]
    Oversized,
    #[error("Telegram response was malformed")]
    Malformed,
}

impl TelegramFetchError {
    const fn code(&self) -> &'static str {
        match self {
            Self::CredentialUnavailable | Self::Credential(_) => "telegram_credential_unavailable",
            Self::CredentialMismatch => "telegram_credential_mismatch",
            Self::Transport => "telegram_transport_unavailable",
            Self::Unauthorized => "telegram_unauthorized",
            Self::WebhookConflict => "telegram_webhook_conflict",
            Self::RateLimited => "telegram_rate_limited",
            Self::Server => "telegram_server_error",
            Self::Http => "telegram_http_error",
            Self::Oversized => "telegram_response_oversized",
            Self::Malformed => "telegram_response_malformed",
        }
    }
}

#[derive(Debug, ThisError)]
enum TelegramDriverError {
    #[error("Telegram store lock is unavailable")]
    Lock,
    #[error("Telegram blocking worker failed")]
    Join,
    #[error("Telegram update is malformed")]
    MalformedUpdate,
    #[error(transparent)]
    Store(#[from] TelegramChannelStoreError),
    #[error(transparent)]
    Session(#[from] SessionUseCaseError),
    #[error(transparent)]
    Approval(#[from] EffectLedgerStoreError),
}

struct DiscordRateLimitGate {
    not_before: tokio::sync::Mutex<tokio::time::Instant>,
}

impl DiscordRateLimitGate {
    fn new() -> Self {
        Self {
            not_before: tokio::sync::Mutex::new(tokio::time::Instant::now()),
        }
    }

    async fn wait(&self) {
        let deadline = *self.not_before.lock().await;
        tokio::time::sleep_until(deadline).await;
    }

    async fn defer(&self, delay: Duration) {
        let candidate = tokio::time::Instant::now() + delay;
        let mut not_before = self.not_before.lock().await;
        if candidate > *not_before {
            *not_before = candidate;
        }
    }
}

struct DiscordDriverRuntime {
    credentials: Arc<FileProviderSecretStore>,
    client: reqwest::Client,
    rate_limits: Arc<DiscordRateLimitGate>,
    api_base_url: String,
    maximum_pending_inputs_per_session: u64,
}

async fn discord_driver(
    store: Arc<Mutex<SqliteStore>>,
    runtime: DiscordDriverRuntime,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut target_not_before = BTreeMap::new();
    loop {
        match drive_discord_batch(
            &store,
            &runtime.credentials,
            &runtime.client,
            &runtime.rate_limits,
            &runtime.api_base_url,
            runtime.maximum_pending_inputs_per_session,
            &mut target_not_before,
        )
        .await
        {
            Ok(processed) if processed != 0 => {
                tracing::info!(processed, "Discord DM messages processed durably");
            }
            Ok(_) => {}
            Err(error) => tracing::error!(%error, "Discord polling batch failed"),
        }
        tokio::select! {
            () = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => return,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn drive_discord_batch(
    store: &Arc<Mutex<SqliteStore>>,
    credentials: &Arc<FileProviderSecretStore>,
    client: &reqwest::Client,
    rate_limits: &Arc<DiscordRateLimitGate>,
    api_base_url: &str,
    maximum_pending_inputs_per_session: u64,
    target_not_before: &mut BTreeMap<mealy_domain::ChannelBindingId, tokio::time::Instant>,
) -> Result<usize, DiscordDriverError> {
    let target_store = Arc::clone(store);
    let targets = tokio::task::spawn_blocking(move || {
        target_store
            .lock()
            .map_err(|_| DiscordDriverError::Lock)?
            .active_discord_poll_targets(16)
            .map_err(DiscordDriverError::Store)
    })
    .await
    .map_err(|_| DiscordDriverError::Join)??;
    let active = targets
        .iter()
        .map(|target| target.binding_id)
        .collect::<BTreeSet<_>>();
    target_not_before.retain(|binding_id, _| active.contains(binding_id));
    let now = tokio::time::Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for target in targets {
        if target_not_before
            .get(&target.binding_id)
            .is_some_and(|deadline| *deadline > now)
        {
            continue;
        }
        let credentials = Arc::clone(credentials);
        let client = client.clone();
        let rate_limits = Arc::clone(rate_limits);
        let api_base_url = api_base_url.to_owned();
        tasks.spawn(async move {
            let result =
                fetch_discord_messages(&credentials, &client, &rate_limits, &api_base_url, &target)
                    .await;
            (target, result)
        });
    }
    let mut processed = 0;
    while let Some(joined) = tasks.join_next().await {
        let (target, fetched) = joined.map_err(|_| DiscordDriverError::Join)?;
        let worker_store = Arc::clone(store);
        match fetched {
            Ok(batch) => {
                target_not_before.insert(
                    target.binding_id,
                    tokio::time::Instant::now() + batch.next_poll_after,
                );
                processed += tokio::task::spawn_blocking(move || {
                    let mut guard = worker_store.lock().map_err(|_| DiscordDriverError::Lock)?;
                    guard.record_discord_poll(RecordDiscordPollCommit {
                        binding_id: target.binding_id,
                        succeeded: true,
                        error_code: None,
                        observed_at: SystemTime::now(),
                    })?;
                    process_discord_messages(
                        &mut guard,
                        &target,
                        batch.messages,
                        maximum_pending_inputs_per_session,
                    )
                })
                .await
                .map_err(|_| DiscordDriverError::Join)??;
            }
            Err(error) => {
                let delay = error.retry_delay();
                target_not_before.insert(target.binding_id, tokio::time::Instant::now() + delay);
                let error_code = error.code().to_owned();
                tracing::warn!(
                    binding_id = %target.binding_id,
                    error_code,
                    retry_after_ms = delay.as_millis(),
                    "Discord REST poll failed"
                );
                tokio::task::spawn_blocking(move || {
                    worker_store
                        .lock()
                        .map_err(|_| DiscordDriverError::Lock)?
                        .record_discord_poll(RecordDiscordPollCommit {
                            binding_id: target.binding_id,
                            succeeded: false,
                            error_code: Some(error_code),
                            observed_at: SystemTime::now(),
                        })
                        .map_err(DiscordDriverError::Store)
                })
                .await
                .map_err(|_| DiscordDriverError::Join)??;
            }
        }
    }
    Ok(processed)
}

struct FetchedDiscordBatch {
    messages: Vec<Value>,
    next_poll_after: Duration,
}

async fn fetch_discord_messages(
    credentials: &Arc<FileProviderSecretStore>,
    client: &reqwest::Client,
    rate_limits: &Arc<DiscordRateLimitGate>,
    api_base_url: &str,
    target: &DiscordPollTarget,
) -> Result<FetchedDiscordBatch, DiscordFetchError> {
    const MAXIMUM_BACKLOG_MESSAGES: usize = 10_000;
    const MAXIMUM_BACKLOG_BYTES: usize = 16 * 1024 * 1024;
    let credential_store = Arc::clone(credentials);
    let secret_id = target.token_secret_id.clone();
    let token = tokio::task::spawn_blocking(move || credential_store.read(&secret_id))
        .await
        .map_err(|_| DiscordFetchError::CredentialUnavailable)?
        .map_err(DiscordFetchError::Credential)?;
    if sha256_digest(token.as_bytes()) != target.token_digest
        || backend::validate_discord_bot_token(&token).is_err()
    {
        return Err(DiscordFetchError::CredentialMismatch);
    }
    let first_query = target
        .after_message_id
        .as_ref()
        .map_or_else(String::new, |message_id| format!("&after={message_id}"));
    let (mut messages, mut next_poll_after) = fetch_discord_page(
        client,
        rate_limits,
        api_base_url,
        &target.discord_channel_id,
        &token,
        &first_query,
    )
    .await?;
    if messages.len() == 100 {
        let Some(floor) = target.after_message_id.as_deref() else {
            return Err(DiscordFetchError::BacklogExceeded);
        };
        let mut before = minimum_discord_message_id(&messages)?;
        loop {
            let query = format!("&before={before}");
            let (page, page_delay) = fetch_discord_page(
                client,
                rate_limits,
                api_base_url,
                &target.discord_channel_id,
                &token,
                &query,
            )
            .await?;
            next_poll_after = next_poll_after.max(page_delay);
            let page_was_full = page.len() == 100;
            let mut crossed_floor = false;
            let mut relevant = Vec::new();
            for message in page {
                let id = discord_message_id(&message)?;
                if discord_snowflake_cmp(id, floor).is_gt() {
                    relevant.push(message);
                } else {
                    crossed_floor = true;
                }
            }
            if relevant.is_empty() {
                break;
            }
            let next_before = minimum_discord_message_id(&relevant)?;
            if discord_snowflake_cmp(&next_before, &before).is_ge() {
                return Err(DiscordFetchError::Malformed);
            }
            messages.extend(relevant);
            if messages.len() > MAXIMUM_BACKLOG_MESSAGES
                || serde_json::to_vec(&messages)
                    .map_err(|_| DiscordFetchError::Malformed)?
                    .len()
                    > MAXIMUM_BACKLOG_BYTES
            {
                return Err(DiscordFetchError::BacklogExceeded);
            }
            if crossed_floor || !page_was_full {
                break;
            }
            before = next_before;
        }
    }
    messages.sort_by(|left, right| {
        let left = left.get("id").and_then(Value::as_str).unwrap_or("");
        let right = right.get("id").and_then(Value::as_str).unwrap_or("");
        discord_snowflake_cmp(left, right)
    });
    for pair in messages.windows(2) {
        if discord_message_id(&pair[0])? == discord_message_id(&pair[1])?
            && canonical_arguments_digest(&pair[0]) != canonical_arguments_digest(&pair[1])
        {
            return Err(DiscordFetchError::Malformed);
        }
    }
    messages.dedup_by(|left, right| {
        left.get("id").and_then(Value::as_str) == right.get("id").and_then(Value::as_str)
    });
    Ok(FetchedDiscordBatch {
        messages,
        next_poll_after,
    })
}

async fn fetch_discord_page(
    client: &reqwest::Client,
    rate_limits: &Arc<DiscordRateLimitGate>,
    api_base_url: &str,
    channel_id: &str,
    token: &str,
    query: &str,
) -> Result<(Vec<Value>, Duration), DiscordFetchError> {
    const MAXIMUM_RESPONSE_BYTES: usize = 1024 * 1024;
    const USER_AGENT: &str = "DiscordBot (https://github.com/Amekn/project_mealy, 0.1.0)";
    let url = format!(
        "{}/channels/{channel_id}/messages?limit=100{query}",
        api_base_url.trim_end_matches('/'),
    );
    rate_limits.wait().await;
    let response = client
        .get(url)
        .header(reqwest::header::AUTHORIZATION, format!("Bot {token}"))
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .send()
        .await
        .map_err(|_| DiscordFetchError::Transport)?;
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let delay = discord_rate_limit_delay(response).await;
        rate_limits.defer(delay).await;
        return Err(DiscordFetchError::RateLimited(delay));
    }
    if !response.status().is_success() {
        return Err(match response.status().as_u16() {
            401 => DiscordFetchError::Unauthorized,
            403 => DiscordFetchError::Forbidden,
            404 => DiscordFetchError::NotFound,
            500..=599 => DiscordFetchError::Server,
            _ => DiscordFetchError::Http,
        });
    }
    let next_poll_after = discord_success_delay(response.headers());
    if next_poll_after > Duration::from_secs(1) {
        rate_limits.defer(next_poll_after).await;
    }
    let body = read_discord_response(response, MAXIMUM_RESPONSE_BYTES).await?;
    let messages: Vec<Value> =
        serde_json::from_slice(&body).map_err(|_| DiscordFetchError::Malformed)?;
    if messages.len() > 100 {
        return Err(DiscordFetchError::Malformed);
    }
    for message in &messages {
        let _ = discord_message_id(message)?;
        if message.get("channel_id").and_then(Value::as_str) != Some(channel_id) {
            return Err(DiscordFetchError::Malformed);
        }
    }
    Ok((messages, next_poll_after))
}

fn discord_message_id(message: &Value) -> Result<&str, DiscordFetchError> {
    message
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| validate_discord_snowflake(value))
        .ok_or(DiscordFetchError::Malformed)
}

fn minimum_discord_message_id(messages: &[Value]) -> Result<String, DiscordFetchError> {
    messages
        .iter()
        .map(discord_message_id)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .min_by(|left, right| discord_snowflake_cmp(left, right))
        .map(str::to_owned)
        .ok_or(DiscordFetchError::Malformed)
}

async fn read_discord_response(
    mut response: reqwest::Response,
    maximum_bytes: usize,
) -> Result<Vec<u8>, DiscordFetchError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum_bytes as u64)
    {
        return Err(DiscordFetchError::Oversized);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| DiscordFetchError::Transport)?
    {
        if body.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(DiscordFetchError::Oversized);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn process_discord_messages(
    store: &mut SqliteStore,
    target: &DiscordPollTarget,
    mut messages: Vec<Value>,
    maximum_pending_inputs_per_session: u64,
) -> Result<usize, DiscordDriverError> {
    messages.sort_by(|left, right| {
        let left = left.get("id").and_then(Value::as_str).unwrap_or("");
        let right = right.get("id").and_then(Value::as_str).unwrap_or("");
        discord_snowflake_cmp(left, right)
    });
    let mut processed = 0;
    for message in messages {
        let message_id = message
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| validate_discord_snowflake(value))
            .ok_or(DiscordDriverError::MalformedMessage)?
            .to_owned();
        let serialized =
            serde_json::to_vec(&message).map_err(|_| DiscordDriverError::MalformedMessage)?;
        if serialized.len() > 256 * 1024 {
            return Err(DiscordDriverError::MalformedMessage);
        }
        let reservation = store.reserve_discord_message(ReserveDiscordMessageCommit {
            binding_id: target.binding_id,
            message_id: message_id.clone(),
            body_digest: canonical_arguments_digest(&message),
            received_at: SystemTime::now(),
        })?;
        if reservation == DiscordMessageReservation::ExistingCompleted {
            continue;
        }
        match discord_message_action(target, &message) {
            DiscordInboundAction::Input {
                delivery_mode,
                content,
            } => {
                let outcome = admit_input(
                    store,
                    &SystemClock,
                    &SystemIdGenerator,
                    InputAdmissionLimits::new(256, 1024 * 1024, maximum_pending_inputs_per_session),
                    AdmitInputCommand {
                        session_id: target.session_id,
                        ownership: target.ownership,
                        dedupe_key: discord_input_dedupe_key(target.binding_id, &message_id)?,
                        delivery_mode,
                        content,
                    },
                )?;
                store.complete_discord_message(CompleteDiscordMessageCommit {
                    binding_id: target.binding_id,
                    message_id,
                    disposition: DiscordMessageDisposition::Admitted(outcome.receipt().clone()),
                    completed_at: SystemTime::now(),
                })?;
            }
            DiscordInboundAction::Approval {
                approval_id,
                subject_digest,
                decision,
            } => {
                let result = store.resolve_approval(ResolveApprovalCommit {
                    approval_id,
                    ownership: target.ownership,
                    expected_subject_digest: subject_digest,
                    decision,
                    idempotency_key: format!("discord-approval:{}:{message_id}", target.binding_id),
                    approval_event_id: SystemIdGenerator.generate_event_id(),
                    effect_event_id: SystemIdGenerator.generate_event_id(),
                    correlation_id: SystemIdGenerator.generate_correlation_id(),
                    decided_at: SystemTime::now(),
                });
                let reason = match result {
                    Ok(receipt) if receipt.decision == ApprovalDecision::Approve => {
                        "approval_approved"
                    }
                    Ok(_) => "approval_denied",
                    Err(
                        error @ (EffectLedgerStoreError::Unavailable(_)
                        | EffectLedgerStoreError::InvariantViolation(_)
                        | EffectLedgerStoreError::InvalidEvidence(_)),
                    ) => return Err(DiscordDriverError::Approval(error)),
                    Err(_) => "approval_resolution_rejected",
                };
                store.complete_discord_message(CompleteDiscordMessageCommit {
                    binding_id: target.binding_id,
                    message_id,
                    disposition: DiscordMessageDisposition::Ignored(reason.to_owned()),
                    completed_at: SystemTime::now(),
                })?;
            }
            DiscordInboundAction::Ignore(reason) => {
                store.complete_discord_message(CompleteDiscordMessageCommit {
                    binding_id: target.binding_id,
                    message_id,
                    disposition: DiscordMessageDisposition::Ignored(reason.to_owned()),
                    completed_at: SystemTime::now(),
                })?;
            }
        }
        processed += 1;
    }
    Ok(processed)
}

#[derive(Debug, Eq, PartialEq)]
enum DiscordInboundAction {
    Input {
        delivery_mode: DeliveryMode,
        content: String,
    },
    Approval {
        approval_id: ApprovalId,
        subject_digest: String,
        decision: ApprovalDecision,
    },
    Ignore(&'static str),
}

fn discord_message_action(target: &DiscordPollTarget, message: &Value) -> DiscordInboundAction {
    if message.get("channel_id").and_then(Value::as_str) != Some(target.discord_channel_id.as_str())
    {
        return DiscordInboundAction::Ignore("channel_not_allowed");
    }
    let Some(author) = message.get("author").and_then(Value::as_object) else {
        return DiscordInboundAction::Ignore("missing_sender");
    };
    if author.get("id").and_then(Value::as_str) != Some(target.discord_user_id.as_str())
        || author.get("bot").and_then(Value::as_bool) == Some(true)
        || message.get("webhook_id").is_some()
    {
        return DiscordInboundAction::Ignore("sender_not_allowed");
    }
    if message.get("type").and_then(Value::as_u64) != Some(0) {
        return DiscordInboundAction::Ignore("unsupported_message_type");
    }
    if message
        .get("attachments")
        .and_then(Value::as_array)
        .is_some_and(|attachments| !attachments.is_empty())
    {
        return DiscordInboundAction::Ignore("unsupported_attachment");
    }
    let Some(content) = message.get("content").and_then(Value::as_str) else {
        return DiscordInboundAction::Ignore("missing_message_content");
    };
    if content.is_empty() || content.len() > 8 * 1024 || content.contains('\0') {
        return DiscordInboundAction::Ignore("invalid_text");
    }
    if let Some(action) = discord_approval_action(content) {
        return action;
    }
    match discord_delivery_mode(content) {
        Ok((delivery_mode, content)) => DiscordInboundAction::Input {
            delivery_mode,
            content,
        },
        Err(reason) => DiscordInboundAction::Ignore(reason),
    }
}

fn discord_approval_action(content: &str) -> Option<DiscordInboundAction> {
    let mut fields = content.split_whitespace();
    let decision = match fields.next()? {
        "/approve" => ApprovalDecision::Approve,
        "/deny" => ApprovalDecision::Deny,
        _ => return None,
    };
    let Some(approval_id) = fields
        .next()
        .and_then(|value| value.parse::<ApprovalId>().ok())
    else {
        return Some(DiscordInboundAction::Ignore("invalid_approval_command"));
    };
    let Some(subject_digest) = fields.next().filter(|value| is_sha256_digest(value)) else {
        return Some(DiscordInboundAction::Ignore("invalid_approval_command"));
    };
    if fields.next().is_some() {
        return Some(DiscordInboundAction::Ignore("invalid_approval_command"));
    }
    Some(DiscordInboundAction::Approval {
        approval_id,
        subject_digest: subject_digest.to_owned(),
        decision,
    })
}

fn discord_delivery_mode(content: &str) -> Result<(DeliveryMode, String), &'static str> {
    let Some((command, remainder)) = content.split_once(char::is_whitespace) else {
        return match content {
            "/queue" | "/steer" | "/interrupt" => Err("empty_delivery_control"),
            "/start" | "/help" => Err("help_command"),
            _ => Ok((DeliveryMode::Queue, content.to_owned())),
        };
    };
    let remainder = remainder.trim_start();
    if remainder.is_empty() {
        return Err("empty_delivery_control");
    }
    match command {
        "/queue" => Ok((DeliveryMode::Queue, remainder.to_owned())),
        "/steer" => Ok((DeliveryMode::SteerAtBoundary, remainder.to_owned())),
        "/interrupt" => Ok((DeliveryMode::InterruptThenQueue, remainder.to_owned())),
        _ => Ok((DeliveryMode::Queue, content.to_owned())),
    }
}

fn discord_snowflake_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

fn discord_success_delay(headers: &reqwest::header::HeaderMap) -> Duration {
    if headers
        .get("x-ratelimit-remaining")
        .and_then(|value| value.to_str().ok())
        == Some("0")
    {
        return headers
            .get("x-ratelimit-reset-after")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_discord_rate_limit_seconds)
            .unwrap_or(Duration::from_secs(5));
    }
    Duration::from_secs(1)
}

async fn discord_rate_limit_delay(response: reqwest::Response) -> Duration {
    let header_delay = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_discord_rate_limit_seconds);
    let body_delay = read_discord_response(response, 64 * 1024)
        .await
        .ok()
        .and_then(|body| serde_json::from_slice::<Value>(&body).ok())
        .and_then(|body| body.get("retry_after").and_then(Value::as_f64))
        .and_then(discord_duration_from_seconds);
    header_delay
        .or(body_delay)
        .unwrap_or(Duration::from_secs(5))
}

fn parse_discord_rate_limit_seconds(value: &str) -> Option<Duration> {
    if value.is_empty()
        || value.len() > 32
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return None;
    }
    value
        .parse::<f64>()
        .ok()
        .and_then(discord_duration_from_seconds)
}

fn discord_duration_from_seconds(seconds: f64) -> Option<Duration> {
    if !seconds.is_finite() || !(0.0..=86_400.0).contains(&seconds) {
        return None;
    }
    Duration::try_from_secs_f64(seconds.max(0.05)).ok()
}

#[derive(Debug, ThisError)]
enum DiscordFetchError {
    #[error("Discord credential broker is unavailable")]
    CredentialUnavailable,
    #[error("Discord credential is unavailable")]
    Credential(#[source] ProviderSecretStoreError),
    #[error("Discord credential digest changed")]
    CredentialMismatch,
    #[error("Discord transport is unavailable")]
    Transport,
    #[error("Discord bot token was rejected")]
    Unauthorized,
    #[error("Discord DM access was forbidden")]
    Forbidden,
    #[error("Discord DM channel was not found")]
    NotFound,
    #[error("Discord rate limit was reached")]
    RateLimited(Duration),
    #[error("Discord server failed")]
    Server,
    #[error("Discord returned an unsuccessful response")]
    Http,
    #[error("Discord response exceeded the byte limit")]
    Oversized,
    #[error("Discord response was malformed")]
    Malformed,
    #[error("Discord DM backlog exceeded the bounded lossless pagination window")]
    BacklogExceeded,
}

impl DiscordFetchError {
    const fn code(&self) -> &'static str {
        match self {
            Self::CredentialUnavailable | Self::Credential(_) => "discord_credential_unavailable",
            Self::CredentialMismatch => "discord_credential_mismatch",
            Self::Transport => "discord_transport_unavailable",
            Self::Unauthorized => "discord_unauthorized",
            Self::Forbidden => "discord_forbidden",
            Self::NotFound => "discord_channel_not_found",
            Self::RateLimited(_) => "discord_rate_limited",
            Self::Server => "discord_server_error",
            Self::Http => "discord_http_error",
            Self::Oversized => "discord_response_oversized",
            Self::Malformed => "discord_response_malformed",
            Self::BacklogExceeded => "discord_backlog_exceeded",
        }
    }

    fn retry_delay(&self) -> Duration {
        match self {
            Self::RateLimited(delay) => *delay,
            Self::Unauthorized | Self::Forbidden | Self::NotFound | Self::CredentialMismatch => {
                Duration::from_mins(5)
            }
            _ => Duration::from_secs(5),
        }
    }
}

#[derive(Debug, ThisError)]
enum DiscordDriverError {
    #[error("Discord store lock is unavailable")]
    Lock,
    #[error("Discord blocking worker failed")]
    Join,
    #[error("Discord message is malformed")]
    MalformedMessage,
    #[error(transparent)]
    Store(#[from] DiscordChannelStoreError),
    #[error(transparent)]
    Session(#[from] SessionUseCaseError),
    #[error(transparent)]
    Approval(#[from] EffectLedgerStoreError),
}

struct OutboxChannelRuntime {
    channel_secrets: Arc<FileChannelSecretStore>,
    telegram_credentials: Arc<FileProviderSecretStore>,
    webhook_client: reqwest::Client,
    telegram_client: reqwest::Client,
    telegram_api_base_url: String,
    discord_credentials: Arc<FileProviderSecretStore>,
    discord_client: reqwest::Client,
    discord_rate_limits: Arc<DiscordRateLimitGate>,
    discord_api_base_url: String,
}

async fn outbox_driver(
    store: Arc<Mutex<SqliteStore>>,
    channels: OutboxChannelRuntime,
    owner_id: WorkerId,
    initial_delay: Duration,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    tokio::select! {
        () = tokio::time::sleep(initial_delay) => {}
        _ = shutdown.changed() => return,
    }
    loop {
        match drive_outbox_batch(&store, &channels, owner_id).await {
            Ok(()) => {}
            Err(error) => tracing::error!(%error, "durable outbox delivery failed"),
        }
        tokio::select! {
            () = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => return,
        }
    }
}

struct RoutedOutboxDelivery {
    delivery: OutboxDelivery,
    webhook_target: Option<OutboundWebhookTarget>,
    telegram_target: Option<OutboundTelegramTarget>,
    discord_target: Option<OutboundDiscordTarget>,
    supported: bool,
    valid_payload: bool,
}

enum OutboxDeliveryResult {
    Delivered,
    Failed(String),
    FailedAfter(String, Duration),
    Terminal(String),
    OutcomeUnknown(String),
}

#[derive(Debug, ThisError)]
enum OutboxDriverError {
    #[error("outbox store lock is unavailable")]
    Lock,
    #[error("outbox blocking worker failed")]
    Join,
    #[error(transparent)]
    Outbox(#[from] OutboxUseCaseError),
    #[error(transparent)]
    Channel(#[from] WebhookChannelStoreError),
    #[error(transparent)]
    Telegram(#[from] TelegramChannelStoreError),
    #[error(transparent)]
    Discord(#[from] DiscordChannelStoreError),
    #[error("outbox session resolves to more than one external channel")]
    AmbiguousRoute,
}

async fn drive_outbox_batch(
    store: &Arc<Mutex<SqliteStore>>,
    channels: &OutboxChannelRuntime,
    owner_id: WorkerId,
) -> Result<(), OutboxDriverError> {
    const MAXIMUM_ATTEMPTS: u32 = 8;
    for _ in 0..64 {
        let claim_store = Arc::clone(store);
        let routed = tokio::task::spawn_blocking(move || {
            claim_routed_outbox(&claim_store, owner_id, MAXIMUM_ATTEMPTS)
        })
        .await
        .map_err(|_| OutboxDriverError::Join)??;
        let Some(routed) = routed else {
            return Ok(());
        };
        let result = if let Some(target) = &routed.webhook_target {
            deliver_signed_webhook(
                &channels.webhook_client,
                &channels.channel_secrets,
                target,
                &routed.delivery,
            )
            .await
        } else if let Some(target) = &routed.telegram_target {
            deliver_telegram_message(
                &channels.telegram_client,
                &channels.telegram_credentials,
                &channels.telegram_api_base_url,
                target,
                &routed.delivery,
            )
            .await
        } else if let Some(target) = &routed.discord_target {
            deliver_discord_message(
                &channels.discord_client,
                &channels.discord_credentials,
                &channels.discord_rate_limits,
                &channels.discord_api_base_url,
                target,
                &routed.delivery,
            )
            .await
        } else if routed.supported && routed.valid_payload {
            tracing::debug!(
                outbox_id = %routed.delivery.outbox_id,
                topic = %routed.delivery.topic,
                attempt = routed.delivery.attempt,
                "local durable notification delivered"
            );
            OutboxDeliveryResult::Delivered
        } else {
            OutboxDeliveryResult::Failed(if routed.supported {
                "outbox payload is not a JSON object".to_owned()
            } else {
                format!(
                    "no delivery handler is registered for topic {}",
                    routed.delivery.topic
                )
            })
        };
        let completion_store = Arc::clone(store);
        tokio::task::spawn_blocking(move || {
            finish_outbox_delivery(
                &completion_store,
                owner_id,
                &routed.delivery,
                result,
                MAXIMUM_ATTEMPTS,
            )
        })
        .await
        .map_err(|_| OutboxDriverError::Join)??;
    }
    Ok(())
}

fn claim_routed_outbox(
    store: &Arc<Mutex<SqliteStore>>,
    owner_id: WorkerId,
    maximum_attempts: u32,
) -> Result<Option<RoutedOutboxDelivery>, OutboxDriverError> {
    let mut guard = store.lock().map_err(|_| OutboxDriverError::Lock)?;
    let claim = claim_next_outbox(
        &mut *guard,
        &SystemClock,
        owner_id,
        Duration::from_secs(30),
        maximum_attempts,
    )?;
    let OutboxClaimOutcome::Claimed(delivery) = claim else {
        return Ok(None);
    };
    let payload = serde_json::from_str::<serde_json::Value>(&delivery.payload_json).ok();
    let valid_payload = payload.as_ref().is_some_and(serde_json::Value::is_object);
    let supported = matches!(
        delivery.topic.as_str(),
        "session.input_acknowledgement"
            | "session.input_promoted"
            | "session.input_steered"
            | "session.interrupt_requested"
            | "session.turn_completed"
            | "delegation.completed"
            | "effect.approval_requested"
    );
    let session_id = payload
        .as_ref()
        .and_then(|value| value.get("session_id"))
        .and_then(serde_json::Value::as_str)
        .and_then(|session_id| session_id.parse().ok());
    let webhook_target = session_id
        .map(|session_id| guard.outbound_webhook_target(session_id, &delivery.topic))
        .transpose()?
        .flatten();
    let telegram_target = session_id
        .map(|session_id| guard.outbound_telegram_target(session_id, &delivery.topic))
        .transpose()?
        .flatten();
    let discord_target = session_id
        .map(|session_id| guard.outbound_discord_target(session_id, &delivery.topic))
        .transpose()?
        .flatten();
    let route_count = usize::from(webhook_target.is_some())
        + usize::from(telegram_target.is_some())
        + usize::from(discord_target.is_some());
    if route_count > 1 {
        return Err(OutboxDriverError::AmbiguousRoute);
    }
    Ok(Some(RoutedOutboxDelivery {
        delivery,
        webhook_target,
        telegram_target,
        discord_target,
        supported,
        valid_payload,
    }))
}

async fn deliver_signed_webhook(
    client: &reqwest::Client,
    channel_secrets: &FileChannelSecretStore,
    target: &OutboundWebhookTarget,
    delivery: &OutboxDelivery,
) -> OutboxDeliveryResult {
    let Ok(secret) = channel_secrets.read(target.binding_id) else {
        return OutboxDeliveryResult::Failed("webhook signing secret is unavailable".to_owned());
    };
    if sha256_digest(&secret) != target.secret_digest {
        return OutboxDeliveryResult::Failed("webhook signing secret identity changed".to_owned());
    }
    let Ok(duration) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) else {
        return OutboxDeliveryResult::Failed("webhook delivery clock is invalid".to_owned());
    };
    let Ok(timestamp_ms) = i64::try_from(duration.as_millis()) else {
        return OutboxDeliveryResult::Failed("webhook delivery clock overflowed".to_owned());
    };
    let nonce = format!("{}-{}", delivery.outbox_id, delivery.attempt);
    let Ok(signature) = sign_webhook(
        &secret,
        target.binding_id,
        timestamp_ms,
        &nonce,
        delivery.payload_json.as_bytes(),
    ) else {
        return OutboxDeliveryResult::Failed("webhook signing evidence is invalid".to_owned());
    };
    let result = client
        .post(&target.callback_url)
        .header("content-type", "application/json")
        .header("x-mealy-binding-id", target.binding_id.to_string())
        .header("x-mealy-delivery-id", delivery.outbox_id.to_string())
        .header("x-mealy-topic", &delivery.topic)
        .header("x-mealy-timestamp", timestamp_ms.to_string())
        .header("x-mealy-nonce", nonce)
        .header("x-mealy-signature", signature)
        .body(delivery.payload_json.clone())
        .send()
        .await;
    match result {
        Ok(response) if response.status().is_success() => {
            tracing::debug!(
                outbox_id = %delivery.outbox_id,
                binding_id = %target.binding_id,
                topic = %delivery.topic,
                attempt = delivery.attempt,
                "signed webhook notification delivered"
            );
            OutboxDeliveryResult::Delivered
        }
        Ok(response) => OutboxDeliveryResult::Failed(format!(
            "webhook callback returned HTTP {}",
            response.status().as_u16()
        )),
        Err(_) => OutboxDeliveryResult::Failed("webhook callback was unavailable".to_owned()),
    }
}

async fn deliver_telegram_message(
    client: &reqwest::Client,
    credentials: &Arc<FileProviderSecretStore>,
    api_base_url: &str,
    target: &OutboundTelegramTarget,
    delivery: &OutboxDelivery,
) -> OutboxDeliveryResult {
    let credential_store = Arc::clone(credentials);
    let secret_id = target.token_secret_id.clone();
    let Ok(Ok(token)) =
        tokio::task::spawn_blocking(move || credential_store.read(&secret_id)).await
    else {
        return OutboxDeliveryResult::Failed("Telegram bot credential is unavailable".to_owned());
    };
    if sha256_digest(token.as_bytes()) != target.token_digest
        || backend::validate_telegram_bot_token(&token).is_err()
    {
        return OutboxDeliveryResult::Failed("Telegram bot credential identity changed".to_owned());
    }
    let text = match render_telegram_outbox(delivery) {
        Ok(text) => text,
        Err(error) => return OutboxDeliveryResult::Failed(error.to_owned()),
    };
    let url = format!(
        "{}/bot{}/sendMessage",
        api_base_url.trim_end_matches('/'),
        token.as_str()
    );
    let result = client
        .post(url)
        .json(&json!({
            "chat_id": target.telegram_chat_id,
            "text": text,
            "disable_web_page_preview": true,
        }))
        .send()
        .await;
    match result {
        Ok(response) if response.status().is_success() => {
            let Ok(body) = read_telegram_response(response, 64 * 1024).await else {
                return OutboxDeliveryResult::OutcomeUnknown(
                    "Telegram sendMessage acknowledgement could not be read; automatic retry is suppressed"
                        .to_owned(),
                );
            };
            match classify_telegram_send_acknowledgement(&body, target.telegram_chat_id) {
                TelegramSendAcknowledgement::Delivered => {}
                TelegramSendAcknowledgement::Rejected => {
                    return OutboxDeliveryResult::Failed(
                        "Telegram sendMessage rejected the request".to_owned(),
                    );
                }
                TelegramSendAcknowledgement::Ambiguous => {
                    return OutboxDeliveryResult::OutcomeUnknown(
                        "Telegram sendMessage acknowledgement was invalid; automatic retry is suppressed"
                            .to_owned(),
                    );
                }
            }
            tracing::debug!(
                outbox_id = %delivery.outbox_id,
                binding_id = %target.binding_id,
                topic = %delivery.topic,
                attempt = delivery.attempt,
                "Telegram notification delivered"
            );
            OutboxDeliveryResult::Delivered
        }
        Ok(response) => OutboxDeliveryResult::Failed(format!(
            "Telegram sendMessage returned HTTP {}",
            response.status().as_u16()
        )),
        Err(_) => OutboxDeliveryResult::OutcomeUnknown(
            "Telegram sendMessage outcome is unknown; automatic retry is suppressed".to_owned(),
        ),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TelegramSendAcknowledgement {
    Delivered,
    Rejected,
    Ambiguous,
}

fn classify_telegram_send_acknowledgement(
    body: &[u8],
    expected_chat_id: i64,
) -> TelegramSendAcknowledgement {
    let Ok(envelope) = serde_json::from_slice::<Value>(body) else {
        return TelegramSendAcknowledgement::Ambiguous;
    };
    match envelope.get("ok").and_then(Value::as_bool) {
        Some(false) => TelegramSendAcknowledgement::Rejected,
        Some(true)
            if envelope
                .get("result")
                .and_then(|result| result.get("message_id"))
                .and_then(Value::as_i64)
                .is_some()
                && envelope
                    .get("result")
                    .and_then(|result| result.get("chat"))
                    .and_then(|chat| chat.get("id"))
                    .and_then(Value::as_i64)
                    == Some(expected_chat_id) =>
        {
            TelegramSendAcknowledgement::Delivered
        }
        Some(true) | None => TelegramSendAcknowledgement::Ambiguous,
    }
}

#[allow(clippy::too_many_lines)]
async fn deliver_discord_message(
    client: &reqwest::Client,
    credentials: &Arc<FileProviderSecretStore>,
    rate_limits: &Arc<DiscordRateLimitGate>,
    api_base_url: &str,
    target: &OutboundDiscordTarget,
    delivery: &OutboxDelivery,
) -> OutboxDeliveryResult {
    const USER_AGENT: &str = "DiscordBot (https://github.com/Amekn/project_mealy, 0.1.0)";
    let credential_store = Arc::clone(credentials);
    let secret_id = target.token_secret_id.clone();
    let Ok(Ok(token)) =
        tokio::task::spawn_blocking(move || credential_store.read(&secret_id)).await
    else {
        return OutboxDeliveryResult::Terminal("Discord bot credential is unavailable".to_owned());
    };
    if sha256_digest(token.as_bytes()) != target.token_digest
        || backend::validate_discord_bot_token(&token).is_err()
    {
        return OutboxDeliveryResult::Terminal(
            "Discord bot credential identity changed".to_owned(),
        );
    }
    let text = match render_discord_outbox(delivery) {
        Ok(text) => text,
        Err(error) => return OutboxDeliveryResult::Terminal(error.to_owned()),
    };
    let digest = sha256_digest(delivery.outbox_id.to_string().as_bytes());
    let nonce = format!("m{}", &digest[..24]);
    let url = format!(
        "{}/channels/{}/messages",
        api_base_url.trim_end_matches('/'),
        target.discord_channel_id
    );
    rate_limits.wait().await;
    let result = client
        .post(url)
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bot {}", token.as_str()),
        )
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .json(&json!({
            "content": text,
            "nonce": nonce,
            "enforce_nonce": true,
            "tts": false,
            "flags": 4,
            "allowed_mentions": {"parse": []},
        }))
        .send()
        .await;
    let Ok(response) = result else {
        return OutboxDeliveryResult::OutcomeUnknown(
            "Discord Create Message outcome is unknown; automatic retry is suppressed".to_owned(),
        );
    };
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let delay = discord_rate_limit_delay(response).await;
        rate_limits.defer(delay).await;
        return OutboxDeliveryResult::FailedAfter(
            "Discord Create Message was rate limited".to_owned(),
            delay,
        );
    }
    if !response.status().is_success() {
        return if response.status().is_server_error() {
            OutboxDeliveryResult::OutcomeUnknown(format!(
                "Discord Create Message returned HTTP {}; outcome is unknown and automatic retry is suppressed",
                response.status().as_u16()
            ))
        } else {
            OutboxDeliveryResult::Terminal(format!(
                "Discord Create Message returned terminal HTTP {}",
                response.status().as_u16()
            ))
        };
    }
    let reset_delay = discord_success_delay(response.headers());
    if reset_delay > Duration::from_secs(1) {
        rate_limits.defer(reset_delay).await;
    }
    let Ok(body) = read_discord_response(response, 128 * 1024).await else {
        return OutboxDeliveryResult::OutcomeUnknown(
            "Discord Create Message acknowledgement could not be read; automatic retry is suppressed"
                .to_owned(),
        );
    };
    let acknowledgement = serde_json::from_slice::<Value>(&body).ok();
    let delivered = acknowledgement.as_ref().is_some_and(|message| {
        message
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(validate_discord_snowflake)
            && message.get("channel_id").and_then(Value::as_str)
                == Some(target.discord_channel_id.as_str())
            && message
                .get("author")
                .and_then(|author| author.get("id"))
                .and_then(Value::as_str)
                == Some(target.bot_user_id.as_str())
            && message
                .get("author")
                .and_then(|author| author.get("bot"))
                .and_then(Value::as_bool)
                == Some(true)
            && message.get("nonce").and_then(Value::as_str) == Some(nonce.as_str())
    });
    if !delivered {
        return OutboxDeliveryResult::OutcomeUnknown(
            "Discord Create Message acknowledgement did not prove destination, bot, nonce, and message identity; automatic retry is suppressed"
                .to_owned(),
        );
    }
    tracing::debug!(
        outbox_id = %delivery.outbox_id,
        binding_id = %target.binding_id,
        topic = %delivery.topic,
        attempt = delivery.attempt,
        "Discord notification delivered"
    );
    OutboxDeliveryResult::Delivered
}

fn render_discord_outbox(delivery: &OutboxDelivery) -> Result<String, &'static str> {
    let payload: Value =
        serde_json::from_str(&delivery.payload_json).map_err(|_| "Discord payload is invalid")?;
    let payload = payload
        .as_object()
        .ok_or("Discord payload is not an object")?;
    let text = match delivery.topic.as_str() {
        "session.input_acknowledgement" => "Mealy accepted your message.".to_owned(),
        "session.input_promoted" => "Mealy started working on your message.".to_owned(),
        "session.input_steered" => "Mealy attached your steering update.".to_owned(),
        "session.interrupt_requested" => {
            "Mealy recorded the interruption and queued your replacement.".to_owned()
        }
        "session.turn_completed" => {
            let status = payload
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("completed");
            let summary = payload
                .get("summary")
                .and_then(Value::as_str)
                .filter(|summary| !summary.is_empty())
                .unwrap_or("The turn completed without a textual summary.");
            format!("Mealy ({status}):\n{summary}")
        }
        "effect.approval_requested" => {
            let approval_id = payload
                .get("approval_id")
                .and_then(Value::as_str)
                .ok_or("Discord approval ID is absent")?;
            let subject_digest = payload
                .get("subject_digest")
                .and_then(Value::as_str)
                .ok_or("Discord approval subject is absent")?;
            let tool_id = payload
                .get("tool_id")
                .and_then(Value::as_str)
                .ok_or("Discord approval tool is absent")?;
            let arguments = payload
                .get("normalized_arguments")
                .ok_or("Discord approval arguments are absent")?;
            let targets = payload
                .get("target_resources")
                .ok_or("Discord approval targets are absent")?;
            format!(
                "Mealy approval required\nTool: {tool_id}\nTargets: {targets}\nArguments: {arguments}\nSubject: {subject_digest}\n\nApprove: /approve {approval_id} {subject_digest}\nDeny: /deny {approval_id} {subject_digest}"
            )
        }
        _ => return Err("Discord topic is unsupported"),
    };
    Ok(truncate_discord_message(&text))
}

fn truncate_discord_message(text: &str) -> String {
    const MAXIMUM_CHARACTERS: usize = 2_000;
    const MARKER: &str = "\n… [truncated; inspect the session timeline for the full result]";
    if text.chars().count() <= MAXIMUM_CHARACTERS {
        return text.to_owned();
    }
    let retained = MAXIMUM_CHARACTERS.saturating_sub(MARKER.chars().count());
    let mut output = text.chars().take(retained).collect::<String>();
    output.push_str(MARKER);
    output
}

fn render_telegram_outbox(delivery: &OutboxDelivery) -> Result<String, &'static str> {
    let payload: Value =
        serde_json::from_str(&delivery.payload_json).map_err(|_| "Telegram payload is invalid")?;
    let payload = payload
        .as_object()
        .ok_or("Telegram payload is not an object")?;
    let text = match delivery.topic.as_str() {
        "session.input_acknowledgement" => "Mealy accepted your message.".to_owned(),
        "session.input_promoted" => "Mealy started working on your message.".to_owned(),
        "session.input_steered" => "Mealy attached your steering update.".to_owned(),
        "session.interrupt_requested" => {
            "Mealy recorded the interruption and queued your replacement.".to_owned()
        }
        "session.turn_completed" => {
            let status = payload
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("completed");
            let summary = payload
                .get("summary")
                .and_then(Value::as_str)
                .filter(|summary| !summary.is_empty())
                .unwrap_or("The turn completed without a textual summary.");
            format!("Mealy ({status}):\n{summary}")
        }
        "effect.approval_requested" => {
            let approval_id = payload
                .get("approval_id")
                .and_then(Value::as_str)
                .ok_or("Telegram approval ID is absent")?;
            let subject_digest = payload
                .get("subject_digest")
                .and_then(Value::as_str)
                .ok_or("Telegram approval subject is absent")?;
            let tool_id = payload
                .get("tool_id")
                .and_then(Value::as_str)
                .ok_or("Telegram approval tool is absent")?;
            let arguments = payload
                .get("normalized_arguments")
                .ok_or("Telegram approval arguments are absent")?;
            let targets = payload
                .get("target_resources")
                .ok_or("Telegram approval targets are absent")?;
            format!(
                "Mealy approval required\nTool: {tool_id}\nTargets: {targets}\nArguments: {arguments}\nSubject: {subject_digest}\n\nApprove: /approve {approval_id} {subject_digest}\nDeny: /deny {approval_id} {subject_digest}"
            )
        }
        _ => return Err("Telegram topic is unsupported"),
    };
    Ok(truncate_telegram_message(&text))
}

fn truncate_telegram_message(text: &str) -> String {
    const MAXIMUM_CHARACTERS: usize = 4_096;
    const MARKER: &str = "\n… [truncated; inspect the session timeline for the full result]";
    if text.chars().count() <= MAXIMUM_CHARACTERS {
        return text.to_owned();
    }
    let retained = MAXIMUM_CHARACTERS.saturating_sub(MARKER.chars().count());
    let mut output = text.chars().take(retained).collect::<String>();
    output.push_str(MARKER);
    output
}

fn finish_outbox_delivery(
    store: &Arc<Mutex<SqliteStore>>,
    owner_id: WorkerId,
    delivery: &OutboxDelivery,
    result: OutboxDeliveryResult,
    maximum_attempts: u32,
) -> Result<(), OutboxDriverError> {
    let mut guard = store.lock().map_err(|_| OutboxDriverError::Lock)?;
    match result {
        OutboxDeliveryResult::Delivered => {
            complete_outbox(&mut *guard, &SystemClock, owner_id, delivery.outbox_id)?;
        }
        OutboxDeliveryResult::Failed(error) => {
            let retry_delay = exponential_retry_delay(
                delivery,
                Duration::from_millis(100),
                Duration::from_secs(30),
            )?;
            retry_outbox(
                &mut *guard,
                &SystemClock,
                owner_id,
                delivery,
                maximum_attempts,
                retry_delay,
                error,
            )?;
        }
        OutboxDeliveryResult::FailedAfter(error, retry_delay) => {
            retry_outbox(
                &mut *guard,
                &SystemClock,
                owner_id,
                delivery,
                maximum_attempts,
                retry_delay,
                error,
            )?;
        }
        OutboxDeliveryResult::Terminal(error) | OutboxDeliveryResult::OutcomeUnknown(error) => {
            retry_outbox(
                &mut *guard,
                &SystemClock,
                owner_id,
                delivery,
                delivery.attempt,
                Duration::from_millis(1),
                error,
            )?;
        }
    }
    Ok(())
}

async fn lease_reaper_driver(
    store: Arc<Mutex<SqliteStore>>,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let recovery_store = Arc::clone(&store);
        match tokio::task::spawn_blocking(move || {
            let mut guard = recovery_store.lock().map_err(|_| {
                mealy_application::StartupRecoveryStoreError::Unavailable(
                    "store lock poisoned".to_owned(),
                )
            })?;
            recover_expired_leases(&mut *guard, &SystemClock, &SystemIdGenerator, 64)
        })
        .await
        {
            Ok(Ok(summary)) if summary.expired_leases != 0 => tracing::warn!(
                expired_leases = summary.expired_leases,
                requeued_runs = summary.requeued_runs,
                waiting_runs = summary.waiting_runs,
                "live lease recovery classified abandoned work"
            ),
            Ok(Ok(_)) => {}
            Ok(Err(error)) => tracing::error!(%error, "live lease recovery failed"),
            Err(error) => tracing::error!(%error, "live lease recovery task failed"),
        }
        tokio::select! {
            () = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => return,
        }
    }
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, Box<dyn Error + Send + Sync>> {
    let duration = time.duration_since(SystemTime::UNIX_EPOCH)?;
    Ok(i64::try_from(duration.as_millis())?)
}

#[cfg(test)]
mod schedule_driver_tests {
    use super::{
        DiscordInboundAction, TelegramInboundAction, TelegramSendAcknowledgement,
        classify_telegram_send_acknowledgement, discord_approval_action, discord_message_action,
        discord_success_delay, drive_schedule_batch, render_discord_outbox, render_telegram_outbox,
        schedule_now_ms, telegram_approval_action,
    };
    use mealy_application::{
        CreateScheduleCommit, DiscordPollTarget, MissedRunPolicy, OutboxDelivery, OwnershipContext,
        ScheduleOverlapPolicy, ScheduleRunStatus, ScheduleStore, create_session,
        next_schedule_occurrence_ms,
    };
    use mealy_domain::{
        ApprovalDecision, ApprovalId, ChannelBindingId, CorrelationId, EventId, OutboxId,
        PrincipalId, ScheduleId, WorkerId,
    };
    use mealy_infrastructure::{SqliteStore, SystemClock, SystemIdGenerator};
    use std::sync::{Arc, Mutex};

    #[test]
    fn due_schedule_is_admitted_once_and_advances_with_history() {
        let mut store = SqliteStore::open_in_memory(0).expect("schedule store");
        let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
        let session_id = create_session(&mut store, &SystemClock, &SystemIdGenerator, ownership)
            .expect("destination session");
        let now = schedule_now_ms(0).expect("current schedule time");
        let created_at_ms = now - 120_000;
        let next_due_at_ms =
            next_schedule_occurrence_ms("* * * * *", "Pacific/Auckland", created_at_ms)
                .expect("due cursor");
        assert!(next_due_at_ms <= now);
        let schedule = store
            .create_schedule(CreateScheduleCommit {
                schedule_id: ScheduleId::new(),
                ownership,
                session_id,
                name: "driver proof".to_owned(),
                prompt: "Run the durable schedule proof.".to_owned(),
                cron_expression: "* * * * *".to_owned(),
                timezone: "Pacific/Auckland".to_owned(),
                missed_run_policy: MissedRunPolicy::Latest,
                overlap_policy: ScheduleOverlapPolicy::SkipIfRunning,
                misfire_grace_ms: 60_000,
                approval_required_actions_allowed: false,
                next_due_at_ms,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at_ms,
            })
            .expect("create due schedule");
        let store = Arc::new(Mutex::new(store));
        assert_eq!(
            drive_schedule_batch(&store, WorkerId::new(), 1_024, 0).expect("drive schedule"),
            1
        );
        assert_eq!(
            drive_schedule_batch(&store, WorkerId::new(), 1_024, 0).expect("idempotent scan"),
            0
        );
        let guard = store.lock().expect("schedule store lock");
        let history = guard
            .schedule_runs(ownership, schedule.schedule_id, 10)
            .expect("schedule history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, ScheduleRunStatus::Admitted);
        assert!(history[0].inbox_entry_id.is_some());
        assert!(
            guard
                .schedule(ownership, schedule.schedule_id)
                .expect("advanced schedule")
                .next_due_at_ms
                > Some(now)
        );
    }

    #[test]
    fn telegram_approval_commands_bind_the_exact_subject() {
        let approval_id = ApprovalId::new();
        let digest = "a".repeat(64);
        assert_eq!(
            telegram_approval_action(&format!(
                "/approve@mealy_process_test_bot {approval_id} {digest}"
            )),
            Some(TelegramInboundAction::Approval {
                approval_id,
                subject_digest: digest.clone(),
                decision: ApprovalDecision::Approve,
            })
        );
        assert_eq!(
            telegram_approval_action(&format!("/deny {approval_id} {digest}")),
            Some(TelegramInboundAction::Approval {
                approval_id,
                subject_digest: digest.clone(),
                decision: ApprovalDecision::Deny,
            })
        );
        assert_eq!(
            telegram_approval_action(&format!("/approve {approval_id} {digest} extra")),
            Some(TelegramInboundAction::Ignore("invalid_approval_command"))
        );
        assert_eq!(telegram_approval_action("ordinary message"), None);
    }

    #[test]
    fn telegram_approval_notification_renders_round_trip_commands() {
        let approval_id = ApprovalId::new();
        let effect_id = mealy_domain::EffectId::new();
        let digest = "b".repeat(64);
        let delivery = OutboxDelivery {
            outbox_id: OutboxId::new(),
            topic: "effect.approval_requested".to_owned(),
            payload_json: serde_json::json!({
                "session_id": mealy_domain::SessionId::new(),
                "approval_id": approval_id,
                "effect_id": effect_id,
                "subject_digest": digest,
                "tool_id": "workspace.create_file",
                "normalized_arguments": {"path": "notes/today.md"},
                "target_resources": ["workspace://notes/today.md"],
                "expires_at_ms": 1_800_000_000_000_i64,
            })
            .to_string(),
            attempt: 1,
        };
        let rendered = render_telegram_outbox(&delivery).expect("render approval");
        assert!(rendered.contains("Tool: workspace.create_file"));
        assert!(rendered.contains("Targets: [\"workspace://notes/today.md\"]"));
        assert!(rendered.contains(&format!("Approve: /approve {approval_id} {digest}")));
        assert!(rendered.contains(&format!("Deny: /deny {approval_id} {digest}")));
    }

    #[test]
    fn telegram_send_acknowledgement_must_prove_the_destination() {
        assert_eq!(
            classify_telegram_send_acknowledgement(
                br#"{"ok":true,"result":{"message_id":42,"chat":{"id":8001}}}"#,
                8001,
            ),
            TelegramSendAcknowledgement::Delivered
        );
        assert_eq!(
            classify_telegram_send_acknowledgement(br#"{"ok":false}"#, 8001),
            TelegramSendAcknowledgement::Rejected
        );
        assert_eq!(
            classify_telegram_send_acknowledgement(
                br#"{"ok":true,"result":{"message_id":42,"chat":{"id":9999}}}"#,
                8001,
            ),
            TelegramSendAcknowledgement::Ambiguous
        );
        assert_eq!(
            classify_telegram_send_acknowledgement(b"not-json", 8001),
            TelegramSendAcknowledgement::Ambiguous
        );
    }

    #[test]
    fn discord_dm_parser_binds_channel_sender_and_exact_approval_subject() {
        let principal_id = PrincipalId::new();
        let binding_id = ChannelBindingId::new();
        let target = DiscordPollTarget {
            binding_id,
            discord_user_id: "1001".to_owned(),
            discord_channel_id: "2001".to_owned(),
            bot_user_id: "3001".to_owned(),
            session_id: mealy_domain::SessionId::new(),
            ownership: OwnershipContext::new(principal_id, binding_id),
            token_secret_id: format!("discord.{binding_id}"),
            token_digest: "a".repeat(64),
            after_message_id: None,
        };
        let message = serde_json::json!({
            "id": "4001",
            "channel_id": "2001",
            "author": {"id": "1001", "bot": false},
            "content": "/steer check the newest evidence",
            "type": 0,
            "attachments": [],
        });
        assert_eq!(
            discord_message_action(&target, &message),
            DiscordInboundAction::Input {
                delivery_mode: mealy_domain::DeliveryMode::SteerAtBoundary,
                content: "check the newest evidence".to_owned(),
            }
        );
        let mut attacker = message;
        attacker["author"]["id"] = serde_json::json!("1002");
        assert_eq!(
            discord_message_action(&target, &attacker),
            DiscordInboundAction::Ignore("sender_not_allowed")
        );

        let approval_id = ApprovalId::new();
        let digest = "b".repeat(64);
        assert_eq!(
            discord_approval_action(&format!("/approve {approval_id} {digest}")),
            Some(DiscordInboundAction::Approval {
                approval_id,
                subject_digest: digest,
                decision: ApprovalDecision::Approve,
            })
        );
    }

    #[test]
    fn discord_rendering_and_rate_headers_are_bounded() {
        let delivery = OutboxDelivery {
            outbox_id: OutboxId::new(),
            topic: "session.turn_completed".to_owned(),
            payload_json: serde_json::json!({
                "session_id": mealy_domain::SessionId::new(),
                "status": "succeeded",
                "summary": format!("@everyone {}", "x".repeat(4_000)),
            })
            .to_string(),
            attempt: 1,
        };
        let rendered = render_discord_outbox(&delivery).expect("render Discord message");
        assert_eq!(rendered.chars().count(), 2_000);
        assert!(rendered.contains("@everyone"));
        assert!(rendered.ends_with("inspect the session timeline for the full result]"));

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-ratelimit-remaining", "0".parse().expect("remaining"));
        headers.insert(
            "x-ratelimit-reset-after",
            "2.75".parse().expect("reset after"),
        );
        assert_eq!(
            discord_success_delay(&headers),
            std::time::Duration::from_millis(2_750)
        );
    }
}
