//! Mealy's trusted daemon composition root.

mod agent;
mod backend;
mod config;
mod effect_runtime;
#[path = "../../../crates/mealy-infrastructure/src/bin/mealy-fixture-worker.rs"]
mod fixture_worker_process;

use agent::{AgentDriverPolicy, BuiltinPhaseTwoProvider, drive_one_agent_run, phase_two_read_tool};
use backend::{DrainController, RuntimeBackend, RuntimeOperationalConfig};
use clap::Parser;
use config::{
    acquire_instance_lock, archive_effective_daemon_config, load_forced_shutdown_marker,
    load_or_create_daemon_config, load_or_create_identity, remove_forced_shutdown_marker,
    write_connection_info, write_forced_shutdown_marker,
};
use effect_runtime::PhaseThreeRuntime;
use mealy_api::{ApiAuth, ApiConfig, AuthenticatedIdentity, router_with_shutdown};
use mealy_application::{
    BeginDaemonRunCommit, CompleteDaemonRunCommit, DaemonRunStatus, IdGenerator, OperationalStore,
    OutboundWebhookTarget, OutboxClaimOutcome, OutboxDelivery, OutboxUseCaseError,
    OwnershipContext, PromotionDefaults, WebhookChannelStore, WebhookChannelStoreError,
    claim_next_outbox, complete_outbox, exponential_retry_delay, pending_promotion_sessions,
    promote_next_input, recover_expired_leases, recover_extension_invocations, recover_startup,
    retry_outbox, sha256_digest, sign_webhook,
};
use mealy_domain::{CorrelationId, WorkerId};
use mealy_infrastructure::{
    FileArtifactBlobStore, FileChannelSecretStore, LATEST_SCHEMA_VERSION, SqliteStore, StoreError,
    SystemClock, SystemIdGenerator, create_pre_migration_backup, inspect_existing_schema_version,
    preserve_forensic_database,
};
use std::{
    collections::BTreeMap,
    error::Error,
    net::SocketAddr,
    path::PathBuf,
    process::ExitCode,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use thiserror::Error as ThisError;
use tokio::sync::watch;

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
}

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
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
    let provider = Arc::new(BuiltinPhaseTwoProvider::new(
        Duration::from_millis(arguments.fake_provider_delay_ms),
        daemon_config.maximum_provider_requests(),
        daemon_config.provider_requests_per_minute(),
    ));
    let read_tool = Arc::new(phase_two_read_tool()?);
    let effect_runtime = if arguments.safe_mode {
        tracing::warn!("safe mode enabled; mutation and background dispatch are disabled");
        None
    } else {
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
    };
    let store = Arc::new(Mutex::new(store));
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let drain_controller = Arc::new(DrainController::new(
        shutdown_sender.clone(),
        start_id,
        daemon_config.drain_deadline_ms(),
    ));
    let sandbox_available = effect_runtime.is_some();
    let backend = Arc::new(RuntimeBackend::new(
        Arc::clone(&store),
        Arc::clone(&artifacts),
        Arc::clone(&channel_secrets),
        RuntimeOperationalConfig {
            home: arguments.home.clone(),
            artifact_gc_minimum_age_hours: daemon_config.artifact_gc_minimum_age_hours(),
            maximum_pending_inputs_per_session: daemon_config.maximum_pending_inputs_per_session(),
            maximum_extension_invocations: daemon_config.maximum_extension_invocations(),
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
    let promotion_defaults =
        PromotionDefaults::new("assistant", daemon_config.agent_loop_limits())?;
    let promotion = (!arguments.safe_mode).then(|| {
        tokio::spawn(promotion_driver(
            Arc::clone(&store),
            promotion_defaults,
            Duration::from_millis(arguments.promotion_delay_ms),
            Duration::from_millis(arguments.promotion_interval_ms.max(1)),
            shutdown_receiver.clone(),
        ))
    });
    let outbox = (!arguments.safe_mode).then(|| {
        tokio::spawn(outbox_driver(
            Arc::clone(&store),
            Arc::clone(&channel_secrets),
            webhook_client,
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
    provider: Arc<BuiltinPhaseTwoProvider>,
    tool: Arc<mealy_infrastructure::FixtureReadTool>,
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

async fn outbox_driver(
    store: Arc<Mutex<SqliteStore>>,
    channel_secrets: Arc<FileChannelSecretStore>,
    webhook_client: reqwest::Client,
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
        match drive_outbox_batch(&store, &channel_secrets, &webhook_client, owner_id).await {
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
    target: Option<OutboundWebhookTarget>,
    supported: bool,
    valid_payload: bool,
}

enum OutboxDeliveryResult {
    Delivered,
    Failed(String),
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
}

async fn drive_outbox_batch(
    store: &Arc<Mutex<SqliteStore>>,
    channel_secrets: &Arc<FileChannelSecretStore>,
    webhook_client: &reqwest::Client,
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
        let result = if let Some(target) = &routed.target {
            deliver_signed_webhook(webhook_client, channel_secrets, target, &routed.delivery).await
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
    );
    let target = payload
        .as_ref()
        .and_then(|value| value.get("session_id"))
        .and_then(serde_json::Value::as_str)
        .and_then(|session_id| session_id.parse().ok())
        .map(|session_id| guard.outbound_webhook_target(session_id, &delivery.topic))
        .transpose()?
        .flatten();
    Ok(Some(RoutedOutboxDelivery {
        delivery,
        target,
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
