//! Local administrative and scripting client for Mealy.

mod dashboard;
mod lifecycle;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{CommandFactory as _, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use eventsource_stream::{EventStreamError, Eventsource};
use futures_util::StreamExt;
use mealy_application::{
    BrowserConfig, CancellationProbe, McpServerConfig, McpServerDiscovery, McpToolGrant,
    MessageRole, ModelProvider, NormalizedMessage, ProviderConfig, ProviderCredentialReference,
    ProviderRequest, ProviderResponse, SubscriptionCliClient, WebAccessConfig, WebSearchConfig,
    default_daemon_config_document, is_sha256_digest, sha256_digest, valid_provider_secret_id,
    validate_discord_snowflake, validate_mcp_server_set, validate_provider_base_url,
    validate_provider_chain,
};
use mealy_domain::{
    AttemptId, ContextManifestId, RunId, ScheduleId, SkillAsset, SkillToolRequirement,
};
use mealy_infrastructure::{
    BrowserBundleError, BrowserHostError, FileProviderSecretStore, InspectedSkillPackage,
    MAXIMUM_ACTIVE_SKILL_INSTRUCTION_BYTES, MAXIMUM_ACTIVE_SKILL_RESOURCE_BYTES, McpHostError,
    ProviderSecretStoreError, SubscriptionCliProvider, SubscriptionCliSettings, activate_backup,
    activate_migration_backup, browser_worker_main, discover_mcp_stdio_server,
    inspect_browser_bundle, inspect_skill_package, inspect_subscription_cli_executable,
    is_trusted_system_executable, mcp_stdio_launcher_main, probe_browser_bundle_product,
    publish_browser_bundle, publish_skill_package, verify_browser_runtime_installation,
};
use mealy_protocol::{
    API_VERSION, AdminMetricsResponse, AdminStatusResponse, AdminUsageReportResponse,
    ApiErrorResponse, ApprovalDecisionCommand, ApprovalResolutionReceipt, ApprovalResponse,
    BackupActivationResponse, BackupResponse, BackupVerificationResponse, CancelTaskRequest,
    CompactionResponse, ControlTaskRequest, CorrectMemoryRequest, CreateBackupRequest,
    CreateCompactionRequest, CreateDiscordChannelRequest, CreateExportRequest,
    CreateScheduleRequest, CreateSessionRequest, CreateSessionResponse,
    CreateTelegramChannelRequest, CreateWebhookChannelRequest, CreateWebhookChannelResponse,
    DelegationResponse, DelegationsResponse, DeliveryMode, DiscordChannelResponse,
    DiscordChannelsResponse, DoctorResponse, DrainDaemonRequest, DrainDaemonResponse,
    EffectAttemptResponse, EffectReconciliationReceipt, EffectResponse, EnableExtensionRequest,
    ExportKindRequest, ExportResponse, ExtensionInvocationResponse, ExtensionLifecycleRequest,
    ExtensionMountGrantCommand, ExtensionResponse, ExtensionsResponse, GarbageCollectionResponse,
    HealthResponse, InputAdmissionResponse, InstallExtensionRequest, InvokeExtensionRequest,
    LocalConnectionInfo, MemoriesResponse, MemoryCategoryCommand, MemoryIndexRebuildResponse,
    MemoryLifecycleRequest, MemoryPromotionAuthorizationCommand, MemoryResponse,
    MemoryRetentionCommand, MemorySearchResponse, MemorySensitivityCommand, MemorySourceCommand,
    MemoryStatusResponse, MigrationBackupActivationResponse, MissedRunPolicyCommand,
    PendingApprovalsResponse, PromoteMemoryRequest, ProposeMemoryRequest, ReadinessResponse,
    RebuildMemoryIndexRequest, ReconcileEffectRequest, ReconciliationOutcomeCommand,
    ResolveApprovalRequest, RevokeDiscordChannelRequest, RevokeTelegramChannelRequest,
    RevokeWebhookChannelRequest, RunGarbageCollectionRequest, ScheduleLifecycleRequest,
    ScheduleOverlapPolicyCommand, ScheduleResponse, ScheduleRunsResponse, SchedulesResponse,
    SessionSearchResponse, SessionStatusResponse, SessionsResponse, SetMemoryPinRequest,
    StageExtensionManifestRequest, SubmitInputRequest, TaskCancellationReceipt, TaskControlReceipt,
    TaskReplayResponse, TaskResponse, TaskStatus, TelegramChannelResponse,
    TelegramChannelsResponse, TimelineEvent, TimelinePageResponse, VerifyBackupRequest,
    WebhookChannelResponse, WebhookChannelsResponse,
};
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{BufRead, Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, ExitCode, Stdio},
    time::{Duration, SystemTime},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

const DAEMON_CONFIG_KEYS: [&str; 9] = [
    "agentLoopLimits",
    "artifactGcMinimumAgeHours",
    "concurrencyLimits",
    "drainDeadlineMs",
    "forensicBackupOnOpenFailure",
    "formatVersion",
    "maximumPendingInputsPerSession",
    "provider",
    "retentionPolicy",
];
const DAEMON_OPTIONAL_CONFIG_KEYS: [&str; 7] = [
    "browser",
    "commandTools",
    "mcpServers",
    "providerFallbacks",
    "skills",
    "webAccess",
    "workspaceRoots",
];
const CHAT_INPUT_CHANNEL_CAPACITY: usize = 32;
const CHAT_UPDATE_CHANNEL_CAPACITY: usize = 256;
const CHAT_MAXIMUM_TRACKED_TURNS: usize = 64;
const CHAT_MAXIMUM_RESUME_EVENTS: usize = 100_000;
const CHAT_MEMORY_NO_WORKSPACE: &str = "mealy://assistant/no-workspace";
const CHAT_MEMORY_GRANTED_WORKSPACES: &str = "mealy://assistant/granted-workspaces";
const DAEMON_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const DAEMON_LONG_REQUEST_TIMEOUT: Duration = Duration::from_mins(10);
const MAXIMUM_DAEMON_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_TIMELINE_SSE_EVENT_BYTES: usize = MAXIMUM_DAEMON_RESPONSE_BYTES;
const MAXIMUM_CONNECTION_DESCRIPTOR_BYTES: u64 = 64 * 1024;
const MAXIMUM_EXTENSION_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAXIMUM_MCP_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_SERVER_ERROR_CODE_BYTES: usize = 64;
const MAXIMUM_SERVER_ERROR_MESSAGE_BYTES: usize = 4 * 1024;
const PROVIDER_PROBE_MAXIMUM_BYTES: u64 = 1024 * 1024;
const PROVIDER_PROBE_MAXIMUM_TEXT_BYTES: usize = 64 * 1024;
// Leave enough room for Responses-compatible reasoning models to complete a trivial probe while
// keeping activation checks cheap and bounded. Some servers account hidden reasoning tokens
// against `max_output_tokens` before emitting the requested visible text.
const PROVIDER_PROBE_MAXIMUM_OUTPUT_TOKENS: u64 = 256;
const SUBSCRIPTION_PROBE_MAXIMUM_OUTPUT_TOKENS: u64 = 256;
const SETUP_PROVIDER_ESTIMATED_LATENCY_MS: u64 = 30_000;
const PROVIDER_DISPATCH_SAFETY_MARGIN_MS: u64 = 5_000;
const PROVIDER_DISCOVERY_MAXIMUM_MODELS: usize = 500;
const PROVIDER_DISCOVERY_MAXIMUM_WIRE_MODELS: usize = 2_000;
const TELEGRAM_PAIR_GET_ME_MAXIMUM_BYTES: usize = 64 * 1024;
const TELEGRAM_PAIR_UPDATES_MAXIMUM_BYTES: usize = 1024 * 1024;
const TELEGRAM_PAIR_MINIMUM_TIMEOUT_SECONDS: u64 = 30;
const TELEGRAM_PAIR_MAXIMUM_TIMEOUT_SECONDS: u64 = 300;
const DISCORD_PAIR_MAXIMUM_RESPONSE_BYTES: usize = 1024 * 1024;
const DISCORD_PAIR_MINIMUM_TIMEOUT_SECONDS: u64 = 30;
const DISCORD_PAIR_MAXIMUM_TIMEOUT_SECONDS: u64 = 300;
const USAGE_DAY_MS: i64 = 86_400_000;
const MAXIMUM_LOCAL_TEXT_ATTACHMENT_BYTES: u64 = 256 * 1024;
const MAXIMUM_LOCAL_ATTACHMENT_PROMPT_BYTES: usize = 16 * 1024;
const MAXIMUM_LOCAL_ATTACHMENT_NAME_BYTES: usize = 255;
const MAXIMUM_LOCAL_ATTACHMENT_INPUT_BYTES: usize = 1024 * 1024;
const CHAT_LOCAL_ATTACHMENT_PROMPT: &str =
    "Use this owner-selected local text attachment when responding.";

#[derive(Debug, Parser)]
#[command(version, about = "Mealy local client and administration CLI")]
struct Arguments {
    /// Private Mealy state directory containing `connection.json`.
    #[arg(long, env = "MEALY_HOME", default_value = ".mealy")]
    home: PathBuf,
    /// Operation to execute.
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
#[command(version, about = "Mealy local client and administration CLI")]
struct LifecycleArguments {
    /// Private Mealy state directory containing `connection.json`.
    #[arg(long, env = "MEALY_HOME", default_value = ".mealy")]
    home: PathBuf,
    /// Installed-program lifecycle operation to execute.
    #[command(subcommand)]
    command: LifecycleCommand,
}

#[derive(Debug, Subcommand)]
enum LifecycleCommand {
    /// Inspect install provenance, release integrity, rollback availability, and update ownership.
    InstallStatus,
    /// Verify a stable release target and optionally apply a schema-compatible archive update.
    Update {
        /// Stable release tag such as v1.2.3, or the latest stable release.
        #[arg(long, default_value = "latest")]
        version: String,
        /// Apply the verified plan; omission performs a no-mutation check.
        #[arg(long)]
        approve: bool,
    },
    /// Inspect one durable disconnect-resistant update transaction.
    UpdateStatus {
        /// Exact transaction UUID printed by `update --approve`.
        transaction_id: String,
    },
    /// Verify and optionally restore bounded installation-management evidence.
    Repair {
        /// Apply the verified repair plan.
        #[arg(long)]
        approve: bool,
    },
    /// Verify and optionally exchange same-schema owner-local release slots.
    Rollback {
        /// Apply the verified rollback plan.
        #[arg(long)]
        approve: bool,
    },
    /// Verify and optionally remove program files while preserving the durable home.
    Uninstall {
        /// Apply the verified uninstall plan.
        #[arg(long)]
        approve: bool,
    },
    /// Generate a native completion script for one supported shell.
    Completion {
        /// Shell whose completion syntax should be generated.
        #[arg(value_enum)]
        shell: CompletionShellArgument,
    },
    /// Internal restartable update helper owned by a transient user service.
    #[command(hide = true)]
    UpdateTransaction {
        /// Exact durable transaction UUID prepared by the foreground client.
        transaction_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Configure a provider, start the owner service, and verify a first usable Linux install.
    Onboard(OnboardOptions),
    /// Initialize a clean home and guide one bounded provider activation while the daemon is stopped.
    Setup(SetupOptions),
    /// Start or resume a friendly line-oriented durable chat session.
    Chat {
        /// Existing session to resume; a new session is created when omitted.
        #[arg(long)]
        session_id: Option<String>,
    },
    /// Session creation, submission, timeline, and status operations.
    Session {
        /// Session operation.
        #[command(subcommand)]
        command: SessionCommand,
    },
    /// Inspect, cancel, or replay durable agent tasks.
    Task {
        /// Task operation.
        #[command(subcommand)]
        command: TaskCommand,
    },
    /// Inspect durable parent-to-child agent delegations.
    Delegation {
        /// Delegation operation.
        #[command(subcommand)]
        command: DelegationCommand,
    },
    /// Inspect durable authenticated approval subjects.
    Approval {
        /// Approval operation.
        #[command(subcommand)]
        command: ApprovalCommand,
    },
    /// Inspect governed external effects and dispatch attempts.
    Effect {
        /// Effect operation.
        #[command(subcommand)]
        command: EffectCommand,
    },
    /// Governed long-term memory lifecycle, retrieval, export, and index maintenance.
    Memory {
        /// Memory operation.
        #[command(subcommand)]
        command: MemoryCommand,
    },
    /// Create or inspect cited derived session compactions.
    Compaction {
        /// Compaction operation.
        #[command(subcommand)]
        command: CompactionCommand,
    },
    /// Install, grant, invoke, upgrade, disable, or revoke out-of-process extensions.
    Extension {
        /// Extension operation.
        #[command(subcommand)]
        command: ExtensionCommand,
    },
    /// Inspect, install, update, enable, or disable data-only skill bundles while stopped.
    Skill {
        /// Skill package operation.
        #[command(subcommand)]
        command: SkillCommand,
    },
    /// Create, inspect, or terminally revoke signed webhook and Telegram channels.
    Channel {
        /// Channel operation.
        #[command(subcommand)]
        command: ChannelCommand,
    },
    /// Create, inspect, pause, resume, cancel, or audit recurring agent schedules.
    Schedule {
        /// Schedule operation.
        #[command(subcommand)]
        command: ScheduleCommand,
    },
    /// Check daemon liveness.
    Health,
    /// Inspect queue, lease, approval, effect, extension, channel, and storage health.
    Status,
    /// Print stable machine-readable operational gauges.
    Metrics,
    /// Print exact settled terminal-run usage for the trailing bounded day range.
    Usage {
        /// Trailing duration in days, ending at the current UTC instant (1 through 31).
        #[arg(long, default_value_t = 30)]
        days: u8,
    },
    /// Diagnose control-plane storage, permissions, and sandbox-profile conformance.
    Doctor,
    /// Serve a temporary least-authority interactive dashboard on a random loopback port.
    Dashboard,
    /// Close command admission and begin bounded graceful drain.
    Drain,
    /// Create an immutable complete online backup under the daemon home.
    Backup {
        /// Portable immutable backup name.
        name: String,
        /// Include identity and channel keys under authenticated encryption.
        #[arg(long)]
        include_secrets: bool,
        /// Environment variable holding the encryption passphrase.
        #[arg(long, default_value = "MEALY_BACKUP_PASSPHRASE")]
        passphrase_env: String,
    },
    /// Restore a backup into an isolated fresh home and verify it without replacement.
    RestoreVerify {
        /// Existing immutable backup name.
        name: String,
        /// Environment variable holding the passphrase for an encrypted backup.
        #[arg(long)]
        passphrase_env: Option<String>,
    },
    /// Atomically activate one verified encrypted backup while the daemon is stopped.
    RestoreActivate {
        /// Existing immutable encrypted backup name.
        name: String,
        /// Exact manifest digest returned by `restore-verify`.
        #[arg(long)]
        expected_manifest_digest: String,
        /// Environment variable holding the encrypted-backup passphrase.
        #[arg(long, default_value = "MEALY_BACKUP_PASSPHRASE")]
        passphrase_env: String,
        /// Explicit authorization for replacing the active home.
        #[arg(long)]
        approve: bool,
    },
    /// Internal stopped-home half of a package-managed cross-schema rollback.
    #[command(hide = true)]
    MigrationHomeActivate {
        /// Existing automatic migration-backup name.
        name: String,
        /// Exact migration manifest digest approved by the operator.
        #[arg(long)]
        expected_manifest_digest: String,
        /// Exact state schema supported by the older release being activated.
        #[arg(long)]
        expected_from_schema_version: u64,
        /// Exact state schema of the migrated home being preserved.
        #[arg(long)]
        expected_to_schema_version: u64,
        /// Read an inherited package-manager home lock from standard input (Linux only).
        #[arg(long, hide = true)]
        inherited_home_lock_stdin: bool,
        /// Explicit authorization for replacing the active home.
        #[arg(long)]
        approve: bool,
    },
    /// Erase only configured-age artifact files absent from canonical metadata.
    GarbageCollect,
    /// Publish an immutable owner-scoped audit, task, artifact, or memory JSON bundle.
    Export {
        /// Portable immutable export name.
        name: String,
        /// Export bundle scope.
        kind: ExportKindArgument,
        /// Task ID, artifact ID, or workspace identity; omit for audit.
        #[arg(long)]
        selector: Option<String>,
    },
    /// Install a user-level daemon service definition with an explicit activation command.
    Service {
        /// Service operation.
        #[command(subcommand)]
        command: ServiceCommand,
    },
    /// Inspect or change governed daemon configuration while the daemon is stopped.
    Config {
        /// Configuration operation.
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, clap::Args)]
struct OnboardOptions {
    /// Authentication/provider route; prompted when omitted.
    #[arg(long, value_enum)]
    route: Option<OnboardRouteArgument>,
    /// Override the route's official, custom, or literal-loopback API version base.
    #[arg(long)]
    base_url: Option<String>,
    /// Exact model ID; discovered or prompted when omitted.
    #[arg(long)]
    model: Option<String>,
    /// Conservative context-token limit; derived from trusted catalog metadata when possible.
    #[arg(long)]
    context_tokens: Option<u64>,
    /// Maximum output tokens Mealy may request or accept.
    #[arg(long, default_value_t = 4_096)]
    maximum_output_tokens: u64,
    /// Environment variable imported once for an API credential.
    #[arg(long)]
    credential_env: Option<String>,
    /// Input price in currency microunits per million tokens.
    #[arg(long)]
    input_microunits_per_million_tokens: Option<u64>,
    /// Output price in currency microunits per million tokens.
    #[arg(long)]
    output_microunits_per_million_tokens: Option<u64>,
    /// Installed official subscription client; PATH lookup is used when omitted.
    #[arg(long)]
    executable_path: Option<PathBuf>,
    /// Use terminal-only JSON when an HTTP endpoint does not support provider streaming.
    #[arg(long)]
    disable_streaming: bool,
    /// Stage configuration without the default bounded live connectivity/model probe.
    #[arg(long, requires = "configure_only")]
    skip_connectivity_test: bool,
    /// Stop after provider configuration instead of installing and starting the Linux service.
    #[arg(long)]
    configure_only: bool,
    /// Explicitly allow replacing the provider configuration in an existing stopped home.
    #[arg(long)]
    reconfigure: bool,
    /// Confirm the reviewed onboarding plan non-interactively.
    #[arg(long)]
    approve: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OnboardRouteArgument {
    /// Discover and admit only an exact zero-price, tool-capable `OpenRouter` `:free` model.
    OpenrouterFree,
    /// Authenticated custom `OpenAI` Responses-compatible HTTPS endpoint.
    Custom,
    /// Credentialless literal-loopback `OpenAI` Responses-compatible endpoint.
    Local,
    /// Existing official Codex CLI session authenticated with a `ChatGPT` subscription.
    ChatgptSubscription,
    /// Existing official Claude Code session authenticated with a Claude subscription.
    ClaudeSubscription,
    /// Official `OpenAI` Responses API credential.
    OpenaiApi,
    /// Official Anthropic Messages API credential.
    AnthropicApi,
}

#[derive(Debug, clap::Args)]
struct SetupOptions {
    /// Provider family; prompted when omitted.
    #[arg(long, value_enum)]
    provider: Option<SetupProviderArgument>,
    /// Override the provider's official or literal-loopback API version base.
    #[arg(long)]
    base_url: Option<String>,
    /// Exact model name or immutable snapshot; prompted when omitted.
    #[arg(long)]
    model: Option<String>,
    /// Conservative context-token limit for the exact model; prompted when omitted.
    #[arg(long)]
    context_tokens: Option<u64>,
    /// Maximum output tokens Mealy may request.
    #[arg(long, default_value_t = 4_096)]
    maximum_output_tokens: u64,
    /// Environment variable imported once for a remote API credential.
    #[arg(long)]
    credential_env: Option<String>,
    /// Input price in currency microunits per million tokens; prompted for remote providers.
    #[arg(long)]
    input_microunits_per_million_tokens: Option<u64>,
    /// Output price in currency microunits per million tokens; prompted for remote providers.
    #[arg(long)]
    output_microunits_per_million_tokens: Option<u64>,
    /// Use terminal-only JSON when the endpoint does not support provider streaming.
    #[arg(long)]
    disable_streaming: bool,
    /// Stage configuration without the default bounded live connectivity/model probe.
    #[arg(long)]
    skip_connectivity_test: bool,
    /// Confirm activation non-interactively; otherwise the wizard requires typing `APPROVE`.
    #[arg(long)]
    approve: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SetupProviderArgument {
    /// Official `OpenAI` Responses API.
    Openai,
    /// Official Anthropic Messages API.
    Anthropic,
    /// `OpenRouter` stateless Responses API beta.
    Openrouter,
    /// Credentialless literal-loopback Responses-compatible endpoint.
    Local,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CompletionShellArgument {
    /// Bourne Again Shell.
    Bash,
    /// Z shell.
    Zsh,
    /// Friendly Interactive Shell.
    Fish,
}

impl From<CompletionShellArgument> for Shell {
    fn from(value: CompletionShellArgument) -> Self {
        match value {
            CompletionShellArgument::Bash => Self::Bash,
            CompletionShellArgument::Zsh => Self::Zsh,
            CompletionShellArgument::Fish => Self::Fish,
        }
    }
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    /// Atomically install the current platform's owner-level service definition.
    Install {
        /// Exact mealyd executable; defaults to the sibling of this mealyctl binary.
        #[arg(long)]
        daemon_path: Option<PathBuf>,
        /// Testable/custom service-definition path; platform user location by default.
        #[arg(long)]
        destination: Option<PathBuf>,
    },
    /// Plan or remove only the exact generated owner-level service definition.
    Remove {
        /// Exact custom service-definition path; loaded/default definition when omitted.
        #[arg(long)]
        destination: Option<PathBuf>,
        /// Stop, disable, and remove the verified service definition.
        #[arg(long)]
        approve: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Inspect the exact validated primary/fallback chain without resolving credentials.
    ProviderList,
    /// List models accessible to the supplied `OpenAI` API credential without changing config.
    ProviderModels {
        /// HTTPS API version base; literal-loopback HTTP is also allowed.
        #[arg(long, default_value = "https://api.openai.com/v1")]
        base_url: String,
        /// Environment variable read once for this discovery request.
        #[arg(long, default_value = "OPENAI_API_KEY")]
        credential_env: String,
        /// Return only model identifiers containing this text (case-insensitive).
        #[arg(long)]
        contains: Option<String>,
        /// Maximum matching model records emitted locally (1-500).
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// List models and advertised token limits accessible to an Anthropic API credential.
    ProviderModelsAnthropic {
        /// HTTPS API version base; literal-loopback HTTP is also allowed.
        #[arg(long, default_value = "https://api.anthropic.com/v1")]
        base_url: String,
        /// Environment variable read once for this discovery request.
        #[arg(long, default_value = "ANTHROPIC_API_KEY")]
        credential_env: String,
        /// Return only model identifiers containing this text (case-insensitive).
        #[arg(long)]
        contains: Option<String>,
        /// Maximum provider records requested and emitted (1-500).
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Continue after this exact `lastId` cursor from an earlier response.
        #[arg(long)]
        after_id: Option<String>,
    },
    /// List tool-capable text models, limits, and posted token prices for an `OpenRouter` key.
    ProviderModelsOpenrouter {
        /// HTTPS API version base; literal-loopback HTTP is accepted for conformance tests.
        #[arg(long, default_value = "https://openrouter.ai/api/v1")]
        base_url: String,
        /// Environment variable read once for this discovery request.
        #[arg(long, default_value = "OPENROUTER_API_KEY")]
        credential_env: String,
        /// Return only model identifiers or display names containing this text.
        #[arg(long)]
        contains: Option<String>,
        /// Maximum matching model records emitted locally (1-500).
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// List models from a credentialless literal-loopback OpenAI-compatible endpoint.
    ProviderModelsLocal {
        /// Literal-loopback HTTP API version base.
        #[arg(long, default_value = "http://127.0.0.1:11434/v1")]
        base_url: String,
        /// Return only model identifiers containing this text (case-insensitive).
        #[arg(long)]
        contains: Option<String>,
        /// Maximum matching model records emitted locally (1-500).
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Configure a credentialless literal-loopback `OpenAI` Responses-compatible provider.
    ProviderLocal {
        /// Stable provider identity retained in routing evidence.
        #[arg(long, default_value = "local.responses")]
        provider_id: String,
        /// Literal-loopback HTTP API version base.
        #[arg(long, default_value = "http://127.0.0.1:11434/v1")]
        base_url: String,
        /// Exact local model name or snapshot.
        #[arg(long)]
        model: String,
        /// Maximum context tokens conservatively declared for this exact local model.
        #[arg(long)]
        context_tokens: u64,
        /// Maximum output tokens Mealy may request.
        #[arg(long, default_value_t = 4_096)]
        maximum_output_tokens: u64,
        /// Use terminal-only JSON when the endpoint does not implement Responses SSE.
        #[arg(long)]
        disable_streaming: bool,
        /// Activate without the default bounded live model/connectivity test.
        #[arg(long)]
        skip_connectivity_test: bool,
        /// Conservative routing latency estimate in milliseconds.
        #[arg(long, default_value_t = 60_000)]
        estimated_latency_ms: u64,
        /// Confirm this provider activation.
        #[arg(long)]
        approve: bool,
    },
    /// Configure official Codex CLI access using its existing `ChatGPT` subscription sign-in.
    ProviderSubscriptionOpenai {
        /// Stable provider identity retained in routing evidence.
        #[arg(long, default_value = "openai.subscription")]
        provider_id: String,
        /// Installed Codex executable; PATH lookup is used when omitted.
        #[arg(long)]
        executable_path: Option<PathBuf>,
        /// Exact subscription-accessible Codex model name.
        #[arg(long)]
        model: String,
        /// Remote residency/trust label used by routing policy.
        #[arg(long, default_value = "openai-subscription")]
        residency: String,
        /// Conservative context limit for this exact model.
        #[arg(long)]
        context_tokens: u64,
        /// Maximum output tokens Mealy accepts from the official client.
        #[arg(long, default_value_t = 4_096)]
        maximum_output_tokens: u64,
        /// Activate without the default bounded authenticated client probe.
        #[arg(long)]
        skip_connectivity_test: bool,
        /// Conservative routing latency estimate in milliseconds.
        #[arg(long, default_value_t = 60_000)]
        estimated_latency_ms: u64,
        /// Confirm this owner-local official-client activation.
        #[arg(long)]
        approve: bool,
    },
    /// Configure official Claude Code access using its existing Claude subscription sign-in.
    ProviderSubscriptionClaude {
        /// Stable provider identity retained in routing evidence.
        #[arg(long, default_value = "claude.subscription")]
        provider_id: String,
        /// Installed Claude executable; PATH lookup is used when omitted.
        #[arg(long)]
        executable_path: Option<PathBuf>,
        /// Exact subscription-accessible Claude model name.
        #[arg(long)]
        model: String,
        /// Remote residency/trust label used by routing policy.
        #[arg(long, default_value = "claude-subscription")]
        residency: String,
        /// Conservative context limit for this exact model.
        #[arg(long)]
        context_tokens: u64,
        /// Maximum output tokens Mealy accepts from the official client.
        #[arg(long, default_value_t = 4_096)]
        maximum_output_tokens: u64,
        /// Activate without the default bounded authenticated client probe.
        #[arg(long)]
        skip_connectivity_test: bool,
        /// Conservative routing latency estimate in milliseconds.
        #[arg(long, default_value_t = 60_000)]
        estimated_latency_ms: u64,
        /// Confirm this owner-local official-client activation.
        #[arg(long)]
        approve: bool,
    },
    /// Configure one `OpenAI` Responses-compatible provider and broker its credential while stopped.
    Provider {
        /// Stable provider identity retained in routing evidence.
        #[arg(long, default_value = "openai.responses")]
        provider_id: String,
        /// HTTPS API version base; literal-loopback HTTP is also allowed.
        #[arg(long, default_value = "https://api.openai.com/v1")]
        base_url: String,
        /// Exact model name or snapshot.
        #[arg(long)]
        model: String,
        /// Portable provider credential identity stored below the private Mealy home.
        #[arg(long, default_value = "openai-primary")]
        secret_id: String,
        /// Environment variable from which mealyctl reads the credential once.
        #[arg(long, default_value = "OPENAI_API_KEY")]
        credential_env: String,
        /// Provider residency/trust label used by routing policy.
        #[arg(long, default_value = "openai-api")]
        residency: String,
        /// Maximum context tokens advertised for the exact model.
        #[arg(long)]
        context_tokens: u64,
        /// Maximum output tokens Mealy may request.
        #[arg(long, default_value_t = 4_096)]
        maximum_output_tokens: u64,
        /// Use terminal-only JSON for an endpoint that does not implement Responses SSE.
        #[arg(long)]
        disable_streaming: bool,
        /// Activate without the default bounded live model/connectivity test.
        #[arg(long)]
        skip_connectivity_test: bool,
        /// Input price in currency microunits per million tokens.
        #[arg(long)]
        input_microunits_per_million_tokens: u64,
        /// Output price in currency microunits per million tokens.
        #[arg(long)]
        output_microunits_per_million_tokens: u64,
        /// Conservative routing latency estimate in milliseconds.
        #[arg(long, default_value_t = 30_000)]
        estimated_latency_ms: u64,
        /// Confirm this high-risk provider and credential activation.
        #[arg(long)]
        approve: bool,
    },
    /// Configure `OpenRouter`'s stateless Responses API beta and broker its API key.
    ProviderOpenrouter {
        /// Stable provider identity retained in routing evidence.
        #[arg(long, default_value = "openrouter.responses")]
        provider_id: String,
        /// `OpenRouter` API version base; the EU in-region base may be supplied explicitly.
        #[arg(long, default_value = "https://openrouter.ai/api/v1")]
        base_url: String,
        /// Exact `OpenRouter` model slug, such as `openai/gpt-5.4`.
        #[arg(long)]
        model: String,
        /// Portable broker identity for the API key.
        #[arg(long, default_value = "openrouter-primary")]
        secret_id: String,
        /// Environment variable from which mealyctl reads the API key once.
        #[arg(long, default_value = "OPENROUTER_API_KEY")]
        credential_env: String,
        /// Residency/trust label used by routing policy.
        #[arg(long, default_value = "openrouter-api")]
        residency: String,
        /// Conservative context limit for this exact model and account routing policy.
        #[arg(long)]
        context_tokens: u64,
        /// Maximum output tokens Mealy may request.
        #[arg(long, default_value_t = 4_096)]
        maximum_output_tokens: u64,
        /// Use terminal-only JSON instead of Responses SSE.
        #[arg(long)]
        disable_streaming: bool,
        /// Activate without the default bounded live Responses compatibility test.
        #[arg(long)]
        skip_connectivity_test: bool,
        /// Conservative input price in currency microunits per million tokens.
        #[arg(long)]
        input_microunits_per_million_tokens: u64,
        /// Conservative output price in currency microunits per million tokens.
        #[arg(long)]
        output_microunits_per_million_tokens: u64,
        /// Conservative routing latency estimate in milliseconds.
        #[arg(long, default_value_t = 30_000)]
        estimated_latency_ms: u64,
        /// Confirm this beta provider and credential activation.
        #[arg(long)]
        approve: bool,
    },
    /// Configure one Anthropic Messages-compatible provider and broker its credential while stopped.
    ProviderAnthropic {
        /// Stable provider identity retained in routing evidence.
        #[arg(long, default_value = "anthropic.messages")]
        provider_id: String,
        /// HTTPS API version base; literal-loopback HTTP is also allowed.
        #[arg(long, default_value = "https://api.anthropic.com/v1")]
        base_url: String,
        /// Exact model name or snapshot.
        #[arg(long)]
        model: String,
        /// Portable provider credential identity stored below the private Mealy home.
        #[arg(long, default_value = "anthropic-primary")]
        secret_id: String,
        /// Environment variable from which mealyctl reads the credential once.
        #[arg(long, default_value = "ANTHROPIC_API_KEY")]
        credential_env: String,
        /// Provider residency/trust label used by routing policy.
        #[arg(long, default_value = "anthropic-api")]
        residency: String,
        /// Maximum context tokens advertised for the exact model.
        #[arg(long)]
        context_tokens: u64,
        /// Maximum output tokens Mealy may request.
        #[arg(long, default_value_t = 4_096)]
        maximum_output_tokens: u64,
        /// Use terminal-only JSON instead of Anthropic Messages SSE.
        #[arg(long)]
        disable_streaming: bool,
        /// Activate without the default bounded live model/connectivity test.
        #[arg(long)]
        skip_connectivity_test: bool,
        /// Input price in currency microunits per million tokens.
        #[arg(long)]
        input_microunits_per_million_tokens: u64,
        /// Output price in currency microunits per million tokens.
        #[arg(long)]
        output_microunits_per_million_tokens: u64,
        /// Conservative routing latency estimate in milliseconds.
        #[arg(long, default_value_t = 30_000)]
        estimated_latency_ms: u64,
        /// Confirm this high-risk provider and credential activation.
        #[arg(long)]
        approve: bool,
    },
    /// Append one explicit same-boundary fallback and broker its credential while stopped.
    ProviderFallback {
        /// Stable fallback identity retained in routing evidence.
        #[arg(long, default_value = "openai-fallback.responses")]
        provider_id: String,
        /// HTTPS API version base; literal-loopback HTTP is also allowed.
        #[arg(long, default_value = "https://api.openai.com/v1")]
        base_url: String,
        /// Exact fallback model name or snapshot.
        #[arg(long)]
        model: String,
        /// Portable fallback credential identity stored below the private Mealy home.
        #[arg(long, default_value = "openai-fallback")]
        secret_id: String,
        /// Environment variable from which mealyctl reads the credential once.
        #[arg(long, default_value = "OPENAI_API_KEY")]
        credential_env: String,
        /// Must exactly match the primary provider residency/trust label.
        #[arg(long, default_value = "openai-api")]
        residency: String,
        /// Maximum context tokens advertised for the exact model.
        #[arg(long)]
        context_tokens: u64,
        /// Maximum output tokens Mealy may request.
        #[arg(long, default_value_t = 4_096)]
        maximum_output_tokens: u64,
        /// Use terminal-only JSON for an endpoint that does not implement Responses SSE.
        #[arg(long)]
        disable_streaming: bool,
        /// Activate without the default bounded live model/connectivity test.
        #[arg(long)]
        skip_connectivity_test: bool,
        /// Input price in currency microunits per million tokens.
        #[arg(long)]
        input_microunits_per_million_tokens: u64,
        /// Output price in currency microunits per million tokens.
        #[arg(long)]
        output_microunits_per_million_tokens: u64,
        /// Conservative routing latency estimate in milliseconds.
        #[arg(long, default_value_t = 30_000)]
        estimated_latency_ms: u64,
        /// Confirm this high-risk fallback and credential activation.
        #[arg(long)]
        approve: bool,
    },
    /// Append one same-boundary Anthropic Messages fallback and broker its credential while stopped.
    ProviderFallbackAnthropic {
        /// Stable fallback identity retained in routing evidence.
        #[arg(long, default_value = "anthropic-fallback.messages")]
        provider_id: String,
        /// HTTPS API version base; literal-loopback HTTP is also allowed.
        #[arg(long, default_value = "https://api.anthropic.com/v1")]
        base_url: String,
        /// Exact fallback model name or snapshot.
        #[arg(long)]
        model: String,
        /// Portable fallback credential identity stored below the private Mealy home.
        #[arg(long, default_value = "anthropic-fallback")]
        secret_id: String,
        /// Environment variable from which mealyctl reads the credential once.
        #[arg(long, default_value = "ANTHROPIC_API_KEY")]
        credential_env: String,
        /// Must exactly match the primary provider residency/trust label.
        #[arg(long, default_value = "anthropic-api")]
        residency: String,
        /// Maximum context tokens advertised for the exact model.
        #[arg(long)]
        context_tokens: u64,
        /// Maximum output tokens Mealy may request.
        #[arg(long, default_value_t = 4_096)]
        maximum_output_tokens: u64,
        /// Use terminal-only JSON instead of Anthropic Messages SSE.
        #[arg(long)]
        disable_streaming: bool,
        /// Activate without the default bounded live model/connectivity test.
        #[arg(long)]
        skip_connectivity_test: bool,
        /// Input price in currency microunits per million tokens.
        #[arg(long)]
        input_microunits_per_million_tokens: u64,
        /// Output price in currency microunits per million tokens.
        #[arg(long)]
        output_microunits_per_million_tokens: u64,
        /// Conservative routing latency estimate in milliseconds.
        #[arg(long, default_value_t = 30_000)]
        estimated_latency_ms: u64,
        /// Confirm this high-risk fallback and credential activation.
        #[arg(long)]
        approve: bool,
    },
    /// Append a credentialless literal-loopback Responses fallback to a local primary.
    ProviderFallbackLocal {
        /// Stable fallback identity retained in routing evidence.
        #[arg(long, default_value = "local-fallback.responses")]
        provider_id: String,
        /// Literal-loopback HTTP API version base.
        #[arg(long, default_value = "http://127.0.0.1:11434/v1")]
        base_url: String,
        /// Exact local fallback model name or snapshot.
        #[arg(long)]
        model: String,
        /// Must exactly match the local primary residency label.
        #[arg(long, default_value = "local")]
        residency: String,
        /// Maximum context tokens conservatively declared for this exact model.
        #[arg(long)]
        context_tokens: u64,
        /// Maximum output tokens Mealy may request.
        #[arg(long, default_value_t = 4_096)]
        maximum_output_tokens: u64,
        /// Use terminal-only JSON when the endpoint does not implement Responses SSE.
        #[arg(long)]
        disable_streaming: bool,
        /// Activate without the default bounded live model/connectivity test.
        #[arg(long)]
        skip_connectivity_test: bool,
        /// Conservative routing latency estimate in milliseconds.
        #[arg(long, default_value_t = 30_000)]
        estimated_latency_ms: u64,
        /// Confirm this fallback activation.
        #[arg(long)]
        approve: bool,
    },
    /// Remove one exact fallback from the explicit routing chain while retaining its credential.
    ProviderFallbackRemove {
        /// Exact configured fallback provider identity.
        provider_id: String,
        /// Confirm removal of this routing path.
        #[arg(long)]
        approve: bool,
    },
    /// Permanently remove one currently unreferenced broker credential while stopped.
    ProviderSecretRevoke {
        /// Exact portable broker secret identity.
        secret_id: String,
        /// Confirm permanent removal; configuration-history rollback may require this credential.
        #[arg(long)]
        approve: bool,
    },
    /// Grant one canonical host directory to read-only workspace tools while stopped.
    WorkspaceGrant {
        /// Stable logical identity shown to the model instead of the host path.
        workspace_id: String,
        /// Existing directory to grant; configuration stores its canonical absolute path.
        root: PathBuf,
        /// Confirm this tool-authority activation.
        #[arg(long)]
        approve: bool,
    },
    /// Revoke one logical workspace grant while stopped.
    WorkspaceRevoke {
        /// Exact configured logical workspace identity.
        workspace_id: String,
        /// Confirm this tool-authority revocation.
        #[arg(long)]
        approve: bool,
    },
    /// Enable approval-gated create-new-file authority for one granted workspace while stopped.
    WorkspaceWriteEnable {
        /// Exact configured logical workspace identity.
        workspace_id: String,
        /// Confirm activation of mutating tool authority.
        #[arg(long)]
        approve: bool,
    },
    /// Remove create-new-file authority while preserving read access to the workspace.
    WorkspaceWriteDisable {
        /// Exact configured logical workspace identity.
        workspace_id: String,
        /// Confirm removal of mutating tool authority.
        #[arg(long)]
        approve: bool,
    },
    /// Grant one digest-pinned direct executable while the daemon is stopped.
    ProcessGrant {
        /// Stable logical identity shown to the model and approval UI.
        command_id: String,
        /// Existing executable file to bind read-only into the sandbox.
        executable: PathBuf,
        /// Confirm activation of high-risk process authority.
        #[arg(long)]
        approve: bool,
    },
    /// Revoke one direct executable identity while the daemon is stopped.
    ProcessRevoke {
        /// Exact configured logical command identity.
        command_id: String,
        /// Confirm removal of high-risk process authority.
        #[arg(long)]
        approve: bool,
    },
    /// Enable bounded web fetch and optional Brave Search authority while stopped.
    WebEnable {
        /// Permit arbitrary public HTTPS destinations after DNS/IP enforcement.
        #[arg(long)]
        allow_public_internet: bool,
        /// Permit an exact DNS suffix over public HTTPS; repeat for multiple domains.
        #[arg(long = "allow-domain")]
        allowed_domains: Vec<String>,
        /// Permit one exact canonical HTTPS or literal-loopback HTTP origin.
        #[arg(long = "allow-origin")]
        allowed_origins: Vec<String>,
        /// Broker identity that also enables the Brave Search adapter when supplied.
        #[arg(long)]
        brave_secret_id: Option<String>,
        /// Environment variable imported once for the Brave subscription token.
        #[arg(long, default_value = "BRAVE_SEARCH_API_KEY")]
        brave_credential_env: String,
        /// Full Brave web-search endpoint; literal-loopback HTTP supports conformance tests.
        #[arg(long, default_value = "https://api.search.brave.com/res/v1/web/search")]
        brave_base_url: String,
        /// Confirm activation of outbound network and optional credential authority.
        #[arg(long)]
        approve: bool,
    },
    /// Disable all web tools while stopped; brokered credentials are retained for rollback.
    WebDisable {
        /// Confirm removal of outbound web authority.
        #[arg(long)]
        approve: bool,
    },
    /// Inspect a Chrome Headless Shell bundle and its sandboxed runtime identity without installing it.
    BrowserInspect {
        /// Extracted Chrome Headless Shell bundle directory.
        bundle: PathBuf,
    },
    /// Install and enable a content-pinned fresh-profile rendered browser while stopped.
    BrowserAdd {
        /// Extracted Chrome Headless Shell bundle directory to copy into private storage.
        bundle: PathBuf,
        /// Confirm installation and model-visible rendered-browser authority.
        #[arg(long)]
        approve: bool,
    },
    /// Show the configured browser runtime and activation state.
    BrowserList,
    /// Re-enable the installed browser after a complete live isolated verification.
    BrowserEnable {
        /// Confirm model-visible rendered-browser authority activation.
        #[arg(long)]
        approve: bool,
    },
    /// Disable rendered-browser authority while retaining immutable runtime bytes.
    BrowserDisable {
        /// Confirm authority removal.
        #[arg(long)]
        approve: bool,
    },
    /// Remove the browser from active configuration while retaining rollback bytes.
    BrowserRevoke {
        /// Confirm authority revocation.
        #[arg(long)]
        approve: bool,
    },
    /// Inspect a native MCP stdio server inside the no-network sandbox without changing authority.
    McpInspect {
        /// Stable logical server identity proposed for later activation.
        server_id: String,
        /// Exact native ELF MCP server executable to inspect.
        executable: PathBuf,
        /// Direct non-secret process argument; repeat in server order.
        #[arg(long = "argument")]
        arguments: Vec<String>,
    },
    /// Install and enable selected read-only tools from one inspected local MCP stdio server.
    McpAdd {
        /// Stable logical server identity used in model-visible tool names.
        server_id: String,
        /// Exact native ELF MCP server executable to copy into private content-addressed storage.
        executable: PathBuf,
        /// Direct non-secret process argument; repeat in server order.
        #[arg(long = "argument")]
        arguments: Vec<String>,
        /// Exact remote tool name reviewed by the owner; repeat to expose more than one.
        #[arg(long = "allow-tool", required = true)]
        allow_tools: Vec<String>,
        /// Hard total timeout for initialization, re-discovery, and one call.
        #[arg(long, default_value_t = 30_000)]
        timeout_ms: u64,
        /// Hard normalized result bound per call.
        #[arg(long, default_value_t = 262_144)]
        maximum_output_bytes: u64,
        /// Confirm installation and model-visible tool authority.
        #[arg(long)]
        approve: bool,
    },
    /// List configured MCP servers and exact reviewed tool definitions.
    McpList,
    /// Re-enable one configured MCP server after exact live toolset verification.
    McpEnable {
        /// Stable configured server identity.
        server_id: String,
        /// Confirm model-visible authority activation.
        #[arg(long)]
        approve: bool,
    },
    /// Disable one MCP server while retaining immutable executable and review evidence.
    McpDisable {
        /// Stable configured server identity.
        server_id: String,
        /// Confirm authority removal.
        #[arg(long)]
        approve: bool,
    },
    /// Revoke one MCP server from active configuration while retaining rollback evidence.
    McpRevoke {
        /// Stable configured server identity.
        server_id: String,
        /// Confirm authority revocation.
        #[arg(long)]
        approve: bool,
    },
    /// Roll back to one digest-pinned configuration archived by a successful daemon start.
    Rollback {
        /// Exact lowercase configuration digest from status or config-history.
        digest: String,
        /// Confirm this high-risk activation is an explicit owner decision.
        #[arg(long)]
        approve: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ExportKindArgument {
    Complete,
    Audit,
    Task,
    Artifact,
    Memory,
}

impl From<ExportKindArgument> for ExportKindRequest {
    fn from(value: ExportKindArgument) -> Self {
        match value {
            ExportKindArgument::Complete => Self::Complete,
            ExportKindArgument::Audit => Self::Audit,
            ExportKindArgument::Task => Self::Task,
            ExportKindArgument::Artifact => Self::Artifact,
            ExportKindArgument::Memory => Self::Memory,
        }
    }
}

#[derive(Debug, Subcommand)]
enum TaskCommand {
    /// Read current task state, usage, and final response.
    Status {
        /// Opaque task ID from the durable timeline.
        task_id: String,
    },
    /// Request cooperative cancellation.
    Cancel {
        /// Opaque task ID.
        task_id: String,
        /// Owner-visible cancellation reason.
        reason: String,
        /// Stable delivery key; generated when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Reconstruct the result exclusively from recorded evidence.
    Replay {
        /// Opaque completed task ID.
        task_id: String,
    },
    /// Fence active work and hold the task outside scheduler admission.
    Pause {
        /// Opaque task ID.
        task_id: String,
        /// Exact revision returned by task status.
        #[arg(long)]
        expected_revision: u64,
    },
    /// Restore a paused task to its durable run boundary.
    Resume {
        /// Opaque task ID.
        task_id: String,
        /// Exact revision returned by task status.
        #[arg(long)]
        expected_revision: u64,
    },
}

#[derive(Debug, Subcommand)]
enum DelegationCommand {
    /// List recent delegations owned by this exact local binding.
    List {
        /// Maximum delegations, newest first.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Read exact child authority, budget, state, and terminal result.
    Status {
        /// Opaque delegation ID returned by `delegation list`.
        delegation_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ApprovalCommand {
    /// List pending approval requests for the authenticated owner/channel.
    List,
    /// Resolve one exact approval subject through an authenticated command.
    Resolve {
        /// Opaque approval ID returned by `approval list`.
        approval_id: String,
        /// Owner decision for the exact rendered subject.
        decision: ApprovalDecisionArgument,
        /// Exact lowercase subject digest returned by `approval list`.
        #[arg(long)]
        subject_digest: String,
        /// Stable delivery key; generated and printed when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum EffectCommand {
    /// Read exact intent, policy, approval, and current lifecycle state.
    Status {
        /// Opaque effect ID from an approval or timeline event.
        effect_id: String,
    },
    /// Read one concrete dispatch attempt and its immutable outcomes.
    Attempt {
        /// Opaque effect-attempt ID from an effect timeline event.
        attempt_id: String,
    },
    /// Record explicit external evidence for an unknown effect attempt.
    Reconcile {
        /// Opaque effect ID owning the unknown attempt.
        effect_id: String,
        /// Opaque attempt ID whose outcome was unknown.
        attempt_id: String,
        /// External result established by the evidence.
        outcome: ReconciliationOutcomeArgument,
        /// Exact effect revision returned by `effect status`.
        #[arg(long)]
        revision: u64,
        /// Non-empty JSON object containing external receipt or diagnostic evidence.
        #[arg(long)]
        evidence_json: String,
        /// Stable delivery key; generated and printed when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum MemoryCommand {
    /// Propose and explicitly activate one owner-entered memory in a single reviewed command.
    Remember {
        /// Exact logical workspace namespace used by agent retrieval.
        #[arg(long)]
        workspace: String,
        /// Exact memory content to retain.
        content: String,
        /// Promotion-policy category.
        #[arg(long, value_enum, default_value_t = MemoryCategoryArgument::Fact)]
        category: MemoryCategoryArgument,
        /// Confidence in integer basis points from zero through 10,000.
        #[arg(long, default_value_t = 8000)]
        confidence: u16,
        /// Disclosure sensitivity.
        #[arg(long, value_enum, default_value_t = MemorySensitivityArgument::Private)]
        sensitivity: MemorySensitivityArgument,
        /// Retention behavior.
        #[arg(long, value_enum, default_value_t = MemoryRetentionArgument::Standard)]
        retention: MemoryRetentionArgument,
        /// Confirm proposal plus immediate owner-authorized activation.
        #[arg(long)]
        approve: bool,
    },
    /// Propose a new governed memory revision.
    Propose {
        /// Exact logical workspace namespace.
        #[arg(long)]
        workspace: String,
        /// Proposed memory content.
        content: String,
        /// Promotion-policy category.
        #[arg(long, value_enum, default_value_t = MemoryCategoryArgument::Fact)]
        category: MemoryCategoryArgument,
        /// Confidence in integer basis points from zero through 10,000.
        #[arg(long, default_value_t = 8000)]
        confidence: u16,
        /// Disclosure sensitivity.
        #[arg(long, value_enum, default_value_t = MemorySensitivityArgument::Internal)]
        sensitivity: MemorySensitivityArgument,
        /// Retention behavior.
        #[arg(long, value_enum, default_value_t = MemoryRetentionArgument::Standard)]
        retention: MemoryRetentionArgument,
        /// Immutable source as LOCATOR=DIGEST; repeat for multiple citations.
        #[arg(long = "source", required = true)]
        sources: Vec<String>,
    },
    /// Activate an exact proposed revision.
    Activate {
        /// Logical memory ID.
        memory_id: String,
        /// Exact proposed revision ID.
        #[arg(long)]
        revision_id: String,
        /// Explicit authorization for sensitive material.
        #[arg(long, value_enum)]
        authorization: Option<MemoryAuthorizationArgument>,
    },
    /// Inspect one logical memory and complete revision history.
    Status {
        /// Logical memory ID.
        memory_id: String,
        /// Exact logical workspace namespace.
        #[arg(long)]
        workspace: String,
    },
    /// List memories in a namespace.
    List {
        /// Exact logical workspace namespace.
        #[arg(long)]
        workspace: String,
        /// Include deleted tombstones.
        #[arg(long)]
        include_deleted: bool,
    },
    /// Lexically search active memories after namespace/sensitivity filtering.
    Search {
        /// Exact logical workspace namespace.
        #[arg(long)]
        workspace: String,
        /// Lexical query.
        query: String,
        /// Maximum sensitivity permitted in results.
        #[arg(long, value_enum, default_value_t = MemorySensitivityArgument::Private)]
        maximum_sensitivity: MemorySensitivityArgument,
        /// Maximum returned results.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Correct active content by creating and activating a new immutable revision.
    Correct {
        /// Logical memory ID.
        memory_id: String,
        /// Optimistic-concurrency revision from `memory status`.
        #[arg(long)]
        expected_revision: u64,
        /// Corrected content.
        content: String,
        /// Confidence in integer basis points.
        #[arg(long, default_value_t = 8000)]
        confidence: u16,
        /// Corrected sensitivity.
        #[arg(long, value_enum, default_value_t = MemorySensitivityArgument::Internal)]
        sensitivity: MemorySensitivityArgument,
        /// Corrected retention behavior.
        #[arg(long, value_enum, default_value_t = MemoryRetentionArgument::Standard)]
        retention: MemoryRetentionArgument,
        /// Immutable replacement source as LOCATOR=DIGEST; repeat as needed.
        #[arg(long = "source", required = true)]
        sources: Vec<String>,
        /// Explicit authorization for sensitive replacement content.
        #[arg(long, value_enum)]
        authorization: Option<MemoryAuthorizationArgument>,
    },
    /// Pin or unpin active memory retention.
    Pin {
        /// Logical memory ID.
        memory_id: String,
        /// Optimistic-concurrency revision.
        #[arg(long)]
        expected_revision: u64,
        /// Restore standard retention instead of pinning.
        #[arg(long)]
        unpin: bool,
    },
    /// Export a namespace as pretty versioned JSON.
    Export {
        /// Exact logical workspace namespace.
        #[arg(long)]
        workspace: String,
        /// Include deleted tombstones.
        #[arg(long)]
        include_deleted: bool,
        /// Optional output file; stdout is used when omitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Expire an active memory without scrubbing revision content.
    Expire {
        /// Logical memory ID.
        memory_id: String,
        /// Optimistic-concurrency revision.
        #[arg(long)]
        expected_revision: u64,
    },
    /// Reject a proposed memory while retaining its audit evidence.
    Reject {
        /// Logical memory ID.
        memory_id: String,
        /// Optimistic-concurrency revision.
        #[arg(long)]
        expected_revision: u64,
    },
    /// Scrub memory content while retaining lifecycle/digest tombstones.
    Delete {
        /// Logical memory ID.
        memory_id: String,
        /// Optimistic-concurrency revision.
        #[arg(long)]
        expected_revision: u64,
    },
    /// Rebuild the authenticated owner's FTS5 derived index rows.
    RebuildIndex,
}

#[derive(Debug, Subcommand)]
enum CompactionCommand {
    /// Commit a cited derived summary and typed carry-forward record.
    Create {
        /// Owning session ID.
        session_id: String,
        /// First canonical timeline cursor, inclusive.
        #[arg(long)]
        first_cursor: u64,
        /// Last canonical timeline cursor, inclusive.
        #[arg(long)]
        last_cursor: u64,
        /// Human-readable derived summary.
        #[arg(long)]
        summary: String,
        /// Strict `CompactionCarryForward` JSON object with source event citations.
        #[arg(long)]
        carry_forward_json: String,
    },
    /// Inspect one immutable compaction and all typed citations.
    Status {
        /// Opaque compaction ID.
        compaction_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ExtensionCommand {
    /// Inspect and install a new inert digest-pinned package.
    Install {
        /// Exact UTF-8 data-only manifest file.
        #[arg(long)]
        manifest: PathBuf,
        /// Lowercase SHA-256 digest of the exact manifest bytes.
        #[arg(long)]
        digest: String,
        /// Canonical package directory containing the digest-pinned executable.
        #[arg(long)]
        installation_root: PathBuf,
    },
    /// List all extensions owned by the authenticated principal.
    List,
    /// Inspect lifecycle, manifest history, and the active grant.
    Status {
        /// Stable extension ID declared by the manifest.
        extension_id: String,
    },
    /// Stage a digest-pinned upgrade or rollback and remove prior authority.
    Stage {
        /// Stable extension ID.
        extension_id: String,
        /// Optimistic-concurrency revision returned by `extension status`.
        #[arg(long)]
        expected_revision: u64,
        /// Exact UTF-8 data-only manifest file.
        #[arg(long)]
        manifest: PathBuf,
        /// Lowercase SHA-256 digest of the exact manifest bytes.
        #[arg(long)]
        digest: String,
        /// Canonical package directory containing the digest-pinned executable.
        #[arg(long)]
        installation_root: PathBuf,
    },
    /// Health-probe and enable the current manifest under an explicit least-authority grant.
    Enable {
        /// Stable extension ID.
        extension_id: String,
        /// Optimistic-concurrency revision returned by `extension status`.
        #[arg(long)]
        expected_revision: u64,
        /// Granted manifest capability; repeat for each approved capability.
        #[arg(long = "capability", required = true)]
        capabilities: Vec<String>,
        /// JSON `ExtensionMountGrantCommand`; repeat for each explicit mapping.
        #[arg(long = "mount-json")]
        mounts: Vec<String>,
        /// Exact outbound destination approved by the owner.
        #[arg(long = "network-destination")]
        network_destinations: Vec<String>,
        /// Opaque secret reference approved by the owner; never a secret value.
        #[arg(long = "secret-reference")]
        secret_references: Vec<String>,
        /// Approve manifest-declared child process creation.
        #[arg(long)]
        allow_process_spawn: bool,
    },
    /// Remove the active grant while retaining install history.
    Disable {
        /// Stable extension ID.
        extension_id: String,
        /// Optimistic-concurrency revision.
        #[arg(long)]
        expected_revision: u64,
    },
    /// Terminally revoke all future authority while retaining evidence.
    Revoke {
        /// Stable extension ID.
        extension_id: String,
        /// Optimistic-concurrency revision.
        #[arg(long)]
        expected_revision: u64,
    },
    /// Invoke one currently granted read-only capability through the supervised host.
    Invoke {
        /// Stable extension ID.
        extension_id: String,
        /// Exact granted manifest capability ID.
        capability: String,
        /// Strict JSON object matching the manifest input schema.
        #[arg(long)]
        input_json: String,
    },
}

#[derive(Debug, Subcommand)]
enum SkillCommand {
    /// Verify a complete data-only bundle without changing the Mealy home.
    Inspect {
        /// Exact package-root `manifest.json` file.
        #[arg(long)]
        manifest: PathBuf,
        /// Real package directory containing only the manifest and declared assets.
        #[arg(long)]
        package_root: PathBuf,
        /// Optional lowercase SHA-256 expected for the exact manifest bytes.
        #[arg(long)]
        digest: Option<String>,
    },
    /// Publish a verified bundle as an installed but disabled skill.
    Install {
        /// Exact package-root `manifest.json` file.
        #[arg(long)]
        manifest: PathBuf,
        /// Real package directory containing only the manifest and declared assets.
        #[arg(long)]
        package_root: PathBuf,
        /// Lowercase SHA-256 of the exact manifest bytes.
        #[arg(long)]
        digest: String,
        /// Confirm installation of the reviewed inert bundle.
        #[arg(long)]
        approve: bool,
    },
    /// Publish a verified replacement revision and leave it disabled for separate review.
    Update {
        /// Existing stable skill identity.
        skill_id: String,
        /// Exact currently installed manifest digest.
        #[arg(long)]
        expected_manifest_digest: String,
        /// Replacement package-root `manifest.json` file.
        #[arg(long)]
        manifest: PathBuf,
        /// Real replacement package directory containing only declared data.
        #[arg(long)]
        package_root: PathBuf,
        /// Lowercase SHA-256 of the exact replacement manifest bytes.
        #[arg(long)]
        digest: String,
        /// Confirm replacement and removal of the prior active instruction authority.
        #[arg(long)]
        approve: bool,
    },
    /// Activate one exact installed revision for new context epochs.
    Enable {
        /// Stable installed skill identity.
        skill_id: String,
        /// Exact installed manifest digest reviewed by the owner.
        #[arg(long)]
        expected_manifest_digest: String,
        /// Confirm model-instruction activation.
        #[arg(long)]
        approve: bool,
    },
    /// Remove instruction authority while retaining the immutable package and history.
    Disable {
        /// Stable installed skill identity.
        skill_id: String,
        /// Exact installed manifest digest currently being disabled.
        #[arg(long)]
        expected_manifest_digest: String,
        /// Confirm instruction-authority removal.
        #[arg(long)]
        approve: bool,
    },
    /// List installed skills and verify every referenced package.
    List,
    /// Inspect one installed skill, asset inventory, and separately governed tool references.
    Status {
        /// Stable installed skill identity.
        skill_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ChannelCommand {
    /// Create a signed external-subject binding and dedicated durable session.
    Create {
        /// Exact platform user/service subject expected in signed request bodies.
        #[arg(long)]
        external_subject: String,
        /// HTTPS callback, or literal loopback HTTP for local development.
        #[arg(long)]
        callback_url: String,
    },
    /// List owner-authorized signed webhook bindings.
    List,
    /// Inspect one binding without exposing its signing secret.
    Status {
        /// Stable binding ID returned by `channel create`.
        binding_id: String,
    },
    /// Terminally revoke a binding and destroy its brokered signing key.
    Revoke {
        /// Stable binding ID.
        binding_id: String,
        /// Optimistic-concurrency revision returned by `channel status`.
        #[arg(long)]
        expected_revision: u64,
    },
    /// Verify a bot token and create an exact Telegram sender/chat binding.
    TelegramCreate {
        /// Exact Telegram sender user ID allowed to submit messages.
        #[arg(long)]
        user_id: i64,
        /// Exact Telegram chat ID used for inbound allowlisting and outbound delivery.
        #[arg(long)]
        chat_id: i64,
        /// One-shot environment variable containing the Bot API token.
        #[arg(long, default_value = "TELEGRAM_BOT_TOKEN")]
        token_env: String,
    },
    /// Pair the next exact private chat that sends a one-time challenge code.
    TelegramPair {
        /// One-shot environment variable containing the Bot API token.
        #[arg(long, default_value = "TELEGRAM_BOT_TOKEN")]
        token_env: String,
        /// Bot API origin used for pairing; must match the daemon's configured origin.
        #[arg(long, default_value = "https://api.telegram.org")]
        api_base_url: String,
        /// Bounded pairing window in seconds.
        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,
    },
    /// List owner-authorized Telegram bindings.
    TelegramList,
    /// Inspect one Telegram binding without exposing its bot token.
    TelegramStatus {
        /// Stable binding ID returned by `telegram-create`.
        binding_id: String,
    },
    /// Terminally revoke one Telegram binding and remove its brokered token.
    TelegramRevoke {
        /// Stable Telegram binding ID.
        binding_id: String,
        /// Optimistic-concurrency revision returned by `telegram-status`.
        #[arg(long)]
        expected_revision: u64,
    },
    /// Verify a bot token and create an exact one-to-one Discord DM binding.
    DiscordCreate {
        /// Exact Discord human user snowflake allowed to submit messages.
        #[arg(long)]
        user_id: String,
        /// Exact one-to-one Discord DM channel snowflake.
        #[arg(long)]
        channel_id: String,
        /// One-shot environment variable containing the Discord bot token.
        #[arg(long, default_value = "DISCORD_BOT_TOKEN")]
        token_env: String,
    },
    /// Pair one explicit Discord DM using a one-time challenge.
    DiscordPair {
        /// Exact one-to-one Discord DM channel snowflake to verify.
        #[arg(long)]
        channel_id: String,
        /// One-shot environment variable containing the Discord bot token.
        #[arg(long, default_value = "DISCORD_BOT_TOKEN")]
        token_env: String,
        /// Exact Discord REST API v10 base, or literal-loopback HTTP for tests.
        #[arg(long, default_value = "https://discord.com/api/v10")]
        api_base_url: String,
        /// Bounded pairing window in seconds.
        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,
    },
    /// List owner-authorized Discord DM bindings.
    DiscordList,
    /// Inspect one Discord DM binding without exposing its bot token.
    DiscordStatus {
        /// Stable binding ID returned by `discord-pair` or `discord-create`.
        binding_id: String,
    },
    /// Terminally revoke one Discord DM binding and remove its brokered token.
    DiscordRevoke {
        /// Stable Discord binding ID.
        binding_id: String,
        /// Optimistic-concurrency revision returned by `discord-status`.
        #[arg(long)]
        expected_revision: u64,
    },
}

#[derive(Debug, Subcommand)]
enum ScheduleCommand {
    /// Create one active five-field cron schedule targeting an existing session.
    Create {
        /// Existing durable destination session.
        session_id: String,
        /// Bounded owner-visible label.
        #[arg(long)]
        name: String,
        /// Canonical five-field cron expression, quoted as one argument.
        #[arg(long)]
        cron: String,
        /// Canonical IANA time-zone identity such as `Pacific/Auckland`.
        #[arg(long)]
        timezone: String,
        /// Daemon-downtime behavior.
        #[arg(long, value_enum, default_value_t)]
        missed_run_policy: MissedRunPolicyArgument,
        /// Same-schedule overlap behavior.
        #[arg(long, value_enum, default_value_t)]
        overlap_policy: ScheduleOverlapPolicyArgument,
        /// Inclusive lateness accepted by `skip`.
        #[arg(long, default_value_t = 60_000)]
        misfire_grace_ms: i64,
        /// Explicitly allow a prompt beginning `/act`, `/edit`, `/manage`, or `/run`.
        #[arg(long)]
        allow_approval_required_action: bool,
        /// Exact input admitted on each fired occurrence.
        prompt: String,
    },
    /// List schedules in stable creation order.
    List,
    /// Inspect one schedule.
    Status {
        /// Stable schedule ID.
        schedule_id: String,
    },
    /// Pause one active schedule.
    Pause {
        /// Stable schedule ID.
        schedule_id: String,
        /// Revision returned by `schedule status`.
        #[arg(long)]
        expected_revision: u64,
    },
    /// Resume one paused schedule from the next future cron instant.
    Resume {
        /// Stable schedule ID.
        schedule_id: String,
        /// Revision returned by `schedule status`.
        #[arg(long)]
        expected_revision: u64,
    },
    /// Terminally cancel one schedule while retaining history.
    Cancel {
        /// Stable schedule ID.
        schedule_id: String,
        /// Revision returned by `schedule status`.
        #[arg(long)]
        expected_revision: u64,
    },
    /// Read newest-first durable occurrence history.
    Runs {
        /// Stable schedule ID.
        schedule_id: String,
        /// Maximum rows from 1 through 1000.
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum MissedRunPolicyArgument {
    Skip,
    #[default]
    Latest,
}

impl From<MissedRunPolicyArgument> for MissedRunPolicyCommand {
    fn from(value: MissedRunPolicyArgument) -> Self {
        match value {
            MissedRunPolicyArgument::Skip => Self::Skip,
            MissedRunPolicyArgument::Latest => Self::Latest,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum ScheduleOverlapPolicyArgument {
    Queue,
    #[default]
    SkipIfRunning,
}

impl From<ScheduleOverlapPolicyArgument> for ScheduleOverlapPolicyCommand {
    fn from(value: ScheduleOverlapPolicyArgument) -> Self {
        match value {
            ScheduleOverlapPolicyArgument::Queue => Self::Queue,
            ScheduleOverlapPolicyArgument::SkipIfRunning => Self::SkipIfRunning,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum MemoryCategoryArgument {
    Preference,
    #[default]
    Fact,
    Goal,
    Decision,
    Constraint,
    Identity,
    Credential,
    Health,
    Financial,
    ThirdPartyPrivate,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum MemorySensitivityArgument {
    Public,
    #[default]
    Internal,
    Private,
    Restricted,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum MemoryRetentionArgument {
    Session,
    #[default]
    Standard,
    Pinned,
    PolicyHold,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum MemoryAuthorizationArgument {
    OwnerPolicy,
    OwnerApproval,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ApprovalDecisionArgument {
    /// Authorize the exact immutable approval subject.
    Approve,
    /// Deny the exact immutable approval subject.
    Deny,
}

impl From<ApprovalDecisionArgument> for ApprovalDecisionCommand {
    fn from(value: ApprovalDecisionArgument) -> Self {
        match value {
            ApprovalDecisionArgument::Approve => Self::Approve,
            ApprovalDecisionArgument::Deny => Self::Deny,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ReconciliationOutcomeArgument {
    /// External evidence proves the original mutation succeeded.
    Succeeded,
    /// External evidence proves the original mutation failed.
    Failed,
}

impl From<ReconciliationOutcomeArgument> for ReconciliationOutcomeCommand {
    fn from(value: ReconciliationOutcomeArgument) -> Self {
        match value {
            ReconciliationOutcomeArgument::Succeeded => Self::Succeeded,
            ReconciliationOutcomeArgument::Failed => Self::Failed,
        }
    }
}

impl From<MemoryCategoryArgument> for MemoryCategoryCommand {
    fn from(value: MemoryCategoryArgument) -> Self {
        match value {
            MemoryCategoryArgument::Preference => Self::Preference,
            MemoryCategoryArgument::Fact => Self::Fact,
            MemoryCategoryArgument::Goal => Self::Goal,
            MemoryCategoryArgument::Decision => Self::Decision,
            MemoryCategoryArgument::Constraint => Self::Constraint,
            MemoryCategoryArgument::Identity => Self::Identity,
            MemoryCategoryArgument::Credential => Self::Credential,
            MemoryCategoryArgument::Health => Self::Health,
            MemoryCategoryArgument::Financial => Self::Financial,
            MemoryCategoryArgument::ThirdPartyPrivate => Self::ThirdPartyPrivate,
        }
    }
}

impl From<MemorySensitivityArgument> for MemorySensitivityCommand {
    fn from(value: MemorySensitivityArgument) -> Self {
        match value {
            MemorySensitivityArgument::Public => Self::Public,
            MemorySensitivityArgument::Internal => Self::Internal,
            MemorySensitivityArgument::Private => Self::Private,
            MemorySensitivityArgument::Restricted => Self::Restricted,
        }
    }
}

impl MemorySensitivityArgument {
    const fn as_query(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Private => "private",
            Self::Restricted => "restricted",
        }
    }
}

impl From<MemoryRetentionArgument> for MemoryRetentionCommand {
    fn from(value: MemoryRetentionArgument) -> Self {
        match value {
            MemoryRetentionArgument::Session => Self::Session,
            MemoryRetentionArgument::Standard => Self::Standard,
            MemoryRetentionArgument::Pinned => Self::Pinned,
            MemoryRetentionArgument::PolicyHold => Self::PolicyHold,
        }
    }
}

impl From<MemoryAuthorizationArgument> for MemoryPromotionAuthorizationCommand {
    fn from(value: MemoryAuthorizationArgument) -> Self {
        match value {
            MemoryAuthorizationArgument::OwnerPolicy => Self::OwnerPolicy,
            MemoryAuthorizationArgument::OwnerApproval => Self::OwnerApproval,
        }
    }
}

#[derive(Debug, Subcommand)]
enum SessionCommand {
    /// Create a new durable session.
    Create,
    /// List recently updated sessions owned by this exact local binding.
    List {
        /// Maximum sessions, newest updated first.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Search canonical user and final-assistant transcript text across owned local sessions.
    Search {
        /// Literal case-insensitive text query; wildcard syntax has no special meaning.
        query: String,
        /// Maximum newest matching turns.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Durably submit one input.
    Send {
        /// Opaque session ID returned by `session create`.
        session_id: String,
        /// UTF-8 input content.
        content: String,
        /// Stable delivery key; generated when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
        /// Delivery behavior.
        #[arg(long, value_enum, default_value_t = DeliveryArgument::Queue)]
        delivery: DeliveryArgument,
    },
    /// Durably submit one explicitly selected bounded UTF-8 local file as untrusted text.
    SendFile {
        /// Opaque session ID returned by `session create`.
        session_id: String,
        /// Existing regular file; symlinks and unsupported extensions are rejected.
        path: PathBuf,
        /// Instruction placed before the untrusted attachment.
        #[arg(
            long,
            default_value = "Review this untrusted text attachment and respond to it."
        )]
        prompt: String,
        /// Stable delivery key; generated when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
        /// Delivery behavior.
        #[arg(long, value_enum, default_value_t = DeliveryArgument::Queue)]
        delivery: DeliveryArgument,
    },
    /// Read current session queue/turn status.
    Status {
        /// Opaque session ID.
        session_id: String,
    },
    /// Watch durable timeline events over SSE.
    Watch {
        /// Opaque session ID.
        session_id: String,
        /// Resume strictly after this durable cursor.
        #[arg(long)]
        after: Option<u64>,
        /// Exit after this many events; zero watches indefinitely.
        #[arg(long, default_value_t = 0)]
        limit: usize,
    },
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum DeliveryArgument {
    /// Normal FIFO queueing.
    #[default]
    Queue,
    /// Steer at the next safe boundary.
    SteerAtBoundary,
    /// Interrupt current work and then queue.
    InterruptThenQueue,
}

impl From<DeliveryArgument> for DeliveryMode {
    fn from(value: DeliveryArgument) -> Self {
        match value {
            DeliveryArgument::Queue => Self::Queue,
            DeliveryArgument::SteerAtBoundary => Self::SteerAtBoundary,
            DeliveryArgument::InterruptThenQueue => Self::InterruptThenQueue,
        }
    }
}

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--browser-worker") {
        return browser_worker_main();
    }
    if std::env::args().nth(1).as_deref() == Some("--mcp-stdio-launcher") {
        return mcp_stdio_launcher_main();
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!(
                "mealyctl: could not initialize async runtime: {}",
                terminal_safe_single_line(&error.to_string())
            );
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "mealyctl: {}",
                terminal_safe_single_line(&error.to_string())
            );
            ExitCode::FAILURE
        }
    }
}

fn combined_cli_command() -> clap::Command {
    <LifecycleCommand as clap::Subcommand>::augment_subcommands(Arguments::command())
}

fn lifecycle_invocation(arguments: &[OsString]) -> bool {
    let mut index = 1;
    while let Some(argument) = arguments.get(index) {
        if argument == "--home" {
            index += 2;
            continue;
        }
        if argument
            .to_str()
            .is_some_and(|value| value.starts_with("--home="))
        {
            index += 1;
            continue;
        }
        if argument
            .to_str()
            .is_some_and(|value| value.starts_with('-'))
        {
            return false;
        }
        return argument.to_str().is_some_and(|value| {
            matches!(
                value,
                "install-status"
                    | "update"
                    | "update-status"
                    | "repair"
                    | "rollback"
                    | "uninstall"
                    | "completion"
                    | "update-transaction"
            )
        });
    }
    false
}

fn parse_operational_arguments(arguments: Vec<OsString>) -> Arguments {
    let mut matches = combined_cli_command().get_matches_from(arguments);
    <Arguments as clap::FromArgMatches>::from_arg_matches_mut(&mut matches)
        .unwrap_or_else(|error| error.exit())
}

async fn run_lifecycle(arguments: LifecycleArguments) -> Result<(), CliError> {
    match arguments.command {
        LifecycleCommand::InstallStatus => print_json(lifecycle::inspect_current_installation()?),
        LifecycleCommand::Update { version, approve } => {
            let plan = lifecycle::plan_update(&arguments.home, &version)?;
            if !approve || !plan.update_available {
                return print_json(plan);
            }
            if !plan.state_schema_compatible {
                return Err(CliError::UpdateSchemaChange {
                    current: plan.installation.state_schema_version.unwrap_or_default(),
                    target: plan.candidate.state_schema_version,
                });
            }
            if !plan.apply_supported {
                print_json(&plan)?;
                return Err(CliError::NativePackageUpdate);
            }
            launch_update_transaction(&arguments.home, &plan).await
        }
        LifecycleCommand::UpdateStatus { transaction_id } => print_json(
            lifecycle::load_update_transaction(&arguments.home, &transaction_id)?,
        ),
        LifecycleCommand::Repair { approve } => run_maintenance(
            &arguments.home,
            lifecycle::MaintenanceOperation::Repair,
            approve,
        ),
        LifecycleCommand::Rollback { approve } => run_maintenance(
            &arguments.home,
            lifecycle::MaintenanceOperation::Rollback,
            approve,
        ),
        LifecycleCommand::Uninstall { approve } => run_maintenance(
            &arguments.home,
            lifecycle::MaintenanceOperation::Uninstall,
            approve,
        ),
        LifecycleCommand::Completion { shell } => {
            let mut output = Vec::new();
            generate(
                Shell::from(shell),
                &mut combined_cli_command(),
                "mealyctl",
                &mut output,
            );
            if output.len() > 4 * 1024 * 1024 {
                return Err(CliError::Protocol(
                    "generated completion script exceeds its output bound".to_owned(),
                ));
            }
            std::io::stdout().write_all(&output)?;
            Ok(())
        }
        LifecycleCommand::UpdateTransaction { transaction_id } => {
            run_update_transaction(&arguments.home, &transaction_id).await
        }
    }
}

#[derive(Clone, Debug)]
struct VerifiedOwnerService {
    fragment: PathBuf,
}

async fn launch_update_transaction(
    home: &Path,
    plan: &lifecycle::UpdatePlan,
) -> Result<(), CliError> {
    let service = verify_owner_service(home, plan, true)?;
    let mut transaction = lifecycle::prepare_update_transaction(home, plan, &service.fragment)?;
    eprintln!("{}", terminal_safe_pretty_json(&transaction)?);
    if let Err(error) = launch_update_helper(&transaction) {
        transaction.failure = Some("update-helper-scheduling-failed".to_owned());
        transaction.phase = lifecycle::UpdateTransactionPhase::Aborted;
        lifecycle::persist_update_transaction(&transaction)?;
        return Err(error);
    }
    let deadline = tokio::time::Instant::now() + Duration::from_mins(35);
    loop {
        let record =
            lifecycle::load_update_transaction(&transaction.home, &transaction.transaction_id)?;
        if record.phase.is_terminal() {
            print_json(&record)?;
            return match record.phase {
                lifecycle::UpdateTransactionPhase::Committed => Ok(()),
                lifecycle::UpdateTransactionPhase::Aborted => Err(CliError::UpdateAborted),
                lifecycle::UpdateTransactionPhase::RolledBack => Err(CliError::UpdateRolledBack),
                lifecycle::UpdateTransactionPhase::RecoveryFailed => {
                    Err(CliError::UpdateRecoveryFailed)
                }
                _ => unreachable!("terminal update phase is exhaustive"),
            };
        }
        if tokio::time::Instant::now() >= deadline {
            print_json(&record)?;
            return Err(CliError::UpdateHelperPending(record.transaction_id));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn launch_update_helper(transaction: &lifecycle::UpdateTransaction) -> Result<(), CliError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = transaction;
        return Err(CliError::UnsupportedPlatform(
            "disconnect-resistant update apply is supported only by the Linux user service"
                .to_owned(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        let systemd_run = Path::new("/usr/bin/systemd-run");
        if !systemd_run.is_file() || !is_trusted_system_executable(systemd_run) {
            return Err(CliError::InvalidService(
                "update apply requires trusted /usr/bin/systemd-run".to_owned(),
            ));
        }
        let executable = &transaction.helper_executable;
        let unit = format!(
            "mealy-update-{}.service",
            transaction.transaction_id.replace('-', "")
        );
        let output = ProcessCommand::new(systemd_run)
            .arg("--user")
            .arg("--quiet")
            .arg("--collect")
            .arg(format!("--unit={unit}"))
            .arg("--property=Type=exec")
            .arg("--property=Restart=on-failure")
            .arg("--property=RestartSec=2s")
            .arg("--property=StartLimitIntervalSec=60s")
            .arg("--property=StartLimitBurst=5")
            .arg("--property=NoNewPrivileges=yes")
            .arg("--property=PrivateTmp=yes")
            .arg("--property=UMask=0077")
            .arg("--property=TasksMax=64")
            .arg("--property=MemoryMax=1G")
            .arg("--property=TimeoutStartSec=30min")
            .arg(executable)
            .arg("--home")
            .arg(&transaction.home)
            .arg("update-transaction")
            .arg(&transaction.transaction_id)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        if output.stdout.len() > 64 * 1024 || output.stderr.len() > 64 * 1024 {
            return Err(CliError::InvalidService(
                "systemd update-helper response exceeded its bound".to_owned(),
            ));
        }
        if !output.status.success() {
            return Err(CliError::InvalidService(format!(
                "could not schedule the independent update helper: {}",
                terminal_safe_single_line(String::from_utf8_lossy(&output.stderr).trim())
            )));
        }
        Ok(())
    }
}

async fn run_update_transaction(home: &Path, transaction_id: &str) -> Result<(), CliError> {
    let mut transaction = lifecycle::load_update_transaction(home, transaction_id)?;
    lifecycle::verify_update_helper_identity(&transaction, &std::env::current_exe()?)?;
    let _update_lock = lock_update_transactions(&transaction.home)?;
    if transaction.phase.is_terminal() {
        return finish_update_helper(&transaction);
    }
    if let Err(failure) = resume_update_transaction(&mut transaction).await {
        recover_failed_update_transaction(&mut transaction, failure).await?;
    }
    finish_update_helper(&transaction)
}

fn lock_update_transactions(home: &Path) -> Result<File, CliError> {
    let lock = open_private_home_lock(&home.join("update-transactions/update.lock"))?;
    lock.lock()?;
    Ok(lock)
}

fn finish_update_helper(transaction: &lifecycle::UpdateTransaction) -> Result<(), CliError> {
    print_json(transaction)?;
    if matches!(
        transaction.phase,
        lifecycle::UpdateTransactionPhase::Committed
            | lifecycle::UpdateTransactionPhase::Aborted
            | lifecycle::UpdateTransactionPhase::RolledBack
    ) {
        let _ = lifecycle::retire_update_helper(transaction);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum UpdateTransactionFailure {
    ServiceIdentity,
    CandidateVerification,
    Backup,
    Drain,
    Activation,
    ServiceStart,
    Qualification,
    Rollback,
}

impl UpdateTransactionFailure {
    const fn code(self) -> &'static str {
        match self {
            Self::ServiceIdentity => "owner-service-identity-failed",
            Self::CandidateVerification => "candidate-reverification-failed",
            Self::Backup => "pre-update-backup-failed",
            Self::Drain => "daemon-drain-failed",
            Self::Activation => "candidate-activation-failed",
            Self::ServiceStart => "updated-service-start-failed",
            Self::Qualification => "updated-service-qualification-failed",
            Self::Rollback => "automatic-rollback-failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpdateRecoveryRoute {
    AbortUntouched,
    RestorePrevious,
    FailClosed,
}

fn update_recovery_route(
    phase: lifecycle::UpdateTransactionPhase,
    slot: Option<lifecycle::ActiveTransactionSlot>,
    backup_available: bool,
    service_identity_trusted: bool,
) -> UpdateRecoveryRoute {
    if phase.is_terminal() {
        return UpdateRecoveryRoute::FailClosed;
    }
    if phase == lifecycle::UpdateTransactionPhase::Scheduled
        && slot == Some(lifecycle::ActiveTransactionSlot::Previous)
        && service_identity_trusted
    {
        return UpdateRecoveryRoute::AbortUntouched;
    }
    if backup_available
        && (slot.is_some()
            || matches!(
                phase,
                lifecycle::UpdateTransactionPhase::Activated
                    | lifecycle::UpdateTransactionPhase::Starting
                    | lifecycle::UpdateTransactionPhase::Verifying
                    | lifecycle::UpdateTransactionPhase::RollingBack
            ))
    {
        return UpdateRecoveryRoute::RestorePrevious;
    }
    UpdateRecoveryRoute::FailClosed
}

fn require_transaction_service(
    transaction: &lifecycle::UpdateTransaction,
    active: bool,
) -> Result<(), UpdateTransactionFailure> {
    verify_transaction_service(transaction, active)
        .map(|_| ())
        .map_err(|_| UpdateTransactionFailure::ServiceIdentity)
}

async fn resume_update_transaction(
    transaction: &mut lifecycle::UpdateTransaction,
) -> Result<(), UpdateTransactionFailure> {
    loop {
        match transaction.phase {
            lifecycle::UpdateTransactionPhase::Scheduled => {
                require_transaction_service(transaction, false)?;
                let plan = reverify_transaction_candidate(transaction)
                    .map_err(|_| UpdateTransactionFailure::CandidateVerification)?;
                if lifecycle::active_transaction_slot(transaction)
                    .map_err(|_| UpdateTransactionFailure::CandidateVerification)?
                    != lifecycle::ActiveTransactionSlot::Previous
                {
                    return Err(UpdateTransactionFailure::CandidateVerification);
                }
                let backup = create_update_backup(transaction)
                    .await
                    .map_err(|_| UpdateTransactionFailure::Backup)?;
                transaction.backup = Some(backup);
                transaction.phase = lifecycle::UpdateTransactionPhase::Prepared;
                lifecycle::persist_update_transaction(transaction)
                    .map_err(|_| UpdateTransactionFailure::Backup)?;
                drop(plan);
            }
            lifecycle::UpdateTransactionPhase::Prepared => {
                require_transaction_service(transaction, false)?;
                transaction.phase = lifecycle::UpdateTransactionPhase::Draining;
                lifecycle::persist_update_transaction(transaction)
                    .map_err(|_| UpdateTransactionFailure::Drain)?;
            }
            lifecycle::UpdateTransactionPhase::Draining => {
                require_transaction_service(transaction, false)?;
                drain_owner_service(transaction)
                    .await
                    .map_err(|_| UpdateTransactionFailure::Drain)?;
                transaction.phase = lifecycle::UpdateTransactionPhase::Stopped;
                lifecycle::persist_update_transaction(transaction)
                    .map_err(|_| UpdateTransactionFailure::Drain)?;
            }
            lifecycle::UpdateTransactionPhase::Stopped => {
                require_transaction_service(transaction, false)?;
                match lifecycle::active_transaction_slot(transaction)
                    .map_err(|_| UpdateTransactionFailure::Activation)?
                {
                    lifecycle::ActiveTransactionSlot::Previous => {
                        let plan = reverify_transaction_candidate(transaction)
                            .map_err(|_| UpdateTransactionFailure::CandidateVerification)?;
                        lifecycle::apply_archive_update(&transaction.home, &plan)
                            .map_err(|_| UpdateTransactionFailure::Activation)?;
                    }
                    lifecycle::ActiveTransactionSlot::Candidate => {}
                }
                if lifecycle::active_transaction_slot(transaction)
                    .map_err(|_| UpdateTransactionFailure::Activation)?
                    != lifecycle::ActiveTransactionSlot::Candidate
                {
                    return Err(UpdateTransactionFailure::Activation);
                }
                transaction.phase = lifecycle::UpdateTransactionPhase::Activated;
                lifecycle::persist_update_transaction(transaction)
                    .map_err(|_| UpdateTransactionFailure::Activation)?;
            }
            lifecycle::UpdateTransactionPhase::Activated => {
                require_transaction_service(transaction, false)?;
                transaction.phase = lifecycle::UpdateTransactionPhase::Starting;
                lifecycle::persist_update_transaction(transaction)
                    .map_err(|_| UpdateTransactionFailure::ServiceStart)?;
            }
            lifecycle::UpdateTransactionPhase::Starting => {
                require_transaction_service(transaction, false)?;
                start_owner_service().map_err(|_| UpdateTransactionFailure::ServiceStart)?;
                transaction.phase = lifecycle::UpdateTransactionPhase::Verifying;
                lifecycle::persist_update_transaction(transaction)
                    .map_err(|_| UpdateTransactionFailure::ServiceStart)?;
            }
            lifecycle::UpdateTransactionPhase::Verifying => {
                require_transaction_service(transaction, true)?;
                qualify_update_slot(transaction, lifecycle::ActiveTransactionSlot::Candidate)
                    .await
                    .map_err(|_| UpdateTransactionFailure::Qualification)?;
                transaction.phase = lifecycle::UpdateTransactionPhase::Committed;
                lifecycle::persist_update_transaction(transaction)
                    .map_err(|_| UpdateTransactionFailure::Qualification)?;
                return Ok(());
            }
            lifecycle::UpdateTransactionPhase::RollingBack => {
                resume_rollback_transaction(transaction).await?;
                return Ok(());
            }
            lifecycle::UpdateTransactionPhase::Committed
            | lifecycle::UpdateTransactionPhase::Aborted
            | lifecycle::UpdateTransactionPhase::RolledBack
            | lifecycle::UpdateTransactionPhase::RecoveryFailed => return Ok(()),
        }
    }
}

async fn resume_rollback_transaction(
    transaction: &mut lifecycle::UpdateTransaction,
) -> Result<(), UpdateTransactionFailure> {
    stop_owner_service(&transaction.home)
        .await
        .map_err(|_| UpdateTransactionFailure::Rollback)?;
    lifecycle::rollback_update_transaction(transaction)
        .map_err(|_| UpdateTransactionFailure::Rollback)?;
    require_transaction_service(transaction, false)?;
    start_owner_service().map_err(|_| UpdateTransactionFailure::Rollback)?;
    qualify_update_slot(transaction, lifecycle::ActiveTransactionSlot::Previous)
        .await
        .map_err(|_| UpdateTransactionFailure::Rollback)?;
    transaction.phase = lifecycle::UpdateTransactionPhase::RolledBack;
    lifecycle::persist_update_transaction(transaction)
        .map_err(|_| UpdateTransactionFailure::Rollback)
}

async fn recover_failed_update_transaction(
    transaction: &mut lifecycle::UpdateTransaction,
    failure: UpdateTransactionFailure,
) -> Result<(), CliError> {
    transaction.failure = Some(failure.code().to_owned());
    let slot = lifecycle::active_transaction_slot(transaction).ok();
    let recovery = update_recovery_route(
        transaction.phase,
        slot,
        transaction.backup.is_some(),
        !matches!(failure, UpdateTransactionFailure::ServiceIdentity),
    );
    if recovery == UpdateRecoveryRoute::AbortUntouched {
        let service_available = match owner_service_active() {
            Ok(true) => true,
            Ok(false) => start_owner_service().is_ok(),
            Err(_) => false,
        };
        if service_available
            && qualify_update_slot(transaction, lifecycle::ActiveTransactionSlot::Previous)
                .await
                .is_ok()
        {
            transaction.phase = lifecycle::UpdateTransactionPhase::Aborted;
            lifecycle::persist_update_transaction(transaction)?;
            return Ok(());
        }
    }
    if recovery == UpdateRecoveryRoute::RestorePrevious {
        transaction.phase = lifecycle::UpdateTransactionPhase::RollingBack;
        transaction.rollback_attempted = true;
        lifecycle::persist_update_transaction(transaction)?;
        if resume_update_transaction(transaction).await.is_ok() {
            return Ok(());
        }
        transaction.failure = Some(UpdateTransactionFailure::Rollback.code().to_owned());
    } else {
        let _ = start_owner_service();
    }
    transaction.phase = lifecycle::UpdateTransactionPhase::RecoveryFailed;
    lifecycle::persist_update_transaction(transaction)?;
    Ok(())
}

fn reverify_transaction_candidate(
    transaction: &lifecycle::UpdateTransaction,
) -> Result<lifecycle::UpdatePlan, CliError> {
    let plan = lifecycle::plan_update_for_managed_prefix(
        &transaction.home,
        &format!("v{}", transaction.candidate.version),
        &transaction.prefix,
    )?;
    if plan.candidate != transaction.candidate
        || plan.installation.current_version != transaction.previous_version
        || plan.installation.current_commit.as_deref() != Some(transaction.previous_commit.as_str())
        || !plan.update_available
        || !plan.state_schema_compatible
        || !plan.apply_supported
    {
        return Err(CliError::UpdateTransactionInconsistent);
    }
    Ok(plan)
}

async fn create_update_backup(
    transaction: &lifecycle::UpdateTransaction,
) -> Result<lifecycle::UpdateBackupEvidence, CliError> {
    let connection = load_connection(&transaction.home)?;
    if connection.api_version != API_VERSION {
        return Err(CliError::UpdateTransactionInconsistent);
    }
    let client = lifecycle_client()?;
    let name = format!("pre-update-{}", transaction.transaction_id);
    let response = authorized_long(
        client.post(format!("{}/v1/admin/backups", connection.base_url)),
        &connection,
    )
    .json(&CreateBackupRequest {
        api_version: API_VERSION.to_owned(),
        name: name.clone(),
        include_secrets: false,
        secret_passphrase: None,
    })
    .send()
    .await?;
    let backup = if response.status().is_success() {
        decode::<BackupResponse>(response).await?
    } else {
        let response = authorized_long(
            client.post(format!(
                "{}/v1/admin/backup-verifications",
                connection.base_url
            )),
            &connection,
        )
        .json(&VerifyBackupRequest {
            api_version: API_VERSION.to_owned(),
            name: name.clone(),
            secret_passphrase: None,
        })
        .send()
        .await?;
        let verified = decode::<BackupVerificationResponse>(response).await?;
        BackupResponse {
            api_version: verified.api_version,
            name: verified.name,
            path: verified.path,
            manifest_digest: verified.manifest_digest,
            file_count: verified.file_count,
            total_bytes: verified.total_bytes,
            schema_version: verified.schema_version,
            artifact_count: verified.artifact_count,
            secrets_included: verified.secrets_included,
        }
    };
    if backup.api_version != API_VERSION
        || backup.name != name
        || backup.secrets_included
        || backup.schema_version != transaction.candidate.state_schema_version
        || backup.file_count == 0
        || backup.manifest_digest.len() != 64
        || !backup
            .manifest_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CliError::UpdateTransactionInconsistent);
    }
    Ok(lifecycle::UpdateBackupEvidence {
        name: backup.name,
        manifest_digest: backup.manifest_digest,
        state_schema_version: backup.schema_version,
    })
}

async fn drain_owner_service(transaction: &lifecycle::UpdateTransaction) -> Result<(), CliError> {
    if !owner_service_active()? {
        let (_home, lock) = lock_stopped_home(&transaction.home)?;
        drop(lock);
        return Ok(());
    }
    let connection = load_connection(&transaction.home)?;
    let client = lifecycle_client()?;
    let response = authorized_long(
        client.post(format!("{}/v1/admin/drain", connection.base_url)),
        &connection,
    )
    .json(&DrainDaemonRequest {
        api_version: API_VERSION.to_owned(),
    })
    .send()
    .await?;
    let drain = decode::<DrainDaemonResponse>(response).await?;
    if drain.api_version != API_VERSION
        || drain.start_id.is_empty()
        || drain.start_id.len() > 128
        || drain.deadline_ms > 300_000
    {
        return Err(CliError::UpdateTransactionInconsistent);
    }
    let deadline = tokio::time::Instant::now()
        + Duration::from_millis(drain.deadline_ms.saturating_add(30_000));
    loop {
        if !owner_service_active()? && !transaction.home.join("connection.json").exists() {
            let (_home, lock) = lock_stopped_home(&transaction.home)?;
            drop(lock);
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(CliError::UpdateTransactionInconsistent);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn stop_owner_service(home: &Path) -> Result<(), CliError> {
    run_systemctl(&["--user", "stop", "--no-block", "mealy.service"], true)?;
    let deadline = tokio::time::Instant::now() + Duration::from_mins(2);
    loop {
        if !owner_service_active()? {
            let (_home, lock) = lock_stopped_home(home)?;
            drop(lock);
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(CliError::UpdateTransactionInconsistent);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn start_owner_service() -> Result<(), CliError> {
    run_systemctl(&["--user", "start", "--no-block", "mealy.service"], true)
}

async fn qualify_update_slot(
    transaction: &lifecycle::UpdateTransaction,
    expected: lifecycle::ActiveTransactionSlot,
) -> Result<(), CliError> {
    let doctor = wait_for_onboard_readiness(&transaction.home).await?;
    if doctor.api_version != API_VERSION || !doctor.control_plane_ready || !doctor.sandbox_available
    {
        return Err(CliError::UpdateTransactionInconsistent);
    }
    let connection = load_connection(&transaction.home)?;
    let client = lifecycle_client()?;
    let readiness = authorized(
        client.get(format!("{}/health/ready", connection.base_url)),
        &connection,
    )
    .send()
    .await?;
    let readiness = decode::<ReadinessResponse>(readiness).await?;
    if readiness.api_version != API_VERSION || !readiness.ready {
        return Err(CliError::UpdateTransactionInconsistent);
    }
    if !owner_service_active()? || lifecycle::active_transaction_slot(transaction)? != expected {
        return Err(CliError::UpdateTransactionInconsistent);
    }
    Ok(())
}

fn lifecycle_client() -> Result<Client, CliError> {
    Ok(Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .build()?)
}

fn verify_transaction_service(
    transaction: &lifecycle::UpdateTransaction,
    require_active: bool,
) -> Result<VerifiedOwnerService, CliError> {
    let plan = lifecycle::UpdatePlan {
        schema_version: "mealy.update-plan.v1",
        installation: lifecycle::inspect_managed_prefix(&transaction.prefix)?,
        requested_version: format!("v{}", transaction.candidate.version),
        candidate: transaction.candidate.clone(),
        update_available: false,
        state_schema_compatible: true,
        apply_supported: true,
        native_update_command: None,
    };
    let service = verify_owner_service(&transaction.home, &plan, require_active)?;
    if service.fragment != transaction.service_fragment {
        return Err(CliError::UpdateTransactionInconsistent);
    }
    Ok(service)
}

fn verify_owner_service(
    home: &Path,
    plan: &lifecycle::UpdatePlan,
    require_active: bool,
) -> Result<VerifiedOwnerService, CliError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (home, plan, require_active);
        return Err(CliError::UnsupportedPlatform(
            "managed update apply requires the Linux user service".to_owned(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        if plan.installation.installation_kind != lifecycle::InstallationKind::ManagedArchive
            || plan.installation.integrity != lifecycle::IntegrityStatus::Verified
        {
            return Err(CliError::UpdateTransactionInconsistent);
        }
        let home = fs::canonicalize(home)?;
        let daemon = plan
            .installation
            .managed_prefix
            .as_ref()
            .ok_or(CliError::UpdateTransactionInconsistent)?
            .join("bin/mealyd")
            .canonicalize()?;
        let paths = service_read_write_paths(&home)?;
        let (_, _, expected, _) = service_definition(&daemon, &home, &paths)?;
        let output = run_systemctl_output(&[
            "--user",
            "show",
            "--property=FragmentPath",
            "--value",
            "mealy.service",
        ])?;
        let fragment_text = std::str::from_utf8(&output)
            .map_err(|_| CliError::UpdateTransactionInconsistent)?
            .trim_end_matches('\n');
        if fragment_text.is_empty()
            || fragment_text.contains('\n')
            || fragment_text.chars().any(char::is_control)
        {
            return Err(CliError::UpdateTransactionInconsistent);
        }
        let fragment = PathBuf::from(fragment_text);
        let metadata = fs::symlink_metadata(&fragment)?;
        let canonical = fragment.canonicalize()?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || canonical != fragment
            || lifecycle::read_bounded_regular_file(&fragment, 64 * 1024)? != expected.as_bytes()
        {
            return Err(CliError::UpdateTransactionInconsistent);
        }
        if require_active && !owner_service_active()? {
            return Err(CliError::InvalidService(
                "managed update apply requires the active verified mealy.service; the no-mutation plan remains valid"
                    .to_owned(),
            ));
        }
        Ok(VerifiedOwnerService { fragment })
    }
}

fn owner_service_active() -> Result<bool, CliError> {
    let systemctl = trusted_systemctl()?;
    let status = ProcessCommand::new(systemctl)
        .args(["--user", "is-active", "--quiet", "mealy.service"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    match status.code() {
        Some(0) => Ok(true),
        Some(3) => Ok(false),
        _ => Err(CliError::UpdateTransactionInconsistent),
    }
}

fn run_systemctl(arguments: &[&str], require_success: bool) -> Result<(), CliError> {
    let systemctl = trusted_systemctl()?;
    let output = ProcessCommand::new(systemctl)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if output.stdout.len() > 64 * 1024 || output.stderr.len() > 64 * 1024 {
        return Err(CliError::UpdateTransactionInconsistent);
    }
    if require_success && !output.status.success() {
        return Err(CliError::InvalidService(format!(
            "systemctl {} failed: {}",
            arguments.join(" "),
            terminal_safe_single_line(String::from_utf8_lossy(&output.stderr).trim())
        )));
    }
    Ok(())
}

fn run_systemctl_output(arguments: &[&str]) -> Result<Vec<u8>, CliError> {
    let systemctl = trusted_systemctl()?;
    let output = ProcessCommand::new(systemctl)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success()
        || output.stdout.len() > 64 * 1024
        || output.stderr.len() > 64 * 1024
    {
        return Err(CliError::UpdateTransactionInconsistent);
    }
    Ok(output.stdout)
}

fn trusted_systemctl() -> Result<&'static Path, CliError> {
    let systemctl = Path::new("/usr/bin/systemctl");
    if !systemctl.is_file() || !is_trusted_system_executable(systemctl) {
        return Err(CliError::InvalidService(
            "managed update apply requires trusted /usr/bin/systemctl".to_owned(),
        ));
    }
    Ok(systemctl)
}

fn run_maintenance(
    home: &Path,
    operation: lifecycle::MaintenanceOperation,
    approve: bool,
) -> Result<(), CliError> {
    let plan = lifecycle::plan_maintenance(operation)?;
    if !approve || !plan.action_required {
        return print_json(plan);
    }
    if !plan.apply_supported {
        print_json(&plan)?;
        return Err(if plan.native_command.is_some() {
            CliError::NativeMaintenance
        } else {
            CliError::MaintenanceUnavailable
        });
    }
    eprintln!("{}", terminal_safe_pretty_json(&plan)?);
    match operation {
        lifecycle::MaintenanceOperation::Repair => {
            lifecycle::repair_archive_manager(&plan.installation)?;
            print_json(lifecycle::inspect_current_installation()?)
        }
        lifecycle::MaintenanceOperation::Rollback => lifecycle::run_archive_manager(
            &plan.installation,
            home,
            lifecycle::ArchiveManagerAction::Rollback,
        )
        .map_err(CliError::from),
        lifecycle::MaintenanceOperation::Uninstall => {
            remove_verified_owner_service_if_present(home)?;
            lifecycle::run_archive_manager(
                &plan.installation,
                home,
                lifecycle::ArchiveManagerAction::Uninstall,
            )
            .map_err(CliError::from)
        }
    }
}

#[cfg(target_os = "linux")]
fn remove_verified_owner_service_if_present(home: &Path) -> Result<(), CliError> {
    let default = linux_default_service_destination()?;
    let default_present = match fs::symlink_metadata(&default) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(CliError::Io(error)),
    };
    let loaded = match loaded_owner_service_fragment() {
        Ok(value) => value,
        Err(_) if !default_present => return Ok(()),
        Err(error) => return Err(error),
    };
    if !default_present && loaded.is_none() {
        return Ok(());
    }
    let plan = plan_service_removal(home, loaded.as_deref())?;
    if !plan.action_required || !plan.apply_supported {
        return Err(CliError::InvalidService(
            "installed owner service could not be verified for safe uninstall".to_owned(),
        ));
    }
    eprintln!("{}", terminal_safe_pretty_json(&plan)?);
    apply_service_removal(&plan)
}

#[cfg(not(target_os = "linux"))]
fn remove_verified_owner_service_if_present(_home: &Path) -> Result<(), CliError> {
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn run() -> Result<(), CliError> {
    let raw_arguments: Vec<OsString> = std::env::args_os().collect();
    if lifecycle_invocation(&raw_arguments) {
        return run_lifecycle(LifecycleArguments::parse_from(raw_arguments)).await;
    }
    let arguments = parse_operational_arguments(raw_arguments);
    if let Command::Onboard(options) = &arguments.command {
        return run_onboard(&arguments.home, options).await;
    }
    if let Command::Setup(options) = &arguments.command {
        return run_setup(&arguments.home, options);
    }
    if let Command::Service { command } = &arguments.command {
        return run_service_installation(&arguments.home, command);
    }
    if let Command::Config { command } = &arguments.command {
        return run_config_operation(&arguments.home, command);
    }
    if let Command::Skill { command } = &arguments.command {
        return run_skill_operation(&arguments.home, command);
    }
    if let Command::Usage { days } = &arguments.command
        && !(1..=31).contains(days)
    {
        return Err(CliError::Protocol(
            "usage history --days must be between 1 and 31".to_owned(),
        ));
    }
    if let Command::RestoreActivate {
        name,
        expected_manifest_digest,
        passphrase_env,
        approve,
    } = &arguments.command
    {
        return run_restore_activation(
            &arguments.home,
            name,
            expected_manifest_digest,
            passphrase_env,
            *approve,
        );
    }
    if let Command::MigrationHomeActivate {
        name,
        expected_manifest_digest,
        expected_from_schema_version,
        expected_to_schema_version,
        inherited_home_lock_stdin,
        approve,
    } = &arguments.command
    {
        return run_migration_home_activation(
            &arguments.home,
            name,
            expected_manifest_digest,
            *expected_from_schema_version,
            *expected_to_schema_version,
            *inherited_home_lock_stdin,
            *approve,
        );
    }
    let connection = load_connection(&arguments.home)?;
    if connection.api_version != API_VERSION {
        return Err(CliError::Protocol(format!(
            "connection descriptor uses unsupported API version {:?}",
            connection.api_version
        )));
    }
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .build()?;
    match arguments.command {
        Command::Onboard(_) => {
            unreachable!("offline onboarding returned before ordinary API initialization")
        }
        Command::Setup(_) => unreachable!("offline setup returned before API initialization"),
        Command::Chat { session_id } => {
            run_chat(&client, &arguments.home, &connection, session_id.as_deref()).await?;
        }
        Command::Session { command } => {
            run_session(&client, &arguments.home, &connection, command).await?;
        }
        Command::Task { command } => run_task(&client, &connection, command).await?,
        Command::Delegation { command } => {
            run_delegation(&client, &connection, command).await?;
        }
        Command::Approval { command } => run_approval(&client, &connection, command).await?,
        Command::Effect { command } => run_effect(&client, &connection, command).await?,
        Command::Memory { command } => run_memory(&client, &connection, command).await?,
        Command::Compaction { command } => run_compaction(&client, &connection, command).await?,
        Command::Extension { command } => run_extension(&client, &connection, command).await?,
        Command::Skill { .. } => {
            unreachable!("offline skill operation returned before API setup")
        }
        Command::Channel { command } => run_channel(&client, &connection, command).await?,
        Command::Schedule { command } => run_schedule(&client, &connection, command).await?,
        Command::Health => {
            let response = authorized(
                client.get(format!("{}/health/live", connection.base_url)),
                &connection,
            )
            .send()
            .await?;
            print_json(decode::<HealthResponse>(response).await?)?;
        }
        Command::Status => {
            let response = authorized(
                client.get(format!("{}/v1/admin/status", connection.base_url)),
                &connection,
            )
            .send()
            .await?;
            print_json(decode::<AdminStatusResponse>(response).await?)?;
        }
        Command::Metrics => {
            let response = authorized(
                client.get(format!("{}/v1/admin/metrics", connection.base_url)),
                &connection,
            )
            .send()
            .await?;
            print_json(decode::<AdminMetricsResponse>(response).await?)?;
        }
        Command::Usage { days } => {
            let to_ms = i64::try_from(unix_timestamp_millis()?).map_err(|_| {
                CliError::Protocol("system clock exceeds the usage-report range".to_owned())
            })?;
            let from_ms = to_ms
                .checked_sub(i64::from(days) * USAGE_DAY_MS)
                .ok_or_else(|| CliError::Protocol("usage-report range underflowed".to_owned()))?;
            let response = authorized(
                client
                    .get(format!("{}/v1/admin/usage", connection.base_url))
                    .query(&[("fromMs", from_ms), ("toMs", to_ms)]),
                &connection,
            )
            .send()
            .await?;
            let report = decode::<AdminUsageReportResponse>(response).await?;
            if report.api_version != API_VERSION
                || report.from_ms != from_ms
                || report.to_ms != to_ms
            {
                return Err(CliError::Protocol(
                    "usage history response does not match the exact requested range".to_owned(),
                ));
            }
            print_json(report)?;
        }
        Command::Doctor => {
            let response = authorized(
                client.get(format!("{}/v1/admin/doctor", connection.base_url)),
                &connection,
            )
            .send()
            .await?;
            print_json(decode::<DoctorResponse>(response).await?)?;
        }
        Command::Dashboard => {
            dashboard::run(&arguments.home, &connection).await?;
        }
        Command::Drain => {
            let response = authorized_long(
                client.post(format!("{}/v1/admin/drain", connection.base_url)),
                &connection,
            )
            .json(&DrainDaemonRequest {
                api_version: API_VERSION.to_owned(),
            })
            .send()
            .await?;
            print_json(decode::<DrainDaemonResponse>(response).await?)?;
        }
        Command::Backup {
            name,
            include_secrets,
            passphrase_env,
        } => {
            let secret_passphrase = include_secrets
                .then(|| read_passphrase_environment(&passphrase_env))
                .transpose()?;
            let mut command = CreateBackupRequest {
                api_version: API_VERSION.to_owned(),
                name,
                include_secrets,
                secret_passphrase: secret_passphrase
                    .as_deref()
                    .map(|value| value.as_str().to_owned()),
            };
            let request = authorized_long(
                client.post(format!("{}/v1/admin/backups", connection.base_url)),
                &connection,
            )
            .json(&command);
            if let Some(passphrase) = &mut command.secret_passphrase {
                passphrase.zeroize();
            }
            let response = request.send().await?;
            print_json(decode::<BackupResponse>(response).await?)?;
        }
        Command::RestoreVerify {
            name,
            passphrase_env,
        } => {
            let secret_passphrase = passphrase_env
                .as_deref()
                .map(read_passphrase_environment)
                .transpose()?;
            let mut command = VerifyBackupRequest {
                api_version: API_VERSION.to_owned(),
                name,
                secret_passphrase: secret_passphrase
                    .as_deref()
                    .map(|value| value.as_str().to_owned()),
            };
            let request = authorized_long(
                client.post(format!(
                    "{}/v1/admin/backup-verifications",
                    connection.base_url
                )),
                &connection,
            )
            .json(&command);
            if let Some(passphrase) = &mut command.secret_passphrase {
                passphrase.zeroize();
            }
            let response = request.send().await?;
            print_json(decode::<BackupVerificationResponse>(response).await?)?;
        }
        Command::RestoreActivate { .. } => {
            unreachable!("offline restore activation is dispatched before connection loading")
        }
        Command::MigrationHomeActivate { .. } => {
            unreachable!(
                "offline migration-home activation is dispatched before connection loading"
            )
        }
        Command::GarbageCollect => {
            let response = authorized_long(
                client.post(format!("{}/v1/admin/artifact-gc", connection.base_url)),
                &connection,
            )
            .json(&RunGarbageCollectionRequest {
                api_version: API_VERSION.to_owned(),
            })
            .send()
            .await?;
            print_json(decode::<GarbageCollectionResponse>(response).await?)?;
        }
        Command::Export {
            name,
            kind,
            selector,
        } => {
            let response = authorized_long(
                client.post(format!("{}/v1/admin/exports", connection.base_url)),
                &connection,
            )
            .json(&CreateExportRequest {
                api_version: API_VERSION.to_owned(),
                name,
                kind: kind.into(),
                selector,
            })
            .send()
            .await?;
            print_json(decode::<ExportResponse>(response).await?)?;
        }
        Command::Service { .. } => unreachable!("service installation returned before API setup"),
        Command::Config { .. } => unreachable!("configuration operation returned before API setup"),
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
enum ChatLine {
    Send {
        delivery: DeliveryMode,
        content: String,
    },
    LocalAttachment {
        path: PathBuf,
    },
    ResolveApproval {
        approval_id: String,
        subject_digest: String,
        decision: ApprovalDecisionCommand,
    },
    Memory(ChatMemoryCommand),
    History(String),
    Help,
    Session,
    Exit,
    Empty,
}

#[derive(Debug, Eq, PartialEq)]
enum ChatMemoryCommand {
    UseNamespace(String),
    Remember(String),
    List,
    Search(String),
    Status(String),
    Activate {
        memory_id: String,
        revision_id: String,
    },
    Correct {
        memory_id: String,
        expected_revision: u64,
        content: String,
    },
    Expire {
        memory_id: String,
        expected_revision: u64,
    },
    Reject {
        memory_id: String,
        expected_revision: u64,
    },
    Delete {
        memory_id: String,
        expected_revision: u64,
    },
}

#[derive(Debug)]
enum ChatInput {
    Line(String),
    EndOfFile,
    Failed(String),
}

#[derive(Debug)]
enum ChatPromotion {
    Task {
        task_id: String,
        correlation_id: String,
        after: u64,
    },
    Steered,
}

#[derive(Debug)]
struct ChatApprovalPreview {
    approval: ApprovalResponse,
    effect: EffectResponse,
}

#[derive(Debug)]
enum ChatUpdate {
    Accepted {
        inbox_entry_id: String,
        delivery: DeliveryMode,
    },
    Resumed {
        reference: String,
    },
    Promoted {
        inbox_entry_id: String,
        task_id: String,
    },
    Steered {
        inbox_entry_id: String,
    },
    InterruptRequested {
        inbox_entry_id: String,
    },
    Status {
        task_id: String,
        status: TaskStatus,
    },
    Progress {
        task_id: String,
        event_type: String,
        detail: Option<String>,
    },
    TextDelta {
        task_id: String,
        delta: String,
    },
    Approval(Box<ChatApprovalPreview>),
    Finished(Box<TaskResponse>),
    Failed {
        reference: String,
        message: String,
    },
}

#[derive(Debug)]
struct ResumableChatAdmission {
    inbox_entry_id: String,
    accepted_cursor: u64,
}

#[derive(Debug)]
struct ResumableChatTask {
    task_id: String,
    correlation_id: String,
}

#[derive(Debug, Default)]
struct ResumableChatState {
    pending: Vec<ResumableChatAdmission>,
    active: Option<ResumableChatTask>,
}

fn parse_chat_line(line: &str) -> ChatLine {
    let line = line.trim();
    if line.is_empty() {
        return ChatLine::Empty;
    }
    if matches!(line, "/quit" | "/exit") {
        return ChatLine::Exit;
    }
    if line == "/help" {
        return ChatLine::Help;
    }
    if line == "/session" {
        return ChatLine::Session;
    }
    if let Some(path) = line.strip_prefix("/attach ") {
        let path = path.trim();
        return if path.is_empty() {
            ChatLine::Help
        } else {
            ChatLine::LocalAttachment {
                path: PathBuf::from(path),
            }
        };
    }
    for (prefix, decision) in [
        ("/approve ", ApprovalDecisionCommand::Approve),
        ("/deny ", ApprovalDecisionCommand::Deny),
    ] {
        if let Some(arguments) = line.strip_prefix(prefix) {
            let mut fields = arguments.split_whitespace();
            if let (Some(approval_id), Some(subject_digest), None) =
                (fields.next(), fields.next(), fields.next())
            {
                return ChatLine::ResolveApproval {
                    approval_id: approval_id.to_owned(),
                    subject_digest: subject_digest.to_owned(),
                    decision,
                };
            }
            return ChatLine::Help;
        }
    }
    if let Some(memory) = parse_chat_memory_line(line) {
        return memory;
    }
    if let Some(query) = line.strip_prefix("/history ") {
        let query = query.trim();
        return if query.is_empty() {
            ChatLine::Help
        } else {
            ChatLine::History(query.to_owned())
        };
    }
    for prefix in [
        mealy_application::PROCESS_RUN_INPUT_PREFIX,
        mealy_application::WORKSPACE_ACTION_INPUT_PREFIX,
        mealy_application::WORKSPACE_EDIT_INPUT_PREFIX,
        mealy_application::WORKSPACE_MANAGE_INPUT_PREFIX,
    ] {
        if let Some(content) = line.strip_prefix(prefix) {
            return ChatLine::Send {
                delivery: DeliveryMode::Queue,
                content: format!("{prefix}{}", content.trim()),
            };
        }
    }
    for (prefix, delivery) in [
        ("/queue ", DeliveryMode::Queue),
        ("/steer ", DeliveryMode::SteerAtBoundary),
        ("/interrupt ", DeliveryMode::InterruptThenQueue),
    ] {
        if let Some(content) = line.strip_prefix(prefix) {
            return ChatLine::Send {
                delivery,
                content: content.trim().to_owned(),
            };
        }
    }
    if line.starts_with('/') {
        return ChatLine::Help;
    }
    ChatLine::Send {
        delivery: DeliveryMode::Queue,
        content: line.to_owned(),
    }
}

fn parse_chat_memory_line(line: &str) -> Option<ChatLine> {
    if let Some(content) = line.strip_prefix("/remember ") {
        let content = content.trim();
        return Some(if content.is_empty() {
            ChatLine::Help
        } else {
            ChatLine::Memory(ChatMemoryCommand::Remember(content.to_owned()))
        });
    }
    if line == "/memories" {
        return Some(ChatLine::Memory(ChatMemoryCommand::List));
    }
    if let Some(query) = line.strip_prefix("/memories ") {
        let query = query.trim();
        return Some(if query.is_empty() {
            ChatLine::Help
        } else {
            ChatLine::Memory(ChatMemoryCommand::Search(query.to_owned()))
        });
    }
    if let Some(workspace) = line.strip_prefix("/memory-use ") {
        let workspace = workspace.trim();
        return Some(if workspace.is_empty() {
            ChatLine::Help
        } else {
            ChatLine::Memory(ChatMemoryCommand::UseNamespace(workspace.to_owned()))
        });
    }
    if let Some(memory_id) = line.strip_prefix("/memory-status ") {
        return Some(
            parse_single_chat_memory_id(memory_id).map_or(ChatLine::Help, |memory_id| {
                ChatLine::Memory(ChatMemoryCommand::Status(memory_id))
            }),
        );
    }
    if let Some(arguments) = line.strip_prefix("/memory-activate ") {
        return Some(parse_chat_memory_pair(arguments).map_or(
            ChatLine::Help,
            |(first, second)| {
                ChatLine::Memory(ChatMemoryCommand::Activate {
                    memory_id: first,
                    revision_id: second,
                })
            },
        ));
    }
    if let Some(arguments) = line.strip_prefix("/memory-correct ") {
        let parsed = split_first_chat_field(arguments).and_then(|(memory_id, remaining)| {
            split_first_chat_field(remaining).and_then(|(revision, content)| {
                revision
                    .parse::<u64>()
                    .ok()
                    .filter(|_| !content.is_empty())
                    .map(|expected_revision| ChatMemoryCommand::Correct {
                        memory_id: memory_id.to_owned(),
                        expected_revision,
                        content: content.to_owned(),
                    })
            })
        });
        return Some(parsed.map_or(ChatLine::Help, ChatLine::Memory));
    }
    for (prefix, operation) in [
        ("/memory-expire ", ChatMemoryLifecycleOperation::Expire),
        ("/memory-reject ", ChatMemoryLifecycleOperation::Reject),
        ("/memory-delete ", ChatMemoryLifecycleOperation::Delete),
    ] {
        if let Some(arguments) = line.strip_prefix(prefix) {
            let parsed = parse_chat_memory_pair(arguments).and_then(|(memory_id, revision)| {
                revision
                    .parse::<u64>()
                    .ok()
                    .map(|expected_revision| match operation {
                        ChatMemoryLifecycleOperation::Expire => ChatMemoryCommand::Expire {
                            memory_id,
                            expected_revision,
                        },
                        ChatMemoryLifecycleOperation::Reject => ChatMemoryCommand::Reject {
                            memory_id,
                            expected_revision,
                        },
                        ChatMemoryLifecycleOperation::Delete => ChatMemoryCommand::Delete {
                            memory_id,
                            expected_revision,
                        },
                    })
            });
            return Some(parsed.map_or(ChatLine::Help, ChatLine::Memory));
        }
    }
    None
}

fn split_first_chat_field(value: &str) -> Option<(&str, &str)> {
    let value = value.trim_start();
    let index = value.find(char::is_whitespace)?;
    let (field, remaining) = value.split_at(index);
    (!field.is_empty()).then_some((field, remaining.trim_start()))
}

#[derive(Clone, Copy)]
enum ChatMemoryLifecycleOperation {
    Expire,
    Reject,
    Delete,
}

fn parse_single_chat_memory_id(value: &str) -> Option<String> {
    let mut fields = value.split_whitespace();
    match (fields.next(), fields.next()) {
        (Some(value), None) => Some(value.to_owned()),
        _ => None,
    }
}

fn parse_chat_memory_pair(value: &str) -> Option<(String, String)> {
    let mut fields = value.split_whitespace();
    match (fields.next(), fields.next(), fields.next()) {
        (Some(first), Some(second), None) => Some((first.to_owned(), second.to_owned())),
        _ => None,
    }
}

#[allow(clippy::too_many_lines)]
async fn run_chat(
    client: &Client,
    home: &Path,
    connection: &LocalConnectionInfo,
    existing_session_id: Option<&str>,
) -> Result<(), CliError> {
    let mut memory_workspace = default_chat_memory_workspace(client, connection).await?;
    let (session_id, resume_status) = if let Some(session_id) = existing_session_id {
        let response = authorized(
            client.get(format!(
                "{}/v1/sessions/{session_id}/status",
                connection.base_url
            )),
            connection,
        )
        .send()
        .await?;
        let status = decode::<SessionStatusResponse>(response).await?;
        (status.session_id.clone(), Some(status))
    } else {
        let response = authorized(
            client.post(format!("{}/v1/sessions", connection.base_url)),
            connection,
        )
        .json(&CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
        })
        .send()
        .await?;
        (
            decode::<CreateSessionResponse>(response).await?.session_id,
            None,
        )
    };
    println!(
        "Mealy chat session {}",
        terminal_safe_single_line(&session_id)
    );
    println!(
        "Governed memory namespace {}",
        terminal_safe_single_line(&memory_workspace)
    );
    println!(
        "Type /help for concurrent delivery and approval controls, /session to print the durable session ID, or /quit."
    );
    let (input_sender, mut input_receiver) =
        tokio::sync::mpsc::channel(CHAT_INPUT_CHANNEL_CAPACITY);
    start_chat_input_reader(input_sender)?;
    let (update_sender, mut update_receiver) =
        tokio::sync::mpsc::channel(CHAT_UPDATE_CHANNEL_CAPACITY);
    let mut watchers = tokio::task::JoinSet::new();
    if let Some(status) = resume_status {
        match discover_resumable_chat_state(client, connection, &status).await {
            Ok(state) => {
                start_resumed_chat_watchers(
                    &mut watchers,
                    client,
                    home,
                    &session_id,
                    status.latest_cursor.0,
                    status.pending_inputs,
                    state,
                    &update_sender,
                );
            }
            Err(error) => {
                eprintln!(
                    "existing work could not be rediscovered: {}",
                    terminal_safe_single_line(&error.to_string())
                );
            }
        }
    }
    loop {
        tokio::select! {
            input = input_receiver.recv() => {
                let Some(input) = input else {
                    stop_chat_watchers(&mut watchers).await;
                    return Ok(());
                };
                let line = match input {
                    ChatInput::Line(line) => line,
                    ChatInput::EndOfFile => {
                        println!();
                        stop_chat_watchers(&mut watchers).await;
                        return Ok(());
                    }
                    ChatInput::Failed(message) => {
                        stop_chat_watchers(&mut watchers).await;
                        return Err(CliError::Protocol(format!("chat input failed: {message}")));
                    }
                };
                let line = match parse_chat_line(&line) {
                    ChatLine::LocalAttachment { path } => {
                        match prepare_local_text_attachment(home, &path, CHAT_LOCAL_ATTACHMENT_PROMPT) {
                            Ok(content) => ChatLine::Send {
                                delivery: DeliveryMode::Queue,
                                content,
                            },
                            Err(error) => {
                                eprintln!(
                                    "local text attachment was not submitted: {}; use /help for the accepted format",
                                    terminal_safe_single_line(&error.to_string())
                                );
                                continue;
                            }
                        }
                    }
                    line => line,
                };
                match line {
                    ChatLine::Send { delivery, content } if !content.is_empty() => {
                        if watchers.len() >= CHAT_MAXIMUM_TRACKED_TURNS {
                            eprintln!(
                                "chat is already tracking {CHAT_MAXIMUM_TRACKED_TURNS} accepted or pending inputs; wait for one to finish"
                            );
                            continue;
                        }
                        let request = SubmitInputRequest {
                            api_version: API_VERSION.to_owned(),
                            idempotency_key: generate_idempotency_key()?,
                            delivery_mode: delivery,
                            content,
                        };
                        let client = client.clone();
                        let home = home.to_path_buf();
                        let initial_connection = connection.clone();
                        let session_id = session_id.clone();
                        let updates = update_sender.clone();
                        watchers.spawn(async move {
                            run_chat_submission(
                                client,
                                home,
                                initial_connection,
                                session_id,
                                request,
                                updates,
                            )
                            .await;
                        });
                    }
                    ChatLine::ResolveApproval {
                        approval_id,
                        subject_digest,
                        decision,
                    } => {
                        match resolve_chat_approval(
                            client,
                            home,
                            &approval_id,
                            &subject_digest,
                            decision,
                        )
                        .await
                        {
                            Ok(receipt) => eprintln!(
                                "approval {} is {:?}",
                                terminal_safe_single_line(&receipt.approval_id),
                                receipt.status
                            ),
                            Err(error) => eprintln!(
                                "approval was not resolved: {}",
                                terminal_safe_single_line(&error.to_string())
                            ),
                        }
                    }
                    ChatLine::Memory(command) => {
                        if let Err(error) = run_chat_memory_command(
                            client,
                            connection,
                            &session_id,
                            &mut memory_workspace,
                            command,
                        )
                        .await
                        {
                            eprintln!(
                                "memory command failed: {}",
                                terminal_safe_single_line(&error.to_string())
                            );
                        }
                    }
                    ChatLine::History(query) => {
                        match search_session_transcripts(client, connection, &query, 20).await {
                            Ok(response) => print_json(response)?,
                            Err(error) => eprintln!(
                                "session history search failed: {}",
                                terminal_safe_single_line(&error.to_string())
                            ),
                        }
                    }
                    ChatLine::Send { .. } | ChatLine::LocalAttachment { .. } | ChatLine::Empty => {}
                    ChatLine::Help => print_chat_help(),
                    ChatLine::Session => println!("{}", terminal_safe_single_line(&session_id)),
                    ChatLine::Exit => {
                        stop_chat_watchers(&mut watchers).await;
                        return Ok(());
                    }
                }
            }
            update = update_receiver.recv() => {
                if let Some(update) = update {
                    render_chat_update(update)?;
                }
            }
            joined = watchers.join_next(), if !watchers.is_empty() => {
                if let Some(Err(error)) = joined {
                    eprintln!(
                        "chat watcher stopped unexpectedly: {}",
                        terminal_safe_single_line(&error.to_string())
                    );
                }
            }
        }
    }
}

async fn default_chat_memory_workspace(
    client: &Client,
    connection: &LocalConnectionInfo,
) -> Result<String, CliError> {
    let response = authorized(
        client.get(format!("{}/v1/admin/status", connection.base_url)),
        connection,
    )
    .send()
    .await?;
    let status = decode::<AdminStatusResponse>(response).await?;
    Ok(if status
        .enabled_read_tools
        .iter()
        .any(|tool| tool.starts_with("workspace."))
    {
        CHAT_MEMORY_GRANTED_WORKSPACES
    } else {
        CHAT_MEMORY_NO_WORKSPACE
    }
    .to_owned())
}

#[allow(clippy::too_many_lines)]
async fn run_chat_memory_command(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
    workspace: &mut String,
    command: ChatMemoryCommand,
) -> Result<(), CliError> {
    match command {
        ChatMemoryCommand::UseNamespace(value) => {
            if !valid_memory_workspace_identity(&value) {
                return Err(CliError::InvalidMemoryOwnerEntry);
            }
            *workspace = value;
            println!(
                "governed memory namespace is now {}",
                terminal_safe_single_line(workspace)
            );
        }
        ChatMemoryCommand::Remember(content) => {
            let digest = sha256_digest(content.as_bytes());
            let source_locator = format!("owner://mealyctl/chat/{session_id}/{digest}");
            let active = remember_memory(
                client,
                connection,
                workspace,
                content,
                MemoryCategoryCommand::Fact,
                8_000,
                MemorySensitivityCommand::Private,
                MemoryRetentionCommand::Standard,
                source_locator,
            )
            .await?;
            print_json(active)?;
        }
        ChatMemoryCommand::List => {
            print_json(fetch_memories(client, connection, workspace, false).await?)?;
        }
        ChatMemoryCommand::Search(query) => {
            let response = authorized(
                client
                    .get(format!("{}/v1/memories/search", connection.base_url))
                    .query(&[
                        ("workspaceIdentity", workspace.as_str()),
                        ("query", query.as_str()),
                        ("maximumSensitivity", "private"),
                        ("limit", "20"),
                    ]),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<MemorySearchResponse>(response).await?)?;
        }
        ChatMemoryCommand::Status(memory_id) => {
            print_json(fetch_memory(client, connection, workspace, &memory_id).await?)?;
        }
        ChatMemoryCommand::Activate {
            memory_id,
            revision_id,
        } => {
            let response = authorized(
                client.post(format!(
                    "{}/v1/memories/{memory_id}/activate",
                    connection.base_url
                )),
                connection,
            )
            .json(&PromoteMemoryRequest {
                api_version: API_VERSION.to_owned(),
                revision_id,
                authorization: Some(MemoryPromotionAuthorizationCommand::OwnerApproval),
            })
            .send()
            .await?;
            print_json(decode::<MemoryResponse>(response).await?)?;
        }
        ChatMemoryCommand::Correct {
            memory_id,
            expected_revision,
            content,
        } => {
            let current = fetch_memory(client, connection, workspace, &memory_id).await?;
            if current.revision != expected_revision {
                return Err(CliError::Protocol(format!(
                    "memory revision changed: expected {expected_revision}, current is {}",
                    current.revision
                )));
            }
            let digest = sha256_digest(content.as_bytes());
            let response = authorized(
                client.post(format!(
                    "{}/v1/memories/{memory_id}/correct",
                    connection.base_url
                )),
                connection,
            )
            .json(&CorrectMemoryRequest {
                api_version: API_VERSION.to_owned(),
                expected_revision,
                content,
                confidence_basis_points: current.confidence_basis_points,
                sensitivity: current.sensitivity,
                retention: current.retention,
                sources: vec![MemorySourceCommand {
                    locator: format!("owner://mealyctl/chat/{session_id}/{digest}"),
                    digest,
                }],
                authorization: Some(MemoryPromotionAuthorizationCommand::OwnerApproval),
            })
            .send()
            .await?;
            print_json(decode::<MemoryResponse>(response).await?)?;
        }
        ChatMemoryCommand::Expire {
            memory_id,
            expected_revision,
        } => {
            print_json(
                memory_lifecycle_request(
                    client,
                    connection,
                    &memory_id,
                    "expire",
                    expected_revision,
                )
                .await?,
            )?;
        }
        ChatMemoryCommand::Reject {
            memory_id,
            expected_revision,
        } => {
            print_json(
                memory_lifecycle_request(
                    client,
                    connection,
                    &memory_id,
                    "reject",
                    expected_revision,
                )
                .await?,
            )?;
        }
        ChatMemoryCommand::Delete {
            memory_id,
            expected_revision,
        } => {
            print_json(
                memory_lifecycle_request(
                    client,
                    connection,
                    &memory_id,
                    "delete",
                    expected_revision,
                )
                .await?,
            )?;
        }
    }
    Ok(())
}

fn valid_memory_workspace_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1_024
        && value.trim() == value
        && !value.chars().any(unsafe_terminal_character)
}

async fn fetch_memory(
    client: &Client,
    connection: &LocalConnectionInfo,
    workspace: &str,
    memory_id: &str,
) -> Result<MemoryResponse, CliError> {
    let response = authorized(
        client
            .get(format!("{}/v1/memories/{memory_id}", connection.base_url))
            .query(&[("workspaceIdentity", workspace)]),
        connection,
    )
    .send()
    .await?;
    decode::<MemoryResponse>(response).await
}

fn print_chat_help() {
    println!(
        "/queue TEXT admits normal FIFO work; plain TEXT is equivalent; /steer TEXT attaches to \
         the active turn at its next safe boundary; /interrupt TEXT requests cancellation and \
         durably queues replacement work; /attach PATH queues one owner-selected, bounded local \
         text file (the complete remainder is the path, so spaces are accepted); /approve \
         APPROVAL_ID SUBJECT_DIGEST and /deny \
         APPROVAL_ID SUBJECT_DIGEST resolve an exact rendered subject; /act TEXT selects the \
         create-new-file tool; /edit TEXT selects digest-preconditioned atomic replacement; \
         /manage TEXT selects directory creation, exact file move/removal, or empty-directory \
         removal; /run TEXT selects configured direct-process authority; /session; \
         /quit"
    );
    println!(
        "/remember TEXT explicitly proposes and activates a private, standard-retention fact; \
         /memories [QUERY] lists or searches the current governed namespace; /memory-use \
         WORKSPACE changes that local namespace; /memory-status MEMORY_ID inspects provenance; \
         /history QUERY searches canonical user/final-assistant text across local sessions"
    );
    println!(
        "/memory-activate MEMORY_ID REVISION_ID activates a reviewed proposal; /memory-correct \
         MEMORY_ID REVISION TEXT creates an immutable corrected revision; /memory-expire, \
         /memory-reject, and /memory-delete each take MEMORY_ID REVISION. Delete scrubs content; \
         expire only removes active retrieval. Advanced category/sensitivity control remains in \
         the top-level `memory` commands."
    );
}

fn start_chat_input_reader(sender: tokio::sync::mpsc::Sender<ChatInput>) -> Result<(), CliError> {
    let handle = std::thread::Builder::new()
        .name("mealy-chat-input".to_owned())
        .spawn(move || {
            loop {
                print!("you> ");
                if let Err(error) = std::io::stdout().flush() {
                    let _ = sender.blocking_send(ChatInput::Failed(error.to_string()));
                    return;
                }
                let mut line = String::new();
                match std::io::stdin().read_line(&mut line) {
                    Ok(0) => {
                        let _ = sender.blocking_send(ChatInput::EndOfFile);
                        return;
                    }
                    Ok(_) => {
                        if sender.blocking_send(ChatInput::Line(line)).is_err() {
                            return;
                        }
                    }
                    Err(error) => {
                        let _ = sender.blocking_send(ChatInput::Failed(error.to_string()));
                        return;
                    }
                }
            }
        })?;
    drop(handle);
    Ok(())
}

async fn stop_chat_watchers(watchers: &mut tokio::task::JoinSet<()>) {
    watchers.abort_all();
    while watchers.join_next().await.is_some() {}
}

async fn discover_resumable_chat_state(
    client: &Client,
    connection: &LocalConnectionInfo,
    status: &SessionStatusResponse,
) -> Result<ResumableChatState, CliError> {
    let mut after = 0_u64;
    let mut observed = 0_usize;
    let mut pending = BTreeMap::<String, u64>::new();
    let mut active = None;
    loop {
        let response = authorized(
            client.get(format!(
                "{}/v1/sessions/{}/timeline?after={after}&limit=1000",
                connection.base_url, status.session_id
            )),
            connection,
        )
        .timeout(Duration::from_secs(30))
        .send()
        .await?;
        let page = decode::<TimelinePageResponse>(response).await?;
        observed = observed.saturating_add(page.events.len());
        if observed > CHAT_MAXIMUM_RESUME_EVENTS {
            return Err(CliError::Protocol(format!(
                "session history exceeds the {CHAT_MAXIMUM_RESUME_EVENTS}-event automatic resume bound"
            )));
        }
        for event in &page.events {
            observe_resumable_chat_event(
                event,
                status.active_turn_id.as_deref(),
                &mut pending,
                &mut active,
            );
        }
        if let Some(last) = page.events.last() {
            after = last.cursor.0;
        }
        if !page.has_more {
            break;
        }
    }
    let mut pending = pending
        .into_iter()
        .map(|(inbox_entry_id, accepted_cursor)| ResumableChatAdmission {
            inbox_entry_id,
            accepted_cursor,
        })
        .collect::<Vec<_>>();
    pending.sort_by_key(|item| item.accepted_cursor);
    Ok(ResumableChatState { pending, active })
}

fn observe_resumable_chat_event(
    event: &TimelineEvent,
    active_turn_id: Option<&str>,
    pending: &mut BTreeMap<String, u64>,
    active: &mut Option<ResumableChatTask>,
) {
    match event.event_type.as_str() {
        "input.accepted" => {
            if let Some(inbox_entry_id) = event.payload["inbox_entry_id"].as_str() {
                pending.insert(inbox_entry_id.to_owned(), event.cursor.0);
            }
        }
        "input.promoted" | "input.steered" => {
            if let Some(inbox_entry_id) = event.payload["inbox_entry_id"].as_str() {
                pending.remove(inbox_entry_id);
            }
        }
        "task.created"
            if active_turn_id.is_some() && event.payload["turn_id"].as_str() == active_turn_id =>
        {
            *active = Some(ResumableChatTask {
                task_id: event.aggregate_id.clone(),
                correlation_id: event.correlation_id.clone(),
            });
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn start_resumed_chat_watchers(
    watchers: &mut tokio::task::JoinSet<()>,
    client: &Client,
    home: &Path,
    session_id: &str,
    latest_cursor: u64,
    expected_pending: u64,
    state: ResumableChatState,
    updates: &tokio::sync::mpsc::Sender<ChatUpdate>,
) {
    if expected_pending != u64::try_from(state.pending.len()).unwrap_or(u64::MAX) {
        eprintln!(
            "session reports {expected_pending} pending inputs but {} could be rediscovered within retained history",
            state.pending.len()
        );
    }
    if let Some(active) = state.active {
        let client = client.clone();
        let home = home.to_path_buf();
        let session_id = session_id.to_owned();
        let updates = updates.clone();
        watchers.spawn(async move {
            run_resumed_chat_task(client, home, session_id, active, latest_cursor, updates).await;
        });
    }
    let remaining = CHAT_MAXIMUM_TRACKED_TURNS.saturating_sub(watchers.len());
    if state.pending.len() > remaining {
        eprintln!(
            "only the first {remaining} retained pending inputs fit the local chat watcher bound"
        );
    }
    for admission in state.pending.into_iter().take(remaining) {
        let client = client.clone();
        let home = home.to_path_buf();
        let session_id = session_id.to_owned();
        let updates = updates.clone();
        watchers.spawn(async move {
            run_resumed_chat_admission(client, home, session_id, admission, updates).await;
        });
    }
}

async fn run_resumed_chat_task(
    client: Client,
    home: PathBuf,
    session_id: String,
    task: ResumableChatTask,
    after: u64,
    updates: tokio::sync::mpsc::Sender<ChatUpdate>,
) {
    if updates
        .send(ChatUpdate::Resumed {
            reference: format!("active task {}", task.task_id),
        })
        .await
        .is_err()
    {
        return;
    }
    match wait_for_chat_result(
        &client,
        &home,
        &session_id,
        &task.task_id,
        &task.correlation_id,
        after,
        &updates,
    )
    .await
    {
        Ok(result) => {
            let _ = updates.send(ChatUpdate::Finished(Box::new(result))).await;
        }
        Err(error) => {
            let _ = updates
                .send(ChatUpdate::Failed {
                    reference: format!("resumed task {}", task.task_id),
                    message: error.to_string(),
                })
                .await;
        }
    }
}

async fn run_resumed_chat_admission(
    client: Client,
    home: PathBuf,
    session_id: String,
    admission: ResumableChatAdmission,
    updates: tokio::sync::mpsc::Sender<ChatUpdate>,
) {
    if updates
        .send(ChatUpdate::Resumed {
            reference: format!("pending input {}", admission.inbox_entry_id),
        })
        .await
        .is_err()
    {
        return;
    }
    let result = async {
        match wait_for_chat_task(
            &client,
            &home,
            &session_id,
            &admission.inbox_entry_id,
            admission.accepted_cursor,
            &updates,
        )
        .await?
        {
            ChatPromotion::Steered => Ok(()),
            ChatPromotion::Task {
                task_id,
                correlation_id,
                after,
            } => {
                let result = wait_for_chat_result(
                    &client,
                    &home,
                    &session_id,
                    &task_id,
                    &correlation_id,
                    after,
                    &updates,
                )
                .await?;
                let _ = updates.send(ChatUpdate::Finished(Box::new(result))).await;
                Ok::<(), CliError>(())
            }
        }
    }
    .await;
    if let Err(error) = result {
        let _ = updates
            .send(ChatUpdate::Failed {
                reference: format!("resumed input {}", admission.inbox_entry_id),
                message: error.to_string(),
            })
            .await;
    }
}

async fn run_chat_submission(
    client: Client,
    home: PathBuf,
    initial_connection: LocalConnectionInfo,
    session_id: String,
    request: SubmitInputRequest,
    updates: tokio::sync::mpsc::Sender<ChatUpdate>,
) {
    let delivery = request.delivery_mode;
    let connection = load_connection(&home).unwrap_or(initial_connection);
    let result = async {
        let admission =
            submit_input_with_retry(&client, &home, &connection, &session_id, &request).await?;
        if updates
            .send(ChatUpdate::Accepted {
                inbox_entry_id: admission.inbox_entry_id.clone(),
                delivery,
            })
            .await
            .is_err()
        {
            return Ok::<(), CliError>(());
        }
        match wait_for_chat_task(
            &client,
            &home,
            &session_id,
            &admission.inbox_entry_id,
            admission.cursor.0,
            &updates,
        )
        .await?
        {
            ChatPromotion::Steered => Ok(()),
            ChatPromotion::Task {
                task_id,
                correlation_id,
                after,
            } => {
                if updates
                    .send(ChatUpdate::Promoted {
                        inbox_entry_id: admission.inbox_entry_id,
                        task_id: task_id.clone(),
                    })
                    .await
                    .is_err()
                {
                    return Ok(());
                }
                let task = wait_for_chat_result(
                    &client,
                    &home,
                    &session_id,
                    &task_id,
                    &correlation_id,
                    after,
                    &updates,
                )
                .await?;
                let _ = updates.send(ChatUpdate::Finished(Box::new(task))).await;
                Ok(())
            }
        }
    }
    .await;
    if let Err(error) = result {
        let _ = updates
            .send(ChatUpdate::Failed {
                reference: format!("{delivery:?} input"),
                message: error.to_string(),
            })
            .await;
    }
}

async fn wait_for_chat_task(
    client: &Client,
    home: &Path,
    session_id: &str,
    inbox_entry_id: &str,
    mut after: u64,
    updates: &tokio::sync::mpsc::Sender<ChatUpdate>,
) -> Result<ChatPromotion, CliError> {
    let mut promotion_event_id = None;
    let mut interrupt_reported = false;
    let mut idle_delay = Duration::from_millis(100);
    loop {
        let Ok(connection) = load_connection(home) else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let Ok(response) = authorized(
            client.get(format!(
                "{}/v1/sessions/{session_id}/timeline?after={after}&limit=1000",
                connection.base_url
            )),
            &connection,
        )
        .send()
        .await
        else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let page = match decode::<TimelinePageResponse>(response).await {
            Ok(page) => page,
            Err(error) if chat_reconnectable_error(&error) => {
                tokio::time::sleep(idle_delay).await;
                idle_delay = idle_delay.saturating_mul(2).min(Duration::from_secs(1));
                continue;
            }
            Err(error) => return Err(error),
        };
        let previous_after = after;
        for event in &page.events {
            let is_admission = event.payload["inbox_entry_id"].as_str() == Some(inbox_entry_id);
            if is_admission {
                match event.event_type.as_str() {
                    "input.promoted" => promotion_event_id = Some(event.event_id.clone()),
                    "input.steered" => {
                        let _ = updates
                            .send(ChatUpdate::Steered {
                                inbox_entry_id: inbox_entry_id.to_owned(),
                            })
                            .await;
                        return Ok(ChatPromotion::Steered);
                    }
                    "input.interrupt_requested" if !interrupt_reported => {
                        interrupt_reported = true;
                        if updates
                            .send(ChatUpdate::InterruptRequested {
                                inbox_entry_id: inbox_entry_id.to_owned(),
                            })
                            .await
                            .is_err()
                        {
                            return Ok(ChatPromotion::Steered);
                        }
                    }
                    _ => {}
                }
            }
            if event.event_type == "task.created"
                && event.causation_id.as_deref() == promotion_event_id.as_deref()
            {
                return Ok(ChatPromotion::Task {
                    task_id: event.aggregate_id.clone(),
                    correlation_id: event.correlation_id.clone(),
                    after: event.cursor.0,
                });
            }
        }
        if let Some(last) = page.events.last() {
            after = last.cursor.0;
        }
        if after != previous_after {
            idle_delay = Duration::from_millis(100);
        }
        if !page.has_more {
            tokio::time::sleep(idle_delay).await;
            idle_delay = idle_delay.saturating_mul(2).min(Duration::from_secs(1));
        }
    }
}

async fn wait_for_chat_result(
    client: &Client,
    home: &Path,
    session_id: &str,
    task_id: &str,
    correlation_id: &str,
    mut after: u64,
    updates: &tokio::sync::mpsc::Sender<ChatUpdate>,
) -> Result<TaskResponse, CliError> {
    let mut prior_status = None;
    let mut rendered_approvals = BTreeSet::new();
    loop {
        let Ok(connection) = load_connection(home) else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        after = match emit_chat_progress(
            client,
            &connection,
            session_id,
            task_id,
            correlation_id,
            after,
            updates,
        )
        .await
        {
            Ok(after) => after,
            Err(error) if chat_reconnectable_error(&error) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
            Err(error) => return Err(error),
        };
        let Ok(response) = authorized(
            client.get(format!("{}/v1/tasks/{task_id}", connection.base_url)),
            &connection,
        )
        .send()
        .await
        else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let task = match decode::<TaskResponse>(response).await {
            Ok(task) => task,
            Err(error) if chat_reconnectable_error(&error) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
            Err(error) => return Err(error),
        };
        if prior_status != Some(task.status) {
            if updates
                .send(ChatUpdate::Status {
                    task_id: task_id.to_owned(),
                    status: task.status,
                })
                .await
                .is_err()
            {
                return Ok(task);
            }
            prior_status = Some(task.status);
        }
        match task.status {
            TaskStatus::Succeeded | TaskStatus::Failed | TaskStatus::Cancelled => return Ok(task),
            TaskStatus::Waiting => {
                let previews = match collect_chat_approvals(client, &connection, task_id).await {
                    Ok(previews) => previews,
                    Err(error) if chat_reconnectable_error(&error) => {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                for preview in previews {
                    if rendered_approvals.insert(preview.approval.approval_id.clone())
                        && updates
                            .send(ChatUpdate::Approval(Box::new(preview)))
                            .await
                            .is_err()
                    {
                        return Ok(task);
                    }
                }
            }
            TaskStatus::Queued
            | TaskStatus::Running
            | TaskStatus::Paused
            | TaskStatus::Cancelling => {}
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn emit_chat_progress(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
    task_id: &str,
    correlation_id: &str,
    mut after: u64,
    updates: &tokio::sync::mpsc::Sender<ChatUpdate>,
) -> Result<u64, CliError> {
    loop {
        let response = authorized(
            client.get(format!(
                "{}/v1/sessions/{session_id}/timeline?after={after}&limit=1000",
                connection.base_url
            )),
            connection,
        )
        .send()
        .await?;
        let page = decode::<TimelinePageResponse>(response).await?;
        for event in &page.events {
            if event.correlation_id != correlation_id {
                continue;
            }
            if event.event_type == "model.output.delta" {
                let delta = event.payload.get("delta").and_then(Value::as_str);
                let authoritative = event.payload.get("authoritative").and_then(Value::as_bool);
                if let Some(delta) = delta.filter(|delta| {
                    !delta.is_empty()
                        && delta.len() <= mealy_application::MAXIMUM_MODEL_PROGRESS_DELTA_BYTES
                        && authoritative == Some(false)
                }) && updates
                    .send(ChatUpdate::TextDelta {
                        task_id: task_id.to_owned(),
                        delta: delta.to_owned(),
                    })
                    .await
                    .is_err()
                {
                    return Ok(after);
                }
                continue;
            }
            if let Some(label) = chat_progress_label(&event.event_type) {
                let detail = event
                    .payload
                    .get("tool_id")
                    .or_else(|| event.payload.get("error_class"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if updates
                    .send(ChatUpdate::Progress {
                        task_id: task_id.to_owned(),
                        event_type: label.to_owned(),
                        detail,
                    })
                    .await
                    .is_err()
                {
                    return Ok(after);
                }
            }
        }
        if let Some(last) = page.events.last() {
            after = last.cursor.0;
        }
        if !page.has_more {
            return Ok(after);
        }
    }
}

fn chat_progress_label(event_type: &str) -> Option<&'static str> {
    match event_type {
        "model.attempt.prepared" => Some("model request prepared"),
        "model.attempt.dispatched" => Some("model request dispatched"),
        "model.attempt.completed" => Some("model response committed"),
        "model.attempt.failed" => Some("model request failed"),
        "tool.call.prepared" => Some("tool call prepared"),
        "tool.call.started" => Some("tool call started"),
        "tool.call.succeeded" => Some("tool result committed"),
        "approval.requested" => Some("approval requested"),
        "approval.approved" => Some("approval approved"),
        "approval.denied" => Some("approval denied"),
        "approval.expired" => Some("approval expired"),
        "approval.revoked" => Some("approval revoked"),
        _ => None,
    }
}

fn chat_reconnectable_error(error: &CliError) -> bool {
    match error {
        CliError::Http(_) | CliError::Io(_) => true,
        CliError::Server { status, .. } => {
            *status == StatusCode::UNAUTHORIZED || retryable_status(*status)
        }
        _ => false,
    }
}

async fn collect_chat_approvals(
    client: &Client,
    connection: &LocalConnectionInfo,
    task_id: &str,
) -> Result<Vec<ChatApprovalPreview>, CliError> {
    let response = authorized(
        client.get(format!("{}/v1/approvals", connection.base_url)),
        connection,
    )
    .send()
    .await?;
    let pending = decode::<PendingApprovalsResponse>(response).await?;
    let mut previews = Vec::new();
    for approval in pending
        .approvals
        .into_iter()
        .filter(|approval| approval.subject.task_id == task_id)
    {
        let effect_response = authorized(
            client.get(format!(
                "{}/v1/effects/{}",
                connection.base_url, approval.effect_id
            )),
            connection,
        )
        .send()
        .await?;
        let effect = decode::<EffectResponse>(effect_response).await?;
        if effect.effect_id != approval.effect_id
            || effect.task_id != approval.subject.task_id
            || effect.arguments_digest != approval.subject.canonical_arguments_digest
            || effect.tool_id != approval.subject.tool_id
            || effect.target_resources != approval.subject.target_resources
        {
            return Err(CliError::Protocol(
                "approval preview did not match its immutable effect intent".to_owned(),
            ));
        }
        previews.push(ChatApprovalPreview { approval, effect });
    }
    Ok(previews)
}

async fn resolve_chat_approval(
    client: &Client,
    home: &Path,
    approval_id: &str,
    subject_digest: &str,
    decision: ApprovalDecisionCommand,
) -> Result<ApprovalResolutionReceipt, CliError> {
    let connection = load_connection(home)?;
    let response = authorized(
        client.post(format!(
            "{}/v1/approvals/{approval_id}/resolve",
            connection.base_url
        )),
        &connection,
    )
    .timeout(Duration::from_secs(30))
    .json(&ResolveApprovalRequest {
        api_version: API_VERSION.to_owned(),
        idempotency_key: generate_idempotency_key()?,
        expected_subject_digest: subject_digest.to_owned(),
        decision,
    })
    .send()
    .await?;
    decode::<ApprovalResolutionReceipt>(response).await
}

fn render_chat_update(update: ChatUpdate) -> Result<(), CliError> {
    match update {
        ChatUpdate::Accepted {
            inbox_entry_id,
            delivery,
        } => eprintln!(
            "accepted {delivery:?} input {}",
            terminal_safe_single_line(&inbox_entry_id)
        ),
        ChatUpdate::Resumed { reference } => {
            eprintln!("resumed tracking {}", terminal_safe_single_line(&reference));
        }
        ChatUpdate::Promoted {
            inbox_entry_id,
            task_id,
        } => eprintln!(
            "input {} promoted to task {}",
            terminal_safe_single_line(&inbox_entry_id),
            terminal_safe_single_line(&task_id)
        ),
        ChatUpdate::Steered { inbox_entry_id } => {
            eprintln!(
                "input {} attached at the active turn's next safe boundary",
                terminal_safe_single_line(&inbox_entry_id)
            );
        }
        ChatUpdate::InterruptRequested { inbox_entry_id } => {
            eprintln!(
                "input {} requested cancellation and remains durably queued",
                terminal_safe_single_line(&inbox_entry_id)
            );
        }
        ChatUpdate::Status { task_id, status } => {
            eprintln!(
                "task {}: {}",
                terminal_safe_single_line(&task_id),
                chat_status_name(status)
            );
        }
        ChatUpdate::Progress {
            task_id,
            event_type,
            detail,
        } => {
            if let Some(detail) = detail {
                eprintln!(
                    "task {}: {} ({})",
                    terminal_safe_single_line(&task_id),
                    terminal_safe_single_line(&event_type),
                    terminal_safe_single_line(&detail)
                );
            } else {
                eprintln!(
                    "task {}: {}",
                    terminal_safe_single_line(&task_id),
                    terminal_safe_single_line(&event_type)
                );
            }
        }
        ChatUpdate::TextDelta { task_id, delta } => {
            eprintln!(
                "mealy~ {}: {}",
                terminal_safe_single_line(&task_id),
                terminal_safe_text(&delta)
            );
        }
        ChatUpdate::Approval(preview) => render_chat_approval(&preview)?,
        ChatUpdate::Finished(task) => render_finished_chat_task(&task)?,
        ChatUpdate::Failed { reference, message } => {
            eprintln!(
                "chat could not track {}: {}",
                terminal_safe_single_line(&reference),
                terminal_safe_single_line(&message)
            );
        }
    }
    Ok(())
}

fn render_chat_approval(preview: &ChatApprovalPreview) -> Result<(), CliError> {
    println!(
        "approval required:\n{}",
        terminal_safe_pretty_json(&json!({
            "approvalId": preview.approval.approval_id,
            "argumentsDigest": preview.effect.arguments_digest,
            "normalizedArguments": preview.effect.normalized_arguments,
            "subject": preview.approval.subject,
            "subjectDigest": preview.approval.subject_digest,
        }))?
    );
    eprintln!(
        "resolve with `/approve {} {}` or `/deny {} {}`",
        terminal_safe_single_line(&preview.approval.approval_id),
        terminal_safe_single_line(&preview.approval.subject_digest),
        terminal_safe_single_line(&preview.approval.approval_id),
        terminal_safe_single_line(&preview.approval.subject_digest),
    );
    Ok(())
}

fn render_finished_chat_task(task: &TaskResponse) -> Result<(), CliError> {
    match task.status {
        TaskStatus::Succeeded => println!(
            "mealy> {}",
            terminal_safe_text(
                task.final_response
                    .as_deref()
                    .unwrap_or("[completed without a renderable response]")
            )
        ),
        TaskStatus::Failed => eprintln!(
            "mealy task {} failed; inspect with `mealyctl task status {}`",
            terminal_safe_single_line(&task.task_id),
            terminal_safe_single_line(&task.task_id)
        ),
        TaskStatus::Cancelled => eprintln!(
            "mealy task {} was cancelled",
            terminal_safe_single_line(&task.task_id)
        ),
        _ => {
            return Err(CliError::Protocol(
                "chat result returned before a terminal task boundary".to_owned(),
            ));
        }
    }
    Ok(())
}

fn terminal_safe_text(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\n' | '\t' => character,
            _ if unsafe_terminal_character(character) => '\u{fffd}',
            _ => character,
        })
        .collect()
}

fn terminal_safe_single_line(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if unsafe_terminal_character(character) {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

fn unsafe_terminal_character(character: char) -> bool {
    let codepoint = u32::from(character);
    character.is_control()
        || matches!(
            codepoint,
            0x061c
                | 0x200b..=0x200f
                | 0x2028..=0x202e
                | 0x2060..=0x206f
                | 0xfeff
        )
}

const fn chat_status_name(status: TaskStatus) -> &'static str {
    match status {
        TaskStatus::Queued => "queued",
        TaskStatus::Running => "running",
        TaskStatus::Waiting => "waiting for approval or reconciliation",
        TaskStatus::Paused => "paused",
        TaskStatus::Cancelling => "cancelling",
        TaskStatus::Succeeded => "succeeded",
        TaskStatus::Failed => "failed",
        TaskStatus::Cancelled => "cancelled",
    }
}

async fn run_approval(
    client: &Client,
    connection: &LocalConnectionInfo,
    command: ApprovalCommand,
) -> Result<(), CliError> {
    match command {
        ApprovalCommand::List => {
            let response = authorized(
                client.get(format!("{}/v1/approvals", connection.base_url)),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<PendingApprovalsResponse>(response).await?)?;
        }
        ApprovalCommand::Resolve {
            approval_id,
            decision,
            subject_digest,
            idempotency_key,
        } => {
            let generated = idempotency_key.is_none();
            let idempotency_key = idempotency_key.map_or_else(generate_idempotency_key, Ok)?;
            if generated {
                eprintln!("MEALY_IDEMPOTENCY_KEY {idempotency_key}");
            }
            let response = authorized(
                client.post(format!(
                    "{}/v1/approvals/{approval_id}/resolve",
                    connection.base_url
                )),
                connection,
            )
            .json(&ResolveApprovalRequest {
                api_version: API_VERSION.to_owned(),
                idempotency_key,
                expected_subject_digest: subject_digest,
                decision: decision.into(),
            })
            .send()
            .await?;
            print_json(decode::<ApprovalResolutionReceipt>(response).await?)?;
        }
    }
    Ok(())
}

async fn run_effect(
    client: &Client,
    connection: &LocalConnectionInfo,
    command: EffectCommand,
) -> Result<(), CliError> {
    match command {
        EffectCommand::Status { effect_id } => {
            let response = authorized(
                client.get(format!("{}/v1/effects/{effect_id}", connection.base_url)),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<EffectResponse>(response).await?)?;
        }
        EffectCommand::Attempt { attempt_id } => {
            let response = authorized(
                client.get(format!(
                    "{}/v1/effect-attempts/{attempt_id}",
                    connection.base_url
                )),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<EffectAttemptResponse>(response).await?)?;
        }
        EffectCommand::Reconcile {
            effect_id,
            attempt_id,
            outcome,
            revision,
            evidence_json,
            idempotency_key,
        } => {
            let evidence = serde_json::from_str::<serde_json::Value>(&evidence_json)?;
            if evidence.as_object().is_none_or(serde_json::Map::is_empty) {
                return Err(CliError::Protocol(
                    "--evidence-json must contain a non-empty JSON object".to_owned(),
                ));
            }
            let generated = idempotency_key.is_none();
            let idempotency_key = idempotency_key.map_or_else(generate_idempotency_key, Ok)?;
            if generated {
                eprintln!("MEALY_IDEMPOTENCY_KEY {idempotency_key}");
            }
            let response = authorized(
                client.post(format!(
                    "{}/v1/effects/{effect_id}/attempts/{attempt_id}/reconcile",
                    connection.base_url
                )),
                connection,
            )
            .json(&ReconcileEffectRequest {
                api_version: API_VERSION.to_owned(),
                idempotency_key,
                expected_effect_revision: revision,
                outcome: outcome.into(),
                evidence,
            })
            .send()
            .await?;
            print_json(decode::<EffectReconciliationReceipt>(response).await?)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn run_memory(
    client: &Client,
    connection: &LocalConnectionInfo,
    command: MemoryCommand,
) -> Result<(), CliError> {
    match command {
        MemoryCommand::Remember {
            workspace,
            content,
            category,
            confidence,
            sensitivity,
            retention,
            approve,
        } => {
            if !approve {
                return Err(CliError::ApprovalRequired);
            }
            let source_digest = sha256_digest(content.as_bytes());
            let source_locator = format!("owner://mealyctl/direct/{source_digest}");
            print_json(
                remember_memory(
                    client,
                    connection,
                    &workspace,
                    content,
                    category.into(),
                    confidence,
                    sensitivity.into(),
                    retention.into(),
                    source_locator,
                )
                .await?,
            )?;
        }
        MemoryCommand::Propose {
            workspace,
            content,
            category,
            confidence,
            sensitivity,
            retention,
            sources,
        } => {
            let response = authorized(
                client.post(format!("{}/v1/memories", connection.base_url)),
                connection,
            )
            .json(&ProposeMemoryRequest {
                api_version: API_VERSION.to_owned(),
                workspace_identity: workspace,
                content,
                category: category.into(),
                confidence_basis_points: confidence,
                sensitivity: sensitivity.into(),
                retention: retention.into(),
                sources: parse_memory_sources(sources)?,
            })
            .send()
            .await?;
            print_json(decode::<MemoryResponse>(response).await?)?;
        }
        MemoryCommand::Activate {
            memory_id,
            revision_id,
            authorization,
        } => {
            let response = authorized(
                client.post(format!(
                    "{}/v1/memories/{memory_id}/activate",
                    connection.base_url
                )),
                connection,
            )
            .json(&PromoteMemoryRequest {
                api_version: API_VERSION.to_owned(),
                revision_id,
                authorization: authorization.map(Into::into),
            })
            .send()
            .await?;
            print_json(decode::<MemoryResponse>(response).await?)?;
        }
        MemoryCommand::Status {
            memory_id,
            workspace,
        } => {
            let response = authorized(
                client
                    .get(format!("{}/v1/memories/{memory_id}", connection.base_url))
                    .query(&[("workspaceIdentity", workspace)]),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<MemoryResponse>(response).await?)?;
        }
        MemoryCommand::List {
            workspace,
            include_deleted,
        } => {
            print_json(fetch_memories(client, connection, &workspace, include_deleted).await?)?;
        }
        MemoryCommand::Search {
            workspace,
            query,
            maximum_sensitivity,
            limit,
        } => {
            let response = authorized(
                client
                    .get(format!("{}/v1/memories/search", connection.base_url))
                    .query(&[
                        ("workspaceIdentity", workspace),
                        ("query", query),
                        (
                            "maximumSensitivity",
                            maximum_sensitivity.as_query().to_owned(),
                        ),
                        ("limit", limit.to_string()),
                    ]),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<MemorySearchResponse>(response).await?)?;
        }
        MemoryCommand::Correct {
            memory_id,
            expected_revision,
            content,
            confidence,
            sensitivity,
            retention,
            sources,
            authorization,
        } => {
            let response = authorized(
                client.post(format!(
                    "{}/v1/memories/{memory_id}/correct",
                    connection.base_url
                )),
                connection,
            )
            .json(&CorrectMemoryRequest {
                api_version: API_VERSION.to_owned(),
                expected_revision,
                content,
                confidence_basis_points: confidence,
                sensitivity: sensitivity.into(),
                retention: retention.into(),
                sources: parse_memory_sources(sources)?,
                authorization: authorization.map(Into::into),
            })
            .send()
            .await?;
            print_json(decode::<MemoryResponse>(response).await?)?;
        }
        MemoryCommand::Pin {
            memory_id,
            expected_revision,
            unpin,
        } => {
            let response = authorized(
                client.post(format!(
                    "{}/v1/memories/{memory_id}/pin",
                    connection.base_url
                )),
                connection,
            )
            .json(&SetMemoryPinRequest {
                api_version: API_VERSION.to_owned(),
                expected_revision,
                pinned: !unpin,
            })
            .send()
            .await?;
            print_json(decode::<MemoryResponse>(response).await?)?;
        }
        MemoryCommand::Export {
            workspace,
            include_deleted,
            output,
        } => {
            let memories = fetch_memories(client, connection, &workspace, include_deleted).await?;
            if let Some(path) = output {
                let bytes = serde_json::to_vec_pretty(&memories)?;
                std::fs::write(&path, bytes)?;
                eprintln!(
                    "exported governed memories to {}",
                    terminal_safe_single_line(&path.display().to_string())
                );
            } else {
                print_json(memories)?;
            }
        }
        MemoryCommand::Expire {
            memory_id,
            expected_revision,
        } => {
            let response = memory_lifecycle_request(
                client,
                connection,
                &memory_id,
                "expire",
                expected_revision,
            )
            .await?;
            print_json(response)?;
        }
        MemoryCommand::Reject {
            memory_id,
            expected_revision,
        } => {
            let response = memory_lifecycle_request(
                client,
                connection,
                &memory_id,
                "reject",
                expected_revision,
            )
            .await?;
            print_json(response)?;
        }
        MemoryCommand::Delete {
            memory_id,
            expected_revision,
        } => {
            let response = memory_lifecycle_request(
                client,
                connection,
                &memory_id,
                "delete",
                expected_revision,
            )
            .await?;
            print_json(response)?;
        }
        MemoryCommand::RebuildIndex => {
            let response = authorized(
                client.post(format!("{}/v1/memory-index/rebuild", connection.base_url)),
                connection,
            )
            .json(&RebuildMemoryIndexRequest {
                api_version: API_VERSION.to_owned(),
            })
            .send()
            .await?;
            print_json(decode::<MemoryIndexRebuildResponse>(response).await?)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn remember_memory(
    client: &Client,
    connection: &LocalConnectionInfo,
    workspace: &str,
    content: String,
    category: MemoryCategoryCommand,
    confidence_basis_points: u16,
    sensitivity: MemorySensitivityCommand,
    retention: MemoryRetentionCommand,
    source_locator: String,
) -> Result<MemoryResponse, CliError> {
    if !valid_memory_workspace_identity(workspace)
        || content.is_empty()
        || content.len() > 65_536
        || content.contains('\0')
        || confidence_basis_points > 10_000
        || source_locator.is_empty()
        || source_locator.len() > 4_096
        || source_locator.chars().any(char::is_control)
    {
        return Err(CliError::InvalidMemoryOwnerEntry);
    }
    let content_digest = sha256_digest(content.as_bytes());
    let response = authorized(
        client.post(format!("{}/v1/memories", connection.base_url)),
        connection,
    )
    .json(&ProposeMemoryRequest {
        api_version: API_VERSION.to_owned(),
        workspace_identity: workspace.to_owned(),
        content,
        category,
        confidence_basis_points,
        sensitivity,
        retention,
        sources: vec![MemorySourceCommand {
            locator: source_locator,
            digest: content_digest.clone(),
        }],
    })
    .send()
    .await?;
    let proposed = decode::<MemoryResponse>(response).await?;
    let revision_id = match proposed.revisions.as_slice() {
        [revision]
            if proposed.status == MemoryStatusResponse::Proposed
                && revision.status == MemoryStatusResponse::Proposed
                && revision.content_digest == content_digest =>
        {
            revision.revision_id.clone()
        }
        _ => {
            return Err(CliError::Protocol(
                "memory proposal response did not identify one exact proposed revision".to_owned(),
            ));
        }
    };
    let memory_id = proposed.memory_id;
    let response = authorized(
        client.post(format!(
            "{}/v1/memories/{memory_id}/activate",
            connection.base_url
        )),
        connection,
    )
    .json(&PromoteMemoryRequest {
        api_version: API_VERSION.to_owned(),
        revision_id: revision_id.clone(),
        authorization: Some(MemoryPromotionAuthorizationCommand::OwnerApproval),
    })
    .send()
    .await?;
    let active = decode::<MemoryResponse>(response).await.map_err(|error| {
        CliError::MemoryActivationIncomplete {
            memory_id: memory_id.clone(),
            revision_id: revision_id.clone(),
            reason: error.to_string(),
        }
    })?;
    if active.memory_id != memory_id
        || active.status != MemoryStatusResponse::Active
        || active
            .revisions
            .last()
            .is_none_or(|revision| revision.revision_id != revision_id)
    {
        return Err(CliError::MemoryActivationIncomplete {
            memory_id,
            revision_id,
            reason: "activation response did not confirm the exact revision".to_owned(),
        });
    }
    Ok(active)
}

async fn run_compaction(
    client: &Client,
    connection: &LocalConnectionInfo,
    command: CompactionCommand,
) -> Result<(), CliError> {
    match command {
        CompactionCommand::Create {
            session_id,
            first_cursor,
            last_cursor,
            summary,
            carry_forward_json,
        } => {
            let carry_forward = serde_json::from_str::<serde_json::Value>(&carry_forward_json)?;
            if !carry_forward.is_object() {
                return Err(CliError::Protocol(
                    "--carry-forward-json must contain a JSON object".to_owned(),
                ));
            }
            let response = authorized(
                client.post(format!(
                    "{}/v1/sessions/{session_id}/compactions",
                    connection.base_url
                )),
                connection,
            )
            .json(&CreateCompactionRequest {
                api_version: API_VERSION.to_owned(),
                source_first_cursor: first_cursor,
                source_last_cursor: last_cursor,
                summary_text: summary,
                carry_forward,
            })
            .send()
            .await?;
            print_json(decode::<CompactionResponse>(response).await?)?;
        }
        CompactionCommand::Status { compaction_id } => {
            let response = authorized(
                client.get(format!(
                    "{}/v1/compactions/{compaction_id}",
                    connection.base_url
                )),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<CompactionResponse>(response).await?)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn run_extension(
    client: &Client,
    connection: &LocalConnectionInfo,
    command: ExtensionCommand,
) -> Result<(), CliError> {
    match command {
        ExtensionCommand::Install {
            manifest,
            digest,
            installation_root,
        } => {
            let response = authorized(
                client.post(format!("{}/v1/extensions", connection.base_url)),
                connection,
            )
            .json(&InstallExtensionRequest {
                api_version: API_VERSION.to_owned(),
                manifest_json: read_extension_manifest(&manifest)?,
                manifest_digest: digest,
                installation_root: canonical_utf8_path(&installation_root)?,
            })
            .send()
            .await?;
            print_json(decode::<ExtensionResponse>(response).await?)?;
        }
        ExtensionCommand::List => {
            let response = authorized(
                client.get(format!("{}/v1/extensions", connection.base_url)),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<ExtensionsResponse>(response).await?)?;
        }
        ExtensionCommand::Status { extension_id } => {
            let response = authorized(
                client.get(format!(
                    "{}/v1/extensions/{extension_id}",
                    connection.base_url
                )),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<ExtensionResponse>(response).await?)?;
        }
        ExtensionCommand::Stage {
            extension_id,
            expected_revision,
            manifest,
            digest,
            installation_root,
        } => {
            let response = authorized(
                client.post(format!(
                    "{}/v1/extensions/{extension_id}/stage",
                    connection.base_url
                )),
                connection,
            )
            .json(&StageExtensionManifestRequest {
                api_version: API_VERSION.to_owned(),
                expected_revision,
                manifest_json: read_extension_manifest(&manifest)?,
                manifest_digest: digest,
                installation_root: canonical_utf8_path(&installation_root)?,
            })
            .send()
            .await?;
            print_json(decode::<ExtensionResponse>(response).await?)?;
        }
        ExtensionCommand::Enable {
            extension_id,
            expected_revision,
            capabilities,
            mounts,
            network_destinations,
            secret_references,
            allow_process_spawn,
        } => {
            let mounts = mounts
                .into_iter()
                .map(|mount| serde_json::from_str::<ExtensionMountGrantCommand>(&mount))
                .collect::<Result<Vec<_>, _>>()?;
            let response = authorized(
                client.post(format!(
                    "{}/v1/extensions/{extension_id}/enable",
                    connection.base_url
                )),
                connection,
            )
            .json(&EnableExtensionRequest {
                api_version: API_VERSION.to_owned(),
                expected_revision,
                capability_ids: capabilities,
                mounts,
                network_destinations,
                secret_references,
                allow_process_spawn,
            })
            .send()
            .await?;
            print_json(decode::<ExtensionResponse>(response).await?)?;
        }
        ExtensionCommand::Disable {
            extension_id,
            expected_revision,
        } => {
            print_json(
                extension_lifecycle_request(
                    client,
                    connection,
                    &extension_id,
                    "disable",
                    expected_revision,
                )
                .await?,
            )?;
        }
        ExtensionCommand::Revoke {
            extension_id,
            expected_revision,
        } => {
            print_json(
                extension_lifecycle_request(
                    client,
                    connection,
                    &extension_id,
                    "revoke",
                    expected_revision,
                )
                .await?,
            )?;
        }
        ExtensionCommand::Invoke {
            extension_id,
            capability,
            input_json,
        } => {
            let input = serde_json::from_str::<serde_json::Value>(&input_json)?;
            if !input.is_object() {
                return Err(CliError::Protocol(
                    "--input-json must contain a JSON object".to_owned(),
                ));
            }
            let response = authorized(
                client.post(format!(
                    "{}/v1/extensions/{extension_id}/invoke",
                    connection.base_url
                )),
                connection,
            )
            .json(&InvokeExtensionRequest {
                api_version: API_VERSION.to_owned(),
                capability_id: capability,
                input,
            })
            .send()
            .await?;
            print_json(decode::<ExtensionInvocationResponse>(response).await?)?;
        }
    }
    Ok(())
}

fn read_extension_manifest(path: &Path) -> Result<String, CliError> {
    let file = open_extension_manifest(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAXIMUM_EXTENSION_MANIFEST_BYTES
    {
        return Err(CliError::InvalidExtensionManifest);
    }
    let mut body = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| CliError::InvalidExtensionManifest)?,
    );
    file.take(MAXIMUM_EXTENSION_MANIFEST_BYTES.saturating_add(1))
        .read_to_end(&mut body)?;
    if body.is_empty()
        || u64::try_from(body.len()).unwrap_or(u64::MAX) > MAXIMUM_EXTENSION_MANIFEST_BYTES
    {
        return Err(CliError::InvalidExtensionManifest);
    }
    String::from_utf8(body).map_err(|_| CliError::InvalidExtensionManifest)
}

#[cfg(unix)]
fn open_extension_manifest(path: &Path) -> Result<File, CliError> {
    use rustix::fs::{Mode, OFlags, open};

    open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| CliError::Io(error.into()))
}

#[cfg(not(unix))]
fn open_extension_manifest(path: &Path) -> Result<File, CliError> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(CliError::InvalidExtensionManifest);
    }
    File::open(path).map_err(CliError::Io)
}

fn canonical_utf8_path(path: &Path) -> Result<String, CliError> {
    std::fs::canonicalize(path)?
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| CliError::Protocol("extension path must be valid UTF-8".to_owned()))
}

async fn extension_lifecycle_request(
    client: &Client,
    connection: &LocalConnectionInfo,
    extension_id: &str,
    operation: &str,
    expected_revision: u64,
) -> Result<ExtensionResponse, CliError> {
    let response = authorized(
        client.post(format!(
            "{}/v1/extensions/{extension_id}/{operation}",
            connection.base_url
        )),
        connection,
    )
    .json(&ExtensionLifecycleRequest {
        api_version: API_VERSION.to_owned(),
        expected_revision,
    })
    .send()
    .await?;
    decode(response).await
}

async fn run_channel(
    client: &Client,
    connection: &LocalConnectionInfo,
    command: ChannelCommand,
) -> Result<(), CliError> {
    match command {
        telegram_command @ (ChannelCommand::TelegramCreate { .. }
        | ChannelCommand::TelegramPair { .. }
        | ChannelCommand::TelegramList
        | ChannelCommand::TelegramStatus { .. }
        | ChannelCommand::TelegramRevoke { .. }) => {
            return run_telegram_channel(client, connection, telegram_command).await;
        }
        discord_command @ (ChannelCommand::DiscordCreate { .. }
        | ChannelCommand::DiscordPair { .. }
        | ChannelCommand::DiscordList
        | ChannelCommand::DiscordStatus { .. }
        | ChannelCommand::DiscordRevoke { .. }) => {
            return run_discord_channel(client, connection, discord_command).await;
        }
        ChannelCommand::Create {
            external_subject,
            callback_url,
        } => {
            let response = authorized(
                client.post(format!("{}/v1/channels/webhooks", connection.base_url)),
                connection,
            )
            .json(&CreateWebhookChannelRequest {
                api_version: API_VERSION.to_owned(),
                external_subject,
                callback_url,
            })
            .send()
            .await?;
            let created = decode::<CreateWebhookChannelResponse>(response).await?;
            eprintln!("store signingSecret now; it is returned only by this creation command");
            print_json(created)?;
        }
        ChannelCommand::List => {
            let response = authorized(
                client.get(format!("{}/v1/channels/webhooks", connection.base_url)),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<WebhookChannelsResponse>(response).await?)?;
        }
        ChannelCommand::Status { binding_id } => {
            let response = authorized(
                client.get(format!(
                    "{}/v1/channels/webhooks/{binding_id}",
                    connection.base_url
                )),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<WebhookChannelResponse>(response).await?)?;
        }
        ChannelCommand::Revoke {
            binding_id,
            expected_revision,
        } => {
            let response = authorized(
                client.post(format!(
                    "{}/v1/channels/webhooks/{binding_id}/revoke",
                    connection.base_url
                )),
                connection,
            )
            .json(&RevokeWebhookChannelRequest {
                api_version: API_VERSION.to_owned(),
                expected_revision,
            })
            .send()
            .await?;
            print_json(decode::<WebhookChannelResponse>(response).await?)?;
        }
    }
    Ok(())
}

async fn run_telegram_channel(
    client: &Client,
    connection: &LocalConnectionInfo,
    command: ChannelCommand,
) -> Result<(), CliError> {
    let response = match command {
        ChannelCommand::TelegramCreate {
            user_id,
            chat_id,
            token_env,
        } => {
            let token = read_channel_credential_environment(&token_env)?;
            submit_telegram_channel_secret(
                client,
                connection,
                CreateTelegramChannelRequest {
                    api_version: API_VERSION.to_owned(),
                    bot_token: token.to_string(),
                    telegram_user_id: user_id,
                    telegram_chat_id: chat_id,
                    initial_next_update_id: 0,
                },
            )
            .await?
        }
        ChannelCommand::TelegramPair {
            token_env,
            api_base_url,
            timeout_seconds,
        } => {
            let token = read_channel_credential_environment(&token_env)?;
            let pairing = pair_telegram_channel(
                token.as_str(),
                &api_base_url,
                Duration::from_secs(timeout_seconds),
            )
            .await?;
            submit_telegram_channel_secret(
                client,
                connection,
                CreateTelegramChannelRequest {
                    api_version: API_VERSION.to_owned(),
                    bot_token: token.to_string(),
                    telegram_user_id: pairing.user,
                    telegram_chat_id: pairing.chat,
                    initial_next_update_id: pairing.next_update,
                },
            )
            .await?
        }
        ChannelCommand::TelegramList => {
            let response = authorized(
                client.get(format!("{}/v1/channels/telegram", connection.base_url)),
                connection,
            )
            .send()
            .await?;
            return print_json(decode::<TelegramChannelsResponse>(response).await?);
        }
        ChannelCommand::TelegramStatus { binding_id } => {
            authorized(
                client.get(format!(
                    "{}/v1/channels/telegram/{binding_id}",
                    connection.base_url
                )),
                connection,
            )
            .send()
            .await?
        }
        ChannelCommand::TelegramRevoke {
            binding_id,
            expected_revision,
        } => {
            authorized(
                client.post(format!(
                    "{}/v1/channels/telegram/{binding_id}/revoke",
                    connection.base_url
                )),
                connection,
            )
            .json(&RevokeTelegramChannelRequest {
                api_version: API_VERSION.to_owned(),
                expected_revision,
            })
            .send()
            .await?
        }
        _ => {
            return Err(CliError::Protocol(
                "non-Telegram command reached Telegram dispatcher".to_owned(),
            ));
        }
    };
    print_json(decode::<TelegramChannelResponse>(response).await?)
}

async fn submit_telegram_channel_secret(
    client: &Client,
    connection: &LocalConnectionInfo,
    mut command: CreateTelegramChannelRequest,
) -> Result<Response, CliError> {
    let request = authorized(
        client.post(format!("{}/v1/channels/telegram", connection.base_url)),
        connection,
    )
    .json(&command);
    command.bot_token.zeroize();
    request.send().await.map_err(CliError::Http)
}

#[derive(Debug, Deserialize)]
struct TelegramPairEnvelope<T> {
    ok: bool,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct TelegramPairBot {
    id: i64,
    is_bot: bool,
    username: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramPairUpdates {
    ok: bool,
    #[serde(default)]
    result: Vec<TelegramPairUpdate>,
}

#[derive(Debug, Deserialize)]
struct TelegramPairUpdate {
    update_id: i64,
    message: Option<TelegramPairMessage>,
}

#[derive(Debug, Deserialize)]
struct TelegramPairMessage {
    from: Option<TelegramPairUser>,
    chat: TelegramPairChat,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramPairUser {
    id: i64,
    is_bot: bool,
}

#[derive(Debug, Deserialize)]
struct TelegramPairChat {
    id: i64,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TelegramPairing {
    user: i64,
    chat: i64,
    next_update: i64,
}

async fn pair_telegram_channel(
    token: &str,
    api_base_url: &str,
    timeout: Duration,
) -> Result<TelegramPairing, CliError> {
    if !(Duration::from_secs(TELEGRAM_PAIR_MINIMUM_TIMEOUT_SECONDS)
        ..=Duration::from_secs(TELEGRAM_PAIR_MAXIMUM_TIMEOUT_SECONDS))
        .contains(&timeout)
    {
        return Err(CliError::TelegramPairing(format!(
            "timeout must be between {TELEGRAM_PAIR_MINIMUM_TIMEOUT_SECONDS} and {TELEGRAM_PAIR_MAXIMUM_TIMEOUT_SECONDS} seconds"
        )));
    }
    validate_telegram_pair_token(token)?;
    let get_me_url = telegram_pair_api_url(api_base_url, token, "getMe")?;
    let get_updates_url = telegram_pair_api_url(api_base_url, token, "getUpdates")?;
    let pairing_client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| telegram_pairing_error("HTTP client is unavailable"))?;
    let bot = telegram_pair_get_me(&pairing_client, get_me_url).await?;
    let challenge = generate_telegram_pair_challenge()?;
    let expected_text = format!("/pair {challenge}");
    eprintln!(
        "send exactly `{expected_text}` to @{} in a private Telegram chat within {} seconds",
        bot.username,
        timeout.as_secs()
    );

    let deadline = tokio::time::Instant::now() + timeout;
    let mut offset = 0_i64;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(telegram_pairing_error("challenge expired"));
        }
        let updates = tokio::time::timeout(
            remaining,
            telegram_pair_get_updates(&pairing_client, get_updates_url.clone(), offset),
        )
        .await
        .map_err(|_| telegram_pairing_error("challenge expired"))??;
        let received_updates = !updates.is_empty();
        if let Some(pairing) = observe_telegram_pair_updates(updates, &expected_text, &mut offset)?
        {
            return Ok(pairing);
        }
        if !received_updates {
            let pause = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .min(Duration::from_millis(250));
            if pause.is_zero() {
                return Err(telegram_pairing_error("challenge expired"));
            }
            tokio::time::sleep(pause).await;
        }
    }
}

fn observe_telegram_pair_updates(
    updates: Vec<TelegramPairUpdate>,
    expected_text: &str,
    offset: &mut i64,
) -> Result<Option<TelegramPairing>, CliError> {
    for update in updates {
        if update.update_id < 0 {
            return Err(telegram_pairing_error(
                "Bot API returned a malformed update",
            ));
        }
        *offset = (*offset).max(
            update
                .update_id
                .checked_add(1)
                .ok_or_else(|| telegram_pairing_error("Bot API update ID overflowed"))?,
        );
        let Some(message) = update.message else {
            continue;
        };
        let Some(sender) = message.from else {
            continue;
        };
        if message.text.as_deref() == Some(expected_text)
            && !sender.is_bot
            && sender.id > 0
            && message.chat.id != 0
            && message.chat.kind == "private"
            && message.chat.id == sender.id
        {
            return Ok(Some(TelegramPairing {
                user: sender.id,
                chat: message.chat.id,
                next_update: *offset,
            }));
        }
    }
    Ok(None)
}

async fn telegram_pair_get_me(
    client: &Client,
    url: reqwest::Url,
) -> Result<VerifiedTelegramPairBot, CliError> {
    let response = client
        .post(url)
        .send()
        .await
        .map_err(|_| telegram_pairing_error("Bot API transport is unavailable"))?;
    validate_telegram_pair_status(&response)?;
    let envelope: TelegramPairEnvelope<TelegramPairBot> =
        read_telegram_pair_json(response, TELEGRAM_PAIR_GET_ME_MAXIMUM_BYTES).await?;
    let bot = envelope
        .ok
        .then_some(envelope.result)
        .flatten()
        .filter(|bot| bot.is_bot && bot.id > 0)
        .ok_or_else(|| telegram_pairing_error("bot identity verification failed"))?;
    let username = bot
        .username
        .filter(|username| valid_telegram_pair_username(username))
        .ok_or_else(|| telegram_pairing_error("bot identity verification failed"))?;
    Ok(VerifiedTelegramPairBot { username })
}

struct VerifiedTelegramPairBot {
    username: String,
}

async fn telegram_pair_get_updates(
    client: &Client,
    url: reqwest::Url,
    offset: i64,
) -> Result<Vec<TelegramPairUpdate>, CliError> {
    let response = client
        .post(url)
        .json(&json!({
            "offset": offset,
            "limit": 100,
            "timeout": 5,
            "allowed_updates": ["message"]
        }))
        .send()
        .await
        .map_err(|_| telegram_pairing_error("Bot API transport is unavailable"))?;
    validate_telegram_pair_status(&response)?;
    let envelope: TelegramPairUpdates =
        read_telegram_pair_json(response, TELEGRAM_PAIR_UPDATES_MAXIMUM_BYTES).await?;
    if !envelope.ok || envelope.result.len() > 100 {
        return Err(telegram_pairing_error(
            "Bot API returned a malformed response",
        ));
    }
    Ok(envelope.result)
}

async fn read_telegram_pair_json<T: DeserializeOwned>(
    mut response: Response,
    maximum_bytes: usize,
) -> Result<T, CliError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum_bytes as u64)
    {
        return Err(telegram_pairing_error(
            "Bot API response exceeded the size limit",
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| telegram_pairing_error("Bot API response could not be read"))?
    {
        if body.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(telegram_pairing_error(
                "Bot API response exceeded the size limit",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|_| telegram_pairing_error("Bot API returned malformed JSON"))
}

fn validate_telegram_pair_status(response: &Response) -> Result<(), CliError> {
    if response.status().is_success() {
        return Ok(());
    }
    let message = match response.status().as_u16() {
        400 | 401 | 404 => "bot token was rejected".to_owned(),
        409 => "getUpdates conflicts with a configured Telegram webhook".to_owned(),
        429 => "Bot API rate limit was reached".to_owned(),
        500..=599 => "Bot API is temporarily unavailable".to_owned(),
        status => format!("Bot API returned HTTP status {status}"),
    };
    Err(telegram_pairing_error(message))
}

fn telegram_pair_api_url(
    api_base_url: &str,
    token: &str,
    method: &str,
) -> Result<reqwest::Url, CliError> {
    let mut url = reqwest::Url::parse(api_base_url)
        .map_err(|_| telegram_pairing_error("Bot API origin is invalid"))?;
    let scheme_allowed = match url.scheme() {
        "https" => true,
        "http" => url
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|address| address.is_loopback()),
        _ => false,
    };
    if url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || !scheme_allowed
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(method, "getMe" | "getUpdates")
    {
        return Err(telegram_pairing_error("Bot API origin is invalid"));
    }
    url.set_path(&format!("/bot{token}/{method}"));
    Ok(url)
}

fn validate_telegram_pair_token(token: &str) -> Result<(), CliError> {
    let Some((bot_id, secret)) = token.split_once(':') else {
        return Err(telegram_pairing_error("bot token is invalid"));
    };
    if token.len() < 16
        || token.len() > 256
        || bot_id.is_empty()
        || !bot_id.bytes().all(|byte| byte.is_ascii_digit())
        || bot_id.parse::<i64>().ok().is_none_or(|value| value <= 0)
        || secret.len() < 16
        || !secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(telegram_pairing_error("bot token is invalid"));
    }
    Ok(())
}

fn valid_telegram_pair_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= 64
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn generate_telegram_pair_challenge() -> Result<String, CliError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| CliError::RandomUnavailable)?;
    Ok(format!("MEALY-{}", URL_SAFE_NO_PAD.encode(bytes)))
}

fn telegram_pairing_error(message: impl Into<String>) -> CliError {
    CliError::TelegramPairing(message.into())
}

async fn run_discord_channel(
    client: &Client,
    connection: &LocalConnectionInfo,
    command: ChannelCommand,
) -> Result<(), CliError> {
    let response = match command {
        ChannelCommand::DiscordCreate {
            user_id,
            channel_id,
            token_env,
        } => {
            let token = read_channel_credential_environment(&token_env)?;
            submit_discord_channel_secret(
                client,
                connection,
                CreateDiscordChannelRequest {
                    api_version: API_VERSION.to_owned(),
                    bot_token: token.to_string(),
                    discord_user_id: user_id,
                    discord_channel_id: channel_id,
                },
            )
            .await?
        }
        ChannelCommand::DiscordPair {
            channel_id,
            token_env,
            api_base_url,
            timeout_seconds,
        } => {
            let token = read_channel_credential_environment(&token_env)?;
            let pairing = pair_discord_channel(
                token.as_str(),
                &api_base_url,
                &channel_id,
                Duration::from_secs(timeout_seconds),
            )
            .await?;
            submit_discord_channel_secret(
                client,
                connection,
                CreateDiscordChannelRequest {
                    api_version: API_VERSION.to_owned(),
                    bot_token: token.to_string(),
                    discord_user_id: pairing.user,
                    discord_channel_id: pairing.channel,
                },
            )
            .await?
        }
        ChannelCommand::DiscordList => {
            let response = authorized(
                client.get(format!("{}/v1/channels/discord", connection.base_url)),
                connection,
            )
            .send()
            .await?;
            return print_json(decode::<DiscordChannelsResponse>(response).await?);
        }
        ChannelCommand::DiscordStatus { binding_id } => {
            authorized(
                client.get(format!(
                    "{}/v1/channels/discord/{binding_id}",
                    connection.base_url
                )),
                connection,
            )
            .send()
            .await?
        }
        ChannelCommand::DiscordRevoke {
            binding_id,
            expected_revision,
        } => {
            authorized(
                client.post(format!(
                    "{}/v1/channels/discord/{binding_id}/revoke",
                    connection.base_url
                )),
                connection,
            )
            .json(&RevokeDiscordChannelRequest {
                api_version: API_VERSION.to_owned(),
                expected_revision,
            })
            .send()
            .await?
        }
        _ => {
            return Err(CliError::Protocol(
                "non-Discord command reached Discord dispatcher".to_owned(),
            ));
        }
    };
    print_json(decode::<DiscordChannelResponse>(response).await?)
}

async fn submit_discord_channel_secret(
    client: &Client,
    connection: &LocalConnectionInfo,
    mut command: CreateDiscordChannelRequest,
) -> Result<Response, CliError> {
    let request = authorized(
        client.post(format!("{}/v1/channels/discord", connection.base_url)),
        connection,
    )
    .json(&command);
    command.bot_token.zeroize();
    request.send().await.map_err(CliError::Http)
}

#[derive(Clone, Debug, Deserialize)]
struct DiscordPairUser {
    id: String,
    username: String,
    #[serde(default)]
    bot: bool,
}

#[derive(Debug, Deserialize)]
struct DiscordPairChannel {
    id: String,
    #[serde(rename = "type")]
    channel_type: u8,
    #[serde(default)]
    recipients: Vec<DiscordPairUser>,
}

#[derive(Clone, Debug, Deserialize)]
struct DiscordPairMessage {
    id: String,
    channel_id: String,
    author: DiscordPairUser,
    content: String,
    #[serde(rename = "type")]
    message_type: u8,
    #[serde(default)]
    attachments: Vec<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DiscordPairing {
    user: String,
    channel: String,
}

#[allow(clippy::too_many_lines)]
async fn pair_discord_channel(
    token: &str,
    api_base_url: &str,
    channel_id: &str,
    timeout: Duration,
) -> Result<DiscordPairing, CliError> {
    if !(Duration::from_secs(DISCORD_PAIR_MINIMUM_TIMEOUT_SECONDS)
        ..=Duration::from_secs(DISCORD_PAIR_MAXIMUM_TIMEOUT_SECONDS))
        .contains(&timeout)
    {
        return Err(discord_pairing_error(format!(
            "timeout must be between {DISCORD_PAIR_MINIMUM_TIMEOUT_SECONDS} and {DISCORD_PAIR_MAXIMUM_TIMEOUT_SECONDS} seconds"
        )));
    }
    validate_discord_pair_token(token)?;
    if !validate_discord_snowflake(channel_id) {
        return Err(discord_pairing_error("DM channel snowflake is invalid"));
    }
    let base = validate_discord_pair_base_url(api_base_url)?;
    let pairing_client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| discord_pairing_error("HTTP client is unavailable"))?;
    let bot: DiscordPairUser = discord_pair_get_json(
        &pairing_client,
        token,
        format!("{base}/users/@me"),
        64 * 1024,
    )
    .await?;
    if !bot.bot
        || !validate_discord_snowflake(&bot.id)
        || bot.username.is_empty()
        || bot.username.len() > 64
        || bot.username.trim() != bot.username
        || bot.username.chars().any(unsafe_terminal_character)
    {
        return Err(discord_pairing_error("bot identity verification failed"));
    }
    let channel: DiscordPairChannel = discord_pair_get_json(
        &pairing_client,
        token,
        format!("{base}/channels/{channel_id}"),
        128 * 1024,
    )
    .await?;
    let human = match channel.recipients.as_slice() {
        [recipient]
            if channel.channel_type == 1
                && channel.id == channel_id
                && validate_discord_snowflake(&channel.id)
                && validate_discord_snowflake(&recipient.id)
                && !recipient.bot
                && recipient.id != bot.id =>
        {
            recipient.clone()
        }
        _ => {
            return Err(discord_pairing_error(
                "channel is not one exact human-to-bot direct message",
            ));
        }
    };
    let latest: Vec<DiscordPairMessage> = discord_pair_get_json(
        &pairing_client,
        token,
        format!("{base}/channels/{channel_id}/messages?limit=1"),
        DISCORD_PAIR_MAXIMUM_RESPONSE_BYTES,
    )
    .await?;
    if latest.len() > 1
        || latest.iter().any(|message| {
            !validate_discord_snowflake(&message.id) || message.channel_id != channel_id
        })
    {
        return Err(discord_pairing_error(
            "Discord returned malformed DM history",
        ));
    }
    let mut after_message_id = latest.into_iter().next().map(|message| message.id);
    let challenge = generate_discord_pair_challenge()?;
    let expected_text = format!("/pair {challenge}");
    eprintln!(
        "send exactly `{expected_text}` in the one-to-one DM channel {channel_id} with bot {} within {} seconds",
        bot.username,
        timeout.as_secs()
    );

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(discord_pairing_error("challenge expired"));
        }
        let query = after_message_id
            .as_ref()
            .map_or_else(String::new, |message_id| format!("&after={message_id}"));
        let response = tokio::time::timeout(
            remaining,
            discord_pair_get_messages(
                &pairing_client,
                token,
                format!("{base}/channels/{channel_id}/messages?limit=100{query}"),
            ),
        )
        .await
        .map_err(|_| discord_pairing_error("challenge expired"))??;
        match response {
            DiscordPairPoll::Messages(messages) => {
                if let Some(pairing) = observe_discord_pair_messages(
                    messages,
                    channel_id,
                    &human.id,
                    &expected_text,
                    &mut after_message_id,
                )? {
                    return Ok(pairing);
                }
                let pause = deadline
                    .saturating_duration_since(tokio::time::Instant::now())
                    .min(Duration::from_secs(1));
                if pause.is_zero() {
                    return Err(discord_pairing_error("challenge expired"));
                }
                tokio::time::sleep(pause).await;
            }
            DiscordPairPoll::RateLimited(delay) => {
                let pause =
                    delay.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
                if pause.is_zero() {
                    return Err(discord_pairing_error("challenge expired"));
                }
                tokio::time::sleep(pause).await;
            }
        }
    }
}

fn observe_discord_pair_messages(
    mut messages: Vec<DiscordPairMessage>,
    expected_channel_id: &str,
    expected_user_id: &str,
    expected_text: &str,
    after_message_id: &mut Option<String>,
) -> Result<Option<DiscordPairing>, CliError> {
    if messages.len() > 100 {
        return Err(discord_pairing_error(
            "Discord returned too many DM messages",
        ));
    }
    messages.sort_by(|left, right| discord_pair_snowflake_cmp(&left.id, &right.id));
    for message in messages {
        if !validate_discord_snowflake(&message.id) || message.channel_id != expected_channel_id {
            return Err(discord_pairing_error(
                "Discord returned malformed DM history",
            ));
        }
        if after_message_id
            .as_deref()
            .is_none_or(|cursor| discord_pair_snowflake_cmp(&message.id, cursor).is_gt())
        {
            *after_message_id = Some(message.id.clone());
        }
        if message.author.id == expected_user_id
            && !message.author.bot
            && message.content == expected_text
            && message.message_type == 0
            && message.attachments.is_empty()
        {
            return Ok(Some(DiscordPairing {
                user: expected_user_id.to_owned(),
                channel: expected_channel_id.to_owned(),
            }));
        }
    }
    Ok(None)
}

enum DiscordPairPoll {
    Messages(Vec<DiscordPairMessage>),
    RateLimited(Duration),
}

async fn discord_pair_get_messages(
    client: &Client,
    token: &str,
    url: String,
) -> Result<DiscordPairPoll, CliError> {
    let response = discord_pair_request(client, token, url).await?;
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        return Ok(DiscordPairPoll::RateLimited(
            discord_pair_retry_after(response).await,
        ));
    }
    validate_discord_pair_status(&response)?;
    Ok(DiscordPairPoll::Messages(
        read_discord_pair_json(response, DISCORD_PAIR_MAXIMUM_RESPONSE_BYTES).await?,
    ))
}

async fn discord_pair_get_json<T: DeserializeOwned>(
    client: &Client,
    token: &str,
    url: String,
    maximum_bytes: usize,
) -> Result<T, CliError> {
    let response = discord_pair_request(client, token, url).await?;
    validate_discord_pair_status(&response)?;
    read_discord_pair_json(response, maximum_bytes).await
}

async fn discord_pair_request(
    client: &Client,
    token: &str,
    url: String,
) -> Result<Response, CliError> {
    client
        .get(url)
        .header(reqwest::header::AUTHORIZATION, format!("Bot {token}"))
        .header(
            reqwest::header::USER_AGENT,
            concat!(
                "DiscordBot (https://github.com/Amekn/mealy, ",
                env!("CARGO_PKG_VERSION"),
                ")"
            ),
        )
        .send()
        .await
        .map_err(|_| discord_pairing_error("Discord transport is unavailable"))
}

async fn read_discord_pair_json<T: DeserializeOwned>(
    mut response: Response,
    maximum_bytes: usize,
) -> Result<T, CliError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum_bytes as u64)
    {
        return Err(discord_pairing_error(
            "Discord response exceeded the size limit",
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| discord_pairing_error("Discord response could not be read"))?
    {
        if body.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(discord_pairing_error(
                "Discord response exceeded the size limit",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|_| discord_pairing_error("Discord returned malformed JSON"))
}

async fn discord_pair_retry_after(response: Response) -> Duration {
    let header = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_discord_pair_seconds);
    let body = read_discord_pair_json::<Value>(response, 64 * 1024)
        .await
        .ok()
        .and_then(|value| value.get("retry_after").and_then(Value::as_f64))
        .and_then(discord_pair_duration);
    header.or(body).unwrap_or(Duration::from_secs(5))
}

fn validate_discord_pair_status(response: &Response) -> Result<(), CliError> {
    if response.status().is_success() {
        return Ok(());
    }
    let message = match response.status().as_u16() {
        400 | 401 => "bot token was rejected".to_owned(),
        403 => "bot cannot access the requested one-to-one DM".to_owned(),
        404 => "one-to-one DM channel was not found".to_owned(),
        429 => "Discord rate limit was reached during setup".to_owned(),
        500..=599 => "Discord is temporarily unavailable".to_owned(),
        status => format!("Discord returned HTTP status {status}"),
    };
    Err(discord_pairing_error(message))
}

fn validate_discord_pair_base_url(value: &str) -> Result<String, CliError> {
    let url = reqwest::Url::parse(value)
        .map_err(|_| discord_pairing_error("Discord API base is invalid"))?;
    let official = url.scheme() == "https"
        && url.host_str() == Some("discord.com")
        && url.port().is_none()
        && matches!(url.path(), "/api/v10" | "/api/v10/");
    let loopback = url.scheme() == "http"
        && url
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|address| address.is_loopback())
        && matches!(url.path(), "" | "/");
    if url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || !(official || loopback)
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(discord_pairing_error("Discord API base is invalid"));
    }
    Ok(value.trim_end_matches('/').to_owned())
}

fn validate_discord_pair_token(token: &str) -> Result<(), CliError> {
    if token.len() < 20
        || token.len() > 256
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(discord_pairing_error("bot token is invalid"));
    }
    Ok(())
}

fn generate_discord_pair_challenge() -> Result<String, CliError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| CliError::RandomUnavailable)?;
    Ok(format!("MEALY-{}", URL_SAFE_NO_PAD.encode(bytes)))
}

fn discord_pair_snowflake_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

fn parse_discord_pair_seconds(value: &str) -> Option<Duration> {
    if value.is_empty()
        || value.len() > 32
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return None;
    }
    value.parse::<f64>().ok().and_then(discord_pair_duration)
}

fn discord_pair_duration(seconds: f64) -> Option<Duration> {
    if !seconds.is_finite() || !(0.0..=86_400.0).contains(&seconds) {
        return None;
    }
    Duration::try_from_secs_f64(seconds.max(0.05)).ok()
}

fn discord_pairing_error(message: impl Into<String>) -> CliError {
    CliError::DiscordPairing(message.into())
}

#[allow(clippy::too_many_lines)]
async fn run_schedule(
    client: &Client,
    connection: &LocalConnectionInfo,
    command: ScheduleCommand,
) -> Result<(), CliError> {
    match command {
        ScheduleCommand::Create {
            session_id,
            name,
            cron,
            timezone,
            missed_run_policy,
            overlap_policy,
            misfire_grace_ms,
            allow_approval_required_action,
            prompt,
        } => {
            let response = authorized(
                client.post(format!("{}/v1/schedules", connection.base_url)),
                connection,
            )
            .json(&CreateScheduleRequest {
                api_version: API_VERSION.to_owned(),
                schedule_id: ScheduleId::new().to_string(),
                session_id,
                name,
                prompt,
                cron_expression: cron,
                timezone,
                missed_run_policy: missed_run_policy.into(),
                overlap_policy: overlap_policy.into(),
                misfire_grace_ms,
                allow_approval_required_action,
            })
            .send()
            .await?;
            print_json(decode::<ScheduleResponse>(response).await?)?;
        }
        ScheduleCommand::List => {
            let response = authorized(
                client.get(format!("{}/v1/schedules", connection.base_url)),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<SchedulesResponse>(response).await?)?;
        }
        ScheduleCommand::Status { schedule_id } => {
            let response = authorized(
                client.get(format!(
                    "{}/v1/schedules/{schedule_id}",
                    connection.base_url
                )),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<ScheduleResponse>(response).await?)?;
        }
        ScheduleCommand::Pause {
            schedule_id,
            expected_revision,
        } => {
            print_json(
                schedule_lifecycle_request(
                    client,
                    connection,
                    &schedule_id,
                    "pause",
                    expected_revision,
                )
                .await?,
            )?;
        }
        ScheduleCommand::Resume {
            schedule_id,
            expected_revision,
        } => {
            print_json(
                schedule_lifecycle_request(
                    client,
                    connection,
                    &schedule_id,
                    "resume",
                    expected_revision,
                )
                .await?,
            )?;
        }
        ScheduleCommand::Cancel {
            schedule_id,
            expected_revision,
        } => {
            print_json(
                schedule_lifecycle_request(
                    client,
                    connection,
                    &schedule_id,
                    "cancel",
                    expected_revision,
                )
                .await?,
            )?;
        }
        ScheduleCommand::Runs { schedule_id, limit } => {
            let response = authorized(
                client
                    .get(format!(
                        "{}/v1/schedules/{schedule_id}/runs",
                        connection.base_url
                    ))
                    .query(&[("limit", limit)]),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<ScheduleRunsResponse>(response).await?)?;
        }
    }
    Ok(())
}

async fn schedule_lifecycle_request(
    client: &Client,
    connection: &LocalConnectionInfo,
    schedule_id: &str,
    operation: &str,
    expected_revision: u64,
) -> Result<ScheduleResponse, CliError> {
    let response = authorized(
        client.post(format!(
            "{}/v1/schedules/{schedule_id}/{operation}",
            connection.base_url
        )),
        connection,
    )
    .json(&ScheduleLifecycleRequest {
        api_version: API_VERSION.to_owned(),
        expected_revision,
    })
    .send()
    .await?;
    decode(response).await
}

async fn fetch_memories(
    client: &Client,
    connection: &LocalConnectionInfo,
    workspace: &str,
    include_deleted: bool,
) -> Result<MemoriesResponse, CliError> {
    let response = authorized(
        client
            .get(format!("{}/v1/memories", connection.base_url))
            .query(&[
                ("workspaceIdentity", workspace.to_owned()),
                ("includeDeleted", include_deleted.to_string()),
            ]),
        connection,
    )
    .send()
    .await?;
    decode(response).await
}

async fn memory_lifecycle_request(
    client: &Client,
    connection: &LocalConnectionInfo,
    memory_id: &str,
    operation: &str,
    expected_revision: u64,
) -> Result<MemoryResponse, CliError> {
    let response = authorized(
        client.post(format!(
            "{}/v1/memories/{memory_id}/{operation}",
            connection.base_url
        )),
        connection,
    )
    .json(&MemoryLifecycleRequest {
        api_version: API_VERSION.to_owned(),
        expected_revision,
    })
    .send()
    .await?;
    decode(response).await
}

fn parse_memory_sources(values: Vec<String>) -> Result<Vec<MemorySourceCommand>, CliError> {
    values
        .into_iter()
        .map(|value| {
            let (locator, digest) = value.split_once('=').ok_or_else(|| {
                CliError::Protocol("--source must use LOCATOR=DIGEST syntax".to_owned())
            })?;
            if locator.is_empty()
                || digest.len() != 64
                || digest
                    .bytes()
                    .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
            {
                return Err(CliError::Protocol(
                    "--source requires a non-empty locator and lowercase SHA-256 digest".to_owned(),
                ));
            }
            Ok(MemorySourceCommand {
                locator: locator.to_owned(),
                digest: digest.to_owned(),
            })
        })
        .collect()
}

async fn run_task(
    client: &Client,
    connection: &LocalConnectionInfo,
    command: TaskCommand,
) -> Result<(), CliError> {
    match command {
        TaskCommand::Status { task_id } => {
            let response = authorized(
                client.get(format!("{}/v1/tasks/{task_id}", connection.base_url)),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<TaskResponse>(response).await?)?;
        }
        TaskCommand::Cancel {
            task_id,
            reason,
            idempotency_key,
        } => {
            let generated = idempotency_key.is_none();
            let idempotency_key = idempotency_key.map_or_else(generate_idempotency_key, Ok)?;
            if generated {
                eprintln!("MEALY_IDEMPOTENCY_KEY {idempotency_key}");
            }
            let response = authorized(
                client.post(format!("{}/v1/tasks/{task_id}/cancel", connection.base_url)),
                connection,
            )
            .json(&CancelTaskRequest {
                api_version: API_VERSION.to_owned(),
                idempotency_key,
                reason,
            })
            .send()
            .await?;
            print_json(decode::<TaskCancellationReceipt>(response).await?)?;
        }
        TaskCommand::Replay { task_id } => {
            let response = authorized(
                client.get(format!("{}/v1/tasks/{task_id}/replay", connection.base_url)),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<TaskReplayResponse>(response).await?)?;
        }
        TaskCommand::Pause {
            task_id,
            expected_revision,
        } => {
            let response = authorized(
                client.post(format!("{}/v1/tasks/{task_id}/pause", connection.base_url)),
                connection,
            )
            .json(&ControlTaskRequest {
                api_version: API_VERSION.to_owned(),
                expected_revision,
            })
            .send()
            .await?;
            print_json(decode::<TaskControlReceipt>(response).await?)?;
        }
        TaskCommand::Resume {
            task_id,
            expected_revision,
        } => {
            let response = authorized(
                client.post(format!("{}/v1/tasks/{task_id}/resume", connection.base_url)),
                connection,
            )
            .json(&ControlTaskRequest {
                api_version: API_VERSION.to_owned(),
                expected_revision,
            })
            .send()
            .await?;
            print_json(decode::<TaskControlReceipt>(response).await?)?;
        }
    }
    Ok(())
}

async fn run_delegation(
    client: &Client,
    connection: &LocalConnectionInfo,
    command: DelegationCommand,
) -> Result<(), CliError> {
    match command {
        DelegationCommand::List { limit } => {
            let response = authorized(
                client.get(format!(
                    "{}/v1/delegations?limit={limit}",
                    connection.base_url
                )),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<DelegationsResponse>(response).await?)?;
        }
        DelegationCommand::Status { delegation_id } => {
            let response = authorized(
                client.get(format!(
                    "{}/v1/delegations/{delegation_id}",
                    connection.base_url
                )),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<DelegationResponse>(response).await?)?;
        }
    }
    Ok(())
}

fn prepare_local_text_attachment(
    home: &Path,
    path: &Path,
    prompt: &str,
) -> Result<String, CliError> {
    if prompt.is_empty()
        || prompt.len() > MAXIMUM_LOCAL_ATTACHMENT_PROMPT_BYTES
        || prompt.trim() != prompt
        || prompt.chars().any(char::is_control)
    {
        return Err(CliError::InvalidLocalAttachment);
    }
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= MAXIMUM_LOCAL_ATTACHMENT_NAME_BYTES
                && !value.chars().any(char::is_control)
        })
        .ok_or(CliError::InvalidLocalAttachment)?;
    let media_type = local_text_attachment_media_type(path)?;
    let file = open_local_attachment(path)?;
    let metadata = file.metadata()?;
    let canonical_path = fs::canonicalize(path)?;
    let canonical_metadata = fs::metadata(&canonical_path)?;
    let canonical_home = fs::canonicalize(home)?;
    if !metadata.is_file()
        || !same_file_identity(&metadata, &canonical_metadata)
        || paths_overlap(&canonical_path, &canonical_home)
        || metadata.len() == 0
        || metadata.len() > MAXIMUM_LOCAL_TEXT_ATTACHMENT_BYTES
    {
        return Err(CliError::InvalidLocalAttachment);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| CliError::InvalidLocalAttachment)?,
    );
    file.take(MAXIMUM_LOCAL_TEXT_ATTACHMENT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAXIMUM_LOCAL_TEXT_ATTACHMENT_BYTES
    {
        return Err(CliError::InvalidLocalAttachment);
    }
    let digest = sha256_digest(&bytes);
    let text = String::from_utf8(bytes).map_err(|_| CliError::InvalidLocalAttachment)?;
    if text.contains('\0') {
        return Err(CliError::InvalidLocalAttachment);
    }
    let metadata_json = serde_json::to_string(&json!({
        "name": name,
        "mediaType": media_type,
        "sha256": digest,
        "sizeBytes": text.len(),
        "trust": "untrusted_owner_selected_text"
    }))?;
    let content = format!(
        "{prompt}\n\n[Untrusted local text attachment metadata: {metadata_json}]\n{text}\n[End untrusted local text attachment]"
    );
    if content.len() > MAXIMUM_LOCAL_ATTACHMENT_INPUT_BYTES {
        return Err(CliError::InvalidLocalAttachment);
    }
    Ok(content)
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    true
}

fn local_text_attachment_media_type(path: &Path) -> Result<&'static str, CliError> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .ok_or(CliError::InvalidLocalAttachment)?;
    match extension.as_str() {
        "md" | "markdown" => Ok("text/markdown; charset=utf-8"),
        "json" => Ok("application/json; charset=utf-8"),
        "csv" => Ok("text/csv; charset=utf-8"),
        "yaml" | "yml" => Ok("application/yaml; charset=utf-8"),
        "toml" => Ok("application/toml; charset=utf-8"),
        "txt" | "text" | "log" | "rs" | "py" | "js" | "ts" | "html" | "css" | "sh" | "sql" => {
            Ok("text/plain; charset=utf-8")
        }
        _ => Err(CliError::InvalidLocalAttachment),
    }
}

#[cfg(unix)]
fn open_local_attachment(path: &Path) -> Result<File, CliError> {
    use rustix::fs::{Mode, OFlags, open};

    open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| CliError::Io(error.into()))
}

#[cfg(not(unix))]
fn open_local_attachment(path: &Path) -> Result<File, CliError> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(CliError::InvalidLocalAttachment);
    }
    File::open(path).map_err(CliError::Io)
}

async fn run_session(
    client: &Client,
    home: &Path,
    connection: &LocalConnectionInfo,
    command: SessionCommand,
) -> Result<(), CliError> {
    match command {
        SessionCommand::Create => {
            let response = authorized(
                client.post(format!("{}/v1/sessions", connection.base_url)),
                connection,
            )
            .json(&CreateSessionRequest {
                api_version: API_VERSION.to_owned(),
            })
            .send()
            .await?;
            print_json(decode::<CreateSessionResponse>(response).await?)?;
        }
        SessionCommand::List { limit } => {
            let response = authorized(
                client.get(format!("{}/v1/sessions?limit={limit}", connection.base_url)),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<SessionsResponse>(response).await?)?;
        }
        SessionCommand::Search { query, limit } => {
            print_json(search_session_transcripts(client, connection, &query, limit).await?)?;
        }
        SessionCommand::Send {
            session_id,
            content,
            idempotency_key,
            delivery,
        } => {
            let generated = idempotency_key.is_none();
            let key = idempotency_key.map_or_else(generate_idempotency_key, Ok)?;
            if generated {
                eprintln!("MEALY_IDEMPOTENCY_KEY {key}");
            }
            let request = SubmitInputRequest {
                api_version: API_VERSION.to_owned(),
                idempotency_key: key,
                delivery_mode: delivery.into(),
                content,
            };
            print_json(
                submit_input_with_retry(client, home, connection, &session_id, &request).await?,
            )?;
        }
        SessionCommand::SendFile {
            session_id,
            path,
            prompt,
            idempotency_key,
            delivery,
        } => {
            let content = prepare_local_text_attachment(home, &path, &prompt)?;
            let generated = idempotency_key.is_none();
            let key = idempotency_key.map_or_else(generate_idempotency_key, Ok)?;
            if generated {
                eprintln!("MEALY_IDEMPOTENCY_KEY {key}");
            }
            let request = SubmitInputRequest {
                api_version: API_VERSION.to_owned(),
                idempotency_key: key,
                delivery_mode: delivery.into(),
                content,
            };
            print_json(
                submit_input_with_retry(client, home, connection, &session_id, &request).await?,
            )?;
        }
        SessionCommand::Status { session_id } => {
            let response = authorized(
                client.get(format!(
                    "{}/v1/sessions/{session_id}/status",
                    connection.base_url
                )),
                connection,
            )
            .send()
            .await?;
            print_json(decode::<SessionStatusResponse>(response).await?)?;
        }
        SessionCommand::Watch {
            session_id,
            after,
            limit,
        } => watch(client, home, &session_id, after, limit).await?,
    }
    Ok(())
}

async fn search_session_transcripts(
    client: &Client,
    connection: &LocalConnectionInfo,
    query: &str,
    limit: usize,
) -> Result<SessionSearchResponse, CliError> {
    let response = authorized(
        client
            .get(format!("{}/v1/sessions/search", connection.base_url))
            .query(&[("query", query), ("limit", &limit.to_string())]),
        connection,
    )
    .send()
    .await?;
    decode::<SessionSearchResponse>(response).await
}

async fn watch(
    client: &Client,
    home: &Path,
    session_id: &str,
    mut after: Option<u64>,
    limit: usize,
) -> Result<(), CliError> {
    let mut observed = 0_usize;
    let mut reconnect_delay = Duration::from_millis(200);
    loop {
        let connection = match load_connection(home) {
            Ok(connection) => connection,
            Err(CliError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                sleep_before_reconnect(
                    "connection descriptor is not available",
                    &mut reconnect_delay,
                )
                .await;
                continue;
            }
            Err(error) => return Err(error),
        };
        if connection.api_version != API_VERSION {
            return Err(CliError::Protocol(format!(
                "connection descriptor uses unsupported API version {:?}",
                connection.api_version
            )));
        }
        let mut request = authorized_stream(
            client.get(format!(
                "{}/v1/sessions/{session_id}/events",
                connection.base_url
            )),
            &connection,
        )
        .header(reqwest::header::ACCEPT, "text/event-stream");
        if let Some(cursor) = after {
            request = request.header("Last-Event-ID", cursor.to_string());
        }
        let Ok(response) = request.send().await else {
            sleep_before_reconnect("timeline connection failed", &mut reconnect_delay).await;
            continue;
        };
        if !response.status().is_success() {
            if retryable_status(response.status()) {
                sleep_before_reconnect(
                    &format!("timeline endpoint returned {}", response.status()),
                    &mut reconnect_delay,
                )
                .await;
                continue;
            }
            return Err(server_error(response).await);
        }
        let observed_before_connect = observed;
        match consume_timeline_stream(response, &mut after, &mut observed, limit).await? {
            TimelineWatchOutcome::LimitReached => return Ok(()),
            TimelineWatchOutcome::Reconnect(reason) => {
                if observed > observed_before_connect {
                    reconnect_delay = Duration::from_millis(200);
                }
                sleep_before_reconnect(reason, &mut reconnect_delay).await;
            }
        }
    }
}

enum TimelineWatchOutcome {
    LimitReached,
    Reconnect(&'static str),
}

async fn consume_timeline_stream(
    response: Response,
    after: &mut Option<u64>,
    observed: &mut usize,
    limit: usize,
) -> Result<TimelineWatchOutcome, CliError> {
    let mut byte_bound = TimelineSseEventByteBound::new(MAXIMUM_TIMELINE_SSE_EVENT_BYTES);
    let bounded_stream = response.bytes_stream().map(move |chunk| {
        let bytes = chunk.map_err(TimelineStreamTransportError::Http)?;
        byte_bound
            .observe(&bytes)
            .map_err(|()| TimelineStreamTransportError::EventTooLarge)?;
        Ok::<_, TimelineStreamTransportError>(bytes)
    });
    let mut events = bounded_stream.eventsource();
    while let Some(event) = events.next().await {
        let event = match event {
            Ok(event) => event,
            Err(EventStreamError::Transport(TimelineStreamTransportError::Http(_))) => {
                return Ok(TimelineWatchOutcome::Reconnect(
                    "timeline stream was interrupted",
                ));
            }
            Err(EventStreamError::Transport(TimelineStreamTransportError::EventTooLarge)) => {
                return Err(CliError::Protocol(
                    "timeline SSE event exceeded its 8 MiB byte bound".to_owned(),
                ));
            }
            Err(EventStreamError::Utf8(_) | EventStreamError::Parser(_)) => {
                return Err(CliError::Protocol(
                    "timeline SSE stream was malformed".to_owned(),
                ));
            }
        };
        if event.event == "error" {
            return parse_timeline_error_event(&event.data);
        }
        let (cursor, timeline) = parse_timeline_event(&event, *after)?;
        *after = Some(cursor);
        println!("{}", terminal_safe_json(&timeline)?);
        *observed = observed.saturating_add(1);
        if limit != 0 && *observed >= limit {
            return Ok(TimelineWatchOutcome::LimitReached);
        }
    }
    Ok(TimelineWatchOutcome::Reconnect("timeline stream ended"))
}

fn parse_timeline_error_event(data: &str) -> Result<TimelineWatchOutcome, CliError> {
    let error = serde_json::from_str::<ApiErrorResponse>(data).map_err(|_| {
        CliError::Protocol("timeline service returned an invalid error event".to_owned())
    })?;
    if !valid_server_api_error(&error) {
        return Err(CliError::Protocol(
            "timeline service returned an invalid error event".to_owned(),
        ));
    }
    if error.retryable {
        Ok(TimelineWatchOutcome::Reconnect(
            "timeline service is temporarily unavailable",
        ))
    } else {
        Err(CliError::Protocol(format!(
            "timeline service error ({}): {}",
            error.code, error.message
        )))
    }
}

fn parse_timeline_event(
    event: &eventsource_stream::Event,
    after: Option<u64>,
) -> Result<(u64, TimelineEvent), CliError> {
    let cursor = event
        .id
        .parse::<u64>()
        .map_err(|_| CliError::Protocol("invalid SSE cursor".to_owned()))?;
    let timeline = serde_json::from_str::<TimelineEvent>(&event.data)
        .map_err(|_| CliError::Protocol("timeline SSE event contained invalid JSON".to_owned()))?;
    if timeline.cursor.0 != cursor
        || timeline.event_type != event.event
        || after.is_some_and(|prior| cursor <= prior)
    {
        return Err(CliError::Protocol(
            "timeline SSE event identity was inconsistent".to_owned(),
        ));
    }
    Ok((cursor, timeline))
}

#[derive(Debug, Error)]
enum TimelineStreamTransportError {
    #[error(transparent)]
    Http(reqwest::Error),
    #[error("timeline SSE event exceeded its byte bound")]
    EventTooLarge,
}

struct TimelineSseEventByteBound {
    maximum_bytes: usize,
    current_bytes: usize,
    at_line_start: bool,
    previous_was_carriage_return: bool,
    previous_carriage_return_completed_event: bool,
}

impl TimelineSseEventByteBound {
    const fn new(maximum_bytes: usize) -> Self {
        Self {
            maximum_bytes,
            current_bytes: 0,
            at_line_start: true,
            previous_was_carriage_return: false,
            previous_carriage_return_completed_event: false,
        }
    }

    fn observe(&mut self, chunk: &[u8]) -> Result<(), ()> {
        for byte in chunk {
            self.current_bytes = self.current_bytes.checked_add(1).ok_or(())?;
            if self.current_bytes > self.maximum_bytes {
                return Err(());
            }
            match *byte {
                b'\r' => {
                    let completed_event = self.at_line_start;
                    if completed_event {
                        self.current_bytes = 0;
                    }
                    self.at_line_start = true;
                    self.previous_was_carriage_return = true;
                    self.previous_carriage_return_completed_event = completed_event;
                }
                b'\n' if self.previous_was_carriage_return => {
                    if self.previous_carriage_return_completed_event {
                        self.current_bytes = 0;
                    }
                    self.previous_was_carriage_return = false;
                    self.previous_carriage_return_completed_event = false;
                }
                b'\n' => {
                    if self.at_line_start {
                        self.current_bytes = 0;
                    }
                    self.at_line_start = true;
                    self.previous_was_carriage_return = false;
                    self.previous_carriage_return_completed_event = false;
                }
                _ => {
                    self.at_line_start = false;
                    self.previous_was_carriage_return = false;
                    self.previous_carriage_return_completed_event = false;
                }
            }
        }
        Ok(())
    }
}

async fn submit_input_with_retry(
    client: &Client,
    home: &Path,
    initial_connection: &LocalConnectionInfo,
    session_id: &str,
    request: &SubmitInputRequest,
) -> Result<InputAdmissionResponse, CliError> {
    let mut connection = initial_connection.clone();
    for attempt in 0_u32..5 {
        let result = authorized(
            client.post(format!(
                "{}/v1/sessions/{session_id}/inputs",
                connection.base_url
            )),
            &connection,
        )
        .timeout(Duration::from_secs(30))
        .json(request)
        .send()
        .await;
        match result {
            Ok(response) if response.status().is_success() => {
                return decode::<InputAdmissionResponse>(response).await;
            }
            Ok(response) if retryable_status(response.status()) && attempt < 4 => {
                eprintln!(
                    "input admission returned {}; retrying with idempotency key {}",
                    response.status(),
                    request.idempotency_key
                );
            }
            Ok(response) => return Err(server_error(response).await),
            Err(_) if attempt < 4 => {
                eprintln!(
                    "input admission response was unavailable; retrying with idempotency key {}",
                    request.idempotency_key
                );
            }
            Err(error) => return Err(CliError::Http(error)),
        }
        tokio::time::sleep(Duration::from_millis(100_u64 << attempt)).await;
        if let Ok(reloaded) = load_connection(home) {
            connection = reloaded;
        }
    }
    unreachable!("bounded retry loop always returns on its final attempt")
}

const fn retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

async fn sleep_before_reconnect(reason: &str, delay: &mut Duration) {
    eprintln!(
        "{reason}; reconnecting after the durable cursor in {} ms",
        delay.as_millis()
    );
    tokio::time::sleep(*delay).await;
    *delay = delay.saturating_mul(2).min(Duration::from_secs(2));
}

struct ResolvedSetup {
    provider: SetupProviderArgument,
    base_url: String,
    model: String,
    context_tokens: u64,
    maximum_output_tokens: u64,
    credential_env: Option<String>,
    input_microunits_per_million_tokens: u64,
    output_microunits_per_million_tokens: u64,
    streaming: bool,
    skip_connectivity_test: bool,
}

struct ResolvedOnboard {
    route: OnboardRouteArgument,
    provider: ProviderConfig,
    secret_id: Option<String>,
    credential_env: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OnboardResponse {
    provider: ProviderConfigurationResponse,
    service: Option<ServiceInstallationResponse>,
    service_started: bool,
    health_verified: bool,
    doctor: Option<DoctorResponse>,
    next_command: String,
}

impl OnboardRouteArgument {
    const fn display_name(self) -> &'static str {
        match self {
            Self::OpenrouterFree => "OpenRouter free model",
            Self::Custom => "custom authenticated OpenAI-compatible endpoint",
            Self::Local => "local credentialless OpenAI-compatible endpoint",
            Self::ChatgptSubscription => "ChatGPT subscription through official Codex CLI",
            Self::ClaudeSubscription => "Claude subscription through official Claude Code",
            Self::OpenaiApi => "OpenAI API",
            Self::AnthropicApi => "Anthropic API",
        }
    }

    const fn default_base_url(self) -> Option<&'static str> {
        match self {
            Self::OpenrouterFree => Some("https://openrouter.ai/api/v1"),
            Self::Local => Some("http://127.0.0.1:11434/v1"),
            Self::OpenaiApi => Some("https://api.openai.com/v1"),
            Self::AnthropicApi => Some("https://api.anthropic.com/v1"),
            Self::Custom | Self::ChatgptSubscription | Self::ClaudeSubscription => None,
        }
    }

    const fn default_credential_environment(self) -> Option<&'static str> {
        match self {
            Self::OpenrouterFree => Some("OPENROUTER_API_KEY"),
            Self::Custom => Some("CUSTOM_API_KEY"),
            Self::OpenaiApi => Some("OPENAI_API_KEY"),
            Self::AnthropicApi => Some("ANTHROPIC_API_KEY"),
            Self::Local | Self::ChatgptSubscription | Self::ClaudeSubscription => None,
        }
    }

    const fn uses_subscription_client(self) -> bool {
        matches!(self, Self::ChatgptSubscription | Self::ClaudeSubscription)
    }
}

async fn run_onboard(home: &Path, options: &OnboardOptions) -> Result<(), CliError> {
    if options.skip_connectivity_test && !options.configure_only {
        return Err(CliError::InvalidSetupInput);
    }
    validate_onboard_home_target(home, options.reconfigure)?;
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stderr = std::io::stderr();
    let mut prompt = stderr.lock();
    let resolved = resolve_onboard(options, &mut input, &mut prompt)?;
    render_onboard_summary(&resolved, options, &mut prompt)?;
    if !options.approve
        && prompt_line(
            &mut input,
            &mut prompt,
            "Type APPROVE to perform this exact onboarding plan: ",
        )? != "APPROVE"
    {
        return Err(CliError::SetupNotApproved);
    }

    initialize_setup_home(home)?;
    let credential_import = resolved
        .secret_id
        .as_deref()
        .zip(resolved.credential_env.as_deref())
        .map(|(secret_id, credential_env)| ProviderCredentialImport {
            secret_id,
            credential_env,
        });
    let provider = activate_provider(
        home,
        resolved.provider,
        credential_import,
        true,
        options.skip_connectivity_test,
    )?;
    let home = absolute_service_path(home)?;
    let next_command = format!(
        "mealyctl --home {} chat",
        setup_shell_argument(&home.display().to_string())
    );

    if options.configure_only {
        writeln!(
            prompt,
            "\nProvider configuration is active. Service installation was intentionally skipped."
        )?;
        return print_json(OnboardResponse {
            provider,
            service: None,
            service_started: false,
            health_verified: false,
            doctor: None,
            next_command: format!(
                "mealyctl --home {} service install",
                setup_shell_argument(&home.display().to_string())
            ),
        });
    }

    let service = install_service_definition(&home, None, None).map_err(|error| {
        CliError::OnboardService(format!("service installation failed: {error}"))
    })?;
    activate_owner_service()
        .map_err(|error| CliError::OnboardService(format!("service activation failed: {error}")))?;
    let doctor = wait_for_onboard_readiness(&home).await.map_err(|error| {
        CliError::OnboardService(format!(
            "service started but did not pass bounded health and doctor verification: {error}"
        ))
    })?;
    writeln!(
        prompt,
        "\nOnboarding complete. The verified owner service is running."
    )?;
    writeln!(prompt, "Start chatting with:\n  {next_command}")?;
    print_json(OnboardResponse {
        provider,
        service: Some(service),
        service_started: true,
        health_verified: true,
        doctor: Some(doctor),
        next_command,
    })
}

fn validate_onboard_home_target(home: &Path, reconfigure: bool) -> Result<(), CliError> {
    let requested = absolute_service_path(home)?;
    let config = requested.join("config.json");
    match fs::symlink_metadata(&config) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(CliError::InvalidProviderConfiguration)
        }
        Ok(_) if !reconfigure => Err(CliError::OnboardExistingHome),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CliError::Io(error)),
    }
}

fn resolve_onboard(
    options: &OnboardOptions,
    input: &mut impl BufRead,
    prompt: &mut impl Write,
) -> Result<ResolvedOnboard, CliError> {
    let route = options
        .route
        .map_or_else(|| prompt_onboard_route(input, prompt), Ok)?;
    if route.uses_subscription_client() {
        return resolve_subscription_onboard(route, options, input, prompt);
    }
    resolve_http_onboard(route, options, input, prompt)
}

fn prompt_onboard_route(
    input: &mut impl BufRead,
    prompt: &mut impl Write,
) -> Result<OnboardRouteArgument, CliError> {
    writeln!(prompt, "How should Mealy access a model?")?;
    writeln!(
        prompt,
        "  1. OpenRouter free model (recommended without paid API credit)"
    )?;
    writeln!(
        prompt,
        "  2. Custom authenticated OpenAI-compatible endpoint"
    )?;
    writeln!(
        prompt,
        "  3. Local credentialless OpenAI-compatible endpoint"
    )?;
    writeln!(
        prompt,
        "  4. ChatGPT subscription through official Codex CLI"
    )?;
    writeln!(
        prompt,
        "  5. Claude subscription through official Claude Code"
    )?;
    writeln!(prompt, "  6. OpenAI API")?;
    writeln!(prompt, "  7. Anthropic API")?;
    match prompt_line(input, prompt, "Route [1-7]: ")?
        .to_ascii_lowercase()
        .as_str()
    {
        "1" | "openrouter" | "openrouter-free" => Ok(OnboardRouteArgument::OpenrouterFree),
        "2" | "custom" => Ok(OnboardRouteArgument::Custom),
        "3" | "local" => Ok(OnboardRouteArgument::Local),
        "4" | "chatgpt" | "chatgpt-subscription" => Ok(OnboardRouteArgument::ChatgptSubscription),
        "5" | "claude" | "claude-subscription" => Ok(OnboardRouteArgument::ClaudeSubscription),
        "6" | "openai" | "openai-api" => Ok(OnboardRouteArgument::OpenaiApi),
        "7" | "anthropic" | "anthropic-api" => Ok(OnboardRouteArgument::AnthropicApi),
        _ => Err(CliError::InvalidSetupInput),
    }
}

#[allow(clippy::too_many_lines)]
fn resolve_http_onboard(
    route: OnboardRouteArgument,
    options: &OnboardOptions,
    input: &mut impl BufRead,
    prompt: &mut impl Write,
) -> Result<ResolvedOnboard, CliError> {
    if options.executable_path.is_some() {
        return Err(CliError::InvalidSetupInput);
    }
    let base_url = options.base_url.clone().map_or_else(
        || match route.default_base_url() {
            Some(default) => Ok(default.to_owned()),
            None => prompt_line(input, prompt, "OpenAI-compatible HTTPS API base URL: "),
        },
        Ok,
    )?;
    let credential_env = route.default_credential_environment().map(|default| {
        options
            .credential_env
            .clone()
            .unwrap_or_else(|| default.to_owned())
    });
    if credential_env
        .as_deref()
        .is_some_and(|name| !valid_provider_credential_environment_name(name))
    {
        return Err(CliError::InvalidSetupInput);
    }
    if matches!(route, OnboardRouteArgument::Local)
        && (options.credential_env.is_some()
            || options
                .input_microunits_per_million_tokens
                .is_some_and(|value| value != 0)
            || options
                .output_microunits_per_million_tokens
                .is_some_and(|value| value != 0))
    {
        return Err(CliError::InvalidSetupInput);
    }
    let local_endpoint =
        validate_provider_base_url(&base_url).map_err(|_| CliError::InvalidSetupInput)?;
    if matches!(route, OnboardRouteArgument::Local) && !local_endpoint {
        return Err(CliError::InvalidSetupInput);
    }

    let discovered = discover_onboard_models(
        route,
        &base_url,
        credential_env.as_deref(),
        options.model.as_deref(),
    )?;
    let selected =
        select_onboard_model(route, discovered, options.model.as_deref(), input, prompt)?;
    let model = selected
        .as_ref()
        .map(|item| item.id.clone())
        .or_else(|| options.model.clone())
        .map_or_else(|| prompt_line(input, prompt, "Exact model ID: "), Ok)?;
    let context_tokens = resolve_onboard_context(
        options.context_tokens,
        selected.as_ref().and_then(|item| item.context_tokens),
        input,
        prompt,
    )?;
    let maximum_output_tokens = selected
        .as_ref()
        .and_then(|item| item.maximum_output_tokens)
        .map_or(options.maximum_output_tokens, |advertised| {
            advertised.min(options.maximum_output_tokens)
        });

    let (input_price, output_price) = if matches!(route, OnboardRouteArgument::OpenrouterFree) {
        if options
            .input_microunits_per_million_tokens
            .is_some_and(|value| value != 0)
            || options
                .output_microunits_per_million_tokens
                .is_some_and(|value| value != 0)
        {
            return Err(CliError::InvalidSetupInput);
        }
        (0, 0)
    } else if matches!(route, OnboardRouteArgument::Local) {
        (0, 0)
    } else {
        (
            options.input_microunits_per_million_tokens.map_or_else(
                || {
                    prompt_u64(
                        input,
                        prompt,
                        "Input price in currency microunits per million tokens (zero only for a verified free route): ",
                        true,
                    )
                },
                Ok,
            )?,
            options.output_microunits_per_million_tokens.map_or_else(
                || {
                    prompt_u64(
                        input,
                        prompt,
                        "Output price in currency microunits per million tokens (zero only for a verified free route): ",
                        true,
                    )
                },
                Ok,
            )?,
        )
    };

    let common = (
        base_url,
        model,
        context_tokens,
        maximum_output_tokens,
        !options.disable_streaming,
        input_price,
        output_price,
    );
    let (provider, secret_id) = match route {
        OnboardRouteArgument::AnthropicApi => (
            ProviderConfig::AnthropicMessages {
                provider_id: "anthropic.messages".to_owned(),
                base_url: common.0,
                model: common.1,
                credential: Some(ProviderCredentialReference::Broker {
                    secret_id: "anthropic-primary".to_owned(),
                }),
                residency: "anthropic-api".to_owned(),
                context_tokens: common.2,
                maximum_output_tokens: common.3,
                streaming: common.4,
                input_microunits_per_million_tokens: common.5,
                output_microunits_per_million_tokens: common.6,
                estimated_latency_ms: SETUP_PROVIDER_ESTIMATED_LATENCY_MS,
            },
            Some("anthropic-primary".to_owned()),
        ),
        OnboardRouteArgument::Local => (
            ProviderConfig::OpenAiResponses {
                provider_id: "local.responses".to_owned(),
                base_url: common.0,
                model: common.1,
                credential: None,
                residency: "local".to_owned(),
                context_tokens: common.2,
                maximum_output_tokens: common.3,
                streaming: common.4,
                input_microunits_per_million_tokens: 0,
                output_microunits_per_million_tokens: 0,
                estimated_latency_ms: SETUP_PROVIDER_ESTIMATED_LATENCY_MS,
            },
            None,
        ),
        OnboardRouteArgument::OpenrouterFree
        | OnboardRouteArgument::Custom
        | OnboardRouteArgument::OpenaiApi => {
            let (provider_id, secret_id, residency) = match route {
                OnboardRouteArgument::OpenrouterFree => (
                    "openrouter.responses",
                    "openrouter-primary",
                    "openrouter-api",
                ),
                OnboardRouteArgument::Custom => {
                    ("custom.responses", "custom-primary", "custom-api")
                }
                OnboardRouteArgument::OpenaiApi => {
                    ("openai.responses", "openai-primary", "openai-api")
                }
                _ => unreachable!("covered Responses route"),
            };
            (
                ProviderConfig::OpenAiResponses {
                    provider_id: provider_id.to_owned(),
                    base_url: common.0,
                    model: common.1,
                    credential: Some(ProviderCredentialReference::Broker {
                        secret_id: secret_id.to_owned(),
                    }),
                    residency: residency.to_owned(),
                    context_tokens: common.2,
                    maximum_output_tokens: common.3,
                    streaming: common.4,
                    input_microunits_per_million_tokens: common.5,
                    output_microunits_per_million_tokens: common.6,
                    estimated_latency_ms: SETUP_PROVIDER_ESTIMATED_LATENCY_MS,
                },
                Some(secret_id.to_owned()),
            )
        }
        OnboardRouteArgument::ChatgptSubscription | OnboardRouteArgument::ClaudeSubscription => {
            unreachable!("subscription routes were resolved separately")
        }
    };
    provider
        .validate()
        .map_err(|_| CliError::InvalidSetupInput)?;
    Ok(ResolvedOnboard {
        route,
        provider,
        secret_id,
        credential_env,
    })
}

fn discover_onboard_models(
    route: OnboardRouteArgument,
    base_url: &str,
    credential_env: Option<&str>,
    requested_model: Option<&str>,
) -> Result<Option<Vec<ProviderModelDiscoveryItem>>, CliError> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                discover_onboard_models_blocking(route, base_url, credential_env, requested_model)
            })
            .join()
            .map_err(|_| {
                CliError::ProviderDiscovery("onboarding model-discovery worker failed".to_owned())
            })?
    })
}

fn discover_onboard_models_blocking(
    route: OnboardRouteArgument,
    base_url: &str,
    credential_env: Option<&str>,
    requested_model: Option<&str>,
) -> Result<Option<Vec<ProviderModelDiscoveryItem>>, CliError> {
    let discover = match route {
        OnboardRouteArgument::OpenrouterFree => {
            let environment = credential_env.ok_or(CliError::InvalidSetupInput)?;
            let credential = read_provider_credential_environment(environment)?;
            let result = discover_openrouter_models_blocking(
                base_url,
                credential.as_str(),
                None,
                PROVIDER_DISCOVERY_MAXIMUM_MODELS,
            )?;
            drop(credential);
            Some(
                result
                    .models
                    .into_iter()
                    .filter(openrouter_model_is_strictly_free)
                    .collect::<Vec<_>>(),
            )
        }
        OnboardRouteArgument::Custom | OnboardRouteArgument::OpenaiApi
            if requested_model.is_none() =>
        {
            let environment = credential_env.ok_or(CliError::InvalidSetupInput)?;
            let credential = read_provider_credential_environment(environment)?;
            let result = discover_openai_models_blocking(
                base_url,
                Some(credential.as_str()),
                None,
                100,
                false,
            )?;
            drop(credential);
            Some(result.models)
        }
        OnboardRouteArgument::Local if requested_model.is_none() => {
            Some(discover_openai_models_blocking(base_url, None, None, 100, true)?.models)
        }
        OnboardRouteArgument::AnthropicApi if requested_model.is_none() => {
            let environment = credential_env.ok_or(CliError::InvalidSetupInput)?;
            let credential = read_provider_credential_environment(environment)?;
            let result =
                discover_anthropic_models_blocking(base_url, credential.as_str(), None, 100, None)?;
            drop(credential);
            Some(result.models)
        }
        OnboardRouteArgument::Custom
        | OnboardRouteArgument::Local
        | OnboardRouteArgument::OpenaiApi
        | OnboardRouteArgument::AnthropicApi => None,
        OnboardRouteArgument::ChatgptSubscription | OnboardRouteArgument::ClaudeSubscription => {
            None
        }
    };
    Ok(discover)
}

fn openrouter_model_is_strictly_free(model: &ProviderModelDiscoveryItem) -> bool {
    model.id.ends_with(":free")
        && model.tool_capable == Some(true)
        && model.token_limits_complete
        && model.context_tokens.is_some_and(|value| value > 0)
        && model.maximum_output_tokens.is_some_and(|value| value > 0)
        && model.pricing_complete
        && model.input_microunits_per_million_tokens == Some(0)
        && model.output_microunits_per_million_tokens == Some(0)
        && model.unsupported_pricing_axes.is_empty()
}

fn select_onboard_model(
    route: OnboardRouteArgument,
    discovered: Option<Vec<ProviderModelDiscoveryItem>>,
    requested: Option<&str>,
    input: &mut impl BufRead,
    prompt: &mut impl Write,
) -> Result<Option<ProviderModelDiscoveryItem>, CliError> {
    let Some(mut models) = discovered else {
        return Ok(None);
    };
    models.sort_by(|left, right| left.id.cmp(&right.id));
    if models.is_empty() {
        return Err(CliError::OnboardNoEligibleModel(route.display_name()));
    }
    if let Some(requested) = requested {
        return models
            .into_iter()
            .find(|model| model.id == requested)
            .map(Some)
            .ok_or(CliError::OnboardNoEligibleModel(route.display_name()));
    }
    writeln!(
        prompt,
        "Eligible models (live account catalog; exact zero posted token price):"
    )?;
    for (index, model) in models.iter().take(20).enumerate() {
        match (model.context_tokens, model.maximum_output_tokens) {
            (Some(context), Some(output)) => writeln!(
                prompt,
                "  {}. {} (context {context}, output {output})",
                index + 1,
                model.id
            )?,
            _ => writeln!(prompt, "  {}. {}", index + 1, model.id)?,
        }
    }
    let selected = prompt_line(input, prompt, "Model number: ")?
        .parse::<usize>()
        .ok()
        .filter(|index| (1..=models.len().min(20)).contains(index))
        .ok_or(CliError::InvalidSetupInput)?;
    Ok(Some(models.remove(selected - 1)))
}

fn resolve_onboard_context(
    requested: Option<u64>,
    advertised: Option<u64>,
    input: &mut impl BufRead,
    prompt: &mut impl Write,
) -> Result<u64, CliError> {
    match (requested, advertised) {
        (Some(requested), Some(advertised)) if requested == 0 || requested > advertised => {
            Err(CliError::InvalidSetupInput)
        }
        (Some(requested), _) if requested > 0 => Ok(requested),
        (None, Some(advertised)) if advertised > 0 => Ok(advertised),
        (None, _) => prompt_u64(input, prompt, "Conservative context-token limit: ", false),
        _ => Err(CliError::InvalidSetupInput),
    }
}

fn resolve_subscription_onboard(
    route: OnboardRouteArgument,
    options: &OnboardOptions,
    input: &mut impl BufRead,
    prompt: &mut impl Write,
) -> Result<ResolvedOnboard, CliError> {
    if options.base_url.is_some()
        || options.credential_env.is_some()
        || options.input_microunits_per_million_tokens.is_some()
        || options.output_microunits_per_million_tokens.is_some()
        || options.disable_streaming
    {
        return Err(CliError::InvalidSetupInput);
    }
    let model = options.model.clone().map_or_else(
        || prompt_line(input, prompt, "Exact subscription model ID: "),
        Ok,
    )?;
    let context_tokens = options.context_tokens.map_or_else(
        || prompt_u64(input, prompt, "Conservative context-token limit: ", false),
        Ok,
    )?;
    let (client, executable_name, provider_id, residency) = match route {
        OnboardRouteArgument::ChatgptSubscription => (
            SubscriptionCliClient::OpenAiCodex,
            "codex",
            "openai.subscription",
            "openai-subscription",
        ),
        OnboardRouteArgument::ClaudeSubscription => (
            SubscriptionCliClient::AnthropicClaude,
            "claude",
            "claude.subscription",
            "claude-subscription",
        ),
        _ => return Err(CliError::InvalidSetupInput),
    };
    let selected = options
        .executable_path
        .clone()
        .or_else(|| find_executable_on_path(executable_name))
        .ok_or(CliError::InvalidProviderConfiguration)?;
    let (canonical, executable_sha256) = inspect_subscription_cli_executable(&selected)
        .map_err(|_| CliError::InvalidProviderConfiguration)?;
    let canonical = canonical
        .to_str()
        .ok_or(CliError::InvalidProviderConfiguration)?;
    let provider = ProviderConfig::SubscriptionCli {
        provider_id: provider_id.to_owned(),
        client,
        executable_path: canonical.to_owned(),
        executable_sha256,
        model,
        residency: residency.to_owned(),
        context_tokens,
        maximum_output_tokens: options.maximum_output_tokens,
        estimated_latency_ms: 60_000,
    };
    provider
        .validate()
        .map_err(|_| CliError::InvalidSetupInput)?;
    Ok(ResolvedOnboard {
        route,
        provider,
        secret_id: None,
        credential_env: None,
    })
}

fn render_onboard_summary(
    resolved: &ResolvedOnboard,
    options: &OnboardOptions,
    prompt: &mut impl Write,
) -> Result<(), CliError> {
    let provider_json = serde_json::to_value(&resolved.provider)?;
    let provider_id = provider_json
        .get("providerId")
        .and_then(Value::as_str)
        .ok_or(CliError::InvalidSetupInput)?;
    let model = provider_json
        .get("model")
        .and_then(Value::as_str)
        .ok_or(CliError::InvalidSetupInput)?;
    writeln!(prompt, "\nReview the exact non-secret onboarding plan:")?;
    writeln!(prompt, "  route: {}", resolved.route.display_name())?;
    writeln!(prompt, "  provider ID: {provider_id}")?;
    writeln!(prompt, "  model: {model}")?;
    if let Some(base_url) = provider_json.get("baseUrl").and_then(Value::as_str) {
        writeln!(prompt, "  API base: {base_url}")?;
    }
    let context_tokens = provider_json
        .get("contextTokens")
        .and_then(Value::as_u64)
        .ok_or(CliError::InvalidSetupInput)?;
    let maximum_output_tokens = provider_json
        .get("maximumOutputTokens")
        .and_then(Value::as_u64)
        .ok_or(CliError::InvalidSetupInput)?;
    writeln!(
        prompt,
        "  context/output tokens: {context_tokens}/{maximum_output_tokens}"
    )?;
    if let (Some(input_price), Some(output_price)) = (
        provider_json
            .get("inputMicrounitsPerMillionTokens")
            .and_then(Value::as_u64),
        provider_json
            .get("outputMicrounitsPerMillionTokens")
            .and_then(Value::as_u64),
    ) {
        writeln!(
            prompt,
            "  input/output price microunits per million tokens: {input_price}/{output_price}"
        )?;
    }
    if let Some(streaming) = provider_json.get("streaming").and_then(Value::as_bool) {
        writeln!(prompt, "  streaming: {streaming}")?;
    }
    writeln!(
        prompt,
        "  provider config digest preview: {}",
        sha256_digest(&serde_json::to_vec(&resolved.provider)?)
    )?;
    writeln!(
        prompt,
        "  connectivity probe: {}",
        if options.skip_connectivity_test {
            "SKIPPED (configuration is not production-verified)"
        } else {
            "required before activation"
        }
    )?;
    if let Some(environment) = &resolved.credential_env {
        writeln!(
            prompt,
            "  credential source: environment variable {environment} (the value is never printed or stored in config)"
        )?;
    } else if resolved.route.uses_subscription_client() {
        writeln!(
            prompt,
            "  credential source: existing official client subscription session (no token extraction)"
        )?;
    } else {
        writeln!(prompt, "  credential source: none (literal loopback only)")?;
    }
    writeln!(
        prompt,
        "  service action: {}",
        if options.configure_only {
            "do not install or start a service"
        } else {
            "install, enable, start, and verify the Linux owner service"
        }
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn activate_owner_service() -> Result<(), CliError> {
    let systemctl = Path::new("/usr/bin/systemctl");
    if !systemctl.is_file() || !is_trusted_system_executable(systemctl) {
        return Err(CliError::InvalidService(
            "onboarding requires trusted /usr/bin/systemctl".to_owned(),
        ));
    }
    for arguments in [
        ["--user", "daemon-reload"].as_slice(),
        ["--user", "enable", "--now", "mealy.service"].as_slice(),
    ] {
        let output = ProcessCommand::new(systemctl).args(arguments).output()?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);
            return Err(CliError::InvalidService(format!(
                "systemctl {} failed: {}",
                arguments.join(" "),
                terminal_safe_single_line(detail.trim())
            )));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn activate_owner_service() -> Result<(), CliError> {
    Err(CliError::UnsupportedPlatform(
        "production onboarding service activation is supported only on Linux".to_owned(),
    ))
}

async fn wait_for_onboard_readiness(home: &Path) -> Result<DoctorResponse, CliError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(connection) = load_connection(home) {
            let client = Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(2))
                .build()?;
            if let Ok(response) = authorized(
                client.get(format!("{}/health/live", connection.base_url)),
                &connection,
            )
            .send()
            .await
                && let Ok(health) = decode::<HealthResponse>(response).await
                && health.api_version == API_VERSION
                && health.live
                && let Ok(response) = authorized(
                    client.get(format!("{}/v1/admin/doctor", connection.base_url)),
                    &connection,
                )
                .send()
                .await
                && let Ok(doctor) = decode::<DoctorResponse>(response).await
                && doctor.api_version == API_VERSION
                && doctor.control_plane_ready
                && doctor.sandbox_available
            {
                return Ok(doctor);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(CliError::InvalidService(
                "timed out after 30 seconds".to_owned(),
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

impl SetupProviderArgument {
    const fn display_name(self) -> &'static str {
        match self {
            Self::Openai => "OpenAI Responses",
            Self::Anthropic => "Anthropic Messages",
            Self::Openrouter => "OpenRouter Responses beta",
            Self::Local => "local Responses-compatible",
        }
    }

    const fn default_base_url(self) -> &'static str {
        match self {
            Self::Openai => "https://api.openai.com/v1",
            Self::Anthropic => "https://api.anthropic.com/v1",
            Self::Openrouter => "https://openrouter.ai/api/v1",
            Self::Local => "http://127.0.0.1:11434/v1",
        }
    }

    const fn default_credential_environment(self) -> Option<&'static str> {
        match self {
            Self::Openai => Some("OPENAI_API_KEY"),
            Self::Anthropic => Some("ANTHROPIC_API_KEY"),
            Self::Openrouter => Some("OPENROUTER_API_KEY"),
            Self::Local => None,
        }
    }

    const fn is_remote(self) -> bool {
        !matches!(self, Self::Local)
    }
}

fn run_setup(home: &Path, options: &SetupOptions) -> Result<(), CliError> {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stderr = std::io::stderr();
    let mut prompt = stderr.lock();
    let setup = resolve_setup(options, &mut input, &mut prompt)?;
    let (provider, secret_id) = setup_provider_config(&setup);
    provider
        .validate()
        .map_err(|_| CliError::InvalidSetupInput)?;
    render_setup_summary(&setup, &provider, &mut prompt)?;
    if !options.approve
        && prompt_line(
            &mut input,
            &mut prompt,
            "Type APPROVE to activate this exact provider configuration: ",
        )? != "APPROVE"
    {
        return Err(CliError::SetupNotApproved);
    }
    initialize_setup_home(home)?;
    let credential_import = secret_id
        .as_deref()
        .zip(setup.credential_env.as_deref())
        .map(|(secret_id, credential_env)| ProviderCredentialImport {
            secret_id,
            credential_env,
        });
    configure_provider(
        home,
        provider,
        credential_import,
        true,
        setup.skip_connectivity_test,
    )?;
    render_setup_handoff(home, &mut prompt)
}

fn resolve_setup(
    options: &SetupOptions,
    input: &mut impl BufRead,
    prompt: &mut impl Write,
) -> Result<ResolvedSetup, CliError> {
    let provider = options
        .provider
        .map_or_else(|| prompt_setup_provider(input, prompt), Ok)?;
    let model = options
        .model
        .clone()
        .map_or_else(|| prompt_line(input, prompt, "Exact model ID: "), Ok)?;
    let context_tokens = options.context_tokens.map_or_else(
        || prompt_u64(input, prompt, "Conservative context-token limit: ", false),
        Ok,
    )?;
    let (input_price, output_price) = if provider.is_remote() {
        (
            options.input_microunits_per_million_tokens.map_or_else(
                || {
                    prompt_u64(
                        input,
                        prompt,
                        "Input price in currency microunits per million tokens (USD $1 = 1000000): ",
                        true,
                    )
                },
                Ok,
            )?,
            options.output_microunits_per_million_tokens.map_or_else(
                || {
                    prompt_u64(
                        input,
                        prompt,
                        "Output price in currency microunits per million tokens (USD $1 = 1000000): ",
                        true,
                    )
                },
                Ok,
            )?,
        )
    } else {
        if options.credential_env.is_some()
            || options
                .input_microunits_per_million_tokens
                .is_some_and(|value| value != 0)
            || options
                .output_microunits_per_million_tokens
                .is_some_and(|value| value != 0)
        {
            return Err(CliError::InvalidSetupInput);
        }
        (0, 0)
    };
    let credential_env = provider.default_credential_environment().map(|default| {
        options
            .credential_env
            .clone()
            .unwrap_or_else(|| default.to_owned())
    });
    if credential_env
        .as_deref()
        .is_some_and(|name| !valid_provider_credential_environment_name(name))
    {
        return Err(CliError::InvalidSetupInput);
    }
    Ok(ResolvedSetup {
        provider,
        base_url: options
            .base_url
            .clone()
            .unwrap_or_else(|| provider.default_base_url().to_owned()),
        model,
        context_tokens,
        maximum_output_tokens: options.maximum_output_tokens,
        credential_env,
        input_microunits_per_million_tokens: input_price,
        output_microunits_per_million_tokens: output_price,
        streaming: !options.disable_streaming,
        skip_connectivity_test: options.skip_connectivity_test,
    })
}

fn prompt_setup_provider(
    input: &mut impl BufRead,
    prompt: &mut impl Write,
) -> Result<SetupProviderArgument, CliError> {
    writeln!(prompt, "Select a provider:")?;
    writeln!(prompt, "  1. OpenAI Responses")?;
    writeln!(prompt, "  2. Anthropic Messages")?;
    writeln!(prompt, "  3. OpenRouter Responses beta")?;
    writeln!(prompt, "  4. Local Responses-compatible (no credential)")?;
    match prompt_line(input, prompt, "Provider [1-4]: ")?
        .to_ascii_lowercase()
        .as_str()
    {
        "1" | "openai" => Ok(SetupProviderArgument::Openai),
        "2" | "anthropic" => Ok(SetupProviderArgument::Anthropic),
        "3" | "openrouter" => Ok(SetupProviderArgument::Openrouter),
        "4" | "local" => Ok(SetupProviderArgument::Local),
        _ => Err(CliError::InvalidSetupInput),
    }
}

fn prompt_line(
    input: &mut impl BufRead,
    prompt: &mut impl Write,
    label: &str,
) -> Result<String, CliError> {
    write!(prompt, "{label}")?;
    prompt.flush()?;
    let mut line = String::new();
    let bytes = input.read_line(&mut line)?;
    let value = line.trim();
    if bytes == 0 || value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control)
    {
        return Err(CliError::InvalidSetupInput);
    }
    Ok(value.to_owned())
}

fn prompt_u64(
    input: &mut impl BufRead,
    prompt: &mut impl Write,
    label: &str,
    zero_allowed: bool,
) -> Result<u64, CliError> {
    let value = prompt_line(input, prompt, label)?;
    value
        .parse::<u64>()
        .ok()
        .filter(|value| zero_allowed || *value > 0)
        .ok_or(CliError::InvalidSetupInput)
}

fn setup_provider_config(setup: &ResolvedSetup) -> (ProviderConfig, Option<String>) {
    let common = (
        setup.base_url.clone(),
        setup.model.clone(),
        setup.context_tokens,
        setup.maximum_output_tokens,
        setup.streaming,
        setup.input_microunits_per_million_tokens,
        setup.output_microunits_per_million_tokens,
    );
    match setup.provider {
        SetupProviderArgument::Openai => (
            ProviderConfig::OpenAiResponses {
                provider_id: "openai.responses".to_owned(),
                base_url: common.0,
                model: common.1,
                credential: Some(ProviderCredentialReference::Broker {
                    secret_id: "openai-primary".to_owned(),
                }),
                residency: "openai-api".to_owned(),
                context_tokens: common.2,
                maximum_output_tokens: common.3,
                streaming: common.4,
                input_microunits_per_million_tokens: common.5,
                output_microunits_per_million_tokens: common.6,
                estimated_latency_ms: SETUP_PROVIDER_ESTIMATED_LATENCY_MS,
            },
            Some("openai-primary".to_owned()),
        ),
        SetupProviderArgument::Anthropic => (
            ProviderConfig::AnthropicMessages {
                provider_id: "anthropic.messages".to_owned(),
                base_url: common.0,
                model: common.1,
                credential: Some(ProviderCredentialReference::Broker {
                    secret_id: "anthropic-primary".to_owned(),
                }),
                residency: "anthropic-api".to_owned(),
                context_tokens: common.2,
                maximum_output_tokens: common.3,
                streaming: common.4,
                input_microunits_per_million_tokens: common.5,
                output_microunits_per_million_tokens: common.6,
                estimated_latency_ms: SETUP_PROVIDER_ESTIMATED_LATENCY_MS,
            },
            Some("anthropic-primary".to_owned()),
        ),
        SetupProviderArgument::Openrouter => (
            ProviderConfig::OpenAiResponses {
                provider_id: "openrouter.responses".to_owned(),
                base_url: common.0,
                model: common.1,
                credential: Some(ProviderCredentialReference::Broker {
                    secret_id: "openrouter-primary".to_owned(),
                }),
                residency: "openrouter-api".to_owned(),
                context_tokens: common.2,
                maximum_output_tokens: common.3,
                streaming: common.4,
                input_microunits_per_million_tokens: common.5,
                output_microunits_per_million_tokens: common.6,
                estimated_latency_ms: SETUP_PROVIDER_ESTIMATED_LATENCY_MS,
            },
            Some("openrouter-primary".to_owned()),
        ),
        SetupProviderArgument::Local => (
            ProviderConfig::OpenAiResponses {
                provider_id: "local.responses".to_owned(),
                base_url: common.0,
                model: common.1,
                credential: None,
                residency: "local".to_owned(),
                context_tokens: common.2,
                maximum_output_tokens: common.3,
                streaming: common.4,
                input_microunits_per_million_tokens: 0,
                output_microunits_per_million_tokens: 0,
                estimated_latency_ms: SETUP_PROVIDER_ESTIMATED_LATENCY_MS,
            },
            None,
        ),
    }
}

fn render_setup_summary(
    setup: &ResolvedSetup,
    provider: &ProviderConfig,
    prompt: &mut impl Write,
) -> Result<(), CliError> {
    writeln!(prompt, "\nReview the exact non-secret setup:")?;
    writeln!(prompt, "  provider: {}", setup.provider.display_name())?;
    writeln!(prompt, "  API base: {}", setup.base_url)?;
    writeln!(prompt, "  model: {}", setup.model)?;
    writeln!(
        prompt,
        "  context/output tokens: {}/{}",
        setup.context_tokens, setup.maximum_output_tokens
    )?;
    if setup.provider.is_remote() {
        writeln!(
            prompt,
            "  input/output price microunits per million tokens: {}/{}",
            setup.input_microunits_per_million_tokens, setup.output_microunits_per_million_tokens
        )?;
        if setup.input_microunits_per_million_tokens == 0
            || setup.output_microunits_per_million_tokens == 0
        {
            writeln!(
                prompt,
                "  WARNING: a zero price weakens that cost axis; approve it only for a verified free route"
            )?;
        }
    }
    writeln!(prompt, "  streaming: {}", setup.streaming)?;
    writeln!(
        prompt,
        "  connectivity probe: {}",
        if setup.skip_connectivity_test {
            "SKIPPED (staged, not production-verified)"
        } else {
            "required before activation"
        }
    )?;
    if let Some(environment) = &setup.credential_env {
        writeln!(
            prompt,
            "  credential source: environment variable {environment} (value is never printed or stored in config)"
        )?;
    } else {
        writeln!(prompt, "  credential source: none (literal-loopback only)")?;
    }
    writeln!(
        prompt,
        "  provider config digest preview: {}",
        sha256_digest(&serde_json::to_vec(provider)?)
    )?;
    Ok(())
}

fn initialize_setup_home(home: &Path) -> Result<(), CliError> {
    let requested = absolute_service_path(home)?;
    create_private_service_directory(&requested)?;
    let (home, _instance_lock) = lock_stopped_home(&requested)?;
    let config_path = home.join("config.json");
    match fs::symlink_metadata(&config_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(CliError::InvalidProviderConfiguration);
            }
            let value: Value = serde_json::from_slice(&fs::read(&config_path)?)?;
            let object = value
                .as_object()
                .ok_or(CliError::InvalidProviderConfiguration)?;
            if !valid_daemon_config_keys(object)
                || object.get("formatVersion").and_then(Value::as_u64) != Some(1)
            {
                return Err(CliError::InvalidProviderConfiguration);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            atomic_write_service(
                &config_path,
                &serde_json::to_vec_pretty(&default_daemon_config_document())?,
            )?;
        }
        Err(error) => return Err(CliError::Io(error)),
    }
    create_private_service_directory(&home.join("config-history"))
}

fn render_setup_handoff(home: &Path, prompt: &mut impl Write) -> Result<(), CliError> {
    let home = absolute_service_path(home)?;
    let home = setup_shell_argument(&home.display().to_string());
    writeln!(prompt, "\nSetup complete. In terminal 1 start the daemon:")?;
    writeln!(prompt, "  mealyd --home {home}")?;
    writeln!(prompt, "Then in terminal 2 verify and chat:")?;
    writeln!(prompt, "  mealyctl --home {home} doctor")?;
    writeln!(prompt, "  mealyctl --home {home} chat")?;
    Ok(())
}

#[cfg(unix)]
fn setup_shell_argument(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(not(unix))]
fn setup_shell_argument(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceInstallationResponse {
    platform: String,
    service_definition: String,
    daemon_path: String,
    home: String,
    read_write_paths: Vec<String>,
    rollback_copy: Option<String>,
    activation_command: String,
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(rename_all = "camelCase")]
struct ServiceRemovalPlan {
    schema_version: &'static str,
    platform: String,
    home: PathBuf,
    service_definition: PathBuf,
    daemon_path: Option<PathBuf>,
    installed: bool,
    definition_verified: bool,
    loaded: bool,
    active: bool,
    action_required: bool,
    apply_supported: bool,
    preserves_home: bool,
    removed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigRollbackResponse {
    activated_digest: String,
    configuration_path: String,
    replaced_configuration_copy: String,
    restart_required: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderConfigurationResponse {
    provider_config_digest: String,
    protocol: String,
    provider_id: String,
    model: String,
    secret_id: Option<String>,
    provider_role: String,
    fallback_ordinal: Option<usize>,
    streaming: bool,
    connectivity_tested: bool,
    configuration_path: String,
    replaced_configuration_copy: String,
    restart_required: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderFallbackRemovalResponse {
    provider_id: String,
    removed_ordinal: usize,
    removed_secret_id: Option<String>,
    credential_retained: bool,
    remaining_provider_ids: Vec<String>,
    configuration_path: String,
    replaced_configuration_copy: String,
    restart_required: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderChainConfigurationResponse {
    primary: ProviderConfig,
    fallbacks: Vec<ProviderConfig>,
    fallback_count: usize,
    credential_values_resolved: bool,
    configuration_path: String,
}

#[derive(Clone, Copy)]
struct ProviderCredentialImport<'a> {
    secret_id: &'a str,
    credential_env: &'a str,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstalledSkillConfigRecord {
    skill_id: String,
    version: String,
    manifest_digest: String,
    package_path: String,
    enabled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SkillPackageResponse {
    operation: String,
    skill_id: String,
    version: String,
    manifest_digest: String,
    installed: bool,
    enabled: bool,
    package_path: Option<String>,
    total_asset_bytes: u64,
    instructions: Vec<SkillAsset>,
    resources: Vec<SkillAsset>,
    required_tools: Vec<SkillToolRequirement>,
    tool_authority: &'static str,
    configuration_path: Option<String>,
    replaced_configuration_copy: Option<String>,
    restart_required: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SkillsResponse {
    skills: Vec<SkillPackageResponse>,
}

#[derive(Debug, Deserialize)]
struct OpenAiModelsEnvelope {
    object: String,
    data: Vec<OpenAiModelWire>,
}

#[derive(Debug, Deserialize)]
struct OpenAiModelWire {
    id: String,
    object: String,
    created: i64,
    owned_by: String,
}

#[derive(Debug, Deserialize)]
struct AnthropicModelsEnvelope {
    data: Vec<AnthropicModelWire>,
    first_id: Option<String>,
    has_more: bool,
    last_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnthropicModelWire {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    created_at: String,
    display_name: String,
    #[serde(default)]
    max_input_tokens: Option<u64>,
    #[serde(default)]
    max_tokens: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct OpenRouterModelsEnvelope {
    data: Vec<OpenRouterModelWire>,
}

#[derive(Debug, Deserialize)]
struct OpenRouterModelWire {
    id: String,
    name: String,
    created: i64,
    context_length: Option<u64>,
    pricing: OpenRouterPricingWire,
    #[serde(default)]
    supported_parameters: Vec<String>,
    architecture: OpenRouterArchitectureWire,
    top_provider: Option<OpenRouterTopProviderWire>,
}

#[derive(Debug, Deserialize)]
struct OpenRouterArchitectureWire {
    #[serde(default)]
    output_modalities: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OpenRouterTopProviderWire {
    context_length: Option<u64>,
    max_completion_tokens: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct OpenRouterPricingWire {
    prompt: String,
    completion: String,
    #[serde(default)]
    request: Option<String>,
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    web_search: Option<String>,
    #[serde(default)]
    internal_reasoning: Option<String>,
    #[serde(default)]
    input_cache_read: Option<String>,
    #[serde(default)]
    input_cache_write: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderModelDiscoveryItem {
    id: String,
    display_name: Option<String>,
    created_at: Option<String>,
    created_at_unix_seconds: Option<u64>,
    owned_by: Option<String>,
    context_tokens: Option<u64>,
    maximum_output_tokens: Option<u64>,
    token_limits_complete: bool,
    input_microunits_per_million_tokens: Option<u64>,
    output_microunits_per_million_tokens: Option<u64>,
    pricing_complete: bool,
    unsupported_pricing_axes: Vec<String>,
    tool_capable: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderModelDiscoveryResponse {
    protocol: String,
    endpoint: String,
    retrieved_at_ms: u128,
    filter: Option<String>,
    requested_limit: usize,
    returned_count: usize,
    provider_has_more: Option<bool>,
    next_after_id: Option<String>,
    locally_truncated: bool,
    pricing_included: bool,
    models: Vec<ProviderModelDiscoveryItem>,
    metadata_notice: &'static str,
    official_models_url: &'static str,
    official_pricing_url: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderSecretRevocationResponse {
    secret_id: String,
    removed: bool,
    active_reference_check: String,
    configuration_history_may_reference: bool,
    service_action: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceConfigurationResponse {
    workspace_id: String,
    canonical_root: Option<String>,
    operation: String,
    configuration_path: String,
    replaced_configuration_copy: String,
    restart_required: bool,
    service_reinstall_required: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessConfigurationResponse {
    command_id: String,
    executable_digest: Option<String>,
    operation: String,
    configuration_path: String,
    replaced_configuration_copy: String,
    restart_required: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
struct WebConfigurationResponse {
    operation: String,
    allow_public_internet: bool,
    allowed_domains: Vec<String>,
    allowed_origins: Vec<String>,
    search_enabled: bool,
    secret_id: Option<String>,
    configuration_path: String,
    replaced_configuration_copy: String,
    restart_required: bool,
    credential_retained_on_disable: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserInspectionResponse {
    bundle_digest: String,
    executable_digest: String,
    product: String,
    protocol_version: String,
    isolation: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserConfigurationResponse {
    operation: String,
    browser: Option<BrowserConfig>,
    runtime_retained_for_rollback: bool,
    configuration_path: String,
    replaced_configuration_copy: String,
    restart_required: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserStatusResponse {
    browser: Option<BrowserConfig>,
    activation_note: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpInspectionResponse {
    server_id: String,
    executable_digest: String,
    arguments: Vec<String>,
    isolation: &'static str,
    discovery: McpServerDiscovery,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpServersConfigurationResponse {
    servers: Vec<McpServerConfig>,
    activation_note: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpConfigurationResponse {
    server_id: String,
    operation: String,
    enabled: bool,
    exposed_tool_ids: Vec<String>,
    executable_digest: String,
    toolset_digest: String,
    executable_retained_for_rollback: bool,
    configuration_path: String,
    replaced_configuration_copy: String,
    restart_required: bool,
}

#[allow(clippy::too_many_lines)]
fn run_config_operation(home: &Path, command: &ConfigCommand) -> Result<(), CliError> {
    match command {
        ConfigCommand::ProviderList => list_provider_chain(home),
        ConfigCommand::ProviderModels {
            base_url,
            credential_env,
            contains,
            limit,
        } => discover_openai_models(base_url, credential_env, contains.as_deref(), *limit),
        ConfigCommand::ProviderModelsAnthropic {
            base_url,
            credential_env,
            contains,
            limit,
            after_id,
        } => discover_anthropic_models(
            base_url,
            credential_env,
            contains.as_deref(),
            *limit,
            after_id.as_deref(),
        ),
        ConfigCommand::ProviderModelsOpenrouter {
            base_url,
            credential_env,
            contains,
            limit,
        } => discover_openrouter_models(base_url, credential_env, contains.as_deref(), *limit),
        ConfigCommand::ProviderModelsLocal {
            base_url,
            contains,
            limit,
        } => discover_local_models(base_url, contains.as_deref(), *limit),
        ConfigCommand::ProviderLocal {
            provider_id,
            base_url,
            model,
            context_tokens,
            maximum_output_tokens,
            disable_streaming,
            skip_connectivity_test,
            estimated_latency_ms,
            approve,
        } => configure_provider(
            home,
            ProviderConfig::OpenAiResponses {
                provider_id: provider_id.clone(),
                base_url: base_url.clone(),
                model: model.clone(),
                credential: None,
                residency: "local".to_owned(),
                context_tokens: *context_tokens,
                maximum_output_tokens: *maximum_output_tokens,
                streaming: !disable_streaming,
                input_microunits_per_million_tokens: 0,
                output_microunits_per_million_tokens: 0,
                estimated_latency_ms: *estimated_latency_ms,
            },
            None,
            *approve,
            *skip_connectivity_test,
        ),
        ConfigCommand::ProviderSubscriptionOpenai {
            provider_id,
            executable_path,
            model,
            residency,
            context_tokens,
            maximum_output_tokens,
            skip_connectivity_test,
            estimated_latency_ms,
            approve,
        } => configure_subscription_provider(
            home,
            provider_id,
            SubscriptionCliClient::OpenAiCodex,
            executable_path.as_deref(),
            "codex",
            model,
            residency,
            *context_tokens,
            *maximum_output_tokens,
            *estimated_latency_ms,
            *approve,
            *skip_connectivity_test,
        ),
        ConfigCommand::ProviderSubscriptionClaude {
            provider_id,
            executable_path,
            model,
            residency,
            context_tokens,
            maximum_output_tokens,
            skip_connectivity_test,
            estimated_latency_ms,
            approve,
        } => configure_subscription_provider(
            home,
            provider_id,
            SubscriptionCliClient::AnthropicClaude,
            executable_path.as_deref(),
            "claude",
            model,
            residency,
            *context_tokens,
            *maximum_output_tokens,
            *estimated_latency_ms,
            *approve,
            *skip_connectivity_test,
        ),
        ConfigCommand::Provider {
            provider_id,
            base_url,
            model,
            secret_id,
            credential_env,
            residency,
            context_tokens,
            maximum_output_tokens,
            disable_streaming,
            skip_connectivity_test,
            input_microunits_per_million_tokens,
            output_microunits_per_million_tokens,
            estimated_latency_ms,
            approve,
        }
        | ConfigCommand::ProviderOpenrouter {
            provider_id,
            base_url,
            model,
            secret_id,
            credential_env,
            residency,
            context_tokens,
            maximum_output_tokens,
            disable_streaming,
            skip_connectivity_test,
            input_microunits_per_million_tokens,
            output_microunits_per_million_tokens,
            estimated_latency_ms,
            approve,
        } => configure_provider(
            home,
            ProviderConfig::OpenAiResponses {
                provider_id: provider_id.clone(),
                base_url: base_url.clone(),
                model: model.clone(),
                credential: Some(ProviderCredentialReference::Broker {
                    secret_id: secret_id.clone(),
                }),
                residency: residency.clone(),
                context_tokens: *context_tokens,
                maximum_output_tokens: *maximum_output_tokens,
                streaming: !disable_streaming,
                input_microunits_per_million_tokens: *input_microunits_per_million_tokens,
                output_microunits_per_million_tokens: *output_microunits_per_million_tokens,
                estimated_latency_ms: *estimated_latency_ms,
            },
            Some(ProviderCredentialImport {
                secret_id,
                credential_env,
            }),
            *approve,
            *skip_connectivity_test,
        ),
        ConfigCommand::ProviderAnthropic {
            provider_id,
            base_url,
            model,
            secret_id,
            credential_env,
            residency,
            context_tokens,
            maximum_output_tokens,
            disable_streaming,
            skip_connectivity_test,
            input_microunits_per_million_tokens,
            output_microunits_per_million_tokens,
            estimated_latency_ms,
            approve,
        } => configure_provider(
            home,
            ProviderConfig::AnthropicMessages {
                provider_id: provider_id.clone(),
                base_url: base_url.clone(),
                model: model.clone(),
                credential: Some(ProviderCredentialReference::Broker {
                    secret_id: secret_id.clone(),
                }),
                residency: residency.clone(),
                context_tokens: *context_tokens,
                maximum_output_tokens: *maximum_output_tokens,
                streaming: !disable_streaming,
                input_microunits_per_million_tokens: *input_microunits_per_million_tokens,
                output_microunits_per_million_tokens: *output_microunits_per_million_tokens,
                estimated_latency_ms: *estimated_latency_ms,
            },
            Some(ProviderCredentialImport {
                secret_id,
                credential_env,
            }),
            *approve,
            *skip_connectivity_test,
        ),
        ConfigCommand::ProviderFallback {
            provider_id,
            base_url,
            model,
            secret_id,
            credential_env,
            residency,
            context_tokens,
            maximum_output_tokens,
            disable_streaming,
            skip_connectivity_test,
            input_microunits_per_million_tokens,
            output_microunits_per_million_tokens,
            estimated_latency_ms,
            approve,
        } => configure_provider_fallback(
            home,
            ProviderConfig::OpenAiResponses {
                provider_id: provider_id.clone(),
                base_url: base_url.clone(),
                model: model.clone(),
                credential: Some(ProviderCredentialReference::Broker {
                    secret_id: secret_id.clone(),
                }),
                residency: residency.clone(),
                context_tokens: *context_tokens,
                maximum_output_tokens: *maximum_output_tokens,
                streaming: !disable_streaming,
                input_microunits_per_million_tokens: *input_microunits_per_million_tokens,
                output_microunits_per_million_tokens: *output_microunits_per_million_tokens,
                estimated_latency_ms: *estimated_latency_ms,
            },
            Some(ProviderCredentialImport {
                secret_id,
                credential_env,
            }),
            *approve,
            *skip_connectivity_test,
        ),
        ConfigCommand::ProviderFallbackLocal {
            provider_id,
            base_url,
            model,
            residency,
            context_tokens,
            maximum_output_tokens,
            disable_streaming,
            skip_connectivity_test,
            estimated_latency_ms,
            approve,
        } => configure_provider_fallback(
            home,
            ProviderConfig::OpenAiResponses {
                provider_id: provider_id.clone(),
                base_url: base_url.clone(),
                model: model.clone(),
                credential: None,
                residency: residency.clone(),
                context_tokens: *context_tokens,
                maximum_output_tokens: *maximum_output_tokens,
                streaming: !disable_streaming,
                input_microunits_per_million_tokens: 0,
                output_microunits_per_million_tokens: 0,
                estimated_latency_ms: *estimated_latency_ms,
            },
            None,
            *approve,
            *skip_connectivity_test,
        ),
        ConfigCommand::ProviderFallbackAnthropic {
            provider_id,
            base_url,
            model,
            secret_id,
            credential_env,
            residency,
            context_tokens,
            maximum_output_tokens,
            disable_streaming,
            skip_connectivity_test,
            input_microunits_per_million_tokens,
            output_microunits_per_million_tokens,
            estimated_latency_ms,
            approve,
        } => configure_provider_fallback(
            home,
            ProviderConfig::AnthropicMessages {
                provider_id: provider_id.clone(),
                base_url: base_url.clone(),
                model: model.clone(),
                credential: Some(ProviderCredentialReference::Broker {
                    secret_id: secret_id.clone(),
                }),
                residency: residency.clone(),
                context_tokens: *context_tokens,
                maximum_output_tokens: *maximum_output_tokens,
                streaming: !disable_streaming,
                input_microunits_per_million_tokens: *input_microunits_per_million_tokens,
                output_microunits_per_million_tokens: *output_microunits_per_million_tokens,
                estimated_latency_ms: *estimated_latency_ms,
            },
            Some(ProviderCredentialImport {
                secret_id,
                credential_env,
            }),
            *approve,
            *skip_connectivity_test,
        ),
        ConfigCommand::ProviderFallbackRemove {
            provider_id,
            approve,
        } => remove_provider_fallback(home, provider_id, *approve),
        ConfigCommand::ProviderSecretRevoke { secret_id, approve } => {
            revoke_provider_secret(home, secret_id, *approve)
        }
        ConfigCommand::WorkspaceGrant {
            workspace_id,
            root,
            approve,
        } => configure_workspace_grant(home, workspace_id, root, *approve),
        ConfigCommand::WorkspaceRevoke {
            workspace_id,
            approve,
        } => configure_workspace_revoke(home, workspace_id, *approve),
        ConfigCommand::WorkspaceWriteEnable {
            workspace_id,
            approve,
        } => configure_workspace_write(home, workspace_id, true, *approve),
        ConfigCommand::WorkspaceWriteDisable {
            workspace_id,
            approve,
        } => configure_workspace_write(home, workspace_id, false, *approve),
        ConfigCommand::ProcessGrant {
            command_id,
            executable,
            approve,
        } => configure_process_grant(home, command_id, executable, *approve),
        ConfigCommand::ProcessRevoke {
            command_id,
            approve,
        } => configure_process_revoke(home, command_id, *approve),
        ConfigCommand::WebEnable {
            allow_public_internet,
            allowed_domains,
            allowed_origins,
            brave_secret_id,
            brave_credential_env,
            brave_base_url,
            approve,
        } => configure_web_access(
            home,
            *allow_public_internet,
            allowed_domains,
            allowed_origins,
            brave_secret_id.as_deref(),
            brave_credential_env,
            brave_base_url,
            *approve,
        ),
        ConfigCommand::WebDisable { approve } => configure_web_disable(home, *approve),
        ConfigCommand::BrowserInspect { bundle } => inspect_browser_runtime(bundle),
        ConfigCommand::BrowserAdd { bundle, approve } => {
            configure_browser_add(home, bundle, *approve)
        }
        ConfigCommand::BrowserList => list_browser_runtime(home),
        ConfigCommand::BrowserEnable { approve } => configure_browser_enabled(home, true, *approve),
        ConfigCommand::BrowserDisable { approve } => {
            configure_browser_enabled(home, false, *approve)
        }
        ConfigCommand::BrowserRevoke { approve } => configure_browser_revoke(home, *approve),
        ConfigCommand::McpInspect {
            server_id,
            executable,
            arguments,
        } => inspect_mcp_server(server_id, executable, arguments),
        ConfigCommand::McpAdd {
            server_id,
            executable,
            arguments,
            allow_tools,
            timeout_ms,
            maximum_output_bytes,
            approve,
        } => configure_mcp_add(
            home,
            server_id,
            executable,
            arguments,
            allow_tools,
            *timeout_ms,
            *maximum_output_bytes,
            *approve,
        ),
        ConfigCommand::McpList => list_mcp_servers(home),
        ConfigCommand::McpEnable { server_id, approve } => {
            configure_mcp_enabled(home, server_id, true, *approve)
        }
        ConfigCommand::McpDisable { server_id, approve } => {
            configure_mcp_enabled(home, server_id, false, *approve)
        }
        ConfigCommand::McpRevoke { server_id, approve } => {
            configure_mcp_revoke(home, server_id, *approve)
        }
        ConfigCommand::Rollback { digest, approve } => {
            rollback_configuration(home, digest, *approve)
        }
    }
}

fn run_skill_operation(home: &Path, command: &SkillCommand) -> Result<(), CliError> {
    match command {
        SkillCommand::Inspect {
            manifest,
            package_root,
            digest,
        } => {
            let package = inspect_skill_package(manifest, package_root, digest.as_deref())?;
            print_json(skill_package_response(
                &package,
                None,
                "inspected",
                None,
                None,
                false,
            ))
        }
        SkillCommand::Install {
            manifest,
            package_root,
            digest,
            approve,
        } => install_skill(home, manifest, package_root, digest, *approve),
        SkillCommand::Update {
            skill_id,
            expected_manifest_digest,
            manifest,
            package_root,
            digest,
            approve,
        } => update_skill(
            home,
            skill_id,
            expected_manifest_digest,
            manifest,
            package_root,
            digest,
            *approve,
        ),
        SkillCommand::Enable {
            skill_id,
            expected_manifest_digest,
            approve,
        } => set_skill_enabled(home, skill_id, expected_manifest_digest, true, *approve),
        SkillCommand::Disable {
            skill_id,
            expected_manifest_digest,
            approve,
        } => set_skill_enabled(home, skill_id, expected_manifest_digest, false, *approve),
        SkillCommand::List => list_skills(home),
        SkillCommand::Status { skill_id } => skill_status(home, skill_id),
    }
}

fn install_skill(
    home: &Path,
    manifest_path: &Path,
    package_root: &Path,
    manifest_digest: &str,
    approve: bool,
) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    let package = inspect_skill_package(manifest_path, package_root, Some(manifest_digest))?;
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let home = fs::canonicalize(home)?;
    let (current, current_body, mut value, mut records) = load_skill_configuration(&home)?;
    if records
        .iter()
        .any(|record| record.skill_id == package.manifest().skill_id)
    {
        return Err(CliError::SkillAlreadyInstalled(
            package.manifest().skill_id.clone(),
        ));
    }
    if records.len() >= 32 {
        return Err(CliError::InvalidSkillConfiguration);
    }
    let installed = publish_skill_package(&package, &home.join("skills"))?;
    let record = InstalledSkillConfigRecord {
        skill_id: package.manifest().skill_id.clone(),
        version: package.manifest().version.clone(),
        manifest_digest: package.manifest_digest().to_owned(),
        package_path: skill_package_relative_path(package.manifest_digest()),
        enabled: false,
    };
    if installed != home.join(&record.package_path) {
        return Err(CliError::InvalidSkillConfiguration);
    }
    records.push(record.clone());
    records.sort_by(|left, right| left.skill_id.cmp(&right.skill_id));
    set_skill_records(&mut value, &records)?;
    publish_skill_configuration(
        &home,
        &current,
        &current_body,
        &value,
        &package,
        &record,
        "installed_disabled",
    )
}

#[allow(clippy::too_many_arguments)]
fn update_skill(
    home: &Path,
    skill_id: &str,
    expected_manifest_digest: &str,
    manifest_path: &Path,
    package_root: &Path,
    replacement_digest: &str,
    approve: bool,
) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    let package = inspect_skill_package(manifest_path, package_root, Some(replacement_digest))?;
    if package.manifest().skill_id != skill_id {
        return Err(CliError::InvalidSkillConfiguration);
    }
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let home = fs::canonicalize(home)?;
    let (current, current_body, mut value, mut records) = load_skill_configuration(&home)?;
    let record = records
        .iter_mut()
        .find(|record| record.skill_id == skill_id)
        .ok_or_else(|| CliError::SkillNotFound(skill_id.to_owned()))?;
    if record.manifest_digest != expected_manifest_digest {
        return Err(CliError::SkillRevisionConflict(skill_id.to_owned()));
    }
    let installed = publish_skill_package(&package, &home.join("skills"))?;
    record.version.clone_from(&package.manifest().version);
    package
        .manifest_digest()
        .clone_into(&mut record.manifest_digest);
    record.package_path = skill_package_relative_path(package.manifest_digest());
    record.enabled = false;
    if installed != home.join(&record.package_path) {
        return Err(CliError::InvalidSkillConfiguration);
    }
    let response_record = record.clone();
    set_skill_records(&mut value, &records)?;
    publish_skill_configuration(
        &home,
        &current,
        &current_body,
        &value,
        &package,
        &response_record,
        "updated_disabled",
    )
}

fn set_skill_enabled(
    home: &Path,
    skill_id: &str,
    expected_manifest_digest: &str,
    enabled: bool,
    approve: bool,
) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let home = fs::canonicalize(home)?;
    let (current, current_body, mut value, mut records) = load_skill_configuration(&home)?;
    let index = records
        .iter()
        .position(|record| record.skill_id == skill_id)
        .ok_or_else(|| CliError::SkillNotFound(skill_id.to_owned()))?;
    if records[index].manifest_digest != expected_manifest_digest {
        return Err(CliError::SkillRevisionConflict(skill_id.to_owned()));
    }
    let package = inspect_installed_skill(&home, &records[index])?;
    if enabled {
        validate_enabled_skill_set(&home, &records, skill_id)?;
    }
    records[index].enabled = enabled;
    let response_record = records[index].clone();
    set_skill_records(&mut value, &records)?;
    publish_skill_configuration(
        &home,
        &current,
        &current_body,
        &value,
        &package,
        &response_record,
        if enabled { "enabled" } else { "disabled" },
    )
}

fn validate_enabled_skill_set(
    home: &Path,
    records: &[InstalledSkillConfigRecord],
    enabling_skill_id: &str,
) -> Result<(), CliError> {
    let enabled = records
        .iter()
        .filter(|record| record.enabled || record.skill_id == enabling_skill_id)
        .collect::<Vec<_>>();
    if enabled.len() > 16 {
        return Err(CliError::InvalidSkillConfiguration);
    }
    let mut instruction_bytes = 0_u64;
    let mut resource_bytes = 0_u64;
    for record in enabled {
        let package = inspect_installed_skill(home, record)?;
        for instruction in &package.manifest().instructions {
            instruction_bytes = instruction_bytes
                .checked_add(instruction.size_bytes)
                .ok_or(CliError::InvalidSkillConfiguration)?;
        }
        for resource in &package.manifest().resources {
            resource_bytes = resource_bytes
                .checked_add(resource.size_bytes)
                .ok_or(CliError::InvalidSkillConfiguration)?;
        }
    }
    if instruction_bytes > MAXIMUM_ACTIVE_SKILL_INSTRUCTION_BYTES
        || resource_bytes > MAXIMUM_ACTIVE_SKILL_RESOURCE_BYTES
    {
        return Err(CliError::InvalidSkillConfiguration);
    }
    Ok(())
}

fn list_skills(home: &Path) -> Result<(), CliError> {
    let home = readable_skill_home(home)?;
    let (current, _current_body, _value, records) = load_skill_configuration(&home)?;
    let skills = records
        .iter()
        .map(|record| {
            let package = inspect_installed_skill(&home, record)?;
            Ok(skill_package_response(
                &package,
                Some(record),
                "status",
                Some(current.display().to_string()),
                None,
                false,
            ))
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    print_json(SkillsResponse { skills })
}

fn skill_status(home: &Path, skill_id: &str) -> Result<(), CliError> {
    let home = readable_skill_home(home)?;
    let (current, _current_body, _value, records) = load_skill_configuration(&home)?;
    let record = records
        .iter()
        .find(|record| record.skill_id == skill_id)
        .ok_or_else(|| CliError::SkillNotFound(skill_id.to_owned()))?;
    let package = inspect_installed_skill(&home, record)?;
    print_json(skill_package_response(
        &package,
        Some(record),
        "status",
        Some(current.display().to_string()),
        None,
        false,
    ))
}

fn readable_skill_home(home: &Path) -> Result<PathBuf, CliError> {
    let home = absolute_service_path(home)?;
    let metadata = fs::symlink_metadata(&home)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::InvalidSkillConfiguration);
    }
    Ok(fs::canonicalize(home)?)
}

fn load_skill_configuration(
    home: &Path,
) -> Result<(PathBuf, Vec<u8>, Value, Vec<InstalledSkillConfigRecord>), CliError> {
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let value = serde_json::from_slice::<Value>(&current_body)?;
    let object = value
        .as_object()
        .filter(|object| {
            valid_daemon_config_keys(object)
                && DAEMON_CONFIG_KEYS
                    .iter()
                    .all(|key| object.contains_key(*key))
                && object.get("formatVersion").and_then(Value::as_u64) == Some(1)
        })
        .ok_or(CliError::InvalidSkillConfiguration)?;
    let records = object
        .get("skills")
        .cloned()
        .map(serde_json::from_value::<Vec<InstalledSkillConfigRecord>>)
        .transpose()?
        .unwrap_or_default();
    validate_skill_records(&records)?;
    Ok((current, current_body, value, records))
}

fn validate_skill_records(records: &[InstalledSkillConfigRecord]) -> Result<(), CliError> {
    if records.len() > 32
        || !records
            .windows(2)
            .all(|window| window[0].skill_id < window[1].skill_id)
    {
        return Err(CliError::InvalidSkillConfiguration);
    }
    let mut identities = BTreeSet::new();
    let mut package_paths = BTreeSet::new();
    if records.iter().all(|record| {
        valid_skill_identifier(&record.skill_id, 128)
            && valid_skill_identifier(&record.version, 128)
            && is_sha256_digest(&record.manifest_digest)
            && record.package_path == skill_package_relative_path(&record.manifest_digest)
            && identities.insert(record.skill_id.as_str())
            && package_paths.insert(record.package_path.as_str())
    }) {
        Ok(())
    } else {
        Err(CliError::InvalidSkillConfiguration)
    }
}

fn valid_skill_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

fn skill_package_relative_path(manifest_digest: &str) -> String {
    format!("skills/{manifest_digest}")
}

fn inspect_installed_skill(
    home: &Path,
    record: &InstalledSkillConfigRecord,
) -> Result<InspectedSkillPackage, CliError> {
    let package_root = home.join(&record.package_path);
    let package = inspect_skill_package(
        &package_root.join("manifest.json"),
        &package_root,
        Some(&record.manifest_digest),
    )?;
    if package.manifest().skill_id != record.skill_id
        || package.manifest().version != record.version
    {
        return Err(CliError::InvalidSkillConfiguration);
    }
    Ok(package)
}

fn set_skill_records(
    value: &mut Value,
    records: &[InstalledSkillConfigRecord],
) -> Result<(), CliError> {
    let object = value
        .as_object_mut()
        .ok_or(CliError::InvalidSkillConfiguration)?;
    if records.is_empty() {
        object.remove("skills");
    } else {
        object.insert("skills".to_owned(), serde_json::to_value(records)?);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn publish_skill_configuration(
    home: &Path,
    current: &Path,
    current_body: &[u8],
    value: &Value,
    package: &InspectedSkillPackage,
    record: &InstalledSkillConfigRecord,
    operation: &str,
) -> Result<(), CliError> {
    let timestamp = unix_timestamp_millis()?;
    let history = home.join("config-history");
    create_private_service_directory(&history)?;
    let replaced = history.join(format!("pre-skill-{timestamp}.json"));
    atomic_write_service(&replaced, current_body)?;
    atomic_write_service(current, &serde_json::to_vec_pretty(value)?)?;
    print_json(skill_package_response(
        package,
        Some(record),
        operation,
        Some(current.display().to_string()),
        Some(replaced.display().to_string()),
        true,
    ))
}

fn skill_package_response(
    package: &InspectedSkillPackage,
    record: Option<&InstalledSkillConfigRecord>,
    operation: &str,
    configuration_path: Option<String>,
    replaced_configuration_copy: Option<String>,
    restart_required: bool,
) -> SkillPackageResponse {
    SkillPackageResponse {
        operation: operation.to_owned(),
        skill_id: package.manifest().skill_id.clone(),
        version: package.manifest().version.clone(),
        manifest_digest: package.manifest_digest().to_owned(),
        installed: record.is_some(),
        enabled: record.is_some_and(|record| record.enabled),
        package_path: record.map(|record| record.package_path.clone()),
        total_asset_bytes: package.total_asset_bytes(),
        instructions: package.manifest().instructions.clone(),
        resources: package.manifest().resources.clone(),
        required_tools: package.manifest().required_tools.iter().cloned().collect(),
        tool_authority: "references_only_no_authority_granted",
        configuration_path,
        replaced_configuration_copy,
        restart_required,
    }
}

fn discover_openai_models(
    base_url: &str,
    credential_env: &str,
    contains: Option<&str>,
    limit: usize,
) -> Result<(), CliError> {
    validate_provider_discovery_arguments(base_url, contains, limit, None)?;
    let credential = read_provider_credential_environment(credential_env)?;
    let result = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                discover_openai_models_blocking(
                    base_url,
                    Some(credential.as_str()),
                    contains,
                    limit,
                    false,
                )
            })
            .join()
            .map_err(|_| CliError::ProviderDiscovery("model discovery worker failed".to_owned()))?
    });
    drop(credential);
    print_json(result?)
}

fn discover_local_models(
    base_url: &str,
    contains: Option<&str>,
    limit: usize,
) -> Result<(), CliError> {
    validate_provider_discovery_arguments(base_url, contains, limit, None)?;
    if validate_provider_base_url(base_url) != Ok(true) {
        return Err(CliError::InvalidProviderDiscoveryRequest);
    }
    let result = std::thread::scope(|scope| {
        scope
            .spawn(|| discover_openai_models_blocking(base_url, None, contains, limit, true))
            .join()
            .map_err(|_| CliError::ProviderDiscovery("model discovery worker failed".to_owned()))?
    });
    print_json(result?)
}

fn discover_openrouter_models(
    base_url: &str,
    credential_env: &str,
    contains: Option<&str>,
    limit: usize,
) -> Result<(), CliError> {
    validate_provider_discovery_arguments(base_url, contains, limit, None)?;
    let credential = read_provider_credential_environment(credential_env)?;
    let result = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                discover_openrouter_models_blocking(base_url, credential.as_str(), contains, limit)
            })
            .join()
            .map_err(|_| CliError::ProviderDiscovery("model discovery worker failed".to_owned()))?
    });
    drop(credential);
    print_json(result?)
}

fn discover_anthropic_models(
    base_url: &str,
    credential_env: &str,
    contains: Option<&str>,
    limit: usize,
    after_id: Option<&str>,
) -> Result<(), CliError> {
    validate_provider_discovery_arguments(base_url, contains, limit, after_id)?;
    let credential = read_provider_credential_environment(credential_env)?;
    let result = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                discover_anthropic_models_blocking(
                    base_url,
                    credential.as_str(),
                    contains,
                    limit,
                    after_id,
                )
            })
            .join()
            .map_err(|_| CliError::ProviderDiscovery("model discovery worker failed".to_owned()))?
    });
    drop(credential);
    print_json(result?)
}

fn validate_provider_discovery_arguments(
    base_url: &str,
    contains: Option<&str>,
    limit: usize,
    after_id: Option<&str>,
) -> Result<(), CliError> {
    validate_provider_base_url(base_url).map_err(|_| CliError::InvalidProviderConfiguration)?;
    if !(1..=PROVIDER_DISCOVERY_MAXIMUM_MODELS).contains(&limit)
        || contains.is_some_and(|value| !valid_provider_discovery_text(value, 256))
        || after_id.is_some_and(|value| !valid_provider_discovery_text(value, 256))
    {
        return Err(CliError::InvalidProviderDiscoveryRequest);
    }
    Ok(())
}

fn valid_provider_discovery_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn provider_models_endpoint(base_url: &str) -> Result<reqwest::Url, CliError> {
    validate_provider_base_url(base_url).map_err(|_| CliError::InvalidProviderConfiguration)?;
    let base = reqwest::Url::parse(&format!("{}/", base_url.trim_end_matches('/')))
        .map_err(|_| CliError::InvalidProviderConfiguration)?;
    base.join("models")
        .map_err(|_| CliError::InvalidProviderConfiguration)
}

fn openrouter_models_endpoint(base_url: &str) -> Result<reqwest::Url, CliError> {
    validate_provider_base_url(base_url).map_err(|_| CliError::InvalidProviderConfiguration)?;
    let base = reqwest::Url::parse(&format!("{}/", base_url.trim_end_matches('/')))
        .map_err(|_| CliError::InvalidProviderConfiguration)?;
    base.join("models/user")
        .map_err(|_| CliError::InvalidProviderConfiguration)
}

fn discover_openai_models_blocking(
    base_url: &str,
    credential: Option<&str>,
    contains: Option<&str>,
    limit: usize,
    local_endpoint: bool,
) -> Result<ProviderModelDiscoveryResponse, CliError> {
    let url = provider_models_endpoint(base_url)?;
    let mut request = provider_discovery_client()?
        .get(url.clone())
        .header(reqwest::header::ACCEPT, "application/json")
        .header(
            reqwest::header::USER_AGENT,
            concat!("mealyctl/", env!("CARGO_PKG_VERSION")),
        );
    if let Some(credential) = credential {
        request = request.bearer_auth(credential);
    }
    let response = request
        .send()
        .map_err(|_| CliError::ProviderDiscovery("provider transport unavailable".to_owned()))?;
    let body = read_provider_discovery_json(response)?;
    let envelope = serde_json::from_slice::<OpenAiModelsEnvelope>(&body).map_err(|_| {
        CliError::ProviderDiscovery("provider returned malformed model-list JSON".to_owned())
    })?;
    if envelope.object != "list" || envelope.data.len() > PROVIDER_DISCOVERY_MAXIMUM_WIRE_MODELS {
        return Err(CliError::ProviderDiscovery(
            "provider returned an invalid model-list envelope".to_owned(),
        ));
    }

    let filter = contains.map(str::to_lowercase);
    let mut models = Vec::new();
    let mut locally_truncated = false;
    for model in envelope.data {
        if model.object != "model"
            || model.created < 0
            || !valid_provider_discovery_text(&model.id, 256)
            || !valid_provider_discovery_text(&model.owned_by, 256)
        {
            return Err(CliError::ProviderDiscovery(
                "provider returned invalid model metadata".to_owned(),
            ));
        }
        if filter
            .as_ref()
            .is_some_and(|filter| !model.id.to_lowercase().contains(filter))
        {
            continue;
        }
        if models.len() == limit {
            locally_truncated = true;
            continue;
        }
        models.push(ProviderModelDiscoveryItem {
            id: model.id,
            display_name: None,
            created_at: None,
            created_at_unix_seconds: Some(u64::try_from(model.created).map_err(|_| {
                CliError::ProviderDiscovery("provider returned invalid model metadata".to_owned())
            })?),
            owned_by: Some(model.owned_by),
            context_tokens: None,
            maximum_output_tokens: None,
            token_limits_complete: false,
            input_microunits_per_million_tokens: None,
            output_microunits_per_million_tokens: None,
            pricing_complete: false,
            unsupported_pricing_axes: Vec::new(),
            tool_capable: None,
        });
    }
    let returned_count = models.len();
    Ok(ProviderModelDiscoveryResponse {
        protocol: "openai_responses".to_owned(),
        endpoint: url.to_string(),
        retrieved_at_ms: unix_timestamp_millis()?,
        filter: contains.map(str::to_owned),
        requested_limit: limit,
        returned_count,
        provider_has_more: None,
        next_after_id: None,
        locally_truncated,
        pricing_included: false,
        models,
        metadata_notice: if local_endpoint {
            "The local OpenAI-compatible Models endpoint identifies installed model IDs, but does not prove that each implements the Responses contract or advertise trustworthy token limits. Declare conservative limits and verify the selected model with Mealy's bounded activation probe. Local pricing is recorded as zero."
        } else {
            "The live OpenAI Models API identifies models accessible to this credential, but does not attest Responses compatibility, token limits, or prices. Verify those values in current official model and pricing documentation before activation."
        },
        official_models_url: "https://developers.openai.com/api/docs/models",
        official_pricing_url: "https://developers.openai.com/api/docs/pricing",
    })
}

fn discover_anthropic_models_blocking(
    base_url: &str,
    credential: &str,
    contains: Option<&str>,
    limit: usize,
    after_id: Option<&str>,
) -> Result<ProviderModelDiscoveryResponse, CliError> {
    let mut url = provider_models_endpoint(base_url)?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("limit", &limit.to_string());
        if let Some(after_id) = after_id {
            query.append_pair("after_id", after_id);
        }
    }
    let response = provider_discovery_client()?
        .get(url.clone())
        .header("x-api-key", credential)
        .header("anthropic-version", "2023-06-01")
        .header(reqwest::header::ACCEPT, "application/json")
        .header(
            reqwest::header::USER_AGENT,
            concat!("mealyctl/", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .map_err(|_| CliError::ProviderDiscovery("provider transport unavailable".to_owned()))?;
    let body = read_provider_discovery_json(response)?;
    let envelope = serde_json::from_slice::<AnthropicModelsEnvelope>(&body).map_err(|_| {
        CliError::ProviderDiscovery("provider returned malformed model-list JSON".to_owned())
    })?;
    if envelope.data.len() > limit
        || envelope.data.len() > PROVIDER_DISCOVERY_MAXIMUM_WIRE_MODELS
        || envelope
            .first_id
            .as_deref()
            .is_some_and(|value| !valid_provider_discovery_text(value, 256))
        || envelope
            .last_id
            .as_deref()
            .is_some_and(|value| !valid_provider_discovery_text(value, 256))
        || (envelope.has_more && (envelope.data.is_empty() || envelope.last_id.is_none()))
    {
        return Err(CliError::ProviderDiscovery(
            "provider returned an invalid model-list envelope".to_owned(),
        ));
    }

    let filter = contains.map(str::to_lowercase);
    let mut models = Vec::new();
    for model in envelope.data {
        if model.kind != "model"
            || !valid_provider_discovery_text(&model.id, 256)
            || !valid_provider_discovery_text(&model.display_name, 256)
            || !valid_provider_discovery_text(&model.created_at, 128)
        {
            return Err(CliError::ProviderDiscovery(
                "provider returned invalid model metadata".to_owned(),
            ));
        }
        if filter
            .as_ref()
            .is_some_and(|filter| !model.id.to_lowercase().contains(filter))
        {
            continue;
        }
        let context_tokens = model.max_input_tokens.filter(|value| *value != 0);
        let maximum_output_tokens = model.max_tokens.filter(|value| *value != 0);
        models.push(ProviderModelDiscoveryItem {
            id: model.id,
            display_name: Some(model.display_name),
            created_at: Some(model.created_at),
            created_at_unix_seconds: None,
            owned_by: None,
            context_tokens,
            maximum_output_tokens,
            token_limits_complete: context_tokens.is_some() && maximum_output_tokens.is_some(),
            input_microunits_per_million_tokens: None,
            output_microunits_per_million_tokens: None,
            pricing_complete: false,
            unsupported_pricing_axes: Vec::new(),
            tool_capable: None,
        });
    }
    let returned_count = models.len();
    let next_after_id = envelope.has_more.then_some(envelope.last_id).flatten();
    Ok(ProviderModelDiscoveryResponse {
        protocol: "anthropic_messages".to_owned(),
        endpoint: url.to_string(),
        retrieved_at_ms: unix_timestamp_millis()?,
        filter: contains.map(str::to_owned),
        requested_limit: limit,
        returned_count,
        provider_has_more: Some(envelope.has_more),
        next_after_id,
        locally_truncated: false,
        pricing_included: false,
        models,
        metadata_notice: "The live Anthropic Models API identifies models accessible to this credential and may advertise token limits. It does not include prices; verify current official pricing before activation, and verify any missing or zero token limit in the model documentation.",
        official_models_url: "https://platform.claude.com/docs/en/api/models/list",
        official_pricing_url: "https://claude.com/pricing",
    })
}

fn discover_openrouter_models_blocking(
    base_url: &str,
    credential: &str,
    contains: Option<&str>,
    limit: usize,
) -> Result<ProviderModelDiscoveryResponse, CliError> {
    let url = openrouter_models_endpoint(base_url)?;
    let response = provider_discovery_client()?
        .get(url.clone())
        .bearer_auth(credential)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(
            reqwest::header::USER_AGENT,
            concat!("mealyctl/", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .map_err(|_| CliError::ProviderDiscovery("provider transport unavailable".to_owned()))?;
    let body = read_provider_discovery_json(response)?;
    let envelope = serde_json::from_slice::<OpenRouterModelsEnvelope>(&body).map_err(|_| {
        CliError::ProviderDiscovery("provider returned malformed model-list JSON".to_owned())
    })?;
    if envelope.data.len() > PROVIDER_DISCOVERY_MAXIMUM_WIRE_MODELS {
        return Err(CliError::ProviderDiscovery(
            "provider returned an invalid model-list envelope".to_owned(),
        ));
    }

    let filter = contains.map(str::to_lowercase);
    let mut models = Vec::new();
    let mut locally_truncated = false;
    for model in envelope.data {
        let Some(item) = normalize_openrouter_model(model, filter.as_deref())? else {
            continue;
        };
        if models.len() < limit {
            models.push(item);
        } else {
            locally_truncated = true;
        }
    }
    let returned_count = models.len();
    Ok(ProviderModelDiscoveryResponse {
        protocol: "openrouter_responses_beta".to_owned(),
        endpoint: url.to_string(),
        retrieved_at_ms: unix_timestamp_millis()?,
        filter: contains.map(str::to_owned),
        requested_limit: limit,
        returned_count,
        provider_has_more: None,
        next_after_id: None,
        locally_truncated,
        pricing_included: true,
        models,
        metadata_notice: "OpenRouter's authenticated user catalog is filtered by account preferences, privacy settings, and guardrails; Mealy additionally emits only text-output models advertising tool support. Posted prices are converted exactly from USD per token when representable, but any nonzero request/image/search/reasoning/cache axis makes pricingComplete false. OpenRouter's Responses API is beta and stateless. Activation still requires conservative declared limits/prices and a live bounded compatibility probe; it does not prove every future tool path or upstream route.",
        official_models_url: "https://openrouter.ai/docs/api/api-reference/models/list-models-user",
        official_pricing_url: "https://openrouter.ai/docs/guides/overview/models#model-pricing",
    })
}

fn normalize_openrouter_model(
    model: OpenRouterModelWire,
    filter: Option<&str>,
) -> Result<Option<ProviderModelDiscoveryItem>, CliError> {
    let Some(display_name) = normalize_openrouter_display_name(&model.name) else {
        return Err(CliError::ProviderDiscovery(
            "provider returned invalid model metadata".to_owned(),
        ));
    };
    if !valid_openrouter_model_metadata(&model) {
        return Err(CliError::ProviderDiscovery(
            "provider returned invalid model metadata".to_owned(),
        ));
    }
    let tool_capable = model
        .supported_parameters
        .iter()
        .any(|parameter| parameter == "tools");
    let text_output = model
        .architecture
        .output_modalities
        .iter()
        .any(|modality| modality == "text");
    if !tool_capable
        || !text_output
        || filter.is_some_and(|filter| {
            !model.id.to_lowercase().contains(filter) && !model.name.to_lowercase().contains(filter)
        })
    {
        return Ok(None);
    }
    let context_tokens = model
        .top_provider
        .as_ref()
        .and_then(|provider| provider.context_length)
        .filter(|value| *value != 0)
        .or_else(|| model.context_length.filter(|value| *value != 0));
    let maximum_output_tokens = model
        .top_provider
        .as_ref()
        .and_then(|provider| provider.max_completion_tokens)
        .filter(|value| *value != 0);
    let input_price = openrouter_price_microunits_per_million(&model.pricing.prompt);
    let output_price = openrouter_price_microunits_per_million(&model.pricing.completion);
    let unsupported_pricing_axes = openrouter_unsupported_pricing_axes(&model.pricing);
    let pricing_complete =
        input_price.is_some() && output_price.is_some() && unsupported_pricing_axes.is_empty();
    let owner = model.id.split_once('/').map(|(owner, _)| owner.to_owned());
    Ok(Some(ProviderModelDiscoveryItem {
        id: model.id,
        display_name: Some(display_name.to_owned()),
        created_at: None,
        created_at_unix_seconds: Some(u64::try_from(model.created).map_err(|_| {
            CliError::ProviderDiscovery("provider returned invalid model metadata".to_owned())
        })?),
        owned_by: owner,
        context_tokens,
        maximum_output_tokens,
        token_limits_complete: context_tokens.is_some() && maximum_output_tokens.is_some(),
        input_microunits_per_million_tokens: input_price,
        output_microunits_per_million_tokens: output_price,
        pricing_complete,
        unsupported_pricing_axes,
        tool_capable: Some(true),
    }))
}

fn normalize_openrouter_display_name(value: &str) -> Option<&str> {
    if value.len() > 256 || value.chars().any(char::is_control) {
        return None;
    }
    let value = value.trim();
    valid_provider_discovery_text(value, 256).then_some(value)
}

fn valid_openrouter_model_metadata(model: &OpenRouterModelWire) -> bool {
    let parameters = model
        .supported_parameters
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    model.created >= 0
        && valid_provider_discovery_text(&model.id, 256)
        && model.supported_parameters.len() <= 128
        && parameters.len() == model.supported_parameters.len()
        && parameters
            .iter()
            .all(|parameter| valid_provider_discovery_text(parameter, 64))
        && model.architecture.output_modalities.len() <= 16
        && model
            .architecture
            .output_modalities
            .iter()
            .all(|modality| valid_provider_discovery_text(modality, 32))
}

fn openrouter_unsupported_pricing_axes(pricing: &OpenRouterPricingWire) -> Vec<String> {
    [
        ("request", pricing.request.as_deref()),
        ("image", pricing.image.as_deref()),
        ("web_search", pricing.web_search.as_deref()),
        ("internal_reasoning", pricing.internal_reasoning.as_deref()),
        ("input_cache_read", pricing.input_cache_read.as_deref()),
        ("input_cache_write", pricing.input_cache_write.as_deref()),
    ]
    .into_iter()
    .filter(|(_, price)| price.is_some_and(|value| !openrouter_price_is_zero(value)))
    .map(|(name, _)| name.to_owned())
    .collect()
}

fn openrouter_price_microunits_per_million(value: &str) -> Option<u64> {
    if value.is_empty()
        || value.len() > 64
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return None;
    }
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || (whole.len() > 1 && whole.starts_with('0'))
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || (value.contains('.') && fraction.is_empty())
        || fraction.len() > 12
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || value.matches('.').count() > 1
    {
        return None;
    }
    let whole = whole.parse::<u64>().ok()?;
    let fraction_digits = fraction.len();
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u64>().ok()?
    };
    whole.checked_mul(1_000_000_000_000).and_then(|scaled| {
        scaled.checked_add(
            fraction.checked_mul(10_u64.pow(u32::try_from(12 - fraction_digits).ok()?))?,
        )
    })
}

fn openrouter_price_is_zero(value: &str) -> bool {
    openrouter_price_microunits_per_million(value) == Some(0)
}

fn provider_discovery_client() -> Result<reqwest::blocking::Client, CliError> {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| CliError::ProviderDiscovery("HTTP client unavailable".to_owned()))
}

fn read_provider_discovery_json(
    mut response: reqwest::blocking::Response,
) -> Result<Vec<u8>, CliError> {
    if !response.status().is_success() {
        return Err(CliError::ProviderDiscovery(format!(
            "provider returned HTTP status {}",
            response.status().as_u16()
        )));
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .unwrap_or_default();
    if !content_type.eq_ignore_ascii_case("application/json") {
        return Err(CliError::ProviderDiscovery(
            "provider did not return model-list JSON".to_owned(),
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > PROVIDER_PROBE_MAXIMUM_BYTES)
    {
        return Err(CliError::ProviderDiscovery(
            "provider model-list response exceeded its byte bound".to_owned(),
        ));
    }
    let mut body = Vec::new();
    response
        .by_ref()
        .take(PROVIDER_PROBE_MAXIMUM_BYTES.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|_| {
            CliError::ProviderDiscovery("provider model-list response could not be read".to_owned())
        })?;
    if u64::try_from(body.len()).unwrap_or(u64::MAX) > PROVIDER_PROBE_MAXIMUM_BYTES {
        return Err(CliError::ProviderDiscovery(
            "provider model-list response exceeded its byte bound".to_owned(),
        ));
    }
    Ok(body)
}

#[allow(clippy::too_many_arguments)]
fn configure_subscription_provider(
    home: &Path,
    provider_id: &str,
    client: SubscriptionCliClient,
    executable_path: Option<&Path>,
    default_executable: &str,
    model: &str,
    residency: &str,
    context_tokens: u64,
    maximum_output_tokens: u64,
    estimated_latency_ms: u64,
    approve: bool,
    skip_connectivity_test: bool,
) -> Result<(), CliError> {
    let selected = executable_path
        .map(Path::to_path_buf)
        .or_else(|| find_executable_on_path(default_executable))
        .ok_or(CliError::InvalidProviderConfiguration)?;
    let (canonical, executable_sha256) = inspect_subscription_cli_executable(&selected)
        .map_err(|_| CliError::InvalidProviderConfiguration)?;
    let canonical = canonical
        .to_str()
        .ok_or(CliError::InvalidProviderConfiguration)?;
    configure_provider(
        home,
        ProviderConfig::SubscriptionCli {
            provider_id: provider_id.to_owned(),
            client,
            executable_path: canonical.to_owned(),
            executable_sha256,
            model: model.to_owned(),
            residency: residency.to_owned(),
            context_tokens,
            maximum_output_tokens,
            estimated_latency_ms,
        },
        None,
        approve,
        skip_connectivity_test,
    )
}

fn find_executable_on_path(name: &str) -> Option<PathBuf> {
    if name.is_empty()
        || name.len() > 128
        || name.contains(std::path::MAIN_SEPARATOR)
        || name.chars().any(char::is_control)
    {
        return None;
    }
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}

fn configure_provider(
    home: &Path,
    provider: ProviderConfig,
    credential_import: Option<ProviderCredentialImport<'_>>,
    approve: bool,
    skip_connectivity_test: bool,
) -> Result<(), CliError> {
    print_json(activate_provider(
        home,
        provider,
        credential_import,
        approve,
        skip_connectivity_test,
    )?)
}

fn activate_provider(
    home: &Path,
    provider: ProviderConfig,
    credential_import: Option<ProviderCredentialImport<'_>>,
    approve: bool,
    skip_connectivity_test: bool,
) -> Result<ProviderConfigurationResponse, CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    provider
        .validate()
        .map_err(|_| CliError::InvalidProviderConfiguration)?;
    validate_provider_credential_import(&provider, credential_import)?;
    let credential = credential_import
        .map(|import| read_provider_credential_environment(import.credential_env))
        .transpose()?;
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let mut value = serde_json::from_slice::<serde_json::Value>(&current_body)?;
    let object = value
        .as_object_mut()
        .ok_or(CliError::InvalidProviderConfiguration)?;
    if !valid_daemon_config_keys(object)
        || DAEMON_CONFIG_KEYS
            .iter()
            .any(|key| !object.contains_key(*key))
        || object
            .get("formatVersion")
            .and_then(serde_json::Value::as_u64)
            != Some(1)
    {
        return Err(CliError::InvalidProviderConfiguration);
    }
    ensure_provider_timeout(object, &provider)?;
    let fallbacks = object
        .get("providerFallbacks")
        .cloned()
        .map(serde_json::from_value::<Vec<ProviderConfig>>)
        .transpose()?
        .unwrap_or_default();
    validate_provider_chain(&provider, &fallbacks)
        .map_err(|_| CliError::InvalidProviderConfiguration)?;
    let secret_store = credential_import
        .map(|_| FileProviderSecretStore::new(home.join("provider-secrets")))
        .transpose()?;
    if let (Some(import), Some(secret_store), Some(credential)) = (
        credential_import,
        secret_store.as_ref(),
        credential.as_ref(),
    ) {
        verify_provider_secret_preflight(secret_store, import.secret_id, credential.as_str())?;
    }
    if !skip_connectivity_test {
        probe_provider_connectivity(
            &provider,
            credential.as_ref().map(|credential| credential.as_str()),
        )?;
    }
    let provider_body = serde_json::to_vec(&provider)?;
    let provider_config_digest = sha256_digest(&provider_body);
    object.insert("provider".to_owned(), serde_json::to_value(&provider)?);
    if fallbacks.is_empty() {
        object.remove("providerFallbacks");
    } else {
        object.insert(
            "providerFallbacks".to_owned(),
            serde_json::to_value(&fallbacks)?,
        );
    }
    let updated = serde_json::to_vec_pretty(&value)?;
    let timestamp = unix_timestamp_millis()?;
    let replaced = home
        .join("config-history")
        .join(format!("pre-provider-{timestamp}.json"));
    if let (Some(import), Some(secret_store), Some(credential)) = (
        credential_import,
        secret_store.as_ref(),
        credential.as_ref(),
    ) {
        secret_store.put(import.secret_id, credential.as_str())?;
    }
    atomic_write_service(&replaced, &current_body)?;
    atomic_write_service(&current, &updated)?;
    let (protocol, provider_id, model, streaming) = provider_configuration_identity(provider)?;
    Ok(ProviderConfigurationResponse {
        provider_config_digest,
        protocol: protocol.to_owned(),
        provider_id,
        model,
        secret_id: credential_import.map(|import| import.secret_id.to_owned()),
        provider_role: "primary".to_owned(),
        fallback_ordinal: None,
        streaming,
        connectivity_tested: !skip_connectivity_test,
        configuration_path: current.display().to_string(),
        replaced_configuration_copy: replaced.display().to_string(),
        restart_required: true,
    })
}

fn list_provider_chain(home: &Path) -> Result<(), CliError> {
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let value = serde_json::from_slice::<Value>(&current_body)?;
    let object = value
        .as_object()
        .ok_or(CliError::InvalidProviderConfiguration)?;
    if !valid_daemon_config_keys(object)
        || DAEMON_CONFIG_KEYS
            .iter()
            .any(|key| !object.contains_key(*key))
        || object.get("formatVersion").and_then(Value::as_u64) != Some(1)
    {
        return Err(CliError::InvalidProviderConfiguration);
    }
    let primary = serde_json::from_value::<ProviderConfig>(
        object
            .get("provider")
            .cloned()
            .ok_or(CliError::InvalidProviderConfiguration)?,
    )?;
    let fallbacks = object
        .get("providerFallbacks")
        .cloned()
        .map(serde_json::from_value::<Vec<ProviderConfig>>)
        .transpose()?
        .unwrap_or_default();
    validate_provider_chain(&primary, &fallbacks)
        .map_err(|_| CliError::InvalidProviderConfiguration)?;
    print_json(ProviderChainConfigurationResponse {
        fallback_count: fallbacks.len(),
        primary,
        fallbacks,
        credential_values_resolved: false,
        configuration_path: current.display().to_string(),
    })
}

fn configure_provider_fallback(
    home: &Path,
    provider: ProviderConfig,
    credential_import: Option<ProviderCredentialImport<'_>>,
    approve: bool,
    skip_connectivity_test: bool,
) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    provider
        .validate()
        .map_err(|_| CliError::InvalidProviderConfiguration)?;
    validate_provider_credential_import(&provider, credential_import)?;
    let credential = credential_import
        .map(|import| read_provider_credential_environment(import.credential_env))
        .transpose()?;
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let mut value = serde_json::from_slice::<serde_json::Value>(&current_body)?;
    let object = value
        .as_object_mut()
        .ok_or(CliError::InvalidProviderConfiguration)?;
    if !valid_daemon_config_keys(object)
        || object
            .get("formatVersion")
            .and_then(serde_json::Value::as_u64)
            != Some(1)
    {
        return Err(CliError::InvalidProviderConfiguration);
    }
    ensure_provider_timeout(object, &provider)?;
    let primary = serde_json::from_value::<ProviderConfig>(
        object
            .get("provider")
            .cloned()
            .ok_or(CliError::InvalidProviderConfiguration)?,
    )?;
    let mut fallbacks = object
        .get("providerFallbacks")
        .cloned()
        .map(serde_json::from_value::<Vec<ProviderConfig>>)
        .transpose()?
        .unwrap_or_default();
    fallbacks.push(provider.clone());
    validate_provider_chain(&primary, &fallbacks)
        .map_err(|_| CliError::InvalidProviderConfiguration)?;
    let secret_store = credential_import
        .map(|_| FileProviderSecretStore::new(home.join("provider-secrets")))
        .transpose()?;
    if let (Some(import), Some(secret_store), Some(credential)) = (
        credential_import,
        secret_store.as_ref(),
        credential.as_ref(),
    ) {
        verify_provider_secret_preflight(secret_store, import.secret_id, credential.as_str())?;
    }
    if !skip_connectivity_test {
        probe_provider_connectivity(
            &provider,
            credential.as_ref().map(|credential| credential.as_str()),
        )?;
    }

    let provider_config_digest = sha256_digest(&serde_json::to_vec(&provider)?);
    object.insert(
        "providerFallbacks".to_owned(),
        serde_json::to_value(&fallbacks)?,
    );
    let updated = serde_json::to_vec_pretty(&value)?;
    let timestamp = unix_timestamp_millis()?;
    let replaced = home
        .join("config-history")
        .join(format!("pre-provider-fallback-{timestamp}.json"));
    if let (Some(import), Some(secret_store), Some(credential)) = (
        credential_import,
        secret_store.as_ref(),
        credential.as_ref(),
    ) {
        secret_store.put(import.secret_id, credential.as_str())?;
    }
    atomic_write_service(&replaced, &current_body)?;
    atomic_write_service(&current, &updated)?;
    let (protocol, provider_id, model, streaming) = provider_configuration_identity(provider)?;
    print_json(ProviderConfigurationResponse {
        provider_config_digest,
        protocol: protocol.to_owned(),
        provider_id,
        model,
        secret_id: credential_import.map(|import| import.secret_id.to_owned()),
        provider_role: "fallback".to_owned(),
        fallback_ordinal: Some(fallbacks.len()),
        streaming,
        connectivity_tested: !skip_connectivity_test,
        configuration_path: current.display().to_string(),
        replaced_configuration_copy: replaced.display().to_string(),
        restart_required: true,
    })
}

fn ensure_provider_timeout(
    config: &mut serde_json::Map<String, Value>,
    provider: &ProviderConfig,
) -> Result<(), CliError> {
    let estimated_latency_ms = match provider {
        ProviderConfig::BuiltinFixture => return Ok(()),
        ProviderConfig::OpenAiResponses {
            estimated_latency_ms,
            ..
        }
        | ProviderConfig::AnthropicMessages {
            estimated_latency_ms,
            ..
        }
        | ProviderConfig::SubscriptionCli {
            estimated_latency_ms,
            ..
        } => *estimated_latency_ms,
    };
    let required_timeout_ms = estimated_latency_ms
        .checked_add(PROVIDER_DISPATCH_SAFETY_MARGIN_MS)
        .ok_or(CliError::InvalidProviderConfiguration)?;
    let limits = config
        .get_mut("agentLoopLimits")
        .and_then(Value::as_object_mut)
        .ok_or(CliError::InvalidProviderConfiguration)?;
    let maximum_wall_time_ms = limits
        .get("maximumWallTimeMs")
        .and_then(Value::as_u64)
        .ok_or(CliError::InvalidProviderConfiguration)?;
    let provider_timeout_ms = limits
        .get("providerTimeoutMs")
        .and_then(Value::as_u64)
        .ok_or(CliError::InvalidProviderConfiguration)?;
    if required_timeout_ms > maximum_wall_time_ms {
        return Err(CliError::InvalidProviderConfiguration);
    }
    if provider_timeout_ms < required_timeout_ms {
        limits.insert(
            "providerTimeoutMs".to_owned(),
            Value::from(required_timeout_ms),
        );
    }
    Ok(())
}

fn remove_provider_fallback(home: &Path, provider_id: &str, approve: bool) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    if provider_id.is_empty()
        || provider_id.len() > 128
        || provider_id.trim() != provider_id
        || provider_id.chars().any(char::is_control)
    {
        return Err(CliError::InvalidProviderConfiguration);
    }
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let mut value = serde_json::from_slice::<Value>(&current_body)?;
    let object = value
        .as_object_mut()
        .ok_or(CliError::InvalidProviderConfiguration)?;
    if !valid_daemon_config_keys(object)
        || DAEMON_CONFIG_KEYS
            .iter()
            .any(|key| !object.contains_key(*key))
        || object.get("formatVersion").and_then(Value::as_u64) != Some(1)
    {
        return Err(CliError::InvalidProviderConfiguration);
    }
    let primary = serde_json::from_value::<ProviderConfig>(
        object
            .get("provider")
            .cloned()
            .ok_or(CliError::InvalidProviderConfiguration)?,
    )?;
    let mut fallbacks = object
        .get("providerFallbacks")
        .cloned()
        .map(serde_json::from_value::<Vec<ProviderConfig>>)
        .transpose()?
        .unwrap_or_default();
    validate_provider_chain(&primary, &fallbacks)
        .map_err(|_| CliError::InvalidProviderConfiguration)?;
    let index = fallbacks
        .iter()
        .position(|provider| provider_config_id(provider).ok() == Some(provider_id))
        .ok_or_else(|| CliError::ProviderFallbackNotFound(provider_id.to_owned()))?;
    let removed = fallbacks.remove(index);
    validate_provider_chain(&primary, &fallbacks)
        .map_err(|_| CliError::InvalidProviderConfiguration)?;
    let removed_secret_id = provider_config_secret_id(&removed).map(ToOwned::to_owned);
    let remaining_provider_ids = fallbacks
        .iter()
        .map(|provider| provider_config_id(provider).map(ToOwned::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    if fallbacks.is_empty() {
        object.remove("providerFallbacks");
    } else {
        object.insert(
            "providerFallbacks".to_owned(),
            serde_json::to_value(&fallbacks)?,
        );
    }
    let updated = serde_json::to_vec_pretty(&value)?;
    let timestamp = unix_timestamp_millis()?;
    let replaced = home
        .join("config-history")
        .join(format!("pre-provider-fallback-remove-{timestamp}.json"));
    atomic_write_service(&replaced, &current_body)?;
    atomic_write_service(&current, &updated)?;
    print_json(ProviderFallbackRemovalResponse {
        provider_id: provider_id.to_owned(),
        removed_ordinal: index + 1,
        credential_retained: removed_secret_id.is_some(),
        removed_secret_id,
        remaining_provider_ids,
        configuration_path: current.display().to_string(),
        replaced_configuration_copy: replaced.display().to_string(),
        restart_required: true,
    })
}

fn provider_config_id(provider: &ProviderConfig) -> Result<&str, CliError> {
    match provider {
        ProviderConfig::OpenAiResponses { provider_id, .. }
        | ProviderConfig::AnthropicMessages { provider_id, .. }
        | ProviderConfig::SubscriptionCli { provider_id, .. } => Ok(provider_id),
        ProviderConfig::BuiltinFixture => Err(CliError::InvalidProviderConfiguration),
    }
}

fn provider_config_secret_id(provider: &ProviderConfig) -> Option<&str> {
    match provider {
        ProviderConfig::OpenAiResponses { credential, .. }
        | ProviderConfig::AnthropicMessages { credential, .. } => match credential {
            Some(ProviderCredentialReference::Broker { secret_id }) => Some(secret_id),
            Some(ProviderCredentialReference::Environment { .. }) | None => None,
        },
        ProviderConfig::SubscriptionCli { .. } | ProviderConfig::BuiltinFixture => None,
    }
}

fn provider_configuration_identity(
    provider: ProviderConfig,
) -> Result<(&'static str, String, String, bool), CliError> {
    match provider {
        ProviderConfig::OpenAiResponses {
            provider_id,
            model,
            streaming,
            ..
        } => Ok(("openai_responses", provider_id, model, streaming)),
        ProviderConfig::AnthropicMessages {
            provider_id,
            model,
            streaming,
            ..
        } => Ok(("anthropic_messages", provider_id, model, streaming)),
        ProviderConfig::SubscriptionCli {
            provider_id,
            client,
            model,
            ..
        } => Ok((client.protocol(), provider_id, model, false)),
        ProviderConfig::BuiltinFixture => Err(CliError::InvalidProviderConfiguration),
    }
}

fn validate_provider_credential_import(
    provider: &ProviderConfig,
    credential_import: Option<ProviderCredentialImport<'_>>,
) -> Result<(), CliError> {
    let (base_url, credential) = match provider {
        ProviderConfig::OpenAiResponses {
            base_url,
            credential,
            ..
        }
        | ProviderConfig::AnthropicMessages {
            base_url,
            credential,
            ..
        } => (base_url, credential),
        ProviderConfig::SubscriptionCli { .. } if credential_import.is_none() => return Ok(()),
        ProviderConfig::SubscriptionCli { .. } | ProviderConfig::BuiltinFixture => {
            return Err(CliError::InvalidProviderConfiguration);
        }
    };
    let local =
        validate_provider_base_url(base_url).map_err(|_| CliError::InvalidProviderConfiguration)?;
    match (credential, credential_import) {
        (None, None) if local => Ok(()),
        (
            Some(ProviderCredentialReference::Broker { secret_id }),
            Some(ProviderCredentialImport {
                secret_id: imported_id,
                ..
            }),
        ) if secret_id == imported_id => Ok(()),
        _ => Err(CliError::InvalidProviderConfiguration),
    }
}

fn verify_provider_secret_preflight(
    store: &FileProviderSecretStore,
    secret_id: &str,
    credential: &str,
) -> Result<(), CliError> {
    match store.read(secret_id) {
        Ok(existing) if existing.as_str() != credential => {
            Err(ProviderSecretStoreError::Conflict.into())
        }
        Ok(_) | Err(ProviderSecretStoreError::NotFound) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn revoke_provider_secret(home: &Path, secret_id: &str, approve: bool) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    if !valid_provider_secret_id(secret_id) {
        return Err(ProviderSecretStoreError::InvalidSecretId.into());
    }
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let config = fs::read(home.join("config.json"))?;
    let value = serde_json::from_slice::<Value>(&config)?;
    let object = value
        .as_object()
        .ok_or(CliError::InvalidProviderConfiguration)?;
    if !valid_daemon_config_keys(object)
        || object.get("formatVersion").and_then(Value::as_u64) != Some(1)
    {
        return Err(CliError::InvalidProviderConfiguration);
    }
    if json_references_secret_id(&value, secret_id) {
        return Err(CliError::ProviderSecretInUse(secret_id.to_owned()));
    }
    let store = FileProviderSecretStore::new(home.join("provider-secrets"))?;
    let removed = match store.read(secret_id) {
        Ok(_) => {
            store.remove(secret_id)?;
            true
        }
        Err(ProviderSecretStoreError::NotFound) => false,
        Err(error) => return Err(error.into()),
    };
    let configuration_history_may_reference = fs::read_dir(home.join("config-history"))
        .ok()
        .is_some_and(|mut entries| entries.next().is_some());
    print_json(ProviderSecretRevocationResponse {
        secret_id: secret_id.to_owned(),
        removed,
        active_reference_check: "unreferenced".to_owned(),
        configuration_history_may_reference,
        service_action: "none_daemon_already_stopped".to_owned(),
    })
}

fn json_references_secret_id(value: &Value, secret_id: &str) -> bool {
    match value {
        Value::Object(object) => {
            object.get("secretId").and_then(Value::as_str) == Some(secret_id)
                || object
                    .values()
                    .any(|value| json_references_secret_id(value, secret_id))
        }
        Value::Array(values) => values
            .iter()
            .any(|value| json_references_secret_id(value, secret_id)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

fn probe_provider_connectivity(
    provider: &ProviderConfig,
    credential: Option<&str>,
) -> Result<(), CliError> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| probe_provider_connectivity_blocking(provider, credential))
            .join()
            .map_err(|_| {
                CliError::ProviderConnectivity("provider probe worker failed".to_owned())
            })?
    })
}

fn probe_provider_connectivity_blocking(
    provider: &ProviderConfig,
    credential: Option<&str>,
) -> Result<(), CliError> {
    match provider {
        ProviderConfig::OpenAiResponses {
            base_url,
            model,
            context_tokens,
            maximum_output_tokens,
            streaming,
            ..
        } => probe_responses_connectivity_blocking(
            base_url,
            model,
            *context_tokens,
            *maximum_output_tokens,
            *streaming,
            credential,
        ),
        ProviderConfig::AnthropicMessages {
            base_url,
            model,
            context_tokens,
            maximum_output_tokens,
            streaming,
            ..
        } => probe_anthropic_connectivity_blocking(
            base_url,
            model,
            *context_tokens,
            *maximum_output_tokens,
            *streaming,
            credential,
        ),
        ProviderConfig::SubscriptionCli {
            provider_id,
            client,
            executable_path,
            executable_sha256,
            model,
            residency,
            context_tokens,
            maximum_output_tokens,
            ..
        } => probe_subscription_connectivity_blocking(
            provider_id,
            *client,
            executable_path,
            executable_sha256,
            model,
            residency,
            *context_tokens,
            *maximum_output_tokens,
        ),
        ProviderConfig::BuiltinFixture => Err(CliError::InvalidProviderConfiguration),
    }
}

struct SubscriptionProbeCancellation;

impl CancellationProbe for SubscriptionProbeCancellation {
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[allow(clippy::too_many_arguments)]
fn probe_subscription_connectivity_blocking(
    provider_id: &str,
    client: SubscriptionCliClient,
    executable_path: &str,
    executable_sha256: &str,
    model: &str,
    residency: &str,
    context_tokens: u64,
    maximum_output_tokens: u64,
) -> Result<(), CliError> {
    let provider = SubscriptionCliProvider::new(SubscriptionCliSettings {
        provider_id: provider_id.to_owned(),
        client,
        executable_path: executable_path.into(),
        executable_sha256: executable_sha256.to_owned(),
        model: model.to_owned(),
        residency: residency.to_owned(),
        context_tokens,
        maximum_output_tokens,
        maximum_concurrent_requests: 1,
        requests_per_minute: 1,
    })
    .map_err(|_| {
        CliError::ProviderConnectivity(
            "official subscription client identity is unavailable".to_owned(),
        )
    })?;
    let now_ms = unix_timestamp_millis()?;
    let deadline_at_ms = now_ms
        .checked_add(180_000)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(|| {
            CliError::ProviderConnectivity("subscription probe deadline overflowed".to_owned())
        })?;
    let request = ProviderRequest {
        run_id: RunId::new(),
        attempt_id: AttemptId::new(),
        context_manifest_id: ContextManifestId::new(),
        provider_id: provider_id.to_owned(),
        model_id: model.to_owned(),
        messages: vec![NormalizedMessage {
            role: MessageRole::User,
            content: "Reply with the single word OK. This is a bounded connectivity test."
                .to_owned(),
            tool_call_id: None,
        }],
        tools: Vec::new(),
        maximum_output_tokens: maximum_output_tokens.min(SUBSCRIPTION_PROBE_MAXIMUM_OUTPUT_TOKENS),
        deadline_at_ms,
    };
    let output = provider
        .complete(&request, &SubscriptionProbeCancellation)
        .map_err(|error| {
            CliError::ProviderConnectivity(format!(
                "official subscription client returned {}",
                error.class.as_str()
            ))
        })?;
    if !matches!(output.response, ProviderResponse::Final { ref text } if !text.is_empty()) {
        return Err(CliError::ProviderConnectivity(
            "official subscription client did not return bounded final text".to_owned(),
        ));
    }
    Ok(())
}

fn provider_probe_client() -> Result<reqwest::blocking::Client, CliError> {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| CliError::ProviderConnectivity("HTTP client unavailable".to_owned()))
}

fn probe_responses_connectivity_blocking(
    base_url: &str,
    model: &str,
    context_tokens: u64,
    maximum_output_tokens: u64,
    streaming: bool,
    credential: Option<&str>,
) -> Result<(), CliError> {
    let probe_output_tokens = maximum_output_tokens.min(PROVIDER_PROBE_MAXIMUM_OUTPUT_TOKENS);
    let base = reqwest::Url::parse(&format!("{}/", base_url.trim_end_matches('/')))
        .map_err(|_| CliError::InvalidProviderConfiguration)?;
    let url = base
        .join("responses")
        .map_err(|_| CliError::InvalidProviderConfiguration)?;
    let mut request = provider_probe_client()?
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(
            reqwest::header::ACCEPT,
            if streaming {
                "text/event-stream"
            } else {
                "application/json"
            },
        )
        .header(
            reqwest::header::USER_AGENT,
            concat!("mealyctl/", env!("CARGO_PKG_VERSION")),
        );
    if let Some(credential) = credential {
        request = request.bearer_auth(credential);
    }
    let response = request
        .json(&json!({
            "model": model,
            "input": [{
                "role": "user",
                "content": "Reply with the single word OK. This is a bounded connectivity test."
            }],
            "tools": [],
            "tool_choice": "none",
            "parallel_tool_calls": false,
            "max_output_tokens": probe_output_tokens,
            "store": false,
            "stream": streaming,
            "truncation": "disabled"
        }))
        .send()
        .map_err(|_| CliError::ProviderConnectivity("provider transport unavailable".to_owned()))?;
    if !response.status().is_success() {
        return Err(CliError::ProviderConnectivity(format!(
            "provider returned HTTP status {}",
            response.status().as_u16()
        )));
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    let body = read_provider_probe_body(response)?;
    if streaming {
        if !content_type.eq_ignore_ascii_case("text/event-stream") {
            return Err(CliError::ProviderConnectivity(
                "provider did not return Responses SSE".to_owned(),
            ));
        }
        validate_provider_probe_stream(&body, model, context_tokens, probe_output_tokens)
    } else {
        if !content_type.eq_ignore_ascii_case("application/json") {
            return Err(CliError::ProviderConnectivity(
                "provider did not return Responses JSON".to_owned(),
            ));
        }
        let envelope = serde_json::from_slice::<Value>(&body).map_err(|_| {
            CliError::ProviderConnectivity("provider returned malformed response JSON".to_owned())
        })?;
        validate_provider_probe_envelope(&envelope, model, context_tokens, probe_output_tokens)
    }
}

fn probe_anthropic_connectivity_blocking(
    base_url: &str,
    model: &str,
    context_tokens: u64,
    maximum_output_tokens: u64,
    streaming: bool,
    credential: Option<&str>,
) -> Result<(), CliError> {
    let probe_output_tokens = maximum_output_tokens.min(PROVIDER_PROBE_MAXIMUM_OUTPUT_TOKENS);
    let base = reqwest::Url::parse(&format!("{}/", base_url.trim_end_matches('/')))
        .map_err(|_| CliError::InvalidProviderConfiguration)?;
    let url = base
        .join("messages")
        .map_err(|_| CliError::InvalidProviderConfiguration)?;
    let mut request = provider_probe_client()?
        .post(url)
        .header("anthropic-version", "2023-06-01")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(
            reqwest::header::ACCEPT,
            if streaming {
                "text/event-stream"
            } else {
                "application/json"
            },
        )
        .header(
            reqwest::header::USER_AGENT,
            concat!("mealyctl/", env!("CARGO_PKG_VERSION")),
        );
    if let Some(credential) = credential {
        request = request.header("x-api-key", credential);
    }
    let response = request
        .json(&json!({
            "model": model,
            "max_tokens": probe_output_tokens,
            "messages": [{
                "role": "user",
                "content": "Reply with the single word OK. This is a bounded connectivity test."
            }],
            "stream": streaming
        }))
        .send()
        .map_err(|_| CliError::ProviderConnectivity("provider transport unavailable".to_owned()))?;
    if !response.status().is_success() {
        return Err(CliError::ProviderConnectivity(format!(
            "provider returned HTTP status {}",
            response.status().as_u16()
        )));
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    let body = read_provider_probe_body(response)?;
    if streaming {
        if !content_type.eq_ignore_ascii_case("text/event-stream") {
            return Err(CliError::ProviderConnectivity(
                "provider did not return Anthropic Messages SSE".to_owned(),
            ));
        }
        validate_anthropic_probe_stream(&body, model, context_tokens, probe_output_tokens)
    } else {
        if !content_type.eq_ignore_ascii_case("application/json") {
            return Err(CliError::ProviderConnectivity(
                "provider did not return Anthropic Messages JSON".to_owned(),
            ));
        }
        let envelope = serde_json::from_slice::<Value>(&body).map_err(|_| {
            CliError::ProviderConnectivity("provider returned malformed response JSON".to_owned())
        })?;
        validate_anthropic_probe_envelope(&envelope, model, context_tokens, probe_output_tokens)
    }
}

fn read_provider_probe_body(
    mut response: reqwest::blocking::Response,
) -> Result<Vec<u8>, CliError> {
    if response
        .content_length()
        .is_some_and(|length| length > PROVIDER_PROBE_MAXIMUM_BYTES)
    {
        return Err(CliError::ProviderConnectivity(
            "provider connectivity response exceeded its byte bound".to_owned(),
        ));
    }
    let mut body = Vec::new();
    response
        .by_ref()
        .take(PROVIDER_PROBE_MAXIMUM_BYTES.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|_| {
            CliError::ProviderConnectivity(
                "provider connectivity response could not be read".to_owned(),
            )
        })?;
    if u64::try_from(body.len()).unwrap_or(u64::MAX) > PROVIDER_PROBE_MAXIMUM_BYTES {
        return Err(CliError::ProviderConnectivity(
            "provider connectivity response exceeded its byte bound".to_owned(),
        ));
    }
    Ok(body)
}

fn validate_provider_probe_stream(
    body: &[u8],
    expected_model: &str,
    context_tokens: u64,
    maximum_output_tokens: u64,
) -> Result<(), CliError> {
    let body = std::str::from_utf8(body).map_err(|_| {
        CliError::ProviderConnectivity("provider SSE was not valid UTF-8".to_owned())
    })?;
    let mut streamed_text = String::new();
    for line in body.lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.strip_prefix(' ').unwrap_or(data);
        if data == "[DONE]" {
            continue;
        }
        let event = serde_json::from_str::<Value>(data).map_err(|_| {
            CliError::ProviderConnectivity("provider SSE contained malformed JSON".to_owned())
        })?;
        match event.get("type").and_then(Value::as_str) {
            Some("response.output_text.delta" | "response.refusal.delta") => {
                let delta = event.get("delta").and_then(Value::as_str).ok_or_else(|| {
                    CliError::ProviderConnectivity(
                        "provider connectivity stream returned a malformed text delta".to_owned(),
                    )
                })?;
                if streamed_text.len().saturating_add(delta.len())
                    > PROVIDER_PROBE_MAXIMUM_TEXT_BYTES
                {
                    return Err(CliError::ProviderConnectivity(
                        "provider connectivity text exceeded its byte bound".to_owned(),
                    ));
                }
                streamed_text.push_str(delta);
            }
            Some("response.completed") => {
                let terminal_text = provider_probe_response_text(
                    event.get("response").ok_or_else(|| {
                        CliError::ProviderConnectivity(
                            "provider completion event omitted its response".to_owned(),
                        )
                    })?,
                    expected_model,
                    context_tokens,
                    maximum_output_tokens,
                )?;
                if !streamed_text.is_empty() && terminal_text != streamed_text {
                    return Err(CliError::ProviderConnectivity(
                        "provider connectivity stream disagreed with its terminal response"
                            .to_owned(),
                    ));
                }
                return Ok(());
            }
            Some("response.failed" | "response.incomplete" | "error") => {
                return Err(CliError::ProviderConnectivity(
                    "provider connectivity test did not complete".to_owned(),
                ));
            }
            Some(_) => {}
            None => {
                return Err(CliError::ProviderConnectivity(
                    "provider SSE event omitted its type".to_owned(),
                ));
            }
        }
    }
    Err(CliError::ProviderConnectivity(
        "provider SSE ended before response.completed".to_owned(),
    ))
}

fn validate_provider_probe_envelope(
    envelope: &Value,
    expected_model: &str,
    context_tokens: u64,
    maximum_output_tokens: u64,
) -> Result<(), CliError> {
    provider_probe_response_text(
        envelope,
        expected_model,
        context_tokens,
        maximum_output_tokens,
    )
    .map(|_| ())
}

fn provider_probe_response_text(
    envelope: &Value,
    expected_model: &str,
    context_tokens: u64,
    maximum_output_tokens: u64,
) -> Result<String, CliError> {
    let valid_id = envelope
        .get("id")
        .and_then(Value::as_str)
        .is_some_and(|value| valid_provider_discovery_text(value, 512));
    let valid_identity = envelope.get("object").and_then(Value::as_str) == Some("response")
        && envelope.get("model").and_then(Value::as_str) == Some(expected_model);
    let completed = envelope.get("status").and_then(Value::as_str) == Some("completed");
    let error_free = envelope.get("error").is_none_or(Value::is_null);
    if !valid_id || !valid_identity || !completed || !error_free {
        return Err(CliError::ProviderConnectivity(
            "provider did not return a completed bounded response".to_owned(),
        ));
    }
    let output = envelope
        .get("output")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CliError::ProviderConnectivity(
                "provider did not return a completed bounded response".to_owned(),
            )
        })?;
    let mut text = String::new();
    for item in output {
        match item.get("type").and_then(Value::as_str) {
            Some("message") => {
                if item.get("role").and_then(Value::as_str) != Some("assistant") {
                    return Err(CliError::ProviderConnectivity(
                        "provider did not return a completed bounded response".to_owned(),
                    ));
                }
                let content = item
                    .get("content")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        CliError::ProviderConnectivity(
                            "provider did not return a completed bounded response".to_owned(),
                        )
                    })?;
                for part in content {
                    let value = match part.get("type").and_then(Value::as_str) {
                        Some("output_text") => part.get("text").and_then(Value::as_str),
                        Some("refusal") => part.get("refusal").and_then(Value::as_str),
                        Some(_) | None => continue,
                    }
                    .ok_or_else(|| {
                        CliError::ProviderConnectivity(
                            "provider did not return a completed bounded response".to_owned(),
                        )
                    })?;
                    if text.len().saturating_add(value.len()) > PROVIDER_PROBE_MAXIMUM_TEXT_BYTES {
                        return Err(CliError::ProviderConnectivity(
                            "provider connectivity text exceeded its byte bound".to_owned(),
                        ));
                    }
                    text.push_str(value);
                }
            }
            Some("function_call") => {
                return Err(CliError::ProviderConnectivity(
                    "provider connectivity test unexpectedly requested a tool".to_owned(),
                ));
            }
            Some(_) | None => {}
        }
    }
    if text.trim().is_empty() {
        return Err(CliError::ProviderConnectivity(
            "provider did not return a completed bounded response".to_owned(),
        ));
    }
    if let Some(usage) = envelope.get("usage").filter(|usage| !usage.is_null()) {
        let input = usage.get("input_tokens").and_then(Value::as_u64);
        let output = usage.get("output_tokens").and_then(Value::as_u64);
        let total = usage.get("total_tokens").and_then(Value::as_u64);
        if input.is_none_or(|tokens| tokens > context_tokens)
            || output.is_none_or(|tokens| tokens > maximum_output_tokens)
            || input.and_then(|input| input.checked_add(output.unwrap_or_default())) != total
        {
            return Err(CliError::ProviderConnectivity(
                "provider connectivity usage was inconsistent".to_owned(),
            ));
        }
    }
    Ok(text)
}

#[allow(clippy::too_many_lines)]
fn validate_anthropic_probe_stream(
    body: &[u8],
    expected_model: &str,
    context_tokens: u64,
    maximum_output_tokens: u64,
) -> Result<(), CliError> {
    let body = std::str::from_utf8(body).map_err(|_| {
        CliError::ProviderConnectivity("provider SSE was not valid UTF-8".to_owned())
    })?;
    let mut started = false;
    let mut text_block_index = None;
    let mut text_stopped = false;
    let mut text_bytes = 0_usize;
    let mut terminal_reason = false;
    let mut initial_output_tokens = None;
    for line in body.lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.strip_prefix(' ').unwrap_or(data);
        let event = serde_json::from_str::<Value>(data).map_err(|_| {
            CliError::ProviderConnectivity("provider SSE contained malformed JSON".to_owned())
        })?;
        match event.get("type").and_then(Value::as_str) {
            Some("message_start") => {
                if started
                    || !anthropic_probe_identity_valid(
                        event.get("message").unwrap_or(&Value::Null),
                        expected_model,
                        context_tokens,
                        maximum_output_tokens,
                    )
                    || !event
                        .pointer("/message/content")
                        .and_then(Value::as_array)
                        .is_some_and(Vec::is_empty)
                {
                    return Err(CliError::ProviderConnectivity(
                        "provider message_start was invalid".to_owned(),
                    ));
                }
                started = true;
                initial_output_tokens = event
                    .pointer("/message/usage/output_tokens")
                    .and_then(Value::as_u64);
            }
            Some("content_block_start") => {
                let index = event.get("index").and_then(Value::as_u64);
                if !started
                    || text_block_index.is_some()
                    || terminal_reason
                    || index.is_none()
                    || event.pointer("/content_block/type").and_then(Value::as_str) != Some("text")
                {
                    return Err(CliError::ProviderConnectivity(
                        "provider connectivity stream returned an invalid content block".to_owned(),
                    ));
                }
                text_block_index = index;
                text_bytes = event
                    .pointer("/content_block/text")
                    .and_then(Value::as_str)
                    .map_or(0, str::len);
                if text_bytes > PROVIDER_PROBE_MAXIMUM_TEXT_BYTES {
                    return Err(CliError::ProviderConnectivity(
                        "provider connectivity text exceeded its byte bound".to_owned(),
                    ));
                }
            }
            Some("content_block_delta") => {
                if text_block_index.is_none()
                    || text_block_index != event.get("index").and_then(Value::as_u64)
                    || text_stopped
                {
                    return Err(CliError::ProviderConnectivity(
                        "provider connectivity stream returned an out-of-order delta".to_owned(),
                    ));
                }
                let delta = event
                    .pointer("/delta/text")
                    .and_then(Value::as_str)
                    .filter(|_| {
                        event.pointer("/delta/type").and_then(Value::as_str) == Some("text_delta")
                    })
                    .ok_or_else(|| {
                        CliError::ProviderConnectivity(
                            "provider connectivity stream returned a malformed delta".to_owned(),
                        )
                    })?;
                text_bytes = text_bytes.saturating_add(delta.len());
                if text_bytes > PROVIDER_PROBE_MAXIMUM_TEXT_BYTES {
                    return Err(CliError::ProviderConnectivity(
                        "provider connectivity text exceeded its byte bound".to_owned(),
                    ));
                }
            }
            Some("content_block_stop") => {
                if text_block_index.is_none()
                    || text_block_index != event.get("index").and_then(Value::as_u64)
                    || text_stopped
                {
                    return Err(CliError::ProviderConnectivity(
                        "provider connectivity stream returned an invalid block stop".to_owned(),
                    ));
                }
                text_stopped = true;
            }
            Some("message_delta") => {
                let reason = event.pointer("/delta/stop_reason").and_then(Value::as_str);
                let output = event
                    .pointer("/usage/output_tokens")
                    .and_then(Value::as_u64);
                if !started
                    || !text_stopped
                    || terminal_reason
                    || !matches!(reason, Some("end_turn" | "stop_sequence" | "refusal"))
                    || output.is_none_or(|tokens| {
                        tokens > maximum_output_tokens
                            || initial_output_tokens.is_some_and(|initial| tokens < initial)
                    })
                {
                    return Err(CliError::ProviderConnectivity(
                        "provider connectivity stream returned an invalid terminal delta"
                            .to_owned(),
                    ));
                }
                terminal_reason = true;
            }
            Some("message_stop") => {
                if started && text_stopped && text_bytes != 0 && terminal_reason {
                    return Ok(());
                }
                return Err(CliError::ProviderConnectivity(
                    "provider connectivity stream stopped before a bounded response".to_owned(),
                ));
            }
            Some("error") => {
                return Err(CliError::ProviderConnectivity(
                    "provider connectivity stream reported an error".to_owned(),
                ));
            }
            Some("ping" | _) => {}
            None => {
                return Err(CliError::ProviderConnectivity(
                    "provider SSE event omitted its type".to_owned(),
                ));
            }
        }
    }
    Err(CliError::ProviderConnectivity(
        "provider SSE ended before message_stop".to_owned(),
    ))
}

fn validate_anthropic_probe_envelope(
    envelope: &Value,
    expected_model: &str,
    context_tokens: u64,
    maximum_output_tokens: u64,
) -> Result<(), CliError> {
    if !anthropic_probe_identity_valid(
        envelope,
        expected_model,
        context_tokens,
        maximum_output_tokens,
    ) {
        return Err(CliError::ProviderConnectivity(
            "provider did not return a valid Anthropic message".to_owned(),
        ));
    }
    let stop_reason = envelope.get("stop_reason").and_then(Value::as_str);
    let mut text_bytes = 0_usize;
    let content_valid = envelope
        .get("content")
        .and_then(Value::as_array)
        .is_some_and(|blocks| {
            !blocks.is_empty()
                && blocks.iter().all(|block| {
                    let Some(text) = block
                        .get("text")
                        .and_then(Value::as_str)
                        .filter(|_| block.get("type").and_then(Value::as_str) == Some("text"))
                    else {
                        return false;
                    };
                    text_bytes = text_bytes.saturating_add(text.len());
                    text_bytes <= PROVIDER_PROBE_MAXIMUM_TEXT_BYTES
                })
        });
    if content_valid
        && text_bytes != 0
        && matches!(stop_reason, Some("end_turn" | "stop_sequence" | "refusal"))
    {
        Ok(())
    } else {
        Err(CliError::ProviderConnectivity(
            "provider did not return a completed bounded Anthropic response".to_owned(),
        ))
    }
}

fn anthropic_probe_identity_valid(
    message: &Value,
    expected_model: &str,
    context_tokens: u64,
    maximum_output_tokens: u64,
) -> bool {
    message.get("type").and_then(Value::as_str) == Some("message")
        && message.get("role").and_then(Value::as_str) == Some("assistant")
        && message
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|value| valid_provider_discovery_text(value, 512))
        && message.get("model").and_then(Value::as_str) == Some(expected_model)
        && message
            .pointer("/usage/input_tokens")
            .and_then(Value::as_u64)
            .is_some_and(|tokens| tokens <= context_tokens)
        && message
            .pointer("/usage/output_tokens")
            .and_then(Value::as_u64)
            .is_some_and(|tokens| tokens <= maximum_output_tokens)
        && message
            .pointer("/usage/cache_creation_input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            == 0
        && message
            .pointer("/usage/cache_read_input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            == 0
}

fn valid_daemon_config_keys(object: &serde_json::Map<String, serde_json::Value>) -> bool {
    (DAEMON_CONFIG_KEYS.len()..=DAEMON_CONFIG_KEYS.len() + DAEMON_OPTIONAL_CONFIG_KEYS.len())
        .contains(&object.len())
        && DAEMON_CONFIG_KEYS
            .iter()
            .all(|key| object.contains_key(*key))
        && object.keys().all(|key| {
            DAEMON_CONFIG_KEYS.contains(&key.as_str())
                || DAEMON_OPTIONAL_CONFIG_KEYS.contains(&key.as_str())
        })
}

fn configure_workspace_grant(
    home: &Path,
    workspace_id: &str,
    root: &Path,
    approve: bool,
) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    validate_workspace_identity(workspace_id)?;
    let canonical_root = root.canonicalize()?;
    let metadata = fs::symlink_metadata(&canonical_root)?;
    let root_text = canonical_root
        .to_str()
        .filter(|value| value.len() <= 4_096 && !value.chars().any(char::is_control))
        .ok_or(CliError::InvalidWorkspaceConfiguration)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(CliError::InvalidWorkspaceConfiguration);
    }
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let canonical_home = fs::canonicalize(&home)?;
    if paths_overlap(&canonical_root, &canonical_home) {
        return Err(CliError::InvalidWorkspaceConfiguration);
    }
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let mut value = serde_json::from_slice::<serde_json::Value>(&current_body)?;
    let object = value
        .as_object_mut()
        .filter(|object| valid_daemon_config_keys(object))
        .ok_or(CliError::InvalidWorkspaceConfiguration)?;
    let mut workspaces = object
        .get("workspaceRoots")
        .cloned()
        .map(serde_json::from_value::<Vec<serde_json::Value>>)
        .transpose()?
        .unwrap_or_default();
    if workspaces.len() >= 16
        || workspaces.iter().any(|workspace| {
            workspace
                .get("workspaceId")
                .and_then(serde_json::Value::as_str)
                == Some(workspace_id)
                || workspace.get("root").and_then(serde_json::Value::as_str) == Some(root_text)
        })
    {
        return Err(CliError::InvalidWorkspaceConfiguration);
    }
    workspaces.push(serde_json::json!({"workspaceId": workspace_id, "root": root_text}));
    workspaces.sort_by(|left, right| {
        left["workspaceId"]
            .as_str()
            .cmp(&right["workspaceId"].as_str())
    });
    object.insert("workspaceRoots".to_owned(), Value::Array(workspaces));
    publish_workspace_configuration(
        &home,
        &current,
        &current_body,
        &value,
        workspace_id,
        Some(root_text),
        "granted",
    )
}

fn configure_workspace_revoke(
    home: &Path,
    workspace_id: &str,
    approve: bool,
) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    validate_workspace_identity(workspace_id)?;
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let mut value = serde_json::from_slice::<serde_json::Value>(&current_body)?;
    let object = value
        .as_object_mut()
        .filter(|object| valid_daemon_config_keys(object))
        .ok_or(CliError::InvalidWorkspaceConfiguration)?;
    let mut workspaces = object
        .get("workspaceRoots")
        .cloned()
        .map(serde_json::from_value::<Vec<serde_json::Value>>)
        .transpose()?
        .unwrap_or_default();
    let prior = workspaces.len();
    workspaces.retain(|workspace| {
        workspace
            .get("workspaceId")
            .and_then(serde_json::Value::as_str)
            != Some(workspace_id)
    });
    if workspaces.len() == prior {
        return Err(CliError::WorkspaceNotFound(workspace_id.to_owned()));
    }
    if workspaces.is_empty() {
        object.remove("workspaceRoots");
    } else {
        object.insert("workspaceRoots".to_owned(), Value::Array(workspaces));
    }
    publish_workspace_configuration(
        &home,
        &current,
        &current_body,
        &value,
        workspace_id,
        None,
        "revoked",
    )
}

fn configure_workspace_write(
    home: &Path,
    workspace_id: &str,
    writable: bool,
    approve: bool,
) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    validate_workspace_identity(workspace_id)?;
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let mut value = serde_json::from_slice::<serde_json::Value>(&current_body)?;
    let object = value
        .as_object_mut()
        .filter(|object| valid_daemon_config_keys(object))
        .ok_or(CliError::InvalidWorkspaceConfiguration)?;
    let workspaces = object
        .get_mut("workspaceRoots")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| CliError::WorkspaceNotFound(workspace_id.to_owned()))?;
    let workspace = workspaces
        .iter_mut()
        .find(|workspace| {
            workspace
                .get("workspaceId")
                .and_then(serde_json::Value::as_str)
                == Some(workspace_id)
        })
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| CliError::WorkspaceNotFound(workspace_id.to_owned()))?;
    let currently_writable = workspace
        .get("writable")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if currently_writable == writable {
        return Err(CliError::InvalidWorkspaceConfiguration);
    }
    if writable {
        workspace.insert("writable".to_owned(), Value::Bool(true));
    } else {
        workspace.remove("writable");
    }
    publish_workspace_configuration(
        &home,
        &current,
        &current_body,
        &value,
        workspace_id,
        None,
        if writable {
            "write_enabled"
        } else {
            "write_disabled"
        },
    )
}

fn configure_process_grant(
    home: &Path,
    command_id: &str,
    executable: &Path,
    approve: bool,
) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    validate_command_identity(command_id)?;
    let (canonical_executable, executable_digest, _) =
        inspect_mcp_executable(executable).map_err(|_| CliError::InvalidCommandConfiguration)?;
    let executable_text = canonical_executable
        .to_str()
        .filter(|value| value.len() <= 4_096 && !value.chars().any(char::is_control))
        .ok_or(CliError::InvalidCommandConfiguration)?;
    if !is_trusted_system_executable(&canonical_executable) {
        return Err(CliError::InvalidCommandConfiguration);
    }
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let mut value = serde_json::from_slice::<Value>(&current_body)?;
    let object = value
        .as_object_mut()
        .filter(|object| valid_daemon_config_keys(object))
        .ok_or(CliError::InvalidCommandConfiguration)?;
    let writable_workspace = object
        .get("workspaceRoots")
        .and_then(Value::as_array)
        .is_some_and(|workspaces| {
            workspaces
                .iter()
                .any(|workspace| workspace.get("writable").and_then(Value::as_bool) == Some(true))
        });
    if !writable_workspace {
        return Err(CliError::InvalidCommandConfiguration);
    }
    let mut commands = object
        .get("commandTools")
        .cloned()
        .map(serde_json::from_value::<Vec<Value>>)
        .transpose()?
        .unwrap_or_default();
    if commands.len() >= 16
        || commands.iter().any(|command| {
            command.get("commandId").and_then(Value::as_str) == Some(command_id)
                || command.get("executable").and_then(Value::as_str) == Some(executable_text)
                || command.get("executableDigest").and_then(Value::as_str)
                    == Some(executable_digest.as_str())
        })
    {
        return Err(CliError::InvalidCommandConfiguration);
    }
    commands.push(json!({
        "commandId": command_id,
        "executable": executable_text,
        "executableDigest": executable_digest,
    }));
    commands.sort_by(|left, right| left["commandId"].as_str().cmp(&right["commandId"].as_str()));
    object.insert("commandTools".to_owned(), Value::Array(commands));
    publish_process_configuration(
        &home,
        &current,
        &current_body,
        &value,
        command_id,
        Some(executable_digest),
        "granted",
    )
}

fn configure_process_revoke(home: &Path, command_id: &str, approve: bool) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    validate_command_identity(command_id)?;
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let mut value = serde_json::from_slice::<Value>(&current_body)?;
    let object = value
        .as_object_mut()
        .filter(|object| valid_daemon_config_keys(object))
        .ok_or(CliError::InvalidCommandConfiguration)?;
    let mut commands = object
        .get("commandTools")
        .cloned()
        .map(serde_json::from_value::<Vec<Value>>)
        .transpose()?
        .unwrap_or_default();
    let prior = commands.len();
    commands.retain(|command| command.get("commandId").and_then(Value::as_str) != Some(command_id));
    if commands.len() == prior {
        return Err(CliError::CommandNotFound(command_id.to_owned()));
    }
    if commands.is_empty() {
        object.remove("commandTools");
    } else {
        object.insert("commandTools".to_owned(), Value::Array(commands));
    }
    publish_process_configuration(
        &home,
        &current,
        &current_body,
        &value,
        command_id,
        None,
        "revoked",
    )
}

#[allow(clippy::too_many_arguments)]
fn publish_process_configuration(
    home: &Path,
    current: &Path,
    current_body: &[u8],
    value: &Value,
    command_id: &str,
    executable_digest: Option<String>,
    operation: &str,
) -> Result<(), CliError> {
    let timestamp = unix_timestamp_millis()?;
    let replaced = home
        .join("config-history")
        .join(format!("pre-process-{timestamp}.json"));
    atomic_write_service(&replaced, current_body)?;
    atomic_write_service(current, &serde_json::to_vec_pretty(value)?)?;
    print_json(ProcessConfigurationResponse {
        command_id: command_id.to_owned(),
        executable_digest,
        operation: operation.to_owned(),
        configuration_path: current.display().to_string(),
        replaced_configuration_copy: replaced.display().to_string(),
        restart_required: true,
    })
}

fn validate_command_identity(value: &str) -> Result<(), CliError> {
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('.')
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(CliError::InvalidCommandConfiguration);
    }
    Ok(())
}

fn publish_workspace_configuration(
    home: &Path,
    current: &Path,
    current_body: &[u8],
    value: &Value,
    workspace_id: &str,
    root: Option<&str>,
    operation: &str,
) -> Result<(), CliError> {
    let timestamp = unix_timestamp_millis()?;
    let replaced = home
        .join("config-history")
        .join(format!("pre-workspace-{timestamp}.json"));
    atomic_write_service(&replaced, current_body)?;
    atomic_write_service(current, &serde_json::to_vec_pretty(value)?)?;
    print_json(WorkspaceConfigurationResponse {
        workspace_id: workspace_id.to_owned(),
        canonical_root: root.map(str::to_owned),
        operation: operation.to_owned(),
        configuration_path: current.display().to_string(),
        replaced_configuration_copy: replaced.display().to_string(),
        restart_required: true,
        service_reinstall_required: false,
    })
}

fn validate_workspace_identity(value: &str) -> Result<(), CliError> {
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('.')
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(CliError::InvalidWorkspaceConfiguration);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn configure_web_access(
    home: &Path,
    allow_public_internet: bool,
    allowed_domains: &[String],
    allowed_origins: &[String],
    brave_secret_id: Option<&str>,
    brave_credential_env: &str,
    brave_base_url: &str,
    approve: bool,
) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    let mut allowed_domains = allowed_domains.to_vec();
    let mut allowed_origins = allowed_origins.to_vec();
    allowed_domains.sort();
    allowed_origins.sort();
    if allowed_domains.windows(2).any(|pair| pair[0] == pair[1])
        || allowed_origins.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(CliError::InvalidWebConfiguration);
    }
    let search = brave_secret_id.map(|secret_id| WebSearchConfig::Brave {
        base_url: brave_base_url.to_owned(),
        credential: ProviderCredentialReference::Broker {
            secret_id: secret_id.to_owned(),
        },
    });
    let config = WebAccessConfig {
        enabled: true,
        allow_public_internet,
        allowed_domains,
        allowed_origins,
        search,
    };
    config
        .validate()
        .map_err(|_| CliError::InvalidWebConfiguration)?;
    let credential = brave_secret_id
        .map(|_| read_provider_credential_environment(brave_credential_env))
        .transpose()?;
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let mut value = serde_json::from_slice::<serde_json::Value>(&current_body)?;
    let object = value
        .as_object_mut()
        .filter(|object| valid_daemon_config_keys(object))
        .ok_or(CliError::InvalidWebConfiguration)?;
    if let (Some(secret_id), Some(credential)) = (brave_secret_id, credential.as_deref()) {
        FileProviderSecretStore::new(home.join("provider-secrets"))?.put(secret_id, credential)?;
    }
    object.insert("webAccess".to_owned(), serde_json::to_value(&config)?);
    publish_web_configuration(
        &home,
        &current,
        &current_body,
        &value,
        "enabled",
        &config,
        brave_secret_id,
        false,
    )
}

fn configure_web_disable(home: &Path, approve: bool) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let mut value = serde_json::from_slice::<serde_json::Value>(&current_body)?;
    let object = value
        .as_object_mut()
        .filter(|object| valid_daemon_config_keys(object))
        .ok_or(CliError::InvalidWebConfiguration)?;
    if configured_browser(object)?.is_some_and(|browser| browser.enabled()) {
        return Err(CliError::BrowserRequiresWeb);
    }
    let prior = object
        .get("webAccess")
        .cloned()
        .map(serde_json::from_value::<WebAccessConfig>)
        .transpose()?
        .filter(|config| config.enabled)
        .ok_or(CliError::WebNotEnabled)?;
    let secret_id = prior
        .search
        .as_ref()
        .and_then(|search| match search.credential() {
            ProviderCredentialReference::Broker { secret_id } => Some(secret_id.as_str()),
            ProviderCredentialReference::Environment { .. } => None,
        });
    object.remove("webAccess");
    publish_web_configuration(
        &home,
        &current,
        &current_body,
        &value,
        "disabled",
        &WebAccessConfig::default(),
        secret_id,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn publish_web_configuration(
    home: &Path,
    current: &Path,
    current_body: &[u8],
    value: &Value,
    operation: &str,
    config: &WebAccessConfig,
    secret_id: Option<&str>,
    credential_retained_on_disable: bool,
) -> Result<(), CliError> {
    let timestamp = unix_timestamp_millis()?;
    let replaced = home
        .join("config-history")
        .join(format!("pre-web-{timestamp}.json"));
    atomic_write_service(&replaced, current_body)?;
    atomic_write_service(current, &serde_json::to_vec_pretty(value)?)?;
    print_json(WebConfigurationResponse {
        operation: operation.to_owned(),
        allow_public_internet: config.allow_public_internet,
        allowed_domains: config.allowed_domains.clone(),
        allowed_origins: config.allowed_origins.clone(),
        search_enabled: config.search.is_some(),
        secret_id: secret_id.map(str::to_owned),
        configuration_path: current.display().to_string(),
        replaced_configuration_copy: replaced.display().to_string(),
        restart_required: true,
        credential_retained_on_disable,
    })
}

fn inspect_browser_runtime(bundle: &Path) -> Result<(), CliError> {
    let inspection = inspect_browser_bundle(bundle, None)?;
    let probe = probe_browser_bundle_product(
        Path::new("/usr/bin/bwrap"),
        inspection.root(),
        Some(inspection.bundle_digest()),
    )?;
    print_json(BrowserInspectionResponse {
        bundle_digest: probe.bundle_digest().to_owned(),
        executable_digest: probe.executable_digest().to_owned(),
        product: probe.product().to_owned(),
        protocol_version: probe.protocol_version().to_owned(),
        isolation: "bubblewrap_empty_environment_no_network_no_home_no_personal_profile",
    })
}

fn configure_browser_add(home: &Path, bundle: &Path, approve: bool) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let home =
        exact_canonical_directory(&home).map_err(|_| CliError::InvalidBrowserConfiguration)?;
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let mut value = serde_json::from_slice::<Value>(&current_body)?;
    let object = value
        .as_object_mut()
        .filter(|object| valid_daemon_config_keys(object))
        .ok_or(CliError::InvalidBrowserConfiguration)?;
    if configured_browser(object)?.is_some() {
        return Err(CliError::InvalidBrowserConfiguration);
    }
    require_enabled_web_for_browser(object)?;
    let inspection = inspect_browser_bundle(bundle, None)?;
    let probe = probe_browser_bundle_product(
        Path::new("/usr/bin/bwrap"),
        inspection.root(),
        Some(inspection.bundle_digest()),
    )?;
    if probe.executable_digest() != inspection.executable_digest() {
        return Err(CliError::InvalidBrowserConfiguration);
    }
    let destination = publish_browser_bundle(&inspection, &home.join("browser-runtimes"))?;
    let browser = BrowserConfig::new(
        true,
        format!("browser-runtimes/{}", inspection.bundle_digest()),
        inspection.bundle_digest().to_owned(),
        "chrome-headless-shell".to_owned(),
        inspection.executable_digest().to_owned(),
        probe.product().to_owned(),
        probe.protocol_version().to_owned(),
    )
    .map_err(|_| CliError::InvalidBrowserConfiguration)?;
    if destination != home.join(browser.bundle_path()) {
        return Err(CliError::InvalidBrowserConfiguration);
    }
    let worker = fs::canonicalize(std::env::current_exe()?)?;
    verify_browser_runtime_installation(&home, Path::new("/usr/bin/bwrap"), &worker, &browser)?;
    object.insert("browser".to_owned(), serde_json::to_value(&browser)?);
    publish_browser_configuration(
        &home,
        &current,
        &current_body,
        &value,
        "installed_and_enabled",
        Some(browser),
        false,
    )
}

fn list_browser_runtime(home: &Path) -> Result<(), CliError> {
    let home = fs::canonicalize(home)?;
    let value = serde_json::from_slice::<Value>(&fs::read(home.join("config.json"))?)?;
    let object = value
        .as_object()
        .filter(|object| valid_daemon_config_keys(object))
        .ok_or(CliError::InvalidBrowserConfiguration)?;
    print_json(BrowserStatusResponse {
        browser: configured_browser(object)?,
        activation_note: "An enabled browser is exposed only after complete bundle verification; every call uses a fresh profile, private network namespace, and scoped GET/HEAD proxy.",
    })
}

fn configure_browser_enabled(home: &Path, enabled: bool, approve: bool) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let home =
        exact_canonical_directory(&home).map_err(|_| CliError::InvalidBrowserConfiguration)?;
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let mut value = serde_json::from_slice::<Value>(&current_body)?;
    let object = value
        .as_object_mut()
        .filter(|object| valid_daemon_config_keys(object))
        .ok_or(CliError::InvalidBrowserConfiguration)?;
    let mut browser = configured_browser(object)?.ok_or(CliError::BrowserNotFound)?;
    if browser.enabled() == enabled {
        return Err(CliError::InvalidBrowserConfiguration);
    }
    if enabled {
        require_enabled_web_for_browser(object)?;
        verify_configured_browser(&home, &browser)?;
    }
    browser = browser.with_enabled(enabled);
    object.insert("browser".to_owned(), serde_json::to_value(&browser)?);
    publish_browser_configuration(
        &home,
        &current,
        &current_body,
        &value,
        if enabled { "enabled" } else { "disabled" },
        Some(browser),
        true,
    )
}

fn configure_browser_revoke(home: &Path, approve: bool) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let home =
        exact_canonical_directory(&home).map_err(|_| CliError::InvalidBrowserConfiguration)?;
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let mut value = serde_json::from_slice::<Value>(&current_body)?;
    let object = value
        .as_object_mut()
        .filter(|object| valid_daemon_config_keys(object))
        .ok_or(CliError::InvalidBrowserConfiguration)?;
    configured_browser(object)?.ok_or(CliError::BrowserNotFound)?;
    object.remove("browser");
    publish_browser_configuration(
        &home,
        &current,
        &current_body,
        &value,
        "revoked",
        None,
        true,
    )
}

fn configured_browser(
    object: &serde_json::Map<String, Value>,
) -> Result<Option<BrowserConfig>, CliError> {
    let browser = object
        .get("browser")
        .cloned()
        .map(serde_json::from_value::<BrowserConfig>)
        .transpose()?;
    if browser
        .as_ref()
        .is_some_and(|config| config.validate().is_err())
    {
        return Err(CliError::InvalidBrowserConfiguration);
    }
    Ok(browser)
}

fn require_enabled_web_for_browser(
    object: &serde_json::Map<String, Value>,
) -> Result<(), CliError> {
    let web = object
        .get("webAccess")
        .cloned()
        .map(serde_json::from_value::<WebAccessConfig>)
        .transpose()?
        .unwrap_or_default();
    if !web.enabled || web.validate().is_err() {
        return Err(CliError::BrowserRequiresWeb);
    }
    Ok(())
}

fn verify_configured_browser(home: &Path, browser: &BrowserConfig) -> Result<(), CliError> {
    let bundle = home.join(browser.bundle_path());
    let inspection = inspect_browser_bundle(&bundle, Some(browser.bundle_digest()))?;
    let probe = probe_browser_bundle_product(
        Path::new("/usr/bin/bwrap"),
        &bundle,
        Some(browser.bundle_digest()),
    )?;
    if inspection.executable_digest() != browser.executable_digest()
        || probe.executable_digest() != browser.executable_digest()
        || probe.product() != browser.product()
        || probe.protocol_version() != browser.protocol_version()
    {
        return Err(CliError::InvalidBrowserConfiguration);
    }
    let worker = fs::canonicalize(std::env::current_exe()?)?;
    verify_browser_runtime_installation(home, Path::new("/usr/bin/bwrap"), &worker, browser)?;
    Ok(())
}

fn publish_browser_configuration(
    home: &Path,
    current: &Path,
    current_body: &[u8],
    value: &Value,
    operation: &str,
    browser: Option<BrowserConfig>,
    runtime_retained_for_rollback: bool,
) -> Result<(), CliError> {
    let timestamp = unix_timestamp_millis()?;
    let replaced = home
        .join("config-history")
        .join(format!("pre-browser-{timestamp}.json"));
    atomic_write_service(&replaced, current_body)?;
    atomic_write_service(current, &serde_json::to_vec_pretty(value)?)?;
    print_json(BrowserConfigurationResponse {
        operation: operation.to_owned(),
        browser,
        runtime_retained_for_rollback,
        configuration_path: current.display().to_string(),
        replaced_configuration_copy: replaced.display().to_string(),
        restart_required: true,
    })
}

fn inspect_mcp_server(
    server_id: &str,
    executable: &Path,
    arguments: &[String],
) -> Result<(), CliError> {
    let (executable, executable_digest, _) = inspect_mcp_executable(executable)?;
    let launcher = fs::canonicalize(std::env::current_exe()?)?;
    let discovery = discover_mcp_stdio_server(
        "/usr/bin/bwrap",
        launcher,
        server_id,
        executable,
        &executable_digest,
        arguments,
    )?;
    print_json(McpInspectionResponse {
        server_id: server_id.to_owned(),
        executable_digest,
        arguments: arguments.to_vec(),
        isolation: "bubblewrap_empty_environment_no_network_no_host_filesystem_no_child_processes",
        discovery,
    })
}

#[allow(clippy::too_many_arguments)]
fn configure_mcp_add(
    home: &Path,
    server_id: &str,
    executable: &Path,
    arguments: &[String],
    allow_tools: &[String],
    timeout_ms: u64,
    maximum_output_bytes: u64,
    approve: bool,
) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    if allow_tools.is_empty() || allow_tools.len() > 64 {
        return Err(CliError::InvalidMcpConfiguration);
    }
    let mut selected = allow_tools.to_vec();
    selected.sort();
    if selected.windows(2).any(|window| window[0] == window[1]) {
        return Err(CliError::InvalidMcpConfiguration);
    }
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let home = exact_canonical_directory(&home).map_err(|_| CliError::InvalidMcpConfiguration)?;
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let mut value = serde_json::from_slice::<Value>(&current_body)?;
    let object = value
        .as_object_mut()
        .filter(|object| valid_daemon_config_keys(object))
        .ok_or(CliError::InvalidMcpConfiguration)?;
    let mut servers = configured_mcp_servers(object)?;
    if servers.iter().any(|server| server.server_id() == server_id) {
        return Err(CliError::InvalidMcpConfiguration);
    }
    let (executable, executable_digest, executable_bytes) = inspect_mcp_executable(executable)?;
    let launcher = fs::canonicalize(std::env::current_exe()?)?;
    let discovery = discover_mcp_stdio_server(
        "/usr/bin/bwrap",
        launcher,
        server_id,
        &executable,
        &executable_digest,
        arguments,
    )?;
    let grants = selected
        .iter()
        .map(|name| {
            let tool = discovery
                .tool(name)
                .ok_or(CliError::InvalidMcpConfiguration)?;
            McpToolGrant::new(tool.definition.clone(), timeout_ms, maximum_output_bytes)
                .map_err(|_| CliError::InvalidMcpConfiguration)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let relative_path = format!("mcp-servers/{executable_digest}/server");
    let server = McpServerConfig::new(
        server_id.to_owned(),
        relative_path.clone(),
        executable_digest,
        arguments.to_vec(),
        discovery
            .toolset_digest()
            .map_err(|_| CliError::InvalidMcpConfiguration)?,
        true,
        grants,
    )
    .map_err(|_| CliError::InvalidMcpConfiguration)?;
    install_mcp_executable(&home, &relative_path, &executable_bytes)?;
    servers.push(server.clone());
    servers.sort_by(|left, right| left.server_id().cmp(right.server_id()));
    validate_mcp_server_set(&servers).map_err(|_| CliError::InvalidMcpConfiguration)?;
    object.insert("mcpServers".to_owned(), serde_json::to_value(&servers)?);
    publish_mcp_configuration(
        &home,
        &current,
        &current_body,
        &value,
        &server,
        "installed_and_enabled",
        false,
    )
}

fn list_mcp_servers(home: &Path) -> Result<(), CliError> {
    let home = fs::canonicalize(home)?;
    let value = serde_json::from_slice::<Value>(&fs::read(home.join("config.json"))?)?;
    let object = value
        .as_object()
        .filter(|object| valid_daemon_config_keys(object))
        .ok_or(CliError::InvalidMcpConfiguration)?;
    let servers = configured_mcp_servers(object)?;
    print_json(McpServersConfigurationResponse {
        servers,
        activation_note: "Only enabled servers whose executable and complete live toolset reproduce every pin are exposed after daemon restart.",
    })
}

fn configure_mcp_enabled(
    home: &Path,
    server_id: &str,
    enabled: bool,
    approve: bool,
) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let home = exact_canonical_directory(&home).map_err(|_| CliError::InvalidMcpConfiguration)?;
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let mut value = serde_json::from_slice::<Value>(&current_body)?;
    let object = value
        .as_object_mut()
        .filter(|object| valid_daemon_config_keys(object))
        .ok_or(CliError::InvalidMcpConfiguration)?;
    let mut servers = configured_mcp_servers(object)?;
    let position = servers
        .iter()
        .position(|server| server.server_id() == server_id)
        .ok_or_else(|| CliError::McpServerNotFound(server_id.to_owned()))?;
    if servers[position].enabled() == enabled {
        return Err(CliError::InvalidMcpConfiguration);
    }
    if enabled {
        verify_configured_mcp_server(&home, &servers[position])?;
    }
    servers[position] = servers[position].with_enabled(enabled);
    validate_mcp_server_set(&servers).map_err(|_| CliError::InvalidMcpConfiguration)?;
    let server = servers[position].clone();
    object.insert("mcpServers".to_owned(), serde_json::to_value(&servers)?);
    publish_mcp_configuration(
        &home,
        &current,
        &current_body,
        &value,
        &server,
        if enabled { "enabled" } else { "disabled" },
        true,
    )
}

fn configure_mcp_revoke(home: &Path, server_id: &str, approve: bool) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let home = exact_canonical_directory(&home).map_err(|_| CliError::InvalidMcpConfiguration)?;
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let mut value = serde_json::from_slice::<Value>(&current_body)?;
    let object = value
        .as_object_mut()
        .filter(|object| valid_daemon_config_keys(object))
        .ok_or(CliError::InvalidMcpConfiguration)?;
    let mut servers = configured_mcp_servers(object)?;
    let position = servers
        .iter()
        .position(|server| server.server_id() == server_id)
        .ok_or_else(|| CliError::McpServerNotFound(server_id.to_owned()))?;
    let server = servers.remove(position).with_enabled(false);
    validate_mcp_server_set(&servers).map_err(|_| CliError::InvalidMcpConfiguration)?;
    if servers.is_empty() {
        object.remove("mcpServers");
    } else {
        object.insert("mcpServers".to_owned(), serde_json::to_value(&servers)?);
    }
    publish_mcp_configuration(
        &home,
        &current,
        &current_body,
        &value,
        &server,
        "revoked",
        true,
    )
}

fn configured_mcp_servers(
    object: &serde_json::Map<String, Value>,
) -> Result<Vec<McpServerConfig>, CliError> {
    let servers = object
        .get("mcpServers")
        .cloned()
        .map(serde_json::from_value::<Vec<McpServerConfig>>)
        .transpose()?
        .unwrap_or_default();
    validate_mcp_server_set(&servers).map_err(|_| CliError::InvalidMcpConfiguration)?;
    Ok(servers)
}

fn verify_configured_mcp_server(home: &Path, server: &McpServerConfig) -> Result<(), CliError> {
    let launcher = fs::canonicalize(std::env::current_exe()?)?;
    let discovery = discover_mcp_stdio_server(
        "/usr/bin/bwrap",
        launcher,
        server.server_id(),
        home.join(server.executable_path()),
        server.executable_digest(),
        server.arguments(),
    )?;
    if discovery
        .toolset_digest()
        .map_err(|_| CliError::InvalidMcpConfiguration)?
        != server.toolset_digest()
        || server.tools().iter().any(|grant| {
            discovery.tool(grant.remote_name()).is_none_or(|tool| {
                tool.definition_digest != grant.definition_digest()
                    || tool.definition != *grant.definition()
            })
        })
    {
        return Err(CliError::InvalidMcpConfiguration);
    }
    Ok(())
}

fn inspect_mcp_executable(executable: &Path) -> Result<(PathBuf, String, Vec<u8>), CliError> {
    let absolute = if executable.is_absolute() {
        executable.to_owned()
    } else {
        std::env::current_dir()?.join(executable)
    };
    if absolute.components().any(|component| {
        !matches!(
            component,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        )
    }) {
        return Err(CliError::InvalidMcpConfiguration);
    }
    let path_metadata = fs::symlink_metadata(&absolute)?;
    let canonical = fs::canonicalize(&absolute)?;
    let file = open_mcp_executable(&absolute)?;
    let metadata = file.metadata()?;
    if canonical != absolute
        || path_metadata.file_type().is_symlink()
        || !same_file_identity(&path_metadata, &metadata)
        || !metadata.is_file()
        || metadata.len() < 4
        || metadata.len() > MAXIMUM_MCP_EXECUTABLE_BYTES
    {
        return Err(CliError::InvalidMcpConfiguration);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(CliError::InvalidMcpConfiguration);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| CliError::InvalidMcpConfiguration)?,
    );
    file.take(MAXIMUM_MCP_EXECUTABLE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAXIMUM_MCP_EXECUTABLE_BYTES
        || bytes.len() < 4
        || &bytes[..4] != b"\x7fELF"
    {
        return Err(CliError::InvalidMcpConfiguration);
    }
    let digest = sha256_digest(&bytes);
    Ok((canonical, digest, bytes))
}

#[cfg(unix)]
fn open_mcp_executable(path: &Path) -> Result<File, CliError> {
    use rustix::fs::{Mode, OFlags, open};

    open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| CliError::Io(error.into()))
}

#[cfg(not(unix))]
fn open_mcp_executable(path: &Path) -> Result<File, CliError> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(CliError::InvalidMcpConfiguration);
    }
    File::open(path).map_err(CliError::Io)
}

fn install_mcp_executable(home: &Path, relative: &str, bytes: &[u8]) -> Result<(), CliError> {
    let root = home.join("mcp-servers");
    create_private_service_directory(&root)?;
    if fs::canonicalize(&root)? != root {
        return Err(CliError::InvalidMcpConfiguration);
    }
    let destination = home.join(relative);
    let parent = destination
        .parent()
        .ok_or(CliError::InvalidMcpConfiguration)?;
    create_private_service_directory(parent)?;
    if fs::canonicalize(parent)? != parent {
        return Err(CliError::InvalidMcpConfiguration);
    }
    match fs::symlink_metadata(&destination) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || fs::read(&destination)? != bytes =>
        {
            return Err(CliError::InvalidMcpConfiguration);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            atomic_write_service(&destination, bytes)?;
        }
        Err(error) => return Err(CliError::Io(error)),
    }
    #[cfg(unix)]
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))?;
    File::open(&destination)?.sync_all()?;
    sync_service_directory(parent)
}

fn exact_canonical_directory(path: &Path) -> Result<PathBuf, CliError> {
    let metadata = fs::symlink_metadata(path)?;
    let canonical = fs::canonicalize(path)?;
    if canonical != path || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::InvalidMcpConfiguration);
    }
    Ok(canonical)
}

#[allow(clippy::too_many_arguments)]
fn publish_mcp_configuration(
    home: &Path,
    current: &Path,
    current_body: &[u8],
    value: &Value,
    server: &McpServerConfig,
    operation: &str,
    executable_retained_for_rollback: bool,
) -> Result<(), CliError> {
    let timestamp = unix_timestamp_millis()?;
    let history = home.join("config-history");
    create_private_service_directory(&history)?;
    let replaced = history.join(format!("pre-mcp-{timestamp}.json"));
    atomic_write_service(&replaced, current_body)?;
    atomic_write_service(current, &serde_json::to_vec_pretty(value)?)?;
    print_json(McpConfigurationResponse {
        server_id: server.server_id().to_owned(),
        operation: operation.to_owned(),
        enabled: server.enabled(),
        exposed_tool_ids: server
            .tools()
            .iter()
            .map(|tool| server.exposed_tool_id(tool.remote_name()))
            .collect(),
        executable_digest: server.executable_digest().to_owned(),
        toolset_digest: server.toolset_digest().to_owned(),
        executable_retained_for_rollback,
        configuration_path: current.display().to_string(),
        replaced_configuration_copy: replaced.display().to_string(),
        restart_required: true,
    })
}

fn rollback_configuration(home: &Path, digest: &str, approve: bool) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    if digest.len() != 64
        || digest
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(CliError::InvalidConfigurationDigest);
    }
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let archived = home.join("config-history").join(format!("{digest}.json"));
    let archived_metadata = fs::symlink_metadata(&archived)?;
    if archived_metadata.file_type().is_symlink() || !archived_metadata.is_file() {
        return Err(CliError::InvalidConfigurationDigest);
    }
    let archived_body = fs::read(&archived)?;
    let value: serde_json::Value = serde_json::from_slice(&archived_body)?;
    if value
        .get("formatVersion")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
    {
        return Err(CliError::InvalidConfigurationDigest);
    }
    let current = home.join("config.json");
    let current_body = fs::read(&current)?;
    let timestamp = unix_timestamp_millis()?;
    let replaced = home
        .join("config-history")
        .join(format!("pre-rollback-{timestamp}.json"));
    atomic_write_service(&replaced, &current_body)?;
    atomic_write_service(&current, &archived_body)?;
    print_json(ConfigRollbackResponse {
        activated_digest: digest.to_owned(),
        configuration_path: current.display().to_string(),
        replaced_configuration_copy: replaced.display().to_string(),
        restart_required: true,
    })
}

fn run_restore_activation(
    home: &Path,
    name: &str,
    expected_manifest_digest: &str,
    passphrase_environment: &str,
    approve: bool,
) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    let passphrase = read_passphrase_environment(passphrase_environment)?;
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let report = activate_backup(
        &home,
        name,
        passphrase.as_str(),
        expected_manifest_digest,
        SystemTime::now(),
    )?;
    print_json(BackupActivationResponse {
        api_version: API_VERSION.to_owned(),
        name: name.to_owned(),
        home: report.home.display().to_string(),
        preserved_home: report.preserved_home.display().to_string(),
        manifest_digest: report.manifest_digest,
        activated_at_ms: report.activated_at_ms,
        schema_version: report.schema_version,
        file_count: report.file_count,
        total_bytes: report.total_bytes,
        artifact_count: report.artifact_count,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_migration_home_activation(
    home: &Path,
    name: &str,
    expected_manifest_digest: &str,
    expected_from_schema_version: u64,
    expected_to_schema_version: u64,
    inherited_home_lock_stdin: bool,
    approve: bool,
) -> Result<(), CliError> {
    if !approve {
        return Err(CliError::ApprovalRequired);
    }
    let (home, _instance_lock) = if inherited_home_lock_stdin {
        lock_inherited_stopped_home(home)?
    } else {
        lock_stopped_home(home)?
    };
    let report = activate_migration_backup(
        &home,
        name,
        expected_manifest_digest,
        expected_from_schema_version,
        expected_to_schema_version,
        SystemTime::now(),
    )?;
    print_json(MigrationBackupActivationResponse {
        api_version: API_VERSION.to_owned(),
        migration_backup_name: report.migration_backup_name,
        home: report.home.display().to_string(),
        preserved_home: report.preserved_home.display().to_string(),
        manifest_digest: report.manifest_digest,
        activated_at_ms: report.activated_at_ms,
        from_schema_version: report.from_schema_version,
        to_schema_version: report.to_schema_version,
        file_count: report.file_count,
        total_bytes: report.total_bytes,
        artifact_count: report.artifact_count,
    })
}

#[cfg(target_os = "linux")]
fn lock_inherited_stopped_home(home: &Path) -> Result<(PathBuf, File), CliError> {
    use std::os::{fd::AsFd as _, unix::fs::MetadataExt};

    let home = absolute_service_path(home)?;
    let metadata = fs::symlink_metadata(&home)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::InvalidService(
            "Mealy home must be a real directory".to_owned(),
        ));
    }
    let lock_path = home.join("mealyd.lock");
    let lock_metadata = fs::symlink_metadata(&lock_path)?;
    if lock_metadata.file_type().is_symlink() || !lock_metadata.is_file() {
        return Err(CliError::InvalidService(
            "Mealy home lock must be a real file".to_owned(),
        ));
    }
    let descriptor_metadata = fs::metadata("/proc/self/fd/0")?;
    if descriptor_metadata.dev() != lock_metadata.dev()
        || descriptor_metadata.ino() != lock_metadata.ino()
    {
        return Err(CliError::InvalidService(
            "inherited descriptor does not identify this Mealy home lock".to_owned(),
        ));
    }

    let owned = std::io::stdin().as_fd().try_clone_to_owned()?;
    let inherited_lock = File::from(owned);
    match inherited_lock.try_lock() {
        Ok(()) => Ok((home, inherited_lock)),
        Err(std::fs::TryLockError::WouldBlock) => Err(CliError::DaemonRunning),
        Err(std::fs::TryLockError::Error(error)) => Err(CliError::Io(error)),
    }
}

#[cfg(not(target_os = "linux"))]
fn lock_inherited_stopped_home(_home: &Path) -> Result<(PathBuf, File), CliError> {
    Err(CliError::InvalidService(
        "inherited package-manager home locks are supported only on Linux".to_owned(),
    ))
}

fn lock_stopped_home(home: &Path) -> Result<(PathBuf, File), CliError> {
    let home = absolute_service_path(home)?;
    let metadata = fs::symlink_metadata(&home)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::InvalidService(
            "Mealy home must be a real directory".to_owned(),
        ));
    }
    let instance_lock = open_private_home_lock(&home.join("mealyd.lock"))?;
    match instance_lock.try_lock() {
        Ok(()) => Ok((home, instance_lock)),
        Err(std::fs::TryLockError::WouldBlock) => Err(CliError::DaemonRunning),
        Err(std::fs::TryLockError::Error(error)) => Err(CliError::Io(error)),
    }
}

#[cfg(unix)]
fn open_private_home_lock(path: &Path) -> Result<File, CliError> {
    use rustix::fs::{Mode, OFlags, open};

    open(
        path,
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from(0o600),
    )
    .map(File::from)
    .map_err(|error| CliError::Io(error.into()))
}

#[cfg(not(unix))]
fn open_private_home_lock(path: &Path) -> Result<File, CliError> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    options.open(path).map_err(CliError::Io)
}

fn unix_timestamp_millis() -> Result<u128, CliError> {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|_| CliError::InvalidConfigurationDigest)
}

fn read_provider_credential_environment(name: &str) -> Result<Zeroizing<String>, CliError> {
    if !valid_provider_credential_environment_name(name) {
        return Err(CliError::InvalidProviderCredentialEnvironment);
    }
    std::env::var(name)
        .map(Zeroizing::new)
        .map_err(|_| CliError::MissingProviderCredential(name.to_owned()))
}

fn valid_provider_credential_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    !name.is_empty()
        && name.len() <= 128
        && bytes
            .next()
            .is_some_and(|byte| byte == b'_' || byte.is_ascii_uppercase())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn read_channel_credential_environment(name: &str) -> Result<Zeroizing<String>, CliError> {
    let mut bytes = name.bytes();
    if name.len() > 128
        || !bytes
            .next()
            .is_some_and(|byte| byte == b'_' || byte.is_ascii_uppercase())
        || !bytes.all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(CliError::InvalidChannelCredentialEnvironment);
    }
    std::env::var(name)
        .map(Zeroizing::new)
        .map_err(|_| CliError::MissingChannelCredential(name.to_owned()))
}

fn run_service_installation(home: &Path, command: &ServiceCommand) -> Result<(), CliError> {
    match command {
        ServiceCommand::Install {
            daemon_path,
            destination,
        } => print_json(install_service_definition(
            home,
            daemon_path.as_deref(),
            destination.as_deref(),
        )?),
        ServiceCommand::Remove {
            destination,
            approve,
        } => run_service_removal(home, destination.as_deref(), *approve),
    }
}

fn install_service_definition(
    home: &Path,
    daemon_path: Option<&Path>,
    destination: Option<&Path>,
) -> Result<ServiceInstallationResponse, CliError> {
    let daemon = daemon_path
        .map(Path::to_owned)
        .map_or_else(default_daemon_path, Ok)?
        .canonicalize()
        .map_err(CliError::Io)?;
    validate_daemon_executable(&daemon)?;
    #[cfg(target_os = "linux")]
    validate_linux_service_sandbox()?;
    let (home, _instance_lock) = lock_stopped_home(home)?;
    let home = fs::canonicalize(home)?;
    let read_write_paths = service_read_write_paths(&home)?;
    let (platform, default_destination, body, activation) =
        service_definition(&daemon, &home, &read_write_paths)?;
    let destination = destination.map_or_else(|| Ok(default_destination), absolute_service_path)?;
    let activation_command = activation(&destination)?;
    let parent = destination.parent().ok_or_else(|| {
        CliError::InvalidService("service definition has no parent directory".to_owned())
    })?;
    create_private_service_directory(parent)?;
    let rollback = preserve_service_rollback(&destination)?;
    atomic_write_service(&destination, body.as_bytes())?;
    Ok(ServiceInstallationResponse {
        platform,
        service_definition: destination.display().to_string(),
        daemon_path: daemon.display().to_string(),
        home: home.display().to_string(),
        read_write_paths: read_write_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        rollback_copy: rollback.map(|path| path.display().to_string()),
        activation_command,
    })
}

fn run_service_removal(
    home: &Path,
    destination: Option<&Path>,
    approve: bool,
) -> Result<(), CliError> {
    let plan = plan_service_removal(home, destination)?;
    if !approve || !plan.action_required {
        return print_json(plan);
    }
    if !plan.apply_supported {
        print_json(&plan)?;
        return Err(CliError::MaintenanceUnavailable);
    }
    eprintln!("{}", terminal_safe_pretty_json(&plan)?);
    apply_service_removal(&plan)?;
    let mut result = plan_service_removal(home, Some(&plan.service_definition))?;
    result.daemon_path.clone_from(&plan.daemon_path);
    result.removed = true;
    print_json(result)
}

#[cfg(target_os = "linux")]
fn plan_service_removal(
    home: &Path,
    destination: Option<&Path>,
) -> Result<ServiceRemovalPlan, CliError> {
    let home = absolute_service_path(home)?.canonicalize()?;
    validate_linux_service_home(&home)?;
    let loaded_fragment = loaded_owner_service_fragment()?;
    let destination = destination.map_or_else(
        || {
            loaded_fragment
                .clone()
                .map_or_else(linux_default_service_destination, Ok)
        },
        absolute_service_path,
    )?;
    validate_linux_service_destination_name(&destination)?;
    let active = owner_service_active_or_absent()?;
    let (installed, daemon_path) = match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            let daemon = if !metadata.file_type().is_symlink()
                && metadata.is_file()
                && destination
                    .canonicalize()
                    .is_ok_and(|path| path == destination)
            {
                lifecycle::read_bounded_regular_file(&destination, 64 * 1024)
                    .ok()
                    .and_then(|bytes| generated_linux_service_daemon(&bytes, &home))
            } else {
                None
            };
            (true, daemon)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (false, None),
        Err(error) => return Err(CliError::Io(error)),
    };
    let definition_verified = daemon_path.is_some();
    let loaded_matches = loaded_fragment
        .as_ref()
        .is_none_or(|fragment| fragment == &destination);
    let action_required = installed || loaded_fragment.is_some();
    let apply_supported = !action_required
        || (installed
            && definition_verified
            && loaded_matches
            && !(active && loaded_fragment.is_none()));
    Ok(ServiceRemovalPlan {
        schema_version: "mealy.service-removal.v1",
        platform: "linux-systemd-user".to_owned(),
        home,
        service_definition: destination,
        daemon_path,
        installed,
        definition_verified,
        loaded: loaded_fragment.is_some(),
        active,
        action_required,
        apply_supported,
        preserves_home: true,
        removed: false,
    })
}

#[cfg(not(target_os = "linux"))]
fn plan_service_removal(
    _home: &Path,
    _destination: Option<&Path>,
) -> Result<ServiceRemovalPlan, CliError> {
    Err(CliError::UnsupportedPlatform(
        "production service removal is supported only on Linux".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
fn apply_service_removal(plan: &ServiceRemovalPlan) -> Result<(), CliError> {
    let loaded = loaded_owner_service_fragment()?;
    if loaded
        .as_ref()
        .is_some_and(|path| path != &plan.service_definition)
        || (loaded.is_none() && owner_service_active_or_absent()?)
    {
        return Err(CliError::InvalidService(
            "loaded mealy.service does not match the reviewed definition".to_owned(),
        ));
    }
    if loaded.is_some() {
        run_systemctl(&["--user", "disable", "--now", "mealy.service"], true)?;
    }
    if owner_service_active_or_absent()? {
        return Err(CliError::InvalidService(
            "mealy.service remained active after disable".to_owned(),
        ));
    }
    let (_home, _instance_lock) = lock_stopped_home(&plan.home)?;
    let current = plan_service_removal(&plan.home, Some(&plan.service_definition))?;
    if !current.installed || !current.definition_verified || !current.apply_supported {
        return Err(CliError::InvalidService(
            "service definition changed after the reviewed removal plan".to_owned(),
        ));
    }
    fs::remove_file(&plan.service_definition)?;
    sync_service_directory(plan.service_definition.parent().ok_or_else(|| {
        CliError::InvalidService("service definition has no parent directory".to_owned())
    })?)?;
    run_systemctl(&["--user", "daemon-reload"], true)?;
    run_systemctl(&["--user", "reset-failed", "mealy.service"], false)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_service_removal(_plan: &ServiceRemovalPlan) -> Result<(), CliError> {
    Err(CliError::UnsupportedPlatform(
        "production service removal is supported only on Linux".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
fn loaded_owner_service_fragment() -> Result<Option<PathBuf>, CliError> {
    let output = run_systemctl_output(&[
        "--user",
        "show",
        "--property=FragmentPath",
        "--value",
        "mealy.service",
    ])?;
    let value = std::str::from_utf8(&output)
        .map_err(|_| CliError::UpdateTransactionInconsistent)?
        .trim_end_matches('\n');
    if value.is_empty() {
        return Ok(None);
    }
    if value.contains('\n') || value.chars().any(char::is_control) {
        return Err(CliError::InvalidService(
            "loaded mealy.service fragment path is invalid".to_owned(),
        ));
    }
    absolute_service_path(Path::new(value)).map(Some)
}

#[cfg(target_os = "linux")]
fn owner_service_active_or_absent() -> Result<bool, CliError> {
    let systemctl = trusted_systemctl()?;
    let status = ProcessCommand::new(systemctl)
        .args(["--user", "is-active", "--quiet", "mealy.service"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    match status.code() {
        Some(0) => Ok(true),
        Some(3 | 4) => Ok(false),
        _ => Err(CliError::InvalidService(
            "could not inspect mealy.service activity".to_owned(),
        )),
    }
}

#[cfg(target_os = "linux")]
fn validate_linux_service_sandbox() -> Result<(), CliError> {
    let configured = Path::new("/usr/bin/bwrap");
    let canonical = configured.canonicalize().map_err(|_| {
        CliError::InvalidService(
            "the Linux user service requires trusted /usr/bin/bwrap".to_owned(),
        )
    })?;
    if canonical != configured || !is_trusted_system_executable(&canonical) {
        return Err(CliError::InvalidService(
            "the Linux user service requires trusted /usr/bin/bwrap".to_owned(),
        ));
    }
    Ok(())
}

fn default_daemon_path() -> Result<PathBuf, CliError> {
    let current = std::env::current_exe()?;
    let name = if cfg!(windows) {
        "mealyd.exe"
    } else {
        "mealyd"
    };
    Ok(current.with_file_name(name))
}

fn validate_daemon_executable(path: &Path) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CliError::InvalidService(
            "mealyd path must be a canonical regular file".to_owned(),
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(CliError::InvalidService(
            "mealyd path is not executable".to_owned(),
        ));
    }
    validate_service_text(&path.display().to_string())
}

type ActivationCommand = fn(&Path) -> Result<String, CliError>;

fn service_definition(
    daemon: &Path,
    home: &Path,
    read_write_paths: &[PathBuf],
) -> Result<(String, PathBuf, String, ActivationCommand), CliError> {
    #[cfg(target_os = "linux")]
    {
        let destination = linux_default_service_destination()?;
        let body = linux_service_body(daemon, home, read_write_paths)?;
        Ok((
            "linux-systemd-user".to_owned(),
            destination,
            body,
            linux_activation_command,
        ))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (daemon, home, read_write_paths);
        Err(CliError::UnsupportedPlatform(
            "production service installation is supported only on Linux; archived preview adapters do not provide a supported worker sandbox"
                .to_owned(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn linux_service_body(
    daemon: &Path,
    home: &Path,
    read_write_paths: &[PathBuf],
) -> Result<String, CliError> {
    let daemon_text = daemon.display().to_string();
    let home_text = home.display().to_string();
    validate_service_text(&daemon_text)?;
    validate_service_text(&home_text)?;
    if read_write_paths.is_empty() || !read_write_paths.iter().any(|path| path == home) {
        return Err(CliError::InvalidService(
            "service write paths must include the exact Mealy home".to_owned(),
        ));
    }
    Ok(format!(
        "[Unit]\nDescription=Mealy local-first agent daemon\nAfter=default.target\nStartLimitIntervalSec=60\nStartLimitBurst=3\n\n\
         [Service]\nType=simple\nExecStart={} --home {}\nRestart=on-failure\nRestartPreventExitStatus=2\nRestartSec=2\n\
         UMask=0077\nNoNewPrivileges=true\n\
         RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\nRestrictRealtime=true\n\
         SystemCallArchitectures=native\n\
         MemoryHigh=1G\nMemoryMax=1536M\nMemorySwapMax=0\nTasksMax=384\nLimitNOFILE=1024\nOOMPolicy=stop\n\n[Install]\nWantedBy=default.target\n",
        systemd_quote(&daemon_text),
        systemd_quote(&home_text),
    ))
}

#[cfg(target_os = "linux")]
fn generated_linux_service_daemon(body: &[u8], home: &Path) -> Option<PathBuf> {
    let body = std::str::from_utf8(body).ok()?;
    let mut commands = body
        .lines()
        .filter_map(|line| line.strip_prefix("ExecStart="));
    let command = commands.next()?;
    if commands.next().is_some() {
        return None;
    }
    let home_suffix = format!(" --home {}", systemd_quote(&home.display().to_string()));
    let daemon_argument = command.strip_suffix(&home_suffix)?;
    let daemon_text = decode_systemd_quoted_argument(daemon_argument)?;
    let daemon = PathBuf::from(daemon_text);
    if !daemon.is_absolute()
        || !daemon.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return None;
    }
    let expected = linux_service_body(&daemon, home, &[home.to_owned()]).ok()?;
    (expected == body).then_some(daemon)
}

#[cfg(target_os = "linux")]
fn decode_systemd_quoted_argument(value: &str) -> Option<String> {
    let value = value.strip_prefix('"')?.strip_suffix('"')?;
    let mut decoded = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => match characters.next()? {
                '\\' => decoded.push('\\'),
                '"' => decoded.push('"'),
                _ => return None,
            },
            '%' => {
                if characters.next()? != '%' {
                    return None;
                }
                decoded.push('%');
            }
            '"' => return None,
            character if character.is_control() => return None,
            character => decoded.push(character),
        }
    }
    (!decoded.is_empty()).then_some(decoded)
}

fn service_read_write_paths(home: &Path) -> Result<Vec<PathBuf>, CliError> {
    let home = fs::canonicalize(home)?;
    #[cfg(target_os = "linux")]
    validate_linux_service_home(&home)?;
    let mut writable = vec![home.clone()];
    let config_path = home.join("config.json");
    let metadata = match fs::symlink_metadata(&config_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(writable),
        Err(error) => return Err(CliError::Io(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CliError::InvalidService(
            "daemon configuration must be a real file".to_owned(),
        ));
    }
    let value: Value = serde_json::from_slice(&fs::read(&config_path)?)?;
    let object = value
        .as_object()
        .filter(|object| valid_daemon_config_keys(object))
        .ok_or_else(|| CliError::InvalidService("daemon configuration is invalid".to_owned()))?;
    let workspaces: &[Value] = match object.get("workspaceRoots") {
        Some(value) => value
            .as_array()
            .ok_or_else(|| {
                CliError::InvalidService("workspace configuration is invalid".to_owned())
            })?
            .as_slice(),
        None => &[],
    };
    if workspaces.len() > 16 {
        return Err(CliError::InvalidService(
            "workspace configuration exceeds its bound".to_owned(),
        ));
    }
    let mut workspace_ids = BTreeSet::new();
    let mut workspace_roots = BTreeSet::new();
    for workspace in workspaces {
        let workspace = workspace.as_object().ok_or_else(|| {
            CliError::InvalidService("workspace configuration is invalid".to_owned())
        })?;
        if !(2..=3).contains(&workspace.len())
            || workspace
                .keys()
                .any(|key| !matches!(key.as_str(), "workspaceId" | "root" | "writable"))
        {
            return Err(CliError::InvalidService(
                "workspace configuration is invalid".to_owned(),
            ));
        }
        let workspace_id = workspace
            .get("workspaceId")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::InvalidService("workspace identity is invalid".to_owned()))?;
        validate_workspace_identity(workspace_id)
            .map_err(|_| CliError::InvalidService("workspace identity is invalid".to_owned()))?;
        let root = workspace
            .get("root")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .ok_or_else(|| CliError::InvalidService("workspace root is invalid".to_owned()))?;
        let configured_writable = workspace.get("writable").map_or(Ok(false), |value| {
            value.as_bool().ok_or_else(|| {
                CliError::InvalidService("workspace write flag is invalid".to_owned())
            })
        })?;
        let canonical = fs::canonicalize(&root)?;
        let root_metadata = fs::symlink_metadata(&root)?;
        if canonical != root
            || root_metadata.file_type().is_symlink()
            || !root_metadata.is_dir()
            || paths_overlap(&canonical, &home)
            || !workspace_ids.insert(workspace_id.to_owned())
            || !workspace_roots.insert(canonical.clone())
        {
            return Err(CliError::InvalidService(
                "workspace root is redirected, unavailable, or overlaps private daemon state"
                    .to_owned(),
            ));
        }
        if configured_writable {
            writable.push(canonical);
        }
    }
    writable.sort();
    writable.dedup();
    Ok(writable)
}

#[cfg(target_os = "linux")]
fn validate_linux_service_home(home: &Path) -> Result<(), CliError> {
    const RAMFS_MAGIC: u64 = 0x8584_58f6;
    const TMPFS_MAGIC: u64 = 0x0102_1994;

    let filesystem = rustix::fs::statfs(home).map_err(|error| CliError::Io(error.into()))?;
    let filesystem_type = filesystem.f_type.cast_unsigned();
    if linux_private_tmp_path(home) || matches!(filesystem_type, RAMFS_MAGIC | TMPFS_MAGIC) {
        return Err(CliError::InvalidService(
            "the systemd service requires a persistent Mealy home outside /tmp, /var/tmp, tmpfs, and ramfs"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_private_tmp_path(path: &Path) -> bool {
    path.starts_with("/tmp") || path.starts_with("/var/tmp")
}

#[cfg(not(target_os = "linux"))]
const fn linux_private_tmp_path(_path: &Path) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn linux_default_service_destination() -> Result<PathBuf, CliError> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .map(|root| root.join("systemd/user/mealy.service"))
        .ok_or_else(|| {
            CliError::InvalidService(
                "XDG_CONFIG_HOME or HOME is required for user service installation".to_owned(),
            )
        })
}

#[cfg(target_os = "linux")]
fn systemd_quote(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    format!("\"{escaped}\"")
}

fn validate_service_text(value: &str) -> Result<(), CliError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        Err(CliError::InvalidService(
            "service paths must be non-empty and contain no control characters".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn absolute_service_path(path: &Path) -> Result<PathBuf, CliError> {
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::Prefix(_)
        )
    }) {
        return Err(CliError::InvalidService(
            "service paths must not contain parent traversal".to_owned(),
        ));
    }
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    validate_service_text(&absolute.display().to_string())?;
    Ok(absolute)
}

fn create_private_service_directory(path: &Path) -> Result<(), CliError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::InvalidService(
            "service parent must be a real directory".to_owned(),
        ));
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn preserve_service_rollback(destination: &Path) -> Result<Option<PathBuf>, CliError> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(CliError::InvalidService(
                "existing service definition is not a regular file".to_owned(),
            ))
        }
        Ok(_) => {
            let mut rollback_name = destination.as_os_str().to_owned();
            rollback_name.push(".previous");
            let rollback = PathBuf::from(rollback_name);
            atomic_write_service(&rollback, &fs::read(destination)?)?;
            Ok(Some(rollback))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CliError::Io(error)),
    }
}

fn atomic_write_service(path: &Path, body: &[u8]) -> Result<(), CliError> {
    let parent = path.parent().ok_or_else(|| {
        CliError::InvalidService("service definition has no parent directory".to_owned())
    })?;
    let mut temporary_name = path.as_os_str().to_owned();
    temporary_name.push(format!(".tmp-{}", std::process::id()));
    let temporary = PathBuf::from(temporary_name);
    let _ = fs::remove_file(&temporary);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary)?;
    if let Err(error) = file.write_all(body).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(CliError::Io(error));
    }
    fs::rename(&temporary, path)?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    sync_service_directory(parent)
}

#[cfg(unix)]
fn sync_service_directory(path: &Path) -> Result<(), CliError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_service_directory(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_activation_command(path: &Path) -> Result<String, CliError> {
    validate_linux_service_destination_name(path)?;
    let enable = "systemctl --user daemon-reload && systemctl --user enable --now mealy.service";
    if path == linux_default_service_destination()? {
        Ok(enable.to_owned())
    } else {
        Ok(format!(
            "systemctl --user link {} && {enable}",
            setup_shell_argument(&path.display().to_string())
        ))
    }
}

#[cfg(target_os = "linux")]
fn validate_linux_service_destination_name(path: &Path) -> Result<(), CliError> {
    if path.file_name().and_then(|name| name.to_str()) != Some("mealy.service") {
        return Err(CliError::InvalidService(
            "a Linux service destination must be named mealy.service".to_owned(),
        ));
    }
    Ok(())
}

fn authorized(
    request: reqwest::RequestBuilder,
    connection: &LocalConnectionInfo,
) -> reqwest::RequestBuilder {
    request
        .bearer_auth(&connection.bearer_token)
        .timeout(DAEMON_REQUEST_TIMEOUT)
}

fn authorized_long(
    request: reqwest::RequestBuilder,
    connection: &LocalConnectionInfo,
) -> reqwest::RequestBuilder {
    request
        .bearer_auth(&connection.bearer_token)
        .timeout(DAEMON_LONG_REQUEST_TIMEOUT)
}

fn authorized_stream(
    request: reqwest::RequestBuilder,
    connection: &LocalConnectionInfo,
) -> reqwest::RequestBuilder {
    request.bearer_auth(&connection.bearer_token)
}

async fn decode<T: DeserializeOwned>(response: Response) -> Result<T, CliError> {
    let (status, body) = read_daemon_response_body(response).await?;
    if status.is_success() {
        let value = serde_json::from_slice::<Value>(&body)?;
        if value.get("apiVersion").and_then(Value::as_str) != Some(API_VERSION) {
            return Err(CliError::Protocol(
                "daemon response used an unsupported API version".to_owned(),
            ));
        }
        serde_json::from_value(value).map_err(CliError::from)
    } else {
        Err(server_error_body(status, &body))
    }
}

async fn server_error(response: Response) -> CliError {
    let status = response.status();
    match read_daemon_response_body(response).await {
        Ok((_, body)) => server_error_body(status, &body),
        Err(error) => error,
    }
}

async fn read_daemon_response_body(
    mut response: Response,
) -> Result<(StatusCode, Vec<u8>), CliError> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAXIMUM_DAEMON_RESPONSE_BYTES as u64)
    {
        return Err(oversized_daemon_response(status));
    }
    let mut body = Vec::new();
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => return Ok((status, body)),
            Err(error) if status.is_success() => return Err(CliError::from(error)),
            Err(_) => {
                return Err(CliError::Server {
                    status,
                    code: "invalid_error_response".to_owned(),
                    message: "daemon error response stream was interrupted".to_owned(),
                });
            }
        };
        if body.len().saturating_add(chunk.len()) > MAXIMUM_DAEMON_RESPONSE_BYTES {
            return Err(oversized_daemon_response(status));
        }
        body.extend_from_slice(&chunk);
    }
}

fn oversized_daemon_response(status: StatusCode) -> CliError {
    if status.is_success() {
        CliError::Protocol("daemon response exceeded its 8 MiB byte bound".to_owned())
    } else {
        CliError::Server {
            status,
            code: "invalid_error_response".to_owned(),
            message: "daemon error response exceeded its 8 MiB byte bound".to_owned(),
        }
    }
}

fn server_error_body(status: StatusCode, body: &[u8]) -> CliError {
    match serde_json::from_slice::<ApiErrorResponse>(body) {
        Ok(error) if valid_server_api_error(&error) => CliError::Server {
            status,
            code: error.code,
            message: error.message,
        },
        Ok(_) | Err(_) => CliError::Server {
            status,
            code: "invalid_error_response".to_owned(),
            message: "daemon returned an invalid error response".to_owned(),
        },
    }
}

fn valid_server_api_error(error: &ApiErrorResponse) -> bool {
    error.api_version == API_VERSION
        && !error.code.is_empty()
        && error.code.len() <= MAXIMUM_SERVER_ERROR_CODE_BYTES
        && error
            .code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && !error.message.trim().is_empty()
        && error.message.len() <= MAXIMUM_SERVER_ERROR_MESSAGE_BYTES
        && !error.message.chars().any(unsafe_terminal_character)
}

fn load_connection(home: &Path) -> Result<LocalConnectionInfo, CliError> {
    let home = validate_private_connection_home(home)?;
    let path = home.join("connection.json");
    let file = open_private_descriptor(&path)?;
    validate_private_descriptor(&file.metadata()?)?;
    let mut bytes = Vec::new();
    file.take(MAXIMUM_CONNECTION_DESCRIPTOR_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAXIMUM_CONNECTION_DESCRIPTOR_BYTES {
        return Err(CliError::InvalidConnection(
            "connection.json exceeds its byte bound".to_owned(),
        ));
    }
    let connection: LocalConnectionInfo = serde_json::from_slice(&bytes)?;
    validate_connection(&connection)?;
    Ok(connection)
}

fn validate_private_connection_home(home: &Path) -> Result<PathBuf, CliError> {
    let absolute = if home.is_absolute() {
        home.to_owned()
    } else {
        std::env::current_dir()?.join(home)
    };
    if absolute.components().any(|component| {
        !matches!(
            component,
            std::path::Component::Prefix(_)
                | std::path::Component::RootDir
                | std::path::Component::Normal(_)
        )
    }) {
        return Err(CliError::InvalidConnection(
            "Mealy home must be a canonical private directory".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(&absolute)?;
    let canonical = canonicalize_connection_home(&absolute)?;
    if canonical != absolute || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::InvalidConnection(
            "Mealy home must be a canonical private directory".to_owned(),
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(CliError::InvalidConnection(
            "Mealy home must not grant group or other permissions".to_owned(),
        ));
    }
    Ok(canonical)
}

#[cfg(windows)]
fn canonicalize_connection_home(path: &Path) -> Result<PathBuf, CliError> {
    dunce::canonicalize(path).map_err(CliError::Io)
}

#[cfg(not(windows))]
fn canonicalize_connection_home(path: &Path) -> Result<PathBuf, CliError> {
    fs::canonicalize(path).map_err(CliError::Io)
}

fn validate_connection(connection: &LocalConnectionInfo) -> Result<(), CliError> {
    let url = reqwest::Url::parse(&connection.base_url)
        .map_err(|error| CliError::InvalidConnection(error.to_string()))?;
    let loopback = url
        .host_str()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    if url.scheme() != "http"
        || !loopback
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port().is_none()
    {
        return Err(CliError::InvalidConnection(
            "baseUrl must be an HTTP loopback origin with an explicit port".to_owned(),
        ));
    }
    let credential = URL_SAFE_NO_PAD
        .decode(&connection.bearer_token)
        .map_err(|_| CliError::InvalidConnection("bearer token is malformed".to_owned()))?;
    if credential.len() != 32 {
        return Err(CliError::InvalidConnection(
            "bearer token must contain 32 random bytes".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_private_descriptor(path: &Path) -> Result<File, CliError> {
    use rustix::fs::{Mode, OFlags, open};

    open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| CliError::Io(error.into()))
}

#[cfg(not(unix))]
fn open_private_descriptor(path: &Path) -> Result<File, CliError> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(CliError::InvalidConnection(
            "connection.json must be a real regular file".to_owned(),
        ));
    }
    File::open(path).map_err(CliError::Io)
}

#[cfg(unix)]
fn validate_private_descriptor(metadata: &fs::Metadata) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;
    if !metadata.is_file()
        || metadata.len() > MAXIMUM_CONNECTION_DESCRIPTOR_BYTES
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(CliError::InvalidConnection(
            "connection.json must be a bounded owner-private regular file".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_descriptor(metadata: &fs::Metadata) -> Result<(), CliError> {
    if !metadata.is_file() || metadata.len() > MAXIMUM_CONNECTION_DESCRIPTOR_BYTES {
        return Err(CliError::InvalidConnection(
            "connection.json must be a bounded regular file".to_owned(),
        ));
    }
    Ok(())
}

fn generate_idempotency_key() -> Result<String, CliError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| CliError::RandomUnavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn read_passphrase_environment(name: &str) -> Result<Zeroizing<String>, CliError> {
    if name.is_empty()
        || name.len() > 128
        || name
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'_')
    {
        return Err(CliError::InvalidPassphraseEnvironment);
    }
    std::env::var(name)
        .map(Zeroizing::new)
        .map_err(|_| CliError::MissingPassphrase(name.to_owned()))
}

fn print_json(value: impl Serialize) -> Result<(), CliError> {
    println!("{}", terminal_safe_pretty_json(&value)?);
    Ok(())
}

fn terminal_safe_json(value: &impl Serialize) -> Result<String, CliError> {
    Ok(escape_terminal_json(&serde_json::to_string(value)?))
}

fn terminal_safe_pretty_json(value: &impl Serialize) -> Result<String, CliError> {
    Ok(escape_terminal_json(&serde_json::to_string_pretty(value)?))
}

fn escape_terminal_json(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '\n' | '\r' | '\t') || !unsafe_terminal_character(character) {
            safe.push(character);
        } else {
            let _ = write!(safe, "\\u{:04x}", u32::from(character));
        }
    }
    safe
}

/// Command-line client failure.
#[derive(Debug, Error)]
enum CliError {
    /// Connection descriptor could not be read.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// JSON encoding or decoding failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Install provenance or lifecycle inspection failed.
    #[error(transparent)]
    Lifecycle(#[from] lifecycle::LifecycleError),
    /// A one-command update would cross the durable-state schema and needs migration recovery.
    #[error(
        "automatic update refused the state-schema change from {current} to {target}; use the documented staged migration release procedure"
    )]
    UpdateSchemaChange {
        /// Active state schema.
        current: u64,
        /// Candidate state schema.
        target: u64,
    },
    /// Native package ownership requires the displayed package-manager command.
    #[error(
        "this installation is package-manager-owned; run the nativeUpdateCommand from the verified plan"
    )]
    NativePackageUpdate,
    /// Native package ownership requires the displayed package-manager handoff.
    #[error(
        "this installation is package-manager-owned; run the nativeCommand from the verified plan"
    )]
    NativeMaintenance,
    /// Current evidence cannot authorize the requested installation mutation.
    #[error("the requested installation maintenance action is unavailable from verified evidence")]
    MaintenanceUnavailable,
    /// The detached helper is still running after the foreground observation window.
    #[error(
        "update helper is still running for transaction {0}; inspect the transaction or user-service journal"
    )]
    UpdateHelperPending(String),
    /// The candidate failed qualification and the prior release was restored.
    #[error("the update failed qualification and was automatically rolled back")]
    UpdateRolledBack,
    /// The target was rejected before program mutation and the prior service remains qualified.
    #[error("the update was aborted before activation; the prior release remains qualified")]
    UpdateAborted,
    /// Neither target nor rollback could be fully qualified automatically.
    #[error(
        "the update helper could not establish a qualified release; preserve the transaction, backup, slots, and user-service journal"
    )]
    UpdateRecoveryFailed,
    /// Durable update identity, service ownership, or phase evidence disagreed.
    #[error("update transaction evidence is inconsistent with the installed system")]
    UpdateTransactionInconsistent,
    /// HTTP client failed before a structured response.
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    /// Server returned a stable API error.
    #[error("server returned {status} ({code}): {message}")]
    Server {
        /// HTTP status.
        status: StatusCode,
        /// Stable API code.
        code: String,
        /// Safe detail.
        message: String,
    },
    /// Local protocol/stream validation failed.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// OS randomness was unavailable.
    #[error("operating-system randomness is unavailable")]
    RandomUnavailable,
    /// Local descriptor would send a bearer credential outside the trusted loopback boundary.
    #[error("invalid local connection descriptor: {0}")]
    InvalidConnection(String),
    /// Passphrase environment-variable name is not portable and bounded.
    #[error("backup passphrase environment-variable name is invalid")]
    InvalidPassphraseEnvironment,
    /// Requested encrypted backup passphrase was not present in the environment.
    #[error("backup passphrase environment variable {0} is missing or not Unicode")]
    MissingPassphrase(String),
    /// High-risk configuration activation omitted explicit owner approval.
    #[error("high-risk configuration activation requires --approve")]
    ApprovalRequired,
    /// Guided setup input is missing, malformed, unbounded, or inconsistent with its provider.
    #[error("guided setup input is invalid; rerun `mealyctl setup --help`")]
    InvalidSetupInput,
    /// Interactive setup did not receive the exact final authorization phrase.
    #[error("guided setup was not approved; no provider activation was attempted")]
    SetupNotApproved,
    /// Onboarding would replace an existing provider configuration without explicit authorization.
    #[error(
        "the Mealy home already has configuration; run `doctor` against a running service or rerun onboarding with --reconfigure while the daemon is stopped"
    )]
    OnboardExistingHome,
    /// A live provider catalog contained no model satisfying the route's fail-closed policy.
    #[error("no eligible model was found for the {0} onboarding route")]
    OnboardNoEligibleModel(&'static str),
    /// Provider setup completed, but service installation, activation, or verification did not.
    #[error(
        "onboarding configured the provider but could not finish the owner service; the stopped home and diagnostics were preserved: {0}"
    )]
    OnboardService(String),
    /// Provider settings or the current daemon configuration document are invalid.
    #[error("provider configuration is invalid")]
    InvalidProviderConfiguration,
    /// Provider model-discovery filtering, pagination, or output bound is invalid.
    #[error("provider model-discovery request is invalid")]
    InvalidProviderDiscoveryRequest,
    /// Bounded provider model discovery failed without exposing response content or credentials.
    #[error("provider model discovery failed: {0}")]
    ProviderDiscovery(String),
    /// Owner-entered memory namespace, content, confidence, or provenance is invalid.
    #[error("owner-entered governed memory is invalid")]
    InvalidMemoryOwnerEntry,
    /// Explicit local text attachment is unsafe, unsupported, oversized, or not valid UTF-8.
    #[error(
        "local text attachment must be a nonempty no-follow regular UTF-8 file with a supported extension and at most 256 KiB"
    )]
    InvalidLocalAttachment,
    /// Proposal succeeded but the exact revision could not be activated; it remains inspectable.
    #[error("memory {memory_id} revision {revision_id} was proposed but not activated: {reason}")]
    MemoryActivationIncomplete {
        /// Durable proposal identity retained for recovery.
        memory_id: String,
        /// Exact immutable proposed revision retained for recovery.
        revision_id: String,
        /// Safe failure classification.
        reason: String,
    },
    /// Bounded live provider/model probe failed without exposing response content or credentials.
    #[error("provider connectivity test failed: {0}")]
    ProviderConnectivity(String),
    /// Credential remains referenced by the active validated configuration.
    #[error("provider credential {0} is still referenced by the current configuration")]
    ProviderSecretInUse(String),
    /// No configured fallback has the requested stable provider identity.
    #[error("provider fallback {0} was not found")]
    ProviderFallbackNotFound(String),
    /// Workspace identity, path, duplicate, or current document is invalid.
    #[error("workspace grant configuration is invalid")]
    InvalidWorkspaceConfiguration,
    /// Command identity, executable, digest, writable workspace, or current document is invalid.
    #[error("direct process configuration is invalid")]
    InvalidCommandConfiguration,
    /// MCP executable, protocol, schema pins, selection, or current config is invalid.
    #[error("MCP server or tool configuration is invalid")]
    InvalidMcpConfiguration,
    /// No configured MCP server has the requested stable identity.
    #[error("MCP server {0} was not found")]
    McpServerNotFound(String),
    /// Sandboxed MCP discovery or live verification failed closed.
    #[error(transparent)]
    McpHost(#[from] McpHostError),
    /// Browser bundle, content pin, runtime identity, or current config is invalid.
    #[error("browser runtime configuration is invalid")]
    InvalidBrowserConfiguration,
    /// No installed browser runtime is present in active configuration.
    #[error("browser runtime was not found")]
    BrowserNotFound,
    /// Browser authority cannot be activated without an explicit web destination grant.
    #[error("browser authority requires enabled web access configuration")]
    BrowserRequiresWeb,
    /// Browser bundle inspection or immutable publication failed closed.
    #[error(transparent)]
    BrowserBundle(#[from] BrowserBundleError),
    /// Sandboxed browser probing or live verification failed closed.
    #[error(transparent)]
    BrowserHost(#[from] BrowserHostError),
    /// Web destinations, search settings, credential reference, or current document is invalid.
    #[error("web access configuration is invalid")]
    InvalidWebConfiguration,
    /// Disable was requested without an active web authority configuration.
    #[error("web access is not enabled")]
    WebNotEnabled,
    /// Owner-selected extension manifest is unsafe, oversized, empty, or not valid UTF-8.
    #[error("extension manifest must be a nonempty no-follow regular UTF-8 file of at most 1 MiB")]
    InvalidExtensionManifest,
    /// Skill manifest, package inventory, installed record, or current config is invalid.
    #[error("skill package or configuration is invalid")]
    InvalidSkillConfiguration,
    /// The requested stable skill identity is already installed.
    #[error("skill {0} is already installed; use skill update with its exact current digest")]
    SkillAlreadyInstalled(String),
    /// No installed skill has the requested stable identity.
    #[error("skill {0} was not found")]
    SkillNotFound(String),
    /// The optimistic manifest-digest fence no longer identifies the installed revision.
    #[error("skill {0} changed; inspect status and retry with the exact current manifest digest")]
    SkillRevisionConflict(String),
    /// Data-only package inspection or immutable publication failed closed.
    #[error(transparent)]
    SkillPackage(#[from] mealy_infrastructure::SkillPackageError),
    /// Requested logical workspace grant is absent.
    #[error("workspace grant {0} was not found")]
    WorkspaceNotFound(String),
    /// Requested logical command grant is absent.
    #[error("direct process grant {0} was not found")]
    CommandNotFound(String),
    /// Credential environment-variable name is not portable and bounded.
    #[error("provider credential environment-variable name is invalid")]
    InvalidProviderCredentialEnvironment,
    /// Requested provider credential was absent from the one-shot import environment.
    #[error("provider credential environment variable {0} is missing or not Unicode")]
    MissingProviderCredential(String),
    /// Channel credential environment-variable name is not portable and bounded.
    #[error("channel credential environment-variable name is invalid")]
    InvalidChannelCredentialEnvironment,
    /// Requested channel credential was absent from the one-shot import environment.
    #[error("channel credential environment variable {0} is missing or not Unicode")]
    MissingChannelCredential(String),
    /// Time-bounded Telegram Bot API pairing failed without exposing token or response content.
    #[error("Telegram pairing failed: {0}")]
    TelegramPairing(String),
    /// Time-bounded Discord REST pairing failed without exposing token or response content.
    #[error("Discord pairing failed: {0}")]
    DiscordPairing(String),
    /// Owner-private provider credential broker rejected the operation.
    #[error(transparent)]
    ProviderSecret(#[from] mealy_infrastructure::ProviderSecretStoreError),
    /// Offline backup verification or atomic activation failed closed.
    #[error(transparent)]
    Maintenance(#[from] mealy_infrastructure::MaintenanceError),
    /// Configuration history digest or archived document is invalid.
    #[error("configuration rollback digest or archived document is invalid")]
    InvalidConfigurationDigest,
    /// Offline configuration rollback cannot race a live daemon.
    #[error("configuration rollback requires mealyd to be stopped")]
    DaemonRunning,
    /// Service definition or executable path is unsafe.
    #[error("invalid service installation: {0}")]
    InvalidService(String),
    /// Current platform has no safe built-in service installer.
    #[cfg(not(target_os = "linux"))]
    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalCommand, Arguments, ChannelCommand, ChatLine, ChatMemoryCommand, CliError, Command,
        CompactionCommand, ConfigCommand, DelegationCommand, DiscordPairMessage, DiscordPairUser,
        EffectCommand, ExtensionCommand, LifecycleArguments, LifecycleCommand,
        MAXIMUM_DAEMON_RESPONSE_BYTES, MAXIMUM_LOCAL_TEXT_ATTACHMENT_BYTES, MemoryCommand,
        ResumableChatTask, SETUP_PROVIDER_ESTIMATED_LATENCY_MS, ScheduleCommand, ServiceCommand,
        SetupProviderArgument, SkillCommand, TelegramPairChat, TelegramPairMessage,
        TelegramPairUpdate, TelegramPairUser, UpdateRecoveryRoute, configure_workspace_grant,
        decode, generate_discord_pair_challenge, generate_telegram_pair_challenge,
        initialize_setup_home, inspect_mcp_executable, lifecycle_invocation, load_connection,
        normalize_openrouter_display_name, observe_discord_pair_messages,
        observe_resumable_chat_event, observe_telegram_pair_updates, openrouter_price_is_zero,
        openrouter_price_microunits_per_million, parse_chat_line, prepare_local_text_attachment,
        resolve_setup, setup_provider_config, telegram_pair_api_url, update_recovery_route,
        validate_anthropic_probe_envelope, validate_anthropic_probe_stream, validate_connection,
        validate_discord_pair_base_url, validate_provider_probe_envelope,
        validate_provider_probe_stream,
    };
    #[cfg(target_os = "linux")]
    use super::{
        decode_systemd_quoted_argument, generated_linux_service_daemon, linux_activation_command,
        linux_service_body, service_definition, service_read_write_paths, systemd_quote,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use clap::Parser;
    use mealy_application::{AgentLoopLimits, ProviderConfig};
    use mealy_protocol::{
        API_VERSION, DeliveryMode, LocalConnectionInfo, TimelineCursor, TimelineEvent,
    };
    use serde_json::json;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
    #[cfg(target_os = "linux")]
    use std::path::Path;
    use std::{collections::BTreeMap, ffi::OsString, io::Cursor, path::PathBuf};

    fn connection(base_url: &str) -> LocalConnectionInfo {
        LocalConnectionInfo {
            api_version: API_VERSION.to_owned(),
            base_url: base_url.to_owned(),
            bearer_token: URL_SAFE_NO_PAD.encode([7_u8; 32]),
            principal_id: "principal".to_owned(),
            channel_binding_id: "binding".to_owned(),
        }
    }

    fn valid_responses_probe_envelope() -> serde_json::Value {
        json!({
            "id": "resp-probe",
            "object": "response",
            "model": "expected-model",
            "status": "completed",
            "output": [{
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "OK"}]
            }],
            "usage": {"input_tokens": 10, "output_tokens": 1, "total_tokens": 11}
        })
    }

    #[test]
    fn update_recovery_routes_every_crash_boundary_without_false_commit() {
        use super::lifecycle::{ActiveTransactionSlot as Slot, UpdateTransactionPhase as Phase};

        assert_eq!(
            update_recovery_route(Phase::Scheduled, Some(Slot::Previous), false, true),
            UpdateRecoveryRoute::AbortUntouched
        );
        assert_eq!(
            update_recovery_route(Phase::Scheduled, Some(Slot::Previous), false, false),
            UpdateRecoveryRoute::FailClosed
        );
        assert_eq!(
            update_recovery_route(Phase::Scheduled, Some(Slot::Candidate), false, true),
            UpdateRecoveryRoute::FailClosed
        );

        for phase in [
            Phase::Prepared,
            Phase::Draining,
            Phase::Stopped,
            Phase::Activated,
            Phase::Starting,
            Phase::Verifying,
            Phase::RollingBack,
        ] {
            for slot in [Slot::Previous, Slot::Candidate] {
                assert_eq!(
                    update_recovery_route(phase, Some(slot), true, true),
                    UpdateRecoveryRoute::RestorePrevious,
                    "{phase:?} with {slot:?} must restore the prior slot"
                );
            }
        }

        for phase in [
            Phase::Activated,
            Phase::Starting,
            Phase::Verifying,
            Phase::RollingBack,
        ] {
            assert_eq!(
                update_recovery_route(phase, None, true, false),
                UpdateRecoveryRoute::RestorePrevious,
                "{phase:?} must attempt stopped rollback even when inspection is damaged"
            );
        }

        for phase in [
            Phase::Committed,
            Phase::Aborted,
            Phase::RolledBack,
            Phase::RecoveryFailed,
        ] {
            assert_eq!(
                update_recovery_route(phase, Some(Slot::Candidate), true, true),
                UpdateRecoveryRoute::FailClosed,
                "terminal phase {phase:?} cannot be resumed by recovery routing"
            );
        }
    }

    #[tokio::test]
    async fn daemon_json_decoder_rejects_oversized_success_and_error_bodies() {
        let success: reqwest::Response = axum::http::Response::builder()
            .status(reqwest::StatusCode::OK)
            .body(vec![b' '; MAXIMUM_DAEMON_RESPONSE_BYTES + 1])
            .expect("oversized success response")
            .into();
        let success_error = decode::<serde_json::Value>(success)
            .await
            .expect_err("oversized successful body must fail");
        assert!(matches!(success_error, CliError::Protocol(message) if message.contains("8 MiB")));

        let failure: reqwest::Response = axum::http::Response::builder()
            .status(reqwest::StatusCode::BAD_GATEWAY)
            .body(vec![b' '; MAXIMUM_DAEMON_RESPONSE_BYTES + 1])
            .expect("oversized error response")
            .into();
        let failure_error = decode::<serde_json::Value>(failure)
            .await
            .expect_err("oversized error body must fail");
        assert!(matches!(
            failure_error,
            CliError::Server { status, code, message }
                if status == reqwest::StatusCode::BAD_GATEWAY
                    && code == "invalid_error_response"
                    && message.contains("8 MiB")
        ));

        for invalid in [json!({"apiVersion": "other"}), json!({"value": true})] {
            let response: reqwest::Response = axum::http::Response::builder()
                .status(reqwest::StatusCode::OK)
                .body(serde_json::to_vec(&invalid).expect("invalid version body"))
                .expect("invalid version response")
                .into();
            assert!(matches!(
                decode::<serde_json::Value>(response)
                    .await
                    .expect_err("unversioned response must fail"),
                CliError::Protocol(message) if message.contains("API version")
            ));
        }
    }

    #[test]
    fn timeline_stream_and_terminal_rendering_are_bounded_and_control_safe() {
        let mut newline_bound = super::TimelineSseEventByteBound::new(8);
        newline_bound.observe(b"d:1\n").expect("first SSE line");
        newline_bound.observe(b"\n").expect("SSE event boundary");
        assert_eq!(newline_bound.current_bytes, 0);
        newline_bound
            .observe(b"12345678")
            .expect("exact byte bound");
        assert!(newline_bound.observe(b"9").is_err());

        let mut carriage_return_bound = super::TimelineSseEventByteBound::new(8);
        carriage_return_bound
            .observe(b"d:1\r\n\r")
            .expect("split CRLF event boundary");
        carriage_return_bound
            .observe(b"\n")
            .expect("CRLF continuation");
        assert_eq!(carriage_return_bound.current_bytes, 0);

        let value = json!({"text": "visible\u{202e}\u{009b}safe"});
        let rendered = super::terminal_safe_json(&value).expect("terminal-safe JSON");
        assert!(rendered.contains("\\u202e"));
        assert!(rendered.contains("\\u009b"));
        assert!(!rendered.contains('\u{202e}'));
        assert!(!rendered.contains('\u{009b}'));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&rendered).expect("preserved JSON"),
            value
        );

        let timeline = timeline_event(
            7,
            "task.created",
            "task",
            "task-7",
            "correlation-7",
            json!({}),
        );
        let mut event = eventsource_stream::Event {
            event: timeline.event_type.clone(),
            data: serde_json::to_string(&timeline).expect("timeline event JSON"),
            id: timeline.cursor.0.to_string(),
            retry: None,
        };
        let (cursor, parsed) =
            super::parse_timeline_event(&event, Some(6)).expect("consistent timeline SSE identity");
        assert_eq!(cursor, 7);
        assert_eq!(parsed, timeline);
        event.id = "6".to_owned();
        assert!(super::parse_timeline_event(&event, Some(6)).is_err());
        event.id = "7".to_owned();
        event.event = "task.failed".to_owned();
        assert!(super::parse_timeline_event(&event, Some(6)).is_err());
    }

    #[test]
    fn daemon_error_envelopes_require_versioned_bounded_terminal_safe_fields() {
        let status = reqwest::StatusCode::BAD_GATEWAY;
        let valid = json!({
            "apiVersion": API_VERSION,
            "code": "unavailable",
            "message": "provider is temporarily unavailable",
            "retryable": true
        });
        assert!(matches!(
            super::server_error_body(
                status,
                &serde_json::to_vec(&valid).expect("valid error body")
            ),
            CliError::Server { code, message, .. }
                if code == "unavailable" && message == "provider is temporarily unavailable"
        ));

        for invalid in [
            json!({
                "apiVersion": "other",
                "code": "unavailable",
                "message": "safe",
                "retryable": false
            }),
            json!({
                "apiVersion": API_VERSION,
                "code": "UPPERCASE",
                "message": "safe",
                "retryable": false
            }),
            json!({
                "apiVersion": API_VERSION,
                "code": "unavailable",
                "message": "clear\u{001b}[2J",
                "retryable": false
            }),
            json!({
                "apiVersion": API_VERSION,
                "code": "unavailable",
                "message": "spoof\u{202e}txt",
                "retryable": false
            }),
        ] {
            assert!(matches!(
                super::server_error_body(
                    status,
                    &serde_json::to_vec(&invalid).expect("invalid error body")
                ),
                CliError::Server { code, message, .. }
                    if code == "invalid_error_response"
                        && message == "daemon returned an invalid error response"
            ));
        }
    }

    #[test]
    fn responses_probe_validators_require_exact_bounded_response_identity() {
        let context_tokens = 32_768;
        let maximum_output_tokens = 64;
        let response = valid_responses_probe_envelope();
        assert!(
            validate_provider_probe_envelope(
                &response,
                "expected-model",
                context_tokens,
                maximum_output_tokens,
            )
            .is_ok()
        );
        assert!(
            validate_provider_probe_envelope(
                &response,
                "other-model",
                context_tokens,
                maximum_output_tokens,
            )
            .is_err()
        );

        let mut unsafe_response = response.clone();
        unsafe_response["id"] = json!("resp-probe\nunsafe");
        assert!(
            validate_provider_probe_envelope(
                &unsafe_response,
                "expected-model",
                context_tokens,
                maximum_output_tokens,
            )
            .is_err()
        );

        let response_event = json!({"type": "response.completed", "response": response});
        let response_stream =
            format!("event: response.completed\ndata: {response_event}\n\ndata: [DONE]\n\n");
        assert!(
            validate_provider_probe_stream(
                response_stream.as_bytes(),
                "expected-model",
                context_tokens,
                maximum_output_tokens,
            )
            .is_ok()
        );
        assert!(
            validate_provider_probe_stream(
                response_stream.as_bytes(),
                "other-model",
                context_tokens,
                maximum_output_tokens,
            )
            .is_err()
        );
        let mismatched_stream = format!(
            "data: {{\"type\":\"response.output_text.delta\",\"delta\":\"DIFFERENT\"}}\n\ndata: {response_event}\n\n"
        );
        assert!(
            validate_provider_probe_stream(
                mismatched_stream.as_bytes(),
                "expected-model",
                context_tokens,
                maximum_output_tokens,
            )
            .is_err()
        );

        let mut unexpected_tool = response.clone();
        unexpected_tool["output"] = json!([{
            "type": "function_call",
            "name": "unavailable",
            "arguments": "{}"
        }]);
        assert!(
            validate_provider_probe_envelope(
                &unexpected_tool,
                "expected-model",
                context_tokens,
                maximum_output_tokens,
            )
            .is_err()
        );

        let mut invalid_usage = response.clone();
        invalid_usage["usage"]["total_tokens"] = json!(12);
        assert!(
            validate_provider_probe_envelope(
                &invalid_usage,
                "expected-model",
                context_tokens,
                maximum_output_tokens,
            )
            .is_err()
        );
    }

    #[test]
    fn anthropic_probe_validators_require_exact_bounded_response_identity() {
        let context_tokens = 32_768;
        let maximum_output_tokens = 64;
        let message = json!({
            "id": "msg-probe",
            "type": "message",
            "role": "assistant",
            "model": "expected-model",
            "content": [{"type": "text", "text": "OK"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 1}
        });
        assert!(
            validate_anthropic_probe_envelope(
                &message,
                "expected-model",
                context_tokens,
                maximum_output_tokens,
            )
            .is_ok()
        );
        assert!(
            validate_anthropic_probe_envelope(
                &message,
                "other-model",
                context_tokens,
                maximum_output_tokens,
            )
            .is_err()
        );

        let anthropic_stream = [
            json!({
                "type": "message_start",
                "message": {
                    "id": "msg-probe",
                    "type": "message",
                    "role": "assistant",
                    "model": "expected-model",
                    "content": [],
                    "usage": {"input_tokens": 10, "output_tokens": 0}
                }
            }),
            json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": "OK"}
            }),
            json!({"type": "content_block_stop", "index": 0}),
            json!({
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn"},
                "usage": {"output_tokens": 1}
            }),
            json!({"type": "message_stop"}),
        ]
        .into_iter()
        .fold(String::new(), |mut body, event| {
            body.push_str("data: ");
            body.push_str(&event.to_string());
            body.push_str("\n\n");
            body
        });
        assert!(
            validate_anthropic_probe_stream(
                anthropic_stream.as_bytes(),
                "expected-model",
                context_tokens,
                maximum_output_tokens,
            )
            .is_ok()
        );
        assert!(
            validate_anthropic_probe_stream(
                anthropic_stream.as_bytes(),
                "other-model",
                context_tokens,
                maximum_output_tokens,
            )
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    fn service_test_tempdir(prefix: &str) -> tempfile::TempDir {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("target/service-test-temp");
        std::fs::create_dir_all(&root).expect("service test root");
        let root = root.canonicalize().expect("canonical service test root");
        tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(root)
            .expect("persistent service test directory")
    }

    #[test]
    fn usage_history_command_defaults_to_thirty_days_and_preserves_an_exact_bound() {
        let default = Arguments::try_parse_from(["mealyctl", "usage"])
            .expect("default usage history command");
        assert!(matches!(default.command, Command::Usage { days: 30 }));
        let bounded = Arguments::try_parse_from(["mealyctl", "usage", "--days", "7"])
            .expect("bounded usage history command");
        assert!(matches!(bounded.command, Command::Usage { days: 7 }));
    }

    #[test]
    fn lifecycle_parser_is_selected_without_growing_the_operational_command_graph() {
        let direct = vec![OsString::from("mealyctl"), OsString::from("install-status")];
        let home_prefixed = vec![
            OsString::from("mealyctl"),
            OsString::from("--home"),
            OsString::from("/srv/mealy"),
            OsString::from("update"),
            OsString::from("--version"),
            OsString::from("v1.2.3"),
        ];
        let operational = vec![OsString::from("mealyctl"), OsString::from("status")];
        let helper = vec![
            OsString::from("mealyctl"),
            OsString::from("update-transaction"),
            OsString::from("019f9010-977b-7c32-9c1b-f21e083ce845"),
        ];
        assert!(lifecycle_invocation(&direct));
        assert!(lifecycle_invocation(&home_prefixed));
        assert!(lifecycle_invocation(&helper));
        assert!(!lifecycle_invocation(&operational));

        let parsed = LifecycleArguments::try_parse_from(home_prefixed)
            .expect("separate lifecycle command graph");
        assert_eq!(parsed.home, PathBuf::from("/srv/mealy"));
        assert!(matches!(
            parsed.command,
            LifecycleCommand::Update {
                version,
                approve: false
            } if version == "v1.2.3"
        ));
    }

    #[test]
    fn local_text_attachment_is_bounded_digest_framed_path_free_and_no_follow() {
        let home = tempfile::tempdir().expect("daemon home");
        let directory = tempfile::tempdir().expect("attachment directory");
        let attachment = directory.path().join("review.md");
        let body = b"# Review\n\nTreat this as untrusted evidence.\n";
        std::fs::write(&attachment, body).expect("attachment");
        let content =
            prepare_local_text_attachment(home.path(), &attachment, "Summarize this document.")
                .expect("prepared attachment");
        assert!(content.starts_with("Summarize this document.\n\n"));
        assert!(content.contains("\"name\":\"review.md\""));
        assert!(content.contains("\"mediaType\":\"text/markdown; charset=utf-8\""));
        assert!(content.contains(&super::sha256_digest(body)));
        assert!(content.contains("# Review\n\nTreat this as untrusted evidence."));
        assert!(!content.contains(&directory.path().display().to_string()));

        let unsupported = directory.path().join("opaque.bin");
        std::fs::write(&unsupported, b"not admitted by extension").expect("unsupported file");
        assert!(prepare_local_text_attachment(home.path(), &unsupported, "Review this.").is_err());
        let invalid_utf8 = directory.path().join("invalid.txt");
        std::fs::write(&invalid_utf8, [0xff, 0xfe]).expect("invalid UTF-8 file");
        assert!(prepare_local_text_attachment(home.path(), &invalid_utf8, "Review this.").is_err());
        let oversized = directory.path().join("large.txt");
        std::fs::File::create(&oversized)
            .expect("oversized file")
            .set_len(MAXIMUM_LOCAL_TEXT_ATTACHMENT_BYTES + 1)
            .expect("oversized length");
        assert!(prepare_local_text_attachment(home.path(), &oversized, "Review this.").is_err());
        assert!(prepare_local_text_attachment(home.path(), &attachment, " leading space").is_err());

        let private_attachment = home.path().join("identity.json");
        std::fs::write(&private_attachment, b"private daemon state").expect("private attachment");
        assert!(
            prepare_local_text_attachment(home.path(), &private_attachment, "Review this.")
                .is_err()
        );

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&attachment, directory.path().join("redirect.md"))
                .expect("attachment symlink");
            assert!(
                prepare_local_text_attachment(
                    home.path(),
                    &directory.path().join("redirect.md"),
                    "Review this."
                )
                .is_err()
            );
        }
    }

    #[test]
    fn workspace_grants_cannot_overlap_private_daemon_state() {
        let parent = tempfile::tempdir().expect("home parent");
        let home = parent.path().join("mealy-home");
        initialize_setup_home(&home).expect("initialize home");
        let child = home.join("workspace");
        std::fs::create_dir(&child).expect("private child");
        for (workspace_id, root) in [
            ("parent", parent.path()),
            ("home", home.as_path()),
            ("child", child.as_path()),
        ] {
            assert!(matches!(
                configure_workspace_grant(&home, workspace_id, root, true),
                Err(CliError::InvalidWorkspaceConfiguration)
            ));
        }
        let outside = tempfile::tempdir().expect("outside workspace");
        configure_workspace_grant(&home, "outside", outside.path(), true)
            .expect("outside workspace grant");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn service_unit_preserves_per_tool_sandbox_compatibility() {
        let home = service_test_tempdir("daemon-home-");
        initialize_setup_home(home.path()).expect("initialize home");
        let writable = service_test_tempdir("writable-workspace-");
        let read_only = service_test_tempdir("read-only-workspace-");
        let config_path = home.path().join("config.json");
        let mut config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&config_path).expect("configuration bytes"))
                .expect("configuration JSON");
        config["workspaceRoots"] = json!([
            {
                "workspaceId": "read-only",
                "root": read_only.path().canonicalize().expect("read-only root")
            },
            {
                "workspaceId": "writable",
                "root": writable.path().canonicalize().expect("writable root"),
                "writable": true
            }
        ]);
        std::fs::write(
            &config_path,
            serde_json::to_vec_pretty(&config).expect("configuration encoding"),
        )
        .expect("write configuration");
        let canonical_home = home.path().canonicalize().expect("canonical home");
        let read_write_paths =
            service_read_write_paths(&canonical_home).expect("service write paths");
        assert!(read_write_paths.contains(&canonical_home));
        assert!(read_write_paths.contains(&writable.path().canonicalize().expect("writable path")));
        assert!(
            !read_write_paths.contains(&read_only.path().canonicalize().expect("read-only path"))
        );
        let (_, _, body, _) = service_definition(
            std::path::Path::new("/usr/bin/true"),
            &canonical_home,
            &read_write_paths,
        )
        .expect("service definition");
        assert!(body.contains("RestartPreventExitStatus=2"));
        assert!(body.contains("UMask=0077"));
        assert!(body.contains(&format!(
            "ExecStart=\"/usr/bin/true\" --home \"{}\"",
            canonical_home.display()
        )));
        assert!(!body.contains("ExecStart=/usr/bin/bwrap"));
        assert!(!body.contains("--bind"));
        assert!(!body.contains("PrivateDevices="));
        assert!(!body.contains("PrivateTmp="));
        assert!(!body.contains("ProtectProc="));
        assert!(!body.contains("ProcSubset="));
        assert!(!body.contains("ProtectSystem="));
        assert!(!body.contains("ProtectHome="));
        assert!(!body.contains("ReadWritePaths="));
        assert!(!body.contains("ProtectHostname="));
        assert!(!body.contains("ProtectKernelLogs="));
        assert!(!body.contains("ProtectKernelTunables="));
        assert!(!body.contains("RestrictSUIDSGID="));
        assert!(body.contains("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK"));
        assert!(body.contains("SystemCallArchitectures=native"));
        config["workspaceRoots"][1]["root"] = json!(canonical_home);
        std::fs::write(
            &config_path,
            serde_json::to_vec_pretty(&config).expect("overlap configuration encoding"),
        )
        .expect("write overlap configuration");
        assert!(service_read_write_paths(home.path()).is_err());

        let private_tmp_home = tempfile::tempdir().expect("private-tmp home");
        assert!(service_read_write_paths(private_tmp_home.path()).is_err());
        assert!(linux_activation_command(Path::new("/srv/mealy/not-mealy.service")).is_err());
        let custom_activation = linux_activation_command(Path::new("/srv/mealy/mealy.service"))
            .expect("custom activation command");
        assert!(custom_activation.contains("systemctl --user link '/srv/mealy/mealy.service'"));
        assert!(custom_activation.ends_with(
            "systemctl --user daemon-reload && systemctl --user enable --now mealy.service"
        ));
        let quoted_activation =
            linux_activation_command(Path::new("/srv/owner's services/mealy.service"))
                .expect("quoted custom activation command");
        assert!(
            quoted_activation
                .starts_with("systemctl --user link '/srv/owner'\\''s services/mealy.service' && ")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_paths_quote_whitespace_specifiers_quotes_and_backslashes() {
        assert_eq!(
            systemd_quote(r#"/srv/owner workspace/100%/quote\"/back\slash"#),
            r#""/srv/owner workspace/100%%/quote\\\"/back\\slash""#
        );
        let home = Path::new("/srv/owner workspace/mealy-home");
        let daemon = Path::new(r#"/srv/owner workspace/100%/quote"/back\slash/mealyd"#);
        let body = linux_service_body(daemon, home, &[home.to_owned()])
            .expect("generated service definition");
        assert_eq!(
            generated_linux_service_daemon(body.as_bytes(), home).as_deref(),
            Some(daemon)
        );
        assert!(
            generated_linux_service_daemon(
                body.replacen("Restart=on-failure", "Restart=always", 1)
                    .as_bytes(),
                home
            )
            .is_none()
        );
        assert!(
            generated_linux_service_daemon(body.as_bytes(), Path::new("/srv/another-home"))
                .is_none()
        );
        assert!(decode_systemd_quoted_argument(r#""bad\q""#).is_none());
        assert!(decode_systemd_quoted_argument(r#""single%specifier""#).is_none());
    }

    #[test]
    fn descriptor_accepts_only_literal_loopback_http_origins() {
        for accepted in ["http://127.0.0.1:4317", "http://[::1]:4317"] {
            validate_connection(&connection(accepted)).expect("loopback origin should be valid");
        }
        for rejected in [
            "https://127.0.0.1:4317",
            "http://localhost:4317",
            "http://192.0.2.1:4317",
            "http://user@127.0.0.1:4317",
            "http://127.0.0.1:4317/path",
            "http://127.0.0.1:4317?query=yes",
            "http://127.0.0.1",
        ] {
            assert!(
                validate_connection(&connection(rejected)).is_err(),
                "descriptor unexpectedly accepted {rejected}"
            );
        }
    }

    #[test]
    fn descriptor_rejects_non_fixed_length_credentials() {
        let mut value = connection("http://127.0.0.1:4317");
        value.bearer_token = URL_SAFE_NO_PAD.encode([7_u8; 16]);
        assert!(validate_connection(&value).is_err());
    }

    #[test]
    fn local_descriptor_and_mcp_executable_reads_are_preflight_bounded() {
        let home = tempfile::tempdir().expect("descriptor home");
        let canonical_home = home
            .path()
            .canonicalize()
            .expect("canonical descriptor home");
        #[cfg(unix)]
        std::fs::set_permissions(&canonical_home, std::fs::Permissions::from_mode(0o700))
            .expect("private descriptor home permissions");
        let descriptor = canonical_home.join("connection.json");
        std::fs::write(
            &descriptor,
            serde_json::to_vec(&connection("http://127.0.0.1:4317")).expect("descriptor JSON"),
        )
        .expect("write descriptor");
        #[cfg(unix)]
        std::fs::set_permissions(&descriptor, std::fs::Permissions::from_mode(0o600))
            .expect("descriptor permissions");
        load_connection(&canonical_home).expect("bounded descriptor");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&descriptor)
            .expect("open descriptor")
            .set_len(super::MAXIMUM_CONNECTION_DESCRIPTOR_BYTES + 1)
            .expect("oversized sparse descriptor");
        assert!(load_connection(&canonical_home).is_err());

        let executable = canonical_home.join("oversized-server");
        let file = std::fs::File::create(&executable).expect("create sparse executable");
        file.set_len(super::MAXIMUM_MCP_EXECUTABLE_BYTES + 1)
            .expect("oversized sparse executable");
        #[cfg(unix)]
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
            .expect("executable permissions");
        assert!(inspect_mcp_executable(&executable).is_err());

        #[cfg(unix)]
        {
            let symlink_descriptor_home = tempfile::tempdir().expect("symlink descriptor home");
            let target = symlink_descriptor_home.path().join("actual.json");
            std::fs::write(
                &target,
                serde_json::to_vec(&connection("http://127.0.0.1:4317"))
                    .expect("symlink target JSON"),
            )
            .expect("write symlink target");
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
                .expect("symlink target permissions");
            std::os::unix::fs::symlink(
                &target,
                symlink_descriptor_home.path().join("connection.json"),
            )
            .expect("descriptor symlink");
            assert!(load_connection(symlink_descriptor_home.path()).is_err());

            let public_home = tempfile::tempdir().expect("public descriptor home");
            let public_descriptor = public_home.path().join("connection.json");
            std::fs::write(
                &public_descriptor,
                serde_json::to_vec(&connection("http://127.0.0.1:4317"))
                    .expect("public descriptor JSON"),
            )
            .expect("write public descriptor");
            std::fs::set_permissions(&public_descriptor, std::fs::Permissions::from_mode(0o600))
                .expect("public descriptor permissions");
            std::fs::set_permissions(public_home.path(), std::fs::Permissions::from_mode(0o750))
                .expect("public home permissions");
            assert!(load_connection(public_home.path()).is_err());

            let parent = tempfile::tempdir().expect("symlink home parent");
            let real_home = parent.path().join("real-home");
            std::fs::create_dir(&real_home).expect("create real home");
            std::fs::set_permissions(&real_home, std::fs::Permissions::from_mode(0o700))
                .expect("real home permissions");
            let real_descriptor = real_home.join("connection.json");
            std::fs::write(
                &real_descriptor,
                serde_json::to_vec(&connection("http://127.0.0.1:4317"))
                    .expect("real descriptor JSON"),
            )
            .expect("write real descriptor");
            std::fs::set_permissions(&real_descriptor, std::fs::Permissions::from_mode(0o600))
                .expect("real descriptor permissions");
            let alias = parent.path().join("home-alias");
            std::os::unix::fs::symlink(&real_home, &alias).expect("home symlink");
            assert!(load_connection(&alias).is_err());
        }
    }

    #[test]
    fn extension_manifest_reads_are_bounded_utf8_regular_and_no_follow() {
        let directory = tempfile::tempdir().expect("extension manifest directory");
        let manifest = directory.path().join("manifest.json");
        std::fs::write(&manifest, b"{\"schemaVersion\":1}").expect("write manifest");
        assert_eq!(
            super::read_extension_manifest(&manifest).expect("bounded manifest"),
            "{\"schemaVersion\":1}"
        );
        std::fs::write(&manifest, [0xff]).expect("write invalid UTF-8");
        assert!(super::read_extension_manifest(&manifest).is_err());
        let file = std::fs::File::create(&manifest).expect("create sparse manifest");
        file.set_len(super::MAXIMUM_EXTENSION_MANIFEST_BYTES + 1)
            .expect("oversized sparse manifest");
        assert!(super::read_extension_manifest(&manifest).is_err());

        #[cfg(unix)]
        {
            let target = directory.path().join("target.json");
            std::fs::write(&target, b"{}").expect("write target manifest");
            let link = directory.path().join("manifest-link.json");
            std::os::unix::fs::symlink(target, &link).expect("manifest symlink");
            assert!(super::read_extension_manifest(&link).is_err());
        }
    }

    #[test]
    fn setup_wizard_prompts_only_for_missing_non_secret_local_values() {
        let arguments =
            Arguments::try_parse_from(["mealyctl", "setup", "--skip-connectivity-test"])
                .expect("guided setup command");
        let Command::Setup(options) = arguments.command else {
            panic!("expected setup command");
        };
        let mut input = Cursor::new(b"4\nlocal-model\n32768\n".as_slice());
        let mut prompt = Vec::new();
        let resolved = resolve_setup(&options, &mut input, &mut prompt).expect("resolve setup");
        assert!(matches!(resolved.provider, SetupProviderArgument::Local));
        assert_eq!(resolved.model, "local-model");
        assert_eq!(resolved.context_tokens, 32_768);
        assert_eq!(resolved.credential_env, None);
        assert_eq!(resolved.base_url, "http://127.0.0.1:11434/v1");
        assert!(resolved.skip_connectivity_test);
        let (provider, secret_id) = setup_provider_config(&resolved);
        assert!(provider.validate().is_ok());
        assert_eq!(secret_id, None);
        let ProviderConfig::OpenAiResponses {
            estimated_latency_ms,
            ..
        } = provider
        else {
            panic!("expected Responses provider");
        };
        assert_eq!(estimated_latency_ms, SETUP_PROVIDER_ESTIMATED_LATENCY_MS);
        assert!(
            SETUP_PROVIDER_ESTIMATED_LATENCY_MS <= AgentLoopLimits::default().provider_timeout_ms,
            "guided setup must produce a route admitted by the default agent budget"
        );
        let prompt = String::from_utf8(prompt).expect("UTF-8 prompt");
        assert!(prompt.contains("Select a provider"));
        assert!(!prompt.to_ascii_lowercase().contains("api key"));
    }

    #[test]
    fn openrouter_price_conversion_and_command_presets_are_exact() {
        assert_eq!(
            normalize_openrouter_display_name(" OpenRouter model "),
            Some("OpenRouter model")
        );
        for invalid in ["", "   ", "model\nname", "model\t"] {
            assert_eq!(normalize_openrouter_display_name(invalid), None);
        }
        let oversized_name = "m".repeat(257);
        assert_eq!(normalize_openrouter_display_name(&oversized_name), None);

        assert_eq!(
            openrouter_price_microunits_per_million("0.00003"),
            Some(30_000_000)
        );
        assert_eq!(
            openrouter_price_microunits_per_million("0.000000000001"),
            Some(1)
        );
        assert_eq!(
            openrouter_price_microunits_per_million("1"),
            Some(1_000_000_000_000)
        );
        for invalid in ["-1", "1e-6", "00.1", "0.", "0.0000000000001", " 0"] {
            assert!(openrouter_price_microunits_per_million(invalid).is_none());
        }
        assert!(openrouter_price_is_zero("0.000000000000"));
        assert!(!openrouter_price_is_zero("0.0001"));
        assert!(!openrouter_price_is_zero("0.0000000000000"));

        let discovery = Arguments::try_parse_from([
            "mealyctl",
            "config",
            "provider-models-openrouter",
            "--contains",
            "claude",
        ])
        .expect("OpenRouter discovery preset");
        assert!(matches!(
            discovery.command,
            Command::Config {
                command: ConfigCommand::ProviderModelsOpenrouter {
                    base_url,
                    credential_env,
                    contains: Some(contains),
                    ..
                }
            } if base_url == "https://openrouter.ai/api/v1"
                && credential_env == "OPENROUTER_API_KEY"
                && contains == "claude"
        ));
        let activation = Arguments::try_parse_from([
            "mealyctl",
            "config",
            "provider-openrouter",
            "--model",
            "anthropic/claude-test",
            "--context-tokens",
            "200000",
            "--input-microunits-per-million-tokens",
            "3000000",
            "--output-microunits-per-million-tokens",
            "15000000",
            "--approve",
        ])
        .expect("OpenRouter activation preset");
        assert!(matches!(
            activation.command,
            Command::Config {
                command: ConfigCommand::ProviderOpenrouter {
                    provider_id,
                    base_url,
                    secret_id,
                    credential_env,
                    approve: true,
                    ..
                }
            } if provider_id == "openrouter.responses"
                && base_url == "https://openrouter.ai/api/v1"
                && secret_id == "openrouter-primary"
                && credential_env == "OPENROUTER_API_KEY"
        ));
    }

    #[test]
    fn onboarding_openrouter_free_policy_requires_complete_exact_zero_metadata() {
        let eligible = super::ProviderModelDiscoveryItem {
            id: "vendor/tool-model:free".to_owned(),
            display_name: Some("Tool model free".to_owned()),
            created_at: None,
            created_at_unix_seconds: Some(1),
            owned_by: Some("vendor".to_owned()),
            context_tokens: Some(32_768),
            maximum_output_tokens: Some(4_096),
            token_limits_complete: true,
            input_microunits_per_million_tokens: Some(0),
            output_microunits_per_million_tokens: Some(0),
            pricing_complete: true,
            unsupported_pricing_axes: Vec::new(),
            tool_capable: Some(true),
        };
        assert!(super::openrouter_model_is_strictly_free(&eligible));

        let mut paid = eligible;
        paid.output_microunits_per_million_tokens = Some(1);
        assert!(!super::openrouter_model_is_strictly_free(&paid));
        paid.output_microunits_per_million_tokens = Some(0);
        paid.id = "vendor/tool-model".to_owned();
        assert!(!super::openrouter_model_is_strictly_free(&paid));
        paid.id = "vendor/tool-model:free".to_owned();
        paid.unsupported_pricing_axes.push("web_search".to_owned());
        assert!(!super::openrouter_model_is_strictly_free(&paid));
    }

    #[test]
    fn chat_command_and_delivery_controls_have_stable_shapes() {
        let arguments =
            Arguments::try_parse_from(["mealyctl", "chat", "--session-id", "durable-session"])
                .expect("chat command");
        assert!(matches!(
            arguments.command,
            Command::Chat {
                session_id: Some(ref session_id)
            } if session_id == "durable-session"
        ));
        assert_eq!(
            parse_chat_line("/steer update the active task"),
            ChatLine::Send {
                delivery: DeliveryMode::SteerAtBoundary,
                content: "update the active task".to_owned(),
            }
        );
        assert_eq!(
            parse_chat_line("/interrupt replace it"),
            ChatLine::Send {
                delivery: DeliveryMode::InterruptThenQueue,
                content: "replace it".to_owned(),
            }
        );
        assert_eq!(
            parse_chat_line("/attach notes/owner selected brief.md"),
            ChatLine::LocalAttachment {
                path: std::path::PathBuf::from("notes/owner selected brief.md"),
            }
        );
        assert_eq!(parse_chat_line("/attach "), ChatLine::Help);
        assert_eq!(
            parse_chat_line("/approve approval-1 subject-digest"),
            ChatLine::ResolveApproval {
                approval_id: "approval-1".to_owned(),
                subject_digest: "subject-digest".to_owned(),
                decision: mealy_protocol::ApprovalDecisionCommand::Approve,
            }
        );
        assert_eq!(
            parse_chat_line("/deny approval-2 subject-digest"),
            ChatLine::ResolveApproval {
                approval_id: "approval-2".to_owned(),
                subject_digest: "subject-digest".to_owned(),
                decision: mealy_protocol::ApprovalDecisionCommand::Deny,
            }
        );
        assert_eq!(parse_chat_line("/approve incomplete"), ChatLine::Help);
        assert_eq!(
            parse_chat_line("/remember The owner prefers concise answers"),
            ChatLine::Memory(ChatMemoryCommand::Remember(
                "The owner prefers concise answers".to_owned()
            ))
        );
        assert_eq!(
            parse_chat_line("/memories concise answers"),
            ChatLine::Memory(ChatMemoryCommand::Search("concise answers".to_owned()))
        );
        assert_eq!(
            parse_chat_line("/memory-correct memory-1 4 corrected fact"),
            ChatLine::Memory(ChatMemoryCommand::Correct {
                memory_id: "memory-1".to_owned(),
                expected_revision: 4,
                content: "corrected fact".to_owned(),
            })
        );
        assert_eq!(
            parse_chat_line("/memory-delete memory-1 5"),
            ChatLine::Memory(ChatMemoryCommand::Delete {
                memory_id: "memory-1".to_owned(),
                expected_revision: 5,
            })
        );
        assert_eq!(
            parse_chat_line("/history amber orbit"),
            ChatLine::History("amber orbit".to_owned())
        );
        assert_eq!(
            parse_chat_line("/act create a report"),
            ChatLine::Send {
                delivery: DeliveryMode::Queue,
                content: "/act create a report".to_owned(),
            }
        );
        assert_eq!(
            parse_chat_line("/edit replace the stale report"),
            ChatLine::Send {
                delivery: DeliveryMode::Queue,
                content: "/edit replace the stale report".to_owned(),
            }
        );
        assert_eq!(
            parse_chat_line("/manage move the completed report into archive"),
            ChatLine::Send {
                delivery: DeliveryMode::Queue,
                content: "/manage move the completed report into archive".to_owned(),
            }
        );
        assert_eq!(parse_chat_line("/quit"), ChatLine::Exit);
    }

    #[test]
    fn chat_resume_reducer_retains_pending_and_finds_the_exact_active_turn() {
        let events = [
            timeline_event(
                1,
                "input.accepted",
                "session",
                "session-1",
                "correlation-a",
                json!({"inbox_entry_id": "input-a"}),
            ),
            timeline_event(
                2,
                "input.promoted",
                "session",
                "session-1",
                "correlation-a",
                json!({"inbox_entry_id": "input-a", "turn_id": "turn-old"}),
            ),
            timeline_event(
                3,
                "input.accepted",
                "session",
                "session-1",
                "correlation-b",
                json!({"inbox_entry_id": "input-b"}),
            ),
            timeline_event(
                4,
                "input.interrupt_requested",
                "session",
                "session-1",
                "correlation-b",
                json!({"inbox_entry_id": "input-b"}),
            ),
            timeline_event(
                5,
                "task.created",
                "task",
                "task-active",
                "correlation-active",
                json!({"turn_id": "turn-active"}),
            ),
        ];
        let mut pending = BTreeMap::new();
        let mut active = None;
        for event in &events {
            observe_resumable_chat_event(event, Some("turn-active"), &mut pending, &mut active);
        }
        assert_eq!(pending, BTreeMap::from([("input-b".to_owned(), 3)]));
        assert_eq!(
            active.map(|task: ResumableChatTask| (task.task_id, task.correlation_id)),
            Some(("task-active".to_owned(), "correlation-active".to_owned()))
        );
    }

    fn timeline_event(
        cursor: u64,
        event_type: &str,
        aggregate_kind: &str,
        aggregate_id: &str,
        correlation_id: &str,
        payload: serde_json::Value,
    ) -> TimelineEvent {
        TimelineEvent {
            cursor: TimelineCursor(cursor),
            event_id: format!("event-{cursor}"),
            aggregate_kind: aggregate_kind.to_owned(),
            aggregate_id: aggregate_id.to_owned(),
            aggregate_sequence: cursor,
            event_type: event_type.to_owned(),
            event_version: 1,
            occurred_at_ms: i64::try_from(cursor).expect("test cursor"),
            correlation_id: correlation_id.to_owned(),
            causation_id: None,
            payload,
            event_digest: "a".repeat(64),
        }
    }

    #[test]
    fn memory_and_compaction_commands_have_stable_owner_workflows() {
        let digest = "a".repeat(64);
        let memory = Arguments::try_parse_from([
            "mealyctl",
            "memory",
            "propose",
            "--workspace",
            "fixture://phase2",
            "remember this",
            "--source",
            &format!("event://1={digest}"),
        ])
        .expect("parse governed memory proposal");
        assert!(matches!(
            memory.command,
            Command::Memory {
                command: MemoryCommand::Propose { .. }
            }
        ));

        let remember = Arguments::try_parse_from([
            "mealyctl",
            "memory",
            "remember",
            "--workspace",
            "mealy://assistant/no-workspace",
            "remember this directly",
            "--approve",
        ])
        .expect("parse direct governed memory activation");
        assert!(matches!(
            remember.command,
            Command::Memory {
                command: MemoryCommand::Remember { approve: true, .. }
            }
        ));

        let history = Arguments::try_parse_from([
            "mealyctl",
            "session",
            "search",
            "continuity marker",
            "--limit",
            "7",
        ])
        .expect("parse transcript search");
        assert!(matches!(
            history.command,
            Command::Session {
                command: super::SessionCommand::Search { limit: 7, .. }
            }
        ));

        let rejection = Arguments::try_parse_from([
            "mealyctl",
            "memory",
            "reject",
            "memory-id",
            "--expected-revision",
            "0",
        ])
        .expect("parse governed memory rejection");
        assert!(matches!(
            rejection.command,
            Command::Memory {
                command: MemoryCommand::Reject {
                    expected_revision: 0,
                    ..
                }
            }
        ));

        let compaction = Arguments::try_parse_from([
            "mealyctl",
            "compaction",
            "create",
            "session-id",
            "--first-cursor",
            "1",
            "--last-cursor",
            "2",
            "--summary",
            "summary",
            "--carry-forward-json",
            "{}",
        ])
        .expect("parse cited compaction command");
        assert!(matches!(
            compaction.command,
            Command::Compaction {
                command: CompactionCommand::Create { .. }
            }
        ));
    }

    #[test]
    fn approval_and_effect_inspection_commands_have_stable_shapes() {
        let approval = Arguments::try_parse_from(["mealyctl", "approval", "list"])
            .expect("approval list command");
        assert!(matches!(
            approval.command,
            Command::Approval {
                command: ApprovalCommand::List
            }
        ));

        let effect = Arguments::try_parse_from(["mealyctl", "effect", "status", "effect-1"])
            .expect("effect status command");
        assert!(matches!(
            effect.command,
            Command::Effect {
                command: EffectCommand::Status { effect_id }
            } if effect_id == "effect-1"
        ));

        let attempt = Arguments::try_parse_from(["mealyctl", "effect", "attempt", "attempt-1"])
            .expect("effect attempt command");
        assert!(matches!(
            attempt.command,
            Command::Effect {
                command: EffectCommand::Attempt { attempt_id }
            } if attempt_id == "attempt-1"
        ));

        let resolve = Arguments::try_parse_from([
            "mealyctl",
            "approval",
            "resolve",
            "approval-1",
            "approve",
            "--subject-digest",
            &"a".repeat(64),
            "--idempotency-key",
            "approval-command-1",
        ])
        .expect("approval resolve command");
        assert!(matches!(
            resolve.command,
            Command::Approval {
                command: ApprovalCommand::Resolve {
                    approval_id,
                    subject_digest,
                    idempotency_key: Some(idempotency_key),
                    ..
                }
            } if approval_id == "approval-1"
                && subject_digest == "a".repeat(64)
                && idempotency_key == "approval-command-1"
        ));

        let reconcile = Arguments::try_parse_from([
            "mealyctl",
            "effect",
            "reconcile",
            "effect-1",
            "attempt-1",
            "succeeded",
            "--revision",
            "3",
            "--evidence-json",
            r#"{"receipt":"external-1"}"#,
            "--idempotency-key",
            "reconciliation-command-1",
        ])
        .expect("effect reconcile command");
        assert!(matches!(
            reconcile.command,
            Command::Effect {
                command: EffectCommand::Reconcile {
                    effect_id,
                    attempt_id,
                    revision: 3,
                    idempotency_key: Some(idempotency_key),
                    ..
                }
            } if effect_id == "effect-1"
                && attempt_id == "attempt-1"
                && idempotency_key == "reconciliation-command-1"
        ));
    }

    #[test]
    fn delegation_commands_have_bounded_owner_inspection_shapes() {
        let list = Arguments::try_parse_from(["mealyctl", "delegation", "list", "--limit", "7"])
            .expect("delegation list command");
        assert!(matches!(
            list.command,
            Command::Delegation {
                command: DelegationCommand::List { limit: 7 }
            }
        ));

        let status =
            Arguments::try_parse_from(["mealyctl", "delegation", "status", "delegation-1"])
                .expect("delegation status command");
        assert!(matches!(
            status.command,
            Command::Delegation {
                command: DelegationCommand::Status { delegation_id }
            } if delegation_id == "delegation-1"
        ));
    }

    #[test]
    fn extension_commands_require_explicit_digest_revision_and_grants() {
        let install = Arguments::try_parse_from([
            "mealyctl",
            "extension",
            "install",
            "--manifest",
            "/tmp/manifest.json",
            "--digest",
            &"a".repeat(64),
            "--installation-root",
            "/tmp/package",
        ])
        .expect("extension install command");
        assert!(matches!(
            install.command,
            Command::Extension {
                command: ExtensionCommand::Install { .. }
            }
        ));

        let enable = Arguments::try_parse_from([
            "mealyctl",
            "extension",
            "enable",
            "extension-1",
            "--expected-revision",
            "2",
            "--capability",
            "health",
            "--capability",
            "text_stats",
        ])
        .expect("extension enable command");
        assert!(matches!(
            enable.command,
            Command::Extension {
                command: ExtensionCommand::Enable {
                    expected_revision: 2,
                    capabilities,
                    ..
                }
            } if capabilities == ["health", "text_stats"]
        ));
    }

    #[test]
    fn skill_commands_separate_inert_installation_from_digest_fenced_activation() {
        let install = Arguments::try_parse_from([
            "mealyctl",
            "skill",
            "install",
            "--manifest",
            "/tmp/skill/manifest.json",
            "--package-root",
            "/tmp/skill",
            "--digest",
            &"a".repeat(64),
            "--approve",
        ])
        .expect("skill install command");
        assert!(matches!(
            install.command,
            Command::Skill {
                command: SkillCommand::Install { approve: true, .. }
            }
        ));

        let enable = Arguments::try_parse_from([
            "mealyctl",
            "skill",
            "enable",
            "mealy.fixture.review",
            "--expected-manifest-digest",
            &"b".repeat(64),
            "--approve",
        ])
        .expect("skill enable command");
        assert!(matches!(
            enable.command,
            Command::Skill {
                command: SkillCommand::Enable {
                    skill_id,
                    expected_manifest_digest,
                    approve: true,
                }
            } if skill_id == "mealy.fixture.review"
                && expected_manifest_digest == "b".repeat(64)
        ));
    }

    #[test]
    fn signed_channel_commands_expose_creation_and_terminal_revocation() {
        let create = Arguments::try_parse_from([
            "mealyctl",
            "channel",
            "create",
            "--external-subject",
            "platform-user-7",
            "--callback-url",
            "https://channel.example.test/mealy",
        ])
        .expect("signed channel create command");
        assert!(matches!(
            create.command,
            Command::Channel {
                command: ChannelCommand::Create { .. }
            }
        ));

        let revoke = Arguments::try_parse_from([
            "mealyctl",
            "channel",
            "revoke",
            "binding-1",
            "--expected-revision",
            "0",
        ])
        .expect("signed channel revoke command");
        assert!(matches!(
            revoke.command,
            Command::Channel {
                command: ChannelCommand::Revoke {
                    expected_revision: 0,
                    ..
                }
            }
        ));

        let telegram = Arguments::try_parse_from([
            "mealyctl",
            "channel",
            "telegram-create",
            "--user-id",
            "7001",
            "--chat-id",
            "8001",
            "--token-env",
            "TELEGRAM_BOT_TOKEN",
        ])
        .expect("Telegram create command");
        assert!(matches!(
            telegram.command,
            Command::Channel {
                command: ChannelCommand::TelegramCreate {
                    user_id: 7001,
                    chat_id: 8001,
                    ..
                }
            }
        ));

        let pairing = Arguments::try_parse_from([
            "mealyctl",
            "channel",
            "telegram-pair",
            "--token-env",
            "TELEGRAM_BOT_TOKEN",
            "--timeout-seconds",
            "90",
        ])
        .expect("Telegram pair command");
        assert!(matches!(
            pairing.command,
            Command::Channel {
                command: ChannelCommand::TelegramPair {
                    timeout_seconds: 90,
                    ..
                }
            }
        ));
    }

    #[test]
    fn telegram_pairing_requires_an_exact_human_private_chat_and_advances_the_cursor() {
        let expected = "/pair MEALY-test-challenge";
        let group_attempt = TelegramPairUpdate {
            update_id: 40,
            message: Some(TelegramPairMessage {
                from: Some(TelegramPairUser {
                    id: 7_001,
                    is_bot: false,
                }),
                chat: TelegramPairChat {
                    id: -8_001,
                    kind: "group".to_owned(),
                },
                text: Some(expected.to_owned()),
            }),
        };
        let private_attempt = TelegramPairUpdate {
            update_id: 41,
            message: Some(TelegramPairMessage {
                from: Some(TelegramPairUser {
                    id: 7_001,
                    is_bot: false,
                }),
                chat: TelegramPairChat {
                    id: 7_001,
                    kind: "private".to_owned(),
                },
                text: Some(expected.to_owned()),
            }),
        };
        let mut offset = 0;
        let pairing = observe_telegram_pair_updates(
            vec![group_attempt, private_attempt],
            expected,
            &mut offset,
        )
        .expect("valid update batch")
        .expect("private pairing");
        assert_eq!(pairing.user, 7_001);
        assert_eq!(pairing.chat, 7_001);
        assert_eq!(pairing.next_update, 42);
        assert_eq!(offset, 42);
    }

    #[test]
    fn telegram_pair_challenges_and_origins_are_strict_and_secret_safe() {
        let challenge = generate_telegram_pair_challenge().expect("pair challenge");
        assert!(challenge.starts_with("MEALY-"));
        assert_eq!(challenge.len(), 28);
        assert!(
            challenge
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );

        let token = "123456:abcdefghijklmnopqrstuvwxyz_ABCDEFGH";
        let url = telegram_pair_api_url("http://127.0.0.1:4317", token, "getUpdates")
            .expect("literal-loopback test origin");
        assert_eq!(url.path(), format!("/bot{token}/getUpdates"));
        for origin in [
            "http://api.telegram.org",
            "http://localhost:4317",
            "https://user@example.test",
            "https://example.test/prefix",
        ] {
            let error = telegram_pair_api_url(origin, token, "getMe")
                .expect_err("unsafe origin must fail")
                .to_string();
            assert!(!error.contains(token));
        }
    }

    #[test]
    fn discord_pairing_requires_the_exact_human_dm_and_canonical_cursor() {
        let expected = "/pair MEALY-test-challenge";
        let mut cursor = Some("40".to_owned());
        let attacker = DiscordPairMessage {
            id: "41".to_owned(),
            channel_id: "8001".to_owned(),
            author: DiscordPairUser {
                id: "7002".to_owned(),
                username: "attacker".to_owned(),
                bot: false,
            },
            content: expected.to_owned(),
            message_type: 0,
            attachments: Vec::new(),
        };
        let valid = DiscordPairMessage {
            id: "42".to_owned(),
            channel_id: "8001".to_owned(),
            author: DiscordPairUser {
                id: "7001".to_owned(),
                username: "owner".to_owned(),
                bot: false,
            },
            content: expected.to_owned(),
            message_type: 0,
            attachments: Vec::new(),
        };
        let pairing = observe_discord_pair_messages(
            vec![valid, attacker],
            "8001",
            "7001",
            expected,
            &mut cursor,
        )
        .expect("valid Discord history")
        .expect("exact Discord pairing");
        assert_eq!(pairing.user, "7001");
        assert_eq!(pairing.channel, "8001");
        assert_eq!(cursor.as_deref(), Some("42"));
    }

    #[test]
    fn discord_pair_challenges_origins_and_commands_are_strict() {
        let challenge = generate_discord_pair_challenge().expect("pair challenge");
        assert!(challenge.starts_with("MEALY-"));
        assert_eq!(challenge.len(), 28);
        assert_eq!(
            validate_discord_pair_base_url("https://discord.com/api/v10").expect("official API"),
            "https://discord.com/api/v10"
        );
        assert!(validate_discord_pair_base_url("http://127.0.0.1:4317").is_ok());
        for origin in [
            "http://discord.com/api/v10",
            "https://api.discord.com/api/v10",
            "https://discord.com/api/v9",
            "http://localhost:4317",
            "https://user@discord.com/api/v10",
        ] {
            assert!(
                validate_discord_pair_base_url(origin).is_err(),
                "accepted unsafe Discord origin {origin}"
            );
        }

        let command = Arguments::try_parse_from([
            "mealyctl",
            "channel",
            "discord-pair",
            "--channel-id",
            "8001",
            "--timeout-seconds",
            "90",
        ])
        .expect("Discord pair command");
        assert!(matches!(
            command.command,
            Command::Channel {
                command: ChannelCommand::DiscordPair {
                    channel_id,
                    timeout_seconds: 90,
                    ..
                }
            } if channel_id == "8001"
        ));
    }

    #[test]
    fn schedule_commands_expose_timezone_policies_and_revision_fences() {
        let create = Arguments::try_parse_from([
            "mealyctl",
            "schedule",
            "create",
            "session-1",
            "--name",
            "weekday brief",
            "--cron",
            "0 9 * * MON-FRI",
            "--timezone",
            "Pacific/Auckland",
            "--missed-run-policy",
            "latest",
            "--overlap-policy",
            "skip-if-running",
            "Prepare the weekday brief.",
        ])
        .expect("schedule create command");
        assert!(matches!(
            create.command,
            Command::Schedule {
                command: ScheduleCommand::Create {
                    session_id,
                    cron,
                    timezone,
                    ..
                }
            } if session_id == "session-1"
                && cron == "0 9 * * MON-FRI"
                && timezone == "Pacific/Auckland"
        ));

        let pause = Arguments::try_parse_from([
            "mealyctl",
            "schedule",
            "pause",
            "schedule-1",
            "--expected-revision",
            "4",
        ])
        .expect("schedule pause command");
        assert!(matches!(
            pause.command,
            Command::Schedule {
                command: ScheduleCommand::Pause {
                    schedule_id,
                    expected_revision: 4,
                }
            } if schedule_id == "schedule-1"
        ));
    }

    #[test]
    fn configuration_rollback_requires_an_exact_digest_and_explicit_approval_shape() {
        let digest = "a".repeat(64);
        let parsed = Arguments::try_parse_from([
            "mealyctl",
            "--home",
            "/tmp/mealy",
            "config",
            "rollback",
            &digest,
            "--approve",
        ])
        .expect("config rollback command");
        assert!(matches!(
            parsed.command,
            Command::Config {
                command: ConfigCommand::Rollback { approve: true, .. }
            }
        ));
    }

    #[test]
    fn service_removal_is_plan_first_and_requires_explicit_approval() {
        let plan = Arguments::try_parse_from([
            "mealyctl",
            "--home",
            "/tmp/mealy",
            "service",
            "remove",
            "--destination",
            "/tmp/mealy.service",
        ])
        .expect("service removal plan");
        assert!(matches!(
            plan.command,
            Command::Service {
                command: ServiceCommand::Remove { approve: false, .. }
            }
        ));

        let apply = Arguments::try_parse_from([
            "mealyctl",
            "--home",
            "/tmp/mealy",
            "service",
            "remove",
            "--destination",
            "/tmp/mealy.service",
            "--approve",
        ])
        .expect("approved service removal");
        assert!(matches!(
            apply.command,
            Command::Service {
                command: ServiceCommand::Remove { approve: true, .. }
            }
        ));
    }

    #[test]
    fn restore_activation_binds_manifest_passphrase_source_and_approval() {
        let digest = "b".repeat(64);
        let parsed = Arguments::try_parse_from([
            "mealyctl",
            "--home",
            "/tmp/mealy",
            "restore-activate",
            "encrypted-daily",
            "--expected-manifest-digest",
            &digest,
            "--passphrase-env",
            "RESTORE_PASSPHRASE",
            "--approve",
        ])
        .expect("restore activation command");
        assert!(matches!(
            parsed.command,
            Command::RestoreActivate {
                name,
                expected_manifest_digest,
                passphrase_env,
                approve: true,
            } if name == "encrypted-daily"
                && expected_manifest_digest == digest
                && passphrase_env == "RESTORE_PASSPHRASE"
        ));
    }
}
