//! Local administrative and scripting client for Mealy.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand, ValueEnum};
use eventsource_stream::Eventsource;
use futures_util::StreamExt;
use mealy_protocol::{
    API_VERSION, AdminMetricsResponse, AdminStatusResponse, ApiErrorResponse,
    ApprovalDecisionCommand, ApprovalResolutionReceipt, BackupResponse, BackupVerificationResponse,
    CancelTaskRequest, CompactionResponse, ControlTaskRequest, CorrectMemoryRequest,
    CreateBackupRequest, CreateCompactionRequest, CreateExportRequest, CreateSessionRequest,
    CreateSessionResponse, CreateWebhookChannelRequest, CreateWebhookChannelResponse, DeliveryMode,
    DoctorResponse, DrainDaemonRequest, DrainDaemonResponse, EffectAttemptResponse,
    EffectReconciliationReceipt, EffectResponse, EnableExtensionRequest, ExportKindRequest,
    ExportResponse, ExtensionInvocationResponse, ExtensionLifecycleRequest,
    ExtensionMountGrantCommand, ExtensionResponse, ExtensionsResponse, GarbageCollectionResponse,
    HealthResponse, InputAdmissionResponse, InstallExtensionRequest, InvokeExtensionRequest,
    LocalConnectionInfo, MemoriesResponse, MemoryCategoryCommand, MemoryIndexRebuildResponse,
    MemoryLifecycleRequest, MemoryPromotionAuthorizationCommand, MemoryResponse,
    MemoryRetentionCommand, MemorySearchResponse, MemorySensitivityCommand, MemorySourceCommand,
    PendingApprovalsResponse, PromoteMemoryRequest, ProposeMemoryRequest,
    RebuildMemoryIndexRequest, ReconcileEffectRequest, ReconciliationOutcomeCommand,
    ResolveApprovalRequest, RevokeWebhookChannelRequest, RunGarbageCollectionRequest,
    SessionStatusResponse, SetMemoryPinRequest, StageExtensionManifestRequest, SubmitInputRequest,
    TaskCancellationReceipt, TaskControlReceipt, TaskReplayResponse, TaskResponse,
    VerifyBackupRequest, WebhookChannelResponse, WebhookChannelsResponse,
};
use reqwest::{Client, Response, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use thiserror::Error;

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

#[derive(Debug, Subcommand)]
enum Command {
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
    /// Create, inspect, or terminally revoke signed external webhook channels.
    Channel {
        /// Channel operation.
        #[command(subcommand)]
        command: ChannelCommand,
    },
    /// Check daemon liveness.
    Health,
    /// Inspect queue, lease, approval, effect, extension, channel, and storage health.
    Status,
    /// Print stable machine-readable operational gauges.
    Metrics,
    /// Diagnose control-plane storage, permissions, and sandbox-profile conformance.
    Doctor,
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
    /// Explicitly restore a previously activated configuration while the daemon is stopped.
    Config {
        /// Configuration operation.
        #[command(subcommand)]
        command: ConfigCommand,
    },
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
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
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

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<(), CliError> {
    let arguments = Arguments::parse();
    if let Command::Service { command } = &arguments.command {
        return run_service_installation(&arguments.home, command);
    }
    if let Command::Config { command } = &arguments.command {
        return run_config_operation(&arguments.home, command);
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
        Command::Session { command } => {
            run_session(&client, &arguments.home, &connection, command).await?;
        }
        Command::Task { command } => run_task(&client, &connection, command).await?,
        Command::Approval { command } => run_approval(&client, &connection, command).await?,
        Command::Effect { command } => run_effect(&client, &connection, command).await?,
        Command::Memory { command } => run_memory(&client, &connection, command).await?,
        Command::Compaction { command } => run_compaction(&client, &connection, command).await?,
        Command::Extension { command } => run_extension(&client, &connection, command).await?,
        Command::Channel { command } => run_channel(&client, &connection, command).await?,
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
        Command::Doctor => {
            let response = authorized(
                client.get(format!("{}/v1/admin/doctor", connection.base_url)),
                &connection,
            )
            .send()
            .await?;
            print_json(decode::<DoctorResponse>(response).await?)?;
        }
        Command::Drain => {
            let response = authorized(
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
            let response = authorized(
                client.post(format!("{}/v1/admin/backups", connection.base_url)),
                &connection,
            )
            .json(&CreateBackupRequest {
                api_version: API_VERSION.to_owned(),
                name,
                include_secrets,
                secret_passphrase,
            })
            .send()
            .await?;
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
            let response = authorized(
                client.post(format!(
                    "{}/v1/admin/backup-verifications",
                    connection.base_url
                )),
                &connection,
            )
            .json(&VerifyBackupRequest {
                api_version: API_VERSION.to_owned(),
                name,
                secret_passphrase,
            })
            .send()
            .await?;
            print_json(decode::<BackupVerificationResponse>(response).await?)?;
        }
        Command::GarbageCollect => {
            let response = authorized(
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
            let response = authorized(
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
                eprintln!("exported governed memories to {}", path.display());
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
    std::fs::read_to_string(path).map_err(CliError::from)
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

async fn watch(
    client: &Client,
    home: &Path,
    session_id: &str,
    mut after: Option<u64>,
    limit: usize,
) -> Result<(), CliError> {
    let mut observed = 0_usize;
    let mut reconnect_delay = Duration::from_millis(200);
    'connect: loop {
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
        let mut request = authorized(
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
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                sleep_before_reconnect(
                    &format!("timeline connection failed: {error}"),
                    &mut reconnect_delay,
                )
                .await;
                continue;
            }
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
        let mut events = response.bytes_stream().eventsource();
        while let Some(event) = events.next().await {
            let event = match event {
                Ok(event) => event,
                Err(error) => {
                    sleep_before_reconnect(
                        &format!("timeline stream interrupted ({error})"),
                        &mut reconnect_delay,
                    )
                    .await;
                    continue 'connect;
                }
            };
            if event.event == "error" {
                if serde_json::from_str::<ApiErrorResponse>(&event.data)
                    .is_ok_and(|error| error.retryable)
                {
                    sleep_before_reconnect(
                        "timeline service is temporarily unavailable",
                        &mut reconnect_delay,
                    )
                    .await;
                    continue 'connect;
                }
                return Err(CliError::Protocol(event.data));
            }
            if !event.id.is_empty() {
                after = Some(
                    event
                        .id
                        .parse()
                        .map_err(|_| CliError::Protocol("invalid SSE cursor".to_owned()))?,
                );
            }
            println!("{}", event.data);
            reconnect_delay = Duration::from_millis(200);
            observed = observed.saturating_add(1);
            if limit != 0 && observed >= limit {
                return Ok(());
            }
        }
        sleep_before_reconnect("timeline stream ended", &mut reconnect_delay).await;
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
                return response.json().await.map_err(CliError::from);
            }
            Ok(response) if retryable_status(response.status()) && attempt < 4 => {
                eprintln!(
                    "input admission returned {}; retrying with idempotency key {}",
                    response.status(),
                    request.idempotency_key
                );
            }
            Ok(response) => return Err(server_error(response).await),
            Err(error) if attempt < 4 => {
                eprintln!(
                    "input admission response was unavailable ({error}); retrying with idempotency key {}",
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceInstallationResponse {
    platform: String,
    service_definition: String,
    daemon_path: String,
    home: String,
    rollback_copy: Option<String>,
    activation_command: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigRollbackResponse {
    activated_digest: String,
    configuration_path: String,
    replaced_configuration_copy: String,
    restart_required: bool,
}

fn run_config_operation(home: &Path, command: &ConfigCommand) -> Result<(), CliError> {
    let ConfigCommand::Rollback { digest, approve } = command;
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
    let home = absolute_service_path(home)?;
    let metadata = fs::symlink_metadata(&home)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::InvalidService(
            "Mealy home must be a real directory".to_owned(),
        ));
    }
    let mut lock_options = OpenOptions::new();
    lock_options.create(true).read(true).write(true);
    #[cfg(unix)]
    lock_options.mode(0o600);
    let instance_lock = lock_options.open(home.join("mealyd.lock"))?;
    match instance_lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Err(CliError::DaemonRunning),
        Err(std::fs::TryLockError::Error(error)) => return Err(CliError::Io(error)),
    }
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
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(|_| CliError::InvalidConfigurationDigest)?
        .as_millis();
    let replaced = home
        .join("config-history")
        .join(format!("pre-rollback-{timestamp}.json"));
    atomic_write_service(&replaced, &current_body)?;
    atomic_write_service(&current, &archived_body)?;
    print_json(ConfigRollbackResponse {
        activated_digest: digest.clone(),
        configuration_path: current.display().to_string(),
        replaced_configuration_copy: replaced.display().to_string(),
        restart_required: true,
    })
}

fn run_service_installation(home: &Path, command: &ServiceCommand) -> Result<(), CliError> {
    let ServiceCommand::Install {
        daemon_path,
        destination,
    } = command;
    let daemon = daemon_path
        .clone()
        .map_or_else(default_daemon_path, Ok)?
        .canonicalize()
        .map_err(CliError::Io)?;
    validate_daemon_executable(&daemon)?;
    let home = absolute_service_path(home)?;
    let (platform, default_destination, body, activation) = service_definition(&daemon, &home)?;
    let destination = destination.as_ref().map_or_else(
        || Ok(default_destination),
        |path| absolute_service_path(path),
    )?;
    let parent = destination.parent().ok_or_else(|| {
        CliError::InvalidService("service definition has no parent directory".to_owned())
    })?;
    create_private_service_directory(parent)?;
    let rollback = preserve_service_rollback(&destination)?;
    atomic_write_service(&destination, body.as_bytes())?;
    print_json(ServiceInstallationResponse {
        platform,
        service_definition: destination.display().to_string(),
        daemon_path: daemon.display().to_string(),
        home: home.display().to_string(),
        rollback_copy: rollback.map(|path| path.display().to_string()),
        activation_command: activation(&destination),
    })
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

type ActivationCommand = fn(&Path) -> String;

fn service_definition(
    daemon: &Path,
    home: &Path,
) -> Result<(String, PathBuf, String, ActivationCommand), CliError> {
    let daemon_text = daemon.display().to_string();
    let home_text = home.display().to_string();
    validate_service_text(&daemon_text)?;
    validate_service_text(&home_text)?;
    #[cfg(target_os = "linux")]
    {
        let configuration_root = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .ok_or_else(|| {
                CliError::InvalidService(
                    "XDG_CONFIG_HOME or HOME is required for user service installation".to_owned(),
                )
            })?;
        let body = format!(
            "[Unit]\nDescription=Mealy local-first agent daemon\nAfter=default.target\n\n\
             [Service]\nType=simple\nExecStart={} --home {}\nRestart=on-failure\nRestartSec=2\n\
             NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\n\
             ReadWritePaths={}\n\n[Install]\nWantedBy=default.target\n",
            systemd_quote(&daemon_text),
            systemd_quote(&home_text),
            systemd_quote(&home_text),
        );
        Ok((
            "linux-systemd-user".to_owned(),
            configuration_root.join("systemd/user/mealy.service"),
            body,
            linux_activation_command,
        ))
    }
    #[cfg(target_os = "macos")]
    {
        let user_home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
            CliError::InvalidService("HOME is required for LaunchAgent installation".to_owned())
        })?;
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\n<key>Label</key><string>dev.mealy.mealyd</string>\n\
             <key>ProgramArguments</key><array><string>{}</string><string>--home</string>\
             <string>{}</string></array>\n<key>KeepAlive</key><true/>\n\
             <key>ProcessType</key><string>Background</string>\n</dict></plist>\n",
            xml_escape(&daemon_text),
            xml_escape(&home_text),
        );
        Ok((
            "macos-launch-agent".to_owned(),
            user_home.join("Library/LaunchAgents/dev.mealy.mealyd.plist"),
            body,
            macos_activation_command,
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (daemon_text, home_text);
        Err(CliError::UnsupportedPlatform(
            "automatic user-service installation is not implemented on this platform; run mealyd under an owner-managed service and use doctor to confirm fail-closed profiles"
                .to_owned(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn systemd_quote(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    format!("\"{escaped}\"")
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
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
fn linux_activation_command(_path: &Path) -> String {
    "systemctl --user daemon-reload && systemctl --user enable --now mealy.service".to_owned()
}

#[cfg(target_os = "macos")]
fn macos_activation_command(path: &Path) -> String {
    format!("launchctl bootstrap gui/$(id -u) {}", path.display())
}

fn authorized(
    request: reqwest::RequestBuilder,
    connection: &LocalConnectionInfo,
) -> reqwest::RequestBuilder {
    request.bearer_auth(&connection.bearer_token)
}

async fn decode<T: DeserializeOwned>(response: Response) -> Result<T, CliError> {
    if response.status().is_success() {
        response.json::<T>().await.map_err(CliError::from)
    } else {
        Err(server_error(response).await)
    }
}

async fn server_error(response: Response) -> CliError {
    let status = response.status();
    match response.json::<ApiErrorResponse>().await {
        Ok(error) => CliError::Server {
            status,
            code: error.code,
            message: error.message,
        },
        Err(error) => CliError::Server {
            status,
            code: "invalid_error_response".to_owned(),
            message: error.to_string(),
        },
    }
}

fn load_connection(home: &Path) -> Result<LocalConnectionInfo, CliError> {
    let path = home.join("connection.json");
    validate_private_descriptor(&path)?;
    let bytes = std::fs::read(path)?;
    let connection: LocalConnectionInfo = serde_json::from_slice(&bytes)?;
    validate_connection(&connection)?;
    Ok(connection)
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
fn validate_private_descriptor(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(CliError::InvalidConnection(
            "connection.json must not be accessible by group or other users".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_descriptor(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

fn generate_idempotency_key() -> Result<String, CliError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| CliError::RandomUnavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn read_passphrase_environment(name: &str) -> Result<String, CliError> {
    if name.is_empty()
        || name.len() > 128
        || name
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'_')
    {
        return Err(CliError::InvalidPassphraseEnvironment);
    }
    std::env::var(name).map_err(|_| CliError::MissingPassphrase(name.to_owned()))
}

fn print_json(value: impl Serialize) -> Result<(), CliError> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
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
    #[error("configuration rollback requires --approve")]
    ApprovalRequired,
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
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalCommand, Arguments, ChannelCommand, Command, CompactionCommand, ConfigCommand,
        EffectCommand, ExtensionCommand, MemoryCommand, validate_connection,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use clap::Parser;
    use mealy_protocol::{API_VERSION, LocalConnectionInfo};

    fn connection(base_url: &str) -> LocalConnectionInfo {
        LocalConnectionInfo {
            api_version: API_VERSION.to_owned(),
            base_url: base_url.to_owned(),
            bearer_token: URL_SAFE_NO_PAD.encode([7_u8; 32]),
            principal_id: "principal".to_owned(),
            channel_binding_id: "binding".to_owned(),
        }
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
}
