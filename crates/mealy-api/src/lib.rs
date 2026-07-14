//! Authenticated loopback HTTP/JSON and SSE adapter for Mealy.

use async_stream::stream;
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{
        DefaultBodyLimit, Extension, Path, Query, Request, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response, Sse, sse::Event},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mealy_application::{
    MAXIMUM_EFFECT_COMMAND_IDEMPOTENCY_KEY_BYTES, MAXIMUM_EFFECT_OUTCOME_DETAILS_BYTES,
};
use mealy_protocol::{
    API_VERSION, AdminMetricsResponse, AdminStatusResponse, AdminUsageReportResponse,
    ApiErrorResponse, ApprovalResolutionReceipt, ArtifactMetadataResponse, BackupResponse,
    BackupVerificationResponse, CancelTaskRequest, CompactionResponse,
    ContextManifestEvidenceResponse, ControlTaskRequest, CorrectMemoryRequest, CreateBackupRequest,
    CreateCompactionRequest, CreateDiscordChannelRequest, CreateExportRequest,
    CreateScheduleRequest, CreateSessionRequest, CreateSessionResponse,
    CreateTelegramChannelRequest, CreateWebhookChannelRequest, CreateWebhookChannelResponse,
    DelegationResponse, DelegationsResponse, DiscordChannelResponse, DiscordChannelsResponse,
    DoctorResponse, DrainDaemonRequest, DrainDaemonResponse, EffectAttemptResponse,
    EffectReconciliationReceipt, EffectResponse, EnableExtensionRequest, ExportResponse,
    ExtensionInvocationResponse, ExtensionLifecycleRequest, ExtensionResponse, ExtensionsResponse,
    GarbageCollectionResponse, HealthResponse, InputAdmissionResponse, InstallExtensionRequest,
    InvokeExtensionRequest, MemoriesResponse, MemoryIndexRebuildResponse, MemoryLifecycleRequest,
    MemoryResponse, MemorySearchResponse, MemorySensitivityCommand, PendingApprovalsResponse,
    PromoteMemoryRequest, ProposeMemoryRequest, ReadinessResponse, RebuildMemoryIndexRequest,
    ReconcileEffectRequest, ResolveApprovalRequest, RevokeDiscordChannelRequest,
    RevokeTelegramChannelRequest, RevokeWebhookChannelRequest, RunGarbageCollectionRequest,
    ScheduleLifecycleRequest, ScheduleResponse, ScheduleRunsResponse, SchedulesResponse,
    SessionSearchResponse, SessionStatusResponse, SessionsResponse, SetMemoryPinRequest,
    StageExtensionManifestRequest, SubmitInputRequest, TaskCancellationReceipt, TaskControlReceipt,
    TaskReplayResponse, TaskResponse, TelegramChannelResponse, TelegramChannelsResponse,
    TimelineCursor, TimelinePageResponse, VerifyBackupRequest, WebhookChannelResponse,
    WebhookChannelsResponse,
};
use serde::Deserialize;
use std::{
    convert::Infallible,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::sync::{Semaphore, TryAcquireError, watch};
use tower::ServiceBuilder;
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    trace::{DefaultOnResponse, TraceLayer},
};
use tracing::Level;

/// Security- and resource-relevant HTTP adapter configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiConfig {
    bind: SocketAddr,
    maximum_body_bytes: usize,
    allowed_origins: Vec<String>,
    maximum_concurrent_commands: usize,
    maximum_timeline_subscribers: usize,
    timeline_poll_interval: Duration,
}

impl ApiConfig {
    /// Creates a validated loopback-only API configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ApiConfigError`] for non-loopback binding or zero limits.
    pub fn new(
        bind: SocketAddr,
        maximum_body_bytes: usize,
        allowed_origins: Vec<String>,
        maximum_concurrent_commands: usize,
        maximum_timeline_subscribers: usize,
        timeline_poll_interval: Duration,
    ) -> Result<Self, ApiConfigError> {
        if !bind.ip().is_loopback() {
            return Err(ApiConfigError::NonLoopbackBind);
        }
        if maximum_body_bytes == 0
            || maximum_concurrent_commands == 0
            || maximum_timeline_subscribers == 0
            || timeline_poll_interval.is_zero()
        {
            return Err(ApiConfigError::ZeroLimit);
        }
        Ok(Self {
            bind,
            maximum_body_bytes,
            allowed_origins,
            maximum_concurrent_commands,
            maximum_timeline_subscribers,
            timeline_poll_interval,
        })
    }

    /// Returns the validated listener address.
    #[must_use]
    pub const fn bind(&self) -> SocketAddr {
        self.bind
    }

    /// Returns whether the listener remains local-only.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        self.bind.ip().is_loopback()
    }

    /// Returns the maximum accepted request-body size.
    #[must_use]
    pub const fn maximum_body_bytes(&self) -> usize {
        self.maximum_body_bytes
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            maximum_body_bytes: 1024 * 1024,
            allowed_origins: Vec::new(),
            maximum_concurrent_commands: 32,
            maximum_timeline_subscribers: 16,
            timeline_poll_interval: Duration::from_millis(200),
        }
    }
}

/// Invalid API configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ApiConfigError {
    /// Remote/public binding is outside the initial security boundary.
    #[error("API listener must bind to a loopback address")]
    NonLoopbackBind,
    /// Resource limits must be enforceable and nonzero.
    #[error("API resource limits must be nonzero")]
    ZeroLimit,
}

/// Identity resolved from one valid local bearer credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedIdentity {
    /// Opaque principal ID resolved by the trusted adapter.
    pub principal_id: String,
    /// Opaque local channel/device binding ID.
    pub channel_binding_id: String,
}

/// Exact untrusted HTTP evidence passed to the backend for signed-channel authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedWebhookEnvelope {
    /// Claimed Unix epoch timestamp in milliseconds.
    pub timestamp_ms: i64,
    /// Bounded one-use replay nonce.
    pub nonce: String,
    /// Lowercase HMAC-SHA256 signature over the exact raw body and framing fields.
    pub signature: String,
    /// Exact raw HTTP body bytes; JSON parsing occurs only after signature verification.
    pub body: Vec<u8>,
}

/// Verified artifact bytes and media type returned by a trusted daemon backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactContent {
    /// Declared media type validated into an HTTP header by this adapter.
    pub media_type: String,
    /// Size-bounded bytes already verified against the committed digest.
    pub bytes: Vec<u8>,
}

/// Fixed-length local bearer authentication material.
#[derive(Clone)]
pub struct ApiAuth {
    token: [u8; 32],
    identity: AuthenticatedIdentity,
}

impl ApiAuth {
    /// Creates authentication state from 32 random bytes and its resolved identity.
    #[must_use]
    pub const fn new(token: [u8; 32], identity: AuthenticatedIdentity) -> Self {
        Self { token, identity }
    }

    /// Returns the base64url credential written to the owner-only connection file.
    #[must_use]
    pub fn encoded_token(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.token)
    }
}

impl fmt::Debug for ApiAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiAuth")
            .field("token", &"[REDACTED]")
            .field("identity", &self.identity)
            .finish()
    }
}

/// Transport-neutral operations supplied by the daemon composition root.
pub trait ApiBackend: Send + Sync + 'static {
    /// Verifies that durable dependencies can serve normal commands.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Unavailable`] while the daemon is not ready.
    fn readiness(&self) -> Result<(), BackendError>;

    /// Returns whether this daemon intentionally rejects every mutation and dispatcher.
    fn safe_mode(&self) -> bool;

    /// Returns whether new command admission remains open before drain.
    fn admission_open(&self) -> bool;

    /// Reads authenticated operational queues, health, storage, and recent-failure gauges.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, persistence, or filesystem inspection fails.
    fn admin_status(
        &self,
        identity: AuthenticatedIdentity,
    ) -> Result<AdminStatusResponse, BackendError>;

    /// Reads stable machine-consumable operational gauges.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization or inspection fails.
    fn admin_metrics(
        &self,
        identity: AuthenticatedIdentity,
    ) -> Result<AdminMetricsResponse, BackendError>;

    /// Reads exact settled terminal-run usage grouped by UTC completion day.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the range, authorization, or canonical usage is invalid.
    fn admin_usage(
        &self,
        identity: AuthenticatedIdentity,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<AdminUsageReportResponse, BackendError>;

    /// Idempotently closes admission and begins bounded graceful drain.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization or lifecycle state rejects the request.
    fn drain_daemon(
        &self,
        identity: AuthenticatedIdentity,
        request: DrainDaemonRequest,
    ) -> Result<DrainDaemonResponse, BackendError>;

    /// Runs installation and platform diagnostics without mutating canonical state.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when owner authorization or a required diagnostic fails.
    fn doctor(&self, identity: AuthenticatedIdentity) -> Result<DoctorResponse, BackendError>;

    /// Creates an immutable complete online backup.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, validation, snapshotting, or publication fails.
    fn create_backup(
        &self,
        identity: AuthenticatedIdentity,
        request: CreateBackupRequest,
    ) -> Result<BackupResponse, BackendError>;

    /// Restores a backup into an isolated fresh home and verifies all integrity evidence.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization or any verification step fails closed.
    fn verify_backup(
        &self,
        identity: AuthenticatedIdentity,
        request: VerifyBackupRequest,
    ) -> Result<BackupVerificationResponse, BackendError>;

    /// Erases only configured-age artifact files absent from canonical references.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, storage inspection, or erasure fails.
    fn run_garbage_collection(
        &self,
        identity: AuthenticatedIdentity,
        request: RunGarbageCollectionRequest,
    ) -> Result<GarbageCollectionResponse, BackendError>;

    /// Publishes one immutable owner-scoped audit, task, artifact, or memory export bundle.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when scope authorization, evidence validation, or publication
    /// fails closed.
    fn create_export(
        &self,
        identity: AuthenticatedIdentity,
        request: CreateExportRequest,
    ) -> Result<ExportResponse, BackendError>;

    /// Creates a durable session for the authenticated identity.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, validation, or persistence fails.
    fn create_session(
        &self,
        identity: AuthenticatedIdentity,
    ) -> Result<CreateSessionResponse, BackendError>;

    /// Lists recent sessions for the exact authenticated binding.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when validation, authorization, or persistence fails.
    fn sessions(
        &self,
        identity: AuthenticatedIdentity,
        limit: usize,
    ) -> Result<SessionsResponse, BackendError>;

    /// Searches canonical user/final-assistant transcript text for the exact binding.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when bounds, authorization, or persistence reject the query.
    fn search_sessions(
        &self,
        _identity: AuthenticatedIdentity,
        _query: String,
        _limit: usize,
    ) -> Result<SessionSearchResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Durably admits an idempotent input.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, idempotency, validation, or persistence fails.
    fn submit_input(
        &self,
        identity: AuthenticatedIdentity,
        session_id: String,
        request: SubmitInputRequest,
    ) -> Result<InputAdmissionResponse, BackendError>;

    /// Reads authorized current session state.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization or persistence fails.
    fn session_status(
        &self,
        identity: AuthenticatedIdentity,
        session_id: String,
    ) -> Result<SessionStatusResponse, BackendError>;

    /// Creates one canonical recurring schedule targeting an authorized session.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when validation, authorization, or persistence fails.
    fn create_schedule(
        &self,
        _identity: AuthenticatedIdentity,
        _request: CreateScheduleRequest,
    ) -> Result<ScheduleResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Lists owner-authorized recurring schedules.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization or persistence fails.
    fn schedules(
        &self,
        _identity: AuthenticatedIdentity,
    ) -> Result<SchedulesResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Reads one owner-authorized recurring schedule.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the schedule is absent, unauthorized, or corrupt.
    fn schedule(
        &self,
        _identity: AuthenticatedIdentity,
        _schedule_id: String,
    ) -> Result<ScheduleResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Pauses one active schedule under an optimistic-concurrency fence.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, lifecycle, or persistence rejects the command.
    fn pause_schedule(
        &self,
        _identity: AuthenticatedIdentity,
        _schedule_id: String,
        _request: ScheduleLifecycleRequest,
    ) -> Result<ScheduleResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Resumes one paused schedule from a newly computed future cursor.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, lifecycle, or persistence rejects the command.
    fn resume_schedule(
        &self,
        _identity: AuthenticatedIdentity,
        _schedule_id: String,
        _request: ScheduleLifecycleRequest,
    ) -> Result<ScheduleResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Terminally cancels one schedule while retaining its history.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, lifecycle, or persistence rejects the command.
    fn cancel_schedule(
        &self,
        _identity: AuthenticatedIdentity,
        _schedule_id: String,
        _request: ScheduleLifecycleRequest,
    ) -> Result<ScheduleResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Reads bounded newest-first occurrence history.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, bounds, or persistence fails.
    fn schedule_runs(
        &self,
        _identity: AuthenticatedIdentity,
        _schedule_id: String,
        _limit: usize,
    ) -> Result<ScheduleRunsResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Reads an authorized bounded timeline page.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, cursor validation, or persistence fails.
    fn timeline_page(
        &self,
        identity: AuthenticatedIdentity,
        session_id: String,
        after: Option<TimelineCursor>,
        limit: usize,
    ) -> Result<TimelinePageResponse, BackendError>;

    /// Reads authorized path-free artifact metadata.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, evidence validation, or persistence fails.
    fn artifact_metadata(
        &self,
        identity: AuthenticatedIdentity,
        artifact_id: String,
    ) -> Result<ArtifactMetadataResponse, BackendError>;

    /// Reads and verifies authorized artifact content.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, content integrity, or storage access fails.
    fn artifact_content(
        &self,
        identity: AuthenticatedIdentity,
        artifact_id: String,
    ) -> Result<ArtifactContent, BackendError>;

    /// Reads an owner-authorized, path-safe context-manifest projection.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, evidence validation, or persistence fails.
    fn context_manifest(
        &self,
        identity: AuthenticatedIdentity,
        manifest_id: String,
    ) -> Result<ContextManifestEvidenceResponse, BackendError>;

    /// Proposes a governed memory revision in an exact workspace namespace.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authentication, validation, policy, or persistence fails.
    fn propose_memory(
        &self,
        identity: AuthenticatedIdentity,
        request: ProposeMemoryRequest,
    ) -> Result<MemoryResponse, BackendError>;

    /// Promotes an exact proposed memory revision under owner policy or approval.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authentication, authorization, lifecycle, or persistence
    /// fails.
    fn promote_memory(
        &self,
        identity: AuthenticatedIdentity,
        memory_id: String,
        request: PromoteMemoryRequest,
    ) -> Result<MemoryResponse, BackendError>;

    /// Reads one complete owner-authorized memory history.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, evidence validation, or persistence fails.
    fn memory(
        &self,
        identity: AuthenticatedIdentity,
        workspace_identity: String,
        memory_id: String,
    ) -> Result<MemoryResponse, BackendError>;

    /// Lists memories for owner inspection and export.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, evidence validation, or persistence fails.
    fn memories(
        &self,
        identity: AuthenticatedIdentity,
        workspace_identity: String,
        include_deleted: bool,
    ) -> Result<MemoriesResponse, BackendError>;

    /// Searches active memories after deterministic namespace and sensitivity filters.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, query validation, indexing, or persistence
    /// fails.
    fn search_memories(
        &self,
        identity: AuthenticatedIdentity,
        workspace_identity: String,
        query: String,
        maximum_sensitivity: MemorySensitivityCommand,
        limit: usize,
    ) -> Result<MemorySearchResponse, BackendError>;

    /// Corrects a memory by superseding, not rewriting, its active revision.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, concurrency, validation, or persistence fails.
    fn correct_memory(
        &self,
        identity: AuthenticatedIdentity,
        memory_id: String,
        request: CorrectMemoryRequest,
    ) -> Result<MemoryResponse, BackendError>;

    /// Pins or unpins active memory retention.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, concurrency, lifecycle, or persistence fails.
    fn set_memory_pin(
        &self,
        identity: AuthenticatedIdentity,
        memory_id: String,
        request: SetMemoryPinRequest,
    ) -> Result<MemoryResponse, BackendError>;

    /// Expires an active memory without scrubbing its audit content.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, concurrency, lifecycle, or persistence fails.
    fn expire_memory(
        &self,
        identity: AuthenticatedIdentity,
        memory_id: String,
        request: MemoryLifecycleRequest,
    ) -> Result<MemoryResponse, BackendError>;

    /// Rejects a proposed memory without discarding its immutable audit evidence.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, concurrency, lifecycle, or persistence fails.
    fn reject_memory(
        &self,
        identity: AuthenticatedIdentity,
        memory_id: String,
        request: MemoryLifecycleRequest,
    ) -> Result<MemoryResponse, BackendError>;

    /// Scrubs memory content and derived-index entries while retaining tombstones.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, concurrency, lifecycle, or persistence fails.
    fn delete_memory(
        &self,
        identity: AuthenticatedIdentity,
        memory_id: String,
        request: MemoryLifecycleRequest,
    ) -> Result<MemoryResponse, BackendError>;

    /// Rebuilds the authenticated owner's derived lexical index rows.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, canonical evidence, or persistence fails.
    fn rebuild_memory_index(
        &self,
        identity: AuthenticatedIdentity,
        request: RebuildMemoryIndexRequest,
    ) -> Result<MemoryIndexRebuildResponse, BackendError>;

    /// Commits a cited derived compaction artifact for an authorized session range.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, source/citation validation, or persistence
    /// fails.
    fn create_compaction(
        &self,
        identity: AuthenticatedIdentity,
        session_id: String,
        request: CreateCompactionRequest,
    ) -> Result<CompactionResponse, BackendError>;

    /// Inspects one immutable compaction and its typed carry-forward record.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, evidence validation, or persistence fails.
    fn compaction(
        &self,
        identity: AuthenticatedIdentity,
        compaction_id: String,
    ) -> Result<CompactionResponse, BackendError>;

    /// Installs one new inert digest-pinned extension package.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, manifest/package validation, or persistence
    /// fails.
    fn install_extension(
        &self,
        identity: AuthenticatedIdentity,
        request: InstallExtensionRequest,
    ) -> Result<ExtensionResponse, BackendError>;

    /// Lists all owner-authorized extensions.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, evidence validation, or persistence fails.
    fn extensions(
        &self,
        identity: AuthenticatedIdentity,
    ) -> Result<ExtensionsResponse, BackendError>;

    /// Reads one complete extension manifest/grant history.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, evidence validation, or persistence fails.
    fn extension(
        &self,
        identity: AuthenticatedIdentity,
        extension_id: String,
    ) -> Result<ExtensionResponse, BackendError>;

    /// Stages an extension upgrade or rollback and clears old authority.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, concurrency, compatibility, package
    /// validation, or persistence fails.
    fn stage_extension_manifest(
        &self,
        identity: AuthenticatedIdentity,
        extension_id: String,
        request: StageExtensionManifestRequest,
    ) -> Result<ExtensionResponse, BackendError>;

    /// Probes health and enables an exact manifest using a fresh explicit grant.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, grant/schema validation, process containment,
    /// health, concurrency, or persistence fails.
    fn enable_extension(
        &self,
        identity: AuthenticatedIdentity,
        extension_id: String,
        request: EnableExtensionRequest,
    ) -> Result<ExtensionResponse, BackendError>;

    /// Temporarily removes extension runtime authority.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, lifecycle, concurrency, or persistence fails.
    fn disable_extension(
        &self,
        identity: AuthenticatedIdentity,
        extension_id: String,
        request: ExtensionLifecycleRequest,
    ) -> Result<ExtensionResponse, BackendError>;

    /// Terminally revokes an extension and active grant.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, lifecycle, concurrency, or persistence fails.
    fn revoke_extension(
        &self,
        identity: AuthenticatedIdentity,
        extension_id: String,
        request: ExtensionLifecycleRequest,
    ) -> Result<ExtensionResponse, BackendError>;

    /// Invokes one granted read-only capability through the supervised host.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, schema/grant validation, durable dispatch, or
    /// terminal persistence fails.
    fn invoke_extension(
        &self,
        identity: AuthenticatedIdentity,
        extension_id: String,
        request: InvokeExtensionRequest,
    ) -> Result<ExtensionInvocationResponse, BackendError>;

    /// Creates one signed external-subject binding and dedicated session.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, callback validation, secret brokering, or
    /// persistence fails.
    fn create_webhook_channel(
        &self,
        identity: AuthenticatedIdentity,
        request: CreateWebhookChannelRequest,
    ) -> Result<CreateWebhookChannelResponse, BackendError>;

    /// Lists signed webhook channels owned by the authenticated principal.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization or persistence fails.
    fn webhook_channels(
        &self,
        identity: AuthenticatedIdentity,
    ) -> Result<WebhookChannelsResponse, BackendError>;

    /// Inspects one owner-authorized signed webhook channel.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, identity, or persistence fails.
    fn webhook_channel(
        &self,
        identity: AuthenticatedIdentity,
        binding_id: String,
    ) -> Result<WebhookChannelResponse, BackendError>;

    /// Terminally revokes a signed webhook channel and its brokered key.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, revision, secret removal, or persistence
    /// fails.
    fn revoke_webhook_channel(
        &self,
        identity: AuthenticatedIdentity,
        binding_id: String,
        request: RevokeWebhookChannelRequest,
    ) -> Result<WebhookChannelResponse, BackendError>;

    /// Creates one Telegram bot/user/chat binding after live token verification.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] for invalid identity, credential, connectivity, or persistence.
    fn create_telegram_channel(
        &self,
        _identity: AuthenticatedIdentity,
        _request: CreateTelegramChannelRequest,
    ) -> Result<TelegramChannelResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Lists Telegram channels owned by the authenticated principal.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization or persistence fails.
    fn telegram_channels(
        &self,
        _identity: AuthenticatedIdentity,
    ) -> Result<TelegramChannelsResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Inspects one owner-authorized Telegram binding.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when absent, unauthorized, or corrupt.
    fn telegram_channel(
        &self,
        _identity: AuthenticatedIdentity,
        _binding_id: String,
    ) -> Result<TelegramChannelResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Terminally revokes one Telegram binding and brokered bot token.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] for authorization, revision, credential, or persistence failure.
    fn revoke_telegram_channel(
        &self,
        _identity: AuthenticatedIdentity,
        _binding_id: String,
        _request: RevokeTelegramChannelRequest,
    ) -> Result<TelegramChannelResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Creates one exact Discord bot/human/DM binding after live verification.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] for invalid identity, credential, connectivity, or persistence.
    fn create_discord_channel(
        &self,
        _identity: AuthenticatedIdentity,
        _request: CreateDiscordChannelRequest,
    ) -> Result<DiscordChannelResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Lists Discord DM channels owned by the authenticated principal.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization or persistence fails.
    fn discord_channels(
        &self,
        _identity: AuthenticatedIdentity,
    ) -> Result<DiscordChannelsResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Inspects one owner-authorized Discord DM binding.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when absent, unauthorized, or corrupt.
    fn discord_channel(
        &self,
        _identity: AuthenticatedIdentity,
        _binding_id: String,
    ) -> Result<DiscordChannelResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Terminally revokes one Discord binding and brokered bot token.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] for authorization, revision, credential, or persistence failure.
    fn revoke_discord_channel(
        &self,
        _identity: AuthenticatedIdentity,
        _binding_id: String,
        _request: RevokeDiscordChannelRequest,
    ) -> Result<DiscordChannelResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Verifies and durably admits one external delivery without local bearer authentication.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] for invalid signatures, stale timestamps, replay, revoked
    /// bindings, malformed bodies, or persistence failure.
    fn receive_signed_webhook(
        &self,
        binding_id: String,
        envelope: SignedWebhookEnvelope,
    ) -> Result<InputAdmissionResponse, BackendError>;

    /// Reads an authorized current task projection.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization or persistence fails.
    fn task(
        &self,
        identity: AuthenticatedIdentity,
        task_id: String,
    ) -> Result<TaskResponse, BackendError>;

    /// Reads one authorized durable delegation projection.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, identity parsing, or persistence fails.
    fn delegation(
        &self,
        _identity: AuthenticatedIdentity,
        _delegation_id: String,
    ) -> Result<DelegationResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Lists bounded newest-first delegations for the authenticated owner binding.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when bounds, authorization, or persistence fails.
    fn delegations(
        &self,
        _identity: AuthenticatedIdentity,
        _limit: usize,
    ) -> Result<DelegationsResponse, BackendError> {
        Err(BackendError::Unavailable)
    }

    /// Durably requests idempotent cooperative cancellation of one authorized task.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, idempotency, validation, or persistence fails.
    fn cancel_task(
        &self,
        identity: AuthenticatedIdentity,
        task_id: String,
        request: CancelTaskRequest,
    ) -> Result<TaskCancellationReceipt, BackendError>;

    /// Pauses one authorized task, fencing active work before acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] for authorization, stale revision, terminal state, or recovery
    /// failure.
    fn pause_task(
        &self,
        identity: AuthenticatedIdentity,
        task_id: String,
        request: ControlTaskRequest,
    ) -> Result<TaskControlReceipt, BackendError>;

    /// Resumes one authorized paused task according to its durable run boundary.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] for authorization, stale revision, or inconsistent state.
    fn resume_task(
        &self,
        identity: AuthenticatedIdentity,
        task_id: String,
        request: ControlTaskRequest,
    ) -> Result<TaskControlReceipt, BackendError>;

    /// Reconstructs an authorized task solely from recorded evidence.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, evidence validation, or persistence fails.
    fn task_replay(
        &self,
        identity: AuthenticatedIdentity,
        task_id: String,
    ) -> Result<TaskReplayResponse, BackendError>;

    /// Lists pending approval subjects visible to the authenticated owner/channel.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, evidence validation, or persistence fails.
    fn pending_approvals(
        &self,
        identity: AuthenticatedIdentity,
    ) -> Result<PendingApprovalsResponse, BackendError>;

    /// Resolves one exact approval subject through an authenticated, idempotent command.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, subject binding, idempotency, expiry, or
    /// persistence validation fails.
    fn resolve_approval(
        &self,
        identity: AuthenticatedIdentity,
        approval_id: String,
        request: ResolveApprovalRequest,
    ) -> Result<ApprovalResolutionReceipt, BackendError>;

    /// Reads one owner-authorized effect and its exact policy/approval evidence.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, evidence validation, or persistence fails.
    fn effect(
        &self,
        identity: AuthenticatedIdentity,
        effect_id: String,
    ) -> Result<EffectResponse, BackendError>;

    /// Reads one owner-authorized effect attempt and immutable outcome evidence.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, evidence validation, or persistence fails.
    fn effect_attempt(
        &self,
        identity: AuthenticatedIdentity,
        attempt_id: String,
    ) -> Result<EffectAttemptResponse, BackendError>;

    /// Reconciles one exact unknown effect attempt using authenticated external evidence.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when authorization, revision, idempotency, evidence, or
    /// persistence validation fails.
    fn reconcile_effect(
        &self,
        identity: AuthenticatedIdentity,
        effect_id: String,
        attempt_id: String,
        request: ReconcileEffectRequest,
    ) -> Result<EffectReconciliationReceipt, BackendError>;
}

/// Failure reported by the daemon backend to the transport adapter.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BackendError {
    /// Authentication/authorization failed.
    #[error("request is unauthorized")]
    Unauthorized,
    /// Authorized resource was not found.
    #[error("resource was not found")]
    NotFound,
    /// Idempotency or optimistic-concurrency conflict.
    #[error("request conflicts with canonical state")]
    Conflict,
    /// Requested timeline history has already been retained away.
    #[error("timeline cursor gap; earliest available cursor is {earliest_cursor}")]
    TimelineGap {
        /// First cursor that can be resumed without a gap.
        earliest_cursor: u64,
    },
    /// Requested timeline cursor is beyond the authorized high watermark.
    #[error("timeline cursor is ahead of the durable high watermark")]
    TimelineCursorAhead,
    /// Request failed semantic validation.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// Bounded adapter capacity is exhausted.
    #[error("server is busy")]
    Busy,
    /// Request body exceeded the configured transport boundary.
    #[error("request body is too large")]
    PayloadTooLarge,
    /// Durable dependency is unavailable.
    #[error("service is temporarily unavailable")]
    Unavailable,
    /// Internal invariant failed closed.
    #[error("internal server error")]
    Internal,
}

#[derive(Clone)]
struct AppState(Arc<StateInner>);

struct StateInner {
    backend: Arc<dyn ApiBackend>,
    auth: ApiAuth,
    allowed_origins: Vec<String>,
    commands: Arc<Semaphore>,
    subscribers: Arc<Semaphore>,
    poll_interval: Duration,
    shutdown: Option<watch::Receiver<bool>>,
}

/// Builds the bounded HTTP router. Binding the validated listener remains the daemon's job.
pub fn router(config: &ApiConfig, auth: ApiAuth, backend: Arc<dyn ApiBackend>) -> Router {
    build_router(config, auth, backend, None)
}

/// Builds the bounded HTTP router with a daemon lifecycle signal for terminating long-lived SSE.
pub fn router_with_shutdown(
    config: &ApiConfig,
    auth: ApiAuth,
    backend: Arc<dyn ApiBackend>,
    shutdown: watch::Receiver<bool>,
) -> Router {
    build_router(config, auth, backend, Some(shutdown))
}

#[allow(clippy::too_many_lines)]
fn build_router(
    config: &ApiConfig,
    auth: ApiAuth,
    backend: Arc<dyn ApiBackend>,
    shutdown: Option<watch::Receiver<bool>>,
) -> Router {
    let state = AppState(Arc::new(StateInner {
        backend,
        auth,
        allowed_origins: config.allowed_origins.clone(),
        commands: Arc::new(Semaphore::new(config.maximum_concurrent_commands)),
        subscribers: Arc::new(Semaphore::new(config.maximum_timeline_subscribers)),
        poll_interval: config.timeline_poll_interval,
        shutdown,
    }));
    let protected = Router::new()
        .route("/health/live", get(liveness_handler))
        .route("/health/ready", get(readiness_handler))
        .route(
            "/v1/sessions",
            get(sessions_handler).post(create_session_handler),
        )
        .route("/v1/sessions/search", get(session_search_handler))
        .route(
            "/v1/sessions/{session_id}/inputs",
            post(submit_input_handler),
        )
        .route(
            "/v1/sessions/{session_id}/status",
            get(session_status_handler),
        )
        .route("/v1/sessions/{session_id}/timeline", get(timeline_handler))
        .route("/v1/sessions/{session_id}/events", get(events_handler))
        .route(
            "/v1/schedules",
            get(schedules_handler).post(create_schedule_handler),
        )
        .route("/v1/schedules/{schedule_id}", get(schedule_handler))
        .route(
            "/v1/schedules/{schedule_id}/pause",
            post(pause_schedule_handler),
        )
        .route(
            "/v1/schedules/{schedule_id}/resume",
            post(resume_schedule_handler),
        )
        .route(
            "/v1/schedules/{schedule_id}/cancel",
            post(cancel_schedule_handler),
        )
        .route(
            "/v1/schedules/{schedule_id}/runs",
            get(schedule_runs_handler),
        )
        .route(
            "/v1/artifacts/{artifact_id}",
            get(artifact_metadata_handler),
        )
        .route(
            "/v1/artifacts/{artifact_id}/content",
            get(artifact_content_handler),
        )
        .route(
            "/v1/context-manifests/{manifest_id}",
            get(context_manifest_handler),
        )
        .route(
            "/v1/memories",
            get(memories_handler).post(propose_memory_handler),
        )
        .route("/v1/memories/search", get(search_memories_handler))
        .route("/v1/memories/{memory_id}", get(memory_handler))
        .route(
            "/v1/memories/{memory_id}/activate",
            post(promote_memory_handler),
        )
        .route(
            "/v1/memories/{memory_id}/correct",
            post(correct_memory_handler),
        )
        .route("/v1/memories/{memory_id}/pin", post(set_memory_pin_handler))
        .route(
            "/v1/memories/{memory_id}/expire",
            post(expire_memory_handler),
        )
        .route(
            "/v1/memories/{memory_id}/reject",
            post(reject_memory_handler),
        )
        .route(
            "/v1/memories/{memory_id}/delete",
            post(delete_memory_handler),
        )
        .route(
            "/v1/memory-index/rebuild",
            post(rebuild_memory_index_handler),
        )
        .route(
            "/v1/sessions/{session_id}/compactions",
            post(create_compaction_handler),
        )
        .route("/v1/compactions/{compaction_id}", get(compaction_handler))
        .route(
            "/v1/extensions",
            get(extensions_handler).post(install_extension_handler),
        )
        .route("/v1/extensions/{extension_id}", get(extension_handler))
        .route(
            "/v1/extensions/{extension_id}/stage",
            post(stage_extension_manifest_handler),
        )
        .route(
            "/v1/extensions/{extension_id}/enable",
            post(enable_extension_handler),
        )
        .route(
            "/v1/extensions/{extension_id}/disable",
            post(disable_extension_handler),
        )
        .route(
            "/v1/extensions/{extension_id}/revoke",
            post(revoke_extension_handler),
        )
        .route(
            "/v1/extensions/{extension_id}/invoke",
            post(invoke_extension_handler),
        )
        .route(
            "/v1/channels/webhooks",
            get(webhook_channels_handler).post(create_webhook_channel_handler),
        )
        .route(
            "/v1/channels/webhooks/{binding_id}",
            get(webhook_channel_handler),
        )
        .route(
            "/v1/channels/webhooks/{binding_id}/revoke",
            post(revoke_webhook_channel_handler),
        )
        .route(
            "/v1/channels/telegram",
            get(telegram_channels_handler).post(create_telegram_channel_handler),
        )
        .route(
            "/v1/channels/telegram/{binding_id}",
            get(telegram_channel_handler),
        )
        .route(
            "/v1/channels/telegram/{binding_id}/revoke",
            post(revoke_telegram_channel_handler),
        )
        .route(
            "/v1/channels/discord",
            get(discord_channels_handler).post(create_discord_channel_handler),
        )
        .route(
            "/v1/channels/discord/{binding_id}",
            get(discord_channel_handler),
        )
        .route(
            "/v1/channels/discord/{binding_id}/revoke",
            post(revoke_discord_channel_handler),
        )
        .route("/v1/admin/status", get(admin_status_handler))
        .route("/v1/admin/metrics", get(admin_metrics_handler))
        .route("/v1/admin/usage", get(admin_usage_handler))
        .route("/v1/admin/doctor", get(doctor_handler))
        .route("/v1/admin/drain", post(drain_daemon_handler))
        .route("/v1/admin/backups", post(create_backup_handler))
        .route(
            "/v1/admin/backup-verifications",
            post(verify_backup_handler),
        )
        .route(
            "/v1/admin/artifact-gc",
            post(run_garbage_collection_handler),
        )
        .route("/v1/admin/exports", post(create_export_handler))
        .route("/v1/delegations", get(delegations_handler))
        .route("/v1/delegations/{delegation_id}", get(delegation_handler))
        .route("/v1/tasks/{task_id}", get(task_handler))
        .route("/v1/tasks/{task_id}/cancel", post(cancel_task_handler))
        .route("/v1/tasks/{task_id}/pause", post(pause_task_handler))
        .route("/v1/tasks/{task_id}/resume", post(resume_task_handler))
        .route("/v1/tasks/{task_id}/replay", get(task_replay_handler))
        .route("/v1/approvals", get(pending_approvals_handler))
        .route(
            "/v1/approvals/{approval_id}/resolve",
            post(resolve_approval_handler),
        )
        .route("/v1/effects/{effect_id}", get(effect_handler))
        .route(
            "/v1/effects/{effect_id}/attempts/{attempt_id}/reconcile",
            post(reconcile_effect_handler),
        )
        .route(
            "/v1/effect-attempts/{attempt_id}",
            get(effect_attempt_handler),
        )
        .fallback(not_found_handler)
        .method_not_allowed_fallback(method_not_allowed_handler)
        .layer(from_fn_with_state(state.clone(), authenticate));
    let signed_ingress = Router::new().route(
        "/v1/channels/webhooks/{binding_id}/deliveries",
        post(receive_signed_webhook_handler),
    );
    Router::new()
        .merge(signed_ingress)
        .merge(protected)
        .layer(SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
            HeaderName::from_static("x-mealy-signature"),
        ]))
        .layer(DefaultBodyLimit::max(config.maximum_body_bytes))
        .layer(
            ServiceBuilder::new()
                .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(|request: &axum::http::Request<Body>| {
                            let request_id = request
                                .headers()
                                .get("x-request-id")
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or("invalid");
                            tracing::info_span!(
                                "http_request",
                                request_id,
                                method = %request.method(),
                                uri = %request.uri(),
                            )
                        })
                        .on_response(DefaultOnResponse::new().level(Level::INFO)),
                )
                .layer(PropagateRequestIdLayer::x_request_id()),
        )
        .with_state(state)
}

async fn authenticate(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    if !origin_allowed(request.headers(), &state.0.allowed_origins) {
        return api_error(
            StatusCode::FORBIDDEN,
            "origin_forbidden",
            "request origin is not allowed",
            false,
        );
    }
    if !valid_bearer(request.headers(), &state.0.auth.token) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credential",
            "a valid local bearer credential is required",
            false,
        );
    }
    let safe_maintenance = matches!(
        request.uri().path(),
        "/v1/admin/drain"
            | "/v1/admin/backups"
            | "/v1/admin/backup-verifications"
            | "/v1/admin/exports"
    );
    if request.method() != axum::http::Method::GET
        && !safe_maintenance
        && (state.0.backend.safe_mode() || !state.0.backend.admission_open())
    {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "admission_closed",
            "daemon command admission is closed for safe mode or graceful drain",
            true,
        );
    }
    request
        .extensions_mut()
        .insert(state.0.auth.identity.clone());
    next.run(request).await
}

fn origin_allowed(headers: &HeaderMap, allowed: &[String]) -> bool {
    let values = headers.get_all(header::ORIGIN).iter().collect::<Vec<_>>();
    match values.as_slice() {
        [] => true,
        [value] => value
            .to_str()
            .ok()
            .is_some_and(|origin| allowed.iter().any(|candidate| candidate == origin)),
        _ => false,
    }
}

fn valid_bearer(headers: &HeaderMap, expected: &[u8; 32]) -> bool {
    let values = headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .collect::<Vec<_>>();
    let [value] = values.as_slice() else {
        return false;
    };
    let Some(encoded) = value
        .to_str()
        .ok()
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    let Ok(decoded) = URL_SAFE_NO_PAD.decode(encoded) else {
        return false;
    };
    let Ok(decoded) = <[u8; 32]>::try_from(decoded) else {
        return false;
    };
    bool::from(decoded.ct_eq(expected))
}

async fn liveness_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        api_version: API_VERSION.to_owned(),
        live: true,
    })
}

async fn readiness_handler(
    State(state): State<AppState>,
) -> Result<Json<ReadinessResponse>, HttpError> {
    let safe_mode = state.0.backend.safe_mode();
    run_backend(state, |backend| backend.readiness()).await?;
    Ok(Json(ReadinessResponse {
        api_version: API_VERSION.to_owned(),
        ready: true,
        state: if safe_mode { "safe_mode" } else { "ready" }.to_owned(),
    }))
}

async fn admin_status_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
) -> Result<Json<AdminStatusResponse>, HttpError> {
    let result = run_backend(state, move |backend| backend.admin_status(identity)).await?;
    Ok(Json(result))
}

async fn admin_metrics_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
) -> Result<Json<AdminMetricsResponse>, HttpError> {
    let result = run_backend(state, move |backend| backend.admin_metrics(identity)).await?;
    Ok(Json(result))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdminUsageParameters {
    from_ms: i64,
    to_ms: i64,
}

async fn admin_usage_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    parameters: Result<Query<AdminUsageParameters>, QueryRejection>,
) -> Result<Json<AdminUsageReportResponse>, HttpError> {
    let Query(parameters) = parameters.map_err(|rejection| map_query_rejection(&rejection))?;
    let result = run_backend(state, move |backend| {
        backend.admin_usage(identity, parameters.from_ms, parameters.to_ms)
    })
    .await?;
    Ok(Json(result))
}

async fn drain_daemon_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request: Result<Json<DrainDaemonRequest>, JsonRejection>,
) -> Result<Json<DrainDaemonResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.drain_daemon(identity, request)
    })
    .await?;
    Ok(Json(result))
}

async fn doctor_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
) -> Result<Json<DoctorResponse>, HttpError> {
    let result = run_backend(state, move |backend| backend.doctor(identity)).await?;
    Ok(Json(result))
}

async fn create_backup_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request: Result<Json<CreateBackupRequest>, JsonRejection>,
) -> Result<Json<BackupResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.create_backup(identity, request)
    })
    .await?;
    Ok(Json(result))
}

async fn verify_backup_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request: Result<Json<VerifyBackupRequest>, JsonRejection>,
) -> Result<Json<BackupVerificationResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.verify_backup(identity, request)
    })
    .await?;
    Ok(Json(result))
}

async fn run_garbage_collection_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request: Result<Json<RunGarbageCollectionRequest>, JsonRejection>,
) -> Result<Json<GarbageCollectionResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.run_garbage_collection(identity, request)
    })
    .await?;
    Ok(Json(result))
}

async fn create_export_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request: Result<Json<CreateExportRequest>, JsonRejection>,
) -> Result<Json<ExportResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.create_export(identity, request)
    })
    .await?;
    Ok(Json(result))
}

async fn create_session_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request: Result<Json<CreateSessionRequest>, JsonRejection>,
) -> Result<Json<CreateSessionResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| backend.create_session(identity)).await?;
    Ok(Json(result))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SessionListParameters {
    limit: Option<usize>,
}

async fn sessions_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    parameters: Result<Query<SessionListParameters>, QueryRejection>,
) -> Result<Json<SessionsResponse>, HttpError> {
    let Query(parameters) = parameters.map_err(|rejection| map_query_rejection(&rejection))?;
    let limit = parameters.limit.unwrap_or(20);
    if !(1..=100).contains(&limit) {
        return Err(HttpError(BackendError::InvalidRequest(
            "session list limit must be between 1 and 100".to_owned(),
        )));
    }
    let result = run_backend(state, move |backend| backend.sessions(identity, limit)).await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SessionSearchParameters {
    query: String,
    limit: Option<usize>,
}

async fn session_search_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    parameters: Result<Query<SessionSearchParameters>, QueryRejection>,
) -> Result<Json<SessionSearchResponse>, HttpError> {
    let Query(parameters) = parameters.map_err(|rejection| map_query_rejection(&rejection))?;
    let limit = parameters.limit.unwrap_or(20);
    if parameters.query.is_empty()
        || parameters.query.len() > 4_096
        || parameters.query.trim() != parameters.query
        || parameters.query.chars().any(char::is_control)
        || !(1..=100).contains(&limit)
    {
        return Err(HttpError(BackendError::InvalidRequest(
            "session transcript search query or limit is invalid".to_owned(),
        )));
    }
    let query = parameters.query;
    let result = run_backend(state, move |backend| {
        backend.search_sessions(identity, query, limit)
    })
    .await?;
    Ok(Json(result))
}

async fn submit_input_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(session_id): Path<String>,
    request: Result<Json<SubmitInputRequest>, JsonRejection>,
) -> Result<Json<InputAdmissionResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.submit_input(identity, session_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn session_status_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(session_id): Path<String>,
) -> Result<Json<SessionStatusResponse>, HttpError> {
    let result = run_backend(state, move |backend| {
        backend.session_status(identity, session_id)
    })
    .await?;
    Ok(Json(result))
}

async fn create_schedule_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request: Result<Json<CreateScheduleRequest>, JsonRejection>,
) -> Result<Json<ScheduleResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.create_schedule(identity, request)
    })
    .await?;
    Ok(Json(result))
}

async fn schedules_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
) -> Result<Json<SchedulesResponse>, HttpError> {
    let result = run_backend(state, move |backend| backend.schedules(identity)).await?;
    Ok(Json(result))
}

async fn schedule_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(schedule_id): Path<String>,
) -> Result<Json<ScheduleResponse>, HttpError> {
    let result = run_backend(state, move |backend| {
        backend.schedule(identity, schedule_id)
    })
    .await?;
    Ok(Json(result))
}

async fn pause_schedule_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(schedule_id): Path<String>,
    request: Result<Json<ScheduleLifecycleRequest>, JsonRejection>,
) -> Result<Json<ScheduleResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.pause_schedule(identity, schedule_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn resume_schedule_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(schedule_id): Path<String>,
    request: Result<Json<ScheduleLifecycleRequest>, JsonRejection>,
) -> Result<Json<ScheduleResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.resume_schedule(identity, schedule_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn cancel_schedule_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(schedule_id): Path<String>,
    request: Result<Json<ScheduleLifecycleRequest>, JsonRejection>,
) -> Result<Json<ScheduleResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.cancel_schedule(identity, schedule_id, request)
    })
    .await?;
    Ok(Json(result))
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
struct ScheduleRunParameters {
    limit: Option<usize>,
}

async fn schedule_runs_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(schedule_id): Path<String>,
    parameters: Result<Query<ScheduleRunParameters>, QueryRejection>,
) -> Result<Json<ScheduleRunsResponse>, HttpError> {
    let Query(parameters) = parameters.map_err(|rejection| map_query_rejection(&rejection))?;
    let limit = parameters.limit.unwrap_or(100);
    let result = run_backend(state, move |backend| {
        backend.schedule_runs(identity, schedule_id, limit)
    })
    .await?;
    Ok(Json(result))
}

async fn artifact_metadata_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(artifact_id): Path<String>,
) -> Result<Json<ArtifactMetadataResponse>, HttpError> {
    let result = run_backend(state, move |backend| {
        backend.artifact_metadata(identity, artifact_id)
    })
    .await?;
    Ok(Json(result))
}

async fn artifact_content_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(artifact_id): Path<String>,
) -> Result<Response, HttpError> {
    let content = run_backend(state, move |backend| {
        backend.artifact_content(identity, artifact_id)
    })
    .await?;
    let content_type = HeaderValue::try_from(content.media_type.as_str())
        .map_err(|_| HttpError(BackendError::Internal))?;
    let mut response = Response::new(Body::from(content.bytes));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"mealy-artifact\""),
    );
    Ok(response)
}

async fn context_manifest_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(manifest_id): Path<String>,
) -> Result<Json<ContextManifestEvidenceResponse>, HttpError> {
    let result = run_backend(state, move |backend| {
        backend.context_manifest(identity, manifest_id)
    })
    .await?;
    Ok(Json(result))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemoryNamespaceParameters {
    workspace_identity: String,
    #[serde(default)]
    include_deleted: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemorySearchParameters {
    workspace_identity: String,
    query: String,
    #[serde(default = "default_memory_sensitivity")]
    maximum_sensitivity: MemorySensitivityCommand,
    #[serde(default = "default_memory_limit")]
    limit: usize,
}

const fn default_memory_sensitivity() -> MemorySensitivityCommand {
    MemorySensitivityCommand::Private
}

const fn default_memory_limit() -> usize {
    20
}

async fn propose_memory_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request: Result<Json<ProposeMemoryRequest>, JsonRejection>,
) -> Result<Json<MemoryResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.propose_memory(identity, request)
    })
    .await?;
    Ok(Json(result))
}

async fn promote_memory_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(memory_id): Path<String>,
    request: Result<Json<PromoteMemoryRequest>, JsonRejection>,
) -> Result<Json<MemoryResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.promote_memory(identity, memory_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn memory_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(memory_id): Path<String>,
    parameters: Result<Query<MemoryNamespaceParameters>, QueryRejection>,
) -> Result<Json<MemoryResponse>, HttpError> {
    let Query(parameters) = parameters.map_err(|rejection| map_query_rejection(&rejection))?;
    let result = run_backend(state, move |backend| {
        backend.memory(identity, parameters.workspace_identity, memory_id)
    })
    .await?;
    Ok(Json(result))
}

async fn memories_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    parameters: Result<Query<MemoryNamespaceParameters>, QueryRejection>,
) -> Result<Json<MemoriesResponse>, HttpError> {
    let Query(parameters) = parameters.map_err(|rejection| map_query_rejection(&rejection))?;
    let result = run_backend(state, move |backend| {
        backend.memories(
            identity,
            parameters.workspace_identity,
            parameters.include_deleted,
        )
    })
    .await?;
    Ok(Json(result))
}

async fn search_memories_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    parameters: Result<Query<MemorySearchParameters>, QueryRejection>,
) -> Result<Json<MemorySearchResponse>, HttpError> {
    let Query(parameters) = parameters.map_err(|rejection| map_query_rejection(&rejection))?;
    let result = run_backend(state, move |backend| {
        backend.search_memories(
            identity,
            parameters.workspace_identity,
            parameters.query,
            parameters.maximum_sensitivity,
            parameters.limit,
        )
    })
    .await?;
    Ok(Json(result))
}

async fn correct_memory_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(memory_id): Path<String>,
    request: Result<Json<CorrectMemoryRequest>, JsonRejection>,
) -> Result<Json<MemoryResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.correct_memory(identity, memory_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn set_memory_pin_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(memory_id): Path<String>,
    request: Result<Json<SetMemoryPinRequest>, JsonRejection>,
) -> Result<Json<MemoryResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.set_memory_pin(identity, memory_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn expire_memory_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(memory_id): Path<String>,
    request: Result<Json<MemoryLifecycleRequest>, JsonRejection>,
) -> Result<Json<MemoryResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.expire_memory(identity, memory_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn reject_memory_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(memory_id): Path<String>,
    request: Result<Json<MemoryLifecycleRequest>, JsonRejection>,
) -> Result<Json<MemoryResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.reject_memory(identity, memory_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn delete_memory_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(memory_id): Path<String>,
    request: Result<Json<MemoryLifecycleRequest>, JsonRejection>,
) -> Result<Json<MemoryResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.delete_memory(identity, memory_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn rebuild_memory_index_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request: Result<Json<RebuildMemoryIndexRequest>, JsonRejection>,
) -> Result<Json<MemoryIndexRebuildResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.rebuild_memory_index(identity, request)
    })
    .await?;
    Ok(Json(result))
}

async fn create_compaction_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(session_id): Path<String>,
    request: Result<Json<CreateCompactionRequest>, JsonRejection>,
) -> Result<Json<CompactionResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.create_compaction(identity, session_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn compaction_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(compaction_id): Path<String>,
) -> Result<Json<CompactionResponse>, HttpError> {
    let result = run_backend(state, move |backend| {
        backend.compaction(identity, compaction_id)
    })
    .await?;
    Ok(Json(result))
}

async fn install_extension_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request: Result<Json<InstallExtensionRequest>, JsonRejection>,
) -> Result<Json<ExtensionResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.install_extension(identity, request)
    })
    .await?;
    Ok(Json(result))
}

async fn extensions_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
) -> Result<Json<ExtensionsResponse>, HttpError> {
    let result = run_backend(state, move |backend| backend.extensions(identity)).await?;
    Ok(Json(result))
}

async fn extension_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(extension_id): Path<String>,
) -> Result<Json<ExtensionResponse>, HttpError> {
    let result = run_backend(state, move |backend| {
        backend.extension(identity, extension_id)
    })
    .await?;
    Ok(Json(result))
}

async fn stage_extension_manifest_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(extension_id): Path<String>,
    request: Result<Json<StageExtensionManifestRequest>, JsonRejection>,
) -> Result<Json<ExtensionResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.stage_extension_manifest(identity, extension_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn enable_extension_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(extension_id): Path<String>,
    request: Result<Json<EnableExtensionRequest>, JsonRejection>,
) -> Result<Json<ExtensionResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.enable_extension(identity, extension_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn disable_extension_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(extension_id): Path<String>,
    request: Result<Json<ExtensionLifecycleRequest>, JsonRejection>,
) -> Result<Json<ExtensionResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.disable_extension(identity, extension_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn revoke_extension_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(extension_id): Path<String>,
    request: Result<Json<ExtensionLifecycleRequest>, JsonRejection>,
) -> Result<Json<ExtensionResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.revoke_extension(identity, extension_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn invoke_extension_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(extension_id): Path<String>,
    request: Result<Json<InvokeExtensionRequest>, JsonRejection>,
) -> Result<Json<ExtensionInvocationResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.invoke_extension(identity, extension_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn create_webhook_channel_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request: Result<Json<CreateWebhookChannelRequest>, JsonRejection>,
) -> Result<Json<CreateWebhookChannelResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.create_webhook_channel(identity, request)
    })
    .await?;
    Ok(Json(result))
}

async fn webhook_channels_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
) -> Result<Json<WebhookChannelsResponse>, HttpError> {
    let result = run_backend(state, move |backend| backend.webhook_channels(identity)).await?;
    Ok(Json(result))
}

async fn webhook_channel_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(binding_id): Path<String>,
) -> Result<Json<WebhookChannelResponse>, HttpError> {
    let result = run_backend(state, move |backend| {
        backend.webhook_channel(identity, binding_id)
    })
    .await?;
    Ok(Json(result))
}

async fn revoke_webhook_channel_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(binding_id): Path<String>,
    request: Result<Json<RevokeWebhookChannelRequest>, JsonRejection>,
) -> Result<Json<WebhookChannelResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.revoke_webhook_channel(identity, binding_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn create_telegram_channel_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request: Result<Json<CreateTelegramChannelRequest>, JsonRejection>,
) -> Result<Json<TelegramChannelResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.create_telegram_channel(identity, request)
    })
    .await?;
    Ok(Json(result))
}

async fn telegram_channels_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
) -> Result<Json<TelegramChannelsResponse>, HttpError> {
    let result = run_backend(state, move |backend| backend.telegram_channels(identity)).await?;
    Ok(Json(result))
}

async fn telegram_channel_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(binding_id): Path<String>,
) -> Result<Json<TelegramChannelResponse>, HttpError> {
    let result = run_backend(state, move |backend| {
        backend.telegram_channel(identity, binding_id)
    })
    .await?;
    Ok(Json(result))
}

async fn revoke_telegram_channel_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(binding_id): Path<String>,
    request: Result<Json<RevokeTelegramChannelRequest>, JsonRejection>,
) -> Result<Json<TelegramChannelResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.revoke_telegram_channel(identity, binding_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn create_discord_channel_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request: Result<Json<CreateDiscordChannelRequest>, JsonRejection>,
) -> Result<Json<DiscordChannelResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.create_discord_channel(identity, request)
    })
    .await?;
    Ok(Json(result))
}

async fn discord_channels_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
) -> Result<Json<DiscordChannelsResponse>, HttpError> {
    let result = run_backend(state, move |backend| backend.discord_channels(identity)).await?;
    Ok(Json(result))
}

async fn discord_channel_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(binding_id): Path<String>,
) -> Result<Json<DiscordChannelResponse>, HttpError> {
    let result = run_backend(state, move |backend| {
        backend.discord_channel(identity, binding_id)
    })
    .await?;
    Ok(Json(result))
}

async fn revoke_discord_channel_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(binding_id): Path<String>,
    request: Result<Json<RevokeDiscordChannelRequest>, JsonRejection>,
) -> Result<Json<DiscordChannelResponse>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.revoke_discord_channel(identity, binding_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn receive_signed_webhook_handler(
    State(state): State<AppState>,
    Path(binding_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<InputAdmissionResponse>, HttpError> {
    let timestamp_ms = signed_header(&headers, "x-mealy-timestamp")?
        .parse::<i64>()
        .map_err(|_| HttpError(BackendError::Unauthorized))?;
    let nonce = signed_header(&headers, "x-mealy-nonce")?.to_owned();
    let signature = signed_header(&headers, "x-mealy-signature")?.to_owned();
    let envelope = SignedWebhookEnvelope {
        timestamp_ms,
        nonce,
        signature,
        body: body.to_vec(),
    };
    let result = run_backend(state, move |backend| {
        backend.receive_signed_webhook(binding_id, envelope)
    })
    .await?;
    Ok(Json(result))
}

fn signed_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, HttpError> {
    let Ok(name) = HeaderName::try_from(name) else {
        return Err(HttpError(BackendError::Internal));
    };
    let values = headers.get_all(name).iter().collect::<Vec<_>>();
    let [value] = values.as_slice() else {
        return Err(HttpError(BackendError::Unauthorized));
    };
    value
        .to_str()
        .map_err(|_| HttpError(BackendError::Unauthorized))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DelegationListParameters {
    limit: Option<usize>,
}

async fn delegations_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    parameters: Result<Query<DelegationListParameters>, QueryRejection>,
) -> Result<Json<DelegationsResponse>, HttpError> {
    let Query(parameters) = parameters.map_err(|rejection| map_query_rejection(&rejection))?;
    let limit = parameters.limit.unwrap_or(20);
    if !(1..=100).contains(&limit) {
        return Err(HttpError(BackendError::InvalidRequest(
            "delegation list limit must be between 1 and 100".to_owned(),
        )));
    }
    let result = run_backend(state, move |backend| backend.delegations(identity, limit)).await?;
    Ok(Json(result))
}

async fn delegation_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(delegation_id): Path<String>,
) -> Result<Json<DelegationResponse>, HttpError> {
    let result = run_backend(state, move |backend| {
        backend.delegation(identity, delegation_id)
    })
    .await?;
    Ok(Json(result))
}

async fn task_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(task_id): Path<String>,
) -> Result<Json<TaskResponse>, HttpError> {
    let result = run_backend(state, move |backend| backend.task(identity, task_id)).await?;
    Ok(Json(result))
}

const MAXIMUM_CANCELLATION_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAXIMUM_CANCELLATION_REASON_BYTES: usize = 1024;

async fn cancel_task_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(task_id): Path<String>,
    request: Result<Json<CancelTaskRequest>, JsonRejection>,
) -> Result<Json<TaskCancellationReceipt>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    validate_cancel_task_request(&request)?;
    let result = run_backend(state, move |backend| {
        backend.cancel_task(identity, task_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn pause_task_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(task_id): Path<String>,
    request: Result<Json<ControlTaskRequest>, JsonRejection>,
) -> Result<Json<TaskControlReceipt>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.pause_task(identity, task_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn resume_task_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(task_id): Path<String>,
    request: Result<Json<ControlTaskRequest>, JsonRejection>,
) -> Result<Json<TaskControlReceipt>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    let result = run_backend(state, move |backend| {
        backend.resume_task(identity, task_id, request)
    })
    .await?;
    Ok(Json(result))
}

fn validate_cancel_task_request(request: &CancelTaskRequest) -> Result<(), HttpError> {
    if request.idempotency_key.is_empty() {
        return Err(HttpError(BackendError::InvalidRequest(
            "idempotencyKey must not be empty".to_owned(),
        )));
    }
    if request.idempotency_key.len() > MAXIMUM_CANCELLATION_IDEMPOTENCY_KEY_BYTES {
        return Err(HttpError(BackendError::InvalidRequest(format!(
            "idempotencyKey exceeds {MAXIMUM_CANCELLATION_IDEMPOTENCY_KEY_BYTES} UTF-8 bytes"
        ))));
    }
    if request.reason.trim().is_empty() {
        return Err(HttpError(BackendError::InvalidRequest(
            "reason must not be blank".to_owned(),
        )));
    }
    if request.reason.len() > MAXIMUM_CANCELLATION_REASON_BYTES {
        return Err(HttpError(BackendError::InvalidRequest(format!(
            "reason exceeds {MAXIMUM_CANCELLATION_REASON_BYTES} UTF-8 bytes"
        ))));
    }
    Ok(())
}

async fn task_replay_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(task_id): Path<String>,
) -> Result<Json<TaskReplayResponse>, HttpError> {
    let result = run_backend(state, move |backend| backend.task_replay(identity, task_id)).await?;
    Ok(Json(result))
}

async fn pending_approvals_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
) -> Result<Json<PendingApprovalsResponse>, HttpError> {
    let result = run_backend(state, move |backend| backend.pending_approvals(identity)).await?;
    Ok(Json(result))
}

async fn resolve_approval_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(approval_id): Path<String>,
    request: Result<Json<ResolveApprovalRequest>, JsonRejection>,
) -> Result<Json<ApprovalResolutionReceipt>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    validate_effect_command_idempotency_key(&request.idempotency_key)?;
    validate_subject_digest(&request.expected_subject_digest)?;
    let result = run_backend(state, move |backend| {
        backend.resolve_approval(identity, approval_id, request)
    })
    .await?;
    Ok(Json(result))
}

async fn effect_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(effect_id): Path<String>,
) -> Result<Json<EffectResponse>, HttpError> {
    let result = run_backend(state, move |backend| backend.effect(identity, effect_id)).await?;
    Ok(Json(result))
}

async fn effect_attempt_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(attempt_id): Path<String>,
) -> Result<Json<EffectAttemptResponse>, HttpError> {
    let result = run_backend(state, move |backend| {
        backend.effect_attempt(identity, attempt_id)
    })
    .await?;
    Ok(Json(result))
}

async fn reconcile_effect_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path((effect_id, attempt_id)): Path<(String, String)>,
    request: Result<Json<ReconcileEffectRequest>, JsonRejection>,
) -> Result<Json<EffectReconciliationReceipt>, HttpError> {
    let Json(request) = request.map_err(|rejection| map_json_rejection(&rejection))?;
    require_version(&request.api_version)?;
    validate_effect_command_idempotency_key(&request.idempotency_key)?;
    validate_reconciliation_evidence(&request.evidence)?;
    let result = run_backend(state, move |backend| {
        backend.reconcile_effect(identity, effect_id, attempt_id, request)
    })
    .await?;
    Ok(Json(result))
}

fn validate_effect_command_idempotency_key(key: &str) -> Result<(), HttpError> {
    if key.is_empty() || key.len() > MAXIMUM_EFFECT_COMMAND_IDEMPOTENCY_KEY_BYTES {
        return Err(HttpError(BackendError::InvalidRequest(format!(
            "idempotencyKey must contain between 1 and \
             {MAXIMUM_EFFECT_COMMAND_IDEMPOTENCY_KEY_BYTES} UTF-8 bytes"
        ))));
    }
    Ok(())
}

fn validate_subject_digest(digest: &str) -> Result<(), HttpError> {
    if digest.len() != 64
        || digest
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(HttpError(BackendError::InvalidRequest(
            "expectedSubjectDigest must be a lowercase SHA-256 digest".to_owned(),
        )));
    }
    Ok(())
}

fn validate_reconciliation_evidence(evidence: &serde_json::Value) -> Result<(), HttpError> {
    let Some(object) = evidence.as_object() else {
        return Err(HttpError(BackendError::InvalidRequest(
            "evidence must be a non-empty JSON object".to_owned(),
        )));
    };
    if object.is_empty() {
        return Err(HttpError(BackendError::InvalidRequest(
            "evidence must be a non-empty JSON object".to_owned(),
        )));
    }
    if serde_json::to_vec(evidence).map_or(true, |encoded| {
        encoded.len() > MAXIMUM_EFFECT_OUTCOME_DETAILS_BYTES
    }) {
        return Err(HttpError(BackendError::InvalidRequest(format!(
            "evidence exceeds {MAXIMUM_EFFECT_OUTCOME_DETAILS_BYTES} canonical JSON bytes"
        ))));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
struct TimelineParameters {
    after: Option<u64>,
    limit: Option<usize>,
}

async fn timeline_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(session_id): Path<String>,
    parameters: Result<Query<TimelineParameters>, QueryRejection>,
) -> Result<Json<TimelinePageResponse>, HttpError> {
    let Query(parameters) = parameters.map_err(|rejection| map_query_rejection(&rejection))?;
    let after = parameters.after.map(TimelineCursor);
    let limit = parameters.limit.unwrap_or(100);
    let result = run_backend(state, move |backend| {
        backend.timeline_page(identity, session_id, after, limit)
    })
    .await?;
    Ok(Json(result))
}

async fn events_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Path(session_id): Path<String>,
    parameters: Result<Query<TimelineParameters>, QueryRejection>,
    headers: HeaderMap,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, HttpError> {
    let Query(parameters) = parameters.map_err(|rejection| map_query_rejection(&rejection))?;
    let header_cursor = headers
        .get("last-event-id")
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .map(TimelineCursor)
                .ok_or_else(|| {
                    HttpError(BackendError::InvalidRequest(
                        "invalid Last-Event-ID".to_owned(),
                    ))
                })
        })
        .transpose()?;
    let mut after = parameters.after.map(TimelineCursor).or(header_cursor);
    let limit = parameters.limit.unwrap_or(100).min(1000);
    let permit = state
        .0
        .subscribers
        .clone()
        .try_acquire_owned()
        .map_err(|_| HttpError(BackendError::Busy))?;
    let poll_interval = state.0.poll_interval;
    let stream_state = state.clone();
    let output = stream! {
        let _permit = permit;
        let mut shutdown = stream_state.0.shutdown.clone();
        loop {
            if shutdown_requested(shutdown.as_ref()) {
                return;
            }
            let page = tokio::select! {
                () = wait_for_shutdown(&mut shutdown) => return,
                page = run_backend(stream_state.clone(), {
                    let identity = identity.clone();
                    let session_id = session_id.clone();
                    move |backend| backend.timeline_page(identity, session_id, after, limit)
                }) => page,
            };
            match page {
                Ok(page) => {
                    let mut emitted = false;
                    for item in page.events {
                        emitted = true;
                        after = Some(item.cursor);
                        let event_name = item.event_type.clone();
                        match serde_json::to_string(&item) {
                            Ok(data) => yield Ok(Event::default()
                                .id(item.cursor.0.to_string())
                                .event(event_name)
                                .data(data)),
                            Err(_) => {
                                yield Ok(Event::default().event("error").data("serialization failure"));
                                return;
                            }
                        }
                    }
                    if !emitted {
                        tokio::select! {
                            () = wait_for_shutdown(&mut shutdown) => return,
                            () = tokio::time::sleep(poll_interval) => {}
                        }
                    }
                }
                Err(error) => {
                    let response = error_body(&error.0);
                    let data = serde_json::to_string(&response)
                        .unwrap_or_else(|_| "{\"code\":\"internal\"}".to_owned());
                    yield Ok(Event::default().event("error").data(data));
                    return;
                }
            }
        }
    };
    Ok(Sse::new(output).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

fn shutdown_requested(receiver: Option<&watch::Receiver<bool>>) -> bool {
    receiver.is_some_and(|receiver| *receiver.borrow())
}

async fn wait_for_shutdown(receiver: &mut Option<watch::Receiver<bool>>) {
    match receiver {
        Some(receiver) => {
            let _ = receiver.changed().await;
        }
        None => std::future::pending::<()>().await,
    }
}

fn map_json_rejection(rejection: &JsonRejection) -> HttpError {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        HttpError(BackendError::PayloadTooLarge)
    } else {
        HttpError(BackendError::InvalidRequest(
            "request body must be valid JSON matching the endpoint schema".to_owned(),
        ))
    }
}

fn map_query_rejection(_rejection: &QueryRejection) -> HttpError {
    HttpError(BackendError::InvalidRequest(
        "query parameters are malformed".to_owned(),
    ))
}

async fn not_found_handler() -> Response {
    api_error(
        StatusCode::NOT_FOUND,
        "not_found",
        "resource was not found",
        false,
    )
}

async fn method_not_allowed_handler() -> Response {
    api_error(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "HTTP method is not allowed for this resource",
        false,
    )
}

async fn run_backend<T, F>(state: AppState, operation: F) -> Result<T, HttpError>
where
    T: Send + 'static,
    F: FnOnce(Arc<dyn ApiBackend>) -> Result<T, BackendError> + Send + 'static,
{
    let permit = state
        .0
        .commands
        .clone()
        .try_acquire_owned()
        .map_err(|error| match error {
            TryAcquireError::NoPermits | TryAcquireError::Closed => HttpError(BackendError::Busy),
        })?;
    let backend = Arc::clone(&state.0.backend);
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation(backend)
    })
    .await
    .map_err(|_| HttpError(BackendError::Internal))?
    .map_err(HttpError)
}

fn require_version(version: &str) -> Result<(), HttpError> {
    if version == API_VERSION {
        Ok(())
    } else {
        Err(HttpError(BackendError::InvalidRequest(format!(
            "unsupported apiVersion {version:?}"
        ))))
    }
}

struct HttpError(BackendError);

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            BackendError::Unauthorized => StatusCode::FORBIDDEN,
            BackendError::NotFound => StatusCode::NOT_FOUND,
            BackendError::Conflict => StatusCode::CONFLICT,
            BackendError::TimelineGap { .. } | BackendError::TimelineCursorAhead => {
                StatusCode::CONFLICT
            }
            BackendError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            BackendError::Busy => StatusCode::TOO_MANY_REQUESTS,
            BackendError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            BackendError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            BackendError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        api_error(
            status,
            error_code(&self.0),
            &self.0.to_string(),
            retryable(&self.0),
        )
    }
}

fn api_error(status: StatusCode, code: &str, message: &str, retryable: bool) -> Response {
    (
        status,
        Json(ApiErrorResponse {
            api_version: API_VERSION.to_owned(),
            code: code.to_owned(),
            message: message.to_owned(),
            retryable,
        }),
    )
        .into_response()
}

fn error_body(error: &BackendError) -> ApiErrorResponse {
    ApiErrorResponse {
        api_version: API_VERSION.to_owned(),
        code: error_code(error).to_owned(),
        message: error.to_string(),
        retryable: retryable(error),
    }
}

const fn error_code(error: &BackendError) -> &'static str {
    match error {
        BackendError::Unauthorized => "unauthorized",
        BackendError::NotFound => "not_found",
        BackendError::Conflict => "conflict",
        BackendError::TimelineGap { .. } => "timeline_gap",
        BackendError::TimelineCursorAhead => "timeline_cursor_ahead",
        BackendError::InvalidRequest(_) => "invalid_request",
        BackendError::Busy => "busy",
        BackendError::PayloadTooLarge => "payload_too_large",
        BackendError::Unavailable => "unavailable",
        BackendError::Internal => "internal",
    }
}

const fn retryable(error: &BackendError) -> bool {
    matches!(error, BackendError::Busy | BackendError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::{
        ApiAuth, ApiBackend, ApiConfig, ArtifactContent, AuthenticatedIdentity, BackendError,
        SignedWebhookEnvelope, router, router_with_shutdown,
    };
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use mealy_protocol::{
        API_VERSION, ApiErrorResponse, ApprovalDecisionCommand, ApprovalResolutionReceipt,
        ApprovalStatusResponse, ArtifactMetadataResponse, CancelTaskRequest, CompactionResponse,
        ContextItemDisposition, ContextManifestEvidenceItemResponse,
        ContextManifestEvidenceResponse, CreateCompactionRequest, CreateSessionResponse,
        EffectAttemptResponse, EffectReconciliationReceipt, EffectResponse, InputAdmissionResponse,
        MemoriesResponse, MemoryIndexRebuildResponse, MemoryLifecycleRequest, MemoryResponse,
        MemorySearchResponse, MemorySensitivityCommand, PendingApprovalsResponse,
        PromoteMemoryRequest, ProposeMemoryRequest, RebuildMemoryIndexRequest,
        ReconcileEffectRequest, ReconciliationOutcomeCommand, ResolveApprovalRequest,
        SessionStatusResponse, SessionSummaryResponse, SessionsResponse, SetMemoryPinRequest,
        SubmitInputRequest, TaskBudgetUsage, TaskCancellationReceipt, TaskReplayResponse,
        TaskResponse, TaskRiskClass, TaskStatus, TaskSuccessCriteriaResponse, TimelineCursor,
        TimelinePageResponse,
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    struct FakeBackend;

    impl ApiBackend for FakeBackend {
        fn readiness(&self) -> Result<(), BackendError> {
            Ok(())
        }

        fn safe_mode(&self) -> bool {
            false
        }

        fn admission_open(&self) -> bool {
            true
        }

        fn admin_status(
            &self,
            _identity: AuthenticatedIdentity,
        ) -> Result<mealy_protocol::AdminStatusResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn admin_metrics(
            &self,
            _identity: AuthenticatedIdentity,
        ) -> Result<mealy_protocol::AdminMetricsResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn admin_usage(
            &self,
            _identity: AuthenticatedIdentity,
            from_ms: i64,
            to_ms: i64,
        ) -> Result<mealy_protocol::AdminUsageReportResponse, BackendError> {
            Ok(mealy_protocol::AdminUsageReportResponse {
                api_version: API_VERSION.to_owned(),
                from_ms,
                to_ms,
                buckets: vec![mealy_protocol::AdminUsageBucketResponse {
                    bucket_start_ms: 86_400_000,
                    bucket_end_ms: to_ms,
                    completed_runs: 1,
                    succeeded_runs: 1,
                    failed_runs: 0,
                    cancelled_runs: 0,
                    used_model_calls: 2,
                    used_tool_calls: 1,
                    used_delegated_runs: 0,
                    used_retries: 0,
                    used_input_tokens: 100,
                    used_output_tokens: 20,
                    used_cost_microunits: 30,
                    used_output_bytes: 40,
                }],
            })
        }

        fn drain_daemon(
            &self,
            _identity: AuthenticatedIdentity,
            _request: mealy_protocol::DrainDaemonRequest,
        ) -> Result<mealy_protocol::DrainDaemonResponse, BackendError> {
            Ok(mealy_protocol::DrainDaemonResponse {
                api_version: API_VERSION.to_owned(),
                start_id: "start-1".to_owned(),
                deadline_ms: 10_000,
                newly_requested: true,
            })
        }

        fn doctor(
            &self,
            _identity: AuthenticatedIdentity,
        ) -> Result<mealy_protocol::DoctorResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn create_backup(
            &self,
            _identity: AuthenticatedIdentity,
            _request: mealy_protocol::CreateBackupRequest,
        ) -> Result<mealy_protocol::BackupResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn verify_backup(
            &self,
            _identity: AuthenticatedIdentity,
            _request: mealy_protocol::VerifyBackupRequest,
        ) -> Result<mealy_protocol::BackupVerificationResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn run_garbage_collection(
            &self,
            _identity: AuthenticatedIdentity,
            _request: mealy_protocol::RunGarbageCollectionRequest,
        ) -> Result<mealy_protocol::GarbageCollectionResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn create_export(
            &self,
            _identity: AuthenticatedIdentity,
            _request: mealy_protocol::CreateExportRequest,
        ) -> Result<mealy_protocol::ExportResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn create_session(
            &self,
            _identity: AuthenticatedIdentity,
        ) -> Result<CreateSessionResponse, BackendError> {
            Ok(CreateSessionResponse {
                api_version: API_VERSION.to_owned(),
                session_id: "session-1".to_owned(),
            })
        }

        fn sessions(
            &self,
            _identity: AuthenticatedIdentity,
            limit: usize,
        ) -> Result<SessionsResponse, BackendError> {
            Ok(SessionsResponse {
                api_version: API_VERSION.to_owned(),
                sessions: (limit > 0)
                    .then(|| SessionSummaryResponse {
                        session_id: "session-1".to_owned(),
                        status: "active".to_owned(),
                        revision: 1,
                        pending_inputs: 0,
                        active_turn_id: None,
                        created_at_ms: 1,
                        updated_at_ms: 2,
                    })
                    .into_iter()
                    .collect(),
            })
        }

        fn submit_input(
            &self,
            _identity: AuthenticatedIdentity,
            _session_id: String,
            _request: SubmitInputRequest,
        ) -> Result<InputAdmissionResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn session_status(
            &self,
            _identity: AuthenticatedIdentity,
            _session_id: String,
        ) -> Result<SessionStatusResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn timeline_page(
            &self,
            _identity: AuthenticatedIdentity,
            _session_id: String,
            _after: Option<TimelineCursor>,
            _limit: usize,
        ) -> Result<TimelinePageResponse, BackendError> {
            Ok(TimelinePageResponse {
                api_version: API_VERSION.to_owned(),
                events: Vec::new(),
                high_watermark: TimelineCursor(0),
                has_more: false,
            })
        }

        fn artifact_metadata(
            &self,
            _identity: AuthenticatedIdentity,
            artifact_id: String,
        ) -> Result<ArtifactMetadataResponse, BackendError> {
            if artifact_id == "missing" {
                return Err(BackendError::NotFound);
            }
            Ok(ArtifactMetadataResponse {
                api_version: API_VERSION.to_owned(),
                artifact_id,
                algorithm: "sha256".to_owned(),
                digest: "a".repeat(64),
                size_bytes: 17,
                media_type: "text/plain".to_owned(),
                origin_kind: "tool_call".to_owned(),
                origin_id: "tool-1".to_owned(),
                producer_kind: "builtin".to_owned(),
                producer_id: "read_text".to_owned(),
                sensitivity: "private".to_owned(),
                retention_class: "task_history".to_owned(),
                access_policy_digest: "b".repeat(64),
                created_at_ms: 10,
            })
        }

        fn artifact_content(
            &self,
            _identity: AuthenticatedIdentity,
            artifact_id: String,
        ) -> Result<ArtifactContent, BackendError> {
            match artifact_id.as_str() {
                "missing" => Err(BackendError::NotFound),
                "corrupt" => Err(BackendError::Internal),
                _ => Ok(ArtifactContent {
                    media_type: "text/plain".to_owned(),
                    bytes: b"verified artifact".to_vec(),
                }),
            }
        }

        fn context_manifest(
            &self,
            identity: AuthenticatedIdentity,
            manifest_id: String,
        ) -> Result<ContextManifestEvidenceResponse, BackendError> {
            if manifest_id == "missing"
                || identity.principal_id != "principal"
                || identity.channel_binding_id != "binding"
            {
                return Err(BackendError::NotFound);
            }
            let item = |ordinal, disposition, content| ContextManifestEvidenceItemResponse {
                item_id: format!("item-{ordinal}"),
                ordinal,
                disposition,
                source_type: "fixture".to_owned(),
                source_locator: format!("fixture://item-{ordinal}"),
                source_content_digest: "a".repeat(64),
                rendered_content_digest: "a".repeat(64),
                inclusion_reason: "fixture selection".to_owned(),
                sensitivity: "private".to_owned(),
                token_estimate: 1,
                transformation: "identity".to_owned(),
                policy_decision: "fixture policy".to_owned(),
                content,
                content_artifact_id: None,
                memory_evidence: None,
                compaction_id: None,
            };
            Ok(ContextManifestEvidenceResponse {
                api_version: API_VERSION.to_owned(),
                manifest_id,
                run_id: "run-1".to_owned(),
                turn_id: "turn-1".to_owned(),
                epoch_id: "epoch-1".to_owned(),
                iteration: 1,
                compiler_version: "v1".to_owned(),
                provider_residency: "local".to_owned(),
                token_budget: 100,
                total_token_estimate: 1,
                tool_schema_set_digest: "b".repeat(64),
                policy_version: "v1".to_owned(),
                projection_digest: "c".repeat(64),
                items: vec![
                    item(
                        0,
                        ContextItemDisposition::Included,
                        Some("included content".to_owned()),
                    ),
                    item(1, ContextItemDisposition::Excluded, None),
                    item(2, ContextItemDisposition::Redacted, None),
                ],
                created_at_ms: 1,
            })
        }

        fn task(
            &self,
            _identity: AuthenticatedIdentity,
            task_id: String,
        ) -> Result<TaskResponse, BackendError> {
            Ok(TaskResponse {
                api_version: API_VERSION.to_owned(),
                task_id,
                run_id: "run-1".to_owned(),
                status: TaskStatus::Succeeded,
                revision: 4,
                final_response: Some("done".to_owned()),
                final_digest: Some("digest".to_owned()),
                usage: TaskBudgetUsage::default(),
                success_criteria: TaskSuccessCriteriaResponse {
                    objective: "Return the recorded result".to_owned(),
                    criteria: Vec::new(),
                    no_objective_criteria_reason: Some("API fixture".to_owned()),
                    risk_class: TaskRiskClass::Low,
                    policy_version: "test.v1".to_owned(),
                    criteria_digest: "digest".to_owned(),
                },
                validation: None,
                model_attempts: 2,
                tool_calls: 1,
            })
        }

        fn propose_memory(
            &self,
            _identity: AuthenticatedIdentity,
            _request: ProposeMemoryRequest,
        ) -> Result<MemoryResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn promote_memory(
            &self,
            _identity: AuthenticatedIdentity,
            _memory_id: String,
            _request: PromoteMemoryRequest,
        ) -> Result<MemoryResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn memory(
            &self,
            _identity: AuthenticatedIdentity,
            _workspace_identity: String,
            _memory_id: String,
        ) -> Result<MemoryResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn memories(
            &self,
            _identity: AuthenticatedIdentity,
            _workspace_identity: String,
            _include_deleted: bool,
        ) -> Result<MemoriesResponse, BackendError> {
            Ok(MemoriesResponse {
                api_version: API_VERSION.to_owned(),
                memories: Vec::new(),
            })
        }

        fn search_memories(
            &self,
            _identity: AuthenticatedIdentity,
            _workspace_identity: String,
            _query: String,
            _maximum_sensitivity: MemorySensitivityCommand,
            _limit: usize,
        ) -> Result<MemorySearchResponse, BackendError> {
            Ok(MemorySearchResponse {
                api_version: API_VERSION.to_owned(),
                hits: Vec::new(),
            })
        }

        fn correct_memory(
            &self,
            _identity: AuthenticatedIdentity,
            _memory_id: String,
            _request: mealy_protocol::CorrectMemoryRequest,
        ) -> Result<MemoryResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn set_memory_pin(
            &self,
            _identity: AuthenticatedIdentity,
            _memory_id: String,
            _request: SetMemoryPinRequest,
        ) -> Result<MemoryResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn expire_memory(
            &self,
            _identity: AuthenticatedIdentity,
            _memory_id: String,
            _request: MemoryLifecycleRequest,
        ) -> Result<MemoryResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn reject_memory(
            &self,
            _identity: AuthenticatedIdentity,
            _memory_id: String,
            _request: MemoryLifecycleRequest,
        ) -> Result<MemoryResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn delete_memory(
            &self,
            _identity: AuthenticatedIdentity,
            _memory_id: String,
            _request: MemoryLifecycleRequest,
        ) -> Result<MemoryResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn rebuild_memory_index(
            &self,
            _identity: AuthenticatedIdentity,
            _request: RebuildMemoryIndexRequest,
        ) -> Result<MemoryIndexRebuildResponse, BackendError> {
            Ok(MemoryIndexRebuildResponse {
                api_version: API_VERSION.to_owned(),
                indexed_revision_count: 0,
                rebuilt_at_ms: 1,
            })
        }

        fn create_compaction(
            &self,
            _identity: AuthenticatedIdentity,
            _session_id: String,
            _request: CreateCompactionRequest,
        ) -> Result<CompactionResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn compaction(
            &self,
            _identity: AuthenticatedIdentity,
            _compaction_id: String,
        ) -> Result<CompactionResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn install_extension(
            &self,
            _identity: AuthenticatedIdentity,
            _request: mealy_protocol::InstallExtensionRequest,
        ) -> Result<mealy_protocol::ExtensionResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn extensions(
            &self,
            _identity: AuthenticatedIdentity,
        ) -> Result<mealy_protocol::ExtensionsResponse, BackendError> {
            Ok(mealy_protocol::ExtensionsResponse {
                api_version: API_VERSION.to_owned(),
                extensions: Vec::new(),
            })
        }

        fn extension(
            &self,
            _identity: AuthenticatedIdentity,
            _extension_id: String,
        ) -> Result<mealy_protocol::ExtensionResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn stage_extension_manifest(
            &self,
            _identity: AuthenticatedIdentity,
            _extension_id: String,
            _request: mealy_protocol::StageExtensionManifestRequest,
        ) -> Result<mealy_protocol::ExtensionResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn enable_extension(
            &self,
            _identity: AuthenticatedIdentity,
            _extension_id: String,
            _request: mealy_protocol::EnableExtensionRequest,
        ) -> Result<mealy_protocol::ExtensionResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn disable_extension(
            &self,
            _identity: AuthenticatedIdentity,
            _extension_id: String,
            _request: mealy_protocol::ExtensionLifecycleRequest,
        ) -> Result<mealy_protocol::ExtensionResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn revoke_extension(
            &self,
            _identity: AuthenticatedIdentity,
            _extension_id: String,
            _request: mealy_protocol::ExtensionLifecycleRequest,
        ) -> Result<mealy_protocol::ExtensionResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn invoke_extension(
            &self,
            _identity: AuthenticatedIdentity,
            _extension_id: String,
            _request: mealy_protocol::InvokeExtensionRequest,
        ) -> Result<mealy_protocol::ExtensionInvocationResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn create_webhook_channel(
            &self,
            _identity: AuthenticatedIdentity,
            _request: mealy_protocol::CreateWebhookChannelRequest,
        ) -> Result<mealy_protocol::CreateWebhookChannelResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn webhook_channels(
            &self,
            _identity: AuthenticatedIdentity,
        ) -> Result<mealy_protocol::WebhookChannelsResponse, BackendError> {
            Ok(mealy_protocol::WebhookChannelsResponse {
                api_version: API_VERSION.to_owned(),
                channels: Vec::new(),
            })
        }

        fn webhook_channel(
            &self,
            _identity: AuthenticatedIdentity,
            _binding_id: String,
        ) -> Result<mealy_protocol::WebhookChannelResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn revoke_webhook_channel(
            &self,
            _identity: AuthenticatedIdentity,
            _binding_id: String,
            _request: mealy_protocol::RevokeWebhookChannelRequest,
        ) -> Result<mealy_protocol::WebhookChannelResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn receive_signed_webhook(
            &self,
            binding_id: String,
            envelope: SignedWebhookEnvelope,
        ) -> Result<InputAdmissionResponse, BackendError> {
            if binding_id != "binding"
                || envelope.timestamp_ms != 1
                || envelope.nonce != "nonce"
                || envelope.signature != "a".repeat(64)
                || envelope.body != br#"{"apiVersion":"v1"}"#
            {
                return Err(BackendError::Unauthorized);
            }
            Ok(InputAdmissionResponse {
                api_version: API_VERSION.to_owned(),
                session_id: "session-1".to_owned(),
                inbox_entry_id: "inbox-1".to_owned(),
                inbox_sequence: 1,
                delivery_mode: mealy_protocol::DeliveryMode::Queue,
                event_id: "event-1".to_owned(),
                outbox_id: "outbox-1".to_owned(),
                accepted_at_ms: 1,
                duplicate: false,
                cursor: TimelineCursor(1),
            })
        }

        fn cancel_task(
            &self,
            _identity: AuthenticatedIdentity,
            task_id: String,
            _request: CancelTaskRequest,
        ) -> Result<TaskCancellationReceipt, BackendError> {
            Ok(TaskCancellationReceipt {
                api_version: API_VERSION.to_owned(),
                task_id,
                status: TaskStatus::Cancelling,
                revision: 2,
                event_id: "event-cancel-1".to_owned(),
                cursor: TimelineCursor(8),
                duplicate: false,
            })
        }

        fn pause_task(
            &self,
            _identity: AuthenticatedIdentity,
            task_id: String,
            request: mealy_protocol::ControlTaskRequest,
        ) -> Result<mealy_protocol::TaskControlReceipt, BackendError> {
            Ok(mealy_protocol::TaskControlReceipt {
                api_version: API_VERSION.to_owned(),
                task_id,
                status: TaskStatus::Paused,
                revision: request.expected_revision + 1,
                event_id: "event-pause-1".to_owned(),
                cursor: TimelineCursor(9),
            })
        }

        fn resume_task(
            &self,
            _identity: AuthenticatedIdentity,
            task_id: String,
            request: mealy_protocol::ControlTaskRequest,
        ) -> Result<mealy_protocol::TaskControlReceipt, BackendError> {
            Ok(mealy_protocol::TaskControlReceipt {
                api_version: API_VERSION.to_owned(),
                task_id,
                status: TaskStatus::Queued,
                revision: request.expected_revision + 1,
                event_id: "event-resume-1".to_owned(),
                cursor: TimelineCursor(10),
            })
        }

        fn task_replay(
            &self,
            _identity: AuthenticatedIdentity,
            task_id: String,
        ) -> Result<TaskReplayResponse, BackendError> {
            Ok(TaskReplayResponse {
                api_version: API_VERSION.to_owned(),
                task_id,
                run_id: "run-1".to_owned(),
                mode: "recorded_evidence".to_owned(),
                evidence_complete: true,
                final_response: Some("done".to_owned()),
                final_digest: Some("digest".to_owned()),
                model_attempts: 2,
                tool_calls: 1,
                live_provider_calls: 0,
                live_tool_calls: 0,
            })
        }

        fn pending_approvals(
            &self,
            _identity: AuthenticatedIdentity,
        ) -> Result<PendingApprovalsResponse, BackendError> {
            Ok(PendingApprovalsResponse {
                api_version: API_VERSION.to_owned(),
                approvals: Vec::new(),
            })
        }

        fn resolve_approval(
            &self,
            _identity: AuthenticatedIdentity,
            approval_id: String,
            request: ResolveApprovalRequest,
        ) -> Result<ApprovalResolutionReceipt, BackendError> {
            let status = match request.decision {
                ApprovalDecisionCommand::Approve => ApprovalStatusResponse::Approved,
                ApprovalDecisionCommand::Deny => ApprovalStatusResponse::Denied,
            };
            Ok(ApprovalResolutionReceipt {
                api_version: API_VERSION.to_owned(),
                approval_id,
                effect_id: "effect-1".to_owned(),
                status,
                decision: request.decision,
                effect_revision: 2,
                approval_event_id: "approval-event-1".to_owned(),
                effect_event_id: "effect-event-1".to_owned(),
                cursor: TimelineCursor(9),
                duplicate: false,
            })
        }

        fn effect(
            &self,
            _identity: AuthenticatedIdentity,
            _effect_id: String,
        ) -> Result<EffectResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn effect_attempt(
            &self,
            _identity: AuthenticatedIdentity,
            _attempt_id: String,
        ) -> Result<EffectAttemptResponse, BackendError> {
            Err(BackendError::NotFound)
        }

        fn reconcile_effect(
            &self,
            _identity: AuthenticatedIdentity,
            effect_id: String,
            attempt_id: String,
            request: ReconcileEffectRequest,
        ) -> Result<EffectReconciliationReceipt, BackendError> {
            Ok(EffectReconciliationReceipt {
                api_version: API_VERSION.to_owned(),
                effect_id,
                attempt_id,
                outcome: request.outcome,
                effect_revision: 4,
                event_id: "reconciliation-event-1".to_owned(),
                cursor: TimelineCursor(10),
                duplicate: false,
            })
        }
    }

    fn app() -> (axum::Router, String) {
        let auth = ApiAuth::new(
            [7; 32],
            AuthenticatedIdentity {
                principal_id: "principal".to_owned(),
                channel_binding_id: "binding".to_owned(),
            },
        );
        let token = auth.encoded_token();
        (
            router(&ApiConfig::default(), auth, Arc::new(FakeBackend)),
            token,
        )
    }

    async fn assert_json_error(response: axum::response::Response, expected: StatusCode) {
        assert_eq!(response.status(), expected);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(response.into_body(), 4096)
            .await
            .expect("error body");
        serde_json::from_slice::<ApiErrorResponse>(&body).expect("versioned JSON error response");
    }

    #[tokio::test]
    async fn admin_usage_route_is_authenticated_exact_and_query_closed() {
        let (app, token) = app();
        let response = app
            .clone()
            .oneshot(
                Request::get("/v1/admin/usage?fromMs=86400001&toMs=172800000")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("usage request"),
            )
            .await
            .expect("usage response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096)
            .await
            .expect("usage response body");
        let report = serde_json::from_slice::<mealy_protocol::AdminUsageReportResponse>(&body)
            .expect("versioned usage report");
        assert_eq!(report.from_ms, 86_400_001);
        assert_eq!(report.to_ms, 172_800_000);
        assert_eq!(report.buckets[0].used_cost_microunits, 30);

        let widened = app
            .clone()
            .oneshot(
                Request::get("/v1/admin/usage?fromMs=86400001&toMs=172800000&currency=NZD")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("widened usage request"),
            )
            .await
            .expect("widened usage response");
        assert_json_error(widened, StatusCode::BAD_REQUEST).await;

        let unauthorized = app
            .oneshot(
                Request::get("/v1/admin/usage?fromMs=86400001&toMs=172800000")
                    .body(Body::empty())
                    .expect("unauthorized usage request"),
            )
            .await
            .expect("unauthorized usage response");
        assert_json_error(unauthorized, StatusCode::UNAUTHORIZED).await;
    }

    #[tokio::test]
    async fn effect_inspection_routes_are_authenticated_and_versioned() {
        let (app, token) = app();
        let approvals = app
            .clone()
            .oneshot(
                Request::get("/v1/approvals")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("approval request"),
            )
            .await
            .expect("approval response");
        assert_eq!(approvals.status(), StatusCode::OK);
        let body = to_bytes(approvals.into_body(), 4096)
            .await
            .expect("approval response body");
        let approvals = serde_json::from_slice::<PendingApprovalsResponse>(&body)
            .expect("versioned approval response");
        assert_eq!(approvals.api_version, API_VERSION);
        assert!(approvals.approvals.is_empty());

        let missing = app
            .oneshot(
                Request::get("/v1/effects/missing")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("effect request"),
            )
            .await
            .expect("effect response");
        assert_json_error(missing, StatusCode::NOT_FOUND).await;
    }

    #[tokio::test]
    async fn effect_command_routes_validate_bound_evidence_and_return_receipts() {
        let (app, token) = app();
        let approval = app
            .clone()
            .oneshot(
                Request::post("/v1/approvals/approval-1/resolve")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "apiVersion": API_VERSION,
                            "idempotencyKey": "approval-delivery-1",
                            "expectedSubjectDigest": "a".repeat(64),
                            "decision": "approve",
                        })
                        .to_string(),
                    ))
                    .expect("approval resolution request"),
            )
            .await
            .expect("approval resolution response");
        assert_eq!(approval.status(), StatusCode::OK);
        let body = to_bytes(approval.into_body(), 4096)
            .await
            .expect("approval receipt body");
        let receipt = serde_json::from_slice::<ApprovalResolutionReceipt>(&body)
            .expect("versioned approval receipt");
        assert_eq!(receipt.approval_id, "approval-1");
        assert_eq!(receipt.status, ApprovalStatusResponse::Approved);

        let bad_digest = app
            .clone()
            .oneshot(
                Request::post("/v1/approvals/approval-1/resolve")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "apiVersion": API_VERSION,
                            "idempotencyKey": "approval-delivery-2",
                            "expectedSubjectDigest": "A".repeat(64),
                            "decision": "deny",
                        })
                        .to_string(),
                    ))
                    .expect("invalid approval request"),
            )
            .await
            .expect("invalid approval response");
        assert_json_error(bad_digest, StatusCode::BAD_REQUEST).await;

        let reconciliation = app
            .clone()
            .oneshot(
                Request::post("/v1/effects/effect-1/attempts/attempt-1/reconcile")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "apiVersion": API_VERSION,
                            "idempotencyKey": "reconciliation-delivery-1",
                            "expectedEffectRevision": 3,
                            "outcome": "succeeded",
                            "evidence": {"receipt": "external-1"},
                        })
                        .to_string(),
                    ))
                    .expect("reconciliation request"),
            )
            .await
            .expect("reconciliation response");
        assert_eq!(reconciliation.status(), StatusCode::OK);
        let body = to_bytes(reconciliation.into_body(), 4096)
            .await
            .expect("reconciliation receipt body");
        let receipt = serde_json::from_slice::<EffectReconciliationReceipt>(&body)
            .expect("versioned reconciliation receipt");
        assert_eq!(receipt.effect_id, "effect-1");
        assert_eq!(receipt.attempt_id, "attempt-1");
        assert_eq!(receipt.outcome, ReconciliationOutcomeCommand::Succeeded);

        let empty_evidence = app
            .oneshot(
                Request::post("/v1/effects/effect-1/attempts/attempt-1/reconcile")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "apiVersion": API_VERSION,
                            "idempotencyKey": "reconciliation-delivery-2",
                            "expectedEffectRevision": 3,
                            "outcome": "failed",
                            "evidence": {},
                        })
                        .to_string(),
                    ))
                    .expect("invalid reconciliation request"),
            )
            .await
            .expect("invalid reconciliation response");
        assert_json_error(empty_evidence, StatusCode::BAD_REQUEST).await;
    }

    #[tokio::test]
    async fn protected_routes_require_the_exact_bearer() {
        let (app, token) = app();
        let unauthorized = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!("{{\"apiVersion\":\"{API_VERSION}\"}}")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let authorized = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!("{{\"apiVersion\":\"{API_VERSION}\"}}")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(authorized.status(), StatusCode::OK);
        let body = to_bytes(authorized.into_body(), 4096).await.expect("body");
        assert!(String::from_utf8_lossy(&body).contains("session-1"));

        let listed = app
            .oneshot(
                Request::get("/v1/sessions?limit=10")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("session list request"),
            )
            .await
            .expect("session list response");
        assert_eq!(listed.status(), StatusCode::OK);
        let body = to_bytes(listed.into_body(), 4096).await.expect("body");
        let sessions: SessionsResponse = serde_json::from_slice(&body).expect("sessions JSON");
        assert_eq!(sessions.sessions.len(), 1);
        assert_eq!(sessions.sessions[0].session_id, "session-1");
    }

    #[tokio::test]
    async fn signed_webhook_ingress_bypasses_local_bearer_only_for_exact_verified_evidence() {
        let (app, _) = app();
        let body = br#"{"apiVersion":"v1"}"#;
        let accepted = app
            .clone()
            .oneshot(
                Request::post("/v1/channels/webhooks/binding/deliveries")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("x-mealy-timestamp", "1")
                    .header("x-mealy-nonce", "nonce")
                    .header("x-mealy-signature", "a".repeat(64))
                    .body(Body::from(body.as_slice()))
                    .expect("signed webhook request"),
            )
            .await
            .expect("signed webhook response");
        assert_eq!(accepted.status(), StatusCode::OK);
        let receipt = to_bytes(accepted.into_body(), 4096)
            .await
            .expect("webhook receipt");
        let receipt = serde_json::from_slice::<InputAdmissionResponse>(&receipt)
            .expect("versioned admission receipt");
        assert_eq!(receipt.session_id, "session-1");

        let rejected = app
            .oneshot(
                Request::post("/v1/channels/webhooks/binding/deliveries")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("x-mealy-timestamp", "1")
                    .header("x-mealy-nonce", "nonce")
                    .header("x-mealy-signature", "b".repeat(64))
                    .body(Body::from(body.as_slice()))
                    .expect("forged webhook request"),
            )
            .await
            .expect("forged webhook response");
        assert_json_error(rejected, StatusCode::FORBIDDEN).await;
    }

    #[tokio::test]
    async fn task_and_replay_queries_are_authenticated_versioned_projections() {
        let (app, token) = app();
        let unauthorized = app
            .clone()
            .oneshot(
                Request::get("/v1/tasks/task-1")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_json_error(unauthorized, StatusCode::UNAUTHORIZED).await;

        let task = app
            .clone()
            .oneshot(
                Request::get("/v1/tasks/task-1")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(task.status(), StatusCode::OK);
        let task_body = to_bytes(task.into_body(), 4096).await.expect("task body");
        let task = serde_json::from_slice::<TaskResponse>(&task_body).expect("task response");
        assert_eq!(task.api_version, API_VERSION);
        assert_eq!(task.task_id, "task-1");
        assert_eq!(task.final_response.as_deref(), Some("done"));

        let replay = app
            .oneshot(
                Request::get("/v1/tasks/task-1/replay")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(replay.status(), StatusCode::OK);
        let replay_body = to_bytes(replay.into_body(), 4096)
            .await
            .expect("replay body");
        let replay =
            serde_json::from_slice::<TaskReplayResponse>(&replay_body).expect("replay response");
        assert_eq!(replay.api_version, API_VERSION);
        assert_eq!(replay.task_id, "task-1");
        assert!(replay.evidence_complete);
        assert_eq!(replay.live_provider_calls, 0);
        assert_eq!(replay.live_tool_calls, 0);
    }

    #[tokio::test]
    async fn artifact_routes_are_authenticated_path_free_and_hardened() {
        let (app, token) = app();
        let unauthorized = app
            .clone()
            .oneshot(
                Request::get("/v1/artifacts/artifact-1")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_json_error(unauthorized, StatusCode::UNAUTHORIZED).await;

        let metadata = app
            .clone()
            .oneshot(
                Request::get("/v1/artifacts/artifact-1")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(metadata.status(), StatusCode::OK);
        let metadata_body = to_bytes(metadata.into_body(), 4096)
            .await
            .expect("metadata body");
        let metadata: ArtifactMetadataResponse =
            serde_json::from_slice(&metadata_body).expect("artifact metadata");
        assert_eq!(metadata.api_version, API_VERSION);
        assert_eq!(metadata.artifact_id, "artifact-1");
        assert!(!String::from_utf8_lossy(&metadata_body).contains("relativePath"));

        let content = app
            .oneshot(
                Request::get("/v1/artifacts/artifact-1/content")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(content.status(), StatusCode::OK);
        assert_eq!(
            content.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static("text/plain"))
        );
        assert_eq!(
            content.headers().get(header::CACHE_CONTROL),
            Some(&header::HeaderValue::from_static("no-store"))
        );
        assert_eq!(
            content.headers().get("x-content-type-options"),
            Some(&header::HeaderValue::from_static("nosniff"))
        );
        assert_eq!(
            content.headers().get(header::CONTENT_DISPOSITION),
            Some(&header::HeaderValue::from_static(
                "attachment; filename=\"mealy-artifact\""
            ))
        );
        let content_body = to_bytes(content.into_body(), 4096)
            .await
            .expect("content body");
        assert_eq!(&content_body[..], b"verified artifact");
    }

    #[tokio::test]
    async fn artifact_absence_and_corruption_use_safe_error_envelopes() {
        let (app, token) = app();
        for (artifact_id, expected) in [
            ("missing", StatusCode::NOT_FOUND),
            ("corrupt", StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::get(format!("/v1/artifacts/{artifact_id}/content"))
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_json_error(response, expected).await;
        }
    }

    #[tokio::test]
    async fn context_manifest_route_is_authenticated_ordered_and_withholds_content() {
        let (app, token) = app();
        let unauthorized = app
            .clone()
            .oneshot(
                Request::get("/v1/context-manifests/manifest-1")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_json_error(unauthorized, StatusCode::UNAUTHORIZED).await;

        let response = app
            .clone()
            .oneshot(
                Request::get("/v1/context-manifests/manifest-1")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("context manifest body");
        let evidence: ContextManifestEvidenceResponse =
            serde_json::from_slice(&body).expect("context manifest evidence");
        assert_eq!(evidence.manifest_id, "manifest-1");
        assert_eq!(evidence.items.len(), 3);
        assert_eq!(evidence.items[0].ordinal, 0);
        assert_eq!(
            evidence.items[0].content.as_deref(),
            Some("included content")
        );

        let value: serde_json::Value =
            serde_json::from_slice(&body).expect("context manifest JSON");
        for ordinal in [1, 2] {
            assert!(value["items"][ordinal].get("content").is_none());
            assert!(value["items"][ordinal].get("contentArtifactId").is_none());
        }
        assert!(!String::from_utf8_lossy(&body).contains("relativePath"));

        let missing = app
            .oneshot(
                Request::get("/v1/context-manifests/missing")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_json_error(missing, StatusCode::NOT_FOUND).await;

        for identity in [
            AuthenticatedIdentity {
                principal_id: "wrong-principal".to_owned(),
                channel_binding_id: "binding".to_owned(),
            },
            AuthenticatedIdentity {
                principal_id: "principal".to_owned(),
                channel_binding_id: "wrong-binding".to_owned(),
            },
        ] {
            let auth = ApiAuth::new([9; 32], identity);
            let token = auth.encoded_token();
            let app = router(&ApiConfig::default(), auth, Arc::new(FakeBackend));
            let response = app
                .oneshot(
                    Request::get("/v1/context-manifests/manifest-1")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_json_error(response, StatusCode::NOT_FOUND).await;
        }
    }

    #[tokio::test]
    async fn cancellation_command_has_a_strict_bounded_schema_and_durable_receipt() {
        let (app, token) = app();
        let valid = serde_json::json!({
            "apiVersion": API_VERSION,
            "idempotencyKey": "cancel-delivery-1",
            "reason": "user requested cancellation",
        });
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/tasks/task-1/cancel")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(valid.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096)
            .await
            .expect("cancellation body");
        let receipt =
            serde_json::from_slice::<TaskCancellationReceipt>(&body).expect("cancellation receipt");
        assert_eq!(receipt.api_version, API_VERSION);
        assert_eq!(receipt.task_id, "task-1");
        assert_eq!(receipt.cursor, TimelineCursor(8));
        assert!(!receipt.duplicate);

        let invalid_requests = [
            serde_json::json!({
                "apiVersion": API_VERSION,
                "reason": "missing idempotency key",
            }),
            serde_json::json!({
                "apiVersion": API_VERSION,
                "idempotencyKey": "cancel-delivery-2",
                "reason": "unknown field must fail",
                "unexpected": true,
            }),
            serde_json::json!({
                "apiVersion": "v2",
                "idempotencyKey": "cancel-delivery-3",
                "reason": "unsupported version",
            }),
            serde_json::json!({
                "apiVersion": API_VERSION,
                "idempotencyKey": "cancel-delivery-4",
                "reason": "   ",
            }),
            serde_json::json!({
                "apiVersion": API_VERSION,
                "idempotencyKey": "x".repeat(257),
                "reason": "oversized key",
            }),
            serde_json::json!({
                "apiVersion": API_VERSION,
                "idempotencyKey": "cancel-delivery-5",
                "reason": "x".repeat(1025),
            }),
        ];
        for body in invalid_requests {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/v1/tasks/task-1/cancel")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body.to_string()))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_json_error(response, StatusCode::BAD_REQUEST).await;
        }
    }

    #[tokio::test]
    async fn unexpected_browser_origin_fails_closed() {
        let (app, token) = app();
        let response = app
            .oneshot(
                Request::post("/v1/sessions")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::ORIGIN, "https://attacker.example")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!("{{\"apiVersion\":\"{API_VERSION}\"}}")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn transcript_search_rejects_missing_empty_untrimmed_and_unbounded_queries() {
        let (app, token) = app();
        for target in [
            "/v1/sessions/search",
            "/v1/sessions/search?query=&limit=20",
            "/v1/sessions/search?query=%20marker&limit=20",
            "/v1/sessions/search?query=marker&limit=0",
            "/v1/sessions/search?query=marker&limit=101",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::get(target)
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_json_error(response, StatusCode::BAD_REQUEST).await;
        }
    }

    #[tokio::test]
    async fn health_and_fallback_routes_remain_authenticated() {
        let (app, token) = app();
        let health = app
            .clone()
            .oneshot(
                Request::get("/health/live")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert!(health.headers().contains_key("x-request-id"));
        assert_json_error(health, StatusCode::UNAUTHORIZED).await;

        let missing = app
            .oneshot(
                Request::get("/does-not-exist")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_json_error(missing, StatusCode::NOT_FOUND).await;
    }

    #[tokio::test]
    async fn extractor_and_method_failures_use_the_versioned_error_envelope() {
        let (app, token) = app();
        let malformed_json = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{"))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_json_error(malformed_json, StatusCode::BAD_REQUEST).await;

        let malformed_query = app
            .clone()
            .oneshot(
                Request::get("/v1/sessions/session-1/timeline?limit=not-a-number")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_json_error(malformed_query, StatusCode::BAD_REQUEST).await;

        let wrong_method = app
            .oneshot(
                Request::delete("/v1/sessions")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_json_error(wrong_method, StatusCode::METHOD_NOT_ALLOWED).await;
    }

    #[tokio::test]
    async fn oversized_json_uses_the_versioned_payload_too_large_error() {
        let (app, token) = app();
        let response = app
            .oneshot(
                Request::post("/v1/sessions")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(vec![b'x'; 1024 * 1024 + 1]))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_json_error(response, StatusCode::PAYLOAD_TOO_LARGE).await;
    }

    #[tokio::test]
    async fn shutdown_signal_terminates_an_idle_sse_subscription() {
        let auth = ApiAuth::new(
            [7; 32],
            AuthenticatedIdentity {
                principal_id: "principal".to_owned(),
                channel_binding_id: "binding".to_owned(),
            },
        );
        let token = auth.encoded_token();
        let (shutdown, receiver) = tokio::sync::watch::channel(false);
        let app =
            router_with_shutdown(&ApiConfig::default(), auth, Arc::new(FakeBackend), receiver);
        let response = app
            .oneshot(
                Request::get("/v1/sessions/session-1/events")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::ACCEPT, "text/event-stream")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = tokio::spawn(to_bytes(response.into_body(), 4096));
        shutdown.send(true).expect("signal shutdown");
        tokio::time::timeout(std::time::Duration::from_secs(1), body)
            .await
            .expect("SSE body should close promptly")
            .expect("body task should complete")
            .expect("body should close without error");
    }

    #[test]
    fn non_loopback_configuration_is_rejected() {
        assert!(
            super::ApiConfig::new(
                "0.0.0.0:3000".parse().expect("address"),
                1024,
                vec![],
                1,
                1,
                std::time::Duration::from_millis(10),
            )
            .is_err()
        );
    }
}
