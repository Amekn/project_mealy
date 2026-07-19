use crate::{
    ContextEpoch, ContextManifest, ContextMemoryEvidence, ModelUsage, NormalizedMessage,
    OwnershipContext, ProviderCapabilities, ProviderErrorClass, ProviderOutput, ProviderRequest,
    ReadToolDescriptor,
};
use mealy_domain::{
    ArtifactId, AttemptId, ChannelBindingId, CompactionId, CorrelationId, EventId, LeaseFence,
    MessageId, PrincipalId, RunId, SessionId, TaskId, ToolCallId, TurnId,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// Maximum non-authoritative streamed text bytes retained for one provider attempt.
pub const MAXIMUM_MODEL_PROGRESS_BYTES: u64 = 64 * 1024;
/// Maximum durable progress events retained for one provider attempt.
pub const MAXIMUM_MODEL_PROGRESS_EVENTS: u64 = 256;
/// Maximum UTF-8 bytes in one durable progress delta event.
pub const MAXIMUM_MODEL_PROGRESS_DELTA_BYTES: usize = 4 * 1024;

/// Durable next step in the bounded Phase 2 agent loop.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentNextAction {
    /// Build the next immutable context projection.
    CompileContext,
    /// Invoke the provider for the current prepared attempt.
    DispatchModel,
    /// Interpret a previously committed normalized provider result.
    ConsumeModelResult,
    /// Invoke the one granted read-only tool.
    DispatchReadTool,
    /// Recompile context after the committed tool observation.
    CompileAfterTool,
    /// Atomically publish the committed final response.
    CommitFinal,
    /// No further worker mutation is permitted.
    Terminal,
}

impl AgentNextAction {
    /// Stable storage spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompileContext => "compile_context",
            Self::DispatchModel => "dispatch_model",
            Self::ConsumeModelResult => "consume_model_result",
            Self::DispatchReadTool => "dispatch_read_tool",
            Self::CompileAfterTool => "compile_after_tool",
            Self::CommitFinal => "commit_final",
            Self::Terminal => "terminal",
        }
    }
}

/// Effective bounded execution policy copied onto every run.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentLoopLimits {
    /// Maximum provider attempts.
    pub maximum_model_calls: u64,
    /// Maximum read-only tool calls.
    pub maximum_tool_calls: u64,
    /// Maximum classified retries.
    pub maximum_retries: u64,
    /// Maximum child runs this run may delegate.
    #[serde(default)]
    pub maximum_delegated_runs: u64,
    /// Aggregate normalized input-token ceiling.
    pub maximum_input_tokens: u64,
    /// Aggregate normalized output-token ceiling.
    pub maximum_output_tokens: u64,
    /// Aggregate provider-neutral cost ceiling.
    pub maximum_cost_microunits: u64,
    /// Aggregate durable output bytes.
    pub maximum_output_bytes: u64,
    /// Total wall-clock deadline from first execution prepare.
    pub maximum_wall_time_ms: u64,
    /// Per-provider-call deadline.
    pub provider_timeout_ms: u64,
    /// Per-tool-call deadline.
    pub tool_timeout_ms: u64,
    /// Content at or below this threshold stays inline.
    pub inline_output_bytes: u64,
    /// Hard bound accepted by the artifact store.
    pub maximum_artifact_bytes: u64,
}

impl Default for AgentLoopLimits {
    fn default() -> Self {
        Self {
            maximum_model_calls: 4,
            maximum_tool_calls: 2,
            maximum_retries: 1,
            maximum_delegated_runs: 2,
            maximum_input_tokens: 32_768,
            maximum_output_tokens: 4_096,
            maximum_cost_microunits: 1_000_000,
            maximum_output_bytes: 4 * 1024 * 1024,
            maximum_wall_time_ms: 120_000,
            provider_timeout_ms: 30_000,
            tool_timeout_ms: 5_000,
            inline_output_bytes: 1_024,
            maximum_artifact_bytes: 4 * 1024 * 1024,
        }
    }
}

impl AgentLoopLimits {
    /// Validates that all required bounds are nonzero and internally ordered.
    ///
    /// # Errors
    ///
    /// Returns [`AgentUseCaseError::InvalidLimits`] for an unenforceable policy.
    pub fn validate(self) -> Result<Self, AgentUseCaseError> {
        if self.maximum_model_calls == 0
            || self.maximum_input_tokens == 0
            || self.maximum_output_tokens == 0
            || self.maximum_output_bytes == 0
            || self.maximum_wall_time_ms == 0
            || self.provider_timeout_ms == 0
            || self.tool_timeout_ms == 0
            || self.inline_output_bytes == 0
            || self.maximum_artifact_bytes < self.inline_output_bytes
            || self.maximum_output_bytes < self.maximum_artifact_bytes
            || self.provider_timeout_ms > self.maximum_wall_time_ms
            || self.tool_timeout_ms > self.maximum_wall_time_ms
        {
            return Err(AgentUseCaseError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Current structured usage and reservation projection.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentBudgetUsage {
    /// Completed or charged-unknown provider calls.
    pub used_model_calls: u64,
    /// Active provider-call reservations.
    pub reserved_model_calls: u64,
    /// Prepared read-tool calls.
    pub used_tool_calls: u64,
    /// Active read-tool reservations.
    pub reserved_tool_calls: u64,
    /// Child runs whose terminal result has been accepted.
    pub used_delegated_runs: u64,
    /// Child-run slots reserved by durable delegation contracts.
    pub reserved_delegated_runs: u64,
    /// Classified retries.
    pub used_retries: u64,
    /// Recorded provider input tokens.
    pub used_input_tokens: u64,
    /// Reserved normalized input tokens.
    pub reserved_input_tokens: u64,
    /// Recorded provider output tokens.
    pub used_output_tokens: u64,
    /// Reserved normalized output tokens.
    pub reserved_output_tokens: u64,
    /// Recorded provider-neutral cost.
    pub used_cost_microunits: u64,
    /// Reserved provider-neutral cost.
    pub reserved_cost_microunits: u64,
    /// Recorded provider/tool output bytes.
    pub used_output_bytes: u64,
    /// Reserved output bytes.
    pub reserved_output_bytes: u64,
}

/// Provider-neutral material from durable canonical state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentContextSource {
    /// Logical source kind.
    pub source_type: String,
    /// Safe logical locator.
    pub source_locator: String,
    /// Digest of the exact canonical source before provider rendering.
    pub source_content_digest: String,
    /// Provider-neutral message.
    pub message: NormalizedMessage,
    /// Sensitivity used by the deterministic compiler.
    pub sensitivity: String,
    /// Original artifact backing this source, when applicable.
    pub content_artifact_id: Option<ArtifactId>,
    /// Exact active memory revision and immutable citations for untrusted retrieved evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_evidence: Option<ContextMemoryEvidence>,
    /// Exact derived compaction represented by this source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compaction_id: Option<CompactionId>,
}

/// Fenced run state loaded at a safe loop boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRunSnapshot {
    /// Claimed run.
    pub run_id: RunId,
    /// Immutable execution role (`assistant`, `delegate`, or `validator`).
    pub agent_role: String,
    /// User-visible task.
    pub task_id: TaskId,
    /// Session mutation turn.
    pub turn_id: TurnId,
    /// Canonical, delegated, or validation turn classification.
    pub turn_kind: String,
    /// Owning session.
    pub session_id: SessionId,
    /// Owning authenticated principal.
    pub principal_id: PrincipalId,
    /// Owning authenticated local channel binding.
    pub channel_binding_id: ChannelBindingId,
    /// Correlation lineage.
    pub correlation_id: CorrelationId,
    /// Current one-based iteration to compile.
    pub next_iteration: u64,
    /// Next session-scoped context epoch number if policy/profile rotation requires a fresh epoch.
    pub next_context_epoch_number: u64,
    /// Durable next action.
    pub next_action: AgentNextAction,
    /// Effective limits.
    pub limits: AgentLoopLimits,
    /// Immutable maximum authority copied onto this root or delegated run.
    pub capability_ceiling: mealy_domain::CapabilityGrant,
    /// Structured usage.
    pub usage: AgentBudgetUsage,
    /// Existing active epoch, if already initialized.
    pub context_epoch: Option<ContextEpoch>,
    /// Ordered, authorized context sources.
    pub context_sources: Vec<AgentContextSource>,
    /// Current prepared/completed attempt.
    pub current_attempt_id: Option<AttemptId>,
    /// Committed normalized result for the current completed attempt.
    pub current_model_output: Option<ProviderOutput>,
    /// Current prepared/completed tool call.
    pub current_tool_call_id: Option<ToolCallId>,
    /// Stable identity of the current prepared read tool.
    pub current_read_tool_id: Option<String>,
    /// Committed normalized arguments for the current tool call.
    pub current_tool_arguments: Option<serde_json::Value>,
    /// Whether cancellation has been durably requested.
    pub cancellation_requested: bool,
}

/// Content-addressed artifact evidence already committed outside `SQLite`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentArtifactCommit {
    /// Logical, owner-scoped artifact metadata ID.
    pub artifact_id: ArtifactId,
    /// Hash algorithm, currently `sha256`.
    pub algorithm: String,
    /// Lowercase content digest.
    pub digest: String,
    /// Exact blob size.
    pub size_bytes: u64,
    /// Store-generated relative path, never a user path.
    pub relative_path: String,
    /// Blob commit time.
    pub committed_at: SystemTime,
    /// Declared media type.
    pub media_type: String,
    /// Sensitivity classification.
    pub sensitivity: String,
}

/// Atomic prepare of one immutable manifest and provider attempt.
#[derive(Clone, Debug, PartialEq)]
pub struct PrepareModelAttemptCommit {
    /// Exact current lease ownership.
    pub fence: LeaseFence,
    /// Create this epoch atomically on the first iteration.
    pub context_epoch: Option<ContextEpoch>,
    /// Exact immutable manifest.
    pub manifest: ContextManifest,
    /// Durable attempt ID allocated before dispatch.
    pub attempt_id: AttemptId,
    /// Normalized request persisted before provider invocation.
    pub request: ProviderRequest,
    /// Immutable provider capability snapshot.
    pub capabilities: ProviderCapabilities,
    /// Stable owner-inspectable provider routing decision.
    pub routing_decision: serde_json::Value,
    /// Digest of normalized capabilities.
    pub capability_digest: String,
    /// Digest of the normalized request.
    pub request_digest: String,
    /// Maximum cost reserved before dispatch.
    pub reserved_cost_microunits: u64,
    /// Maximum response bytes reserved before dispatch.
    pub reserved_output_bytes: u64,
    /// Effective policy used to initialize structured budget state.
    pub limits: AgentLoopLimits,
    /// `context.epoch.created`, when an epoch is present.
    pub epoch_event_id: Option<EventId>,
    /// `context.manifest.created` event.
    pub manifest_event_id: EventId,
    /// `model.attempt.prepared` event.
    pub attempt_event_id: EventId,
    /// Loop-checkpoint event.
    pub checkpoint_event_id: EventId,
    /// Commit time.
    pub prepared_at: SystemTime,
    /// Absolute attempt deadline.
    pub deadline_at: SystemTime,
}

/// Marks a prepared provider attempt as externally dispatching.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchModelAttemptCommit {
    /// Exact current lease ownership.
    pub fence: LeaseFence,
    /// Prepared attempt.
    pub attempt_id: AttemptId,
    /// Durable dispatch event.
    pub event_id: EventId,
    /// Commit time immediately before invocation.
    pub dispatched_at: SystemTime,
}

/// Durable outcome of crossing the provider dispatch boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelDispatchReceipt {
    /// The attempt became externally dispatchable before its immutable deadline.
    Dispatched,
    /// The undispatched preparation expired and was atomically retired without charging usage.
    DeadlineElapsed,
}

/// Appends one bounded non-authoritative provider text delta while an attempt is dispatching.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordModelProgressCommit {
    /// Exact current lease ownership.
    pub fence: LeaseFence,
    /// Dispatching attempt.
    pub attempt_id: AttemptId,
    /// Zero-based attempt-local progress sequence.
    pub progress_sequence: u64,
    /// Exact coalesced UTF-8 delta.
    pub delta: String,
    /// Cumulative UTF-8 bytes after this delta.
    pub cumulative_bytes: u64,
    /// Durable non-authoritative progress event.
    pub event_id: EventId,
    /// Observation time.
    pub recorded_at: SystemTime,
}

/// Records the normalized provider terminal result before any dependent tool runs.
#[derive(Clone, Debug, PartialEq)]
pub struct RecordModelResultCommit {
    /// Exact current lease ownership.
    pub fence: LeaseFence,
    /// Dispatching attempt.
    pub attempt_id: AttemptId,
    /// Normalized terminal output.
    pub output: ProviderOutput,
    /// Canonical bounded response JSON.
    pub response_json: String,
    /// Digest of canonical response JSON.
    pub response_digest: String,
    /// Optional committed response artifact.
    pub response_artifact: Option<AgentArtifactCommit>,
    /// `artifact.committed` event when a response artifact is linked.
    pub artifact_event_id: Option<EventId>,
    /// Durable completion event.
    pub event_id: EventId,
    /// Loop-checkpoint event.
    pub checkpoint_event_id: EventId,
    /// Completion time.
    pub completed_at: SystemTime,
}

/// Records one classified provider failure and optionally schedules a fenced retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordModelFailureCommit {
    /// Exact current lease ownership.
    pub fence: LeaseFence,
    /// Dispatching attempt that failed.
    pub attempt_id: AttemptId,
    /// Stable normalized failure class.
    pub error_class: ProviderErrorClass,
    /// Redacted bounded diagnostic message.
    pub error_message: String,
    /// Whether another attempt under identical trust/tool policy may succeed.
    pub retryable: bool,
    /// Persisted delay before a retry becomes scheduler-eligible.
    pub retry_delay: Duration,
    /// Durable attempt-failure event.
    pub attempt_event_id: EventId,
    /// Durable loop-checkpoint event when a retry is scheduled.
    pub checkpoint_event_id: EventId,
    /// Durable lease-release/run-requeue event when a retry is scheduled.
    pub lease_event_id: EventId,
    /// Completion time.
    pub completed_at: SystemTime,
}

/// Durable result of classifying one failed provider dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelFailureReceipt {
    /// Whether the run was atomically requeued for another provider attempt.
    pub retry_scheduled: bool,
    /// Earliest scheduler eligibility when a retry was scheduled.
    pub retry_at: Option<SystemTime>,
}

/// Prepares one schema-validated invocation derived from a committed model result.
#[derive(Clone, Debug, PartialEq)]
pub struct PrepareReadToolCommit {
    /// Exact current lease ownership.
    pub fence: LeaseFence,
    /// Model attempt that proposed the invocation.
    pub model_attempt_id: AttemptId,
    /// Distinct attempt identity for tool execution.
    pub tool_attempt_id: AttemptId,
    /// Normalized tool-call identity.
    pub tool_call_id: ToolCallId,
    /// Bound descriptor.
    pub descriptor: ReadToolDescriptor,
    /// Schema-validated normalized arguments.
    pub arguments: serde_json::Value,
    /// Digest of normalized arguments.
    pub arguments_digest: String,
    /// Durable prepare event.
    pub event_id: EventId,
    /// Commit time.
    pub prepared_at: SystemTime,
}

/// Marks a prepared read tool as externally running.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchReadToolCommit {
    /// Exact current lease ownership.
    pub fence: LeaseFence,
    /// Prepared call.
    pub tool_call_id: ToolCallId,
    /// Durable dispatch event.
    pub event_id: EventId,
    /// Commit time immediately before invocation.
    pub started_at: SystemTime,
}

/// Records one bounded read-tool result and advances to context recompilation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordReadToolResultCommit {
    /// Exact current lease ownership.
    pub fence: LeaseFence,
    /// Running call.
    pub tool_call_id: ToolCallId,
    /// Bounded inline UTF-8 output when no artifact is needed.
    pub output_inline: Option<String>,
    /// Committed artifact for oversized output.
    pub output_artifact: Option<AgentArtifactCommit>,
    /// `artifact.committed` event when an output artifact is linked.
    pub artifact_event_id: Option<EventId>,
    /// Digest of exact output bytes.
    pub output_digest: String,
    /// Exact output byte count.
    pub output_size_bytes: u64,
    /// Declared media type.
    pub output_media_type: String,
    /// Safe logical source locator.
    pub source_locator: String,
    /// Durable success event.
    pub event_id: EventId,
    /// Loop-checkpoint event.
    pub checkpoint_event_id: EventId,
    /// Completion time.
    pub completed_at: SystemTime,
}

/// Idempotent authenticated cancellation command committed before cooperative notification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestTaskCancellationCommit {
    /// Authenticated owner and local channel binding.
    pub ownership: OwnershipContext,
    /// Task to cancel.
    pub task_id: TaskId,
    /// Stable command-delivery key.
    pub idempotency_key: String,
    /// Bounded owner-visible reason.
    pub reason: String,
    /// Event reserved for a new command.
    pub event_id: EventId,
    /// Run event used when cancellation must unpark waiting work.
    pub run_event_id: EventId,
    /// Approval event used when cancellation revokes an undispatched pending effect.
    pub approval_event_id: EventId,
    /// Effect event used when cancellation denies an undispatched effect.
    pub effect_event_id: EventId,
    /// Commit time.
    pub requested_at: SystemTime,
}

/// Canonical receipt for a new or exact duplicate cancellation command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskCancellationCommitReceipt {
    /// Cancelled task.
    pub task_id: TaskId,
    /// Revision committed by the original command.
    pub revision: u64,
    /// Original durable event.
    pub event_id: EventId,
    /// Original timeline cursor.
    pub cursor: u64,
    /// Whether this is an exact duplicate delivery.
    pub duplicate: bool,
}

/// Authenticated owner task-control transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskControlAction {
    /// Fence active work and hold the task outside scheduler admission.
    Pause,
    /// Restore the task status implied by its durable run boundary.
    Resume,
}

/// Exact optimistic-concurrency task pause or resume command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskControlCommit {
    /// Authenticated owner and channel binding.
    pub ownership: OwnershipContext,
    /// Task to control.
    pub task_id: TaskId,
    /// Exact task revision observed by the owner.
    pub expected_revision: u64,
    /// Requested transition.
    pub action: TaskControlAction,
    /// Durable task control event.
    pub event_id: EventId,
    /// Event identities reserved if pausing must fence/recover active work.
    pub recovery_event_ids: crate::LeaseRecoveryEventIds,
    /// Command time.
    pub controlled_at: SystemTime,
}

/// Canonical task-control receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskControlCommitReceipt {
    /// Controlled task.
    pub task_id: TaskId,
    /// Stable lifecycle spelling after the transition.
    pub status: String,
    /// New task revision.
    pub revision: u64,
    /// Durable task event.
    pub event_id: EventId,
    /// Global timeline cursor.
    pub cursor: u64,
}

/// Durable final assistant message inserted atomically with run/task/turn completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalMessageCommit {
    /// Message identity.
    pub message_id: MessageId,
    /// Durable `message.assistant.final` journal event.
    pub event_id: EventId,
    /// Model attempt that produced the final answer.
    pub source_attempt_id: AttemptId,
    /// Bounded inline final answer.
    pub content: String,
    /// SHA-256 digest of exact content bytes.
    pub content_digest: String,
    /// Exact UTF-8 byte count.
    pub byte_length: u64,
}

/// Authorized task projection needed by public inspection and replay.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentTaskView {
    /// Task identity.
    pub task_id: TaskId,
    /// Owning run.
    pub run_id: RunId,
    /// Stable lifecycle spelling.
    pub status: String,
    /// Task revision.
    pub revision: u64,
    /// Final answer, when committed.
    pub final_response: Option<String>,
    /// Digest of the final answer.
    pub final_digest: Option<String>,
    /// Structured usage.
    pub usage: AgentBudgetUsage,
    /// Number of durable provider attempts.
    pub model_attempts: u64,
    /// Number of durable read-tool calls.
    pub tool_calls: u64,
}

/// Deterministic report reconstructed exclusively from recorded evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentReplayReport {
    /// Source task.
    pub task_id: TaskId,
    /// Source run.
    pub run_id: RunId,
    /// Fixed replay mode; no live dependency exists on this port.
    pub mode: String,
    /// Whether all required evidence and digests were consistent.
    pub evidence_complete: bool,
    /// Recorded final answer.
    pub final_response: Option<String>,
    /// Recomputed final digest.
    pub final_digest: Option<String>,
    /// Ordered recorded model attempt count.
    pub model_attempts: u64,
    /// Ordered recorded tool-call count.
    pub tool_calls: u64,
    /// Provider calls made by replay, always zero by construction.
    pub live_provider_calls: u64,
    /// Tool calls made by replay, always zero by construction.
    pub live_tool_calls: u64,
}

/// Storage failures for fenced agent-loop transitions and authorized evidence reads.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AgentStoreError {
    /// Lease ownership or deadline no longer permits mutation.
    #[error("agent lease fence is stale")]
    StaleFence,
    /// Resource does not exist or is deliberately hidden from this owner.
    #[error("agent resource was not found")]
    NotFound,
    /// Durable cancellation prevents another external dispatch.
    #[error("agent run is cancelled")]
    Cancelled,
    /// A configured budget cannot reserve or settle another operation.
    #[error("agent run budget is exhausted: {0}")]
    BudgetExceeded(String),
    /// Concurrent canonical state changed.
    #[error("agent execution conflicted with canonical state")]
    Conflict,
    /// Persistence dependency failed.
    #[error("agent execution store is unavailable: {0}")]
    Unavailable(String),
    /// Stored evidence violates an invariant.
    #[error("agent execution invariant violation: {0}")]
    InvariantViolation(String),
}

/// Atomic storage boundary for the provider/read-tool loop.
pub trait AgentExecutionStore {
    /// Loads the current run and validates exact active, unexpired ownership.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for stale ownership, missing state, or persistence failure.
    fn load_agent_run(
        &self,
        fence: LeaseFence,
        observed_at: SystemTime,
    ) -> Result<AgentRunSnapshot, AgentStoreError>;

    /// Commits context, a provider attempt, and budget reservation before dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for stale ownership, conflict, budget, or persistence failure.
    fn prepare_model_attempt(
        &mut self,
        commit: PrepareModelAttemptCommit,
    ) -> Result<(), AgentStoreError>;

    /// Durably marks an attempt immediately before invoking the provider, or atomically retires
    /// an undispatched preparation whose immutable deadline has elapsed without charging usage.
    ///
    /// # Errors
    ///
    /// Returns the exact dispatch outcome, or [`AgentStoreError`] for stale ownership, unrelated
    /// canonical conflict, or persistence failure.
    fn dispatch_model_attempt(
        &mut self,
        commit: DispatchModelAttemptCommit,
    ) -> Result<ModelDispatchReceipt, AgentStoreError>;

    /// Appends one bounded non-authoritative text delta without settling the provider attempt.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for stale ownership, cancellation, invalid sequence/bounds, or
    /// persistence failure.
    fn record_model_progress(
        &mut self,
        commit: RecordModelProgressCommit,
    ) -> Result<(), AgentStoreError>;

    /// Records normalized provider output and usage before dependent execution.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for stale ownership, invalid usage, or persistence failure.
    fn record_model_result(
        &mut self,
        commit: RecordModelResultCommit,
    ) -> Result<(), AgentStoreError>;

    /// Records a provider failure, settles its reservation, and atomically requeues a bounded
    /// retry after a persisted delay when policy and budget allow.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for stale ownership, invalid error evidence, budget conflict,
    /// or persistence failure.
    fn record_model_failure(
        &mut self,
        commit: RecordModelFailureCommit,
    ) -> Result<ModelFailureReceipt, AgentStoreError>;

    /// Commits a validated read-tool call before dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for stale ownership, budget, conflict, or persistence failure.
    fn prepare_read_tool(&mut self, commit: PrepareReadToolCommit) -> Result<(), AgentStoreError>;

    /// Durably marks a tool call immediately before trusted execution.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for stale ownership, conflict, or persistence failure.
    fn dispatch_read_tool(&mut self, commit: DispatchReadToolCommit)
    -> Result<(), AgentStoreError>;

    /// Records exact tool evidence before another provider attempt.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for stale ownership, invalid evidence, or persistence failure.
    fn record_read_tool_result(
        &mut self,
        commit: RecordReadToolResultCommit,
    ) -> Result<(), AgentStoreError>;

    /// Durably requests cooperative cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for authorization, idempotency, conflict, or persistence failure.
    fn request_task_cancellation(
        &mut self,
        commit: RequestTaskCancellationCommit,
    ) -> Result<TaskCancellationCommitReceipt, AgentStoreError>;

    /// Atomically pauses or resumes an authorized task at an exact revision.
    ///
    /// Pausing a running task first recovers and fences its active lease in the same transaction,
    /// so a stale provider/tool result cannot commit after the pause acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for authorization, stale revision, terminal state, or recovery
    /// failure.
    fn control_task(
        &mut self,
        commit: TaskControlCommit,
    ) -> Result<TaskControlCommitReceipt, AgentStoreError>;
}

/// Read-only evidence port. It intentionally has no provider or tool dependency.
pub trait AgentEvidenceStore {
    /// Returns an authorized task projection.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] when the resource is hidden, absent, or unavailable.
    fn agent_task(
        &self,
        ownership: OwnershipContext,
        task_id: TaskId,
    ) -> Result<AgentTaskView, AgentStoreError>;

    /// Reconstructs a report using durable model/tool/message evidence only.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] when the resource is hidden, absent, or evidence cannot be read.
    fn replay_agent_task(
        &self,
        ownership: OwnershipContext,
        task_id: TaskId,
    ) -> Result<AgentReplayReport, AgentStoreError>;
}

/// Application-level loop failures.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AgentUseCaseError {
    /// Effective limits are zero or internally inconsistent.
    #[error("agent loop limits are invalid")]
    InvalidLimits,
    /// Content representation violated an inline/artifact invariant.
    #[error("agent output must have exactly one valid content representation")]
    InvalidOutputRepresentation,
    /// A timestamp or duration cannot be represented.
    #[error("agent deadline cannot be represented")]
    DeadlineOverflow,
    /// Provider retry delay bounds or ordinal are invalid.
    #[error("provider retry delay is invalid")]
    InvalidRetryDelay,
    /// Persistence failed.
    #[error(transparent)]
    Store(#[from] AgentStoreError),
}

/// Computes an absolute bounded deadline.
///
/// # Errors
///
/// Returns [`AgentUseCaseError::DeadlineOverflow`] when time cannot be represented.
pub fn bounded_deadline(now: SystemTime, timeout_ms: u64) -> Result<SystemTime, AgentUseCaseError> {
    now.checked_add(Duration::from_millis(timeout_ms))
        .ok_or(AgentUseCaseError::DeadlineOverflow)
}

/// Computes bounded exponential provider retry delay with stable per-attempt jitter.
///
/// # Errors
///
/// Returns [`AgentUseCaseError::InvalidRetryDelay`] for a zero ordinal, zero/inverted bound, or a
/// maximum above one hour.
pub fn provider_retry_delay(
    attempt_id: AttemptId,
    retry_ordinal: u64,
    base: Duration,
    maximum: Duration,
) -> Result<Duration, AgentUseCaseError> {
    if retry_ordinal == 0
        || base < Duration::from_millis(1)
        || maximum < base
        || maximum > Duration::from_hours(1)
    {
        return Err(AgentUseCaseError::InvalidRetryDelay);
    }
    let exponent = retry_ordinal.saturating_sub(1).min(31);
    let exponential_ms = base
        .as_millis()
        .saturating_mul(1_u128 << exponent)
        .min(maximum.as_millis());
    let jitter_window_ms = exponential_ms / 4;
    let seed = attempt_id.as_uuid().as_u128()
        ^ u128::from(retry_ordinal).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let jitter_ms = if jitter_window_ms == 0 {
        0
    } else {
        seed % (jitter_window_ms + 1)
    };
    let delay_ms = exponential_ms
        .saturating_add(jitter_ms)
        .min(maximum.as_millis());
    u64::try_from(delay_ms)
        .map(Duration::from_millis)
        .map_err(|_| AgentUseCaseError::InvalidRetryDelay)
}

/// Ensures a tool result uses exactly one inline-or-artifact representation.
///
/// # Errors
///
/// Returns [`AgentUseCaseError::InvalidOutputRepresentation`] for invalid representation or size.
pub fn validate_tool_result(commit: &RecordReadToolResultCommit) -> Result<(), AgentUseCaseError> {
    if commit.output_inline.is_some() == commit.output_artifact.is_some() {
        return Err(AgentUseCaseError::InvalidOutputRepresentation);
    }
    let represented_size = commit.output_inline.as_ref().map_or_else(
        || commit.output_artifact.as_ref().map(|item| item.size_bytes),
        |text| Some(u64::try_from(text.len()).unwrap_or(u64::MAX)),
    );
    if represented_size != Some(commit.output_size_bytes) {
        return Err(AgentUseCaseError::InvalidOutputRepresentation);
    }
    Ok(())
}

/// Adds usage values with checked arithmetic for adapter-side validation.
///
/// # Errors
///
/// Returns [`AgentStoreError::InvariantViolation`] if counters overflow.
pub fn checked_usage_total(
    left: ModelUsage,
    right: ModelUsage,
) -> Result<ModelUsage, AgentStoreError> {
    Ok(ModelUsage {
        input_tokens: left
            .input_tokens
            .checked_add(right.input_tokens)
            .ok_or_else(|| {
                AgentStoreError::InvariantViolation("input token usage overflow".to_owned())
            })?,
        output_tokens: left
            .output_tokens
            .checked_add(right.output_tokens)
            .ok_or_else(|| {
                AgentStoreError::InvariantViolation("output token usage overflow".to_owned())
            })?,
        total_tokens: left
            .total_tokens
            .checked_add(right.total_tokens)
            .ok_or_else(|| {
                AgentStoreError::InvariantViolation("total token usage overflow".to_owned())
            })?,
        cost_microunits: left
            .cost_microunits
            .checked_add(right.cost_microunits)
            .ok_or_else(|| AgentStoreError::InvariantViolation("cost usage overflow".to_owned()))?,
    })
}

#[cfg(test)]
mod tests {
    use super::{AgentLoopLimits, AgentUseCaseError, provider_retry_delay};
    use mealy_domain::AttemptId;
    use std::{str::FromStr, time::Duration};

    #[test]
    fn default_loop_limits_are_enforceable() {
        let defaults = AgentLoopLimits::default();
        assert_eq!(defaults.provider_timeout_ms, 30_000);
        assert_eq!(defaults.validate(), Ok(defaults));
    }

    #[test]
    fn artifact_bound_cannot_be_smaller_than_inline_threshold() {
        let limits = AgentLoopLimits {
            inline_output_bytes: 2,
            maximum_artifact_bytes: 1,
            ..AgentLoopLimits::default()
        };
        assert_eq!(limits.validate(), Err(AgentUseCaseError::InvalidLimits));
    }

    #[test]
    fn provider_retry_delay_is_deterministic_exponential_and_bounded() {
        let attempt_id =
            AttemptId::from_str("018f4f8f-0000-7000-8000-000000000001").expect("attempt ID");
        let base = Duration::from_millis(250);
        let maximum = Duration::from_secs(5);
        let first = provider_retry_delay(attempt_id, 1, base, maximum).expect("first retry");
        let second = provider_retry_delay(attempt_id, 2, base, maximum).expect("second retry");
        assert!((base..=Duration::from_millis(312)).contains(&first));
        assert!((Duration::from_millis(500)..=Duration::from_millis(625)).contains(&second));
        assert!(second > first);
        assert_eq!(
            provider_retry_delay(attempt_id, 2, base, maximum),
            Ok(second)
        );
        assert_eq!(
            provider_retry_delay(attempt_id, 0, base, maximum),
            Err(AgentUseCaseError::InvalidRetryDelay)
        );
        assert_eq!(
            provider_retry_delay(attempt_id, 1, Duration::ZERO, Duration::from_secs(1)),
            Err(AgentUseCaseError::InvalidRetryDelay)
        );
    }
}
