//! Versioned, framework-neutral transport data types for Mealy clients.

use serde::{Deserialize, Serialize};

/// Initial public API version.
pub const API_VERSION: &str = "v1";

/// OS-user-private connection descriptor shared by `mealyd` and `mealyctl`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalConnectionInfo {
    /// Semantic descriptor version.
    pub api_version: String,
    /// Loopback HTTP origin, such as `http://127.0.0.1:37281`.
    pub base_url: String,
    /// Base64url bearer credential. The containing file must be owner-only.
    pub bearer_token: String,
    /// Authenticated local principal ID.
    pub principal_id: String,
    /// Verified local channel/device binding ID.
    pub channel_binding_id: String,
}

/// Opaque durable position used to resume a timeline stream.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TimelineCursor(pub u64);

/// Transport spelling of input-delivery behavior.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    /// Promote after current work in FIFO order.
    Queue,
    /// Attach at the next safe active-run boundary.
    SteerAtBoundary,
    /// Interrupt active work before FIFO promotion.
    InterruptThenQueue,
}

impl From<mealy_domain::DeliveryMode> for DeliveryMode {
    fn from(value: mealy_domain::DeliveryMode) -> Self {
        match value {
            mealy_domain::DeliveryMode::Queue => Self::Queue,
            mealy_domain::DeliveryMode::SteerAtBoundary => Self::SteerAtBoundary,
            mealy_domain::DeliveryMode::InterruptThenQueue => Self::InterruptThenQueue,
        }
    }
}

impl From<DeliveryMode> for mealy_domain::DeliveryMode {
    fn from(value: DeliveryMode) -> Self {
        match value {
            DeliveryMode::Queue => Self::Queue,
            DeliveryMode::SteerAtBoundary => Self::SteerAtBoundary,
            DeliveryMode::InterruptThenQueue => Self::InterruptThenQueue,
        }
    }
}

/// Current transport projection of a task lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// Accepted but not currently leased.
    Queued,
    /// Executing under a current lease.
    Running,
    /// Parked at a durable wait boundary.
    Waiting,
    /// Explicitly paused.
    Paused,
    /// Cancellation is draining.
    Cancelling,
    /// Successfully completed.
    Succeeded,
    /// Terminal failure.
    Failed,
    /// Terminal cancellation.
    Cancelled,
}

impl From<mealy_domain::TaskStatus> for TaskStatus {
    fn from(value: mealy_domain::TaskStatus) -> Self {
        match value {
            mealy_domain::TaskStatus::Queued => Self::Queued,
            mealy_domain::TaskStatus::Running => Self::Running,
            mealy_domain::TaskStatus::Waiting => Self::Waiting,
            mealy_domain::TaskStatus::Paused => Self::Paused,
            mealy_domain::TaskStatus::Cancelling => Self::Cancelling,
            mealy_domain::TaskStatus::Succeeded => Self::Succeeded,
            mealy_domain::TaskStatus::Failed => Self::Failed,
            mealy_domain::TaskStatus::Cancelled => Self::Cancelled,
        }
    }
}

/// Authenticated request to create a session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionRequest {
    /// Requested semantic API version.
    pub api_version: String,
}

/// Committed session-creation response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Opaque session ID.
    pub session_id: String,
}

/// Authenticated, idempotent request to submit one input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitInputRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Stable channel delivery key.
    pub idempotency_key: String,
    /// Durable ordering behavior.
    pub delivery_mode: DeliveryMode,
    /// Bounded UTF-8 content.
    pub content: String,
}

/// Durable admission response returned only after commit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputAdmissionResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Opaque session ID.
    pub session_id: String,
    /// Opaque inbox-entry ID.
    pub inbox_entry_id: String,
    /// Positive session-scoped FIFO sequence.
    pub inbox_sequence: u64,
    /// Delivery behavior bound to the idempotency key.
    pub delivery_mode: DeliveryMode,
    /// Original acceptance event ID.
    pub event_id: String,
    /// Original acknowledgement outbox ID.
    pub outbox_id: String,
    /// UTC epoch milliseconds.
    pub accepted_at_ms: i64,
    /// Whether this request returned an earlier exact admission.
    pub duplicate: bool,
    /// Highest visible cursor after admission.
    pub cursor: TimelineCursor,
}

/// Current authorized session projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStatusResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Opaque session ID.
    pub session_id: String,
    /// Canonical revision.
    pub revision: u64,
    /// Number of pending durable inputs.
    pub pending_inputs: u64,
    /// Active turn, when present.
    pub active_turn_id: Option<String>,
    /// Latest authorized timeline cursor.
    pub latest_cursor: TimelineCursor,
}

/// One recent session owned by the exact authenticated principal/channel binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummaryResponse {
    /// Opaque session ID accepted by `chat --session-id`.
    pub session_id: String,
    /// Stable lifecycle spelling.
    pub status: String,
    /// Canonical optimistic-concurrency revision.
    pub revision: u64,
    /// Pending durable inputs.
    pub pending_inputs: u64,
    /// Active turn, when present.
    pub active_turn_id: Option<String>,
    /// UTC creation time in epoch milliseconds.
    pub created_at_ms: i64,
    /// UTC latest update time in epoch milliseconds.
    pub updated_at_ms: i64,
}

/// Bounded recent-session discovery response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionsResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Most recently updated exact-binding sessions first.
    pub sessions: Vec<SessionSummaryResponse>,
}

/// One bounded canonical-turn match from exact-binding transcript search.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSearchHitResponse {
    /// Owning session accepted by `chat --session-id`.
    pub session_id: String,
    /// Canonical turn identity.
    pub turn_id: String,
    /// Canonical task identity accepted by task inspection commands.
    pub task_id: String,
    /// Bounded excerpt when the authenticated user side matched.
    pub user_excerpt: Option<String>,
    /// Digest of the complete canonical user input.
    pub user_content_digest: String,
    /// Bounded excerpt when the committed final assistant side matched.
    pub assistant_excerpt: Option<String>,
    /// Digest of the complete final assistant content when present.
    pub assistant_content_digest: Option<String>,
    /// UTC canonical turn creation time.
    pub created_at_ms: i64,
}

/// Bounded, newest-first transcript search response for one exact authenticated binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSearchResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Literal query used by the storage boundary.
    pub query: String,
    /// Matching canonical turns.
    pub hits: Vec<SessionSearchHitResponse>,
}

/// Stable transport projection of one task.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskView {
    /// Opaque stable task ID.
    pub id: String,
    /// Current lifecycle state.
    pub status: TaskStatus,
    /// Optimistic-concurrency revision.
    pub revision: u64,
}

/// Current provider- and tool-budget usage for one task run.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskBudgetUsage {
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
    /// Recorded provider and tool output bytes.
    pub used_output_bytes: u64,
    /// Reserved output bytes.
    pub reserved_output_bytes: u64,
}

/// Transport spelling of task impact used by validation policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskRiskClass {
    /// Bounded, inspectable impact.
    Low,
    /// Material impact requiring independent evidence.
    Medium,
    /// High-impact work requiring the strongest policy controls.
    High,
}

impl From<mealy_domain::RiskClass> for TaskRiskClass {
    fn from(value: mealy_domain::RiskClass) -> Self {
        match value {
            mealy_domain::RiskClass::Low => Self::Low,
            mealy_domain::RiskClass::Medium => Self::Medium,
            mealy_domain::RiskClass::High => Self::High,
        }
    }
}

/// One explicit success condition exposed to the task owner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessCriterionResponse {
    /// Stable criterion identity within the task.
    pub criterion_id: String,
    /// Requirement stated independently from producer output.
    pub requirement: String,
}

/// Owner-inspectable success contract attached at admission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskSuccessCriteriaResponse {
    /// Task objective.
    pub objective: String,
    /// Explicit success conditions.
    pub criteria: Vec<SuccessCriterionResponse>,
    /// Durable reason when objective criteria do not apply.
    pub no_objective_criteria_reason: Option<String>,
    /// Policy-visible impact.
    pub risk_class: TaskRiskClass,
    /// Validation policy bundle.
    pub policy_version: String,
    /// Digest of canonical criteria JSON.
    pub criteria_digest: String,
}

/// Mechanism that produced validation evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationMethodResponse {
    /// Reproducible deterministic checks.
    Deterministic,
    /// Independent model evaluation with a fresh selected context.
    FreshContextModel,
    /// Explicit durable policy waiver.
    Waiver,
}

/// Result of applying task criteria to selected evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationOutcomeResponse {
    /// All required criteria were established.
    Passed,
    /// Producer output needs another bounded revision.
    NeedsRevision,
    /// Evidence established failure.
    Failed,
    /// Evidence was insufficient for a safe conclusion.
    Inconclusive,
    /// An authorized owner accepted residual risk.
    Waived,
}

/// Durable validation evidence attached to a task.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskValidationResponse {
    /// Stable validation identity.
    pub validation_id: String,
    /// Producer run whose output was checked.
    pub producer_run_id: String,
    /// Fresh validator run, when one was required.
    pub validator_run_id: Option<String>,
    /// Selected validation-context manifest.
    pub context_manifest_id: String,
    /// Validation mechanism.
    pub method: ValidationMethodResponse,
    /// Validation result.
    pub outcome: ValidationOutcomeResponse,
    /// Task-specific rubric applied to the evidence.
    pub rubric: serde_json::Value,
    /// Canonical evidence supporting the result.
    pub evidence: serde_json::Value,
    /// Stable validation policy bundle.
    pub policy_version: String,
    /// Timeline position of the durable validation fact.
    pub cursor: TimelineCursor,
}

/// Authorized current projection of a Phase 2 agent task.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Opaque stable task ID.
    pub task_id: String,
    /// Opaque owning run ID.
    pub run_id: String,
    /// Current lifecycle state.
    pub status: TaskStatus,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// Final assistant response, when durably committed.
    pub final_response: Option<String>,
    /// SHA-256 digest of the final response, when committed.
    pub final_digest: Option<String>,
    /// Current structured resource usage.
    pub usage: TaskBudgetUsage,
    /// Objective, criteria, risk, and policy fixed at task admission.
    pub success_criteria: TaskSuccessCriteriaResponse,
    /// Current durable validation, when one has been attached.
    pub validation: Option<TaskValidationResponse>,
    /// Number of durable provider attempts.
    pub model_attempts: u64,
    /// Number of durable read-tool calls.
    pub tool_calls: u64,
}

/// Authorized current projection of one durable parent-to-child delegation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Opaque stable delegation ID.
    pub delegation_id: String,
    /// Waiting or completed parent run.
    pub parent_run_id: String,
    /// Child task visible through the normal task evidence API.
    pub child_task_id: String,
    /// Child run visible through timeline and replay evidence.
    pub child_run_id: String,
    /// Exact three-way-intersected child authority; never secret values.
    pub effective_capabilities: serde_json::Value,
    /// Exact separately enforced child budget.
    pub child_budget: serde_json::Value,
    /// Queued, running, succeeded, failed, or cancelled.
    pub state: String,
    /// Structured terminal result returned to the parent, when available.
    pub result: Option<serde_json::Value>,
}

/// Bounded newest-first owner delegation list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationsResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Authorized delegations.
    pub delegations: Vec<DelegationResponse>,
}

/// Strict idempotent command requesting cooperative task cancellation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelTaskRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Stable command-delivery key.
    pub idempotency_key: String,
    /// Bounded user-facing cancellation reason.
    pub reason: String,
}

/// Durable receipt for an accepted or duplicate cancellation command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskCancellationReceipt {
    /// Semantic API version.
    pub api_version: String,
    /// Opaque cancelled task ID.
    pub task_id: String,
    /// State committed by the original cancellation command.
    pub status: TaskStatus,
    /// Task revision committed by the original cancellation command.
    pub revision: u64,
    /// Durable cancellation event ID.
    pub event_id: String,
    /// Durable cancellation event cursor.
    pub cursor: TimelineCursor,
    /// Whether this request returned the original receipt for an exact duplicate.
    pub duplicate: bool,
}

/// Strict optimistic-concurrency task pause or resume command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlTaskRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Exact task revision returned by task status.
    pub expected_revision: u64,
}

/// Durable receipt for one task pause or resume transition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskControlReceipt {
    /// Semantic API version.
    pub api_version: String,
    /// Opaque controlled task ID.
    pub task_id: String,
    /// Canonical state after the transition.
    pub status: TaskStatus,
    /// New task revision.
    pub revision: u64,
    /// Durable control event ID.
    pub event_id: String,
    /// Durable control event cursor.
    pub cursor: TimelineCursor,
}

/// Deterministic task replay reconstructed exclusively from durable evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskReplayResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Opaque source task ID.
    pub task_id: String,
    /// Opaque source run ID.
    pub run_id: String,
    /// Stable replay mode; Phase 2 uses recorded evidence only.
    pub mode: String,
    /// Whether every required record and digest was consistent.
    pub evidence_complete: bool,
    /// Recorded final assistant response, when committed.
    pub final_response: Option<String>,
    /// Recomputed SHA-256 digest of the final response.
    pub final_digest: Option<String>,
    /// Ordered recorded provider-attempt count.
    pub model_attempts: u64,
    /// Ordered recorded read-tool-call count.
    pub tool_calls: u64,
    /// Live provider calls made by replay; zero for recorded-evidence replay.
    pub live_provider_calls: u64,
    /// Live tool calls made by replay; zero for recorded-evidence replay.
    pub live_tool_calls: u64,
}

/// Authenticated owner decision for one exact approval subject.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecisionCommand {
    /// Authorize the exact subject shown to the owner.
    Approve,
    /// Deny the exact subject shown to the owner.
    Deny,
}

/// Public lifecycle spelling for an approval request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatusResponse {
    /// The exact subject is waiting for an authenticated decision.
    Pending,
    /// The owner approved the exact subject before expiry.
    Approved,
    /// The owner denied the exact subject before expiry.
    Denied,
    /// The exclusive approval deadline elapsed.
    Expired,
    /// Previously granted authority was explicitly revoked.
    Revoked,
}

/// Public lifecycle spelling for a governed external effect.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectStatusResponse {
    /// Exact intent exists but has not yet been evaluated.
    Proposed,
    /// Deterministic policy requires an authenticated owner decision.
    AwaitingApproval,
    /// Policy and any required approval authorize dispatch.
    Authorized,
    /// The external dispatch boundary may have been crossed.
    Dispatching,
    /// External success was confirmed.
    Succeeded,
    /// External failure was confirmed.
    Failed,
    /// The external outcome cannot currently be proven.
    OutcomeUnknown,
    /// An explicitly authorized compensating operation succeeded.
    Compensated,
    /// Policy, owner decision, expiry, or revocation denied dispatch.
    Denied,
}

/// Exact immutable material presented for an approval decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalSubjectResponse {
    /// Governed effect identity.
    pub effect_id: String,
    /// Authenticated owner identity bound into the subject.
    pub principal_id: String,
    /// Owning task identity.
    pub task_id: String,
    /// Stable tool identity.
    pub tool_id: String,
    /// Exact tool contract version.
    pub tool_version: String,
    /// Digest of schema-normalized arguments.
    pub canonical_arguments_digest: String,
    /// Exact capability being requested.
    pub capability_scope: String,
    /// Canonically ordered target resources.
    pub target_resources: Vec<String>,
    /// Digest of the exact executable identity policy evaluated.
    pub executable_identity_digest: String,
    /// Exact deterministic policy bundle version.
    pub policy_version: String,
    /// Exclusive UTC epoch-millisecond approval deadline.
    pub expires_at_ms: i64,
}

/// Authorized owner projection of one durable approval request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Opaque approval request identity.
    pub approval_id: String,
    /// Opaque governed effect identity.
    pub effect_id: String,
    /// Canonical exact subject.
    pub subject: ApprovalSubjectResponse,
    /// SHA-256 digest the owner command must echo.
    pub subject_digest: String,
    /// Current approval lifecycle.
    pub status: ApprovalStatusResponse,
    /// Explicit owner decision, when one was recorded.
    pub decision: Option<ApprovalDecisionCommand>,
    /// UTC epoch milliseconds at which the request was committed.
    pub requested_at_ms: i64,
    /// UTC epoch milliseconds at which it became terminal.
    pub resolved_at_ms: Option<i64>,
}

/// Deterministically ordered pending approval query result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingApprovalsResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Requests ordered by durable request time and approval ID.
    pub approvals: Vec<ApprovalResponse>,
}

/// Strict idempotent command resolving one exact pending approval.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolveApprovalRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Stable command-delivery key.
    pub idempotency_key: String,
    /// Exact subject digest rendered to the authenticated owner.
    pub expected_subject_digest: String,
    /// Owner decision for that exact subject.
    pub decision: ApprovalDecisionCommand,
}

/// Durable receipt for a new or exact-duplicate approval resolution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalResolutionReceipt {
    /// Semantic API version.
    pub api_version: String,
    /// Approval resolved by the original command.
    pub approval_id: String,
    /// Effect authorized or denied by the original command.
    pub effect_id: String,
    /// Terminal approval state committed by the original command.
    pub status: ApprovalStatusResponse,
    /// Exact owner decision committed by the original command.
    pub decision: ApprovalDecisionCommand,
    /// Effect revision committed by the original command.
    pub effect_revision: u64,
    /// Approval-aggregate event committed by the original command.
    pub approval_event_id: String,
    /// Effect-aggregate event committed by the original command.
    pub effect_event_id: String,
    /// Highest timeline cursor committed by the original command.
    pub cursor: TimelineCursor,
    /// Whether this delivery returned the original receipt unchanged.
    pub duplicate: bool,
}

/// Authorized owner projection of one governed effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Stable effect identity.
    pub effect_id: String,
    /// Owning task identity.
    pub task_id: String,
    /// Proposing run identity.
    pub run_id: String,
    /// Current effect lifecycle.
    pub status: EffectStatusResponse,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// Stable tool identity.
    pub tool_id: String,
    /// Exact tool contract version.
    pub tool_version: String,
    /// Digest of the complete immutable tool descriptor.
    pub descriptor_digest: String,
    /// Exact schema-normalized arguments.
    pub normalized_arguments: serde_json::Value,
    /// Digest of the normalized arguments.
    pub arguments_digest: String,
    /// Requested capability scope.
    pub capability_scope: String,
    /// Canonically ordered resources targeted by the operation.
    pub target_resources: Vec<String>,
    /// Exact executable identity digest policy authorized.
    pub executable_identity_digest: String,
    /// Stable policy decision spelling.
    pub policy_decision: String,
    /// Exact deterministic policy bundle version.
    pub policy_version: String,
    /// Owner-inspectable policy explanation.
    pub policy_explanation: String,
    /// Enforceable policy obligations copied onto dispatch.
    pub policy_obligations: serde_json::Value,
    /// Stable downstream key for keyed operations.
    pub idempotency_key: Option<String>,
    /// Bound approval request, when policy required one.
    pub approval: Option<ApprovalResponse>,
    /// UTC epoch milliseconds at which intent was committed.
    pub created_at_ms: i64,
    /// UTC epoch milliseconds of the latest accepted transition.
    pub updated_at_ms: i64,
}

/// Public lifecycle spelling for one concrete effect dispatch attempt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectAttemptStatusResponse {
    /// Authorization, input, key, and fence are durable; dispatch has not started.
    Prepared,
    /// The external dispatch boundary may have been crossed.
    Running,
    /// External success was confirmed.
    Succeeded,
    /// External failure was confirmed.
    Failed,
    /// The external result cannot currently be established.
    OutcomeUnknown,
    /// The prior result is unknown, but the declared contract safely authorizes a new attempt.
    InterruptedRetryable,
    /// The original worker stopped before dispatch, so a new fenced attempt is safe.
    InterruptedUndispatched,
}

/// Public outcome spelling for effect evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectOutcomeResponse {
    /// External success was established.
    Succeeded,
    /// External failure was established.
    Failed,
    /// External outcome remains ambiguous.
    OutcomeUnknown,
    /// A separately authorized compensation was established.
    Compensated,
}

/// One immutable canonical outcome evidence record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectOutcomeEvidenceResponse {
    /// Zero for the original worker result; positive for explicit reconciliation.
    pub sequence: u64,
    /// Established outcome.
    pub outcome: EffectOutcomeResponse,
    /// Complete versioned canonical evidence envelope.
    pub evidence: serde_json::Value,
    /// SHA-256 digest of the canonical evidence envelope.
    pub evidence_digest: String,
    /// Journal event that committed the evidence.
    pub event_id: String,
    /// UTC epoch milliseconds at which Mealy accepted the evidence.
    pub recorded_at_ms: i64,
}

/// Authorized owner projection of one exact effect dispatch attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectAttemptResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Stable dispatch-attempt identity.
    pub attempt_id: String,
    /// Governed effect identity.
    pub effect_id: String,
    /// One-based attempt ordinal within the effect.
    pub ordinal: u64,
    /// Current durable dispatch boundary.
    pub status: EffectAttemptStatusResponse,
    /// Stable downstream key for keyed operations.
    pub idempotency_key: Option<String>,
    /// Fencing token copied from the exact worker lease.
    pub fencing_token: u64,
    /// UTC epoch milliseconds at which preparation committed.
    pub prepared_at_ms: i64,
    /// UTC epoch milliseconds at which dispatch began.
    pub started_at_ms: Option<i64>,
    /// UTC epoch milliseconds at which the initial result committed.
    pub completed_at_ms: Option<i64>,
    /// Stable failure or ambiguity classification.
    pub error_class: Option<String>,
    /// Original result followed by any reconciliation evidence.
    pub outcomes: Vec<EffectOutcomeEvidenceResponse>,
}

/// Explicit owner conclusion for an unknown effect outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationOutcomeCommand {
    /// External evidence proves the original operation succeeded.
    Succeeded,
    /// External evidence proves the original operation failed.
    Failed,
}

/// Strict idempotent command reconciling one unknown effect attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReconcileEffectRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Stable command-delivery key.
    pub idempotency_key: String,
    /// Exact current effect revision the owner inspected.
    pub expected_effect_revision: u64,
    /// Established external result.
    pub outcome: ReconciliationOutcomeCommand,
    /// Non-empty structured external evidence supporting the conclusion.
    pub evidence: serde_json::Value,
}

/// Durable receipt for a new or exact-duplicate reconciliation command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectReconciliationReceipt {
    /// Semantic API version.
    pub api_version: String,
    /// Effect reconciled by the original command.
    pub effect_id: String,
    /// Original ambiguous attempt reconciled by the command.
    pub attempt_id: String,
    /// External result established by the original command.
    pub outcome: ReconciliationOutcomeCommand,
    /// Effect revision committed by the original command.
    pub effect_revision: u64,
    /// Journal event committed by the original command.
    pub event_id: String,
    /// Timeline cursor committed by the original command.
    pub cursor: TimelineCursor,
    /// Whether this delivery returned the original receipt unchanged.
    pub duplicate: bool,
}

/// Authorized path-free projection of immutable artifact metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactMetadataResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Opaque logical artifact ID.
    pub artifact_id: String,
    /// Digest algorithm used by the immutable content blob.
    pub algorithm: String,
    /// Canonical digest of the plaintext logical content.
    pub digest: String,
    /// Exact verified content size.
    pub size_bytes: u64,
    /// Declared media type returned by the content endpoint.
    pub media_type: String,
    /// Stable origin category.
    pub origin_kind: String,
    /// Opaque origin identity within its category.
    pub origin_id: String,
    /// Stable producer category.
    pub producer_kind: String,
    /// Opaque producer identity within its category.
    pub producer_id: String,
    /// Sensitivity classification.
    pub sensitivity: String,
    /// Retention-policy classification.
    pub retention_class: String,
    /// Digest of the access policy applied by the trusted runtime.
    pub access_policy_digest: String,
    /// UTC epoch milliseconds at which metadata was committed.
    pub created_at_ms: i64,
}

/// Transport spelling of a context-item selection outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextItemDisposition {
    /// Content was included in the provider projection.
    Included,
    /// Content was excluded by deterministic selection.
    Excluded,
    /// Item metadata is visible while content is withheld.
    Redacted,
}

/// One ordered item in an authorized context-manifest inspection response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextManifestEvidenceItemResponse {
    /// Opaque stable item ID.
    pub item_id: String,
    /// Contiguous zero-based position.
    pub ordinal: u64,
    /// Selection outcome.
    pub disposition: ContextItemDisposition,
    /// Typed source class.
    pub source_type: String,
    /// Safe logical source locator, never a local or artifact-store path.
    pub source_locator: String,
    /// Digest of canonical source content.
    pub source_content_digest: String,
    /// Digest after the recorded transformation.
    pub rendered_content_digest: String,
    /// Recorded selection reason.
    pub inclusion_reason: String,
    /// Sensitivity classification.
    pub sensitivity: String,
    /// Deterministic token estimate.
    pub token_estimate: u64,
    /// Recorded transformation identifier.
    pub transformation: String,
    /// Recorded policy decision explanation.
    pub policy_decision: String,
    /// Authorized inline content for an included item only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Authorized artifact reference for an included oversized item only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_artifact_id: Option<String>,
    /// Exact retrieved memory revision and source citations, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_evidence: Option<ContextMemoryEvidenceResponse>,
    /// Exact derived compaction artifact, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compaction_id: Option<String>,
}

/// One immutable source digest cited by retrieved memory context.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextMemorySourceCitationResponse {
    /// One-based source ordinal on the immutable memory revision.
    pub source_ordinal: u64,
    /// Canonical source content digest.
    pub source_digest: String,
}

/// Exact governed-memory evidence retained in a context manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextMemoryEvidenceResponse {
    /// Opaque logical memory ID.
    pub memory_id: String,
    /// Opaque immutable revision ID.
    pub revision_id: String,
    /// Immutable source citations.
    pub sources: Vec<ContextMemorySourceCitationResponse>,
}

/// Authorized path-safe inspection response for one immutable context manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextManifestEvidenceResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Opaque manifest ID.
    pub manifest_id: String,
    /// Opaque owning run ID.
    pub run_id: String,
    /// Opaque owning turn ID.
    pub turn_id: String,
    /// Opaque immutable context-epoch ID.
    pub epoch_id: String,
    /// One-based loop iteration.
    pub iteration: u64,
    /// Deterministic compiler version.
    pub compiler_version: String,
    /// Provider residency constraint.
    pub provider_residency: String,
    /// Maximum compiled context tokens.
    pub token_budget: u64,
    /// Sum of included-item token estimates.
    pub total_token_estimate: u64,
    /// Digest of the ordered tool-schema set.
    pub tool_schema_set_digest: String,
    /// Policy bundle version.
    pub policy_version: String,
    /// Digest of the exact provider projection.
    pub projection_digest: String,
    /// Items in committed deterministic order.
    pub items: Vec<ContextManifestEvidenceItemResponse>,
    /// UTC epoch milliseconds at which the manifest was committed.
    pub created_at_ms: i64,
}

/// Governed-memory lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryStatusResponse {
    /// Awaiting promotion policy.
    Proposed,
    /// Eligible for retrieval.
    Active,
    /// Replaced by a corrected revision.
    Superseded,
    /// Removed from retrieval under retention or owner action.
    Expired,
    /// Rejected before activation.
    Rejected,
    /// Content scrubbed; minimal tombstone retained.
    Deleted,
}

impl From<mealy_domain::MemoryStatus> for MemoryStatusResponse {
    fn from(value: mealy_domain::MemoryStatus) -> Self {
        match value {
            mealy_domain::MemoryStatus::Proposed => Self::Proposed,
            mealy_domain::MemoryStatus::Active => Self::Active,
            mealy_domain::MemoryStatus::Superseded => Self::Superseded,
            mealy_domain::MemoryStatus::Expired => Self::Expired,
            mealy_domain::MemoryStatus::Rejected => Self::Rejected,
            mealy_domain::MemoryStatus::Deleted => Self::Deleted,
        }
    }
}

/// Promotion-policy category for governed memory.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryCategoryCommand {
    /// User preference.
    Preference,
    /// Revisable factual claim.
    Fact,
    /// Ongoing objective.
    Goal,
    /// Prior decision.
    Decision,
    /// Durable constraint.
    Constraint,
    /// Sensitive identity information.
    Identity,
    /// Credential reference or authentication fact.
    Credential,
    /// Sensitive health information.
    Health,
    /// Sensitive financial information.
    Financial,
    /// Private information about a third party.
    ThirdPartyPrivate,
}

/// Disclosure sensitivity for governed memory.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySensitivityCommand {
    /// Public under owner policy.
    Public,
    /// Internal trusted-environment content.
    Internal,
    /// Private owner content.
    Private,
    /// Explicit narrow-policy content.
    Restricted,
}

/// Retention behavior for governed memory.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryRetentionCommand {
    /// Expires with the source session.
    Session,
    /// Normal configured retention.
    Standard,
    /// Explicit owner pin.
    Pinned,
    /// Policy hold.
    PolicyHold,
}

/// One immutable memory source supplied by an owner command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemorySourceCommand {
    /// Safe logical locator.
    pub locator: String,
    /// Canonical lowercase SHA-256 content digest.
    pub digest: String,
}

/// Proposes a governed logical memory and first immutable revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProposeMemoryRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Exact workspace namespace.
    pub workspace_identity: String,
    /// Bounded proposed content.
    pub content: String,
    /// Promotion-policy category.
    pub category: MemoryCategoryCommand,
    /// Integer confidence from zero through 10,000 basis points.
    pub confidence_basis_points: u16,
    /// Disclosure sensitivity.
    pub sensitivity: MemorySensitivityCommand,
    /// Retention behavior.
    pub retention: MemoryRetentionCommand,
    /// Immutable source evidence.
    pub sources: Vec<MemorySourceCommand>,
}

/// Explicit owner authorization mechanism for sensitive promotion.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryPromotionAuthorizationCommand {
    /// The configured owner policy explicitly permits this exact revision.
    OwnerPolicy,
    /// This authenticated command is recorded as an explicit bound owner approval.
    OwnerApproval,
}

/// Promotes an exact proposed memory revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PromoteMemoryRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Exact proposed revision ID.
    pub revision_id: String,
    /// Required for sensitive categories; optional for ordinary facts.
    pub authorization: Option<MemoryPromotionAuthorizationCommand>,
}

/// Corrects an active memory with a new immutable revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CorrectMemoryRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Optimistic-concurrency revision of the logical memory.
    pub expected_revision: u64,
    /// Corrected bounded content.
    pub content: String,
    /// Integer confidence from zero through 10,000 basis points.
    pub confidence_basis_points: u16,
    /// Disclosure sensitivity.
    pub sensitivity: MemorySensitivityCommand,
    /// Retention behavior.
    pub retention: MemoryRetentionCommand,
    /// Immutable replacement sources.
    pub sources: Vec<MemorySourceCommand>,
    /// Required for sensitive categories; optional otherwise.
    pub authorization: Option<MemoryPromotionAuthorizationCommand>,
}

/// Sets pinned or standard retention on an active memory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetMemoryPinRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Optimistic-concurrency revision.
    pub expected_revision: u64,
    /// Pin when true; restore standard retention when false.
    pub pinned: bool,
}

/// Optimistic lifecycle command for expiry or deletion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryLifecycleRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Optimistic-concurrency revision.
    pub expected_revision: u64,
}

/// Authenticated request to rebuild the caller's derived lexical index rows.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RebuildMemoryIndexRequest {
    /// Requested semantic API version.
    pub api_version: String,
}

/// One immutable source citation in a memory response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemorySourceResponse {
    /// Safe logical locator.
    pub locator: String,
    /// Canonical source digest.
    pub digest: String,
}

/// One immutable memory revision in ascending history order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryRevisionResponse {
    /// Opaque revision ID.
    pub revision_id: String,
    /// One-based ordinal.
    pub ordinal: u64,
    /// Revision lifecycle state.
    pub status: MemoryStatusResponse,
    /// Content is absent after deletion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Canonical content digest retained in a tombstone.
    pub content_digest: String,
    /// Confidence in basis points.
    pub confidence_basis_points: u16,
    /// Revision sensitivity.
    pub sensitivity: MemorySensitivityCommand,
    /// Revision retention.
    pub retention: MemoryRetentionCommand,
    /// Prior corrected revision.
    pub supersedes_revision_id: Option<String>,
    /// Immutable provenance sources.
    pub sources: Vec<MemorySourceResponse>,
    /// UTC creation time.
    pub created_at_ms: i64,
    /// UTC verification time.
    pub last_verified_at_ms: i64,
}

/// Complete owner-authorized logical memory projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Opaque logical memory ID.
    pub memory_id: String,
    /// Owner principal ID.
    pub principal_id: String,
    /// Exact workspace namespace.
    pub workspace_identity: String,
    /// Logical lifecycle state.
    pub status: MemoryStatusResponse,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// Promotion-policy category.
    pub category: MemoryCategoryCommand,
    /// Current confidence in basis points.
    pub confidence_basis_points: u16,
    /// Current sensitivity.
    pub sensitivity: MemorySensitivityCommand,
    /// Current retention.
    pub retention: MemoryRetentionCommand,
    /// UTC creation time.
    pub created_at_ms: i64,
    /// UTC verification time.
    pub last_verified_at_ms: i64,
    /// Immutable revision history.
    pub revisions: Vec<MemoryRevisionResponse>,
}

/// Owner-authorized namespace list/export response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoriesResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Deterministically ordered memories.
    pub memories: Vec<MemoryResponse>,
}

/// One lexical retrieval hit.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemorySearchHitResponse {
    /// Complete cited memory.
    pub memory: MemoryResponse,
    /// FTS5 BM25 rank; lower is more relevant.
    pub lexical_rank: f64,
}

/// Deterministically filtered lexical search response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemorySearchResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Ranked results.
    pub hits: Vec<MemorySearchHitResponse>,
}

/// Derived lexical-index rebuild receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryIndexRebuildResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Active revisions indexed for this owner.
    pub indexed_revision_count: u64,
    /// UTC rebuild completion time.
    pub rebuilt_at_ms: i64,
}

/// Owner request to commit one cited derived compaction artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateCompactionRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// First canonical source cursor, inclusive.
    pub source_first_cursor: u64,
    /// Last canonical source cursor, inclusive.
    pub source_last_cursor: u64,
    /// Human-readable derived summary stored as a content-addressed artifact.
    pub summary_text: String,
    /// Strictly decoded [`mealy_domain::CompactionCarryForward`] JSON.
    pub carry_forward: serde_json::Value,
}

/// Owner-authorized projection of one immutable cited compaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompactionResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Opaque compaction ID.
    pub compaction_id: String,
    /// Opaque content-addressed artifact metadata ID.
    pub artifact_id: String,
    /// First canonical source cursor, inclusive.
    pub source_first_cursor: u64,
    /// Last canonical source cursor, inclusive.
    pub source_last_cursor: u64,
    /// Stable extraction prompt version.
    pub prompt_version: String,
    /// Extraction configuration digest.
    pub config_digest: String,
    /// Exact summary artifact digest.
    pub artifact_digest: String,
    /// Human-readable derived summary.
    pub summary_text: String,
    /// Typed goals, constraints, approvals, and effect outcomes with citations.
    pub carry_forward: serde_json::Value,
    /// Timeline position of `context.compacted`.
    pub cursor: TimelineCursor,
}

/// Stable extension lifecycle state exposed through the owner API.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionStatusResponse {
    /// Digest-pinned package is inert pending an explicit grant.
    Installed,
    /// Exact current manifest has an active owner grant.
    Enabled,
    /// Runtime authority is temporarily removed.
    Disabled,
    /// Supervised runtime failed and awaits owner action.
    Failed,
    /// All future authority is terminally revoked.
    Revoked,
}

/// Filesystem access accepted by an explicit extension grant command.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionFilesystemAccessCommand {
    /// Read-only mapping.
    ReadOnly,
    /// Read-write mapping, usable only through effect-mediated capabilities.
    ReadWrite,
}

/// Exact logical-to-host filesystem mapping granted by the owner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionMountGrantCommand {
    /// Manifest-declared logical permission name.
    pub name: String,
    /// Granted access mode.
    pub access: ExtensionFilesystemAccessCommand,
    /// Exact canonical host directory.
    pub host_path: String,
    /// Exact normalized sandbox mount point.
    pub sandbox_path: String,
}

/// Installs a new inert digest-pinned extension package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallExtensionRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Exact original manifest JSON text whose bytes are digest-pinned.
    pub manifest_json: String,
    /// Owner-supplied SHA-256 pin for `manifestJson` bytes.
    pub manifest_digest: String,
    /// Canonical local package root. It is never returned in public projections.
    pub installation_root: String,
}

/// Stages an upgrade or rollback while removing prior authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StageExtensionManifestRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Optimistic-concurrency extension revision.
    pub expected_revision: u64,
    /// Exact original manifest JSON text.
    pub manifest_json: String,
    /// Owner-supplied SHA-256 manifest byte pin.
    pub manifest_digest: String,
    /// Canonical local package root.
    pub installation_root: String,
}

/// Explicitly enables one exact staged manifest and least-authority grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnableExtensionRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Optimistic-concurrency extension revision.
    pub expected_revision: u64,
    /// Exact capability IDs approved by the owner.
    pub capability_ids: Vec<String>,
    /// Explicit filesystem mappings.
    pub mounts: Vec<ExtensionMountGrantCommand>,
    /// Exact outbound network destinations.
    pub network_destinations: Vec<String>,
    /// Exact opaque secret references.
    pub secret_references: Vec<String>,
    /// Whether child process creation is approved.
    pub allow_process_spawn: bool,
}

/// Optimistic disable or terminal-revocation command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionLifecycleRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Optimistic-concurrency extension revision.
    pub expected_revision: u64,
}

/// Invokes one currently granted read-only extension capability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvokeExtensionRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Exact manifest capability ID.
    pub capability_id: String,
    /// Strict schema-validated input object.
    pub input: serde_json::Value,
}

/// Owner-safe projection of one immutable manifest history entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionManifestRevisionResponse {
    /// Exact manifest byte digest.
    pub manifest_digest: String,
    /// Package version declared by that manifest.
    pub version: String,
    /// UTC installation/staging time.
    pub installed_at_ms: i64,
}

/// Owner-safe summary of the active immutable extension grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionGrantResponse {
    /// Opaque immutable grant ID.
    pub grant_id: String,
    /// Exact grant digest.
    pub grant_digest: String,
    /// Manifest digest reviewed by the grant.
    pub manifest_digest: String,
    /// Exact capability IDs.
    pub capability_ids: Vec<String>,
    /// Explicit filesystem mappings.
    pub mounts: Vec<ExtensionMountGrantCommand>,
    /// Exact network destinations.
    pub network_destinations: Vec<String>,
    /// Opaque secret references, never values.
    pub secret_references: Vec<String>,
    /// Whether child process creation is granted.
    pub allow_process_spawn: bool,
    /// Stable policy bundle version.
    pub policy_version: String,
    /// UTC issue time.
    pub issued_at_ms: i64,
}

/// Complete owner-authorized extension projection without local package paths.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Opaque extension ID.
    pub extension_id: String,
    /// Owner principal ID.
    pub principal_id: String,
    /// Current lifecycle status.
    pub status: ExtensionStatusResponse,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// Exact current manifest digest.
    pub manifest_digest: String,
    /// Current package version.
    pub version: String,
    /// Human-readable extension identity.
    pub name: String,
    /// Human-readable publisher identity.
    pub publisher: String,
    /// Parsed current data-only manifest.
    pub manifest: serde_json::Value,
    /// Active grant only while enabled.
    pub active_grant: Option<ExtensionGrantResponse>,
    /// Immutable manifest history without installation paths.
    pub manifest_history: Vec<ExtensionManifestRevisionResponse>,
    /// Last successful health time.
    pub last_healthy_at_ms: Option<i64>,
    /// Last failed health time.
    pub last_failure_at_ms: Option<i64>,
}

/// Deterministically ordered owner extension list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionsResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Installed extensions.
    pub extensions: Vec<ExtensionResponse>,
}

/// Durable extension invocation state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionInvocationStatusResponse {
    /// Dispatch evidence exists before launch.
    Dispatching,
    /// Valid request-bound response committed.
    Succeeded,
    /// Classified terminal failure committed.
    Failed,
    /// Startup recovery found no trustworthy terminal response.
    Abandoned,
}

/// Owner-safe durable extension invocation receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionInvocationResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Opaque invocation ID.
    pub invocation_id: String,
    /// Opaque extension ID.
    pub extension_id: String,
    /// Exact capability ID.
    pub capability_id: String,
    /// Durable terminal status.
    pub status: ExtensionInvocationStatusResponse,
    /// Validated output after success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    /// Canonical output digest after success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_digest: Option<String>,
    /// Stable failure class.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    /// Sanitized failure explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// Observed worker duration.
    pub duration_ms: Option<u64>,
    /// UTC dispatch time.
    pub started_at_ms: i64,
    /// UTC terminal time.
    pub completed_at_ms: Option<i64>,
}

/// Administrative creation of one signed external webhook channel.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateWebhookChannelRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Exact verified platform subject mapped to the local principal.
    pub external_subject: String,
    /// Owner-approved callback URL for durable outbound notifications.
    pub callback_url: String,
}

/// Signed webhook channel lifecycle exposed to the owner.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookChannelStatusResponse {
    /// Inbound authentication and outbound delivery are active.
    Active,
    /// All future authority is terminally revoked.
    Revoked,
}

/// Owner-safe signed webhook channel projection without secret material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookChannelResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Stable channel binding used in the signed ingress URL.
    pub binding_id: String,
    /// Dedicated durable session for this external identity.
    pub session_id: String,
    /// Exact platform subject expected in signed bodies.
    pub external_subject: String,
    /// Owner-approved outbound webhook URL.
    pub callback_url: String,
    /// Current terminal lifecycle state.
    pub status: WebhookChannelStatusResponse,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// UTC creation time.
    pub created_at_ms: i64,
    /// UTC last-update time.
    pub updated_at_ms: i64,
}

/// One-time channel creation result containing the newly generated signing secret.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateWebhookChannelResponse {
    /// Owner-safe durable channel projection.
    pub channel: WebhookChannelResponse,
    /// URL-safe base64 32-byte secret returned only by the creation command.
    pub signing_secret: String,
    /// Versioned HMAC framing contract.
    pub signature_version: String,
    /// HMAC algorithm identifier.
    pub signature_algorithm: String,
}

/// Deterministically ordered owner signed-webhook list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookChannelsResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Owner-authorized bindings.
    pub channels: Vec<WebhookChannelResponse>,
}

/// Optimistic terminal channel revocation command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeWebhookChannelRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Exact current channel revision.
    pub expected_revision: u64,
}

/// Administrative creation of one exact Telegram bot/user/chat binding.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateTelegramChannelRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Bot token read from a one-shot environment variable by the CLI.
    pub bot_token: String,
    /// Exact Telegram sender user ID allowed to submit updates.
    pub telegram_user_id: i64,
    /// Exact Telegram chat ID allowed for inbound and outbound messages.
    pub telegram_chat_id: i64,
    /// First update the binding may process; zero for manual-ID setup.
    #[serde(default)]
    pub initial_next_update_id: i64,
}

impl std::fmt::Debug for CreateTelegramChannelRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreateTelegramChannelRequest")
            .field("api_version", &self.api_version)
            .field("bot_token", &"[REDACTED]")
            .field("telegram_user_id", &self.telegram_user_id)
            .field("telegram_chat_id", &self.telegram_chat_id)
            .field("initial_next_update_id", &self.initial_next_update_id)
            .finish()
    }
}

/// Telegram channel lifecycle exposed to the owner.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TelegramChannelStatusResponse {
    /// Polling, admission, and outbound delivery are active.
    Active,
    /// Bot-token authority is terminally revoked.
    Revoked,
}

/// Owner-safe Telegram binding projection without bot-token material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelegramChannelResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Stable channel binding.
    pub binding_id: String,
    /// Dedicated durable conversation session.
    pub session_id: String,
    /// Exact allowed Telegram sender.
    pub telegram_user_id: i64,
    /// Exact allowed Telegram chat.
    pub telegram_chat_id: i64,
    /// Bot user ID verified with `getMe` during setup.
    pub bot_user_id: i64,
    /// Bot username verified with `getMe` during setup.
    pub bot_username: String,
    /// Current lifecycle.
    pub status: TelegramChannelStatusResponse,
    /// First not-yet-terminally-processed update ID.
    pub next_update_id: i64,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// Most recent successful Bot API poll time.
    pub last_success_at_ms: Option<i64>,
    /// Most recent failed Bot API poll time.
    pub last_failure_at_ms: Option<i64>,
    /// Consecutive poll failures.
    pub consecutive_failures: u64,
    /// Stable secret-free last error code.
    pub last_error_code: Option<String>,
    /// UTC creation time.
    pub created_at_ms: i64,
    /// UTC last lifecycle update time.
    pub updated_at_ms: i64,
}

/// Deterministically ordered owner Telegram-channel list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelegramChannelsResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Owner-authorized bindings.
    pub channels: Vec<TelegramChannelResponse>,
}

/// Optimistic terminal Telegram-channel revocation command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeTelegramChannelRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Exact current channel revision.
    pub expected_revision: u64,
}

/// Administrative creation of one exact Discord bot/human/DM binding.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateDiscordChannelRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Bot token read from a one-shot environment variable by the CLI.
    pub bot_token: String,
    /// Exact Discord human user snowflake allowed to submit messages.
    pub discord_user_id: String,
    /// Exact one-to-one Discord DM channel snowflake.
    pub discord_channel_id: String,
}

impl std::fmt::Debug for CreateDiscordChannelRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreateDiscordChannelRequest")
            .field("api_version", &self.api_version)
            .field("bot_token", &"[REDACTED]")
            .field("discord_user_id", &self.discord_user_id)
            .field("discord_channel_id", &self.discord_channel_id)
            .finish()
    }
}

/// Discord DM channel lifecycle exposed to the owner.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscordChannelStatusResponse {
    /// Polling, admission, and outbound delivery are active.
    Active,
    /// Bot-token authority is terminally revoked.
    Revoked,
}

/// Owner-safe Discord DM binding projection without bot-token material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscordChannelResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Stable channel binding.
    pub binding_id: String,
    /// Dedicated durable conversation session.
    pub session_id: String,
    /// Exact allowed Discord human user snowflake.
    pub discord_user_id: String,
    /// Exact one-to-one Discord DM channel snowflake.
    pub discord_channel_id: String,
    /// Bot user snowflake verified during setup.
    pub bot_user_id: String,
    /// Bot username verified during setup.
    pub bot_username: String,
    /// Current lifecycle.
    pub status: DiscordChannelStatusResponse,
    /// Last terminally processed message snowflake.
    pub after_message_id: Option<String>,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// Most recent Discord API poll time.
    pub last_success_at_ms: Option<i64>,
    /// Most recent failed poll time.
    pub last_failure_at_ms: Option<i64>,
    /// Consecutive poll failures.
    pub consecutive_failures: u64,
    /// Stable secret-free last error code.
    pub last_error_code: Option<String>,
    /// UTC creation time.
    pub created_at_ms: i64,
    /// UTC last lifecycle update time.
    pub updated_at_ms: i64,
}

/// Deterministically ordered owner Discord-channel list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscordChannelsResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Owner-authorized bindings.
    pub channels: Vec<DiscordChannelResponse>,
}

/// Optimistic terminal Discord-channel revocation command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeDiscordChannelRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Exact current channel revision.
    pub expected_revision: u64,
}

/// Strict raw-body contract authenticated by the signed webhook ingress.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedWebhookInputRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Stable platform delivery identity used for durable inbox deduplication.
    pub delivery_id: String,
    /// Exact platform subject that must match the configured binding.
    pub subject: String,
    /// UTF-8 user content admitted only after signature and replay verification.
    pub content: String,
    /// Requested durable queue/steering behavior.
    pub delivery_mode: DeliveryMode,
}

/// Durable daemon process-lifetime classification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonRunStatusResponse {
    /// Process is serving or draining.
    Running,
    /// Bounded graceful drain completed.
    Clean,
    /// Drain deadline or second signal forced termination.
    Forced,
    /// A later process observed missing terminal evidence.
    Unclean,
}

/// One bounded recent durable failure summary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationalFailureResponse {
    /// Timeline cursor.
    pub cursor: TimelineCursor,
    /// Stable event type.
    pub event_type: String,
    /// Aggregate category.
    pub aggregate_kind: String,
    /// Aggregate identity.
    pub aggregate_id: String,
    /// End-to-end correlation identity.
    pub correlation_id: String,
    /// UTC occurrence time.
    pub occurred_at_ms: i64,
}

/// Secret-free live pressure plus durable cross-restart history for one configured endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderEndpointStatusResponse {
    /// Stable wire-protocol adapter identity.
    pub protocol: String,
    /// Stable configured provider identity.
    pub provider_id: String,
    /// Exact configured model identity.
    pub model_id: String,
    /// Owner-declared residency/trust label.
    pub residency: String,
    /// Whether the endpoint is literal-loopback local.
    pub local: bool,
    /// Whether the endpoint emits bounded non-authoritative text deltas.
    pub streaming: bool,
    /// Current process-lifetime health classification.
    pub health: String,
    /// Owner-configured routing estimate.
    pub estimated_latency_ms: u64,
    /// Cumulative durably dispatched attempt count across retained daemon lifetimes.
    pub invocation_count: u64,
    /// Requests currently consuming the endpoint concurrency ceiling.
    pub in_flight_requests: u64,
    /// Configured simultaneous request ceiling.
    pub maximum_concurrent_requests: u64,
    /// Requests reserved in the current UTC minute window.
    pub requests_in_current_minute: u64,
    /// Configured request ceiling per minute.
    pub requests_per_minute: u64,
    /// Most recent live or durably committed successful endpoint response in epoch milliseconds.
    pub last_success_at_ms: Option<i64>,
    /// Most recent live or durably committed classified endpoint failure in epoch milliseconds.
    pub last_failure_at_ms: Option<i64>,
}

/// Authenticated owner operational health projection and bounded gauges.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminStatusResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Current process-lifetime identity.
    pub start_id: String,
    /// Durable process-lifetime status.
    pub run_status: DaemonRunStatusResponse,
    /// Query-only fail-closed mode.
    pub safe_mode: bool,
    /// Whether command admission is still open.
    pub admission_open: bool,
    /// Effective non-secret configuration digest.
    pub config_digest: String,
    /// Effective security policy bundle digest.
    pub policy_bundle_digest: String,
    /// Current `SQLite` schema revision.
    pub schema_version: u64,
    /// Pending session inbox rows.
    pub pending_inputs: u64,
    /// Queued/running/waiting agent runs.
    pub nonterminal_runs: u64,
    /// Active fenced work leases.
    pub active_leases: u64,
    /// Pending approval subjects.
    pub pending_approvals: u64,
    /// Effects requiring reconciliation.
    pub unknown_effects: u64,
    /// Pending or delivering outbox rows.
    pub pending_outbox: u64,
    /// Terminally failed outbox rows.
    pub failed_outbox: u64,
    /// Enabled extensions.
    pub enabled_extensions: u64,
    /// Failed extensions.
    pub failed_extensions: u64,
    /// Aggregate primary/fallback provider health classification.
    pub provider_health: String,
    /// Effective provider identity selected for this daemon lifetime.
    pub provider_id: String,
    /// Effective model identity selected for this daemon lifetime.
    pub provider_model_id: String,
    /// Effective provider residency label used by routing policy.
    pub provider_residency: String,
    /// Whether the effective provider endpoint is local to this host.
    pub provider_local: bool,
    /// Primary followed by every explicit fallback endpoint and its independent health.
    pub provider_endpoints: Vec<ProviderEndpointStatusResponse>,
    /// Exact model-visible read tools enabled for newly promoted tasks in this daemon lifetime.
    pub enabled_read_tools: Vec<String>,
    /// Exact effect tools available only to explicitly selected action-mode tasks.
    pub enabled_action_tools: Vec<String>,
    /// Current extension-host enforcement health classification.
    pub extension_host_health: String,
    /// Active signed channel bindings.
    pub active_channels: u64,
    /// Active external channels with consecutive transport failures.
    pub degraded_channels: u64,
    /// Reserved remote updates awaiting terminal processing evidence.
    pub reserved_channel_updates: u64,
    /// Active recurring agent schedules.
    pub active_schedules: u64,
    /// Paused recurring agent schedules.
    pub paused_schedules: u64,
    /// Schedule occurrences currently held by a daemon claim.
    pub claimed_schedule_runs: u64,
    /// Terminally failed schedule occurrence admissions.
    pub failed_schedule_runs: u64,
    /// Policy-skipped schedule occurrences.
    pub skipped_schedule_runs: u64,
    /// Current `SQLite` database and sidecar bytes.
    pub database_bytes: u64,
    /// Current committed artifact bytes.
    pub artifact_bytes: u64,
    /// Current committed artifact count.
    pub artifact_count: u64,
    /// Newest durable failure summaries.
    pub recent_failures: Vec<OperationalFailureResponse>,
    /// UTC process start time.
    pub started_at_ms: i64,
    /// UTC readiness time.
    pub ready_at_ms: i64,
    /// UTC terminal time for a prior process.
    pub completed_at_ms: Option<i64>,
    /// Terminal reason for a prior process.
    pub completion_reason: Option<String>,
}

/// Stable machine-readable operational gauges for local metric collection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminMetricsResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Gauge name to unsigned value.
    pub gauges: std::collections::BTreeMap<String, u64>,
}

/// One non-empty UTC-day aggregate of exact settled terminal-run usage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUsageBucketResponse {
    /// UTC day start in epoch milliseconds.
    pub bucket_start_ms: i64,
    /// UTC day end, clipped to the requested exclusive upper bound.
    pub bucket_end_ms: i64,
    /// Terminal root, delegated, or validation runs settled in this bucket.
    pub completed_runs: u64,
    /// Successfully completed runs.
    pub succeeded_runs: u64,
    /// Failed runs.
    pub failed_runs: u64,
    /// Cancelled runs.
    pub cancelled_runs: u64,
    /// Settled or conservatively charged provider calls.
    pub used_model_calls: u64,
    /// Settled read/effect tool calls.
    pub used_tool_calls: u64,
    /// Settled delegated child-run reservations.
    pub used_delegated_runs: u64,
    /// Classified provider/tool retries.
    pub used_retries: u64,
    /// Recorded provider input tokens.
    pub used_input_tokens: u64,
    /// Recorded provider output tokens.
    pub used_output_tokens: u64,
    /// Provider-neutral configured-price microunits, not an invoice amount.
    pub used_cost_microunits: u64,
    /// Recorded provider/tool output bytes.
    pub used_output_bytes: u64,
}

/// Authenticated exact-owner terminal usage grouped by UTC completion day.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUsageReportResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Inclusive requested lower epoch-millisecond bound.
    pub from_ms: i64,
    /// Exclusive requested upper epoch-millisecond bound.
    pub to_ms: i64,
    /// Ordered non-empty UTC-day buckets; empty days are omitted.
    pub buckets: Vec<AdminUsageBucketResponse>,
}

/// Authenticated request to begin bounded graceful drain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DrainDaemonRequest {
    /// Requested semantic API version.
    pub api_version: String,
}

/// Idempotent acknowledgement that command admission is closing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DrainDaemonResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Current process-lifetime identity.
    pub start_id: String,
    /// Configured forced-drain deadline.
    pub deadline_ms: u64,
    /// Whether this command initiated the drain rather than observing it.
    pub newly_requested: bool,
}

/// Authenticated request to create one immutable complete backup below the daemon home.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateBackupRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Portable immutable backup label.
    pub name: String,
    /// Opt in to authenticated-encrypted identity and brokered channel-key backup.
    #[serde(default)]
    pub include_secrets: bool,
    /// Passphrase used only for Argon2id key derivation and never persisted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_passphrase: Option<String>,
}

/// Published complete-backup evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Immutable backup label.
    pub name: String,
    /// Owner-local final directory.
    pub path: String,
    /// Digest of the exact canonical manifest bytes.
    pub manifest_digest: String,
    /// Manifest-covered file count.
    pub file_count: u64,
    /// Manifest-covered aggregate bytes.
    pub total_bytes: u64,
    /// Captured `SQLite` schema revision.
    pub schema_version: u64,
    /// Captured canonical artifact blobs.
    pub artifact_count: u64,
    /// Whether encrypted secret material is present.
    pub secrets_included: bool,
}

/// Authenticated request to verify one immutable backup in an isolated fresh home.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifyBackupRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Existing backup label below the daemon's backup root.
    pub name: String,
    /// Passphrase for an encrypted secret archive, omitted for non-secret backups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_passphrase: Option<String>,
}

/// Fresh-home backup verification evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupVerificationResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Verified backup label.
    pub name: String,
    /// Owner-local immutable backup directory.
    pub path: String,
    /// Digest of the verified manifest bytes.
    pub manifest_digest: String,
    /// UTC verification time in epoch milliseconds.
    pub verified_at_ms: i64,
    /// Verified `SQLite` schema revision.
    pub schema_version: u64,
    /// Verified file count.
    pub file_count: u64,
    /// Verified aggregate bytes.
    pub total_bytes: u64,
    /// Artifact blobs cross-checked against canonical metadata.
    pub artifact_count: u64,
    /// Whether encrypted secret material is present.
    pub secrets_included: bool,
    /// Whether decrypted identity is active in the restored canonical registry.
    pub identity_verified: bool,
}

/// Offline stopped-home backup activation evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupActivationResponse {
    /// Semantic response version.
    pub api_version: String,
    /// Activated immutable backup label.
    pub name: String,
    /// Newly active owner-local home.
    pub home: String,
    /// Complete pre-activation home retained beside it.
    pub preserved_home: String,
    /// Exact approved and activated backup manifest digest.
    pub manifest_digest: String,
    /// UTC atomic exchange time in epoch milliseconds.
    pub activated_at_ms: i64,
    /// Verified restored `SQLite` schema revision.
    pub schema_version: u64,
    /// Manifest-covered file count.
    pub file_count: u64,
    /// Manifest-covered aggregate bytes.
    pub total_bytes: u64,
    /// Canonical artifacts cross-checked before activation.
    pub artifact_count: u64,
}

/// Offline stopped-home activation evidence for a pre-migration snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationBackupActivationResponse {
    /// Semantic response version.
    pub api_version: String,
    /// Activated immutable migration-backup label.
    pub migration_backup_name: String,
    /// Newly active owner-local home.
    pub home: String,
    /// Complete migrated home retained beside it.
    pub preserved_home: String,
    /// Exact approved and activated migration manifest digest.
    pub manifest_digest: String,
    /// UTC atomic exchange time in epoch milliseconds.
    pub activated_at_ms: i64,
    /// Restored older state-schema revision.
    pub from_schema_version: u64,
    /// State-schema revision of the preserved migrated home.
    pub to_schema_version: u64,
    /// Snapshot-manifest file count.
    pub file_count: u64,
    /// Snapshot-manifest aggregate bytes.
    pub total_bytes: u64,
    /// Canonical artifacts cross-checked and copied before activation.
    pub artifact_count: u64,
}

/// Authenticated request for an age-gated artifact retention pass.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunGarbageCollectionRequest {
    /// Requested semantic API version.
    pub api_version: String,
}

/// Physical artifact-erasure summary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GarbageCollectionResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Configured minimum artifact age in hours.
    pub minimum_age_hours: u64,
    /// Aged unreferenced committed blobs erased.
    pub removed_blob_count: u64,
    /// Bytes erased from unreferenced committed blobs.
    pub removed_blob_bytes: u64,
    /// Aged incomplete temporary files erased.
    pub removed_temporary_file_count: u64,
    /// Young orphan files retained for later reconciliation/collection.
    pub retained_young_file_count: u64,
    /// Referenced blobs retained regardless of age.
    pub retained_referenced_blob_count: u64,
}

/// Enforceability of one host sandbox profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxProfileStatusResponse {
    /// The current adapter can enforce the profile.
    Enforceable,
    /// The adapter deliberately rejects the profile because required guarantees are absent.
    Denied,
}

/// Host-specific sandbox profile conformance evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxProfileResponse {
    /// Stable policy profile name.
    pub profile: String,
    /// Enforceability on the current host and installed adapter.
    pub status: SandboxProfileStatusResponse,
    /// Bounded operator-facing evidence or denial reason.
    pub detail: String,
}

/// Authenticated operational diagnostics for a clean installation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Host operating-system identifier.
    pub operating_system: String,
    /// Host architecture identifier.
    pub architecture: String,
    /// Whether every required control-plane check passed.
    pub control_plane_ready: bool,
    /// Whether the optional sandboxed effect proof is available.
    pub sandbox_available: bool,
    /// Exact supported/denied policy profiles.
    pub sandbox_profiles: Vec<SandboxProfileResponse>,
    /// Human-readable bounded diagnostic checks.
    pub checks: std::collections::BTreeMap<String, String>,
}

/// Supported immutable scoped-export bundle kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportKindRequest {
    /// Complete secret-free archive of canonical state, configuration, and referenced artifacts.
    Complete,
    /// Complete owner-visible timeline/audit evidence across sessions.
    Audit,
    /// One task's fully validated recorded-replay graph.
    Task,
    /// One artifact's authorized metadata and exact content bytes.
    Artifact,
    /// All governed memories, including tombstones, in one workspace namespace.
    Memory,
}

/// Authenticated request to publish one immutable scoped export.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateExportRequest {
    /// Requested semantic API version.
    pub api_version: String,
    /// Portable immutable bundle label.
    pub name: String,
    /// Scope-specific bundle kind.
    pub kind: ExportKindRequest,
    /// Task ID, artifact ID, or workspace identity; omitted for complete and audit scopes.
    pub selector: Option<String>,
}

/// Published immutable scoped-export evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Immutable export label.
    pub name: String,
    /// Scope-specific bundle kind.
    pub kind: ExportKindRequest,
    /// Task ID, artifact ID, or workspace identity when applicable.
    pub selector: Option<String>,
    /// Owner-local final JSON bundle path.
    pub path: String,
    /// SHA-256 digest of the exact JSON bytes.
    pub digest: String,
    /// Exact JSON byte count.
    pub size_bytes: u64,
    /// UTC publication time in epoch milliseconds.
    pub exported_at_ms: i64,
}

/// Stable presentation event emitted by timeline query/SSE.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEvent {
    /// Durable global cursor.
    pub cursor: TimelineCursor,
    /// Opaque event ID.
    pub event_id: String,
    /// Aggregate category.
    pub aggregate_kind: String,
    /// Opaque aggregate ID.
    pub aggregate_id: String,
    /// Aggregate-scoped sequence.
    pub aggregate_sequence: u64,
    /// Stable event type.
    pub event_type: String,
    /// Event payload version.
    pub event_version: u32,
    /// UTC epoch milliseconds.
    pub occurred_at_ms: i64,
    /// Opaque correlation ID.
    pub correlation_id: String,
    /// Opaque causal event ID.
    pub causation_id: Option<String>,
    /// Versioned bounded JSON payload.
    pub payload: serde_json::Value,
    /// Canonical digest of the exact provider-neutral event envelope for citations.
    pub event_digest: String,
}

/// Bounded page returned by timeline query.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelinePageResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Ordered events.
    pub events: Vec<TimelineEvent>,
    /// Highest cursor currently visible.
    pub high_watermark: TimelineCursor,
    /// Whether another bounded page exists.
    pub has_more: bool,
}

/// Wire spelling for schedule downtime behavior.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissedRunPolicyCommand {
    /// Suppress occurrences outside their configured grace window.
    Skip,
    /// Coalesce downtime and admit the latest occurrence once.
    Latest,
}

/// Wire spelling for same-schedule overlap behavior.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleOverlapPolicyCommand {
    /// Admit into the destination session's FIFO queue.
    Queue,
    /// Suppress while an earlier scheduled input remains pending or active.
    SkipIfRunning,
}

/// Strict request to create one recurring agent schedule.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateScheduleRequest {
    /// Semantic API version.
    pub api_version: String,
    /// Client-proposed canonical `UUIDv7` resource identity and durable creation key.
    pub schedule_id: String,
    /// Existing owner-authorized destination session.
    pub session_id: String,
    /// Bounded owner-visible label.
    pub name: String,
    /// Exact input admitted on every fired occurrence.
    pub prompt: String,
    /// Canonical five-field cron expression.
    pub cron_expression: String,
    /// Canonical IANA time-zone identity.
    pub timezone: String,
    /// Explicit daemon-downtime behavior.
    pub missed_run_policy: MissedRunPolicyCommand,
    /// Explicit same-schedule overlap behavior.
    pub overlap_policy: ScheduleOverlapPolicyCommand,
    /// Inclusive lateness accepted by `skip`.
    pub misfire_grace_ms: i64,
    /// Explicit owner opt-in when the prompt begins `/act`, `/edit`, or `/run`.
    pub allow_approval_required_action: bool,
}

/// Public schedule lifecycle spelling.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleStatusResponse {
    /// Due occurrences may be claimed.
    Active,
    /// Claims are suspended.
    Paused,
    /// Schedule is terminally disabled.
    Cancelled,
}

/// Complete owner-authorized schedule projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Stable schedule identity.
    pub schedule_id: String,
    /// Destination session.
    pub session_id: String,
    /// Owner-visible name.
    pub name: String,
    /// Exact scheduled input.
    pub prompt: String,
    /// Canonical cron expression.
    pub cron_expression: String,
    /// Canonical IANA time zone.
    pub timezone: String,
    /// Downtime behavior.
    pub missed_run_policy: MissedRunPolicyCommand,
    /// Overlap behavior.
    pub overlap_policy: ScheduleOverlapPolicyCommand,
    /// Inclusive skip grace.
    pub misfire_grace_ms: i64,
    /// Whether approval-required action prefixes were explicitly authorized.
    pub allow_approval_required_action: bool,
    /// Current lifecycle.
    pub status: ScheduleStatusResponse,
    /// Exact next cron instant, absent after cancellation.
    pub next_due_at_ms: Option<i64>,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// Creation UTC epoch milliseconds.
    pub created_at_ms: i64,
    /// Last update UTC epoch milliseconds.
    pub updated_at_ms: i64,
}

/// Stable schedule list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchedulesResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Definitions in stable creation order.
    pub schedules: Vec<ScheduleResponse>,
}

/// Revision-fenced pause, resume, or cancel request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScheduleLifecycleRequest {
    /// Semantic API version.
    pub api_version: String,
    /// Exact revision last rendered to the owner.
    pub expected_revision: u64,
}

/// Public occurrence lifecycle spelling.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleRunStatusResponse {
    /// One daemon lifetime owns the admission attempt.
    Claimed,
    /// The deterministic input was accepted or already present.
    Admitted,
    /// Misfire or overlap policy suppressed admission.
    Skipped,
    /// A terminal bounded admission failure occurred.
    Failed,
}

/// Crash-stable action chosen before a schedule occurrence claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleRunIntentResponse {
    /// Admit the deterministic scheduled input.
    Fire,
    /// Skip because the latest due instant exceeded grace.
    SkipMisfire,
    /// Skip because an earlier occurrence remained active.
    SkipOverlap,
}

/// One durable schedule occurrence projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleRunResponse {
    /// Stable occurrence-run identity.
    pub schedule_run_id: String,
    /// Owning schedule.
    pub schedule_id: String,
    /// Exact selected cron instant.
    pub scheduled_for_ms: i64,
    /// Whether older due occurrences were coalesced.
    pub coalesced: bool,
    /// Crash-stable action selected before claim.
    pub intent: ScheduleRunIntentResponse,
    /// Current lifecycle.
    pub status: ScheduleRunStatusResponse,
    /// Accepted inbox entry when admitted.
    pub inbox_entry_id: Option<String>,
    /// Bounded skip/failure reason.
    pub reason: Option<String>,
    /// First claim UTC epoch milliseconds.
    pub created_at_ms: i64,
    /// Terminal UTC epoch milliseconds.
    pub completed_at_ms: Option<i64>,
}

/// Bounded newest-first occurrence history response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleRunsResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Stable schedule identity.
    pub schedule_id: String,
    /// Newest-first durable history.
    pub runs: Vec<ScheduleRunResponse>,
}

/// Stable error response safe for local clients.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Stable machine-readable code.
    pub code: String,
    /// Safe human-readable explanation.
    pub message: String,
    /// Whether retry may succeed without changing the request.
    pub retryable: bool,
}

/// Liveness response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Process liveness.
    pub live: bool,
}

/// Readiness response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadinessResponse {
    /// Semantic API version.
    pub api_version: String,
    /// Whether migration/recovery completed and admission is enabled.
    pub ready: bool,
    /// Safe current state explanation.
    pub state: String,
}

#[cfg(test)]
mod tests {
    use super::{
        API_VERSION, ArtifactMetadataResponse, CancelTaskRequest, ContextItemDisposition,
        ContextManifestEvidenceItemResponse, ContextManifestEvidenceResponse,
        CreateDiscordChannelRequest, CreateTelegramChannelRequest, DeliveryMode,
        SubmitInputRequest, TimelineCursor,
    };

    #[test]
    fn submit_input_wire_shape_is_stable_camel_case() {
        let value = serde_json::to_value(SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "delivery-1".to_owned(),
            delivery_mode: DeliveryMode::InterruptThenQueue,
            content: "hello".to_owned(),
        })
        .expect("serialize request");
        assert_eq!(value["apiVersion"], API_VERSION);
        assert_eq!(value["idempotencyKey"], "delivery-1");
        assert_eq!(value["deliveryMode"], "interrupt_then_queue");
    }

    #[test]
    fn telegram_setup_debug_output_redacts_the_bot_token() {
        let request = CreateTelegramChannelRequest {
            api_version: API_VERSION.to_owned(),
            bot_token: "123456:super-secret-telegram-token".to_owned(),
            telegram_user_id: 7,
            telegram_chat_id: 8,
            initial_next_update_id: 0,
        };
        let debug = format!("{request:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn discord_setup_debug_output_redacts_the_bot_token() {
        let request = CreateDiscordChannelRequest {
            api_version: API_VERSION.to_owned(),
            bot_token: "discord.super-secret-token".to_owned(),
            discord_user_id: "7".to_owned(),
            discord_channel_id: "8".to_owned(),
        };
        let debug = format!("{request:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn timeline_cursor_is_an_opaque_json_integer() {
        assert_eq!(
            serde_json::to_string(&TimelineCursor(42)).expect("serialize cursor"),
            "42"
        );
    }

    #[test]
    fn cancellation_command_wire_shape_is_strict_camel_case() {
        let request = CancelTaskRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "cancel-1".to_owned(),
            reason: "no longer needed".to_owned(),
        };
        let value = serde_json::to_value(&request).expect("serialize request");
        assert_eq!(value["apiVersion"], API_VERSION);
        assert_eq!(value["idempotencyKey"], "cancel-1");
        assert_eq!(value["reason"], "no longer needed");

        let unknown_field = serde_json::json!({
            "apiVersion": API_VERSION,
            "idempotencyKey": "cancel-1",
            "reason": "no longer needed",
            "unexpected": true,
        });
        assert!(serde_json::from_value::<CancelTaskRequest>(unknown_field).is_err());
    }

    #[test]
    fn artifact_metadata_wire_shape_never_contains_a_storage_path() {
        let metadata = ArtifactMetadataResponse {
            api_version: API_VERSION.to_owned(),
            artifact_id: "artifact-1".to_owned(),
            algorithm: "sha256".to_owned(),
            digest: "a".repeat(64),
            size_bytes: 42,
            media_type: "text/plain".to_owned(),
            origin_kind: "tool_call".to_owned(),
            origin_id: "tool-1".to_owned(),
            producer_kind: "builtin".to_owned(),
            producer_id: "read_text".to_owned(),
            sensitivity: "private".to_owned(),
            retention_class: "task_history".to_owned(),
            access_policy_digest: "b".repeat(64),
            created_at_ms: 10,
        };
        let value = serde_json::to_value(metadata).expect("serialize artifact metadata");
        assert_eq!(value["artifactId"], "artifact-1");
        assert_eq!(value["sizeBytes"], 42);
        assert!(value.get("relativePath").is_none());
        assert!(value.get("path").is_none());
    }

    #[test]
    fn withheld_context_items_omit_content_fields_on_the_wire() {
        let item = ContextManifestEvidenceItemResponse {
            item_id: "item-1".to_owned(),
            ordinal: 0,
            disposition: ContextItemDisposition::Redacted,
            source_type: "memory".to_owned(),
            source_locator: "memory://private".to_owned(),
            source_content_digest: "a".repeat(64),
            rendered_content_digest: "a".repeat(64),
            inclusion_reason: "withheld".to_owned(),
            sensitivity: "private".to_owned(),
            token_estimate: 10,
            transformation: "identity".to_owned(),
            policy_decision: "redact".to_owned(),
            content: None,
            content_artifact_id: None,
            memory_evidence: None,
            compaction_id: None,
        };
        let response = ContextManifestEvidenceResponse {
            api_version: API_VERSION.to_owned(),
            manifest_id: "manifest-1".to_owned(),
            run_id: "run-1".to_owned(),
            turn_id: "turn-1".to_owned(),
            epoch_id: "epoch-1".to_owned(),
            iteration: 1,
            compiler_version: "v1".to_owned(),
            provider_residency: "local".to_owned(),
            token_budget: 100,
            total_token_estimate: 0,
            tool_schema_set_digest: "b".repeat(64),
            policy_version: "v1".to_owned(),
            projection_digest: "c".repeat(64),
            items: vec![item],
            created_at_ms: 1,
        };
        let value = serde_json::to_value(response).expect("serialize context evidence");
        assert_eq!(value["items"][0]["disposition"], "redacted");
        assert!(value["items"][0].get("content").is_none());
        assert!(value["items"][0].get("contentArtifactId").is_none());
        assert!(!value.to_string().contains("relativePath"));
    }
}
