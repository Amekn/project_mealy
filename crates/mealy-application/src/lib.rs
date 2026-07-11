//! Application use cases and infrastructure ports.

mod agent;
mod agent_effect;
mod approval;
mod artifact;
mod channel;
mod compaction;
mod context;
mod delegation;
mod digest;
mod effect_ledger;
mod executor;
mod extension;
mod fixture_write;
mod memory;
mod operations;
mod outbox;
mod policy;
mod ports;
mod promotion;
mod provider;
mod recovery;
mod scheduler;
mod sessions;
mod startup;
mod timeline;
mod tools;
mod validation;

pub use agent::{
    AgentArtifactCommit, AgentBudgetUsage, AgentContextSource, AgentEvidenceStore,
    AgentExecutionStore, AgentLoopLimits, AgentNextAction, AgentReplayReport, AgentRunSnapshot,
    AgentStoreError, AgentTaskView, AgentUseCaseError, DispatchModelAttemptCommit,
    DispatchReadToolCommit, FinalMessageCommit, PrepareModelAttemptCommit, PrepareReadToolCommit,
    RecordModelResultCommit, RecordReadToolResultCommit, RequestTaskCancellationCommit,
    TaskCancellationCommitReceipt, TaskControlAction, TaskControlCommit, TaskControlCommitReceipt,
    bounded_deadline, checked_usage_total, validate_tool_result,
};
pub use agent_effect::{
    AGENT_EFFECT_OBSERVATION_CONTRACT_VERSION, AgentEffectInvocation,
    AgentEffectObservationReceipt, AgentEffectStore, ParkAgentEffectRunCommit,
    RecordAgentEffectObservationCommit, RecordAgentEffectProposalCommit,
    ResumeAgentEffectRunCommit,
};
pub use approval::{
    APPROVAL_SUBJECT_CONTRACT_VERSION, ApprovalSubject, ApprovalSubjectError,
    EFFECT_IDEMPOTENCY_KEY_PREFIX, canonical_arguments_digest, derive_effect_idempotency_key,
};

pub use artifact::{
    ArtifactBlobStore, ArtifactBlobStoreError, ArtifactContentDescriptor, ArtifactEvidenceStore,
    ArtifactEvidenceStoreError, ArtifactMetadata, CommittedArtifactBlob,
};
pub use channel::{
    CompleteWebhookDeliveryCommit, OutboundWebhookTarget, RegisterWebhookChannelCommit,
    ReserveWebhookDeliveryCommit, RevokeWebhookChannelCommit, WEBHOOK_MAXIMUM_CLOCK_SKEW,
    WEBHOOK_MAXIMUM_DELIVERY_ID_BYTES, WEBHOOK_MAXIMUM_NONCE_BYTES, WEBHOOK_SIGNATURE_ALGORITHM,
    WEBHOOK_SIGNATURE_VERSION, WEBHOOK_SIGNING_SECRET_BYTES, WebhookChannelBindingView,
    WebhookChannelStatus, WebhookChannelStore, WebhookChannelStoreError,
    WebhookDeliveryReservation, WebhookSignatureError, sign_webhook,
    validate_webhook_binding_fields, validate_webhook_timestamp, verify_webhook_signature,
    webhook_input_dedupe_key, webhook_signature_digest,
};
pub use compaction::{
    COMPACTION_PROMPT_VERSION, CommitCompaction, CompactionSourceEvent, CompactionSourceSnapshot,
    CompactionStore, CompactionStoreError, CompactionView, compaction_citations,
    compaction_source_event_digest, validate_compaction_commit,
};
pub use context::{
    CompiledContext, ContextDisposition, ContextEpoch, ContextError, ContextManifest,
    ContextManifestEvidence, ContextManifestEvidenceItem, ContextManifestEvidenceStore,
    ContextManifestEvidenceStoreError, ContextManifestItem, ContextMemoryEvidence,
    ContextMemorySourceCitation, compile_context, estimate_tokens, validate_context_manifest,
    validate_context_manifest_evidence,
};
pub use delegation::{
    AcquireResourceClaimCommit, DELEGATION_CONTRACT_VERSION, DelegationStore, DelegationView,
    PrepareDelegationCommit, RecordDelegationResultCommit, ResourceClass, StartDelegationCommit,
    validate_delegation_commit,
};
pub use digest::{SHA256_ALGORITHM, SHA256_DIGEST_HEX_LENGTH, is_sha256_digest, sha256_digest};
pub use effect_ledger::{
    APPROVAL_RESOLUTION_REQUEST_CONTRACT_VERSION, ApprovalRequestDraft, ApprovalRequestView,
    ApprovalResolutionReceipt, EFFECT_INTENT_CONTRACT_VERSION,
    EFFECT_OUTCOME_EVIDENCE_CONTRACT_VERSION, EFFECT_RECONCILIATION_REQUEST_CONTRACT_VERSION,
    EffectAttemptBoundary, EffectAttemptOutcome, EffectAttemptState, EffectAttemptView,
    EffectCommandRequestError, EffectLedgerStore, EffectLedgerStoreError, EffectLedgerView,
    EffectOutcomeEvidenceError, EffectOutcomeKind, EffectOutcomeView, EffectReconciliationOutcome,
    EffectReconciliationReceipt, EffectRecoveryCandidate, EffectRecoveryDisposition,
    ExpireApprovalCommit, INTERRUPTED_EFFECT_OUTCOME_CLASSIFICATION,
    INTERRUPTED_EFFECT_OUTCOME_ERROR_CLASS, INTERRUPTED_EFFECT_RETRY_CLASSIFICATION,
    INTERRUPTED_EFFECT_RETRY_ERROR_CLASS, INTERRUPTED_EFFECT_UNDISPATCHED_CLASSIFICATION,
    INTERRUPTED_EFFECT_UNDISPATCHED_ERROR_CLASS, MAXIMUM_EFFECT_COMMAND_IDEMPOTENCY_KEY_BYTES,
    MAXIMUM_EFFECT_OUTCOME_DETAILS_BYTES, MarkEffectAttemptRunningCommit,
    PrepareEffectAttemptCommit, ReconcileEffectOutcomeCommit, RecordEffectAttemptOutcomeCommit,
    RecordEffectProposalCommit, RecoverInterruptedEffectCommit, ResolveApprovalCommit,
    approval_resolution_request_digest, approval_resolution_request_material, effect_intent_digest,
    effect_intent_material, effect_outcome_evidence_digest, effect_outcome_evidence_material,
    effect_reconciliation_request_digest, effect_reconciliation_request_material,
};
pub use executor::{
    EXECUTOR_PROTOCOL_VERSION, ExecutorError, ExecutorFrame, ExecutorMount, ExecutorProtocolError,
    ExecutorRequest, ExecutorRequestError, ExecutorResult, ExecutorTerminal, SandboxExecutor,
};
pub use extension::{
    BeginExtensionInvocationCommit, CompleteExtensionInvocationCommit, DisableExtensionCommit,
    EXTENSION_HOST_API_VERSION, EXTENSION_MANIFEST_MAXIMUM_BYTES, EXTENSION_POLICY_VERSION,
    EXTENSION_RPC_VERSION, EnableExtensionCommit, ExtensionDispatchRequest, ExtensionGrant,
    ExtensionGrantError, ExtensionHost, ExtensionHostError, ExtensionInvocationStatus,
    ExtensionInvocationTerminal, ExtensionInvocationView, ExtensionManifestInspection,
    ExtensionManifestInspectionError, ExtensionManifestRevisionView, ExtensionMountGrant,
    ExtensionRecoveryError, ExtensionRpcError, ExtensionRpcRequest, ExtensionRpcResponse,
    ExtensionStore, ExtensionStoreError, ExtensionView, InstallExtensionCommit,
    RevokeExtensionCommit, StageExtensionManifestCommit, extension_grant_digest,
    inspect_extension_manifest, recover_extension_invocations, validate_extension_object,
};
pub use fixture_write::{
    FIXTURE_WRITE_CAPABILITY, FIXTURE_WRITE_FILE_OPERATION, FIXTURE_WRITE_FILE_TOOL_ID,
    FIXTURE_WRITE_INPUT_PREFIX, FIXTURE_WRITE_MAXIMUM_CONTENT_CHARACTERS,
    FIXTURE_WRITE_MAXIMUM_DURATION_MS, FIXTURE_WRITE_MAXIMUM_MEMORY_BYTES,
    FIXTURE_WRITE_MAXIMUM_OUTPUT_BYTES, FIXTURE_WRITE_SANDBOX_ROOT, FixtureWriteArgumentError,
    FixtureWriteContractError, FixtureWriteDispatch, FixtureWritePolicyGrant,
    build_fixture_write_executor_request, evaluate_fixture_write_policy,
    fixture_write_approval_subject, fixture_write_file_descriptor,
    normalize_fixture_write_file_arguments,
};
pub use memory::{
    CorrectMemoryCommit, DeleteMemoryCommit, ExpireMemoryCommit, MEMORY_POLICY_VERSION,
    MemoryIndexRebuildReceipt, MemoryRevisionView, MemorySearchHit, MemorySearchQuery,
    MemorySource, MemoryStore, MemoryStoreError, MemoryView, PromoteMemoryCommit,
    ProposeMemoryCommit, RejectMemoryCommit, SetMemoryPinCommit, memory_context_locator,
    memory_event_cursor, validate_memory_proposal, validate_memory_search, validate_sources,
};

pub use operations::{
    BeginDaemonRunCommit, CompleteDaemonRunCommit, DaemonRunStatus, OperationalFailure,
    OperationalSnapshot, OperationalStore, OperationalStoreError,
};
pub use outbox::{
    CompleteOutboxCommit, OutboxClaimCommit, OutboxClaimOutcome, OutboxDelivery,
    OutboxDeliveryStore, OutboxStoreError, OutboxUseCaseError, RetryOutboxCommit,
    claim_next_outbox, complete_outbox, exponential_retry_delay, retry_outbox,
};
pub use policy::{
    FIXTURE_POLICY_VERSION, FixturePolicyGrant, PolicyDecision, PolicyEvaluation,
    PolicyObligations, PolicyRequest, PolicyRequestError, evaluate_fixture_policy,
};
pub use ports::{Clock, IdGenerator};
pub use promotion::{
    InboxPromotionStore, InitialTaskContract, InterruptionReceipt, PromotionCandidate,
    PromotionCommit, PromotionDefaults, PromotionOutcome, PromotionReceipt, PromotionStoreError,
    PromotionUseCaseError, SteeringReceipt, initial_task_contract, pending_promotion_sessions,
    promote_next_input,
};
pub use provider::{
    CancellationProbe, CapabilityRequirement, MessageRole, ModelProvider, ModelUsage,
    NormalizedMessage, ProviderCapabilities, ProviderError, ProviderErrorClass,
    ProviderFallbackPolicy, ProviderLocality, ProviderOutput, ProviderPricing, ProviderRequest,
    ProviderResponse, ProviderRouteCandidate, ProviderRoutePlan, ProviderRoutingError,
    ProviderRoutingPolicy, ProviderToolDefinition, route_provider,
};
pub use recovery::{RecoveryPlan, plan_interrupted_effect};
pub use scheduler::{
    CompleteRunCommit, HeartbeatCommit, LeaseClaimCommit, LeaseClaimOutcome, LeaseClaimReceipt,
    LeaseConcurrencyLimits, LeaseLimits, LeaseReleaseReason, ReleaseLeaseCommit,
    RunCompletionReceipt, RunCompletionStatus, SchedulerStore, SchedulerStoreError,
    SchedulerUseCaseError, claim_next_work, claim_next_work_with_concurrency, claimed_run_id,
    complete_agent_run, complete_run, heartbeat_lease, release_lease,
};
pub use sessions::{
    AdmitInputCommand, InputAdmissionCommit, InputAdmissionLimits, InputAdmissionOutcome,
    InputAdmissionReceipt, OwnershipContext, SessionCreationCommit, SessionStore,
    SessionStoreError, SessionUseCaseError, admit_input, create_session,
};
pub use startup::{
    LeaseRecoveryEventIds, StartupRecoveryBatch, StartupRecoveryCommit, StartupRecoveryError,
    StartupRecoveryStore, StartupRecoveryStoreError, StartupRecoverySummary,
    recover_expired_leases, recover_startup,
};
pub use timeline::{
    SessionStatusView, TimelineCursor, TimelineEvent, TimelinePage, TimelineQuery, TimelineStore,
    TimelineStoreError, TimelineUseCaseError, query_session_status, query_timeline,
};
pub use tools::{
    ReadOnlyTool, ReadToolDescriptor, ReadToolError, ReadToolOutput,
    TOOL_DESCRIPTOR_CONTRACT_VERSION, ToolConcurrency, ToolDescriptor, ToolDescriptorEvidenceError,
    ToolDescriptorValidationError, validate_fixture_read_arguments,
};
pub use validation::{
    RecordValidationCommit, TaskSuccessCriteriaView, VALIDATION_POLICY_VERSION,
    ValidationContextDraft, ValidationRecordView, ValidationStore, validate_validation_commit,
};
