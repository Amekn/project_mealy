//! Application use cases and infrastructure ports.

mod agent;
mod agent_effect;
mod approval;
mod artifact;
mod browser;
mod channel;
mod compaction;
mod context;
mod daemon_config;
mod delegation;
mod digest;
mod discord;
mod effect_ledger;
mod executor;
mod extension;
mod fixture_write;
mod mcp;
mod memory;
mod operations;
mod outbox;
mod policy;
mod ports;
mod process_run;
mod promotion;
mod provider;
mod provider_config;
mod recovery;
mod schedule;
mod scheduler;
mod sessions;
mod startup;
mod telegram;
mod timeline;
mod tools;
mod validation;
mod web_config;
mod workspace_create;
mod workspace_manage;

pub use agent::{
    AgentArtifactCommit, AgentBudgetUsage, AgentContextSource, AgentEvidenceStore,
    AgentExecutionStore, AgentLoopLimits, AgentNextAction, AgentReplayReport, AgentRunSnapshot,
    AgentStoreError, AgentTaskView, AgentUseCaseError, DispatchModelAttemptCommit,
    DispatchReadToolCommit, FinalMessageCommit, MAXIMUM_MODEL_PROGRESS_BYTES,
    MAXIMUM_MODEL_PROGRESS_DELTA_BYTES, MAXIMUM_MODEL_PROGRESS_EVENTS, ModelDispatchReceipt,
    ModelFailureReceipt, PrepareModelAttemptCommit, PrepareReadToolCommit,
    RecordModelFailureCommit, RecordModelProgressCommit, RecordModelResultCommit,
    RecordReadToolResultCommit, RequestTaskCancellationCommit, TaskCancellationCommitReceipt,
    TaskControlAction, TaskControlCommit, TaskControlCommitReceipt, bounded_deadline,
    checked_usage_total, provider_retry_delay, validate_tool_result,
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
pub use browser::{
    BROWSER_CDP_PROTOCOL_VERSION, BROWSER_MAXIMUM_BUNDLE_BYTES, BROWSER_MAXIMUM_BUNDLE_FILE_BYTES,
    BROWSER_MAXIMUM_BUNDLE_FILES, BROWSER_SNAPSHOT_TOOL_ID, BrowserConfig, BrowserConfigError,
    BrowserElementTarget, BrowserFillTarget, BrowserLinkTarget, BrowserSnapshotRequest,
    browser_maximum_screenshot_bytes, browser_snapshot_descriptor,
    validate_browser_snapshot_arguments,
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
pub use daemon_config::{DAEMON_CONFIG_FORMAT_VERSION, default_daemon_config_document};
pub use delegation::{
    AGENT_DELEGATE_RESULT_LOCATOR, AGENT_DELEGATE_TOOL_ID, AcquireResourceClaimCommit,
    AgentDelegationRequest, DELEGATION_CONTRACT_VERSION, DelegationStore, DelegationView,
    LaunchAgentDelegationCommit, MAXIMUM_DELEGATION_CONTEXT_BYTES, MAXIMUM_DELEGATION_CRITERIA,
    MAXIMUM_DELEGATION_INSTRUCTION_BYTES, MAXIMUM_DELEGATION_OBJECTIVE_BYTES,
    PrepareDelegationCommit, RecordDelegationResultCommit, ResourceClass, StartDelegationCommit,
    agent_delegate_tool_descriptor, validate_delegation_commit,
};
pub use digest::{SHA256_ALGORITHM, SHA256_DIGEST_HEX_LENGTH, is_sha256_digest, sha256_digest};
pub use discord::{
    CompleteDiscordMessageCommit, DISCORD_MAXIMUM_BOT_USERNAME_BYTES,
    DISCORD_MAXIMUM_ERROR_CODE_BYTES, DISCORD_MAXIMUM_IGNORE_REASON_BYTES,
    DiscordChannelBindingView, DiscordChannelStatus, DiscordChannelStore, DiscordChannelStoreError,
    DiscordMessageDisposition, DiscordMessageReservation, DiscordPollTarget, OutboundDiscordTarget,
    RecordDiscordPollCommit, RegisterDiscordChannelCommit, ReserveDiscordMessageCommit,
    RevokeDiscordChannelCommit, discord_input_dedupe_key, validate_discord_binding,
    validate_discord_snowflake,
};
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
pub use mcp::{
    MCP_MAXIMUM_ARGUMENTS, MCP_MAXIMUM_DEFINITION_BYTES, MCP_MAXIMUM_SERVERS,
    MCP_MAXIMUM_TOOLS_PER_SERVER, MCP_PROTOCOL_VERSION, McpConfigError, McpServerConfig,
    McpServerDiscovery, McpToolGrant, McpToolInspection, mcp_read_tool_descriptor,
    mcp_tool_definition_digest, validate_mcp_server_set, validate_mcp_tool_arguments,
};
pub use memory::{
    CorrectMemoryCommit, DeleteMemoryCommit, ExpireMemoryCommit, MEMORY_POLICY_VERSION,
    MemoryIndexRebuildReceipt, MemoryRevisionView, MemorySearchHit, MemorySearchQuery,
    MemorySource, MemoryStore, MemoryStoreError, MemoryView, PromoteMemoryCommit,
    ProposeMemoryCommit, RejectMemoryCommit, SetMemoryPinCommit, memory_context_locator,
    memory_event_cursor, validate_memory_proposal, validate_memory_search, validate_sources,
};

pub use operations::{
    BeginDaemonRunCommit, CompleteDaemonRunCommit, CompletedUsageBucket, CompletedUsageReport,
    DaemonRunStatus, OperationalFailure, OperationalSnapshot, OperationalStore,
    OperationalStoreError, ProviderEndpointHistory,
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
pub use process_run::{
    PROCESS_RUN_CAPABILITY, PROCESS_RUN_INPUT_PREFIX, PROCESS_RUN_OPERATION,
    PROCESS_RUN_POLICY_VERSION, PROCESS_RUN_TOOL_ID, ProcessRunArgumentError,
    ProcessRunContractError, ProcessRunDispatch, ProcessRunPolicyGrant,
    build_process_run_executor_request, evaluate_process_run_policy,
    normalize_process_run_arguments, process_run_approval_subject, process_run_descriptor,
};
pub use promotion::{
    InboxPromotionStore, InitialTaskContract, InitialTaskProfile, InterruptionReceipt,
    PromotionCandidate, PromotionCommit, PromotionDefaults, PromotionOutcome, PromotionReceipt,
    PromotionStoreError, PromotionUseCaseError, SteeringReceipt, initial_task_contract,
    initial_task_contract_for_profile, pending_promotion_sessions, promote_next_input,
    valid_general_assistant_capability_ceiling,
};
pub use provider::{
    CancellationProbe, CapabilityRequirement, DIRECT_PROVIDER_INPUT_TOKEN_OVERHEAD, MessageRole,
    ModelProvider, ModelUsage, NormalizedMessage, ProviderCapabilities, ProviderError,
    ProviderErrorClass, ProviderFailureDisposition, ProviderFallbackPolicy, ProviderLocality,
    ProviderOutput, ProviderPricing, ProviderProgress, ProviderProgressSink, ProviderRequest,
    ProviderResponse, ProviderRouteCandidate, ProviderRoutePlan, ProviderRoutingError,
    ProviderRoutingPolicy, ProviderToolDefinition, route_provider,
};
pub use provider_config::{
    MAXIMUM_PROVIDER_CREDENTIAL_BYTES, MAXIMUM_PROVIDER_FALLBACKS, ProviderConfig,
    ProviderConfigError, ProviderCredentialReference, SubscriptionCliClient,
    valid_provider_secret_id, validate_provider_base_url, validate_provider_chain,
};
pub use recovery::{RecoveryPlan, plan_interrupted_effect};
pub use schedule::{
    ClaimScheduleRunCommit, CompleteScheduleRunCommit, CreateScheduleCommit,
    MAXIMUM_CRON_EXPRESSION_BYTES, MAXIMUM_MISFIRE_GRACE_MS, MAXIMUM_SCHEDULE_NAME_BYTES,
    MAXIMUM_SCHEDULE_PROMPT_BYTES, MAXIMUM_TIMEZONE_BYTES, MissedRunPolicy, ScheduleClaimOutcome,
    ScheduleContractError, ScheduleDefinition, ScheduleDueDecision, ScheduleOverlapPolicy,
    ScheduleRunIntent, ScheduleRunStatus, ScheduleRunView, ScheduleStatus, ScheduleStore,
    ScheduleStoreError, ScheduleTransition, ScheduleView, TransitionScheduleCommit,
    next_schedule_occurrence_ms, plan_due_schedule, validate_schedule_definition,
    validate_schedule_view,
};
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
pub use telegram::{
    CompleteTelegramUpdateCommit, OutboundTelegramTarget, RecordTelegramPollCommit,
    RegisterTelegramChannelCommit, ReserveTelegramUpdateCommit, RevokeTelegramChannelCommit,
    TELEGRAM_MAXIMUM_BOT_USERNAME_BYTES, TELEGRAM_MAXIMUM_ERROR_CODE_BYTES,
    TELEGRAM_MAXIMUM_IGNORE_REASON_BYTES, TelegramChannelBindingView, TelegramChannelStatus,
    TelegramChannelStore, TelegramChannelStoreError, TelegramPollTarget, TelegramUpdateDisposition,
    TelegramUpdateReservation, telegram_input_dedupe_key, validate_telegram_binding,
};
pub use timeline::{
    SESSION_SEARCH_MAXIMUM_EXCERPT_BYTES, SessionSearchHitView, SessionSearchQuery,
    SessionStatusView, SessionSummaryView, TimelineCursor, TimelineEvent, TimelinePage,
    TimelineQuery, TimelineStore, TimelineStoreError, TimelineUseCaseError, query_session_status,
    query_sessions, query_timeline, search_sessions, session_search_excerpt,
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
pub use web_config::{
    WebAccessConfig, WebAccessConfigError, WebSearchConfig, web_url_authorized_by_capabilities,
};
pub use workspace_create::{
    WORKSPACE_ACTION_INPUT_PREFIX, WORKSPACE_CREATE_CAPABILITY, WORKSPACE_CREATE_FILE_OPERATION,
    WORKSPACE_CREATE_FILE_TOOL_ID, WORKSPACE_CREATE_MAXIMUM_CONTENT_CHARACTERS,
    WORKSPACE_CREATE_POLICY_VERSION, WORKSPACE_EDIT_INPUT_PREFIX, WORKSPACE_REPLACE_CAPABILITY,
    WORKSPACE_REPLACE_FILE_OPERATION, WORKSPACE_REPLACE_FILE_TOOL_ID,
    WORKSPACE_REPLACE_MAXIMUM_EDIT_TEXT_CHARACTERS, WORKSPACE_REPLACE_MAXIMUM_EDITS,
    WORKSPACE_REPLACE_MAXIMUM_EXPECTED_OCCURRENCES, WORKSPACE_REPLACE_POLICY_VERSION,
    WorkspaceCreateArgumentError, WorkspaceCreateContractError, WorkspaceCreateDispatch,
    WorkspaceCreatePolicyGrant, WorkspaceReplaceArgumentError, WorkspaceReplaceContractError,
    WorkspaceReplaceDispatch, WorkspaceReplacePolicyGrant, build_workspace_create_executor_request,
    build_workspace_replace_executor_request, evaluate_workspace_create_policy,
    evaluate_workspace_replace_policy, normalize_workspace_create_file_arguments,
    normalize_workspace_replace_file_arguments, workspace_create_approval_subject,
    workspace_create_file_descriptor, workspace_replace_approval_subject,
    workspace_replace_file_descriptor,
};
pub use workspace_manage::{
    WORKSPACE_CREATE_DIRECTORY_OPERATION, WORKSPACE_MANAGE_CAPABILITY,
    WORKSPACE_MANAGE_INPUT_PREFIX, WORKSPACE_MANAGE_PATH_TOOL_ID, WORKSPACE_MANAGE_POLICY_VERSION,
    WORKSPACE_MOVE_FILE_OPERATION, WORKSPACE_REMOVE_EMPTY_DIRECTORY_OPERATION,
    WORKSPACE_REMOVE_FILE_OPERATION, WorkspaceManageArgumentError, WorkspaceManageContractError,
    WorkspaceManageDispatch, WorkspaceManagePolicyGrant, build_workspace_manage_executor_request,
    evaluate_workspace_manage_policy, normalize_workspace_manage_path_arguments,
    workspace_manage_approval_subject, workspace_manage_path_descriptor,
};
