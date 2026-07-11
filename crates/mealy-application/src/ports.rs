use mealy_domain::{
    ApprovalId, ArtifactId, AttemptId, ChannelBindingId, CompactionId, ContextEpochId,
    ContextItemId, ContextManifestId, CorrelationId, DelegationId, EffectId, EventId,
    ExtensionGrantId, ExtensionId, ExtensionInvocationId, InboxEntryId, LeaseId, MemoryId,
    MemoryRevisionId, MessageId, OutboxId, RunId, SessionId, TaskId, ToolCallId, TurnId,
    ValidationId, WorkerId,
};
use std::time::SystemTime;

/// Supplies wall-clock time to use cases without hiding nondeterminism in domain logic.
pub trait Clock {
    /// Returns the current wall-clock instant.
    fn now(&self) -> SystemTime;
}

/// Supplies typed identifiers to use cases.
pub trait IdGenerator {
    /// Generates a verified external channel-binding identifier.
    fn generate_channel_binding_id(&self) -> ChannelBindingId;

    /// Generates a new session identifier.
    fn generate_session_id(&self) -> SessionId;

    /// Generates a new durable inbox-entry identifier.
    fn generate_inbox_entry_id(&self) -> InboxEntryId;

    /// Generates a new journal-event identifier.
    fn generate_event_id(&self) -> EventId;

    /// Generates a new durable outbox identifier.
    fn generate_outbox_id(&self) -> OutboxId;

    /// Generates a new command/event correlation identifier.
    fn generate_correlation_id(&self) -> CorrelationId;

    /// Generates a promoted turn identifier.
    fn generate_turn_id(&self) -> TurnId;

    /// Generates a task identifier.
    fn generate_task_id(&self) -> TaskId;

    /// Generates an agent-run identifier.
    fn generate_run_id(&self) -> RunId;

    /// Generates a work-lease identifier.
    fn generate_lease_id(&self) -> LeaseId;

    /// Generates a scheduler-worker identifier.
    fn generate_worker_id(&self) -> WorkerId;

    /// Generates a model/tool attempt ID.
    fn generate_attempt_id(&self) -> AttemptId;

    /// Generates a normalized tool-call ID.
    fn generate_tool_call_id(&self) -> ToolCallId;

    /// Generates an immutable artifact metadata ID.
    fn generate_artifact_id(&self) -> ArtifactId;

    /// Generates a context epoch ID.
    fn generate_context_epoch_id(&self) -> ContextEpochId;

    /// Generates a context manifest ID.
    fn generate_context_manifest_id(&self) -> ContextManifestId;

    /// Generates a context item ID.
    fn generate_context_item_id(&self) -> ContextItemId;

    /// Generates a provider-neutral durable message ID.
    fn generate_message_id(&self) -> MessageId;

    /// Generates a durable effect intent ID.
    fn generate_effect_id(&self) -> EffectId;

    /// Generates an authenticated approval request ID.
    fn generate_approval_id(&self) -> ApprovalId;

    /// Generates an independent validation record ID.
    fn generate_validation_id(&self) -> ValidationId;

    /// Generates a parent-to-child delegation contract ID.
    fn generate_delegation_id(&self) -> DelegationId;

    /// Generates a governed memory identity.
    fn generate_memory_id(&self) -> MemoryId;

    /// Generates an immutable memory revision identity.
    fn generate_memory_revision_id(&self) -> MemoryRevisionId;

    /// Generates a derived compaction identity.
    fn generate_compaction_id(&self) -> CompactionId;

    /// Generates an installed extension identity.
    fn generate_extension_id(&self) -> ExtensionId;

    /// Generates an immutable extension grant identity.
    fn generate_extension_grant_id(&self) -> ExtensionGrantId;

    /// Generates a bounded extension invocation identity.
    fn generate_extension_invocation_id(&self) -> ExtensionInvocationId;
}
