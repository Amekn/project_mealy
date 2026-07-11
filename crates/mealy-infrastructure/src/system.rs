use mealy_application::{Clock, IdGenerator};
use mealy_domain::{
    ApprovalId, ArtifactId, AttemptId, ChannelBindingId, CompactionId, ContextEpochId,
    ContextItemId, ContextManifestId, CorrelationId, DelegationId, EffectId, EventId,
    ExtensionGrantId, ExtensionId, ExtensionInvocationId, InboxEntryId, LeaseId, MemoryId,
    MemoryRevisionId, MessageId, OutboxId, RunId, SessionId, TaskId, ToolCallId, TurnId,
    ValidationId, WorkerId,
};
use std::time::SystemTime;

/// Production wall clock used at application transaction boundaries.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Production `UUIDv7` generator for application-owned session operations.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemIdGenerator;

impl IdGenerator for SystemIdGenerator {
    fn generate_channel_binding_id(&self) -> ChannelBindingId {
        ChannelBindingId::new()
    }

    fn generate_session_id(&self) -> SessionId {
        SessionId::new()
    }

    fn generate_inbox_entry_id(&self) -> InboxEntryId {
        InboxEntryId::new()
    }

    fn generate_event_id(&self) -> EventId {
        EventId::new()
    }

    fn generate_outbox_id(&self) -> OutboxId {
        OutboxId::new()
    }

    fn generate_correlation_id(&self) -> CorrelationId {
        CorrelationId::new()
    }

    fn generate_turn_id(&self) -> TurnId {
        TurnId::new()
    }

    fn generate_task_id(&self) -> TaskId {
        TaskId::new()
    }

    fn generate_run_id(&self) -> RunId {
        RunId::new()
    }

    fn generate_lease_id(&self) -> LeaseId {
        LeaseId::new()
    }

    fn generate_worker_id(&self) -> WorkerId {
        WorkerId::new()
    }

    fn generate_attempt_id(&self) -> AttemptId {
        AttemptId::new()
    }

    fn generate_tool_call_id(&self) -> ToolCallId {
        ToolCallId::new()
    }

    fn generate_artifact_id(&self) -> ArtifactId {
        ArtifactId::new()
    }

    fn generate_context_epoch_id(&self) -> ContextEpochId {
        ContextEpochId::new()
    }

    fn generate_context_manifest_id(&self) -> ContextManifestId {
        ContextManifestId::new()
    }

    fn generate_context_item_id(&self) -> ContextItemId {
        ContextItemId::new()
    }

    fn generate_message_id(&self) -> MessageId {
        MessageId::new()
    }

    fn generate_effect_id(&self) -> EffectId {
        EffectId::new()
    }

    fn generate_approval_id(&self) -> ApprovalId {
        ApprovalId::new()
    }

    fn generate_validation_id(&self) -> ValidationId {
        ValidationId::new()
    }

    fn generate_delegation_id(&self) -> DelegationId {
        DelegationId::new()
    }

    fn generate_memory_id(&self) -> MemoryId {
        MemoryId::new()
    }

    fn generate_memory_revision_id(&self) -> MemoryRevisionId {
        MemoryRevisionId::new()
    }

    fn generate_compaction_id(&self) -> CompactionId {
        CompactionId::new()
    }

    fn generate_extension_id(&self) -> ExtensionId {
        ExtensionId::new()
    }

    fn generate_extension_grant_id(&self) -> ExtensionGrantId {
        ExtensionGrantId::new()
    }

    fn generate_extension_invocation_id(&self) -> ExtensionInvocationId {
        ExtensionInvocationId::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{SystemClock, SystemIdGenerator};
    use mealy_application::{Clock, IdGenerator};

    #[test]
    fn production_adapters_supply_time_and_uuid_v7_ids() {
        let before = std::time::SystemTime::now();
        let now = SystemClock.now();
        let after = std::time::SystemTime::now();
        assert!(now >= before && now <= after);

        let first = SystemIdGenerator.generate_session_id();
        let second = SystemIdGenerator.generate_session_id();
        assert_ne!(first, second);
        assert_eq!(first.as_uuid().get_version_num(), 7);
        assert_eq!(second.as_uuid().get_version_num(), 7);
    }
}
