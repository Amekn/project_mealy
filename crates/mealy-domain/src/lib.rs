//! Pure domain types and lifecycle invariants for Mealy.

mod effect;
mod id;
mod session;
mod task;

pub use effect::{
    EffectError, EffectState, EffectStatus, EffectTransition, IdempotencyClass, RecoveryAction,
};
pub use id::{
    ApprovalId, ArtifactId, AttemptId, ChannelBindingId, ContextManifestId, CorrelationId,
    EffectId, EventId, InboxEntryId, LeaseId, MemoryId, OutboxId, PrincipalId, RunId, SessionId,
    TaskId, ToolCallId, TurnId, ValidationId,
};
pub use session::DeliveryMode;
pub use task::{TaskError, TaskState, TaskStatus, TaskTransition};
