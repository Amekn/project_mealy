//! Pure domain types and lifecycle invariants for Mealy.

mod approval;
mod compaction;
mod delegation;
mod effect;
mod extension;
mod id;
mod memory;
mod policy;
mod scheduler;
mod session;
mod skill;
mod task;
mod tool;
mod validation;

pub use approval::{ApprovalDecision, ApprovalStatus};
pub use compaction::{
    CitedCompactionItem, CompactedApproval, CompactedEffect, CompactionCarryForward,
    CompactionCitation, CompactionError, CompactionRecord, CompactionSourceRange,
};
pub use delegation::{CapabilityGrant, CapabilityGrantError};
pub use effect::{
    EffectError, EffectState, EffectStatus, EffectTransition, IdempotencyClass, RecoveryAction,
};
pub use extension::{
    EXTENSION_MANIFEST_SCHEMA_VERSION, ExtensionCapabilityKind, ExtensionCapabilityManifest,
    ExtensionCompatibility, ExtensionEntryPoint, ExtensionError, ExtensionFieldSchema,
    ExtensionFilesystemAccess, ExtensionFilesystemPermission, ExtensionHealthCheck, ExtensionKind,
    ExtensionManifest, ExtensionMigration, ExtensionObjectSchema, ExtensionPermissions,
    ExtensionRuntimeFile, ExtensionScalarType, ExtensionShutdownBehavior, ExtensionShutdownMode,
    ExtensionState, ExtensionStatus, ExtensionTransition,
};
pub use id::{
    ApprovalId, ArtifactId, AttemptId, ChannelBindingId, CompactionId, ContextEpochId,
    ContextItemId, ContextManifestId, CorrelationId, DelegationId, EffectId, EventId,
    ExtensionGrantId, ExtensionId, ExtensionInvocationId, InboxEntryId, LeaseId, MemoryId,
    MemoryRevisionId, MessageId, OutboxId, PrincipalId, RunId, ScheduleId, ScheduleRunId,
    SessionId, TaskId, ToolCallId, TurnId, ValidationId, WorkerId,
};
pub use memory::{
    MemoryCategory, MemoryConfidence, MemoryError, MemoryMetadata, MemoryNamespace,
    MemoryPromotionAuthorization, MemoryProvenance, MemoryRetention, MemorySensitivity,
    MemoryState, MemoryStatus, MemoryTransition,
};
pub use policy::PolicyProfile;
pub use scheduler::{FencingToken, LeaseError, LeaseFence, LeaseStatus, TurnStatus, WorkLease};
pub use session::DeliveryMode;
pub use skill::{
    SKILL_MANIFEST_CONTRACT_VERSION, SkillAsset, SkillManifest, SkillManifestError,
    SkillToolRequirement,
};
pub use task::{TaskError, TaskState, TaskStatus, TaskTransition};
pub use tool::{EffectClass, ExecutorKind, ExecutorKindError, RecoveryStrategy, RiskClass};
pub use validation::{
    SuccessCriterion, TaskSuccessCriteria, ValidationContractError, ValidationMethod,
    ValidationOutcome,
};
