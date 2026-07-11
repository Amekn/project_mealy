use crate::{AgentLoopLimits, AgentStoreError, OwnershipContext};
use mealy_domain::{
    CapabilityGrant, CorrelationId, DelegationId, EventId, LeaseFence, LeaseId, RunId, TaskId,
    TaskSuccessCriteria, WorkerId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::SystemTime;

/// Stable contract version for delegated work packages.
pub const DELEGATION_CONTRACT_VERSION: &str = "mealy.delegation.v1";

/// Conflict domain protected by one exclusive resource claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceClass {
    /// Canonical workspace mutation scope.
    WorkspaceWrite,
    /// Named external service mutation scope.
    ServiceMutation,
    /// Governed memory namespace.
    MemoryNamespace,
    /// Exclusive local device.
    Device,
}

impl ResourceClass {
    /// Stable storage spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkspaceWrite => "workspace_write",
            Self::ServiceMutation => "service_mutation",
            Self::MemoryNamespace => "memory_namespace",
            Self::Device => "device",
        }
    }
}

/// Complete bounded delegation contract proposed under a parent fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareDelegationCommit {
    /// Exact live parent ownership.
    pub parent_fence: LeaseFence,
    /// Stable delegation identity.
    pub delegation_id: DelegationId,
    /// Fresh child task.
    pub child_task_id: TaskId,
    /// Fresh child run.
    pub child_run_id: RunId,
    /// Self-contained work order.
    pub work_order: Value,
    /// Explicit child success criteria.
    pub success_criteria: TaskSuccessCriteria,
    /// Bounded context package; never the parent's implicit full history.
    pub context_package: Value,
    /// Child authority requested by the parent.
    pub requested_capabilities: CapabilityGrant,
    /// Current policy ceiling independently intersected with parent authority.
    pub policy_capabilities: CapabilityGrant,
    /// Separate child execution budget.
    pub child_budget: AgentLoopLimits,
    /// Delegation journal event.
    pub event_id: EventId,
    /// Commit time.
    pub prepared_at: SystemTime,
}

/// Fenced acquisition of one exclusive conflict key by a child run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquireResourceClaimCommit {
    /// Exact child worker ownership.
    pub fence: LeaseFence,
    /// Owning delegation.
    pub delegation_id: DelegationId,
    /// Stable claim identity.
    pub claim_id: EventId,
    /// Conflict domain.
    pub resource_class: ResourceClass,
    /// Canonical exact resource key.
    pub resource_key: String,
    /// Claim journal event.
    pub event_id: EventId,
    /// End-to-end trace correlation.
    pub correlation_id: CorrelationId,
    /// Acquisition time.
    pub acquired_at: SystemTime,
}

/// Starts one queued child under a fresh durable lease and fencing token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartDelegationCommit {
    /// Delegation whose child becomes active.
    pub delegation_id: DelegationId,
    /// Fresh child lease identity.
    pub lease_id: LeaseId,
    /// Child worker identity.
    pub owner_id: WorkerId,
    /// Child start journal event.
    pub event_id: EventId,
    /// End-to-end trace correlation.
    pub correlation_id: CorrelationId,
    /// Lease acquisition time.
    pub started_at: SystemTime,
    /// Exclusive lease expiry.
    pub expires_at: SystemTime,
}

/// Fenced terminal child result and resource-release boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordDelegationResultCommit {
    /// Exact child lease; superseded workers cannot commit.
    pub child_fence: LeaseFence,
    /// Owning delegation.
    pub delegation_id: DelegationId,
    /// Structured result returned to the parent.
    pub result: Value,
    /// Whether the child established its own criteria.
    pub succeeded: bool,
    /// Delegation result journal event.
    pub event_id: EventId,
    /// End-to-end trace correlation.
    pub correlation_id: CorrelationId,
    /// Result time.
    pub completed_at: SystemTime,
}

/// Durable delegation projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationView {
    /// Stable delegation identity.
    pub delegation_id: DelegationId,
    /// Parent run.
    pub parent_run_id: RunId,
    /// Child task.
    pub child_task_id: TaskId,
    /// Child run.
    pub child_run_id: RunId,
    /// Effective child authority.
    pub effective_capabilities: CapabilityGrant,
    /// Separate child budget.
    pub child_budget: AgentLoopLimits,
    /// Queued/running/terminal state.
    pub state: String,
    /// Structured terminal result.
    pub result: Option<Value>,
}

/// Durable delegation and resource-ownership port.
pub trait DelegationStore {
    /// Atomically creates child task/run lineage, exact authority intersection, separate budget,
    /// context package, and parent delegated-run reservation.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for stale parent ownership, widened capabilities, exhausted
    /// delegation budget, malformed packages, or storage failure.
    fn prepare_delegation(
        &mut self,
        commit: PrepareDelegationCommit,
    ) -> Result<DelegationView, AgentStoreError>;

    /// Starts one queued child under a fresh lease.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for a non-queued child, invalid expiry, or storage failure.
    fn start_delegation(
        &mut self,
        commit: StartDelegationCommit,
    ) -> Result<LeaseFence, AgentStoreError>;

    /// Acquires one exclusive resource conflict key under the exact child fence.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError::Conflict`] when another live run owns the key.
    fn acquire_resource_claim(
        &mut self,
        commit: AcquireResourceClaimCommit,
    ) -> Result<(), AgentStoreError>;

    /// Commits a structured terminal result, releases claims, and settles the parent's delegated
    /// run reservation. A stale child fence cannot commit.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for stale ownership, malformed result, divergent state, or
    /// storage failure.
    fn record_delegation_result(
        &mut self,
        commit: RecordDelegationResultCommit,
    ) -> Result<DelegationView, AgentStoreError>;

    /// Loads one delegation through the owning session principal/channel.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for unauthorized/missing or corrupt state.
    fn delegation(
        &self,
        ownership: OwnershipContext,
        delegation_id: DelegationId,
    ) -> Result<DelegationView, AgentStoreError>;
}

/// Validates bounded, object-shaped delegation package fields.
///
/// # Errors
///
/// Returns [`AgentStoreError::InvariantViolation`] for malformed work or capability evidence.
pub fn validate_delegation_commit(commit: &PrepareDelegationCommit) -> Result<(), AgentStoreError> {
    if commit.child_run_id == commit.parent_fence.run_id()
        || !commit.work_order.is_object()
        || commit
            .work_order
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
        || !commit.context_package.is_object()
        || commit
            .context_package
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
        || serde_json::to_vec(&commit.work_order).map_or(true, |bytes| bytes.len() > 65_536)
        || serde_json::to_vec(&commit.context_package).map_or(true, |bytes| bytes.len() > 262_144)
        || commit.success_criteria.validate().is_err()
        || commit.requested_capabilities.validate().is_err()
        || commit.policy_capabilities.validate().is_err()
        || commit.child_budget.validate().is_err()
    {
        return Err(AgentStoreError::InvariantViolation(
            "delegation contract is invalid".to_owned(),
        ));
    }
    Ok(())
}
