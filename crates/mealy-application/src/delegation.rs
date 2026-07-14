use crate::{
    AgentLoopLimits, AgentStoreError, OwnershipContext, ReadToolDescriptor,
    ToolDescriptorEvidenceError, sha256_digest,
};
use mealy_domain::{
    CapabilityGrant, CorrelationId, DelegationId, EventId, InboxEntryId, LeaseFence, LeaseId,
    OutboxId, RunId, TaskId, TaskSuccessCriteria, ToolCallId, TurnId, WorkerId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{Duration, SystemTime};

/// Stable contract version for delegated work packages.
pub const DELEGATION_CONTRACT_VERSION: &str = "mealy.delegation.v1";

/// Provider-visible identity for bounded internal child work.
pub const AGENT_DELEGATE_TOOL_ID: &str = "agent.delegate";

/// Canonical locator returned when a child result becomes parent tool evidence.
pub const AGENT_DELEGATE_RESULT_LOCATOR: &str = "delegation://result";

/// Maximum provider-visible delegated objective bytes.
pub const MAXIMUM_DELEGATION_OBJECTIVE_BYTES: usize = 4_096;

/// Maximum provider-visible delegated instruction bytes.
pub const MAXIMUM_DELEGATION_INSTRUCTION_BYTES: usize = 16_384;

/// Maximum explicit context-package bytes accepted from the parent model.
pub const MAXIMUM_DELEGATION_CONTEXT_BYTES: usize = 32_768;

/// Maximum independently checkable criteria in one provider-created work order.
pub const MAXIMUM_DELEGATION_CRITERIA: usize = 8;

/// Provider-facing, authority-free request for one bounded child computation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentDelegationRequest {
    /// Exact child objective.
    pub objective: String,
    /// Self-contained instructions; implicit parent history is never inherited.
    pub instructions: String,
    /// Concrete result checks the child should satisfy.
    pub success_criteria: Vec<String>,
    /// Explicit bounded context selected by the parent model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

impl AgentDelegationRequest {
    /// Parses and validates the exact provider-visible delegation argument contract.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError::InvariantViolation`] for extra fields, invalid shapes, or
    /// over-bound text/context.
    pub fn from_arguments(arguments: &Value) -> Result<Self, AgentStoreError> {
        let request = serde_json::from_value::<Self>(arguments.clone())
            .map_err(|_| invalid_delegation_arguments())?;
        let valid_text = |text: &str, maximum: usize| {
            !text.is_empty()
                && text.len() <= maximum
                && text.trim() == text
                && !text.chars().any(char::is_control)
        };
        if !valid_text(&request.objective, MAXIMUM_DELEGATION_OBJECTIVE_BYTES)
            || !valid_text(&request.instructions, MAXIMUM_DELEGATION_INSTRUCTION_BYTES)
            || request.success_criteria.is_empty()
            || request.success_criteria.len() > MAXIMUM_DELEGATION_CRITERIA
            || request
                .success_criteria
                .iter()
                .any(|criterion| !valid_text(criterion, 4_096))
            || request.context.as_ref().is_some_and(|context| {
                !context.is_object()
                    || context.as_object().is_some_and(serde_json::Map::is_empty)
                    || serde_json::to_vec(context)
                        .map_or(true, |bytes| bytes.len() > MAXIMUM_DELEGATION_CONTEXT_BYTES)
            })
        {
            return Err(invalid_delegation_arguments());
        }
        Ok(request)
    }
}

fn invalid_delegation_arguments() -> AgentStoreError {
    AgentStoreError::InvariantViolation(
        "agent delegation arguments are outside the bounded contract".to_owned(),
    )
}

/// Builds the immutable provider and durable-evidence descriptor for internal delegation.
///
/// # Errors
///
/// Returns [`ToolDescriptorEvidenceError`] only if the fixed timeout cannot be encoded.
pub fn agent_delegate_tool_descriptor() -> Result<ReadToolDescriptor, ToolDescriptorEvidenceError> {
    let input_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "objective": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAXIMUM_DELEGATION_OBJECTIVE_BYTES
            },
            "instructions": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAXIMUM_DELEGATION_INSTRUCTION_BYTES
            },
            "successCriteria": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAXIMUM_DELEGATION_CRITERIA,
                "items": {"type": "string", "minLength": 1, "maxLength": 4096}
            },
            "context": {
                "type": "object",
                "minProperties": 1
            }
        },
        "required": ["objective", "instructions", "successCriteria"],
        "additionalProperties": false
    });
    let mut descriptor = ReadToolDescriptor {
        tool_id: AGENT_DELEGATE_TOOL_ID.to_owned(),
        version: "1".to_owned(),
        schema_digest: sha256_digest(input_schema.to_string().as_bytes()),
        input_schema,
        output_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "contractVersion": {"const": "mealy.delegation-result.v1"},
                "delegationId": {"type": "string"},
                "childTaskId": {"type": "string"},
                "childRunId": {"type": "string"},
                "status": {"enum": ["succeeded", "failed", "cancelled"]},
                "summary": {"type": "string"},
                "sourceLocator": {"const": AGENT_DELEGATE_RESULT_LOCATOR}
            },
            "required": [
                "contractVersion", "delegationId", "childTaskId", "childRunId", "status",
                "summary", "sourceLocator"
            ],
            "additionalProperties": false
        }),
        descriptor_digest: String::new(),
        // Internal durable computation is replay-safe and has no external effect authority.
        effect_class: "read_only".to_owned(),
        risk_class: "low".to_owned(),
        required_capability: "agent:delegate".to_owned(),
        timeout: Duration::from_mins(5),
        maximum_output_bytes: 64 * 1024,
        conflict_key_template: "agent-delegate:{objective}".to_owned(),
        recovery: "retry".to_owned(),
    };
    descriptor.descriptor_digest = descriptor.computed_descriptor_digest()?;
    Ok(descriptor)
}

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

/// Atomic agent-loop launch that binds a prepared parent tool call to one child and parks the
/// parent until the child commits a terminal result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchAgentDelegationCommit {
    /// Complete delegation contract and fresh child identities.
    pub delegation: PrepareDelegationCommit,
    /// Exact prepared provider-originated parent tool call.
    pub parent_tool_call_id: ToolCallId,
    /// Fresh delegated turn identity.
    pub child_turn_id: TurnId,
    /// Synthetic promoted inbox identity holding only the explicit child package.
    pub child_inbox_entry_id: InboxEntryId,
    /// Reserved identity required by the inbox schema; no external acknowledgement is emitted.
    pub child_acknowledgement_outbox_id: OutboxId,
    /// Parent tool-call started event.
    pub tool_event_id: EventId,
    /// Parent lease release event.
    pub lease_event_id: EventId,
    /// Parent run waiting event.
    pub parent_run_event_id: EventId,
    /// Parent task waiting event.
    pub parent_task_event_id: EventId,
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

    /// Atomically starts a provider-originated delegation, materializes its isolated child turn,
    /// and releases the parent lease into a durable waiting state.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for stale parent ownership, model/tool divergence, exhausted
    /// child authority, malformed context, or storage failure.
    fn launch_agent_delegation(
        &mut self,
        commit: LaunchAgentDelegationCommit,
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

    /// Lists a bounded newest-first set of delegations owned by one principal/channel pair.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for an invalid limit, corrupt evidence, or storage failure.
    fn delegations(
        &self,
        ownership: OwnershipContext,
        limit: usize,
    ) -> Result<Vec<DelegationView>, AgentStoreError>;
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
