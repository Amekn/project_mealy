use crate::{AgentStoreError, OwnershipContext};
use mealy_domain::{
    CapabilityGrant, ContextManifestId, CorrelationId, EventId, LeaseFence, PrincipalId, RunId,
    TaskId, TaskSuccessCriteria, ValidationId, ValidationMethod, ValidationOutcome,
};
use serde_json::Value;
use std::time::SystemTime;

/// Stable policy version for the first validation/delegation proof.
pub const VALIDATION_POLICY_VERSION: &str = "mealy.validation.phase4.v1";

/// Durable task criteria projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskSuccessCriteriaView {
    /// Task governed by the criteria.
    pub task_id: TaskId,
    /// Exact criteria contract.
    pub criteria: TaskSuccessCriteria,
    /// SHA-256 over canonical criteria JSON.
    pub criteria_digest: String,
    /// Commit time.
    pub created_at: SystemTime,
}

/// Complete fresh-context package supplied to an independent validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationContextDraft {
    /// Fresh manifest identity, never reused from the producer.
    pub manifest_id: ContextManifestId,
    /// Exact user request/objective material.
    pub request: Value,
    /// Exact task criteria and task-specific rubric inputs.
    pub criteria: Value,
    /// Producer outputs selected for validation.
    pub outputs: Value,
    /// Tool, effect, artifact, and timeline evidence selected for validation.
    pub evidence: Value,
    /// Read-only capability envelope independently computed for the validator.
    pub capabilities: CapabilityGrant,
}

/// Atomic commit of validation evidence and the task's success-gate reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordValidationCommit {
    /// Exact live producer fence; stale producer work cannot attach validation.
    pub producer_fence: LeaseFence,
    /// Task being validated.
    pub task_id: TaskId,
    /// New durable validation identity.
    pub validation_id: ValidationId,
    /// Child validator task for a fresh-context model run.
    pub validator_task_id: Option<TaskId>,
    /// Child validator run for a fresh-context model run.
    pub validator_run_id: Option<RunId>,
    /// Independent validation context.
    pub context: ValidationContextDraft,
    /// Deterministic, independent-model, or waiver path.
    pub method: ValidationMethod,
    /// Complete outcome vocabulary.
    pub outcome: ValidationOutcome,
    /// Task-specific rubric applied to the evidence.
    pub rubric: Value,
    /// Canonical evidence supporting the outcome.
    pub evidence: Value,
    /// Principal responsible for the validation or waiver.
    pub responsible_principal_id: PrincipalId,
    /// Stable policy bundle version.
    pub policy_version: String,
    /// Validation aggregate event.
    pub event_id: EventId,
    /// Correlation shared with producer work.
    pub correlation_id: CorrelationId,
    /// Commit time.
    pub recorded_at: SystemTime,
}

/// Authorized durable validation projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationRecordView {
    /// Stable validation identity.
    pub validation_id: ValidationId,
    /// Validated task.
    pub task_id: TaskId,
    /// Producer run whose output was checked.
    pub producer_run_id: RunId,
    /// Independent validator run, when used.
    pub validator_run_id: Option<RunId>,
    /// Fresh manifest identity.
    pub context_manifest_id: ContextManifestId,
    /// Validation method.
    pub method: ValidationMethod,
    /// Validation outcome.
    pub outcome: ValidationOutcome,
    /// Canonical rubric.
    pub rubric: Value,
    /// Canonical evidence.
    pub evidence: Value,
    /// Responsible principal.
    pub responsible_principal_id: PrincipalId,
    /// Policy version.
    pub policy_version: String,
    /// Timeline cursor of the durable validation fact.
    pub cursor: u64,
}

/// Task criteria and validation evidence persistence port.
pub trait ValidationStore {
    /// Loads explicit criteria through task ownership.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for unauthorized/missing state or corrupt evidence.
    fn task_success_criteria(
        &self,
        ownership: OwnershipContext,
        task_id: TaskId,
    ) -> Result<TaskSuccessCriteriaView, AgentStoreError>;

    /// Atomically records independent validation, validator lineage, journal evidence, and the
    /// task validation gate under the producer fence.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for stale ownership, invalid context/authority, policy mismatch,
    /// duplicate evidence, or storage failure.
    fn record_validation(
        &mut self,
        commit: RecordValidationCommit,
    ) -> Result<ValidationRecordView, AgentStoreError>;

    /// Loads one validation only through its task owner.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for unauthorized/missing state or corrupt evidence.
    fn validation_record(
        &self,
        ownership: OwnershipContext,
        validation_id: ValidationId,
    ) -> Result<ValidationRecordView, AgentStoreError>;

    /// Loads the validation currently attached to a task, when one exists.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for unauthorized/missing task state or corrupt evidence.
    fn task_validation(
        &self,
        ownership: OwnershipContext,
        task_id: TaskId,
    ) -> Result<Option<ValidationRecordView>, AgentStoreError>;
}

/// Validates the bounded, object-shaped validator inputs and least-authority envelope.
///
/// # Errors
///
/// Returns [`AgentStoreError::InvariantViolation`] for malformed or authority-bearing context.
pub fn validate_validation_commit(commit: &RecordValidationCommit) -> Result<(), AgentStoreError> {
    let values = [
        &commit.context.request,
        &commit.context.criteria,
        &commit.context.outputs,
        &commit.context.evidence,
        &commit.rubric,
        &commit.evidence,
    ];
    if values.iter().any(|value| {
        !value.is_object()
            || value.as_object().is_some_and(serde_json::Map::is_empty)
            || serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > 262_144)
    }) || commit.context.capabilities.validate().is_err()
        || commit
            .context
            .capabilities
            .effect_classes
            .iter()
            .any(|class| *class != mealy_domain::EffectClass::ReadOnly)
        || commit
            .context
            .capabilities
            .profiles
            .iter()
            .any(|profile| *profile != mealy_domain::PolicyProfile::Observe)
        || !commit.context.capabilities.secret_references.is_empty()
        || !commit.context.capabilities.network_destinations.is_empty()
        || commit.policy_version != VALIDATION_POLICY_VERSION
    {
        return Err(AgentStoreError::InvariantViolation(
            "validation context or authority is invalid".to_owned(),
        ));
    }
    let child_ids_present = commit.validator_task_id.is_some() && commit.validator_run_id.is_some();
    let identity_valid = match commit.method {
        ValidationMethod::FreshContextModel => {
            commit.outcome != ValidationOutcome::Waived && child_ids_present
        }
        ValidationMethod::Deterministic => {
            commit.outcome != ValidationOutcome::Waived && !child_ids_present
        }
        ValidationMethod::Waiver => {
            commit.outcome == ValidationOutcome::Waived && !child_ids_present
        }
    };
    if !identity_valid {
        return Err(AgentStoreError::InvariantViolation(
            "validation method, outcome, and child identities diverge".to_owned(),
        ));
    }
    Ok(())
}
