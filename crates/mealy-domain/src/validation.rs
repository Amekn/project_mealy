use crate::RiskClass;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAXIMUM_CRITERIA: usize = 64;
const MAXIMUM_TEXT_BYTES: usize = 4_096;

/// One explicit, owner-inspectable success condition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SuccessCriterion {
    /// Stable criterion identity within the task.
    pub criterion_id: String,
    /// Bounded requirement stated independently from the producer result.
    pub requirement: String,
}

/// Objective and criteria governing whether one task may report success.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskSuccessCriteria {
    /// Bounded task objective.
    pub objective: String,
    /// Objective criteria, preferred whenever any deterministic condition applies.
    pub criteria: Vec<SuccessCriterion>,
    /// Recorded reason used only when no objective criterion applies.
    pub no_objective_criteria_reason: Option<String>,
    /// Risk that selects the required validation policy.
    pub risk_class: RiskClass,
    /// Stable validation-policy bundle version.
    pub policy_version: String,
}

impl TaskSuccessCriteria {
    /// Validates exact criteria/no-objective-reason exclusivity and all text bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationContractError`] for ambiguous, duplicate, empty, or unbounded criteria.
    pub fn validate(&self) -> Result<(), ValidationContractError> {
        if !valid_text(&self.objective) || !valid_text(&self.policy_version) {
            return Err(ValidationContractError::InvalidText);
        }
        let has_criteria = !self.criteria.is_empty();
        let has_reason = self.no_objective_criteria_reason.is_some();
        if has_criteria == has_reason || self.criteria.len() > MAXIMUM_CRITERIA {
            return Err(ValidationContractError::AmbiguousCriteria);
        }
        if self
            .no_objective_criteria_reason
            .as_deref()
            .is_some_and(|reason| !valid_text(reason))
        {
            return Err(ValidationContractError::InvalidText);
        }
        let mut ids = std::collections::BTreeSet::new();
        if self.criteria.iter().any(|criterion| {
            !valid_text(&criterion.criterion_id)
                || !valid_text(&criterion.requirement)
                || !ids.insert(criterion.criterion_id.as_str())
        }) {
            return Err(ValidationContractError::InvalidCriterion);
        }
        Ok(())
    }

    /// Returns whether policy requires a fresh independent validation run.
    #[must_use]
    pub const fn independent_validation_required(&self) -> bool {
        matches!(self.risk_class, RiskClass::Medium | RiskClass::High)
    }
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_TEXT_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

/// Mechanism that produced one durable validation record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationMethod {
    /// Reproducible schema, digest, test, or service-read evidence.
    Deterministic,
    /// Independent read-only model run with a fresh context manifest.
    FreshContextModel,
    /// Explicit authenticated policy waiver.
    Waiver,
}

/// Complete validation outcome vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationOutcome {
    /// All required criteria were established.
    Passed,
    /// Producer output needs another bounded revision.
    NeedsRevision,
    /// Evidence established that criteria were not met.
    Failed,
    /// Available evidence could not establish a safe conclusion.
    Inconclusive,
    /// An authenticated policy-authorized owner accepted the residual risk.
    Waived,
}

/// Invalid success-criteria or validation contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ValidationContractError {
    /// Objective, policy, or reason text is empty or outside its canonical bound.
    #[error("validation contract text is invalid")]
    InvalidText,
    /// Criteria and the no-objective reason are both present, absent, or unbounded.
    #[error("success criteria and no-objective reason are ambiguous")]
    AmbiguousCriteria,
    /// A criterion has invalid text or a duplicate stable identity.
    #[error("success criterion is invalid")]
    InvalidCriterion,
}

#[cfg(test)]
mod tests {
    use super::{SuccessCriterion, TaskSuccessCriteria, ValidationContractError};
    use crate::RiskClass;

    #[test]
    fn medium_risk_requires_independent_validation_and_explicit_criteria() {
        let criteria = TaskSuccessCriteria {
            objective: "Write the exact approved bytes".to_owned(),
            criteria: vec![SuccessCriterion {
                criterion_id: "content_digest".to_owned(),
                requirement: "The workspace file digest matches the approved content".to_owned(),
            }],
            no_objective_criteria_reason: None,
            risk_class: RiskClass::Medium,
            policy_version: "phase4.validation.v1".to_owned(),
        };
        assert_eq!(criteria.validate(), Ok(()));
        assert!(criteria.independent_validation_required());
    }

    #[test]
    fn criteria_or_reason_must_be_exactly_one() {
        let invalid = TaskSuccessCriteria {
            objective: "Subjective conversation".to_owned(),
            criteria: Vec::new(),
            no_objective_criteria_reason: None,
            risk_class: RiskClass::Low,
            policy_version: "phase4.validation.v1".to_owned(),
        };
        assert_eq!(
            invalid.validate(),
            Err(ValidationContractError::AmbiguousCriteria)
        );
    }
}
