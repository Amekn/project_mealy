use crate::{
    ApprovalId, ApprovalStatus, ArtifactId, CompactionId, EffectId, EffectStatus, EventId,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

const MAXIMUM_CARRY_ITEMS: usize = 256;
const MAXIMUM_CITATIONS_PER_ITEM: usize = 64;
const MAXIMUM_KEY_BYTES: usize = 256;
const MAXIMUM_TEXT_BYTES: usize = 8_192;
const MAXIMUM_VERSION_BYTES: usize = 1_024;
const SHA256_DIGEST_HEX_LENGTH: usize = 64;

/// Inclusive journal cursor range from which a compaction was derived.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompactionSourceRange {
    /// First canonical event cursor represented by the derived artifact.
    pub first_cursor: u64,
    /// Last canonical event cursor represented by the derived artifact.
    pub last_cursor: u64,
}

impl CompactionSourceRange {
    /// Returns whether the inclusive range is ordered and contains `cursor`.
    #[must_use]
    pub const fn contains(self, cursor: u64) -> bool {
        self.first_cursor > 0
            && self.first_cursor <= self.last_cursor
            && cursor >= self.first_cursor
            && cursor <= self.last_cursor
    }
}

/// Immutable journal evidence cited by a compacted item.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompactionCitation {
    /// Stable source event identifier.
    pub event_id: EventId,
    /// Canonical journal cursor at extraction time.
    pub cursor: u64,
    /// Canonical digest of the source event envelope.
    pub event_digest: String,
}

/// A typed prose fact whose source evidence remains directly inspectable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CitedCompactionItem {
    /// Stable identity within the source session.
    pub item_key: String,
    /// Bounded, non-authoritative derived text.
    pub text: String,
    /// One or more immutable source event citations.
    pub citations: Vec<CompactionCitation>,
}

/// Unresolved approval preserved independently from summary prose.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompactedApproval {
    /// Durable approval identity.
    pub approval_id: ApprovalId,
    /// Must remain pending while represented as unresolved.
    pub status: ApprovalStatus,
    /// Digest binding the decision to its exact current subject.
    pub subject_digest: String,
    /// Immutable source evidence.
    pub citations: Vec<CompactionCitation>,
}

/// Canonical effect state preserved independently from summary prose.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompactedEffect {
    /// Durable effect identity.
    pub effect_id: EffectId,
    /// Exact lifecycle state observed at compaction time.
    pub status: EffectStatus,
    /// Bounded owner-inspectable outcome or unresolved-state description.
    pub outcome: String,
    /// Immutable source evidence.
    pub citations: Vec<CompactionCitation>,
}

/// Safety-critical state carried through compaction as typed collections.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct CompactionCarryForward {
    /// Current user or task goals.
    pub current_goals: Vec<CitedCompactionItem>,
    /// Safety and authority constraints that remain applicable.
    pub safety_constraints: Vec<CitedCompactionItem>,
    /// Decisions that constrain later execution.
    pub decisions: Vec<CitedCompactionItem>,
    /// Work that remains unresolved but is not itself an approval.
    pub unresolved_work: Vec<CitedCompactionItem>,
    /// Pending approvals and exact subject bindings.
    pub unresolved_approvals: Vec<CompactedApproval>,
    /// Known and ambiguous external effect outcomes.
    pub effect_outcomes: Vec<CompactedEffect>,
}

/// Derived compaction artifact plus exact provenance and typed carry-forward state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompactionRecord {
    /// Stable compaction identity.
    pub compaction_id: CompactionId,
    /// Immutable artifact containing the human-readable derived summary.
    pub artifact_id: ArtifactId,
    /// Inclusive canonical source history represented by this artifact.
    pub source_range: CompactionSourceRange,
    /// Versioned extraction prompt.
    pub prompt_version: String,
    /// Digest of extraction configuration and policy.
    pub config_digest: String,
    /// Digest of the exact derived artifact bytes.
    pub artifact_digest: String,
    /// Typed state that may not be delegated to summary prose.
    pub carry_forward: CompactionCarryForward,
}

impl CompactionRecord {
    /// Validates source bounds, digests, typed item limits, and citation coverage.
    ///
    /// # Errors
    ///
    /// Returns [`CompactionError`] when the artifact cannot be tied exactly to canonical history.
    pub fn validate(&self) -> Result<(), CompactionError> {
        if self.source_range.first_cursor == 0
            || self.source_range.first_cursor > self.source_range.last_cursor
        {
            return Err(CompactionError::InvalidSourceRange);
        }
        if !valid_text(&self.prompt_version, MAXIMUM_VERSION_BYTES) {
            return Err(CompactionError::InvalidPromptVersion);
        }
        if !is_sha256_digest(&self.config_digest) || !is_sha256_digest(&self.artifact_digest) {
            return Err(CompactionError::InvalidDigest);
        }

        let statement_sets = [
            &self.carry_forward.current_goals,
            &self.carry_forward.safety_constraints,
            &self.carry_forward.decisions,
            &self.carry_forward.unresolved_work,
        ];
        let total_items = statement_sets
            .iter()
            .map(|items| items.len())
            .sum::<usize>()
            .saturating_add(self.carry_forward.unresolved_approvals.len())
            .saturating_add(self.carry_forward.effect_outcomes.len());
        if total_items > MAXIMUM_CARRY_ITEMS {
            return Err(CompactionError::TooManyCarryItems);
        }

        let mut keys = BTreeSet::new();
        for items in statement_sets {
            for item in items {
                if !valid_text(&item.item_key, MAXIMUM_KEY_BYTES)
                    || !valid_text(&item.text, MAXIMUM_TEXT_BYTES)
                    || !keys.insert(item.item_key.as_str())
                {
                    return Err(CompactionError::InvalidCarryItem);
                }
                validate_citations(&item.citations, self.source_range)?;
            }
        }
        for approval in &self.carry_forward.unresolved_approvals {
            if approval.status != ApprovalStatus::Pending
                || !is_sha256_digest(&approval.subject_digest)
            {
                return Err(CompactionError::InvalidUnresolvedApproval);
            }
            validate_citations(&approval.citations, self.source_range)?;
        }
        for effect in &self.carry_forward.effect_outcomes {
            if !valid_text(&effect.outcome, MAXIMUM_TEXT_BYTES) {
                return Err(CompactionError::InvalidEffectOutcome);
            }
            validate_citations(&effect.citations, self.source_range)?;
        }
        Ok(())
    }
}

fn validate_citations(
    citations: &[CompactionCitation],
    range: CompactionSourceRange,
) -> Result<(), CompactionError> {
    if citations.is_empty() || citations.len() > MAXIMUM_CITATIONS_PER_ITEM {
        return Err(CompactionError::InvalidCitation);
    }
    let mut identities = BTreeSet::new();
    if citations.iter().any(|citation| {
        !range.contains(citation.cursor)
            || !is_sha256_digest(&citation.event_digest)
            || !identities.insert((citation.event_id, citation.cursor))
    }) {
        return Err(CompactionError::InvalidCitation);
    }
    Ok(())
}

fn valid_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == SHA256_DIGEST_HEX_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Invalid compaction provenance or typed carry-forward contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CompactionError {
    /// Source cursors must form a non-empty ordered inclusive range.
    #[error("compaction source event range is invalid")]
    InvalidSourceRange,
    /// Extraction prompt version must be bounded canonical text.
    #[error("compaction prompt version is invalid")]
    InvalidPromptVersion,
    /// Artifact, configuration, and event digests must be canonical lowercase SHA-256.
    #[error("compaction digest is invalid")]
    InvalidDigest,
    /// Typed carry-forward exceeds its global item bound.
    #[error("compaction contains too many carry-forward items")]
    TooManyCarryItems,
    /// A statement has invalid text or duplicates a stable item key.
    #[error("compaction carry-forward item is invalid")]
    InvalidCarryItem,
    /// A citation is absent, duplicated, outside the source range, or has a bad digest.
    #[error("compaction citation is invalid")]
    InvalidCitation,
    /// An unresolved approval is not pending or is not bound to a canonical subject digest.
    #[error("compaction unresolved approval is invalid")]
    InvalidUnresolvedApproval,
    /// An effect outcome description is invalid.
    #[error("compaction effect outcome is invalid")]
    InvalidEffectOutcome,
}

#[cfg(test)]
mod tests {
    use super::{
        CitedCompactionItem, CompactedApproval, CompactedEffect, CompactionCarryForward,
        CompactionCitation, CompactionError, CompactionRecord, CompactionSourceRange,
    };
    use crate::{
        ApprovalId, ApprovalStatus, ArtifactId, CompactionId, EffectId, EffectStatus, EventId,
    };

    fn citation(cursor: u64) -> CompactionCitation {
        CompactionCitation {
            event_id: EventId::new(),
            cursor,
            event_digest: "a".repeat(64),
        }
    }

    fn record() -> CompactionRecord {
        CompactionRecord {
            compaction_id: CompactionId::new(),
            artifact_id: ArtifactId::new(),
            source_range: CompactionSourceRange {
                first_cursor: 10,
                last_cursor: 20,
            },
            prompt_version: "phase5.compaction.v1".to_owned(),
            config_digest: "b".repeat(64),
            artifact_digest: "c".repeat(64),
            carry_forward: CompactionCarryForward {
                current_goals: vec![CitedCompactionItem {
                    item_key: "goal:ship".to_owned(),
                    text: "Finish and verify the requested build".to_owned(),
                    citations: vec![citation(10)],
                }],
                safety_constraints: vec![CitedCompactionItem {
                    item_key: "constraint:no-network".to_owned(),
                    text: "Do not use outbound network access".to_owned(),
                    citations: vec![citation(11)],
                }],
                unresolved_approvals: vec![CompactedApproval {
                    approval_id: ApprovalId::new(),
                    status: ApprovalStatus::Pending,
                    subject_digest: "d".repeat(64),
                    citations: vec![citation(12)],
                }],
                effect_outcomes: vec![CompactedEffect {
                    effect_id: EffectId::new(),
                    status: EffectStatus::OutcomeUnknown,
                    outcome: "Dispatch crossed the boundary; reconciliation is required".to_owned(),
                    citations: vec![citation(20)],
                }],
                ..CompactionCarryForward::default()
            },
        }
    }

    #[test]
    fn typed_safety_state_requires_exact_source_citations() {
        assert_eq!(record().validate(), Ok(()));

        let mut outside_range = record();
        outside_range.carry_forward.current_goals[0].citations[0].cursor = 21;
        assert_eq!(
            outside_range.validate(),
            Err(CompactionError::InvalidCitation)
        );
    }

    #[test]
    fn unresolved_approval_must_still_be_pending() {
        let mut resolved = record();
        resolved.carry_forward.unresolved_approvals[0].status = ApprovalStatus::Approved;
        assert_eq!(
            resolved.validate(),
            Err(CompactionError::InvalidUnresolvedApproval)
        );
    }
}
