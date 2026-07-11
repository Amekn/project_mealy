use crate::{ApprovalId, MemoryId, PrincipalId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

const MAXIMUM_WORKSPACE_IDENTITY_BYTES: usize = 1_024;
const MAXIMUM_PROVENANCE_ITEMS: usize = 64;
const MAXIMUM_LOCATOR_BYTES: usize = 4_096;
const SHA256_DIGEST_HEX_LENGTH: usize = 64;

/// Canonical lifecycle state for one logical governed memory.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryStatus {
    /// Extracted evidence awaits policy review or owner authorization.
    Proposed,
    /// The current revision is eligible for deterministic retrieval.
    Active,
    /// A correction replaced the current revision without erasing its provenance.
    Superseded,
    /// Retention or an explicit owner action removed the memory from retrieval.
    Expired,
    /// Policy or an owner rejected the proposed memory.
    Rejected,
    /// Content was scrubbed while a minimal audit tombstone remains.
    Deleted,
}

impl MemoryStatus {
    /// Returns whether the memory may participate in retrieval.
    #[must_use]
    pub const fn is_retrievable(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns whether the state may only progress to deletion.
    #[must_use]
    pub const fn is_inactive_terminal(self) -> bool {
        matches!(self, Self::Superseded | Self::Expired | Self::Rejected)
    }
}

/// State machine for one logical governed memory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryState {
    id: MemoryId,
    status: MemoryStatus,
    revision: u64,
}

impl MemoryState {
    /// Creates a newly proposed memory at revision zero.
    #[must_use]
    pub const fn new(id: MemoryId) -> Self {
        Self {
            id,
            status: MemoryStatus::Proposed,
            revision: 0,
        }
    }

    /// Rehydrates a persisted aggregate after its state has already been validated by storage.
    #[must_use]
    pub const fn rehydrate(id: MemoryId, status: MemoryStatus, revision: u64) -> Self {
        Self {
            id,
            status,
            revision,
        }
    }

    /// Returns the stable logical memory ID.
    #[must_use]
    pub const fn id(&self) -> MemoryId {
        self.id
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn status(&self) -> MemoryStatus {
        self.status
    }

    /// Returns the optimistic-concurrency revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Promotes a proposed memory into deterministic retrieval.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError`] when the transition is invalid or the revision overflows.
    pub fn activate(&mut self) -> Result<MemoryTransition, MemoryError> {
        self.transition(MemoryStatus::Active)
    }

    /// Rejects a proposed memory without discarding its audit provenance.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError`] when the transition is invalid or the revision overflows.
    pub fn reject(&mut self) -> Result<MemoryTransition, MemoryError> {
        self.transition(MemoryStatus::Rejected)
    }

    /// Marks an active revision as replaced by a correction.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError`] when the transition is invalid or the revision overflows.
    pub fn supersede(&mut self) -> Result<MemoryTransition, MemoryError> {
        self.transition(MemoryStatus::Superseded)
    }

    /// Removes an active memory from retrieval under its retention policy.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError`] when the transition is invalid or the revision overflows.
    pub fn expire(&mut self) -> Result<MemoryTransition, MemoryError> {
        self.transition(MemoryStatus::Expired)
    }

    /// Scrubs memory content while retaining a minimal lifecycle tombstone.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError`] when the transition is invalid or the revision overflows.
    pub fn delete(&mut self) -> Result<MemoryTransition, MemoryError> {
        self.transition(MemoryStatus::Deleted)
    }

    fn transition(&mut self, target: MemoryStatus) -> Result<MemoryTransition, MemoryError> {
        if !allowed(self.status, target) {
            return Err(MemoryError::InvalidTransition {
                memory_id: self.id,
                from: self.status,
                to: target,
            });
        }
        let transition = MemoryTransition {
            memory_id: self.id,
            from: self.status,
            to: target,
            previous_revision: self.revision,
            new_revision: self
                .revision
                .checked_add(1)
                .ok_or(MemoryError::RevisionOverflow { memory_id: self.id })?,
        };
        self.status = target;
        self.revision = transition.new_revision;
        Ok(transition)
    }
}

const fn allowed(from: MemoryStatus, to: MemoryStatus) -> bool {
    matches!(
        (from, to),
        (
            MemoryStatus::Proposed,
            MemoryStatus::Active | MemoryStatus::Rejected | MemoryStatus::Deleted
        ) | (
            MemoryStatus::Active,
            MemoryStatus::Superseded | MemoryStatus::Expired | MemoryStatus::Deleted
        ) | (
            MemoryStatus::Superseded | MemoryStatus::Expired | MemoryStatus::Rejected,
            MemoryStatus::Deleted
        )
    )
}

/// Immutable fact describing one accepted memory transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryTransition {
    memory_id: MemoryId,
    from: MemoryStatus,
    to: MemoryStatus,
    previous_revision: u64,
    new_revision: u64,
}

impl MemoryTransition {
    /// Returns the logical memory that changed.
    #[must_use]
    pub const fn memory_id(self) -> MemoryId {
        self.memory_id
    }

    /// Returns the state before the transition.
    #[must_use]
    pub const fn from(self) -> MemoryStatus {
        self.from
    }

    /// Returns the state after the transition.
    #[must_use]
    pub const fn to(self) -> MemoryStatus {
        self.to
    }

    /// Returns the revision storage must compare before committing.
    #[must_use]
    pub const fn previous_revision(self) -> u64 {
        self.previous_revision
    }

    /// Returns the revision produced by the transition.
    #[must_use]
    pub const fn new_revision(self) -> u64 {
        self.new_revision
    }
}

/// Semantic class used by promotion policy and owner inspection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryCategory {
    /// A user preference that may guide later choices.
    Preference,
    /// A potentially revisable factual claim.
    Fact,
    /// An ongoing objective.
    Goal,
    /// A previously made decision and its relevant rationale.
    Decision,
    /// A durable behavioral or safety constraint.
    Constraint,
    /// Sensitive identity information.
    Identity,
    /// A credential reference or authentication fact; never raw secret material.
    Credential,
    /// Sensitive health information.
    Health,
    /// Sensitive financial information.
    Financial,
    /// Private information about a third party.
    ThirdPartyPrivate,
}

impl MemoryCategory {
    /// Returns whether promotion requires explicit owner policy or a bound approval.
    #[must_use]
    pub const fn requires_explicit_owner_authorization(self) -> bool {
        matches!(
            self,
            Self::Identity
                | Self::Credential
                | Self::Health
                | Self::Financial
                | Self::ThirdPartyPrivate
        )
    }
}

/// Sensitivity label enforced before relevance scoring.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySensitivity {
    /// Safe for public disclosure under the owning policy.
    Public,
    /// Internal to the owner's trusted environment.
    Internal,
    /// Private owner information.
    Private,
    /// Highly sensitive content requiring an explicit narrow policy.
    Restricted,
}

/// Retention behavior attached to every memory revision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryRetention {
    /// Eligible for expiry when its originating session is retired.
    Session,
    /// Governed by the normal configured retention window.
    Standard,
    /// Explicitly retained by the owner until unpinned.
    Pinned,
    /// Retained under a policy hold that owner operations cannot silently bypass.
    PolicyHold,
}

/// Confidence in a memory claim, expressed as integer basis points from zero to 10,000.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MemoryConfidence(u16);

impl MemoryConfidence {
    /// Maximum representable confidence value.
    pub const MAXIMUM: u16 = 10_000;

    /// Creates a bounded confidence value.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError::InvalidConfidence`] when `basis_points` exceeds 10,000.
    pub const fn new(basis_points: u16) -> Result<Self, MemoryError> {
        if basis_points <= Self::MAXIMUM {
            Ok(Self(basis_points))
        } else {
            Err(MemoryError::InvalidConfidence { basis_points })
        }
    }

    /// Returns the exact integer confidence value.
    #[must_use]
    pub const fn basis_points(self) -> u16 {
        self.0
    }
}

/// Namespace boundary evaluated before lexical or semantic relevance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryNamespace {
    /// Principal that owns and may inspect the memory.
    pub principal_id: PrincipalId,
    /// Stable workspace identity within the principal namespace.
    pub workspace_identity: String,
}

/// Immutable provenance attached to a memory revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryProvenance {
    /// Principal responsible for the proposal.
    pub proposed_by_principal_id: PrincipalId,
    /// Owner-inspectable source locators, never raw secret values.
    pub source_locators: BTreeSet<String>,
    /// Canonical source content digests used to detect stale or changed evidence.
    pub source_digests: BTreeSet<String>,
}

/// Required governance metadata for one immutable memory revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryMetadata {
    /// Principal/workspace boundary.
    pub namespace: MemoryNamespace,
    /// Promotion-policy class.
    pub category: MemoryCategory,
    /// Evidence provenance.
    pub provenance: MemoryProvenance,
    /// Confidence in the current revision.
    pub confidence: MemoryConfidence,
    /// Disclosure sensitivity.
    pub sensitivity: MemorySensitivity,
    /// Retention behavior.
    pub retention: MemoryRetention,
    /// Creation timestamp in Unix milliseconds.
    pub created_at_ms: i64,
    /// Most recent evidence verification timestamp in Unix milliseconds.
    pub last_verified_at_ms: i64,
}

impl MemoryMetadata {
    /// Validates namespace, timestamp, and immutable provenance bounds.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError`] for invalid workspace, timestamps, locators, or source digests.
    pub fn validate(&self) -> Result<(), MemoryError> {
        if !valid_text(
            &self.namespace.workspace_identity,
            MAXIMUM_WORKSPACE_IDENTITY_BYTES,
        ) {
            return Err(MemoryError::InvalidWorkspaceIdentity);
        }
        if self.created_at_ms < 0 || self.last_verified_at_ms < self.created_at_ms {
            return Err(MemoryError::InvalidVerificationTime);
        }
        if self.provenance.source_locators.is_empty()
            || self.provenance.source_locators.len() > MAXIMUM_PROVENANCE_ITEMS
            || self
                .provenance
                .source_locators
                .iter()
                .any(|locator| !valid_text(locator, MAXIMUM_LOCATOR_BYTES))
        {
            return Err(MemoryError::InvalidProvenanceLocator);
        }
        if self.provenance.source_digests.is_empty()
            || self.provenance.source_digests.len() > MAXIMUM_PROVENANCE_ITEMS
            || self
                .provenance
                .source_digests
                .iter()
                .any(|digest| !is_sha256_digest(digest))
        {
            return Err(MemoryError::InvalidSourceDigest);
        }
        Ok(())
    }

    /// Enforces explicit owner policy or approval for sensitive promotion categories.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError`] when sensitive material lacks explicit authorization or a policy
    /// version is malformed.
    pub fn validate_promotion(
        &self,
        authorization: Option<&MemoryPromotionAuthorization>,
    ) -> Result<(), MemoryError> {
        if self.category.requires_explicit_owner_authorization() && authorization.is_none() {
            return Err(MemoryError::SensitivePromotionRequiresAuthorization);
        }
        if let Some(MemoryPromotionAuthorization::OwnerPolicy { policy_version }) = authorization
            && !valid_text(policy_version, MAXIMUM_LOCATOR_BYTES)
        {
            return Err(MemoryError::InvalidPolicyVersion);
        }
        Ok(())
    }
}

/// Explicit evidence authorizing promotion of sensitive memory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MemoryPromotionAuthorization {
    /// An owner-configured policy explicitly covers the sensitive category.
    OwnerPolicy {
        /// Stable policy bundle version evaluated for this exact revision.
        policy_version: String,
    },
    /// A bound owner approval authorizes this exact memory revision.
    Approval {
        /// Durable approval record.
        approval_id: ApprovalId,
    },
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

/// Invalid governed-memory lifecycle or metadata contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MemoryError {
    /// The requested lifecycle edge is not permitted.
    #[error("memory {memory_id} cannot transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// Memory being changed.
        memory_id: MemoryId,
        /// Current state.
        from: MemoryStatus,
        /// Requested state.
        to: MemoryStatus,
    },
    /// The optimistic-concurrency revision exhausted its integer range.
    #[error("memory {memory_id} revision overflow")]
    RevisionOverflow {
        /// Memory whose revision overflowed.
        memory_id: MemoryId,
    },
    /// Confidence must be between zero and 10,000 inclusive.
    #[error("memory confidence {basis_points} exceeds 10000 basis points")]
    InvalidConfidence {
        /// Rejected confidence value.
        basis_points: u16,
    },
    /// Workspace identity is empty, padded, unbounded, or contains control characters.
    #[error("memory workspace identity is invalid")]
    InvalidWorkspaceIdentity,
    /// Verification time predates creation or a timestamp is negative.
    #[error("memory verification timestamp is invalid")]
    InvalidVerificationTime,
    /// Provenance must contain bounded canonical locators.
    #[error("memory provenance locator is invalid")]
    InvalidProvenanceLocator,
    /// Provenance must contain canonical lowercase SHA-256 source digests.
    #[error("memory source digest is invalid")]
    InvalidSourceDigest,
    /// Sensitive categories require owner policy or a bound approval.
    #[error("sensitive memory promotion requires explicit owner authorization")]
    SensitivePromotionRequiresAuthorization,
    /// Owner policy versions must be bounded canonical text.
    #[error("memory promotion policy version is invalid")]
    InvalidPolicyVersion,
}

#[cfg(test)]
mod tests {
    use super::{
        MemoryCategory, MemoryConfidence, MemoryError, MemoryMetadata, MemoryNamespace,
        MemoryPromotionAuthorization, MemoryProvenance, MemoryRetention, MemorySensitivity,
        MemoryState, MemoryStatus,
    };
    use crate::{MemoryId, PrincipalId};
    use std::collections::BTreeSet;

    fn metadata(category: MemoryCategory) -> MemoryMetadata {
        MemoryMetadata {
            namespace: MemoryNamespace {
                principal_id: PrincipalId::new(),
                workspace_identity: "workspace-a".to_owned(),
            },
            category,
            provenance: MemoryProvenance {
                proposed_by_principal_id: PrincipalId::new(),
                source_locators: BTreeSet::from(["event:12".to_owned()]),
                source_digests: BTreeSet::from(["a".repeat(64)]),
            },
            confidence: MemoryConfidence::new(8_500).expect("bounded confidence"),
            sensitivity: MemorySensitivity::Private,
            retention: MemoryRetention::Standard,
            created_at_ms: 1_000,
            last_verified_at_ms: 1_100,
        }
    }

    #[test]
    fn lifecycle_preserves_inactive_records_until_explicit_deletion() {
        let mut memory = MemoryState::new(MemoryId::new());
        assert_eq!(
            memory.activate().expect("activate").to(),
            MemoryStatus::Active
        );
        assert_eq!(memory.supersede().expect("supersede").new_revision(), 2);
        assert_eq!(memory.delete().expect("delete").to(), MemoryStatus::Deleted);
        assert_eq!(
            memory.activate(),
            Err(MemoryError::InvalidTransition {
                memory_id: memory.id(),
                from: MemoryStatus::Deleted,
                to: MemoryStatus::Active,
            })
        );
    }

    #[test]
    fn sensitive_promotion_requires_owner_policy_or_approval() {
        let health = metadata(MemoryCategory::Health);
        assert_eq!(health.validate(), Ok(()));
        assert_eq!(
            health.validate_promotion(None),
            Err(MemoryError::SensitivePromotionRequiresAuthorization)
        );
        assert_eq!(
            health.validate_promotion(Some(&MemoryPromotionAuthorization::OwnerPolicy {
                policy_version: "memory.owner.v1".to_owned(),
            })),
            Ok(())
        );
        assert_eq!(
            metadata(MemoryCategory::Fact).validate_promotion(None),
            Ok(())
        );
    }

    #[test]
    fn metadata_rejects_bad_digests_and_verification_time() {
        let mut invalid = metadata(MemoryCategory::Fact);
        invalid.provenance.source_digests = BTreeSet::from(["ABC".to_owned()]);
        assert_eq!(invalid.validate(), Err(MemoryError::InvalidSourceDigest));

        invalid = metadata(MemoryCategory::Fact);
        invalid.last_verified_at_ms = invalid.created_at_ms - 1;
        assert_eq!(
            invalid.validate(),
            Err(MemoryError::InvalidVerificationTime)
        );
        assert_eq!(
            MemoryConfidence::new(10_001),
            Err(MemoryError::InvalidConfidence {
                basis_points: 10_001
            })
        );
    }
}
