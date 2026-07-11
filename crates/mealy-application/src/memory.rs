use crate::{OwnershipContext, TimelineCursor, is_sha256_digest};
use mealy_domain::{
    CorrelationId, EventId, MemoryCategory, MemoryConfidence, MemoryId, MemoryMetadata,
    MemoryPromotionAuthorization, MemoryRetention, MemoryRevisionId, MemorySensitivity,
    MemoryStatus,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, time::SystemTime};
use thiserror::Error;

/// Stable policy bundle for governed memory promotion and retrieval.
pub const MEMORY_POLICY_VERSION: &str = "mealy.memory.v1";

/// One immutable provenance link attached to a memory revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemorySource {
    /// Owner-inspectable safe logical locator.
    pub locator: String,
    /// Canonical digest of the cited source content.
    pub digest: String,
}

/// Complete proposal of a new logical memory and its first immutable revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposeMemoryCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Fresh logical memory identity.
    pub memory_id: MemoryId,
    /// Fresh immutable revision identity.
    pub revision_id: MemoryRevisionId,
    /// Bounded proposed content.
    pub content: String,
    /// Required namespace, provenance, policy, and timestamp metadata.
    pub metadata: MemoryMetadata,
    /// Paired immutable source links.
    pub sources: Vec<MemorySource>,
    /// `memory.proposed` journal fact.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Proposal time.
    pub proposed_at: SystemTime,
}

/// Explicit promotion of one proposed memory revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromoteMemoryCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Logical memory.
    pub memory_id: MemoryId,
    /// Exact proposed revision.
    pub revision_id: MemoryRevisionId,
    /// Explicit authorization when sensitive policy requires it.
    pub authorization: Option<MemoryPromotionAuthorization>,
    /// Journal event for owner policy or bound approval evidence.
    pub authorization_event_id: Option<EventId>,
    /// `memory.activated` journal fact.
    pub activation_event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Activation time.
    pub activated_at: SystemTime,
}

/// Atomic correction that preserves the prior revision and activates a replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrectMemoryCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Logical memory being corrected.
    pub memory_id: MemoryId,
    /// Optimistic-concurrency revision of the logical memory.
    pub expected_revision: u64,
    /// Fresh replacement revision identity.
    pub revision_id: MemoryRevisionId,
    /// Corrected bounded content.
    pub content: String,
    /// Revised confidence.
    pub confidence: MemoryConfidence,
    /// Revised sensitivity.
    pub sensitivity: MemorySensitivity,
    /// Revised retention policy.
    pub retention: MemoryRetention,
    /// Immutable sources supporting the correction.
    pub sources: Vec<MemorySource>,
    /// Explicit authorization when the replacement is sensitive.
    pub authorization: Option<MemoryPromotionAuthorization>,
    /// `memory.revision_proposed` fact.
    pub revision_event_id: EventId,
    /// Owner authorization fact, when required.
    pub authorization_event_id: Option<EventId>,
    /// `memory.corrected` fact used as both replacement activation and aggregate update evidence.
    pub corrected_event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Correction and verification time.
    pub corrected_at: SystemTime,
}

/// Change to memory retention without mutating immutable revision content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetMemoryPinCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Logical memory.
    pub memory_id: MemoryId,
    /// Optimistic-concurrency revision.
    pub expected_revision: u64,
    /// Pin when true; restore standard retention when false.
    pub pinned: bool,
    /// Journal fact.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Update time.
    pub updated_at: SystemTime,
}

/// Explicitly removes an active memory from retrieval without scrubbing audit content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpireMemoryCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Logical memory.
    pub memory_id: MemoryId,
    /// Optimistic-concurrency revision.
    pub expected_revision: u64,
    /// Journal fact.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Expiry time.
    pub expired_at: SystemTime,
}

/// Explicitly rejects a proposed memory while retaining its immutable content and provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RejectMemoryCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Logical memory.
    pub memory_id: MemoryId,
    /// Optimistic-concurrency revision.
    pub expected_revision: u64,
    /// `memory.rejected` journal fact.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Rejection time.
    pub rejected_at: SystemTime,
}

/// Scrubs all revision content while retaining minimal lifecycle and digest tombstones.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteMemoryCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Logical memory.
    pub memory_id: MemoryId,
    /// Optimistic-concurrency revision.
    pub expected_revision: u64,
    /// Journal fact.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Deletion time.
    pub deleted_at: SystemTime,
}

/// Deterministically filtered lexical retrieval query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemorySearchQuery {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Exact workspace namespace; evaluated before lexical relevance.
    pub workspace_identity: String,
    /// FTS5 lexical query. An empty query returns the newest active memories deterministically.
    pub query: String,
    /// Maximum sensitivity permitted by the current context policy.
    pub maximum_sensitivity: MemorySensitivity,
    /// Maximum number of results from one through 100.
    pub limit: usize,
}

/// One immutable memory revision in an owner-authorized inspection view.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryRevisionView {
    /// Stable revision identity.
    pub revision_id: MemoryRevisionId,
    /// One-based monotonic ordinal.
    pub ordinal: u64,
    /// Revision lifecycle status.
    pub status: MemoryStatus,
    /// Content is absent only after deletion.
    pub content: Option<String>,
    /// Canonical content digest retained in tombstones.
    pub content_digest: String,
    /// Confidence at revision creation.
    pub confidence: MemoryConfidence,
    /// Sensitivity at revision creation.
    pub sensitivity: MemorySensitivity,
    /// Retention at revision creation.
    pub retention: MemoryRetention,
    /// Prior revision corrected by this revision.
    pub supersedes_revision_id: Option<MemoryRevisionId>,
    /// Immutable provenance links.
    pub sources: Vec<MemorySource>,
    /// Creation timestamp in Unix milliseconds.
    pub created_at_ms: i64,
    /// Verification timestamp in Unix milliseconds.
    pub last_verified_at_ms: i64,
}

/// Complete owner-authorized logical memory and revision history.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryView {
    /// Stable logical memory identity.
    pub memory_id: MemoryId,
    /// Exact principal/workspace namespace.
    pub principal_id: mealy_domain::PrincipalId,
    /// Stable logical workspace identity.
    pub workspace_identity: String,
    /// Logical lifecycle state.
    pub status: MemoryStatus,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// Promotion-policy category.
    pub category: MemoryCategory,
    /// Current confidence.
    pub confidence: MemoryConfidence,
    /// Current sensitivity.
    pub sensitivity: MemorySensitivity,
    /// Current retention behavior.
    pub retention: MemoryRetention,
    /// Proposal timestamp in Unix milliseconds.
    pub created_at_ms: i64,
    /// Most recent verification timestamp in Unix milliseconds.
    pub last_verified_at_ms: i64,
    /// Immutable revision history in ascending ordinal order.
    pub revisions: Vec<MemoryRevisionView>,
}

/// Retrieved memory treated as untrusted cited evidence, never as hidden instruction text.
#[derive(Clone, Debug, PartialEq)]
pub struct MemorySearchHit {
    /// Owner-authorized logical memory and immutable citations.
    pub memory: MemoryView,
    /// FTS5 BM25 rank; lower values are more relevant.
    pub lexical_rank: f64,
}

/// Outcome from rebuilding the derived lexical index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryIndexRebuildReceipt {
    /// Number of active revisions indexed.
    pub indexed_revision_count: u64,
    /// Rebuild completion time in Unix milliseconds.
    pub rebuilt_at_ms: i64,
}

/// Failure from governed memory persistence and retrieval.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MemoryStoreError {
    /// Memory is absent or deliberately hidden from the supplied owner/channel/namespace.
    #[error("memory was not found")]
    NotFound,
    /// Input violates lifecycle, metadata, source, or content bounds.
    #[error("memory contract is invalid: {0}")]
    InvalidContract(String),
    /// Sensitive material lacks exact owner policy or approval evidence.
    #[error("memory promotion was denied by policy")]
    PolicyDenied,
    /// Optimistic revision or immutable identity conflicts with current state.
    #[error("memory commit conflicted with current state")]
    Conflict,
    /// Lexical index is marked degraded; deterministic namespace-filtered fallback was used.
    #[error("memory lexical index is degraded: {0}")]
    IndexDegraded(String),
    /// Persistence could not complete the operation.
    #[error("memory store is unavailable: {0}")]
    Unavailable(String),
    /// Stored canonical data violates an application invariant.
    #[error("memory store invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port for governed memory lifecycle, retrieval, inspection, export, and index maintenance.
pub trait MemoryStore {
    /// Atomically creates a proposed logical memory, immutable first revision, provenance, and fact.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when ownership, contract validation, or persistence fails.
    fn propose_memory(
        &mut self,
        commit: ProposeMemoryCommit,
    ) -> Result<MemoryView, MemoryStoreError>;

    /// Promotes an exact proposed revision after policy and any explicit owner evidence.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when authorization, lifecycle validation, or persistence fails.
    fn promote_memory(
        &mut self,
        commit: PromoteMemoryCommit,
    ) -> Result<MemoryView, MemoryStoreError>;

    /// Atomically supersedes the active revision and activates a corrected replacement.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when authorization, concurrency, validation, or persistence
    /// fails.
    fn correct_memory(
        &mut self,
        commit: CorrectMemoryCommit,
    ) -> Result<MemoryView, MemoryStoreError>;

    /// Pins or unpins active memory retention under optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when ownership, lifecycle, concurrency, or persistence fails.
    fn set_memory_pin(
        &mut self,
        commit: SetMemoryPinCommit,
    ) -> Result<MemoryView, MemoryStoreError>;

    /// Expires an active memory and removes it from retrieval.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when ownership, lifecycle, concurrency, or persistence fails.
    fn expire_memory(&mut self, commit: ExpireMemoryCommit)
    -> Result<MemoryView, MemoryStoreError>;

    /// Rejects a proposed memory without discarding its immutable audit evidence.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when ownership, lifecycle, concurrency, or persistence fails.
    fn reject_memory(&mut self, commit: RejectMemoryCommit)
    -> Result<MemoryView, MemoryStoreError>;

    /// Scrubs revision content and removes every derived index entry.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when ownership, lifecycle, concurrency, or persistence fails.
    fn delete_memory(&mut self, commit: DeleteMemoryCommit)
    -> Result<MemoryView, MemoryStoreError>;

    /// Inspects one memory and complete revision history through its namespace owner.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when ownership, stored evidence, or persistence fails.
    fn memory(
        &self,
        ownership: OwnershipContext,
        workspace_identity: &str,
        memory_id: MemoryId,
    ) -> Result<MemoryView, MemoryStoreError>;

    /// Lists namespace memories deterministically for inspection and export.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when ownership, stored evidence, or persistence fails.
    fn memories(
        &self,
        ownership: OwnershipContext,
        workspace_identity: &str,
        include_deleted: bool,
    ) -> Result<Vec<MemoryView>, MemoryStoreError>;

    /// Applies namespace, lifecycle, and sensitivity filters before lexical ranking.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when authorization, query validation, indexing, or persistence
    /// fails.
    fn search_memories(
        &self,
        query: MemorySearchQuery,
    ) -> Result<Vec<MemorySearchHit>, MemoryStoreError>;

    /// Rebuilds the FTS5 derived index solely from active canonical revisions.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when authorization, canonical evidence, or persistence fails.
    fn rebuild_memory_index(
        &mut self,
        ownership: OwnershipContext,
        rebuilt_at: SystemTime,
    ) -> Result<MemoryIndexRebuildReceipt, MemoryStoreError>;
}

/// Validates a proposal without performing storage I/O.
///
/// # Errors
///
/// Returns [`MemoryStoreError::InvalidContract`] for namespace, content, timestamp, or provenance
/// mismatches.
pub fn validate_memory_proposal(commit: &ProposeMemoryCommit) -> Result<(), MemoryStoreError> {
    commit
        .metadata
        .validate()
        .map_err(|error| invalid_contract(error.to_string()))?;
    if commit.metadata.namespace.principal_id != commit.ownership.principal_id()
        || commit.metadata.provenance.proposed_by_principal_id != commit.ownership.principal_id()
        || !valid_content(&commit.content)
    {
        return Err(invalid_contract(
            "proposal ownership, content, or provenance is invalid",
        ));
    }
    validate_sources(&commit.sources, &commit.metadata)?;
    Ok(())
}

/// Validates bounded paired source provenance and exact metadata sets.
///
/// # Errors
///
/// Returns [`MemoryStoreError::InvalidContract`] when sources are empty, duplicated, malformed,
/// or diverge from the domain metadata.
pub fn validate_sources(
    sources: &[MemorySource],
    metadata: &MemoryMetadata,
) -> Result<(), MemoryStoreError> {
    if sources.is_empty() || sources.len() > 64 {
        return Err(invalid_contract("memory sources are empty or unbounded"));
    }
    let locators = sources
        .iter()
        .map(|source| source.locator.clone())
        .collect::<BTreeSet<_>>();
    let digests = sources
        .iter()
        .map(|source| source.digest.clone())
        .collect::<BTreeSet<_>>();
    if locators.len() != sources.len()
        || sources.iter().any(|source| {
            source.locator.is_empty()
                || source.locator.len() > 4_096
                || source.locator.trim() != source.locator
                || source.locator.chars().any(char::is_control)
                || !is_sha256_digest(&source.digest)
        })
        || locators != metadata.provenance.source_locators
        || digests != metadata.provenance.source_digests
    {
        return Err(invalid_contract(
            "paired memory sources diverge from immutable provenance",
        ));
    }
    Ok(())
}

/// Validates lexical query bounds before storage access.
///
/// # Errors
///
/// Returns [`MemoryStoreError::InvalidContract`] for unsafe query or namespace bounds.
pub fn validate_memory_search(query: &MemorySearchQuery) -> Result<(), MemoryStoreError> {
    if query.workspace_identity.is_empty()
        || query.workspace_identity.len() > 1_024
        || query.workspace_identity.trim() != query.workspace_identity
        || query.query.len() > 4_096
        || query.query.chars().any(char::is_control)
        || !(1..=100).contains(&query.limit)
    {
        return Err(invalid_contract("memory search bounds are invalid"));
    }
    Ok(())
}

/// Produces a context-safe logical locator for a cited memory revision.
#[must_use]
pub fn memory_context_locator(memory_id: MemoryId, revision_id: MemoryRevisionId) -> String {
    format!("memory://{memory_id}/revisions/{revision_id}")
}

/// Timeline cursor helper retained in the memory API for citation projections.
#[must_use]
pub const fn memory_event_cursor(cursor: u64) -> TimelineCursor {
    TimelineCursor(cursor)
}

fn valid_content(content: &str) -> bool {
    !content.is_empty() && content.len() <= 65_536 && !content.contains('\0')
}

fn invalid_contract(message: impl Into<String>) -> MemoryStoreError {
    MemoryStoreError::InvalidContract(message.into())
}

#[cfg(test)]
mod tests {
    use super::{MemorySource, ProposeMemoryCommit, validate_memory_proposal, validate_sources};
    use crate::OwnershipContext;
    use mealy_domain::{
        ChannelBindingId, CorrelationId, EventId, MemoryCategory, MemoryConfidence, MemoryId,
        MemoryMetadata, MemoryNamespace, MemoryProvenance, MemoryRetention, MemoryRevisionId,
        MemorySensitivity, PrincipalId,
    };
    use std::{collections::BTreeSet, time::UNIX_EPOCH};

    #[test]
    fn proposal_requires_exact_paired_provenance_and_owner_namespace() {
        let principal_id = PrincipalId::new();
        let source = MemorySource {
            locator: "event://12".to_owned(),
            digest: "a".repeat(64),
        };
        let metadata = MemoryMetadata {
            namespace: MemoryNamespace {
                principal_id,
                workspace_identity: "workspace-a".to_owned(),
            },
            category: MemoryCategory::Fact,
            provenance: MemoryProvenance {
                proposed_by_principal_id: principal_id,
                source_locators: BTreeSet::from([source.locator.clone()]),
                source_digests: BTreeSet::from([source.digest.clone()]),
            },
            confidence: MemoryConfidence::new(9_000).expect("confidence"),
            sensitivity: MemorySensitivity::Internal,
            retention: MemoryRetention::Standard,
            created_at_ms: 0,
            last_verified_at_ms: 0,
        };
        let mut commit = ProposeMemoryCommit {
            ownership: OwnershipContext::new(principal_id, ChannelBindingId::new()),
            memory_id: MemoryId::new(),
            revision_id: MemoryRevisionId::new(),
            content: "The deployment window is Tuesday".to_owned(),
            metadata: metadata.clone(),
            sources: vec![source],
            event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            proposed_at: UNIX_EPOCH,
        };
        assert_eq!(validate_memory_proposal(&commit), Ok(()));
        commit.sources[0].digest = "b".repeat(64);
        assert!(validate_sources(&commit.sources, &metadata).is_err());
    }
}
