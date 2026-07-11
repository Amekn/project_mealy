use crate::{
    CommittedArtifactBlob, OwnershipContext, TimelineCursor, TimelineEvent, is_sha256_digest,
    sha256_digest,
};
use mealy_domain::{
    CompactionCitation, CompactionId, CompactionRecord, CorrelationId, EventId, SessionId,
};
use std::time::SystemTime;
use thiserror::Error;

/// Stable deterministic extraction contract for Phase 5 compaction.
pub const COMPACTION_PROMPT_VERSION: &str = "mealy.compaction.v1";

/// Authorized canonical history from which a compaction may be derived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactionSourceSnapshot {
    /// Owning session.
    pub session_id: SessionId,
    /// Exact workspace namespace at extraction time.
    pub workspace_identity: String,
    /// First source cursor, inclusive.
    pub first_cursor: TimelineCursor,
    /// Last source cursor, inclusive.
    pub last_cursor: TimelineCursor,
    /// Ordered immutable canonical events. Source history is never removed by compaction.
    pub events: Vec<CompactionSourceEvent>,
}

/// Canonical source event with a digest over its exact durable envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactionSourceEvent {
    /// Authorized event projection.
    pub event: TimelineEvent,
    /// Canonical lowercase SHA-256 digest of the event envelope.
    pub event_digest: String,
}

/// Complete atomic input for committing one derived compaction artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitCompaction {
    /// Authenticated principal and verified channel binding.
    pub ownership: OwnershipContext,
    /// Owning session.
    pub session_id: SessionId,
    /// Domain-validated compaction provenance and typed carry-forward.
    pub record: CompactionRecord,
    /// Exact human-readable derived summary.
    pub summary_text: String,
    /// Content-addressed blob already durably published by the artifact adapter.
    pub artifact_blob: CommittedArtifactBlob,
    /// Journal fact for the immutable compaction record.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Commit time.
    pub created_at: SystemTime,
}

/// Owner-authorized inspection view of one derived compaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactionView {
    /// Exact domain provenance and typed state.
    pub record: CompactionRecord,
    /// Human-readable derived summary.
    pub summary_text: String,
    /// Timeline cursor of `context.compacted`.
    pub cursor: TimelineCursor,
}

/// Persistence failure for compaction snapshots and commits.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CompactionStoreError {
    /// Session or compaction is absent or deliberately hidden from the supplied owner.
    #[error("compaction was not found")]
    NotFound,
    /// Source range is empty, stale, incomplete, or outside retained canonical history.
    #[error("compaction source range is invalid")]
    InvalidSourceRange,
    /// Artifact, typed state, or citations violate the compaction contract.
    #[error("compaction contract is invalid: {0}")]
    InvalidContract(String),
    /// The same immutable identity was committed with different material.
    #[error("compaction commit conflicts with existing state")]
    Conflict,
    /// Persistence could not complete the operation.
    #[error("compaction store is unavailable: {0}")]
    Unavailable(String),
    /// Stored canonical data violates an application invariant.
    #[error("compaction store invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port for authorized source snapshots and immutable derived compaction records.
pub trait CompactionStore {
    /// Loads a bounded exact source range through the owning session.
    ///
    /// # Errors
    ///
    /// Returns [`CompactionStoreError`] when the session is unauthorized, the range is invalid,
    /// or canonical events are unavailable.
    fn compaction_source_snapshot(
        &self,
        ownership: OwnershipContext,
        session_id: SessionId,
        first_cursor: TimelineCursor,
        last_cursor: TimelineCursor,
    ) -> Result<CompactionSourceSnapshot, CompactionStoreError>;

    /// Atomically commits artifact metadata, typed carry-forward, citations, and a journal fact.
    ///
    /// # Errors
    ///
    /// Returns [`CompactionStoreError`] for unauthorized, stale, malformed, or conflicting input.
    fn commit_compaction(
        &mut self,
        commit: CommitCompaction,
    ) -> Result<CompactionView, CompactionStoreError>;

    /// Loads one compaction through the owning principal and verified channel.
    ///
    /// # Errors
    ///
    /// Returns [`CompactionStoreError`] when absent, unauthorized, unavailable, or corrupt.
    fn compaction(
        &self,
        ownership: OwnershipContext,
        compaction_id: CompactionId,
    ) -> Result<CompactionView, CompactionStoreError>;

    /// Loads the most recent committed compaction for a session, when one exists.
    ///
    /// # Errors
    ///
    /// Returns [`CompactionStoreError`] when the session is unauthorized or storage is corrupt.
    fn latest_compaction(
        &self,
        ownership: OwnershipContext,
        session_id: SessionId,
    ) -> Result<Option<CompactionView>, CompactionStoreError>;
}

/// Validates exact artifact bytes, record provenance, and flattened typed citations.
///
/// # Errors
///
/// Returns [`CompactionStoreError::InvalidContract`] for any mismatch.
pub fn validate_compaction_commit(commit: &CommitCompaction) -> Result<(), CompactionStoreError> {
    commit
        .record
        .validate()
        .map_err(|error| invalid_contract(error.to_string()))?;
    commit
        .artifact_blob
        .validate()
        .map_err(|error| invalid_contract(error.to_string()))?;
    if commit.record.prompt_version != COMPACTION_PROMPT_VERSION
        || commit.summary_text.is_empty()
        || commit.summary_text.len() > 262_144
        || sha256_digest(commit.summary_text.as_bytes()) != commit.record.artifact_digest
        || commit.artifact_blob.digest != commit.record.artifact_digest
        || commit.artifact_blob.size_bytes
            != u64::try_from(commit.summary_text.len())
                .map_err(|_| invalid_contract("summary length is out of range"))?
        || !is_sha256_digest(&commit.record.config_digest)
    {
        return Err(invalid_contract(
            "artifact, prompt, summary, or configuration digest diverged",
        ));
    }
    Ok(())
}

/// Digests the exact provider-neutral timeline envelope cited by compaction.
///
/// # Errors
///
/// Returns [`CompactionStoreError::InvalidContract`] when the event timestamp is not representable.
pub fn compaction_source_event_digest(
    event: &TimelineEvent,
) -> Result<String, CompactionStoreError> {
    let occurred_at_ms = event
        .occurred_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invalid_contract("source event time precedes Unix epoch"))?
        .as_millis();
    let material = serde_json::json!({
        "cursor": event.cursor.0,
        "eventId": event.event_id,
        "aggregateKind": event.aggregate_kind,
        "aggregateId": event.aggregate_id,
        "aggregateSequence": event.aggregate_sequence,
        "eventType": event.event_type,
        "eventVersion": event.event_version,
        "occurredAtMs": occurred_at_ms,
        "correlationId": event.correlation_id,
        "causationId": event.causation_id,
        "payloadJson": event.payload_json,
    })
    .to_string();
    Ok(sha256_digest(material.as_bytes()))
}

/// Flattens every typed carry-forward citation in deterministic storage order.
#[must_use]
pub fn compaction_citations(
    record: &CompactionRecord,
) -> Vec<(&'static str, String, &CompactionCitation)> {
    let mut citations = Vec::new();
    for (kind, items) in [
        ("current_goal", &record.carry_forward.current_goals),
        (
            "safety_constraint",
            &record.carry_forward.safety_constraints,
        ),
        ("decision", &record.carry_forward.decisions),
        ("unresolved_work", &record.carry_forward.unresolved_work),
    ] {
        for item in items {
            citations.extend(
                item.citations
                    .iter()
                    .map(|citation| (kind, item.item_key.clone(), citation)),
            );
        }
    }
    for approval in &record.carry_forward.unresolved_approvals {
        citations.extend(approval.citations.iter().map(|citation| {
            (
                "unresolved_approval",
                approval.approval_id.to_string(),
                citation,
            )
        }));
    }
    for effect in &record.carry_forward.effect_outcomes {
        citations.extend(
            effect
                .citations
                .iter()
                .map(|citation| ("effect_outcome", effect.effect_id.to_string(), citation)),
        );
    }
    citations
}

fn invalid_contract(message: impl Into<String>) -> CompactionStoreError {
    CompactionStoreError::InvalidContract(message.into())
}

#[cfg(test)]
mod tests {
    use super::{
        COMPACTION_PROMPT_VERSION, CommitCompaction, compaction_citations,
        validate_compaction_commit,
    };
    use crate::{CommittedArtifactBlob, OwnershipContext, sha256_digest};
    use mealy_domain::{
        ArtifactId, ChannelBindingId, CompactionCarryForward, CompactionId, CompactionRecord,
        CompactionSourceRange, CorrelationId, EventId, PrincipalId, SessionId,
    };
    use std::time::UNIX_EPOCH;

    #[test]
    fn commit_binds_exact_summary_bytes_to_the_derived_artifact() {
        let summary = "A cited compacted summary".to_owned();
        let digest = sha256_digest(summary.as_bytes());
        let commit = CommitCompaction {
            ownership: OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new()),
            session_id: SessionId::new(),
            record: CompactionRecord {
                compaction_id: CompactionId::new(),
                artifact_id: ArtifactId::new(),
                source_range: CompactionSourceRange {
                    first_cursor: 1,
                    last_cursor: 2,
                },
                prompt_version: COMPACTION_PROMPT_VERSION.to_owned(),
                config_digest: "a".repeat(64),
                artifact_digest: digest.clone(),
                carry_forward: CompactionCarryForward::default(),
            },
            summary_text: summary.clone(),
            artifact_blob: CommittedArtifactBlob::new_sha256(
                digest,
                u64::try_from(summary.len()).expect("summary length"),
            )
            .expect("blob descriptor"),
            event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            created_at: UNIX_EPOCH,
        };
        assert_eq!(validate_compaction_commit(&commit), Ok(()));
        assert!(compaction_citations(&commit.record).is_empty());
    }
}
