use crate::OwnershipContext;
use mealy_domain::{CorrelationId, EventId, SessionId, TurnId};
use std::time::SystemTime;
use thiserror::Error;

/// Stable global position in the immutable presentation timeline.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct TimelineCursor(pub u64);

/// Authorized, bounded timeline query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimelineQuery {
    /// Session whose events are requested.
    pub session_id: SessionId,
    /// Authenticated owner and channel binding.
    pub ownership: OwnershipContext,
    /// Return events strictly after this cursor.
    pub after: Option<TimelineCursor>,
    /// Maximum rows returned.
    pub limit: usize,
}

/// Provider-neutral immutable timeline fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelineEvent {
    /// Durable global cursor.
    pub cursor: TimelineCursor,
    /// Immutable journal-event ID.
    pub event_id: EventId,
    /// Aggregate category.
    pub aggregate_kind: String,
    /// Opaque aggregate ID.
    pub aggregate_id: String,
    /// Contiguous sequence scoped to the aggregate.
    pub aggregate_sequence: u64,
    /// Stable namespaced fact name.
    pub event_type: String,
    /// Version of the event payload.
    pub event_version: u32,
    /// Transaction clock instant.
    pub occurred_at: SystemTime,
    /// Correlates related work.
    pub correlation_id: CorrelationId,
    /// Direct causal event when present.
    pub causation_id: Option<EventId>,
    /// Bounded canonical JSON string.
    pub payload_json: String,
}

/// One bounded page of timeline facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelinePage {
    /// Ordered events strictly after the requested cursor.
    pub events: Vec<TimelineEvent>,
    /// Highest cursor currently committed for this authorized session.
    pub high_watermark: TimelineCursor,
    /// More matching events remain after this page.
    pub has_more: bool,
}

/// Authorized current session projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionStatusView {
    /// Session ID.
    pub session_id: SessionId,
    /// Canonical optimistic-concurrency revision.
    pub revision: u64,
    /// Number of pending durable inbox records.
    pub pending_inputs: u64,
    /// Active mutating turn, when one exists.
    pub active_turn_id: Option<TurnId>,
    /// Highest durable timeline cursor visible to this session.
    pub latest_cursor: TimelineCursor,
}

/// Timeline/query persistence failures.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TimelineStoreError {
    /// Session does not exist.
    #[error("session was not found")]
    SessionNotFound,
    /// Principal or binding does not own the session.
    #[error("session access is unauthorized")]
    Unauthorized,
    /// Requested cursor predates retained history.
    #[error("timeline cursor gap; earliest available cursor is {earliest:?}")]
    Gap {
        /// Earliest cursor that can be requested.
        earliest: TimelineCursor,
    },
    /// Requested cursor is beyond the durable high watermark.
    #[error("timeline cursor is ahead of the durable high watermark")]
    CursorAhead,
    /// Persistence dependency failed.
    #[error("timeline store is unavailable: {0}")]
    Unavailable(String),
    /// Stored timeline data is invalid.
    #[error("timeline invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port for authorized timeline and session-status queries.
pub trait TimelineStore {
    /// Reads a bounded, cursor-exclusive page.
    ///
    /// # Errors
    ///
    /// Returns [`TimelineStoreError`] for authorization, cursor, or persistence failure.
    fn timeline_page(&self, query: TimelineQuery) -> Result<TimelinePage, TimelineStoreError>;

    /// Reads current authorized session status.
    ///
    /// # Errors
    ///
    /// Returns [`TimelineStoreError`] for authorization or persistence failure.
    fn session_status(
        &self,
        session_id: SessionId,
        ownership: OwnershipContext,
    ) -> Result<SessionStatusView, TimelineStoreError>;
}

/// Validation failures before a timeline query reaches storage.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TimelineUseCaseError {
    /// Page size must be within 1 through 1,000 rows.
    #[error("timeline page size must be between 1 and 1000")]
    InvalidPageSize,
    /// Store rejected the query.
    #[error(transparent)]
    Store(#[from] TimelineStoreError),
}

/// Reads a bounded authorized timeline page.
///
/// # Errors
///
/// Returns [`TimelineUseCaseError`] for invalid bounds or store failure.
pub fn query_timeline(
    store: &impl TimelineStore,
    query: TimelineQuery,
) -> Result<TimelinePage, TimelineUseCaseError> {
    if !(1..=1000).contains(&query.limit) {
        return Err(TimelineUseCaseError::InvalidPageSize);
    }
    store
        .timeline_page(query)
        .map_err(TimelineUseCaseError::from)
}

/// Reads current authorized session state.
///
/// # Errors
///
/// Returns [`TimelineUseCaseError`] when the store rejects the query.
pub fn query_session_status(
    store: &impl TimelineStore,
    session_id: SessionId,
    ownership: OwnershipContext,
) -> Result<SessionStatusView, TimelineUseCaseError> {
    store
        .session_status(session_id, ownership)
        .map_err(TimelineUseCaseError::from)
}
