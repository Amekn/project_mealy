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

/// One owner-authorized session summary for bounded discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSummaryView {
    /// Session ID.
    pub session_id: SessionId,
    /// Stable lifecycle spelling.
    pub status: String,
    /// Canonical optimistic-concurrency revision.
    pub revision: u64,
    /// Number of pending durable inbox records.
    pub pending_inputs: u64,
    /// Active turn, when present.
    pub active_turn_id: Option<TurnId>,
    /// Creation time.
    pub created_at: SystemTime,
    /// Latest canonical session update time.
    pub updated_at: SystemTime,
}

/// Maximum UTF-8 bytes returned for either side of one transcript-search hit.
pub const SESSION_SEARCH_MAXIMUM_EXCERPT_BYTES: usize = 512;

/// Exact-binding bounded search across canonical user and final-assistant transcript text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSearchQuery {
    /// Authenticated principal and channel binding.
    pub ownership: OwnershipContext,
    /// Non-empty literal text query; wildcard syntax has no special meaning.
    pub query: String,
    /// Maximum matching turns from one through 100.
    pub limit: usize,
}

/// One canonical turn matching an owner-authorized transcript query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSearchHitView {
    /// Owning session accepted by `chat --session-id`.
    pub session_id: SessionId,
    /// Canonical turn identity.
    pub turn_id: TurnId,
    /// Canonical root task identity.
    pub task_id: mealy_domain::TaskId,
    /// Bounded user-text excerpt when that side matched.
    pub user_excerpt: Option<String>,
    /// Digest of the complete canonical user input.
    pub user_content_digest: String,
    /// Bounded final-assistant excerpt when that side matched.
    pub assistant_excerpt: Option<String>,
    /// Digest of the complete final assistant text when present.
    pub assistant_content_digest: Option<String>,
    /// Turn creation time used for deterministic newest-first ordering.
    pub created_at: SystemTime,
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
    /// Search query or result bounds are invalid.
    #[error("session transcript search bounds are invalid")]
    InvalidSearch,
    /// Persistence dependency failed.
    #[error("timeline store is unavailable: {0}")]
    Unavailable(String),
    /// Stored timeline data is invalid.
    #[error("timeline invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port for authorized timeline and session-status queries.
pub trait TimelineStore {
    /// Lists a bounded set of sessions owned by the exact principal/channel binding.
    ///
    /// # Errors
    ///
    /// Returns [`TimelineStoreError`] for invalid stored evidence or persistence failure.
    fn sessions(
        &self,
        ownership: OwnershipContext,
        limit: usize,
    ) -> Result<Vec<SessionSummaryView>, TimelineStoreError>;

    /// Searches canonical transcript text within the exact principal/channel binding.
    ///
    /// # Errors
    ///
    /// Returns [`TimelineStoreError`] for invalid bounds, corrupt evidence, or persistence failure.
    fn search_sessions(
        &self,
        query: &SessionSearchQuery,
    ) -> Result<Vec<SessionSearchHitView>, TimelineStoreError>;

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
    /// Transcript search text must be non-empty, trimmed, control-free, and at most 4,096 bytes.
    #[error("session transcript search query is invalid")]
    InvalidSearchQuery,
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

/// Lists recently updated sessions for one exact authenticated binding.
///
/// # Errors
///
/// Returns [`TimelineUseCaseError`] when the limit is outside 1 through 100 or storage fails.
pub fn query_sessions(
    store: &impl TimelineStore,
    ownership: OwnershipContext,
    limit: usize,
) -> Result<Vec<SessionSummaryView>, TimelineUseCaseError> {
    if !(1..=100).contains(&limit) {
        return Err(TimelineUseCaseError::InvalidPageSize);
    }
    store.sessions(ownership, limit).map_err(Into::into)
}

/// Searches canonical user/final-assistant transcript text for one exact authenticated binding.
///
/// # Errors
///
/// Returns [`TimelineUseCaseError`] for unsafe query/limit values or storage failure.
pub fn search_sessions(
    store: &impl TimelineStore,
    query: &SessionSearchQuery,
) -> Result<Vec<SessionSearchHitView>, TimelineUseCaseError> {
    if query.query.is_empty()
        || query.query.len() > 4_096
        || query.query.trim() != query.query
        || query.query.chars().any(char::is_control)
        || !(1..=100).contains(&query.limit)
    {
        return Err(TimelineUseCaseError::InvalidSearchQuery);
    }
    store.search_sessions(query).map_err(Into::into)
}

/// Returns one UTF-8-safe bounded excerpt around a literal case-insensitive ASCII match.
#[must_use]
pub fn session_search_excerpt(content: &str, query: &str) -> Option<String> {
    if query.is_empty() {
        return None;
    }
    let match_start = if query.is_ascii() {
        content
            .as_bytes()
            .windows(query.len())
            .position(|window| window.eq_ignore_ascii_case(query.as_bytes()))
    } else {
        content.find(query)
    }?;
    let mut start = match_start.saturating_sub(128);
    while !content.is_char_boundary(start) {
        start = start.saturating_add(1);
    }
    let mut end = start
        .saturating_add(SESSION_SEARCH_MAXIMUM_EXCERPT_BYTES)
        .min(content.len());
    while !content.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    Some(content[start..end].to_owned())
}

#[cfg(test)]
mod tests {
    use super::{SESSION_SEARCH_MAXIMUM_EXCERPT_BYTES, session_search_excerpt};

    #[test]
    fn transcript_excerpt_is_literal_case_insensitive_and_utf8_bounded() {
        let content = format!("{}Needle-Marker{}", "é".repeat(300), "界".repeat(300));
        let excerpt = session_search_excerpt(&content, "needle-marker").expect("matching excerpt");
        assert!(excerpt.contains("Needle-Marker"));
        assert!(excerpt.len() <= SESSION_SEARCH_MAXIMUM_EXCERPT_BYTES);
        assert!(session_search_excerpt(&content, "%").is_none());
        assert!(session_search_excerpt(&content, "").is_none());
    }
}
