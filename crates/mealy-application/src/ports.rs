use mealy_domain::{CorrelationId, EventId, InboxEntryId, OutboxId, SessionId};
use std::time::SystemTime;

/// Supplies wall-clock time to use cases without hiding nondeterminism in domain logic.
pub trait Clock {
    /// Returns the current wall-clock instant.
    fn now(&self) -> SystemTime;
}

/// Supplies typed identifiers to use cases.
pub trait IdGenerator {
    /// Generates a new session identifier.
    fn generate_session_id(&self) -> SessionId;

    /// Generates a new durable inbox-entry identifier.
    fn generate_inbox_entry_id(&self) -> InboxEntryId;

    /// Generates a new journal-event identifier.
    fn generate_event_id(&self) -> EventId;

    /// Generates a new durable outbox identifier.
    fn generate_outbox_id(&self) -> OutboxId;

    /// Generates a new command/event correlation identifier.
    fn generate_correlation_id(&self) -> CorrelationId;
}
