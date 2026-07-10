use mealy_application::{Clock, IdGenerator};
use mealy_domain::{CorrelationId, EventId, InboxEntryId, OutboxId, SessionId};
use std::time::SystemTime;

/// Production wall clock used at application transaction boundaries.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Production `UUIDv7` generator for application-owned session operations.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemIdGenerator;

impl IdGenerator for SystemIdGenerator {
    fn generate_session_id(&self) -> SessionId {
        SessionId::new()
    }

    fn generate_inbox_entry_id(&self) -> InboxEntryId {
        InboxEntryId::new()
    }

    fn generate_event_id(&self) -> EventId {
        EventId::new()
    }

    fn generate_outbox_id(&self) -> OutboxId {
        OutboxId::new()
    }

    fn generate_correlation_id(&self) -> CorrelationId {
        CorrelationId::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{SystemClock, SystemIdGenerator};
    use mealy_application::{Clock, IdGenerator};

    #[test]
    fn production_adapters_supply_time_and_uuid_v7_ids() {
        let before = std::time::SystemTime::now();
        let now = SystemClock.now();
        let after = std::time::SystemTime::now();
        assert!(now >= before && now <= after);

        let first = SystemIdGenerator.generate_session_id();
        let second = SystemIdGenerator.generate_session_id();
        assert_ne!(first, second);
        assert_eq!(first.as_uuid().get_version_num(), 7);
        assert_eq!(second.as_uuid().get_version_num(), 7);
    }
}
