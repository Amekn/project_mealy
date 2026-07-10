//! Deterministic helpers for Mealy tests.

use mealy_application::{Clock, IdGenerator};
use mealy_domain::{CorrelationId, EventId, InboxEntryId, OutboxId, SessionId};
use std::{
    sync::atomic::{AtomicI64, AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const UUID_V7_MAX_EPOCH_MS: u64 = (1_u64 << 48) - 1;
const UUID_V7_COUNTER_LOW_MASK: u64 = (1_u64 << 62) - 1;

/// Thread-safe manually advanced UTC epoch-millisecond clock.
#[derive(Debug)]
pub struct TestClock {
    now_ms: AtomicI64,
}

impl TestClock {
    /// Creates a clock at a fixed epoch-millisecond value.
    #[must_use]
    pub const fn new(now_ms: i64) -> Self {
        Self {
            now_ms: AtomicI64::new(now_ms),
        }
    }

    /// Reads the current deterministic time.
    #[must_use]
    pub fn now_ms(&self) -> i64 {
        self.now_ms.load(Ordering::SeqCst)
    }

    /// Advances the clock and returns the resulting value.
    pub fn advance_ms(&self, delta_ms: i64) -> i64 {
        self.now_ms.fetch_add(delta_ms, Ordering::SeqCst) + delta_ms
    }
}

impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        let now_ms = self.now_ms();
        let offset = Duration::from_millis(now_ms.unsigned_abs());
        if now_ms.is_negative() {
            UNIX_EPOCH
                .checked_sub(offset)
                .expect("test clock instant must be representable")
        } else {
            UNIX_EPOCH
                .checked_add(offset)
                .expect("test clock instant must be representable")
        }
    }
}

/// Thread-safe deterministic generator for UUIDv7-backed domain identifiers.
#[derive(Debug)]
pub struct TestIdGenerator {
    epoch_ms: u64,
    counter: AtomicU64,
}

impl TestIdGenerator {
    /// Creates a generator at a fixed Unix epoch in milliseconds with a zero counter.
    ///
    /// # Panics
    ///
    /// Panics when `epoch_ms` exceeds the 48-bit timestamp field available in `UUIDv7`.
    #[must_use]
    pub const fn new(epoch_ms: u64) -> Self {
        assert!(
            epoch_ms <= UUID_V7_MAX_EPOCH_MS,
            "test ID epoch exceeds the UUIDv7 timestamp range"
        );
        Self {
            epoch_ms,
            counter: AtomicU64::new(0),
        }
    }

    fn next_uuid(&self) -> Uuid {
        let counter = self
            .counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
            .expect("test ID counter exhausted");

        let timestamp = u128::from(self.epoch_ms) << 80;
        let version = 7_u128 << 76;
        let counter_high = u128::from(counter >> 62) << 64;
        let rfc_4122_variant = 0b10_u128 << 62;
        let counter_low = u128::from(counter & UUID_V7_COUNTER_LOW_MASK);

        Uuid::from_u128(timestamp | version | counter_high | rfc_4122_variant | counter_low)
    }
}

impl IdGenerator for TestIdGenerator {
    fn generate_session_id(&self) -> SessionId {
        SessionId::from_uuid(self.next_uuid())
    }

    fn generate_inbox_entry_id(&self) -> InboxEntryId {
        InboxEntryId::from_uuid(self.next_uuid())
    }

    fn generate_event_id(&self) -> EventId {
        EventId::from_uuid(self.next_uuid())
    }

    fn generate_outbox_id(&self) -> OutboxId {
        OutboxId::from_uuid(self.next_uuid())
    }

    fn generate_correlation_id(&self) -> CorrelationId {
        CorrelationId::from_uuid(self.next_uuid())
    }
}

#[cfg(test)]
mod tests {
    use super::{TestClock, TestIdGenerator};
    use mealy_application::{Clock, IdGenerator};
    use mealy_domain::{CorrelationId, EventId, InboxEntryId, OutboxId, SessionId};
    use std::{collections::HashSet, sync::Arc, thread, time::Duration};
    use uuid::{Uuid, Variant};

    const EPOCH_MS: u64 = 1_700_000_000_123;

    fn generate_all_types(generator: &TestIdGenerator) -> [Uuid; 5] {
        let session_id: SessionId = generator.generate_session_id();
        let inbox_entry_id: InboxEntryId = generator.generate_inbox_entry_id();
        let event_id: EventId = generator.generate_event_id();
        let outbox_id: OutboxId = generator.generate_outbox_id();
        let correlation_id: CorrelationId = generator.generate_correlation_id();

        [
            session_id.as_uuid(),
            inbox_entry_id.as_uuid(),
            event_id.as_uuid(),
            outbox_id.as_uuid(),
            correlation_id.as_uuid(),
        ]
    }

    #[test]
    fn clock_advances_only_when_requested() {
        let clock = TestClock::new(100);
        assert_eq!(clock.now_ms(), 100);
        assert_eq!(clock.advance_ms(25), 125);
        assert_eq!(clock.now_ms(), 125);
    }

    #[test]
    fn clock_trait_converts_milliseconds_to_system_time() {
        let clock = TestClock::new(1_250);
        assert_eq!(
            Clock::now(&clock),
            std::time::UNIX_EPOCH + Duration::from_millis(1_250)
        );

        clock.advance_ms(-1_500);
        assert_eq!(
            Clock::now(&clock),
            std::time::UNIX_EPOCH - Duration::from_millis(250)
        );
    }

    #[test]
    fn id_sequence_is_repeatable_for_a_fixed_epoch() {
        let first = TestIdGenerator::new(EPOCH_MS);
        let second = TestIdGenerator::new(EPOCH_MS);

        assert_eq!(generate_all_types(&first), generate_all_types(&second));
        assert_eq!(generate_all_types(&first), generate_all_types(&second));
    }

    #[test]
    fn every_id_type_is_unique_and_uuid_v7() {
        let generator = TestIdGenerator::new(EPOCH_MS);
        let ids = generate_all_types(&generator);
        let unique = ids.into_iter().collect::<HashSet<_>>();

        assert_eq!(unique.len(), ids.len());
        for id in ids {
            assert_eq!(id.get_version_num(), 7);
            assert_eq!(id.get_variant(), Variant::RFC4122);
        }
    }

    #[test]
    fn concurrent_generation_remains_unique() {
        const THREADS: usize = 8;
        const IDS_PER_THREAD: usize = 128;

        let generator = Arc::new(TestIdGenerator::new(EPOCH_MS));
        let handles = (0..THREADS)
            .map(|_| {
                let generator = Arc::clone(&generator);
                thread::spawn(move || {
                    (0..IDS_PER_THREAD)
                        .map(|_| generator.generate_event_id().as_uuid())
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();

        let ids = handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("ID generation thread must finish"))
            .collect::<Vec<_>>();
        let unique = ids.iter().copied().collect::<HashSet<_>>();

        assert_eq!(ids.len(), THREADS * IDS_PER_THREAD);
        assert_eq!(unique.len(), ids.len());
    }
}
