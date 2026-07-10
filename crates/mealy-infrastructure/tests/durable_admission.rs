//! Cross-crate proof that acknowledged session input survives a real `SQLite` reopen.

use mealy_application::{
    AdmitInputCommand, InputAdmissionLimits, InputAdmissionOutcome, OwnershipContext,
    SessionStoreError, SessionUseCaseError, admit_input, create_session,
};
use mealy_domain::{ChannelBindingId, DeliveryMode, PrincipalId, SessionId};
use mealy_infrastructure::SqliteStore;
use mealy_testkit::{TestClock, TestIdGenerator};
use std::{fs, path::PathBuf};

const NOW_MS: i64 = 1_782_062_400_000;

struct TemporaryDatabase {
    path: PathBuf,
}

impl TemporaryDatabase {
    fn new() -> Self {
        Self {
            path: std::env::temp_dir()
                .join(format!("mealy-admission-{}.sqlite3", SessionId::new())),
        }
    }

    fn sidecar(&self, suffix: &str) -> PathBuf {
        let mut path = self.path.as_os_str().to_owned();
        path.push(suffix);
        PathBuf::from(path)
    }
}

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(self.sidecar(suffix));
        }
    }
}

#[test]
fn acknowledged_input_survives_reopen_and_deduplicates() {
    let database = TemporaryDatabase::new();
    let clock = TestClock::new(NOW_MS);
    let ids = TestIdGenerator::new(NOW_MS as u64);
    let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    let command_content = "preserve this accepted input".to_owned();

    let (session_id, first_receipt) = {
        let mut store = SqliteStore::open(&database.path, NOW_MS).expect("open file store");
        let session_id =
            create_session(&mut store, &clock, &ids, ownership).expect("create durable session");
        let outcome = admit_input(
            &mut store,
            &clock,
            &ids,
            InputAdmissionLimits::default(),
            AdmitInputCommand {
                session_id,
                ownership,
                dedupe_key: "channel-event-42".to_owned(),
                delivery_mode: DeliveryMode::Queue,
                content: command_content.clone(),
            },
        )
        .expect("acknowledge durably admitted input");
        assert!(matches!(outcome, InputAdmissionOutcome::Accepted(_)));
        (session_id, outcome.receipt().clone())
    };

    let mut reopened = SqliteStore::open(&database.path, NOW_MS + 1).expect("reopen store");
    let duplicate = admit_input(
        &mut reopened,
        &clock,
        &ids,
        InputAdmissionLimits::default(),
        AdmitInputCommand {
            session_id,
            ownership,
            dedupe_key: "channel-event-42".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: command_content,
        },
    )
    .expect("recover original admission receipt");

    assert!(duplicate.is_duplicate());
    assert_eq!(duplicate.receipt(), &first_receipt);
    assert_eq!(reopened.journal_count().expect("journal count"), 2);
    assert_eq!(reopened.outbox_count().expect("outbox count"), 1);

    let changed_retry = admit_input(
        &mut reopened,
        &clock,
        &ids,
        InputAdmissionLimits::default(),
        AdmitInputCommand {
            session_id,
            ownership,
            dedupe_key: "channel-event-42".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "changed after acknowledgement".to_owned(),
        },
    )
    .expect_err("idempotency key must remain bound to exact input");
    assert_eq!(
        changed_retry,
        SessionUseCaseError::Store(SessionStoreError::IdempotencyConflict)
    );
    assert_eq!(reopened.journal_count().expect("journal count"), 2);
    assert_eq!(reopened.outbox_count().expect("outbox count"), 1);
}
