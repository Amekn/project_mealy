//! Durable outbox claim, crash recovery, ownership, and completion proof.

use mealy_application::{
    AdmitInputCommand, InputAdmissionLimits, OutboxClaimOutcome, OutboxStoreError,
    OutboxUseCaseError, OwnershipContext, admit_input, claim_next_outbox, complete_outbox,
    create_session, recover_startup,
};
use mealy_domain::{ChannelBindingId, DeliveryMode, PrincipalId, WorkerId};
use mealy_infrastructure::SqliteStore;
use mealy_testkit::{TestClock, TestIdGenerator};
use std::time::Duration;

const NOW_MS: i64 = 1_782_062_400_000;

#[test]
fn startup_recovers_an_inflight_delivery_under_a_new_exact_owner() {
    let clock = TestClock::new(NOW_MS);
    let ids = TestIdGenerator::new(NOW_MS as u64);
    let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
    let session_id = create_session(&mut store, &clock, &ids, ownership).expect("create session");
    admit_input(
        &mut store,
        &clock,
        &ids,
        InputAdmissionLimits::default(),
        AdmitInputCommand {
            session_id,
            ownership,
            dedupe_key: "delivery".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "hello".to_owned(),
        },
    )
    .expect("admit input");

    let first_owner = WorkerId::new();
    let OutboxClaimOutcome::Claimed(first) =
        claim_next_outbox(&mut store, &clock, first_owner, Duration::from_secs(30), 3)
            .expect("claim first attempt")
    else {
        panic!("expected pending acknowledgement");
    };
    assert_eq!(first.attempt, 1);

    let wrong_owner = complete_outbox(&mut store, &clock, WorkerId::new(), first.outbox_id)
        .expect_err("another worker cannot complete the claim");
    assert_eq!(
        wrong_owner,
        OutboxUseCaseError::Store(OutboxStoreError::StaleClaim)
    );

    let recovery = recover_startup(&mut store, &clock, &ids, 16).expect("recover process crash");
    assert_eq!(recovery.pending_outbox, 1);
    let second_owner = WorkerId::new();
    let OutboxClaimOutcome::Claimed(second) =
        claim_next_outbox(&mut store, &clock, second_owner, Duration::from_secs(30), 3)
            .expect("reclaim after restart")
    else {
        panic!("expected recovered acknowledgement");
    };
    assert_eq!(second.outbox_id, first.outbox_id);
    assert_eq!(second.attempt, 2);

    let stale = complete_outbox(&mut store, &clock, first_owner, first.outbox_id)
        .expect_err("pre-crash owner must remain fenced");
    assert_eq!(
        stale,
        OutboxUseCaseError::Store(OutboxStoreError::StaleClaim)
    );
    complete_outbox(&mut store, &clock, second_owner, second.outbox_id)
        .expect("current owner completes delivery");
    assert_eq!(
        claim_next_outbox(&mut store, &clock, second_owner, Duration::from_secs(30), 3,)
            .expect("inspect drained outbox"),
        OutboxClaimOutcome::NoPendingDelivery
    );
}
