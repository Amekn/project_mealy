//! Cross-crate Phase 1 proof for promotion, leases, recovery, and timeline cursors.

use mealy_application::{
    AdmitInputCommand, InputAdmissionLimits, LeaseClaimOutcome, LeaseConcurrencyLimits,
    LeaseLimits, LeaseReleaseReason, OwnershipContext, PromotionDefaults, PromotionOutcome,
    ReleaseLeaseCommit, RunCompletionStatus, SchedulerStore, SchedulerStoreError,
    SchedulerUseCaseError, TimelineQuery, admit_input, claim_next_work,
    claim_next_work_with_concurrency, complete_run, create_session, heartbeat_lease,
    pending_promotion_sessions, promote_next_input, query_session_status, query_timeline,
    recover_expired_leases,
};
use mealy_domain::{
    ChannelBindingId, CorrelationId, DeliveryMode, EventId, PrincipalId, SessionId, WorkerId,
};
use mealy_infrastructure::SqliteStore;
use mealy_testkit::{TestClock, TestIdGenerator};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, SystemTime},
};

const NOW_MS: i64 = 1_782_062_400_000;

struct TemporaryDatabase(PathBuf);

impl TemporaryDatabase {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("mealy-phase1-{}.sqlite3", SessionId::new())))
    }

    fn sidecar(&self, suffix: &str) -> PathBuf {
        let mut path = self.0.as_os_str().to_owned();
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

fn admit(
    store: &mut SqliteStore,
    clock: &TestClock,
    ids: &TestIdGenerator,
    session_id: SessionId,
    ownership: OwnershipContext,
    sequence: u64,
) {
    admit_mode(
        store,
        clock,
        ids,
        session_id,
        ownership,
        sequence,
        DeliveryMode::Queue,
    );
}

fn admit_mode(
    store: &mut SqliteStore,
    clock: &TestClock,
    ids: &TestIdGenerator,
    session_id: SessionId,
    ownership: OwnershipContext,
    sequence: u64,
    delivery_mode: DeliveryMode,
) {
    admit_input(
        store,
        clock,
        ids,
        InputAdmissionLimits::default(),
        AdmitInputCommand {
            session_id,
            ownership,
            dedupe_key: format!("delivery-{sequence}"),
            delivery_mode,
            content: format!("input {sequence}"),
        },
    )
    .expect("admit input");
}

#[test]
fn steer_at_boundary_attaches_fifo_input_to_the_active_run() {
    let clock = TestClock::new(NOW_MS);
    let ids = TestIdGenerator::new(NOW_MS as u64);
    let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
    let session_id = create_session(&mut store, &clock, &ids, ownership).expect("create session");
    admit(&mut store, &clock, &ids, session_id, ownership, 1);
    let PromotionOutcome::Promoted(active) = promote_next_input(
        &mut store,
        &clock,
        &ids,
        session_id,
        ownership,
        &PromotionDefaults::default(),
    )
    .expect("promote initial input") else {
        panic!("expected active turn");
    };
    admit_mode(
        &mut store,
        &clock,
        &ids,
        session_id,
        ownership,
        2,
        DeliveryMode::SteerAtBoundary,
    );
    assert_eq!(
        pending_promotion_sessions(&store, 10)
            .expect("scan active steering candidate")
            .len(),
        1
    );
    let PromotionOutcome::Steered(steered) = promote_next_input(
        &mut store,
        &clock,
        &ids,
        session_id,
        ownership,
        &PromotionDefaults::default(),
    )
    .expect("attach steering input") else {
        panic!("expected steering attachment");
    };
    assert_eq!(steered.inbox_sequence, 2);
    assert_eq!(steered.turn_id, active.turn_id);
    assert_eq!(steered.run_id, active.run_id);
    let status = query_session_status(&store, session_id, ownership).expect("query status");
    assert_eq!(status.pending_inputs, 0);
    assert_eq!(status.active_turn_id, Some(active.turn_id));
    let timeline = query_timeline(
        &store,
        TimelineQuery {
            session_id,
            ownership,
            after: None,
            limit: 100,
        },
    )
    .expect("query steering timeline");
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "input.steered")
            .count(),
        1
    );
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "run.input_attached")
            .count(),
        1
    );
}

#[test]
fn interrupt_then_queue_cancels_unclaimed_work_and_promotes_after_the_boundary() {
    let clock = TestClock::new(NOW_MS);
    let ids = TestIdGenerator::new(NOW_MS as u64);
    let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
    let session_id = create_session(&mut store, &clock, &ids, ownership).expect("create session");
    admit(&mut store, &clock, &ids, session_id, ownership, 1);
    let PromotionOutcome::Promoted(first) = promote_next_input(
        &mut store,
        &clock,
        &ids,
        session_id,
        ownership,
        &PromotionDefaults::default(),
    )
    .expect("promote initial input") else {
        panic!("expected first turn");
    };
    admit_mode(
        &mut store,
        &clock,
        &ids,
        session_id,
        ownership,
        2,
        DeliveryMode::InterruptThenQueue,
    );
    let PromotionOutcome::InterruptRequested(interruption) = promote_next_input(
        &mut store,
        &clock,
        &ids,
        session_id,
        ownership,
        &PromotionDefaults::default(),
    )
    .expect("request interruption") else {
        panic!("expected interruption request");
    };
    assert!(interruption.cancelled_before_claim);
    assert_eq!(interruption.turn_id, first.turn_id);
    let waiting = query_session_status(&store, session_id, ownership).expect("query boundary");
    assert_eq!(waiting.pending_inputs, 1);
    assert_eq!(waiting.active_turn_id, None);

    let PromotionOutcome::Promoted(second) = promote_next_input(
        &mut store,
        &clock,
        &ids,
        session_id,
        ownership,
        &PromotionDefaults::default(),
    )
    .expect("promote interrupting input after cancellation boundary") else {
        panic!("expected replacement turn");
    };
    assert_eq!(second.inbox_sequence, 2);
    assert_eq!(second.delivery_mode, DeliveryMode::InterruptThenQueue);
    assert_ne!(second.turn_id, first.turn_id);
    let timeline = query_timeline(
        &store,
        TimelineQuery {
            session_id,
            ownership,
            after: None,
            limit: 100,
        },
    )
    .expect("query interruption timeline");
    for expected in [
        "input.interrupt_requested",
        "task.cancelled",
        "run.cancelled",
    ] {
        assert_eq!(
            timeline
                .events
                .iter()
                .filter(|event| event.event_type == expected)
                .count(),
            1,
            "missing or duplicated {expected}"
        );
    }
}

#[test]
fn interrupt_then_queue_waits_for_a_running_worker_to_commit_cancelled() {
    let clock = TestClock::new(NOW_MS);
    let ids = TestIdGenerator::new(NOW_MS as u64);
    let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
    let session_id = create_session(&mut store, &clock, &ids, ownership).expect("create session");
    admit(&mut store, &clock, &ids, session_id, ownership, 1);
    assert!(matches!(
        promote_next_input(
            &mut store,
            &clock,
            &ids,
            session_id,
            ownership,
            &PromotionDefaults::default(),
        )
        .expect("promote initial input"),
        PromotionOutcome::Promoted(_)
    ));
    let LeaseClaimOutcome::Claimed(claim) = claim_next_work(
        &mut store,
        &clock,
        &ids,
        WorkerId::new(),
        Duration::from_secs(10),
        LeaseLimits::default(),
    )
    .expect("claim active work") else {
        panic!("expected claimed run");
    };
    admit_mode(
        &mut store,
        &clock,
        &ids,
        session_id,
        ownership,
        2,
        DeliveryMode::InterruptThenQueue,
    );
    let PromotionOutcome::InterruptRequested(interruption) = promote_next_input(
        &mut store,
        &clock,
        &ids,
        session_id,
        ownership,
        &PromotionDefaults::default(),
    )
    .expect("request running interruption") else {
        panic!("expected interruption request");
    };
    assert!(!interruption.cancelled_before_claim);
    assert!(
        pending_promotion_sessions(&store, 10)
            .expect("scan while cancellation is pending")
            .is_empty(),
        "same interrupt must not be requested repeatedly"
    );
    complete_run(
        &mut store,
        &clock,
        &ids,
        claim.lease.fence(),
        RunCompletionStatus::Cancelled,
        "cancelled at a safe boundary".to_owned(),
    )
    .expect("current worker commits cancellation boundary");
    let status = query_session_status(&store, session_id, ownership).expect("query cancellation");
    assert_eq!(status.active_turn_id, None);
    assert_eq!(status.pending_inputs, 1);
    assert!(matches!(
        promote_next_input(
            &mut store,
            &clock,
            &ids,
            session_id,
            ownership,
            &PromotionDefaults::default(),
        )
        .expect("promote after running cancellation"),
        PromotionOutcome::Promoted(receipt)
            if receipt.inbox_sequence == 2
                && receipt.delivery_mode == DeliveryMode::InterruptThenQueue
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn phase1_core_recovers_expired_work_and_preserves_timeline_order() {
    let database = TemporaryDatabase::new();
    let clock = TestClock::new(NOW_MS);
    let ids = TestIdGenerator::new(NOW_MS as u64);
    let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    let mut store = SqliteStore::open(&database.0, NOW_MS).expect("open store");
    let session_id = create_session(&mut store, &clock, &ids, ownership).expect("create session");
    admit(&mut store, &clock, &ids, session_id, ownership, 1);
    admit(&mut store, &clock, &ids, session_id, ownership, 2);

    let promoted = promote_next_input(
        &mut store,
        &clock,
        &ids,
        session_id,
        ownership,
        &PromotionDefaults::default(),
    )
    .expect("promote FIFO head");
    let PromotionOutcome::Promoted(promotion) = promoted else {
        panic!("expected a promoted turn");
    };
    assert_eq!(promotion.inbox_sequence, 1);
    assert!(matches!(
        promote_next_input(
            &mut store,
            &clock,
            &ids,
            session_id,
            ownership,
            &PromotionDefaults::default(),
        )
        .expect("inspect blocked head"),
        PromotionOutcome::ActiveTurn {
            pending_mode: Some(DeliveryMode::Queue),
            ..
        }
    ));

    let first_claim = claim_next_work(
        &mut store,
        &clock,
        &ids,
        WorkerId::new(),
        Duration::from_secs(10),
        LeaseLimits::default(),
    )
    .expect("claim queued run");
    let LeaseClaimOutcome::Claimed(first_claim) = first_claim else {
        panic!("expected runnable work");
    };
    assert_eq!(first_claim.lease.fence().fencing_token().get(), 1);
    let first_fence = first_claim.lease.fence();

    clock.advance_ms(1_000);
    heartbeat_lease(
        &mut store,
        &clock,
        first_fence,
        Duration::from_secs(10),
        LeaseLimits::default(),
    )
    .expect("heartbeat current lease");
    let regressed_release = store
        .release(ReleaseLeaseCommit {
            fence: first_fence,
            event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            released_at: SystemTime::UNIX_EPOCH
                + Duration::from_millis((NOW_MS + 500).cast_unsigned()),
            reason: LeaseReleaseReason::Yield,
        })
        .expect_err("release cannot precede the last durable heartbeat");
    assert_eq!(regressed_release, SchedulerStoreError::StaleFence);
    clock.advance_ms(11_000);
    let recovery = recover_expired_leases(&mut store, &clock, &ids, 32)
        .expect("reap expired lease while daemon remains online");
    assert_eq!(recovery.expired_leases, 1);
    assert_eq!(recovery.requeued_runs, 1);
    assert_eq!(recovery.pending_outbox, 3);

    let stale = heartbeat_lease(
        &mut store,
        &clock,
        first_fence,
        Duration::from_secs(10),
        LeaseLimits::default(),
    )
    .expect_err("expired worker fence must remain stale");
    assert_eq!(
        stale,
        SchedulerUseCaseError::Store(SchedulerStoreError::StaleFence)
    );

    let reclaimed = claim_next_work(
        &mut store,
        &clock,
        &ids,
        WorkerId::new(),
        Duration::from_secs(10),
        LeaseLimits::default(),
    )
    .expect("reclaim requeued work");
    let LeaseClaimOutcome::Claimed(reclaimed) = reclaimed else {
        panic!("expected reclaimed work");
    };
    assert!(reclaimed.lease.fence().fencing_token().get() > first_fence.fencing_token().get());

    let stale_result = complete_run(
        &mut store,
        &clock,
        &ids,
        first_fence,
        RunCompletionStatus::Succeeded,
        "late result".to_owned(),
    )
    .expect_err("expired worker cannot commit a terminal result");
    assert_eq!(
        stale_result,
        SchedulerUseCaseError::Store(SchedulerStoreError::StaleFence)
    );
    let completion = complete_run(
        &mut store,
        &clock,
        &ids,
        reclaimed.lease.fence(),
        RunCompletionStatus::Succeeded,
        "done".to_owned(),
    )
    .expect("current worker commits terminal result");
    assert_eq!(completion.run_id, reclaimed.lease.fence().run_id());
    let duplicate_result = complete_run(
        &mut store,
        &clock,
        &ids,
        reclaimed.lease.fence(),
        RunCompletionStatus::Succeeded,
        "duplicate".to_owned(),
    )
    .expect_err("released completion fence must be invalidated");
    assert_eq!(
        duplicate_result,
        SchedulerUseCaseError::Store(SchedulerStoreError::StaleFence)
    );

    let status = query_session_status(&store, session_id, ownership).expect("query status");
    assert_eq!(status.pending_inputs, 1);
    assert_eq!(status.active_turn_id, None);
    let second = promote_next_input(
        &mut store,
        &clock,
        &ids,
        session_id,
        ownership,
        &PromotionDefaults::default(),
    )
    .expect("promote second FIFO input after completion");
    let PromotionOutcome::Promoted(second) = second else {
        panic!("expected second promoted turn");
    };
    assert_eq!(second.inbox_sequence, 2);
    assert_ne!(second.turn_id, promotion.turn_id);
    let status = query_session_status(&store, session_id, ownership).expect("query next status");
    assert_eq!(status.pending_inputs, 0);
    assert_eq!(status.active_turn_id, Some(second.turn_id));
    let page = query_timeline(
        &store,
        TimelineQuery {
            session_id,
            ownership,
            after: None,
            limit: 100,
        },
    )
    .expect("query durable timeline");
    assert!(!page.events.is_empty());
    assert!(
        page.events
            .windows(2)
            .all(|pair| pair[0].cursor < pair[1].cursor)
    );
    assert_eq!(page.high_watermark, status.latest_cursor);
    let resumed = query_timeline(
        &store,
        TimelineQuery {
            session_id,
            ownership,
            after: Some(page.high_watermark),
            limit: 100,
        },
    )
    .expect("resume after high watermark");
    assert!(resumed.events.is_empty());
}

#[test]
fn concurrent_claimers_have_exactly_one_winner() {
    let database = TemporaryDatabase::new();
    let clock = TestClock::new(NOW_MS);
    let ids = TestIdGenerator::new(NOW_MS as u64);
    let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    {
        let mut store = SqliteStore::open(&database.0, NOW_MS).expect("open setup store");
        let session_id =
            create_session(&mut store, &clock, &ids, ownership).expect("create session");
        admit(&mut store, &clock, &ids, session_id, ownership, 1);
        assert!(matches!(
            promote_next_input(
                &mut store,
                &clock,
                &ids,
                session_id,
                ownership,
                &PromotionDefaults::default(),
            )
            .expect("promote work"),
            PromotionOutcome::Promoted(_)
        ));
    }

    let barrier = Arc::new(Barrier::new(2));
    let handles = (0..2)
        .map(|worker| {
            let path = database.0.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let mut store = SqliteStore::open(path, NOW_MS).expect("open claimant store");
                barrier.wait();
                claim_next_work(
                    &mut store,
                    &TestClock::new(NOW_MS),
                    &TestIdGenerator::new((NOW_MS + worker).cast_unsigned()),
                    WorkerId::new(),
                    Duration::from_secs(10),
                    LeaseLimits::default(),
                )
            })
        })
        .collect::<Vec<_>>();
    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().expect("claimant thread"))
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(LeaseClaimOutcome::Claimed(_))))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| {
                matches!(
                    outcome,
                    Ok(LeaseClaimOutcome::NoRunnableWork)
                        | Err(SchedulerUseCaseError::Store(SchedulerStoreError::Conflict))
                )
            })
            .count(),
        1
    );
}

#[test]
fn durable_claim_enforces_principal_and_agent_role_concurrency() {
    let clock = TestClock::new(NOW_MS);
    let ids = TestIdGenerator::new(NOW_MS as u64);
    let first_principal = PrincipalId::new();
    let limits = LeaseConcurrencyLimits::new(1, 1, 2).expect("valid limits");
    let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");

    let mut runnable = Vec::new();
    for index in 0..4 {
        let principal = if index < 2 {
            first_principal
        } else {
            PrincipalId::new()
        };
        let ownership = OwnershipContext::new(principal, ChannelBindingId::new());
        let session_id = create_session(&mut store, &clock, &ids, ownership).expect("session");
        admit(&mut store, &clock, &ids, session_id, ownership, index + 1);
        let PromotionOutcome::Promoted(receipt) = promote_next_input(
            &mut store,
            &clock,
            &ids,
            session_id,
            ownership,
            &PromotionDefaults::default(),
        )
        .expect("promotion") else {
            panic!("work should be promoted");
        };
        runnable.push(receipt.run_id);
    }

    let first = claim_next_work_with_concurrency(
        &mut store,
        &clock,
        &ids,
        WorkerId::new(),
        Duration::from_secs(10),
        LeaseLimits::default(),
        limits,
    )
    .expect("first claim");
    let LeaseClaimOutcome::Claimed(first) = first else {
        panic!("first run should be claimable");
    };
    assert_eq!(first.lease.fence().run_id(), runnable[0]);

    let second = claim_next_work_with_concurrency(
        &mut store,
        &clock,
        &ids,
        WorkerId::new(),
        Duration::from_secs(10),
        LeaseLimits::default(),
        limits,
    )
    .expect("second eligible claim");
    let LeaseClaimOutcome::Claimed(second) = second else {
        panic!("a different principal should retain capacity");
    };
    assert_eq!(second.lease.fence().run_id(), runnable[2]);

    assert_eq!(
        claim_next_work_with_concurrency(
            &mut store,
            &clock,
            &ids,
            WorkerId::new(),
            Duration::from_secs(10),
            LeaseLimits::default(),
            limits,
        )
        .expect("role-saturated query"),
        LeaseClaimOutcome::NoRunnableWork
    );
}

#[test]
fn global_cursor_gaps_between_sessions_do_not_report_retention_gaps() {
    let clock = TestClock::new(NOW_MS);
    let ids = TestIdGenerator::new(NOW_MS as u64);
    let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
    let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
    let first = create_session(&mut store, &clock, &ids, ownership).expect("create first session");
    let second =
        create_session(&mut store, &clock, &ids, ownership).expect("create second session");
    admit(&mut store, &clock, &ids, first, ownership, 1);
    admit(&mut store, &clock, &ids, second, ownership, 2);

    let from_origin = query_timeline(
        &store,
        TimelineQuery {
            session_id: second,
            ownership,
            after: Some(mealy_application::TimelineCursor(0)),
            limit: 100,
        },
    )
    .expect("global cursors belonging to another session are not retention gaps");
    assert_eq!(
        from_origin
            .events
            .iter()
            .map(|event| event.event_type.as_str())
            .collect::<Vec<_>>(),
        vec!["session.created", "input.accepted"]
    );
    assert!(
        from_origin.events[0].cursor.0 > 1,
        "the test requires an earlier global cursor owned by another session"
    );
}
