use crate::{Clock, IdGenerator};
use mealy_domain::{CorrelationId, EventId};
use std::time::SystemTime;
use thiserror::Error;

/// Event IDs reserved for one expired-lease recovery transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseRecoveryEventIds {
    /// `lease.expired` event ID.
    pub lease_expired: EventId,
    /// `run.requeued` event ID.
    pub run_requeued: EventId,
    /// Effect recovery event ID for unknown, retryable, or undispatched interruption evidence.
    pub effect_recovered: EventId,
    /// `task.waiting` event ID when an unknown effect blocks task execution.
    pub task_waiting: EventId,
    /// `agent.boundary_recovered` event ID and checkpoint evidence ID.
    pub agent_boundary_recovered: EventId,
}

/// One bounded startup recovery transaction request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupRecoveryCommit {
    /// Recovery cutoff from the application clock.
    pub now: SystemTime,
    /// Maximum expired leases to process in this transaction.
    pub batch_limit: usize,
    /// Stable correlation for this startup recovery pass.
    pub correlation_id: CorrelationId,
    /// Preallocated event IDs, one set per possible transition.
    pub event_ids: Vec<LeaseRecoveryEventIds>,
    /// Whether process-crash outbox claims should be reset during this pass.
    pub recover_outbox_claims: bool,
}

/// Result of one idempotent recovery batch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StartupRecoveryBatch {
    /// Leases transitioned from active to expired.
    pub expired_leases: u64,
    /// Runs safely returned to the runnable queue.
    pub requeued_runs: u64,
    /// Runs parked in waiting because an external effect outcome is unknown.
    pub waiting_runs: u64,
    /// Pending/delivering outbox rows awaiting resumption.
    pub pending_outbox: u64,
    /// More expired leases remain at the same cutoff.
    pub has_more: bool,
    /// Highest recovery timeline cursor, if recovery emitted facts.
    pub cursor: Option<u64>,
}

/// Aggregate startup recovery result.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StartupRecoverySummary {
    /// Total leases expired.
    pub expired_leases: u64,
    /// Total runs requeued.
    pub requeued_runs: u64,
    /// Total runs parked in waiting on explicit effect reconciliation.
    pub waiting_runs: u64,
    /// Pending outbox rows observed after recovery.
    pub pending_outbox: u64,
    /// Highest emitted cursor.
    pub cursor: Option<u64>,
}

/// Startup-recovery persistence failures.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum StartupRecoveryStoreError {
    /// Persistence dependency failed.
    #[error("startup recovery store is unavailable: {0}")]
    Unavailable(String),
    /// Canonical recovery state is inconsistent.
    #[error("startup recovery invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port for deterministic recovery before readiness.
pub trait StartupRecoveryStore {
    /// Expires one bounded batch and reports pending outbound delivery.
    ///
    /// # Errors
    ///
    /// Returns [`StartupRecoveryStoreError`] on persistence or invariant failure.
    fn recover_startup_batch(
        &mut self,
        commit: StartupRecoveryCommit,
    ) -> Result<StartupRecoveryBatch, StartupRecoveryStoreError>;
}

/// Startup-recovery use-case failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum StartupRecoveryError {
    /// Batch size must be between 1 and 1,000.
    #[error("startup recovery batch size must be between 1 and 1000")]
    InvalidBatchSize,
    /// Recovery counters overflowed.
    #[error("startup recovery counter overflow")]
    CounterOverflow,
    /// Store rejected recovery.
    #[error(transparent)]
    Store(#[from] StartupRecoveryStoreError),
}

/// Runs bounded, deterministic lease/outbox recovery to completion before readiness.
///
/// # Errors
///
/// Returns [`StartupRecoveryError`] for invalid bounds, overflow, or store failure.
pub fn recover_startup(
    store: &mut impl StartupRecoveryStore,
    clock: &impl Clock,
    ids: &impl IdGenerator,
    batch_limit: usize,
) -> Result<StartupRecoverySummary, StartupRecoveryError> {
    recover(store, clock, ids, batch_limit, true)
}

/// Reaps expired worker leases while the daemon remains online.
///
/// Unlike startup recovery, this leaves live outbox dispatcher claims untouched.
///
/// # Errors
///
/// Returns [`StartupRecoveryError`] for invalid bounds, overflow, or store failure.
pub fn recover_expired_leases(
    store: &mut impl StartupRecoveryStore,
    clock: &impl Clock,
    ids: &impl IdGenerator,
    batch_limit: usize,
) -> Result<StartupRecoverySummary, StartupRecoveryError> {
    recover(store, clock, ids, batch_limit, false)
}

fn recover(
    store: &mut impl StartupRecoveryStore,
    clock: &impl Clock,
    ids: &impl IdGenerator,
    batch_limit: usize,
    recover_outbox_claims: bool,
) -> Result<StartupRecoverySummary, StartupRecoveryError> {
    if !(1..=1000).contains(&batch_limit) {
        return Err(StartupRecoveryError::InvalidBatchSize);
    }
    let now = clock.now();
    let correlation_id = ids.generate_correlation_id();
    let mut summary = StartupRecoverySummary::default();
    loop {
        let event_ids = (0..batch_limit)
            .map(|_| LeaseRecoveryEventIds {
                lease_expired: ids.generate_event_id(),
                run_requeued: ids.generate_event_id(),
                effect_recovered: ids.generate_event_id(),
                task_waiting: ids.generate_event_id(),
                agent_boundary_recovered: ids.generate_event_id(),
            })
            .collect();
        let batch = store.recover_startup_batch(StartupRecoveryCommit {
            now,
            batch_limit,
            correlation_id,
            event_ids,
            recover_outbox_claims,
        })?;
        summary.expired_leases = summary
            .expired_leases
            .checked_add(batch.expired_leases)
            .ok_or(StartupRecoveryError::CounterOverflow)?;
        summary.requeued_runs = summary
            .requeued_runs
            .checked_add(batch.requeued_runs)
            .ok_or(StartupRecoveryError::CounterOverflow)?;
        summary.waiting_runs = summary
            .waiting_runs
            .checked_add(batch.waiting_runs)
            .ok_or(StartupRecoveryError::CounterOverflow)?;
        summary.pending_outbox = batch.pending_outbox;
        summary.cursor = batch.cursor.or(summary.cursor);
        if !batch.has_more {
            return Ok(summary);
        }
    }
}
