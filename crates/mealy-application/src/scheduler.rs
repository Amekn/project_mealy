use crate::{Clock, FinalMessageCommit, IdGenerator};
use mealy_domain::{
    CorrelationId, EventId, LeaseFence, OutboxId, RunId, SessionId, TaskId, TurnId, WorkLease,
    WorkerId,
};
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// Bounded lease duration policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseLimits {
    minimum: Duration,
    maximum: Duration,
}

impl LeaseLimits {
    /// Creates lease-duration bounds.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerUseCaseError`] for zero or inverted bounds.
    pub fn new(minimum: Duration, maximum: Duration) -> Result<Self, SchedulerUseCaseError> {
        if minimum.is_zero() || maximum < minimum {
            return Err(SchedulerUseCaseError::InvalidLeaseLimits);
        }
        Ok(Self { minimum, maximum })
    }

    /// Returns whether a duration is permitted.
    #[must_use]
    pub fn contains(self, value: Duration) -> bool {
        value >= self.minimum && value <= self.maximum
    }
}

impl Default for LeaseLimits {
    fn default() -> Self {
        Self {
            minimum: Duration::from_secs(1),
            maximum: Duration::from_mins(5),
        }
    }
}

/// Values supplied to an atomic next-work claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseClaimCommit {
    /// Claiming worker.
    pub owner_id: WorkerId,
    /// ID reserved for the claimed lease.
    pub lease_id: mealy_domain::LeaseId,
    /// `run.started` event ID for the claim.
    pub run_event_id: EventId,
    /// `task.started` event ID when the task first enters running state.
    pub task_event_id: EventId,
    /// Correlation ID for scheduler activity.
    pub correlation_id: CorrelationId,
    /// Claim time.
    pub claimed_at: SystemTime,
    /// Exclusive deadline.
    pub expires_at: SystemTime,
    /// Per-principal/session/role durable claim ceilings.
    pub concurrency_limits: LeaseConcurrencyLimits,
}

/// Durable scheduler concurrency ceilings evaluated in the lease-claim transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseConcurrencyLimits {
    /// Maximum active leases for one principal.
    pub maximum_per_principal: u32,
    /// Maximum active leases for one session.
    pub maximum_per_session: u32,
    /// Maximum active leases for one agent role.
    pub maximum_per_agent_role: u32,
}

impl LeaseConcurrencyLimits {
    /// Creates positive scheduler concurrency ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerUseCaseError::InvalidConcurrencyLimits`] when any ceiling is zero.
    pub const fn new(
        maximum_per_principal: u32,
        maximum_per_session: u32,
        maximum_per_agent_role: u32,
    ) -> Result<Self, SchedulerUseCaseError> {
        if maximum_per_principal == 0 || maximum_per_session == 0 || maximum_per_agent_role == 0 {
            return Err(SchedulerUseCaseError::InvalidConcurrencyLimits);
        }
        Ok(Self {
            maximum_per_principal,
            maximum_per_session,
            maximum_per_agent_role,
        })
    }
}

impl Default for LeaseConcurrencyLimits {
    fn default() -> Self {
        Self {
            maximum_per_principal: u32::MAX,
            maximum_per_session: u32::MAX,
            maximum_per_agent_role: u32::MAX,
        }
    }
}

/// Work returned to a scheduler worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseClaimReceipt {
    /// Canonical lease and fence.
    pub lease: WorkLease,
    /// Task owning the run.
    pub task_id: TaskId,
    /// Turn owning the task.
    pub turn_id: TurnId,
    /// Timeline cursor for the durable claim event.
    pub cursor: u64,
}

/// Result of claiming the oldest runnable work item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeaseClaimOutcome {
    /// Runnable work was atomically leased.
    Claimed(LeaseClaimReceipt),
    /// No eligible work exists.
    NoRunnableWork,
}

/// Values supplied to a durable heartbeat.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeartbeatCommit {
    /// Exact active lease fence.
    pub fence: LeaseFence,
    /// Heartbeat time.
    pub heartbeat_at: SystemTime,
    /// New exclusive deadline.
    pub expires_at: SystemTime,
}

/// Why a worker deliberately gives work back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseReleaseReason {
    /// Cooperative yield while keeping work runnable.
    Yield,
    /// Daemon shutdown drain.
    Shutdown,
    /// Classified retry at a later scheduler attempt.
    Retry,
}

impl LeaseReleaseReason {
    /// Stable journal/storage spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Yield => "yield",
            Self::Shutdown => "shutdown",
            Self::Retry => "retry",
        }
    }
}

/// Values supplied to a fenced lease release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseLeaseCommit {
    /// Exact active lease fence.
    pub fence: LeaseFence,
    /// Release event ID.
    pub event_id: EventId,
    /// Correlation ID for the release.
    pub correlation_id: CorrelationId,
    /// Release time.
    pub released_at: SystemTime,
    /// Classified reason.
    pub reason: LeaseReleaseReason,
}

/// Terminal result accepted from a fenced worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunCompletionStatus {
    /// Run produced its final response successfully.
    Succeeded,
    /// Run terminated with a classified failure.
    Failed,
    /// Run honored a cancellation request or forced stop.
    Cancelled,
}

impl RunCompletionStatus {
    /// Stable storage spelling shared by run and task projections.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Stable terminal turn spelling.
    #[must_use]
    pub const fn turn_status(self) -> &'static str {
        match self {
            Self::Succeeded => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Complete atomic input for a worker-originated terminal result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteRunCommit {
    /// Exact active lease fence.
    pub fence: LeaseFence,
    /// Terminal classification.
    pub status: RunCompletionStatus,
    /// Bounded final response or operator-safe failure summary.
    pub summary: String,
    /// Durable final assistant message inserted in the same terminal transaction.
    pub final_message: Option<FinalMessageCommit>,
    /// Run terminal event.
    pub run_event_id: EventId,
    /// Task terminal event.
    pub task_event_id: EventId,
    /// Turn terminal event.
    pub turn_event_id: EventId,
    /// Session-visible terminal event.
    pub session_event_id: EventId,
    /// Durable final delivery.
    pub outbox_id: OutboxId,
    /// Correlates the terminal transition.
    pub correlation_id: CorrelationId,
    /// Worker completion time, which must precede lease expiry.
    pub completed_at: SystemTime,
}

/// Receipt for an accepted fenced terminal result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunCompletionReceipt {
    /// Completed run.
    pub run_id: RunId,
    /// Owning task.
    pub task_id: TaskId,
    /// Owning turn.
    pub turn_id: TurnId,
    /// Owning session released for its next FIFO input.
    pub session_id: SessionId,
    /// Final response outbox record.
    pub outbox_id: OutboxId,
    /// Highest timeline cursor committed with the result.
    pub cursor: u64,
}

/// Scheduler persistence failures.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SchedulerStoreError {
    /// Lease fence no longer identifies current unexpired ownership.
    #[error("lease fence is stale")]
    StaleFence,
    /// Concurrent scheduler state changed.
    #[error("scheduler state conflicted")]
    Conflict,
    /// Persistence dependency failed.
    #[error("scheduler store is unavailable: {0}")]
    Unavailable(String),
    /// Canonical data violates an invariant.
    #[error("scheduler store invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port for atomic lease claim, heartbeat, and release operations.
pub trait SchedulerStore {
    /// Claims the oldest eligible run.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerStoreError`] on conflict or persistence failure.
    fn claim_next(
        &mut self,
        commit: LeaseClaimCommit,
    ) -> Result<LeaseClaimOutcome, SchedulerStoreError>;

    /// Extends exactly one current unexpired lease.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerStoreError::StaleFence`] for any identity/token/expiry mismatch.
    fn heartbeat(&mut self, commit: HeartbeatCommit) -> Result<WorkLease, SchedulerStoreError>;

    /// Releases exactly one current unexpired lease and requeues its run.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerStoreError::StaleFence`] for any identity/token/expiry mismatch.
    fn release(&mut self, commit: ReleaseLeaseCommit) -> Result<u64, SchedulerStoreError>;

    /// Commits a terminal worker result only under the exact current unexpired fence.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerStoreError::StaleFence`] for any ownership/token/expiry mismatch.
    fn complete_run(
        &mut self,
        commit: CompleteRunCommit,
    ) -> Result<RunCompletionReceipt, SchedulerStoreError>;
}

/// Rejected scheduler use case.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SchedulerUseCaseError {
    /// Lease bound policy itself is invalid.
    #[error("lease limits must be nonzero and ordered")]
    InvalidLeaseLimits,
    /// At least one durable concurrency ceiling is zero.
    #[error("scheduler concurrency limits must be positive")]
    InvalidConcurrencyLimits,
    /// Requested duration is outside configured bounds.
    #[error("lease duration is outside configured bounds")]
    LeaseDurationOutOfBounds,
    /// Adding the duration overflowed the clock representation.
    #[error("lease expiry cannot be represented")]
    ExpiryOverflow,
    /// Terminal summary must contain 1 through 64 KiB of UTF-8.
    #[error("run completion summary must contain 1 through 65536 bytes")]
    InvalidCompletionSummary,
    /// Atomic storage failed.
    #[error(transparent)]
    Store(#[from] SchedulerStoreError),
}

/// Claims the oldest runnable work item with a bounded deadline.
///
/// # Errors
///
/// Returns [`SchedulerUseCaseError`] for invalid duration or store failure.
pub fn claim_next_work(
    store: &mut impl SchedulerStore,
    clock: &impl Clock,
    ids: &impl IdGenerator,
    owner_id: WorkerId,
    ttl: Duration,
    limits: LeaseLimits,
) -> Result<LeaseClaimOutcome, SchedulerUseCaseError> {
    claim_next_work_with_concurrency(
        store,
        clock,
        ids,
        owner_id,
        ttl,
        limits,
        LeaseConcurrencyLimits::default(),
    )
}

/// Claims the oldest work whose principal, session, and role retain durable capacity.
///
/// # Errors
///
/// Returns [`SchedulerUseCaseError`] for invalid duration/concurrency or store failure.
pub fn claim_next_work_with_concurrency(
    store: &mut impl SchedulerStore,
    clock: &impl Clock,
    ids: &impl IdGenerator,
    owner_id: WorkerId,
    ttl: Duration,
    limits: LeaseLimits,
    concurrency_limits: LeaseConcurrencyLimits,
) -> Result<LeaseClaimOutcome, SchedulerUseCaseError> {
    if !limits.contains(ttl) {
        return Err(SchedulerUseCaseError::LeaseDurationOutOfBounds);
    }
    LeaseConcurrencyLimits::new(
        concurrency_limits.maximum_per_principal,
        concurrency_limits.maximum_per_session,
        concurrency_limits.maximum_per_agent_role,
    )?;
    let claimed_at = clock.now();
    let expires_at = claimed_at
        .checked_add(ttl)
        .ok_or(SchedulerUseCaseError::ExpiryOverflow)?;
    store
        .claim_next(LeaseClaimCommit {
            owner_id,
            lease_id: ids.generate_lease_id(),
            run_event_id: ids.generate_event_id(),
            task_event_id: ids.generate_event_id(),
            correlation_id: ids.generate_correlation_id(),
            claimed_at,
            expires_at,
            concurrency_limits,
        })
        .map_err(SchedulerUseCaseError::from)
}

/// Heartbeats an exact active lease with a bounded extension from now.
///
/// # Errors
///
/// Returns [`SchedulerUseCaseError`] for invalid duration, overflow, or a stale fence.
pub fn heartbeat_lease(
    store: &mut impl SchedulerStore,
    clock: &impl Clock,
    fence: LeaseFence,
    extend_by: Duration,
    limits: LeaseLimits,
) -> Result<WorkLease, SchedulerUseCaseError> {
    if !limits.contains(extend_by) {
        return Err(SchedulerUseCaseError::LeaseDurationOutOfBounds);
    }
    let heartbeat_at = clock.now();
    let expires_at = heartbeat_at
        .checked_add(extend_by)
        .ok_or(SchedulerUseCaseError::ExpiryOverflow)?;
    store
        .heartbeat(HeartbeatCommit {
            fence,
            heartbeat_at,
            expires_at,
        })
        .map_err(SchedulerUseCaseError::from)
}

/// Releases current work through its exact fence.
///
/// # Errors
///
/// Returns [`SchedulerUseCaseError`] when the fence is stale or persistence fails.
pub fn release_lease(
    store: &mut impl SchedulerStore,
    clock: &impl Clock,
    ids: &impl IdGenerator,
    fence: LeaseFence,
    reason: LeaseReleaseReason,
) -> Result<u64, SchedulerUseCaseError> {
    store
        .release(ReleaseLeaseCommit {
            fence,
            event_id: ids.generate_event_id(),
            correlation_id: ids.generate_correlation_id(),
            released_at: clock.now(),
            reason,
        })
        .map_err(SchedulerUseCaseError::from)
}

/// Atomically accepts a terminal worker result under its exact unexpired lease fence.
///
/// # Errors
///
/// Returns [`SchedulerUseCaseError`] for an invalid summary, stale fence, or store failure.
pub fn complete_run(
    store: &mut impl SchedulerStore,
    clock: &impl Clock,
    ids: &impl IdGenerator,
    fence: LeaseFence,
    status: RunCompletionStatus,
    summary: String,
) -> Result<RunCompletionReceipt, SchedulerUseCaseError> {
    if summary.is_empty() || summary.len() > 64 * 1024 {
        return Err(SchedulerUseCaseError::InvalidCompletionSummary);
    }
    store
        .complete_run(CompleteRunCommit {
            fence,
            status,
            summary,
            final_message: None,
            run_event_id: ids.generate_event_id(),
            task_event_id: ids.generate_event_id(),
            turn_event_id: ids.generate_event_id(),
            session_event_id: ids.generate_event_id(),
            outbox_id: ids.generate_outbox_id(),
            correlation_id: ids.generate_correlation_id(),
            completed_at: clock.now(),
        })
        .map_err(SchedulerUseCaseError::from)
}

/// Atomically accepts a successful agent result and its durable final message under one fence.
///
/// # Errors
///
/// Returns [`SchedulerUseCaseError`] for invalid final content, stale ownership, or store failure.
pub fn complete_agent_run(
    store: &mut impl SchedulerStore,
    clock: &impl Clock,
    ids: &impl IdGenerator,
    fence: LeaseFence,
    final_message: FinalMessageCommit,
) -> Result<RunCompletionReceipt, SchedulerUseCaseError> {
    if final_message.content.is_empty() || final_message.content.len() > 64 * 1024 {
        return Err(SchedulerUseCaseError::InvalidCompletionSummary);
    }
    let summary = final_message.content.clone();
    store
        .complete_run(CompleteRunCommit {
            fence,
            status: RunCompletionStatus::Succeeded,
            summary,
            final_message: Some(final_message),
            run_event_id: ids.generate_event_id(),
            task_event_id: ids.generate_event_id(),
            turn_event_id: ids.generate_event_id(),
            session_event_id: ids.generate_event_id(),
            outbox_id: ids.generate_outbox_id(),
            correlation_id: ids.generate_correlation_id(),
            completed_at: clock.now(),
        })
        .map_err(SchedulerUseCaseError::from)
}

/// Returns the run ID from a lease claim when present.
#[must_use]
pub fn claimed_run_id(outcome: &LeaseClaimOutcome) -> Option<RunId> {
    match outcome {
        LeaseClaimOutcome::Claimed(receipt) => Some(receipt.lease.fence().run_id()),
        LeaseClaimOutcome::NoRunnableWork => None,
    }
}
