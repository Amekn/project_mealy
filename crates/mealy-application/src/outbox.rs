use crate::Clock;
use mealy_domain::{OutboxId, WorkerId};
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// One outbound record exclusively claimed for a delivery attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxDelivery {
    /// Stable delivery identifier used by downstream deduplication.
    pub outbox_id: OutboxId,
    /// Destination/handler topic.
    pub topic: String,
    /// Versioned JSON delivery body.
    pub payload_json: String,
    /// One-based durable attempt number.
    pub attempt: u32,
}

/// Result of a bounded outbox claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboxClaimOutcome {
    /// One due record was atomically moved to `delivering`.
    Claimed(OutboxDelivery),
    /// No due record is currently eligible.
    NoPendingDelivery,
}

/// Values supplied to an atomic outbox claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboxClaimCommit {
    /// Daemon delivery worker taking ownership.
    pub owner_id: WorkerId,
    /// Claim time.
    pub claimed_at: SystemTime,
    /// Claims older than this instant can be recovered from a failed dispatcher.
    pub stale_before: SystemTime,
    /// Attempts at or above this bound become terminally failed.
    pub maximum_attempts: u32,
}

/// Values supplied after a successful downstream delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteOutboxCommit {
    /// Delivered record.
    pub outbox_id: OutboxId,
    /// Exact worker that claimed the current attempt.
    pub owner_id: WorkerId,
    /// Completion time.
    pub delivered_at: SystemTime,
}

/// Values supplied after a classified downstream failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryOutboxCommit {
    /// Failed record.
    pub outbox_id: OutboxId,
    /// Exact worker that claimed the current attempt.
    pub owner_id: WorkerId,
    /// Failure observation time.
    pub failed_at: SystemTime,
    /// Next eligible time, or `None` for a terminal failure.
    pub retry_at: Option<SystemTime>,
    /// Bounded operator-safe failure classification.
    pub error: String,
}

/// Outbox persistence failures.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OutboxStoreError {
    /// Record is no longer delivering under the supplied worker claim.
    #[error("outbox delivery claim is stale")]
    StaleClaim,
    /// Persistence dependency failed.
    #[error("outbox store is unavailable: {0}")]
    Unavailable(String),
    /// Canonical outbox data violates an invariant.
    #[error("outbox invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port for durable outbox claiming, retry, and completion.
pub trait OutboxDeliveryStore {
    /// Claims the oldest due record and recovers timed-out dispatcher claims.
    ///
    /// # Errors
    ///
    /// Returns [`OutboxStoreError`] for persistence or invariant failures.
    fn claim_next_outbox(
        &mut self,
        commit: OutboxClaimCommit,
    ) -> Result<OutboxClaimOutcome, OutboxStoreError>;

    /// Marks the exact current claim delivered.
    ///
    /// # Errors
    ///
    /// Returns [`OutboxStoreError::StaleClaim`] if ownership changed.
    fn complete_outbox(&mut self, commit: CompleteOutboxCommit) -> Result<(), OutboxStoreError>;

    /// Requeues or terminally fails the exact current claim.
    ///
    /// # Errors
    ///
    /// Returns [`OutboxStoreError::StaleClaim`] if ownership changed.
    fn retry_outbox(&mut self, commit: RetryOutboxCommit) -> Result<(), OutboxStoreError>;
}

/// Outbox policy or persistence failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OutboxUseCaseError {
    /// Claim timeout must be nonzero and at most one hour.
    #[error("outbox claim timeout must be between one millisecond and one hour")]
    InvalidClaimTimeout,
    /// Maximum attempts must be within 1 through 100.
    #[error("outbox maximum attempts must be between 1 and 100")]
    InvalidMaximumAttempts,
    /// Retry delay cannot be zero or exceed one day.
    #[error("outbox retry delay must be between one millisecond and one day")]
    InvalidRetryDelay,
    /// Error classification must be nonempty and no larger than 4 KiB.
    #[error("outbox error classification must contain 1 through 4096 bytes")]
    InvalidError,
    /// Clock arithmetic overflowed.
    #[error("outbox scheduling time cannot be represented")]
    TimeOverflow,
    /// Durable store rejected the operation.
    #[error(transparent)]
    Store(#[from] OutboxStoreError),
}

/// Claims the oldest due delivery under bounded retry policy.
///
/// # Errors
///
/// Returns [`OutboxUseCaseError`] for invalid policy, clock overflow, or store failure.
pub fn claim_next_outbox(
    store: &mut impl OutboxDeliveryStore,
    clock: &impl Clock,
    owner_id: WorkerId,
    claim_timeout: Duration,
    maximum_attempts: u32,
) -> Result<OutboxClaimOutcome, OutboxUseCaseError> {
    if claim_timeout.is_zero() || claim_timeout > Duration::from_hours(1) {
        return Err(OutboxUseCaseError::InvalidClaimTimeout);
    }
    if !(1..=100).contains(&maximum_attempts) {
        return Err(OutboxUseCaseError::InvalidMaximumAttempts);
    }
    let claimed_at = clock.now();
    let stale_before = claimed_at
        .checked_sub(claim_timeout)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    store
        .claim_next_outbox(OutboxClaimCommit {
            owner_id,
            claimed_at,
            stale_before,
            maximum_attempts,
        })
        .map_err(OutboxUseCaseError::from)
}

/// Commits successful delivery under the exact claim owner.
///
/// # Errors
///
/// Returns [`OutboxUseCaseError`] when the claim is stale or persistence fails.
pub fn complete_outbox(
    store: &mut impl OutboxDeliveryStore,
    clock: &impl Clock,
    owner_id: WorkerId,
    outbox_id: OutboxId,
) -> Result<(), OutboxUseCaseError> {
    store
        .complete_outbox(CompleteOutboxCommit {
            outbox_id,
            owner_id,
            delivered_at: clock.now(),
        })
        .map_err(OutboxUseCaseError::from)
}

/// Persists a bounded retry or terminal failure under the exact claim owner.
///
/// # Errors
///
/// Returns [`OutboxUseCaseError`] for invalid bounds, overflow, stale ownership, or persistence.
pub fn retry_outbox(
    store: &mut impl OutboxDeliveryStore,
    clock: &impl Clock,
    owner_id: WorkerId,
    delivery: &OutboxDelivery,
    maximum_attempts: u32,
    retry_delay: Duration,
    error: String,
) -> Result<(), OutboxUseCaseError> {
    if !(1..=100).contains(&maximum_attempts) {
        return Err(OutboxUseCaseError::InvalidMaximumAttempts);
    }
    if retry_delay.is_zero() || retry_delay > Duration::from_hours(24) {
        return Err(OutboxUseCaseError::InvalidRetryDelay);
    }
    if error.is_empty() || error.len() > 4096 {
        return Err(OutboxUseCaseError::InvalidError);
    }
    let failed_at = clock.now();
    let retry_at = if delivery.attempt >= maximum_attempts {
        None
    } else {
        Some(
            failed_at
                .checked_add(retry_delay)
                .ok_or(OutboxUseCaseError::TimeOverflow)?,
        )
    };
    store
        .retry_outbox(RetryOutboxCommit {
            outbox_id: delivery.outbox_id,
            owner_id,
            failed_at,
            retry_at,
            error,
        })
        .map_err(OutboxUseCaseError::from)
}

/// Computes bounded exponential retry delay with stable per-delivery jitter.
///
/// Stable jitter prevents synchronized retries while keeping crash/replay behavior inspectable.
/// The result is always between `base` and `maximum`, inclusive.
///
/// # Errors
///
/// Returns [`OutboxUseCaseError::InvalidRetryDelay`] for zero, inverted, sub-millisecond, or
/// greater-than-one-day bounds.
pub fn exponential_retry_delay(
    delivery: &OutboxDelivery,
    base: Duration,
    maximum: Duration,
) -> Result<Duration, OutboxUseCaseError> {
    if base.is_zero()
        || base < Duration::from_millis(1)
        || maximum < base
        || maximum > Duration::from_hours(24)
    {
        return Err(OutboxUseCaseError::InvalidRetryDelay);
    }
    let base_ms = base.as_millis();
    let maximum_ms = maximum.as_millis();
    let exponent = delivery.attempt.saturating_sub(1).min(31);
    let multiplier = 1_u128 << exponent;
    let exponential_ms = base_ms.saturating_mul(multiplier).min(maximum_ms);
    let jitter_window_ms = exponential_ms / 4;
    let seed = delivery.outbox_id.as_uuid().as_u128()
        ^ u128::from(delivery.attempt).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let jitter_ms = if jitter_window_ms == 0 {
        0
    } else {
        seed % (jitter_window_ms + 1)
    };
    let delay_ms = exponential_ms.saturating_add(jitter_ms).min(maximum_ms);
    let delay_ms = u64::try_from(delay_ms).map_err(|_| OutboxUseCaseError::InvalidRetryDelay)?;
    Ok(Duration::from_millis(delay_ms))
}

#[cfg(test)]
mod tests {
    use super::{OutboxDelivery, exponential_retry_delay};
    use mealy_domain::OutboxId;
    use std::{str::FromStr, time::Duration};

    #[test]
    fn exponential_retry_is_stable_jittered_monotonic_and_bounded() {
        let outbox_id =
            OutboxId::from_str("01890f3c-7b7a-7000-8000-000000000001").expect("fixture outbox ID");
        let delays = (1..=16)
            .map(|attempt| {
                let delivery = OutboxDelivery {
                    outbox_id,
                    topic: "fixture".to_owned(),
                    payload_json: "{}".to_owned(),
                    attempt,
                };
                let first = exponential_retry_delay(
                    &delivery,
                    Duration::from_millis(100),
                    Duration::from_secs(30),
                )
                .expect("valid delay");
                assert_eq!(
                    first,
                    exponential_retry_delay(
                        &delivery,
                        Duration::from_millis(100),
                        Duration::from_secs(30),
                    )
                    .expect("repeat delay")
                );
                first
            })
            .collect::<Vec<_>>();
        assert!(delays.windows(2).all(|pair| pair[0] <= pair[1]));
        assert!(
            delays
                .iter()
                .all(|delay| *delay >= Duration::from_millis(100))
        );
        assert!(delays.iter().all(|delay| *delay <= Duration::from_secs(30)));
        assert_ne!(delays[0], Duration::from_millis(100));
        assert_eq!(*delays.last().expect("last delay"), Duration::from_secs(30));
    }
}
