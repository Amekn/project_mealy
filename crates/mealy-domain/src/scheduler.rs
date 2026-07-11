use crate::{LeaseId, RunId, WorkerId};
use serde::{Deserialize, Serialize};
use std::{num::NonZeroU64, time::SystemTime};
use thiserror::Error;

/// Monotonic token that invalidates work performed under an older lease.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct FencingToken(NonZeroU64);

impl FencingToken {
    /// Creates a nonzero fencing token.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the numeric token persisted by the scheduler.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Exact lease identity required by every worker-originated state commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseFence {
    lease_id: LeaseId,
    run_id: RunId,
    owner_id: WorkerId,
    fencing_token: FencingToken,
}

impl LeaseFence {
    /// Creates a lease fence from canonical scheduler identity.
    #[must_use]
    pub const fn new(
        lease_id: LeaseId,
        run_id: RunId,
        owner_id: WorkerId,
        fencing_token: FencingToken,
    ) -> Self {
        Self {
            lease_id,
            run_id,
            owner_id,
            fencing_token,
        }
    }

    /// Returns the lease identifier.
    #[must_use]
    pub const fn lease_id(self) -> LeaseId {
        self.lease_id
    }

    /// Returns the leased run.
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    /// Returns the worker that owns the lease.
    #[must_use]
    pub const fn owner_id(self) -> WorkerId {
        self.owner_id
    }

    /// Returns the current fencing token.
    #[must_use]
    pub const fn fencing_token(self) -> FencingToken {
        self.fencing_token
    }
}

/// Durable lifecycle of a scheduler lease.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    /// The matching worker may commit before expiry.
    Active,
    /// The owner deliberately returned the lease.
    Released,
    /// Recovery or a claimant observed the lease past expiry.
    Expired,
}

/// Canonical domain representation of a work lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkLease {
    fence: LeaseFence,
    acquired_at: SystemTime,
    heartbeat_at: SystemTime,
    expires_at: SystemTime,
    status: LeaseStatus,
}

impl WorkLease {
    /// Creates an active lease with its first heartbeat at acquisition time.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError`] unless expiry is strictly later than acquisition.
    pub fn new(
        fence: LeaseFence,
        acquired_at: SystemTime,
        expires_at: SystemTime,
    ) -> Result<Self, LeaseError> {
        if expires_at <= acquired_at {
            return Err(LeaseError::InvalidExpiry);
        }
        Ok(Self {
            fence,
            acquired_at,
            heartbeat_at: acquired_at,
            expires_at,
            status: LeaseStatus::Active,
        })
    }

    /// Rehydrates a previously validated durable lease snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError`] when stored times contradict the lease lifecycle.
    pub fn rehydrate(
        fence: LeaseFence,
        acquired_at: SystemTime,
        heartbeat_at: SystemTime,
        expires_at: SystemTime,
        status: LeaseStatus,
    ) -> Result<Self, LeaseError> {
        if heartbeat_at < acquired_at || expires_at <= heartbeat_at {
            return Err(LeaseError::InvalidExpiry);
        }
        Ok(Self {
            fence,
            acquired_at,
            heartbeat_at,
            expires_at,
            status,
        })
    }

    /// Returns the exact worker fence.
    #[must_use]
    pub const fn fence(&self) -> LeaseFence {
        self.fence
    }

    /// Returns the acquisition instant.
    #[must_use]
    pub const fn acquired_at(&self) -> SystemTime {
        self.acquired_at
    }

    /// Returns the most recent accepted heartbeat instant.
    #[must_use]
    pub const fn heartbeat_at(&self) -> SystemTime {
        self.heartbeat_at
    }

    /// Returns the exclusive expiry boundary.
    #[must_use]
    pub const fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    /// Returns the lifecycle state.
    #[must_use]
    pub const fn status(&self) -> LeaseStatus {
        self.status
    }

    /// Extends an active, unexpired lease without moving its deadline backwards.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError`] for an inactive/expired lease, clock regression, or non-extension.
    pub fn heartbeat(&mut self, now: SystemTime, new_expiry: SystemTime) -> Result<(), LeaseError> {
        self.require_active()?;
        if now < self.heartbeat_at {
            return Err(LeaseError::ClockRegression);
        }
        if now >= self.expires_at {
            return Err(LeaseError::AlreadyExpired);
        }
        if new_expiry <= self.expires_at {
            return Err(LeaseError::ExpiryNotExtended);
        }
        self.heartbeat_at = now;
        self.expires_at = new_expiry;
        Ok(())
    }

    /// Releases an active lease before its expiry.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError`] when the lease is inactive, expired, or time regresses.
    pub fn release(&mut self, now: SystemTime) -> Result<(), LeaseError> {
        self.require_active()?;
        if now < self.heartbeat_at {
            return Err(LeaseError::ClockRegression);
        }
        if now >= self.expires_at {
            return Err(LeaseError::AlreadyExpired);
        }
        self.status = LeaseStatus::Released;
        Ok(())
    }

    /// Marks an active lease expired at or after its deadline.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError`] when the lease is inactive or the deadline has not arrived.
    pub fn expire(&mut self, now: SystemTime) -> Result<(), LeaseError> {
        self.require_active()?;
        if now < self.expires_at {
            return Err(LeaseError::NotExpired);
        }
        self.status = LeaseStatus::Expired;
        Ok(())
    }

    fn require_active(&self) -> Result<(), LeaseError> {
        if self.status == LeaseStatus::Active {
            Ok(())
        } else {
            Err(LeaseError::NotActive {
                status: self.status,
            })
        }
    }
}

/// Canonical lifecycle of one promoted conversational turn.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnStatus {
    /// The turn owns the session mutation slot.
    Active,
    /// Work and required delivery completed.
    Completed,
    /// Work ended in a terminal failure.
    Failed,
    /// Work ended by cancellation.
    Cancelled,
}

/// Rejected lease transition.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeaseError {
    /// Expiry must be strictly later than acquisition.
    #[error("lease expiry must be later than acquisition")]
    InvalidExpiry,
    /// Only an active lease can transition.
    #[error("lease is not active; current state is {status:?}")]
    NotActive {
        /// Current lifecycle state.
        status: LeaseStatus,
    },
    /// A heartbeat or release was attempted at or after expiry.
    #[error("lease has already reached its expiry boundary")]
    AlreadyExpired,
    /// Expiry cannot occur before its durable deadline.
    #[error("lease expiry boundary has not arrived")]
    NotExpired,
    /// Heartbeats must move the deadline forward.
    #[error("heartbeat must extend the current lease deadline")]
    ExpiryNotExtended,
    /// Scheduler time must not move before the last durable heartbeat.
    #[error("scheduler clock regressed before the last heartbeat")]
    ClockRegression,
}

#[cfg(test)]
mod tests {
    use super::{FencingToken, LeaseError, LeaseFence, LeaseStatus, WorkLease};
    use crate::{LeaseId, RunId, WorkerId};
    use std::time::{Duration, SystemTime};

    fn lease() -> WorkLease {
        let fence = LeaseFence::new(
            LeaseId::new(),
            RunId::new(),
            WorkerId::new(),
            FencingToken::new(1).expect("nonzero fence"),
        );
        WorkLease::new(
            fence,
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH + Duration::from_secs(10),
        )
        .expect("valid lease")
    }

    #[test]
    fn heartbeat_only_extends_an_unexpired_lease() {
        let mut lease = lease();
        lease
            .heartbeat(
                SystemTime::UNIX_EPOCH + Duration::from_secs(5),
                SystemTime::UNIX_EPOCH + Duration::from_secs(20),
            )
            .expect("extend lease");
        assert_eq!(
            lease.expires_at(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(20)
        );
        assert_eq!(
            lease.heartbeat(
                SystemTime::UNIX_EPOCH + Duration::from_secs(6),
                SystemTime::UNIX_EPOCH + Duration::from_secs(19),
            ),
            Err(LeaseError::ExpiryNotExtended)
        );
    }

    #[test]
    fn expiry_is_explicit_and_terminal() {
        let mut lease = lease();
        assert_eq!(
            lease.expire(SystemTime::UNIX_EPOCH + Duration::from_secs(9)),
            Err(LeaseError::NotExpired)
        );
        lease
            .expire(SystemTime::UNIX_EPOCH + Duration::from_secs(10))
            .expect("expire at boundary");
        assert_eq!(lease.status(), LeaseStatus::Expired);
        assert!(matches!(
            lease.release(SystemTime::UNIX_EPOCH + Duration::from_secs(11)),
            Err(LeaseError::NotActive { .. })
        ));
    }
}
