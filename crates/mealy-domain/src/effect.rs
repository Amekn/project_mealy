use crate::EffectId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Declared retry semantics for a tool or service effect.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyClass {
    /// The operation cannot change external state.
    Pure,
    /// Repeating the same normalized operation is safe by contract.
    Idempotent,
    /// Repetition is safe only when the same downstream key is reused.
    Keyed,
    /// Repetition may duplicate or corrupt external state.
    NonIdempotent,
}

/// Canonical effect lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectStatus {
    /// An exact effect intent exists but has not been authorized.
    Proposed,
    /// Policy requires an authenticated human decision.
    AwaitingApproval,
    /// Policy and any approval permit dispatch.
    Authorized,
    /// A worker may have crossed the external side-effect boundary.
    Dispatching,
    /// The external outcome is confirmed successful.
    Succeeded,
    /// The external outcome is confirmed unsuccessful.
    Failed,
    /// Dispatch occurred but the external outcome cannot yet be proven.
    OutcomeUnknown,
    /// A compensating action was confirmed.
    Compensated,
    /// Policy or an authorized principal denied the effect.
    Denied,
}

impl EffectStatus {
    /// Returns whether no automatic execution transition remains.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Compensated | Self::Denied
        )
    }
}

/// Recovery decision after an interrupted dispatch boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    /// Start a new bounded attempt with the same normalized input.
    Retry,
    /// Retry only while reusing the existing downstream idempotency key.
    RetryWithSameKey,
    /// Stop and determine the external outcome before another dispatch.
    Reconcile,
}

/// Canonical state of an effect aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectState {
    id: EffectId,
    status: EffectStatus,
    revision: u64,
    idempotency: IdempotencyClass,
    idempotency_key: Option<String>,
}

impl EffectState {
    /// Creates a proposed effect with declared retry semantics.
    #[must_use]
    pub fn new(
        id: EffectId,
        idempotency: IdempotencyClass,
        idempotency_key: Option<String>,
    ) -> Self {
        Self {
            id,
            status: EffectStatus::Proposed,
            revision: 0,
            idempotency,
            idempotency_key,
        }
    }

    /// Returns the effect ID.
    #[must_use]
    pub const fn id(&self) -> EffectId {
        self.id
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn status(&self) -> EffectStatus {
        self.status
    }

    /// Returns the optimistic-concurrency revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Parks the effect for a bound approval.
    ///
    /// # Errors
    ///
    /// Returns [`EffectError`] when the transition is invalid or the revision overflows.
    pub fn request_approval(&mut self) -> Result<EffectTransition, EffectError> {
        self.transition(EffectStatus::AwaitingApproval)
    }

    /// Authorizes a proposed or approved effect.
    ///
    /// # Errors
    ///
    /// Returns [`EffectError`] when the transition is invalid or the revision overflows.
    pub fn authorize(&mut self) -> Result<EffectTransition, EffectError> {
        self.transition(EffectStatus::Authorized)
    }

    /// Denies a proposed or waiting effect.
    ///
    /// # Errors
    ///
    /// Returns [`EffectError`] when the transition is invalid or the revision overflows.
    pub fn deny(&mut self) -> Result<EffectTransition, EffectError> {
        self.transition(EffectStatus::Denied)
    }

    /// Records that dispatch may cross the external boundary.
    ///
    /// # Errors
    ///
    /// Returns [`EffectError`] if a keyed effect has no key, the transition is invalid, or the
    /// revision overflows.
    pub fn begin_dispatch(&mut self) -> Result<EffectTransition, EffectError> {
        if self.idempotency == IdempotencyClass::Keyed && self.idempotency_key.is_none() {
            return Err(EffectError::MissingIdempotencyKey { effect_id: self.id });
        }
        self.transition(EffectStatus::Dispatching)
    }

    /// Records a confirmed successful external outcome.
    ///
    /// # Errors
    ///
    /// Returns [`EffectError`] when the transition is invalid or the revision overflows.
    pub fn succeed(&mut self) -> Result<EffectTransition, EffectError> {
        self.transition(EffectStatus::Succeeded)
    }

    /// Records a confirmed unsuccessful external outcome.
    ///
    /// # Errors
    ///
    /// Returns [`EffectError`] when the transition is invalid or the revision overflows.
    pub fn fail(&mut self) -> Result<EffectTransition, EffectError> {
        self.transition(EffectStatus::Failed)
    }

    /// Records that dispatch occurred but the result is ambiguous.
    ///
    /// # Errors
    ///
    /// Returns [`EffectError`] when the transition is invalid or the revision overflows.
    pub fn mark_unknown(&mut self) -> Result<EffectTransition, EffectError> {
        self.transition(EffectStatus::OutcomeUnknown)
    }

    /// Resolves an unknown outcome as successful.
    ///
    /// # Errors
    ///
    /// Returns [`EffectError`] when the transition is invalid or the revision overflows.
    pub fn reconcile_succeeded(&mut self) -> Result<EffectTransition, EffectError> {
        self.transition(EffectStatus::Succeeded)
    }

    /// Resolves an unknown outcome as failed.
    ///
    /// # Errors
    ///
    /// Returns [`EffectError`] when the transition is invalid or the revision overflows.
    pub fn reconcile_failed(&mut self) -> Result<EffectTransition, EffectError> {
        self.transition(EffectStatus::Failed)
    }

    /// Records a confirmed compensating action.
    ///
    /// # Errors
    ///
    /// Returns [`EffectError`] when the transition is invalid or the revision overflows.
    pub fn compensate(&mut self) -> Result<EffectTransition, EffectError> {
        self.transition(EffectStatus::Compensated)
    }

    /// Classifies recovery after a worker was interrupted during dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`EffectError`] unless the effect is currently dispatching.
    pub fn interrupted_dispatch_recovery(&self) -> Result<RecoveryAction, EffectError> {
        if self.status != EffectStatus::Dispatching {
            return Err(EffectError::RecoveryOutsideDispatch {
                effect_id: self.id,
                status: self.status,
            });
        }

        Ok(match self.idempotency {
            IdempotencyClass::Pure | IdempotencyClass::Idempotent => RecoveryAction::Retry,
            IdempotencyClass::Keyed if self.idempotency_key.is_some() => {
                RecoveryAction::RetryWithSameKey
            }
            IdempotencyClass::Keyed | IdempotencyClass::NonIdempotent => RecoveryAction::Reconcile,
        })
    }

    fn transition(&mut self, target: EffectStatus) -> Result<EffectTransition, EffectError> {
        if !allowed(self.status, target) {
            return Err(EffectError::InvalidTransition {
                effect_id: self.id,
                from: self.status,
                to: target,
            });
        }
        let transition = EffectTransition {
            effect_id: self.id,
            from: self.status,
            to: target,
            previous_revision: self.revision,
            new_revision: self
                .revision
                .checked_add(1)
                .ok_or(EffectError::RevisionOverflow { effect_id: self.id })?,
        };
        self.status = target;
        self.revision = transition.new_revision;
        Ok(transition)
    }
}

const fn allowed(from: EffectStatus, to: EffectStatus) -> bool {
    matches!(
        (from, to),
        (
            EffectStatus::Proposed,
            EffectStatus::AwaitingApproval | EffectStatus::Authorized | EffectStatus::Denied
        ) | (
            EffectStatus::AwaitingApproval,
            EffectStatus::Authorized | EffectStatus::Denied
        ) | (EffectStatus::Authorized, EffectStatus::Dispatching)
            | (
                EffectStatus::Dispatching,
                EffectStatus::Succeeded | EffectStatus::Failed | EffectStatus::OutcomeUnknown
            )
            | (
                EffectStatus::OutcomeUnknown,
                EffectStatus::Succeeded | EffectStatus::Failed | EffectStatus::Compensated
            )
    )
}

/// Immutable fact describing one accepted effect transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectTransition {
    /// Effect aggregate that changed.
    effect_id: EffectId,
    /// State before the transition.
    from: EffectStatus,
    /// State after the transition.
    to: EffectStatus,
    /// Revision checked by the caller.
    previous_revision: u64,
    /// Revision to persist atomically with the event.
    new_revision: u64,
}

impl EffectTransition {
    /// Returns the effect aggregate that changed.
    #[must_use]
    pub const fn effect_id(self) -> EffectId {
        self.effect_id
    }

    /// Returns the state before the transition.
    #[must_use]
    pub const fn from(self) -> EffectStatus {
        self.from
    }

    /// Returns the state after the transition.
    #[must_use]
    pub const fn to(self) -> EffectStatus {
        self.to
    }

    /// Returns the revision that must still be current when the transition is committed.
    #[must_use]
    pub const fn previous_revision(self) -> u64 {
        self.previous_revision
    }

    /// Returns the new revision produced by the accepted transition.
    #[must_use]
    pub const fn new_revision(self) -> u64 {
        self.new_revision
    }
}

/// A rejected effect transition or recovery request.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EffectError {
    /// The requested lifecycle edge is not permitted.
    #[error("effect {effect_id} cannot transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// Effect being changed.
        effect_id: EffectId,
        /// Current state.
        from: EffectStatus,
        /// Requested state.
        to: EffectStatus,
    },
    /// Keyed idempotency was declared without a concrete key.
    #[error("effect {effect_id} declares keyed idempotency without a key")]
    MissingIdempotencyKey {
        /// Effect missing a downstream key.
        effect_id: EffectId,
    },
    /// Recovery classification was requested outside dispatch.
    #[error("effect {effect_id} recovery requires dispatching state, got {status:?}")]
    RecoveryOutsideDispatch {
        /// Effect being classified.
        effect_id: EffectId,
        /// Current state.
        status: EffectStatus,
    },
    /// The optimistic-concurrency revision exhausted its integer range.
    #[error("effect {effect_id} revision overflow")]
    RevisionOverflow {
        /// Effect whose revision overflowed.
        effect_id: EffectId,
    },
}

#[cfg(test)]
mod tests {
    use super::{EffectError, EffectState, IdempotencyClass, RecoveryAction};
    use crate::EffectId;

    fn dispatching(class: IdempotencyClass, key: Option<&str>) -> EffectState {
        let mut effect = EffectState::new(EffectId::new(), class, key.map(str::to_owned));
        effect.authorize().expect("authorize effect");
        effect.begin_dispatch().expect("begin dispatch");
        effect
    }

    #[test]
    fn non_idempotent_interruption_requires_reconciliation() {
        let effect = dispatching(IdempotencyClass::NonIdempotent, None);
        assert_eq!(
            effect
                .interrupted_dispatch_recovery()
                .expect("classify dispatch"),
            RecoveryAction::Reconcile
        );
    }

    #[test]
    fn keyed_retry_reuses_the_same_key() {
        let effect = dispatching(IdempotencyClass::Keyed, Some("effect-key"));
        assert_eq!(
            effect
                .interrupted_dispatch_recovery()
                .expect("classify dispatch"),
            RecoveryAction::RetryWithSameKey
        );
    }

    #[test]
    fn keyed_effect_cannot_dispatch_without_key() {
        let mut effect = EffectState::new(EffectId::new(), IdempotencyClass::Keyed, None);
        effect.authorize().expect("authorize effect");
        assert!(matches!(
            effect.begin_dispatch(),
            Err(EffectError::MissingIdempotencyKey { .. })
        ));
    }

    #[test]
    fn unknown_effect_can_only_be_resolved_explicitly() {
        let mut effect = dispatching(IdempotencyClass::NonIdempotent, None);
        effect.mark_unknown().expect("mark outcome unknown");
        effect
            .reconcile_succeeded()
            .expect("reconcile confirmed success");
        assert!(effect.status().is_terminal());
    }
}
