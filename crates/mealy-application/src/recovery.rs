use mealy_domain::{EffectError, EffectState, RecoveryAction};

/// A user-inspectable recovery plan for an interrupted effect dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPlan {
    /// Mechanically safe next action.
    pub action: RecoveryAction,
    /// Stable explanation suitable for a timeline event.
    pub reason: &'static str,
}

/// Classifies an interrupted effect without consulting a model.
///
/// # Errors
///
/// Returns [`EffectError`] unless the effect is currently dispatching.
pub fn plan_interrupted_effect(effect: &EffectState) -> Result<RecoveryPlan, EffectError> {
    let action = effect.interrupted_dispatch_recovery()?;
    let reason = match action {
        RecoveryAction::Retry => "the effect contract permits a bounded retry",
        RecoveryAction::RetryWithSameKey => {
            "the downstream idempotency key must be reused for a bounded retry"
        }
        RecoveryAction::Reconcile => {
            "the external outcome is ambiguous and must be reconciled before another dispatch"
        }
    };
    Ok(RecoveryPlan { action, reason })
}

#[cfg(test)]
mod tests {
    use super::plan_interrupted_effect;
    use mealy_domain::{EffectId, EffectState, IdempotencyClass, RecoveryAction};

    #[test]
    fn planner_preserves_non_idempotent_safety() {
        let mut effect = EffectState::new(EffectId::new(), IdempotencyClass::NonIdempotent, None);
        effect.authorize().expect("authorize effect");
        effect.begin_dispatch().expect("begin dispatch");
        let plan = plan_interrupted_effect(&effect).expect("classify recovery");
        assert_eq!(plan.action, RecoveryAction::Reconcile);
        assert!(plan.reason.contains("ambiguous"));
    }
}
