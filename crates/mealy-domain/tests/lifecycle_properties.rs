//! Generative checks for Mealy's task and effect lifecycle invariants.

use mealy_domain::{
    EffectError, EffectId, EffectState, EffectStatus, EffectTransition, IdempotencyClass,
    RecoveryAction, TaskError, TaskId, TaskState, TaskTransition, ValidationId,
};
use proptest::prelude::*;

#[derive(Clone, Copy, Debug)]
enum TaskOperation {
    Start,
    Wait,
    Resume,
    Pause,
    RequestCancel,
    FinishCancel,
    Fail,
    SucceedWithoutValidation,
    SucceedWithValidation,
}

#[derive(Clone, Copy, Debug)]
enum EffectOperation {
    RequestApproval,
    Authorize,
    Deny,
    BeginDispatch,
    Succeed,
    Fail,
    MarkUnknown,
    ReconcileSucceeded,
    ReconcileFailed,
    Compensate,
}

fn task_operation() -> impl Strategy<Value = TaskOperation> {
    prop_oneof![
        Just(TaskOperation::Start),
        Just(TaskOperation::Wait),
        Just(TaskOperation::Resume),
        Just(TaskOperation::Pause),
        Just(TaskOperation::RequestCancel),
        Just(TaskOperation::FinishCancel),
        Just(TaskOperation::Fail),
        Just(TaskOperation::SucceedWithoutValidation),
        Just(TaskOperation::SucceedWithValidation),
    ]
}

fn effect_operation() -> impl Strategy<Value = EffectOperation> {
    prop_oneof![
        Just(EffectOperation::RequestApproval),
        Just(EffectOperation::Authorize),
        Just(EffectOperation::Deny),
        Just(EffectOperation::BeginDispatch),
        Just(EffectOperation::Succeed),
        Just(EffectOperation::Fail),
        Just(EffectOperation::MarkUnknown),
        Just(EffectOperation::ReconcileSucceeded),
        Just(EffectOperation::ReconcileFailed),
        Just(EffectOperation::Compensate),
    ]
}

fn idempotency_class() -> impl Strategy<Value = IdempotencyClass> {
    prop_oneof![
        Just(IdempotencyClass::Pure),
        Just(IdempotencyClass::Idempotent),
        Just(IdempotencyClass::Keyed),
        Just(IdempotencyClass::NonIdempotent),
    ]
}

fn apply_task_operation(
    task: &mut TaskState,
    operation: TaskOperation,
) -> Result<TaskTransition, TaskError> {
    match operation {
        TaskOperation::Start => task.start(),
        TaskOperation::Wait => task.wait(),
        TaskOperation::Resume => task.resume(),
        TaskOperation::Pause => task.pause(),
        TaskOperation::RequestCancel => task.request_cancel(),
        TaskOperation::FinishCancel => task.finish_cancel(),
        TaskOperation::Fail => task.fail(),
        TaskOperation::SucceedWithoutValidation => task.succeed(None),
        TaskOperation::SucceedWithValidation => task.succeed(Some(ValidationId::new())),
    }
}

fn apply_effect_operation(
    effect: &mut EffectState,
    operation: EffectOperation,
) -> Result<EffectTransition, EffectError> {
    match operation {
        EffectOperation::RequestApproval => effect.request_approval(),
        EffectOperation::Authorize => effect.authorize(),
        EffectOperation::Deny => effect.deny(),
        EffectOperation::BeginDispatch => effect.begin_dispatch(),
        EffectOperation::Succeed => effect.succeed(),
        EffectOperation::Fail => effect.fail(),
        EffectOperation::MarkUnknown => effect.mark_unknown(),
        EffectOperation::ReconcileSucceeded => effect.reconcile_succeeded(),
        EffectOperation::ReconcileFailed => effect.reconcile_failed(),
        EffectOperation::Compensate => effect.compensate(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_task_sequences_never_leave_terminal_states(
        validation_required in any::<bool>(),
        operations in prop::collection::vec(task_operation(), 0..192),
    ) {
        let mut task = TaskState::new(TaskId::new(), validation_required);
        let mut reached_terminal = None;

        for operation in operations {
            let _result = apply_task_operation(&mut task, operation);

            if let Some(terminal_status) = reached_terminal {
                prop_assert_eq!(task.status(), terminal_status);
            } else if task.status().is_terminal() {
                reached_terminal = Some(task.status());
            }
        }
    }

    #[test]
    fn task_transitions_increment_once_and_rejections_do_not_mutate(
        validation_required in any::<bool>(),
        operations in prop::collection::vec(task_operation(), 0..192),
    ) {
        let mut task = TaskState::new(TaskId::new(), validation_required);

        for operation in operations {
            let before = task.clone();
            let result = apply_task_operation(&mut task, operation);

            if let Ok(transition) = result {
                prop_assert_eq!(transition.task_id(), task.id());
                prop_assert_eq!(transition.from(), before.status());
                prop_assert_eq!(transition.to(), task.status());
                prop_assert_eq!(transition.previous_revision(), before.revision());
                prop_assert_eq!(transition.new_revision(), before.revision() + 1);
                prop_assert_eq!(task.revision(), before.revision() + 1);
            } else {
                prop_assert_eq!(&task, &before);
            }
        }
    }

    #[test]
    fn effect_transitions_increment_once_and_rejections_do_not_mutate(
        idempotency in idempotency_class(),
        key_value in prop::option::of(any::<u64>()),
        operations in prop::collection::vec(effect_operation(), 0..192),
    ) {
        let key = key_value.map(|value| format!("effect-{value}"));
        let mut effect = EffectState::new(EffectId::new(), idempotency, key);

        for operation in operations {
            let before = effect.clone();
            let result = apply_effect_operation(&mut effect, operation);

            if let Ok(transition) = result {
                prop_assert_eq!(transition.effect_id(), effect.id());
                prop_assert_eq!(transition.from(), before.status());
                prop_assert_eq!(transition.to(), effect.status());
                prop_assert_eq!(transition.previous_revision(), before.revision());
                prop_assert_eq!(transition.new_revision(), before.revision() + 1);
                prop_assert_eq!(effect.revision(), before.revision() + 1);
            } else {
                prop_assert_eq!(&effect, &before);
            }
        }
    }

    #[test]
    fn non_idempotent_dispatch_recovery_never_retries(
        approval_path in any::<bool>(),
        irrelevant_key in prop::option::of(any::<u64>()),
    ) {
        let key = irrelevant_key.map(|value| format!("effect-{value}"));
        let mut effect = EffectState::new(
            EffectId::new(),
            IdempotencyClass::NonIdempotent,
            key,
        );
        if approval_path {
            effect.request_approval().expect("approval request is valid");
        }
        effect.authorize().expect("authorization is valid");
        effect.begin_dispatch().expect("non-idempotent dispatch is valid");

        let recovery = effect
            .interrupted_dispatch_recovery()
            .expect("dispatch recovery is classifiable");
        prop_assert_eq!(recovery, RecoveryAction::Reconcile);
        prop_assert!(!matches!(
            recovery,
            RecoveryAction::Retry | RecoveryAction::RetryWithSameKey
        ));
    }

    #[test]
    fn keyed_effects_without_keys_never_cross_dispatch(
        approval_path in any::<bool>(),
        operations in prop::collection::vec(effect_operation(), 0..192),
    ) {
        let mut effect = EffectState::new(EffectId::new(), IdempotencyClass::Keyed, None);

        for operation in operations {
            let _result = apply_effect_operation(&mut effect, operation);
            prop_assert_ne!(effect.status(), EffectStatus::Dispatching);
        }

        let mut dispatch_probe =
            EffectState::new(EffectId::new(), IdempotencyClass::Keyed, None);
        if approval_path {
            dispatch_probe
                .request_approval()
                .expect("approval request is valid");
        }
        dispatch_probe.authorize().expect("authorization is valid");
        let before_dispatch = dispatch_probe.clone();

        let missing_key_was_rejected = matches!(
            dispatch_probe.begin_dispatch(),
            Err(EffectError::MissingIdempotencyKey { .. })
        );
        prop_assert!(missing_key_was_rejected);
        prop_assert_eq!(&dispatch_probe, &before_dispatch);
        prop_assert_ne!(dispatch_probe.status(), EffectStatus::Dispatching);
    }
}
