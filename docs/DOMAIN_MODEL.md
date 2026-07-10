# Domain Model

This document gives implementation names to the normative concepts in `REQUIREMENTS.md`. Domain types live in `mealy-domain`; transport DTOs do not define these invariants.

## ID policy

All externally visible objects use UUIDv7 newtypes. IDs are opaque and never convey authorization. Journal aggregate sequences and inbox sequences are monotonic integers scoped to their aggregate/session.

Required newtypes:

```text
PrincipalId  ChannelBindingId  SessionId  InboxEntryId  TurnId
TaskId       RunId              AttemptId  ToolCallId    EffectId
ApprovalId   ArtifactId         ContextManifestId       MemoryId
ValidationId LeaseId            CorrelationId           EventId
```

Stringly typed IDs are forbidden across domain/application boundaries.

## Aggregate boundaries

### Session

Owns conversational ordering, inbox promotion, context epoch pointer, and active turn pointer. It does not own principal authorization or arbitrary task state.

Invariants:

- inbox sequence is unique and increasing;
- no more than one promoted mutating turn;
- a dedupe key maps to one admission result;
- a context epoch changes only at a turn boundary.

### Task

Owns objective, criteria, risk, budget, lifecycle, parent task, and final outcome. A task may have multiple runs and validations.

Invariants:

- terminal states cannot return to active states;
- success requires policy-required validation;
- cancellation does not erase unknown effects;
- revisions increase on every transition.

### Run

Owns agent role, delegated work order, capability ceiling, budget, lineage, and attempt list. Child capabilities are an intersection, never an implicit copy.

### Effect

Owns the exact normalized intent, subject digest, policy decision, approval, dispatch metadata, idempotency key, recovery class, and outcome.

Invariants:

- dispatch requires an active authorization for the current subject digest;
- only one current dispatch lease/fencing token may commit;
- non-idempotent unknown outcomes cannot transition back to dispatch automatically;
- reconciliation creates evidence and an explicit transition.

### Memory

Owns a logical memory and versioned revisions. Source links remain immutable even when a corrected revision supersedes content.

## Commands versus facts

Commands are authenticated requests that may fail preconditions:

```text
SubmitInput  PromoteInput  PauseTask  ResumeTask  CancelTask
StartRun     RecordModelResult  ProposeEffect  ResolveApproval
RecordEffectOutcome  ReconcileEffect  ProposeMemory  AcceptMemory
RecordValidation
```

Journal events are past-tense facts produced only after a committed transition:

```text
input.accepted  input.promoted  task.started  task.waiting
model.attempt_completed  effect.proposed  approval.requested
effect.outcome_unknown  effect.reconciled  context.compiled
memory.activated  validation.completed  task.succeeded
```

An event handler never mutates canonical state outside an application transaction. Outbox consumers perform delivery and report results through commands.

## Error taxonomy

- `InvalidTransition`: domain lifecycle forbids the command.
- `Conflict`: expected revision, lease, or resource claim is stale.
- `Unauthorized`: authenticated principal lacks access.
- `PolicyDenied`: capability was evaluated and denied.
- `ApprovalRequired`: durable waiting state was created.
- `ResourceBusy`: bounded scheduling conflict.
- `RetryableDependency`: classified external transient failure.
- `OutcomeUnknown`: dispatch may have taken effect and needs reconciliation.
- `InvariantViolation`: bug or corrupt canonical state; fail closed and alert.

Errors exposed by the API use stable codes and safe details. Internal causes become sensitive artifacts when needed.
