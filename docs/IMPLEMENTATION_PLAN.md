# Implementation Plan

The plan builds vertical proofs. A phase is complete only when its exit gate passes; creating empty modules is not progress.

## Phase 0: Executable domain skeleton

Deliver:

- workspace and crate dependency rules;
- typed IDs and task/effect state machines;
- transition and property tests;
- initial SQLite migration with journal, aggregate sequence, session inbox, tasks, runs, leases, effects, and outbox;
- deterministic clock/ID test adapters.

Exit gate: domain tests reject invalid transitions, and a real SQLite transaction atomically commits a task change, journal event, and outbox row.

## Phase 1: Durable admission and scheduler

Deliver:

- loopback API authentication;
- session creation and idempotent input admission;
- durable FIFO promotion;
- work lease claim, heartbeat, expiry, and fencing;
- timeline query/SSE cursor;
- startup recovery for leases and pending outbox rows;
- `mealyctl session create|send|watch|status`.

Exit gate: kill the daemon after acknowledgement but before promotion; restart and observe exactly one promoted input and a continuous timeline.

## Phase 2: Provider and read-only loop

Deliver:

- provider capability port and deterministic fake provider;
- context epochs and context manifests;
- bounded agent loop with one read-only tool;
- normalized model attempts and usage;
- artifact store for large tool/provider output;
- cancellation and budget limits.

Exit gate: public-API scenario runs fake model → read tool → final answer; replay uses recorded results without provider/tool calls.

## Phase 3: Effect and approval proof

Deliver:

- tool descriptors and policy evaluation;
- sandbox executor process protocol;
- effect intent, approval subject hash, dispatch, outcome, and reconciliation;
- stable idempotency keys;
- waiting/resume across restart;
- unknown-outcome operator workflow.

Exit gate: crash injection at every line between intent creation, dispatch, external mutation, result receipt, and commit. Each case produces the expected retry, success, failure, or `outcome_unknown` state without duplicate non-idempotent mutation.

## Phase 4: Validation and delegation

Deliver:

- success criteria and risk policy;
- deterministic validator and fresh-context model validator;
- child run lineage, capability intersection, separate budgets, and structured return;
- resource conflict claims;
- validation evidence in task completion.

Exit gate: parallel child runs cannot both claim one write scope; stale child result is fenced; medium-risk task cannot succeed without passing validation or a durable waiver.

## Phase 5: Memory and compaction

Deliver:

- structured compaction carry-forward and source citations;
- memory proposal/revision lifecycle;
- namespace/sensitivity/retention policy;
- SQLite FTS5 retrieval and degraded operation without embeddings;
- inspection, correction, export, and deletion CLI.

Exit gate: compaction preserves typed unresolved effects/constraints, source history remains queryable, and a cross-principal memory leak test fails closed.

## Phase 6: Extension and channel boundary

Deliver:

- manifest schema and digest pinning;
- supervised extension host with scoped RPC;
- one sample out-of-process tool extension;
- one external channel adapter with signature verification and durable outbox delivery;
- crash/upgrade/revocation lifecycle.

Exit gate: hostile extension fixtures cannot read undeclared secrets, write outside grants, forge an effect outcome, or stop `mealyd`; duplicate channel webhooks admit one input.

## Phase 7: Operational hardening

Deliver:

- service installation, doctor, safe mode, graceful drain;
- backup, restore verification, export, retention, garbage collection;
- migration snapshot suite and corrupt-database forensic backup;
- metrics/traces and admin health views;
- platform sandbox conformance lanes.

Exit gate: restore into a fresh home passes integrity/scenario checks; corrupt DB handling preserves original files; supported OS lanes prove or explicitly deny each policy profile.

## Deferred until the core proof

- web UI;
- Discord beyond the first channel proof if another channel is chosen;
- semantic/vector memory;
- plugin marketplace;
- distributed scheduler;
- multi-user product UX.

These features consume established APIs. They must not introduce alternate state, queue, policy, or approval paths.
