# Implementation Plan

The plan builds vertical proofs. A phase is complete only when its exit gate passes; creating empty modules is not progress.

Current status: Phases 0 through 7 are implemented. Their gates cross the real HTTP, process,
SQLite, artifact, outbox, and SSE boundaries. The process suites hard-kill the daemon across
admission, provider dispatch, and read-tool preparation, then prove fenced recovery, exact budget
settlement, and recorded-only replay. Phase 3 additionally crosses approval, sandbox dispatch,
external mutation, outcome, and observation boundaries and proves denial, expiry, cancellation,
unknown-outcome reconciliation, and effect-aware recorded replay without duplicate mutation.
Phase 4 adds task admission criteria/risk, deterministic and fresh-context validation, validation-
gated success, bounded child authority/budgets/results, exclusive resource claims, lineage-aware
timelines, and owner-inspectable validation evidence.
Phase 5 adds cited immutable compactions, governed memory lifecycle and provenance, owner/workspace
namespace enforcement, deterministic FTS5 retrieval with degraded fallback, untrusted context
projection, content deletion with audit tombstones, and restart-safe recorded replay.
Phase 6 adds data-only digest-pinned extension packages, explicit immutable grants, supervised
one-shot RPC, crash/upgrade/revocation evidence, signed external-subject channel bindings, brokered
HMAC keys, replay reservations, and signed durable callback delivery across restart.
Phase 7 adds owner service installation, schema-versioned retention configuration and rollback
history, safe mode, bounded clean/forced drain evidence, operational gauges and request traces,
complete online backup with optional authenticated-encrypted secrets, isolated fresh-home restore
verification, scoped exports, age/reference-safe artifact GC, automatic pre-migration snapshots,
corrupt-store forensic preservation, and explicit platform sandbox conformance reporting.
Release review additionally closes durable task pause/resume fencing, atomic input-capacity
backpressure, configured run/concurrency limits across every required scheduler dimension,
deterministic jittered retry, a data-only skill contract, live provider routing evidence with
same-trust fallback checks, complete secret-free export, and task/run/attempt trace identity.

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

Status: complete. `phase2_read_only_loop`, `phase2_attempt_recovery`, and `phase2_cancellation`
exercise the public API and real daemon process. Replay verifies the complete state/journal/timeline
and artifact graph and fails closed under targeted evidence corruption without making live calls.

## Phase 3: Effect and approval proof

Deliver:

- tool descriptors and policy evaluation;
- sandbox executor process protocol;
- effect intent, approval subject hash, dispatch, outcome, and reconciliation;
- stable idempotency keys;
- waiting/resume across restart;
- unknown-outcome operator workflow.

Exit gate: crash injection at every line between intent creation, dispatch, external mutation, result receipt, and commit. Each case produces the expected retry, success, failure, or `outcome_unknown` state without duplicate non-idempotent mutation.

Status: complete. The approval-gated fixture write binds its schema-normalized arguments,
capability, target, executable identity, policy version, and expiry into one durable subject. The
ledger atomically parks/resumes the agent loop, reserves and settles tool/output budgets, dispatches
only through the least-authority Bubblewrap worker, records terminal or unknown evidence, and
supports authenticated idempotent approval/reconciliation commands through API and CLI. The
`phase3_effect_approval` process suite proves denial, exclusive expiry, cancellation revocation,
cold restart before and after approval, prepared-before-dispatch recovery, post-mutation ambiguity,
terminal-before-observation recovery, one external mutation, and recorded-only replay with zero
live calls.

## Phase 4: Validation and delegation

Deliver:

- success criteria and risk policy;
- deterministic validator and fresh-context model validator;
- child run lineage, capability intersection, separate budgets, and structured return;
- resource conflict claims;
- validation evidence in task completion.

Exit gate: parallel child runs cannot both claim one write scope; stale child result is fenced; medium-risk task cannot succeed without passing validation or a durable waiver.

Status: complete. Root tasks atomically persist typed capability ceilings, explicit success
criteria, risk, validation policy, and lineage. Low-risk reads run deterministic evidence checks;
medium-risk writes create a fresh read-only validator task/run and cannot cross the schema success
gate without a passing record or waiver. Validation survives restart without duplication and is
visible in task/timeline projections. Delegation atomically intersects parent, requested, and
current-policy authority; reserves and settles a separate child budget; fences structured results;
and rejects out-of-scope or concurrently owned resource claims. The Phase 4 storage and process
suites prove the exit gate, v7-to-v8 preservation, context-policy epoch rotation, and recorded-only
multi-turn replay.

## Phase 5: Memory and compaction

Deliver:

- structured compaction carry-forward and source citations;
- memory proposal/revision lifecycle;
- namespace/sensitivity/retention policy;
- SQLite FTS5 retrieval and degraded operation without embeddings;
- inspection, correction, export, and deletion CLI.

Exit gate: compaction preserves typed unresolved effects/constraints, source history remains queryable, and a cross-principal memory leak test fails closed.

Status: complete. Compaction commits validate exact source cursor/event/digest citations, require
typed goals and safety constraints, and cannot omit canonical pending approvals or effect outcomes.
Memory proposals retain immutable source evidence and support explicit activation/rejection,
superseding corrections, pin/expiry/deletion, owner export, and active-only FTS5 indexing with a
canonical fallback and rebuild path. Context manifests expose exact memory revision/source and
compaction provenance while labeling retrieved memory as untrusted evidence. The Phase 5 process
scenario crosses the authenticated API and real daemon, retrieves memory and compaction evidence,
deletes memory content, hard-restarts, and still completes recorded-only replay; storage/backend
tests prove sensitive-promotion authorization and fail-closed principal/channel/workspace scope.

## Phase 6: Extension and channel boundary

Deliver:

- manifest schema and digest pinning;
- supervised extension host with scoped RPC;
- one sample out-of-process tool extension;
- one external channel adapter with signature verification and durable outbox delivery;
- crash/upgrade/revocation lifecycle.

Exit gate: hostile extension fixtures cannot read undeclared secrets, write outside grants, forge an effect outcome, or stop `mealyd`; duplicate channel webhooks admit one input.

Status: complete. Extension installation and upgrade inspect exact manifest, executable, and
runtime digests before any code runs. Health and granted read-only capabilities execute through a
bounded empty-environment Bubblewrap host; dispatch evidence precedes launch and every valid output
or classified failure is terminally recorded. The sample extension process proves ambient secret,
filesystem, environment, network, forged-response, crash, fresh-grant upgrade, revocation, and
restart behavior. The signed webhook adapter creates a dedicated principal-bound session and
owner-only key file, verifies exact raw bodies and timestamp/nonce HMAC framing before JSON parsing,
reserves replay evidence before inbox admission, and reuses the existing durable outbox for signed
callbacks. Its process suite proves one admission for an exact duplicate, rejection of nonce reuse,
forgery, stale timestamps, and wrong subjects, callback retry across hard restart with a stable
delivery ID, key destruction, terminal revocation, and v9-to-v10 preservation.

## Phase 7: Operational hardening

Deliver:

- service installation, doctor, safe mode, graceful drain;
- backup, restore verification, export, retention, garbage collection;
- migration snapshot suite and corrupt-database forensic backup;
- metrics/traces and admin health views;
- platform sandbox conformance lanes.

Exit gate: restore into a fresh home passes integrity/scenario checks; corrupt DB handling preserves original files; supported OS lanes prove or explicitly deny each policy profile.

Status: complete. The authenticated admin API and `mealyctl` expose status, metrics, doctor, drain,
complete backup, restore verification, complete/scoped export, and GC. Backup manifests cover the online
SQLite snapshot, configuration, and every canonical artifact; secret inclusion is explicit and
uses Argon2id-derived XChaCha20-Poly1305, while fresh-home verification authenticates the decrypted
identity against restored canonical state. Startup snapshots every older supported schema before
its transactional migration and preserves corrupt databases plus WAL/SHM sidecars before failing.
Safe mode starts no dispatch workers and rejects mutations while retaining recovery operations.
Clean drain checkpoints and exits zero; a blocked provider proves the bounded status-2 path records
durable `forced` evidence. Doctor and CI lanes report Linux Bubblewrap conformance and explicitly
deny unavailable profiles/platform adapters. `phase7_operations` crosses the actual daemon/API
process boundary for the exit gate; maintenance, migration, artifact, API, and configuration unit
tests cover tamper, wrong-passphrase, prior-schema, GC, request-ID, and marker invariants.
The same process suite covers pause/resume revision and lease fencing, complete archive export, and
the public doctor fallback proof; scheduler/session units enforce durable concurrency and queue
capacity while provider/resource/extension guards enforce adapter-side limits.

## Deferred until the core proof

- web UI;
- Discord beyond the first channel proof if another channel is chosen;
- semantic/vector memory;
- plugin marketplace;
- distributed scheduler;
- multi-user product UX.

These features consume established APIs. They must not introduce alternate state, queue, policy, or approval paths.
