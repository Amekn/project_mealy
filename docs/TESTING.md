# Testing and Verification

## Test layers

### Domain unit and property tests

Fast, infrastructure-free tests cover state transitions, capability intersections, approval subject hashes, recovery classification, budget arithmetic, resource-claim ordering, and context mandatory-item rules.

Property examples:

- terminal task states never become active;
- aggregate sequence never decreases or duplicates;
- stale fencing tokens never authorize a commit;
- changing any effect subject field changes the approval digest;
- child capabilities are never broader than parent and profile grants;
- non-idempotent unknown effects never classify as automatic retry.

### Storage integration tests

Use real SQLite files, WAL, foreign keys, concurrent connections, busy timeouts, and migrations. Mock repositories cannot prove transaction or locking semantics.

Required checks:

- canonical row + event + outbox atomicity;
- rollback leaves none of the three;
- idempotent duplicate input admission;
- lease claim races and expiry;
- artifact rename/link crash cleanup;
- migration from every supported snapshot;
- backup and restore integrity.

### Process-boundary tests

Spawn the real executor/extension protocol. Verify framing, malformed messages, size limits, cancellation, timeout, stdout/stderr pressure, secret minimization, worker death, and daemon survival.

### Public-API scenarios

Scenarios start `mealyd`, drive versioned API commands, watch SSE, and assert durable database/artifact state only through supported inspection helpers.

The Phase 1 scenario at `apps/mealyd/tests/phase1_recovery.rs` currently proves authenticated
admission, hard process death before promotion/outbox delivery, identity-preserving restart,
exactly-one promotion, outbox resumption, stable idempotent receipts, and cursor-resumed SSE. The
storage scenarios in `crates/mealy-infrastructure/tests/phase1_runtime.rs` and
`outbox_delivery.rs` cover claim races, live expiry, stale result fencing, all three input delivery
modes, and outbox ownership recovery.

The Phase 2 process suites at `apps/mealyd/tests/phase2_read_only_loop.rs`,
`phase2_attempt_recovery.rs`, and `phase2_cancellation.rs` prove the bounded fake-provider → read
tool → final loop, content-addressed artifact output, cooperative cancellation, timeout
containment, immediate startup recovery, retry lineage, exact reservation settlement, and
recorded-only replay. Their corruption matrix covers normalized responses and usage, lifecycle
ordering, successful-row error classes, policy and descriptor capability evidence, artifact
producer metadata and blob presence, checkpoints, exact operation payloads, per-aggregate journal
sequence chains, terminal graph state, and journal-to-timeline links. Every replay assertion also
checks that no live provider or tool call occurred.

The Phase 3 suite at `apps/mealyd/tests/phase3_effect_approval.rs` drives the authenticated public
approval/effect commands and a real Bubblewrap worker. It proves deny, expiry, cancellation
revocation, exact command deduplication/conflict behavior, budget settlement, and the crash matrix
from parked intent through preparation, dispatch, external mutation, outcome commit, observation,
and reconciliation. Successful and reconciled tasks replay from recorded effect evidence with zero
live provider/executor calls, while attempt counts and workspace bytes prove that unsafe work was
not repeated.

The Phase 4 process suite at `apps/mealyd/tests/phase4_validation.rs` runs a deterministic low-risk
validator and a fresh-context medium-risk validator through the public task API, then hard-restarts
the daemon and proves stable validation identity, zero duplicate records, read-only validator
authority, child lineage, validation-gated success, and recorded-only replay. SQLite tests prove
three-way child capability intersection, separate delegated-run budget reservation/settlement,
out-of-scope claim rejection, exclusive write-scope arbitration, stale child-result fencing,
lineage-aware timeline visibility, and v7-to-v8 data preservation.

The Phase 5 process suite at `apps/mealyd/tests/phase5_memory_context.rs` creates a cited typed
compaction and an activated governed memory through the authenticated API, then proves both are
selected into model context with exact owner-inspectable provenance and explicit untrusted-memory
labeling. It completes recorded-only replay before and after memory content deletion, hard-restarts
the daemon, and proves the same replay and provenance remain available without live model/tool
calls. SQLite tests cover proposal/activation/rejection/correction/pin/expiry/deletion transitions,
sensitive owner authorization, active-only FTS5 synchronization and degraded fallback, index
rebuild, immutable citations, canonical approval/effect carry-forward, typed goal/safety retention,
v8-to-v9 preservation, and cross-principal/channel/workspace denial.

The Phase 6 process suites at `apps/mealyd/tests/phase6_extension_boundary.rs` and
`phase6_channel_boundary.rs` cross the authenticated administration API, unauthenticated-but-signed
ingress, SQLite replay registry, owner-only secret broker, real Bubblewrap extension worker, and a
real HTTP callback receiver. They prove manifest/executable/runtime digest pinning, least-authority
grant replacement, health-gated enable, schema-bound RPC, secret/environment/filesystem/network
isolation, forged-response and crash containment, upgrade, terminal revocation, raw-body HMAC
verification, stale/forged/wrong-subject rejection, exact duplicate admission, nonce replay denial,
and signed outbox delivery after a hard daemon restart. Storage tests cover immutable invocation and
manifest evidence, revocable principal/channel registries, replay reservation recovery, active-only
outbound routing, secret-file permissions/deletion, and v9-to-v10 preservation.

The Phase 7 process suite at `apps/mealyd/tests/phase7_operations.rs` starts real daemon processes
for safe mode, clean drain, corrupt-open failure, and a provider call deliberately held beyond a
100 ms drain deadline. It proves mutation denial with recovery operations still available,
authenticated operational/doctor views, Argon2id/XChaCha20-Poly1305 secret backup, isolated
fresh-home identity/artifact/database verification, immutable audit export, status-0 clean drain,
complete archive export, task pause/resume fencing, explicit same-trust provider fallback through
the public doctor endpoint, status-2 forced evidence, and byte-identical forensic preservation.
Infrastructure tests cover atomic queue backpressure, durable concurrency dimensions,
deterministic jittered retry,
wrong-passphrase/tamper failure, unencrypted default backup, prior-schema snapshots, v10-to-v11
preservation, referenced-vs-orphan GC, configuration history, and forced-marker reconciliation.

Replay reports evidence as incomplete when an excluded artifact-backed context item cannot be
byte-for-byte reconstructed inside the SQLite-only verifier. The artifact adapter still verifies
the referenced blob, but Mealy does not claim a deterministic rendered digest or token estimate
without those bytes. This is a deliberate fail-closed boundary pending byte-aware replay evidence.

## Crash matrix

Each boundary is tested by a deterministic failpoint before and after the action:

| Flow | Failpoints |
|---|---|
| Input | before DB begin; after inbox insert; before commit; after commit before response |
| Lease | after claim; during heartbeat; after expiry; stale result commit |
| Model | before request; after request dispatch; after full response; before normalized commit |
| Effect | before authorization; after approval; before dispatch; after external mutation; before outcome commit |
| Artifact | during stream; after flush; after rename; before/after DB link |
| Outbox | before send; after remote accept; before delivery commit |
| Compaction | after source selection; after generation; before derived record commit |
| Migration | before backup; during migration; before version marker; restore verification |

## Security matrix

- Missing/invalid local API credential.
- Disallowed browser Origin and oversized body.
- Forged channel identity and replayed webhook.
- Cross-principal session/task/artifact/memory access.
- Model text pretending to approve an effect.
- Approval replay with changed arguments, tool version, target, policy, principal, or expiry.
- Sandbox path traversal, symlink, environment, process, and network escape attempts.
- Extension requests undeclared capability/secret/network target.
- Secret canary search across provider payload, logs, journal, artifacts, and worker environment.

## Provider contract suite

Every provider adapter runs the same tests for:

- text and supported modalities;
- streaming and cancellation;
- tool-call normalization and malformed arguments;
- structured output;
- empty/partial responses and provider errors;
- context overflow;
- usage and cost fields;
- retry hints and rate limits;
- cross-provider history projection;
- no credential leakage into normalized records.

## Validation gates

CI initially runs:

```text
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
documentation link/requirement checks
schema compatibility checks
```

The checked-in CI matrix compiles every control-plane target on Linux, macOS, and Windows, runs the
strict workspace gate on Linux, and has a separate Bubblewrap conformance lane. `doctor` explicitly
denies every profile whose guarantees the current host cannot supply. Live-provider tests are
opt-in and cannot be the sole evidence for deterministic behavior.

## Requirements coverage

Scenario names and the release review in [`REQUIREMENTS_COVERAGE.md`](REQUIREMENTS_COVERAGE.md) map
MUST requirement groups to concrete storage, API, process, property, migration, and security tests.

Green tests prove only covered requirements. Completion reviews inspect the mapping instead of treating `cargo test` as proof of the entire product.
