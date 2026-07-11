# Mealy

Mealy is a local-first, self-contained agent runtime for a reliable personal AI assistant.

This repository now contains the completed **Phases 0–7 release-one runtime proof**: a runnable local daemon,
authenticated CLI/API, durable session inbox, FIFO/steering/interruption semantics, fenced work
leases, restart recovery, outbox delivery, resumable timeline SSE, and a bounded provider-neutral
agent loop. The loop currently uses a deterministic local fake provider and one production fixture
read tool; it persists immutable context manifests, normalized attempts and usage, content-addressed
artifacts, cancellation, checkpoints, and recorded-only replay. Its approval-gated fixture write
uses an exact policy subject, durable effect ledger, stable idempotency key, out-of-process Linux
sandbox, explicit unknown-outcome reconciliation, automatic expiry, and effect-aware replay.
Every admitted task also has explicit success criteria and risk policy. Low-risk reads retain
deterministic validation evidence; medium-risk writes cannot succeed until a fresh, read-only
validator run passes. Durable delegation contracts intersect parent/request/policy capabilities,
reserve separate budgets, fence structured child results, and arbitrate exclusive resource claims.
Governed memory now has proposal, explicit activation/rejection, immutable correction history,
pin/expiry/deletion, owner-scoped export, and filtered FTS5 retrieval with a deterministic degraded
fallback. Session compactions are immutable artifacts whose typed goals, safety constraints,
approvals, effects, and source-event digests are validated against canonical history. Retrieved
memory is labeled untrusted evidence, compaction and memory provenance are owner-inspectable, and
recorded replay survives content deletion and daemon restart. General external model adapters and
arbitrary mutating tools remain future work. Digest-pinned data-only extension manifests now drive
explicit owner grants and one-shot Bubblewrap RPC workers; install, health-gated enable, invocation,
upgrade, disable, crash isolation, and terminal revocation retain durable evidence. A built-in
signed webhook channel maps a verified external subject to a dedicated session, authenticates the
exact raw body with brokered HMAC keys, rejects stale/replayed deliveries, and signs retrying
outbound callbacks from the durable outbox.
Operational hardening adds schema-versioned configuration and rollback history, durable daemon
lifetime evidence, safe mode, bounded clean/forced drain, authenticated status/metrics/doctor
views, immutable online backups, optional authenticated-encrypted secret archives, isolated fresh-
home restore verification, scoped exports, retention/GC, automatic pre-migration snapshots,
corrupt-database forensic preservation, owner-level service installation, request traces, and
explicit platform sandbox conformance reporting.

## Start here

- [`REQUIREMENTS.md`](REQUIREMENTS.md) — normative requirements and release-one acceptance boundary.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — practical design and requirement traceability.
- [`docs/research/REFERENCE_SYSTEMS.md`](docs/research/REFERENCE_SYSTEMS.md) — pinned review of all eight reference systems.
- [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) — vertical phases and exit gates.
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — installation, backup, retention, and recovery runbook.
- [`docs/REQUIREMENTS_COVERAGE.md`](docs/REQUIREMENTS_COVERAGE.md) — normative release evidence.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — trust boundaries and abuse cases.

## Repository map

- `apps/mealyd`: trusted daemon composition root.
- `apps/mealyctl`: local client and administration CLI.
- `crates/mealy-domain`: pure IDs and lifecycle state machines.
- `crates/mealy-application`: use cases, recovery planning, and ports.
- `crates/mealy-infrastructure`: SQLite, artifacts, processes, providers, and OS adapters.
- `crates/mealy-protocol`: versioned transport DTOs.
- `crates/mealy-api`: authenticated HTTP/SSE adapter.
- `crates/mealy-testkit`: deterministic scenario support.
- `docs`: design, decisions, research, and verification strategy.
- `schemas`: reviewed external contract fixtures.
- `tests`: integration and public-API scenarios.

## Development

The workspace is pinned by `rust-toolchain.toml`.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo test --workspace --doc
```

Run the daemon in one terminal:

```sh
cargo run -p mealyd -- --home .mealy
```

Then drive its authenticated loopback API through the CLI:

```sh
cargo run -p mealyctl -- --home .mealy health
cargo run -p mealyctl -- --home .mealy status
cargo run -p mealyctl -- --home .mealy doctor
cargo run -p mealyctl -- --home .mealy session create
cargo run -p mealyctl -- --home .mealy session send <SESSION_ID> "hello"
cargo run -p mealyctl -- --home .mealy session status <SESSION_ID>
cargo run -p mealyctl -- --home .mealy session watch <SESSION_ID>
cargo run -p mealyctl -- --home .mealy task status <TASK_ID>
cargo run -p mealyctl -- --home .mealy task pause <TASK_ID> --expected-revision <REVISION>
cargo run -p mealyctl -- --home .mealy task resume <TASK_ID> --expected-revision <REVISION>
cargo run -p mealyctl -- --home .mealy task replay <TASK_ID>
cargo run -p mealyctl -- --home .mealy task cancel <TASK_ID> "stop this run"
cargo run -p mealyctl -- --home .mealy approval list
cargo run -p mealyctl -- --home .mealy effect status <EFFECT_ID>
cargo run -p mealyctl -- --home .mealy memory list --workspace <WORKSPACE_IDENTITY>
cargo run -p mealyctl -- --home .mealy memory search --workspace <WORKSPACE_IDENTITY> "release"
cargo run -p mealyctl -- --home .mealy compaction status <COMPACTION_ID>
cargo run -p mealyctl -- --home .mealy extension list
cargo run -p mealyctl -- --home .mealy channel list
cargo run -p mealyctl -- --home .mealy backup nightly
cargo run -p mealyctl -- --home .mealy restore-verify nightly
cargo run -p mealyctl -- --home .mealy export audit-snapshot audit
cargo run -p mealyctl -- --home .mealy export complete-snapshot complete
cargo run -p mealyctl -- --home .mealy drain
```

`mealyd` creates an owner-only home and bearer credential, binds only to a literal loopback IP,
recovers before publishing readiness, and prevents two daemons from owning one home. `mealyctl`
disables proxies and redirects, validates the private loopback descriptor, prints generated
idempotency keys before dispatch, retries admission with the same key, and reconnects timeline
watchers after daemon restart without losing their durable cursor.

The process scenarios hard-kill the daemon across admission, provider, read-tool, approval, effect
preparation, external mutation, outcome, and observation boundaries; restart from the same
database; and verify fencing, exact budget settlement, explicit reconciliation, effect-free
replay, and continuous timeline evidence. Replay also fails closed for corrupted graph, journal,
sequence, checkpoint, descriptor, artifact, usage, deadline, timeline, memory, compaction,
extension, and channel evidence. Phase 7 process tests additionally prove safe-mode mutation
denial, encrypted backup and isolated restore verification, immutable export, clean and forced
drain, pre-migration preservation, and corrupt-database forensics. See
[`docs/OPERATIONS.md`](docs/OPERATIONS.md) for operator workflows and downgrade constraints.

## Reference clones

The eight research repositories are shallow-cloned outside this worktree at:

```text
../mealy-agentic-references/
```

Their commit pins and licenses are recorded in the research report. They are not build dependencies. The Claude Code mirror has no license and must not be used as a code source.

## License

See [`LICENSE`](LICENSE).
