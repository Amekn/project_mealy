# Requirements Coverage

This is the release-one implementation review for [`REQUIREMENTS.md`](../REQUIREMENTS.md). A row is
`covered` only when the behavior exists at a real enforcement or persistence boundary and has
repeatable evidence. A green compiler or unrelated test is not treated as requirement evidence.

## Normative requirement groups

| Requirements | Status | Implementation and verification evidence |
|---|---|---|
| DUR-001..002, API-001 | covered | `sessions`, `promotion`, journal/outbox transactions, and the single authenticated API; `durable_admission`, `phase1_runtime`, and `phase1_recovery` prove acknowledgement-before-processing and atomic transitions. |
| SEC-001..003, AUTH-001 | covered | Model/context content is data only; effects cross typed policy/executor ports; Bubblewrap is the only claimed mutation boundary. API and signed-channel tests prove IDs/body claims grant no authority. |
| AUTH-010..013, CHAN-010..013 | covered | Local bearer identity and raw-body HMAC verification resolve registered principal/binding records. Binding and extension grants are terminally revocable without history deletion. Durable inbox/outbox, webhook replay reservations, and callback retry are proven by `phase6_channel_boundary`, `sqlite::channel`, and `outbox_delivery`. |
| TASK-010..017 | covered | Typed UUIDv7 IDs, explicit lifecycle states, FIFO delivery modes, durable pause/resume fencing, cancellation, lineage, and bounded delegation are implemented. `lifecycle_properties`, `phase1_runtime`, `phase2_cancellation`, `phase4_validation`, and `phase7_operations` cover the transitions. |
| SCHED-010..015, OPS-001 | covered | Expiring leases, heartbeat, fencing, transactional per-principal/session/role ceilings, configured daemon/provider/extension/resource ceilings, atomic inbox backpressure, persisted due times, bounded attempts, and exponential outbox retry with deterministic jitter. `phase1_runtime`, recovery tests, outbox tests, and session-capacity tests cover the boundaries. |
| AGENT-010..016 | covered | The explicit context → model → validation → tool/effect → observation → final loop persists every dependency boundary. Schema-versioned daemon configuration supplies run budgets. Phase 2–4 process suites cover normalization, limits, repair/failure boundaries, deterministic tool order, profiles, and independent validation. |
| TOOL-010..018, REC-001 | covered | Immutable tool descriptors, exact approval subjects, intent-before-dispatch, stable effect keys, terminal/unknown outcomes, reconciliation, output limits/artifacts, and sandbox obligations. Domain properties, tool/policy units, `sandbox_executor`, and `phase3_effect_approval` cover mutation and crash points. |
| SEC-010..017 | covered | Default-deny typed policy evaluates identity, role/risk, exact arguments/resources/workspace/time/capability, records version/explanation, and emits sandbox/secret obligations. Five profiles exist; unsupported guarantees are explicitly denied by `doctor`. Security and process tests cover argument drift, ambient authority, secret canaries, traversal, and fail-closed profiles. |
| CTX-001, CTX-010..015 | covered | Context epochs/manifests persist ordered included/excluded/redacted evidence, digests, reasons, sensitivity, tokens, transformations, policy and residency. Compaction retains canonical sources and typed goals/constraints/approvals/effects. Phase 2 and 5 storage/process tests verify inspection and replay integrity. |
| MEM-001, MEM-010..015 | covered | Governed proposal/activation/rejection/supersession/expiry/deletion, provenance/namespace/confidence/sensitivity/retention, deterministic FTS5 plus fallback, untrusted citations, correction/pin/export/index rebuild. `phase5_memory_context` and memory store tests include cross-scope denial and tombstones. |
| PROV-010..014 | covered | The versioned capability contract includes modalities, tools, structured output, reasoning, streaming, context/output limits, pricing, residency, concurrency/rate ceilings, and retry hints. Live attempt preparation uses deterministic routing across capability/privacy/locality/health/cost/latency/policy; fallback is explicit and cannot reduce trust. Provider units and the public `doctor` scenario exercise fallback exclusion. Credentials never enter normalized context. |
| EXT-001, EXT-010..016 | covered | Data-only skills contain digest-pinned instructions/resources and separate tool references. Extensions use digest-pinned manifests, inspection without execution, explicit immutable grants, compatibility/migration/rollback metadata, bounded out-of-process RPC, failure isolation, upgrade and revocation. Skill units, `extension_host`, and `phase6_extension_boundary` prove the contract. |
| REC-010..017 | covered | SQLite state/journal/outbox atomicity, content-addressed artifacts, startup classification, unknown-effect honesty, forensic preservation, backup-aware transactional migrations, and effect-free recorded replay. Phase 1–7 crash suites, migration snapshots, replay-corruption cases, and maintenance tests provide evidence. Live replay is intentionally absent; the MAY requirement does not weaken recorded replay. |
| OBS-010..013, ART-010..011 | covered | The timeline spans all lifecycle/effect/context/validation/artifact/recovery facts with resumable gap-aware cursors. Artifact metadata and atomic blob publication are enforced. Admin status/metrics expose queues, leases, approvals, unknown effects, health, storage, schema and failures; HTTP and agent spans carry request/task/run/attempt/correlation/causation identity. |
| VAL-010..016 | covered | Every admitted task stores objective criteria/risk. Deterministic checks are preferred; medium-risk mutation requires a separately authorized fresh-context validator and durable outcome/evidence. `phase4_validation` and replay tests use the public API and deterministic provider. |
| CFG-010..012, DATA-010..013 | covered | Non-secret schema-versioned config, effective digests/history, explicit approved offline rollback, class/sensitivity/principal/task/channel/legal retention selectors, encrypted opt-in secret backup, isolated restore verification, complete archive plus scoped exports, memory tombstones, and reference-safe GC. Phase 7, config, maintenance, and artifact tests cover these paths. |
| NFR-REL-001..004, NFR-PERF-002, NFR-PERF-004 | covered | Startup recovery is automatic/queryable; acknowledged input survives provider/extension/sandbox/process failures; every retry/timeout is bounded; cursors resume and detect gaps; all ingress/provider/tool/extension/artifact frames have byte/item limits. |
| NFR-PERF-001, NFR-PERF-003 | measurement target | Accepted-input p95 latency and idle resident memory are SHOULD-level hardware-sensitive targets, not release blockers. The runtime avoids synchronous provider work on admission and keeps optional workers/models outside the idle baseline; repeatable benchmark baselines remain release-engineering measurements rather than functional enforcement claims. |
| NFR-PORT-001..002, NFR-OPS-001..002 | covered | The control plane compiles on Linux/macOS/Windows without container/cloud/workflow dependencies. Native service installation is Linux/macOS; unsupported worker profiles/platforms deny explicitly. CLI exposes doctor/status/backup/restore verification/safe mode/drain and forced termination evidence. |
| NFR-QUAL-001..004 | covered | Domain property tests, policy/recovery/effect/migration units, real SQLite integration tests, real process crash scenarios, public API workflows, fallback doctor scenario, extension/channel failures, migration snapshots, and sandbox/authorization/secret security cases run locally and in CI. |

## Release-one acceptance path

The eleven acceptance steps are crossed by the process suites rather than mocked at the storage
boundary:

1. `phase1_recovery` authenticates the local principal and durably admits input before reply.
2. `phase2_read_only_loop` claims a fenced run and persists the exact context manifest.
3. The built-in normalized provider proposes `fixture.read`; the bounded tool result becomes an
   artifact and then a final response.
4. `phase3_effect_approval` proposes the sandboxed fixture write, persists exact approval evidence,
   and parks the run.
5. Hard restart preserves queue, approval, cursor, manifest, budgets, and completed boundaries.
6. Approval resumes without repeating completed work; the effect crash matrix proves at-most-once
   mutation or explicit `outcome_unknown`.
7. `phase4_validation` records deterministic/fresh independent evidence before task success.
8. Final delivery crosses the durable outbox, and `task replay` validates the recorded graph with
   zero provider, tool, extension, or effect calls.

## Deliberate release boundary

The deferred items in the requirements—multi-tenant hosting, distributed scheduling, public
internet exposure, mobile clients—and the plan's web/Discord/vector/marketplace work remain outside
release one. General live provider and tool adapters can now be added behind the covered contracts;
they must pass the same provider, sandbox, effect, recovery, and traceability suites before being
advertised as supported.

The final local gate is:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo test --workspace --doc
```
