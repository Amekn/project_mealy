# Mealy Architecture

- Version: 0.1.0
- Status: proposed implementation baseline
- Requirements: [`REQUIREMENTS.md`](REQUIREMENTS.md)
- Research: [`docs/research/REFERENCE_SYSTEMS.md`](docs/research/REFERENCE_SYSTEMS.md)

## 1. Executive design

Mealy is a **modular monolith with isolated workers**:

- one Rust daemon, `mealyd`, is the trusted control plane and composition root;
- one SQLite database is the transactional authority for canonical state, transition history, leases, inboxes, and outboxes;
- immutable large content lives in a content-addressed artifact store;
- agent reasoning orchestration lives in application modules, not in channels or providers;
- shell, filesystem mutation, browser control, and third-party extensions execute outside the daemon process;
- local clients and channel adapters use one versioned command/query/event API;
- recovery resumes from explicit durable boundaries and never guesses that an unknown effect failed.

This is deliberately not microservices, not pure event sourcing, and not an in-process plugin platform. The architecture keeps the first personal-daemon release operable while preserving the boundaries that are expensive to retrofit later.

## 2. What the references changed

The previous architecture had several sound instincts—daemon ownership, thin channels, SQLite, explicit policy, context manifests, independent validation—but its append-only event ledger was asked to be the answer to too many problems. The reference systems sharpened the design:

| Evidence | Adopted decision |
|---|---|
| Codex uses explicit thread/turn/item primitives, generated protocol schemas, bounded server queues, platform sandboxes, and fresh Guardian review sessions. | Use explicit domain IDs, versioned DTOs, bounded ingress, OS enforcement, and isolated risk-based validation. |
| OpenClaw has a successful single gateway and channel model, but its events are not replayed, queues are in-process, plugins are trusted in-process, and sandboxing is off by default. | Keep one daemon and thin channels; move input queues to SQLite, make events resumable, isolate extensions, and make restricted execution the normal path. |
| Hermes centralizes providers/tools and uses SQLite/FTS, but large orchestration modules and JSON mirrors create coupling and recovery complexity; its security policy correctly distinguishes OS boundaries from heuristics. | Use coarse architectural modules, one canonical store, small ports, and explicit OS boundaries. Avoid mirror files as a second authority. |
| OpenCode's Effect services, durable aggregate sequencing, context epochs, input promotion, and atomic projectors are strong; its ongoing dual-write/event migration demonstrates the cost of pure event sourcing. | Adopt aggregate sequences, context epochs, and atomic state+journal commits, but keep normalized canonical tables rather than requiring full reconstruction from all historical events. |
| Vercel AI SDK cleanly separates UI/model/provider messages, validates tools, bounds loops, and re-validates approvals; it intentionally leaves durability and memory ownership to applications. | Use message layers and schema validation at adapters; Mealy supplies the missing durable host semantics. |
| Eve proves durable step checkpoints and parked approvals, but interrupted steps re-run, message FIFO is delegated to channels, and durability depends on a workflow world. | Checkpoint at safe boundaries, persist parked work, own the FIFO in core, and implement scheduling locally. |
| Pi's small agent core and JSONL session tree are understandable; its durability design correctly refuses unsafe tool replay, but the fully durable harness remains a design rather than implemented recovery. | Keep the loop small, make recovery semantics part of tool contracts, and test them before calling the runtime durable. |
| The Claude Code mirror shows strong transcript-before-execution persistence, queued writes, explicit tool risk metadata, coordinator/worker isolation, and fresh verification. It is an unlicensed third-party mirror of proprietary source. | Use only independently described architectural lessons; do not copy code, identifiers, or implementation text from that mirror. |

Detailed evidence and commit pins are in the research report.

## 3. Architectural invariants

1. A channel acknowledgement follows, never precedes, the durable inbox commit.
2. Only application use cases may transition canonical task/run/effect state.
3. Each accepted transition writes canonical state, a journal event, and outbox entries in one SQLite transaction.
4. Journal events are immutable history; canonical tables are the efficient current-state authority. Neither is an eventually consistent shadow of the other.
5. Every worker commit is fenced by the current lease token.
6. A model is an untrusted decision proposer. A policy decision is made by deterministic code.
7. The daemon never runs model-proposed shell or arbitrary extension code in its own process.
8. An approval binds an exact effect intent; it is invalid if the intent changes.
9. Unknown non-idempotent effects stop for reconciliation.
10. Context and compaction are derived, inspectable records; source history remains canonical.
11. Third-party extension manifests are readable without loading their code.
12. Debug replay consumes recorded results and cannot produce external effects.

## 4. System context

```mermaid
flowchart LR
  User["Owner"] --> Clients["CLI / TUI / Web"]
  Platforms["Discord / future channels"] --> ChannelAdapters["Channel adapters"]
  Clients --> API["Versioned local API"]
  ChannelAdapters --> API

  subgraph Daemon["mealyd — trusted control plane"]
    API --> App["Application use cases"]
    App --> Scheduler["Durable scheduler"]
    App --> Policy["Policy and approvals"]
    App --> Context["Context and memory"]
    App --> Providers["Provider broker"]
    App --> Store["Transactional store"]
  end

  Store --> SQLite[("SQLite")]
  Store --> Artifacts[("Content-addressed artifacts")]
  Providers --> Models["Local / remote model providers"]
  Scheduler --> Executor["Sandbox executor process"]
  Scheduler --> ExtensionHost["Extension host process"]
  Executor --> OS["Filesystem / commands / browser"]
  ExtensionHost --> Services["External services"]
```

### 4.1 Runtime trust zones

| Zone | Contents | Secret access | Arbitrary code | Failure effect |
|---|---|---:|---:|---|
| Trusted control plane | daemon, store, policy, provider broker, secret broker | scoped broker access | first-party compiled code only | daemon restart and recovery |
| Restricted executor | shell/file/browser worker under OS policy | invocation-scoped handles only | model-proposed commands | kill worker; classify active effect |
| Extension host | one or more third-party extension processes | declared scoped handles only | installed extension code | disable affected extension; daemon remains healthy |
| External | model providers, APIs, channels | credentials sent only by broker | outside Mealy | retry, reconcile, or degrade by policy |

The initial implementation may use trusted built-in channel and provider adapters in the daemon. No third-party code is promoted into that zone.

## 5. Code architecture

The dependency direction is coarse on purpose. Too many crates would turn a personal daemon into a distributed system made of Cargo packages.

```mermaid
flowchart TB
  mealyd["apps/mealyd"] --> api["mealy-api"]
  mealyd --> infra["mealy-infrastructure"]
  mealyd --> app["mealy-application"]
  mealyctl["apps/mealyctl"] --> protocol["mealy-protocol"]
  api --> protocol
  api --> app
  infra --> app
  app --> domain["mealy-domain"]
  protocol --> domain
  testkit["mealy-testkit"] --> protocol
  testkit --> domain
```

### 5.1 Crate responsibilities

#### `mealy-domain`

Pure domain types and state machines. It has no database, network, OS, async runtime, provider SDK, or web framework dependencies.

- typed IDs and time/value objects;
- session, task, run, attempt, approval, effect, memory, and validation states;
- transition validation and invariant errors;
- capability, risk, and effect classifications;
- version-neutral event facts used by the application layer.

#### `mealy-application`

Use cases and ports. It coordinates transactions but does not know SQLite or HTTP details.

- command handlers and query handlers;
- durable scheduler, leases, and recovery classifier;
- agent loop and delegation;
- policy orchestration and approval binding;
- context compilation and memory lifecycle;
- validation orchestration;
- port traits for transactions, providers, executors, artifacts, secrets, clocks, IDs, and extension hosts.

Application modules are internal boundaries, not separate services:

```text
identity  sessions  tasks  scheduler  agents  providers
tools     policy    context memory     validation channels
```

Cross-module writes occur through use cases, never by reaching into another module's repository tables.

#### `mealy-infrastructure`

Concrete adapters.

- SQLite repositories, transactions, migrations, lease claims, and outbox;
- filesystem content-addressed artifacts;
- process supervisor and sandbox backends;
- built-in provider clients;
- OS keyring/secret broker;
- extension RPC host client;
- telemetry exporters and system service integration.

#### `mealy-protocol`

Stable transport-facing DTOs and event envelopes. Domain types are not serialized directly. This permits protocol compatibility to evolve separately from internal refactoring.

#### `mealy-api`

Authentication, authorization entry, bounded request handling, command/query routes, timeline streaming, health, readiness, and OpenAPI generation.

#### Applications

- `mealyd`: composition root, config, lifecycle, supervision, recovery, API listener.
- `mealyctl`: local administrative and scripting client. The first interactive surface.

#### `mealy-testkit`

Deterministic clock and ID generators, fake providers, fake executors, crash injection, scenario driver, and fixture builders. Production crates must not depend on it.

## 6. Domain model

### 6.1 Ownership hierarchy

```text
Principal
└── Session (ordered durable inbox)
    ├── Turn (one promoted input)
    │   └── Task (user-visible objective; may outlive a turn)
    │       ├── Run (one agent role)
    │       │   ├── Attempt (model/tool/validation attempt)
    │       │   └── Child Run edges
    │       ├── Effect Intent → Approval → Effect Outcome
    │       ├── Context Manifests
    │       ├── Artifact References
    │       └── Validation Runs
    └── Inbox entries not yet promoted
```

A task may be created from a turn or by a schedule. A session is conversational ordering, not an authorization boundary. A run is execution lineage, not a user-visible chat thread.

### 6.2 Task state machine

```mermaid
stateDiagram-v2
  [*] --> queued
  queued --> running: lease acquired
  running --> waiting: approval / user input / backoff
  waiting --> queued: condition satisfied
  running --> paused: owner pause
  paused --> queued: resume
  running --> succeeded: criteria and validation pass
  running --> failed: terminal error
  queued --> cancelled
  running --> cancelling
  waiting --> cancelled
  paused --> cancelled
  cancelling --> cancelled: workers drained
  cancelling --> failed: forced stop leaves terminal failure
```

State changes carry a monotonic `revision`. Commands use expected revisions where races matter.

### 6.3 Run and attempt distinction

A run represents the logical execution by one agent role. Attempts represent retryable operations. Retrying a provider call creates a new attempt under the same run. Restarting a failed implementation from a clean context may create a new sibling run. This makes cost, failure, and validation lineage explicit rather than overwriting one status row.

### 6.4 Effect state machine

```mermaid
stateDiagram-v2
  [*] --> proposed
  proposed --> denied: policy deny
  proposed --> awaiting_approval: policy asks
  proposed --> authorized: policy allow
  awaiting_approval --> authorized: valid approval
  awaiting_approval --> denied: deny / expiry
  authorized --> dispatching: effect lease acquired
  dispatching --> succeeded: confirmed outcome
  dispatching --> failed: confirmed no success
  dispatching --> outcome_unknown: worker/transport lost ambiguity
  outcome_unknown --> succeeded: reconciliation confirms
  outcome_unknown --> failed: reconciliation confirms no effect
  outcome_unknown --> compensated: compensation confirmed
```

`outcome_unknown` is a first-class safety state. The scheduler never turns it into `authorized` by timeout alone.

## 7. Persistence architecture

### 7.1 Why transactional journaling, not pure event sourcing

Mealy needs history, resumable streams, causation, and forensic replay. It does not need every future version to rebuild all state from every event schema ever emitted. The store therefore has two co-authoritative products committed together:

1. normalized canonical tables for current state and scheduling;
2. an immutable transition journal for history, streaming, audit, and debug simulation.

Derived read models may be rebuilt. Canonical state is changed by migrations, not reconstructed by replaying unbounded historical business logic. This avoids both the dual-source problem seen in mirror-file designs and the migration burden exposed by a pure event transition.

### 7.2 Transaction pattern

Every mutating use case follows one shape:

```text
BEGIN IMMEDIATE
  authenticate/authorize preconditions already resolved
  load canonical rows and verify expected revisions/fencing token
  apply domain transition
  write canonical rows
  append versioned journal event with aggregate sequence
  append zero or more outbox records
COMMIT
publish in-process wakeup hint
```

The wakeup is only a latency optimization. Polling the database is sufficient after a missed notification or restart.

### 7.3 Core tables

The initial schema is organized by responsibility:

| Area | Canonical tables |
|---|---|
| Identity | `principals`, `channel_bindings`, `auth_credentials`, `revocations` |
| Conversation | `sessions`, `session_inbox`, `turns`, `messages` |
| Work | `tasks`, `runs`, `run_edges`, `attempts`, `work_leases`, `resource_claims` |
| Effects | `tool_calls`, `effect_intents`, `approvals`, `effect_outcomes` |
| Context | `context_epochs`, `context_manifests`, `context_items`, `compactions` |
| Memory | `memories`, `memory_sources`, `memory_revisions`, FTS tables |
| Evidence | `artifacts`, `artifact_links`, `validations`, `validation_evidence` |
| Operations | `journal_events`, `aggregate_sequences`, `outbox`, `config_versions`, `migration_history` |

Foreign keys are enabled. SQLite uses WAL mode, a busy timeout, and explicit durability settings selected by profile. Schema constraints enforce unique aggregate sequence, inbox dedupe keys, active lease ownership, and stable effect idempotency keys.

### 7.4 Journal envelope

```text
event_id             UUIDv7
aggregate_kind       session | task | run | effect | memory | ...
aggregate_id         stable domain ID
aggregate_sequence   contiguous per aggregate
event_type           namespaced semantic type
event_version        positive integer
occurred_at           UTC timestamp from the transaction clock
actor_principal_id   nullable only for system recovery events
correlation_id       task or request lineage
causation_id         command/event that caused this event
policy_version       when security-relevant
sensitivity          classification
payload              bounded JSON
```

Payloads are small. Large request/response bodies, logs, patches, and media become artifacts.

### 7.5 Artifact commit protocol

1. Stream bytes to a private temporary file while hashing and enforcing size.
2. Flush and atomically rename to `artifacts/<algorithm>/<digest>`.
3. In a database transaction, insert metadata and link it to the owning object.
4. A garbage collector removes unreferenced, aged content; it never removes referenced content.

Content encryption at rest is an adapter concern, but the digest is over the plaintext logical content and sensitive metadata is access-controlled.

## 8. Durable inbox, scheduler, and recovery

### 8.1 Input admission

Each adapter derives a stable delivery dedupe key from the channel event ID. Admission inserts the inbox row, journal event, and acknowledgement outbox record atomically. Duplicate delivery returns the original admission result.

The session driver promotes inbox records according to one of three explicit modes:

- `queue`: FIFO, one turn after the current turn;
- `steer_at_boundary`: attach to the current run at the next model/tool boundary without cancelling an active effect;
- `interrupt_then_queue`: request cancellation, then promote after the active run reaches a terminal or forced-stop boundary.

No accepted message lives only in RAM.

### 8.2 Lease claim

A worker claims work with `(lease_id, owner_id, fencing_token, expires_at)`. Renewals update only the matching lease. Every result commit verifies the fencing token against the canonical row. An expired worker may continue computing, but it cannot alter Mealy after another worker claims the work.

### 8.3 Resource claims

Tools and agents declare normalized conflict keys, for example:

```text
workspace-write:C:/repo
service-mutate:github:owner/repo
memory-write:principal/project
device-exclusive:browser-profile/default
```

The scheduler obtains claims in lexical order to avoid deadlock. Read claims may share; write/exclusive claims may not. Policy may require stricter serialization than the tool declares.

### 8.4 Startup recovery

Recovery runs before readiness:

1. Open SQLite and validate migration state.
2. Verify artifact root and quarantine incomplete temporary files.
3. Expire stale leases and increment fencing tokens.
4. Classify non-terminal attempts and effects.
5. Requeue safe model attempts and pure/idempotent operations.
6. Mark ambiguous non-idempotent effects `outcome_unknown`.
7. Restore waiting approvals and user-input requests.
8. Resume durable outbox delivery.
9. Publish a recovery summary and become ready.

Classification is deterministic code covered by table-driven tests. It is not delegated to a model.

### 8.5 Recovery matrix

| Interrupted boundary | Default recovery |
|---|---|
| Before provider request dispatch | retry attempt |
| Provider request sent, no normalized response recorded | retry only under provider/cost policy; preserve prior attempt |
| Normalized model response recorded | continue from recorded response |
| Pure/read-only tool not confirmed | bounded retry |
| Idempotent effect with stable downstream key | retry with same key |
| Non-idempotent effect after dispatch | `outcome_unknown`; reconcile |
| Approval waiting | restore waiting state |
| Compaction not committed | recompute derived artifact |
| Artifact committed but link transaction missing | GC later unless reconciliation links it |
| Outbox delivery unknown | retry using delivery dedupe key |

## 9. Agent runtime

### 9.1 Loop

```mermaid
flowchart TD
  Promote["Promote durable input"] --> Compile["Compile context manifest"]
  Compile --> Model["Create model attempt"]
  Model --> Normalize["Normalize and validate response"]
  Normalize --> Decide{"Response kind"}
  Decide -->|final| Validate["Validation policy"]
  Decide -->|tools| Intents["Create tool/effect intents"]
  Intents --> Policy["Policy + approvals"]
  Policy --> Execute["Sandbox/extension execution"]
  Execute --> Observe["Persist ordered results"]
  Observe --> Budget{"Continue within budgets?"}
  Budget -->|yes| Compile
  Budget -->|no| Fail["Bounded terminal outcome"]
  Validate --> Complete["Complete task and outbox reply"]
```

The loop is an application state machine. Provider SDK callbacks and UI streams adapt into it; they do not own it.

### 9.2 Message layers

Following the successful separation in Vercel AI SDK and Codex:

1. **Domain message**: provider-neutral, durable user/assistant/tool/event facts.
2. **Context item**: authorized, transformed material selected for one attempt.
3. **Provider message**: normalized provider contract.
4. **Wire payload**: provider-specific request/stream type.
5. **Presentation event**: channel-safe timeline representation.

Conversions are one-way at explicit adapters. Raw provider payloads may be retained as sensitive artifacts for debugging but never become the domain model.

### 9.3 Model attempts

Each request records provider/model, normalized parameter set, context manifest ID, tool schema digests, policy/routing decision, timeout, and budget reservation before dispatch. Completion records usage, finish reason, response artifact, normalized result, and provider request ID.

Streaming deltas are best-effort presentation data. The terminal normalized response is the durable boundary.

### 9.4 Delegation

Delegation creates a child run with:

- a self-contained work order and success criteria;
- explicit parent/root lineage;
- a new context manifest and fresh context window;
- an independently computed capability intersection;
- separate budgets and resource claims;
- a structured result contract.

The parent remains responsible for synthesis. It cannot claim child output as validated merely because the child completed.

## 10. Tools, policy, and execution

### 10.1 Tool descriptor

Every tool publishes metadata before it can be selected:

```text
id, version, input_schema, output_schema
effect_class, risk_class, required_capabilities
timeout, maximum_output, concurrency_mode
conflict_key_template
idempotency: pure | idempotent | keyed | non_idempotent
recovery: retry | reconcile | compensate | never_retry
executor: builtin | sandbox | extension:<id> | provider
```

The schema digest is included in the context manifest and effect intent.

### 10.2 Policy decision

The policy engine receives a typed request, not an arbitrary shell string alone:

```text
principal + channel binding
task/run/agent role and risk
tool descriptor and normalized arguments
target capability and resource claims
workspace roots and sandbox profile
secret references and network destinations
current policy bundle version
```

It returns `deny`, `allow`, or `require_approval`, plus obligations such as a narrower sandbox, argument rewrite, redaction, maximum duration, or validator requirement.

Policy rules are deterministic data interpreted by first-party code in v1. A policy language may be added later, but it must not make authorization depend on an LLM.

### 10.3 Approval binding

The approval subject hash covers:

```text
effect_id | tool_id@version | canonical_arguments_digest
capability_scope | target_resources | policy_version | expiry
```

Approval replies are authenticated commands. They never arrive as untrusted conversational text. Channels may render native buttons, but those buttons call the same approval API.

### 10.4 Executor protocol

The daemon launches a worker with a one-use capability token and a descriptor containing:

- effect and attempt IDs;
- fencing token;
- executable/tool identity digest;
- sandbox profile and mounted roots;
- resource/time/output limits;
- scoped secret handles;
- idempotency key;
- normalized arguments.

The worker emits structured start, progress, and terminal frames. Loss of the worker after dispatch is interpreted according to the tool recovery descriptor, not assumed failure.

### 10.5 Platform sandbox adapters

- Linux: prefer namespaces/bubblewrap or an equivalent backend with explicit filesystem and network policy.
- macOS: use Seatbelt or a container/VM adapter with documented limits.
- Windows: use restricted tokens/AppContainer/job objects or an external VM/container backend; unsupported filesystem carve-outs fail closed.

The architecture exposes capability semantics, not one platform's flags. `doctor` reports which profiles the current host can enforce.

## 11. Context and memory

### 11.1 Context compiler

The compiler is a deterministic pipeline:

```text
candidate discovery
→ authorization and namespace filtering
→ sensitivity/provider-residency filtering
→ relevance and recency scoring
→ typed mandatory-item insertion
→ budget allocation
→ compaction/truncation transforms
→ ordered context manifest
→ provider message projection
```

Mandatory typed items include active goal, unresolved constraints, current effect/approval state, latest user input, agent profile, and policy obligations. These are not left to semantic retrieval.

### 11.2 Context epochs

A session context epoch pins the baseline instructions, agent profile, workspace identity, and relevant configuration digest. Changes reconcile into a new epoch at a turn boundary. An in-flight request never observes half of a configuration change, following the context-snapshot lesson from OpenCode and prompt-stability lesson from Hermes.

### 11.3 Compaction

Compaction creates:

- a structured carry-forward record for decisions, constraints, unresolved work, effect outcomes, and citations;
- a human-readable summary;
- a source event range and content digests;
- prompt/model/config provenance;
- a quality/validation result when required.

The original history remains available. Subsequent contexts cite the compaction artifact and can expand selected source evidence.

### 11.4 Memory model

Memory is not the transcript. A memory proposal is extracted from cited source items, filtered by policy, and promoted to active state by configured rules. Versioned correction supersedes rather than silently edits history.

V1 uses SQLite structured filters and FTS5. Embeddings are an optional adapter added only after lexical/provenance behavior is correct. This keeps degraded mode useful and avoids making a vector index authoritative.

## 12. Providers

Provider ports describe capabilities rather than forcing all vendors into the lowest common denominator. The common contract covers model listing, normalized request/response, streaming, tool calling, structured output, usage, cancellation, and error classification. Namespaced capability metadata preserves vendor features without infecting the core.

Routing is a policy decision with an explanation. Fallback creates a new attempt and re-runs context residency checks. A local-to-remote fallback is never implicit.

The provider broker owns credentials, rate limits, concurrency, and cost reservations. Agent workers and extension hosts receive no ambient provider API keys.

## 13. Extension architecture

### 13.1 Manifest plane

Discovery reads a data-only manifest containing identity, digest/signature, compatibility, capability contracts, schemas, requested permissions, network destinations, secret references, migrations, and health behavior. Configuration UIs and policy review can operate without importing extension code.

### 13.2 Runtime plane

Third-party extensions execute in a supervised process. The daemon speaks a versioned framed RPC protocol over local IPC. The host:

- grants only manifest-approved capabilities;
- sends opaque secret handles or brokered requests, not the full environment;
- validates every request and response schema;
- applies time, memory, output, and restart limits;
- attributes all actions to the extension identity;
- can revoke or kill the extension without stopping the daemon.

An extension cannot open arbitrary daemon HTTP routes. It may register a channel endpoint descriptor that the trusted API layer serves after applying route authentication and bounds.

### 13.3 Extension types

- provider adapter;
- channel adapter;
- tool service;
- memory source;
- artifact renderer;
- notification sink.

Skills remain declarative resources. If a skill ships code, that code is a declared extension/tool and gets a separate permission review.

## 14. API and channel model

### 14.1 Initial transport

The first daemon exposes versioned HTTP/JSON plus server-sent events on loopback. It uses a randomly generated local bearer credential stored with OS-user-only permissions, strict Origin handling for browser access, bounded bodies, and no unauthenticated mode. Unix socket or named-pipe transport can be added without changing protocol DTOs.

Remote listening is disabled by default and is not a release-one requirement.

### 14.2 Command/query split

- Commands mutate state and return the committed revision/event cursor.
- Queries read authorized current state.
- Timeline streams resume after a journal cursor and emit a gap/error if retention prevents continuity.

Key command groups:

```text
sessions.create, sessions.submit, sessions.steer
tasks.pause, tasks.resume, tasks.cancel
approvals.resolve
effects.reconcile
memory.propose, memory.accept, memory.correct, memory.delete
admin.reload, admin.backup, admin.recover
```

DTOs carry an API version and idempotency key where applicable. Generated OpenAPI is an artifact checked in CI, not the source of domain truth.

### 14.3 Presentation events

The API projects durable journal facts into stable user-facing events. High-frequency provider deltas may be delivered live but are marked ephemeral. A final message, tool result summary, error, approval, and lifecycle transition always has a durable cursor.

## 15. Validation and evaluations

Validation is a policy-driven run, not an unconditional extra model call.

- Low risk: deterministic checks may be sufficient.
- Medium risk: a fresh read-only validator run is required unless policy records a waiver.
- High risk: deterministic evidence plus independent review is required before success; effect authorization remains a separate policy concern.

Validator context is assembled independently from the request, criteria, final artifacts, tool evidence, and timeline facts. It excludes producer scratch context and does not inherit write capabilities.

Scenario evaluation uses the public API with a fake provider and real SQLite/process boundaries. LLM-as-judge scores may be tracked, but deterministic gates decide CI unless a rubric explicitly requires a judge.

## 16. Operations

### 16.1 Daemon lifecycle

```text
bootstrap logging
→ load config and secret references
→ open/backup-check/migrate SQLite
→ verify artifact store
→ run recovery
→ start extension/provider health
→ bind API
→ ready
```

Shutdown stops admission, drains within a deadline, revokes worker leases, records interrupted work, flushes outbox state, checkpoints SQLite, and exits. A second signal forces worker termination and records the forced path on next recovery.

### 16.2 Health

- Liveness: process event loop and database connection respond.
- Readiness: migrations and recovery complete; API can admit work.
- Degraded: optional provider, extension, index, or channel unavailable while core remains safe.

### 16.3 Backup and migration

Backup uses SQLite's online backup API or a safe checkpointed copy and includes an artifact manifest. Restore is verified into a separate directory before replacement. A corrupt database is moved with WAL/SHM sidecars to a timestamped forensic backup before any fresh start.

Every migration has forward tests from supported historical snapshots. Destructive canonical-data changes require an explicit export/transform/import plan and cannot hide behind a schema migration.

## 17. Repository layout

```text
project_mealy/
├── apps/
│   ├── mealyd/                 daemon composition root
│   └── mealyctl/               local admin/client CLI
├── crates/
│   ├── mealy-domain/           pure domain state machines
│   ├── mealy-application/      use cases and ports
│   ├── mealy-infrastructure/   SQLite, OS, provider, process adapters
│   ├── mealy-protocol/         versioned transport DTOs
│   ├── mealy-api/              authenticated HTTP/SSE adapter
│   └── mealy-testkit/          deterministic test support
├── docs/
│   ├── decisions/              accepted ADRs
│   └── research/               reference evidence and gap matrix
├── schemas/                    reviewed protocol/manifest schema fixtures
├── tests/
│   ├── integration/            cross-crate adapter tests
│   └── scenarios/              public-API recovery and security scenarios
├── ARCHITECTURE.md
└── REQUIREMENTS.md
```

Each directory has a README that states ownership, allowed dependencies, and completion criteria. Empty future-feature directories are not created merely to advertise ambition.

## 18. Requirement-to-component traceability

| Requirements | Primary owner | Key evidence |
|---|---|---|
| DUR-001..002, TASK-010..017, CHAN-013 | application sessions/tasks + SQLite adapter | inbox, atomic transition, and lifecycle scenario tests |
| AUTH-001, AUTH-010..013, CHAN-010..012, API-001 | identity/policy + API/channel adapters | authorization, revocation, shared-timeline, and outbox tests |
| SCHED-010..015 | application scheduler + infrastructure lease store | stale-fence and queue-backpressure tests |
| AGENT-010..016, PROV-010..014 | agent module + provider broker | fake-provider loop and fallback scenarios |
| TOOL-010..018 | tool/effect module + executor | effect crash matrix and approval-binding tests |
| SEC-001..017, AUTH-010..013 | policy/identity + API + sandbox adapter | threat-model and boundary tests |
| CTX-001, CTX-010..015 | context module | manifest snapshot and compaction provenance tests |
| MEM-001, MEM-010..015 | memory module + FTS adapter | lifecycle, namespace, deletion tests |
| EXT-001, EXT-010..016 | extension manifest/host adapters | hostile extension and crash isolation tests |
| REC-001..017 | store + recovery + artifacts | crash-point scenario suite and backup restore tests |
| OBS-010..013, ART-010..011 | journal/outbox/artifacts/API | cursor resume, gap, atomic artifact tests |
| VAL-010..016 | validation + testkit | independent-context and rubric scenarios |
| CFG-010..012, DATA-010..013 | daemon config/admin | migration, backup, export, rollback tests |
| OPS-001, NFR-REL-001..004, NFR-PERF-001..004 | scheduler + recovery + API + bounded adapters | recovery scale, latency, cursor, crash, and resource tests |
| NFR-PORT-001..002, NFR-OPS-001..002 | composition root + platform adapters + admin CLI | cross-platform CI, doctor, safe-mode, drain, and restore tests |
| NFR-QUAL-001..004 | all components + testkit | unit, property, integration, scenario, and security suites |

The full verification matrix is maintained in [`docs/TESTING.md`](docs/TESTING.md).

## 19. Rejected alternatives

### Pure event sourcing

Rejected for the initial system. It makes every historical event version executable migration input forever and complicates operational queries. Mealy retains an immutable transition journal without requiring it to reconstruct all canonical tables.

### JSONL transcripts as runtime state

Rejected as the authority for scheduling, approvals, and effects. JSONL is excellent for portable export and branching conversation history, as Codex and Pi show, but cross-object atomic transitions and indexed recovery belong in SQLite.

### Hosted workflow engine

Rejected as a core dependency. Eve demonstrates the value of durable steps, but Mealy's self-contained constraint requires local leases and checkpoints. A hosted scheduler could later be an adapter only if semantics remain unchanged.

### In-process third-party plugins

Rejected. OpenClaw, Hermes, OpenCode, and Pi all treat loaded extensions as fully trusted code. That is acceptable for explicit first-party/full-trust use, not as Mealy's default plugin promise.

### One crate per feature

Rejected initially. Strong module boundaries and dependency tests are cheaper than dozens of crates. Split a module only when it needs a different process, compatibility contract, compile profile, or ownership cadence.

### Automatic retry of every interrupted step

Rejected. A process crash does not prove an external call failed. Recovery depends on the tool's idempotency and reconciliation contract.

## 20. Known risks and deliberate constraints

- Cross-platform sandbox parity is difficult. Capability profiles must fail closed rather than imply false equivalence.
- SQLite is a single-node choice. It is correct for the product scope and intentionally defers distributed execution.
- Durable model-response recording can contain sensitive data. Retention, encryption adapters, and redaction need early implementation.
- Out-of-process extensions add RPC and packaging work. That cost buys a boundary the references consistently lack.
- Independent validation adds latency and cost. Risk policy and deterministic evidence keep it proportional.
- Local browser UI authentication requires careful Origin and token handling. It is scheduled after CLI-based proof of the core.

## 21. Implementation rule

The first vertical slice in `REQUIREMENTS.md` is the architecture proof. Features that bypass its durable inbox, lease fencing, effect state machine, context manifest, or recovery path are not acceptable shortcuts; they would prove a different system.
