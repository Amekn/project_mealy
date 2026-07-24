# Mealy Software Requirements

- Version: 0.2.0
- Status: release-one requirements implemented; pre-1.0 production evidence in progress
- Normative terms: **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as defined by RFC 2119.

## 1. Product statement

Mealy is a local-first, self-contained agent runtime for a reliable personal AI assistant. A long-lived daemon owns conversations, tasks, agent execution, context, memory, policy, approvals, tools, artifacts, and recovery. TUI, CLI, web, Discord, and future integrations are authenticated clients of that runtime; none is a second agent runtime or an alternate source of truth.

Mealy may use local or remote model providers and external services, but it MUST NOT require another agent product such as Codex, Claude Code, OpenClaw, Hermes, OpenCode, Pi, or Eve to implement its core behavior.

The first release targets one owner on one machine. Identity, authorization, and namespace boundaries are nevertheless first-class from the beginning so that adding more principals later does not require replacing the data model.

## 2. Evidence and the gap Mealy addresses

The architecture research in [`docs/research/REFERENCE_SYSTEMS.md`](docs/research/REFERENCE_SYSTEMS.md) found excellent individual patterns but no reference system that combines all of the following:

- deterministic, durable per-session input queues owned by the runtime;
- explicit recovery semantics for unknown external side effects;
- OS-enforced isolation as a default boundary rather than an optional warning;
- out-of-process third-party extensions with least-privilege capability grants;
- identity authorization that does not mistake a session identifier or shared gateway secret for a principal boundary;
- inspectable, reproducible context manifests and governed memory;
- risk-based independent validation linked to durable evidence;
- a local daemon that owns these guarantees without depending on a hosted workflow engine.

Mealy exists to close that integration gap. It is not intended to win by accumulating the most tools or channels.

## 3. Scope

### 3.1 In scope

- A supervised local daemon and local administrative client.
- Durable sessions, tasks, turns, runs, attempts, tool calls, approvals, effects, artifacts, validation, and timelines.
- One or more Mealy-native agents with explicit roles and capability scopes.
- Local and remote model providers behind a common interface.
- Sandboxed command and file tools, service tools, skills, channel adapters, and extension hosts.
- Deterministic recovery after process termination or machine reboot.
- Context compilation, compaction, and governed long-term memory.
- Versioned APIs, schemas, migrations, backup, export, and operational diagnostics.
- Evaluation and scenario infrastructure that tests behavior through the same public boundary used by clients.

### 3.2 Deferred, not precluded

- Adversarial multi-tenant hosting.
- Distributed scheduling across multiple Mealy daemon nodes.
- A public internet-facing control plane.
- A general marketplace for unreviewed native extensions.
- Mobile-native clients.

### 3.3 Non-goals

- Perfect containment of arbitrary native code running with the owner's OS account.
- Bit-for-bit reproduction of nondeterministic model output.
- Pretending an external side effect is exactly-once when the target service provides no idempotency or reconciliation mechanism.
- Treating prompts, allowlists, command classifiers, or approval dialogs as substitutes for OS isolation.
- Storing private model reasoning. Mealy records user-visible reasoning summaries, decisions, inputs, outputs, and evidence instead.

## 4. Terms

- **Principal**: an authenticated user, service, or runtime identity.
- **Channel binding**: the verified mapping from a channel identity to a Mealy principal.
- **Session**: an ordered conversation boundary and durable input inbox.
- **Task**: a user-visible unit of work with success criteria and a lifecycle.
- **Turn**: one admitted input and the agent work it triggers.
- **Run**: one agent's execution for a task or delegated subtask.
- **Attempt**: a bounded execution attempt within a run, such as one model call or tool dispatch.
- **Effect**: an operation that may change state outside Mealy.
- **Artifact**: immutable content referenced by digest, such as a patch, log, screenshot, or report.
- **Context manifest**: the exact ordered description of material supplied to a model call, including reasons and content digests.
- **Memory**: governed information intended for use beyond the current turn.
- **Skill**: instructions and resources loaded on demand; it is not executable authority by itself.
- **Extension**: a versioned component that adds a channel, provider, tool, memory source, or other capability.

## 5. Product invariants

These rules apply to every implementation phase.

1. **DUR-001 — Durable admission.** Mealy MUST durably store an accepted input before acknowledging it to a channel.
2. **DUR-002 — Single transition authority.** Task and run state transitions MUST occur through the application layer and MUST be committed atomically with their audit event and any outbound notification.
3. **SEC-001 — Untrusted model.** Model output and retrieved external content MUST be treated as untrusted input, never as an authenticated principal or policy decision.
4. **SEC-002 — Mediated effects.** Agents MUST NOT invoke the OS, network, credentials, memory writer, or external services except through a typed capability mediated by policy.
5. **SEC-003 — Real boundary.** Claims of isolation MUST be backed by an OS process, sandbox, VM, container, or equivalent enforcement mechanism.
6. **AUTH-001 — Identity before routing.** Session IDs, continuation tokens, and shared channel secrets MUST NOT be treated as user authorization boundaries.
7. **REC-001 — Honest recovery.** An effect with an unknown outcome MUST NOT be automatically repeated unless its idempotency is proven.
8. **CTX-001 — Inspectable context.** Every model call MUST have a persisted context manifest sufficient to explain what was included and why.
9. **MEM-001 — Governed memory.** A model MUST NOT silently turn conversation content into trusted long-term memory.
10. **EXT-001 — Least privilege.** Third-party extension authority MUST be explicit, reviewable, revocable, and narrower than the daemon's authority.
11. **API-001 — One semantic API.** Every channel MUST use the same command, query, authorization, policy, and timeline semantics.
12. **OPS-001 — Bounded work.** Queues, concurrency, retries, output, context, time, and spend MUST have enforceable limits.

## 6. Functional requirements

### 6.1 Identity and channels

- **AUTH-010:** Every inbound request MUST be associated with a verified principal and channel binding before it can read or mutate a session.
- **AUTH-011:** Channel adapters MUST verify platform signatures or local OS credentials and MUST NOT trust a body-supplied user identifier.
- **AUTH-012:** Authorization MUST be checked for every command and query; possession of a resource ID alone MUST grant nothing.
- **AUTH-013:** The owner MUST be able to revoke a device, channel binding, token, or extension grant without deleting historical records.
- **CHAN-010:** Channels MUST remain thin adapters. They MAY format messages and hold transport-specific cursors, but MUST NOT own agent state, policy, approvals, or task queues.
- **CHAN-011:** Channel delivery MUST use a durable outbox with retry and deduplication metadata.
- **CHAN-012:** The same task timeline and approval state MUST be observable from every authorized channel, subject to presentation limits.
- **CHAN-013:** A channel that receives a burst while a session is busy MUST be able to enqueue every accepted input durably without an in-memory-only side queue.

### 6.2 Sessions, tasks, and lifecycle

- **TASK-010:** Session, task, turn, run, attempt, tool call, approval, effect, validation, and artifact MUST have distinct stable IDs.
- **TASK-011:** Task states MUST include at least `queued`, `running`, `waiting`, `paused`, `succeeded`, `failed`, and `cancelled`; terminal states MUST be explicit.
- **TASK-012:** The user MUST be able to steer, enqueue, pause, resume, interrupt, and cancel work. Each action MUST have a documented ordering rule.
- **TASK-013:** Inputs within one session MUST have a durable monotonic sequence. The runtime MUST support `queue`, `steer-at-boundary`, and `interrupt-then-queue` delivery semantics without losing accepted input.
- **TASK-014:** At most one turn may mutate a session's canonical conversation history at a time. Independent sessions MAY run concurrently.
- **TASK-015:** Parent/child run lineage, delegated input, capability inheritance, and terminal outcome MUST be durable.
- **TASK-016:** Delegation MUST pass a bounded, explicit context package. Child agents MUST NOT inherit the parent's full history, credentials, workspace, or permissions implicitly.
- **TASK-017:** Cancellation MUST be cooperative first and forceful after a configured grace period. The resulting partial or unknown state MUST be recorded.

### 6.3 Scheduler and concurrency

- **SCHED-010:** Runnable work MUST be claimed using a durable lease with expiry, heartbeat, and a fencing token.
- **SCHED-011:** A stale worker MUST be unable to commit results after its lease is superseded.
- **SCHED-012:** Concurrency limits MUST be configurable by daemon, principal, session, provider, extension, agent role, and resource class.
- **SCHED-013:** Resource ownership MUST cover at least workspace write scopes, service mutation scopes, memory namespaces, and exclusive devices.
- **SCHED-014:** Backpressure MUST reject or defer excess work predictably; unbounded in-memory queues are forbidden.
- **SCHED-015:** Retries MUST use classified errors, bounded attempts, exponential backoff with jitter, and a persisted next-attempt time.

### 6.4 Agent execution

- **AGENT-010:** Mealy MUST own an explicit agent loop: compile context, call a model, validate structured output, propose tools or a response, execute authorized tools, observe results, and decide the next step.
- **AGENT-011:** Each loop step MUST have configurable limits for model calls, tool calls, tokens, cost, wall time, retries, output bytes, and delegated runs.
- **AGENT-012:** Provider streams MAY be transient, but complete model request metadata, the final normalized response, usage, and error MUST be recorded at a durable boundary before dependent effects begin.
- **AGENT-013:** Provider-specific message and tool formats MUST be normalized at the adapter boundary. Provider fields MUST NOT leak into domain state except in namespaced metadata.
- **AGENT-014:** Structured outputs and tool arguments MUST be schema-validated. Repair attempts MUST be bounded and visible.
- **AGENT-015:** Parallel tool execution MUST be opt-in per tool batch and MUST respect declared conflict keys. Results MUST be presented to the model in deterministic call order.
- **AGENT-016:** Agent profiles MUST declare model policy, instructions, tools, budgets, memory access, workspace access, validation policy, and delegation policy.

### 6.5 Tools, effects, and approvals

- **TOOL-010:** A tool contract MUST declare input and output schemas, effect class, risk class, required capabilities, timeout, output limits, conflict keys, idempotency behavior, and recovery strategy.
- **TOOL-011:** Read-only, reversible, idempotent, and non-idempotent operations MUST be distinguishable in policy and recovery.
- **TOOL-012:** For every effect, Mealy MUST persist the intent and authorization before dispatch and persist one of `succeeded`, `failed`, or `outcome_unknown` afterward.
- **TOOL-013:** When a downstream service supports idempotency keys, Mealy MUST derive a stable key from the effect ID and reuse it across retries.
- **TOOL-014:** `outcome_unknown` for a non-idempotent effect MUST pause for reconciliation or explicit owner direction; it MUST NOT be silently retried.
- **TOOL-015:** Approval requests MUST bind the principal, task, effect ID, exact normalized arguments or digest, policy version, expiry, and requested capability.
- **TOOL-016:** Changing tool arguments, capability scope, executable identity, or policy version after approval MUST invalidate or re-evaluate the approval.
- **TOOL-017:** Approval is a decision, not containment. Approved execution MUST still run within the granted OS and network boundary.
- **TOOL-018:** Tool output MUST be size-limited, sanitized for display, stored as an artifact when large, and referenced by digest.

### 6.6 Policy, sandboxing, and secrets

- **SEC-010:** Policy MUST default deny and evaluate principal, channel, agent, task risk, tool, normalized arguments, target resource, workspace, time, and requested capability.
- **SEC-011:** The first release MUST provide at least `observe`, `workspace-write`, `networked`, `service-operator`, and `full-trust` policy profiles.
- **SEC-012:** Shell and filesystem mutation MUST execute outside the daemon process in an enforceable sandbox or a clearly marked full-trust mode.
- **SEC-013:** Sandbox policy MUST independently control readable paths, writable paths, executable/process access, environment, network destinations, and resource limits where the host OS permits.
- **SEC-014:** A platform incapable of enforcing a requested profile MUST fail closed or require an explicit, recorded downgrade approval.
- **SEC-015:** Secrets MUST be referenced by opaque IDs, resolved only inside a trusted broker, scoped to a capability, and redacted from prompts, events, logs, and artifacts by default.
- **SEC-016:** Credentials supplied to a tool MUST be limited to that invocation and MUST NOT be inherited by arbitrary child processes.
- **SEC-017:** Security-sensitive decisions MUST record the policy bundle version and an explanation suitable for owner inspection.

### 6.7 Context and compaction

- **CTX-010:** A context manifest MUST record ordered item IDs, source type, source locator, content digest, inclusion reason, sensitivity, token estimate, transformation, and policy decision.
- **CTX-011:** Context compilation MUST enforce namespace, authorization, sensitivity, freshness, relevance, budget, and provider residency constraints.
- **CTX-012:** The system prompt baseline for a turn MUST be versioned. Runtime changes MUST create a new context epoch rather than mutating an in-flight request.
- **CTX-013:** Compaction MUST produce a derived artifact linked to its source event range and prompt/config version. It MUST NOT delete the canonical source history.
- **CTX-014:** Safety constraints, unresolved approvals, current goals, and effect outcomes MUST be preserved across compaction by typed extraction, not summary prose alone.
- **CTX-015:** The owner MUST be able to inspect included, excluded, compacted, and redacted context without exposing secrets they are not authorized to view.

### 6.8 Memory

- **MEM-010:** Memory states MUST include at least `proposed`, `active`, `superseded`, `expired`, `rejected`, and `deleted`.
- **MEM-011:** Every memory MUST carry provenance, principal and workspace namespace, confidence, sensitivity, retention, creation time, last verification time, and source digests.
- **MEM-012:** Memory promotion MUST be policy-driven. Sensitive identity, credential, health, financial, or private third-party information MUST require explicit owner policy or approval.
- **MEM-013:** Retrieval MUST combine deterministic filters with lexical search initially; semantic retrieval MAY be added behind the same interface.
- **MEM-014:** Retrieved memory MUST be treated as untrusted evidence and MUST retain citations in the context manifest.
- **MEM-015:** The owner MUST be able to inspect, correct, pin, export, expire, and delete memories and rebuild derived indexes.

### 6.9 Providers

- **PROV-010:** Model adapters MUST implement a versioned capability contract covering input modalities, tool calling, structured output, reasoning controls, streaming, context limits, pricing, residency, and retry hints.
- **PROV-011:** Routing MUST support model capability, privacy, locality, availability, cost, latency, and user policy.
- **PROV-012:** Fallback MUST be explicit and MUST NOT move private data to a less trusted provider or silently change tool semantics.
- **PROV-013:** Provider requests MUST have timeouts, cancellation, rate limiting, concurrency limits, normalized errors, and usage accounting.
- **PROV-014:** Provider credentials MUST be isolated from agent context and from extensions that do not own the provider call.

### 6.10 Skills and extensions

- **EXT-010:** A skill MUST consist of versioned instructions and resources. Executable helpers MUST be declared as tools or extension capabilities and evaluated separately.
- **EXT-011:** Every extension MUST have a signed or digest-pinned manifest declaring identity, version, compatibility, entry points, schemas, capabilities, permissions, network targets, secrets, health checks, migrations, and shutdown behavior.
- **EXT-012:** Manifest inspection and configuration validation MUST NOT execute extension code.
- **EXT-013:** Third-party extensions MUST run out of process by default using a versioned RPC contract. In-process loading MUST be limited to compiled first-party components or explicit full-trust mode.
- **EXT-014:** Extension failure MUST be isolated to its capabilities where possible and MUST NOT corrupt daemon state.
- **EXT-015:** Extension upgrades MUST support compatibility checks, rollback, and state migration without widening permissions silently.
- **EXT-016:** MCP MAY be an adapter protocol for tools and resources, but MCP server trust and capability grants MUST still pass through Mealy policy.

### 6.11 Persistence, recovery, and replay

- **REC-010:** SQLite-backed canonical state, the transition journal, and the delivery outbox MUST be committed in one transaction for each state change.
- **REC-011:** Large immutable content MUST be stored outside SQLite in a content-addressed artifact store and referenced by digest.
- **REC-012:** Startup recovery MUST find expired leases, incomplete attempts, pending outbox messages, and unknown effects before normal scheduling begins.
- **REC-013:** Recovery MUST classify each incomplete operation as safe to resume, safe to retry, requires compensation, requires reconciliation, or terminally failed.
- **REC-014:** Corrupt storage recovery MUST preserve the original database and sidecars for forensics before attempting rebuild or restore.
- **REC-015:** Migrations MUST be transactional where SQLite allows, backup-aware, forward tested, downgrade documented, and incapable of silently deleting canonical history.
- **REC-016:** Debug replay MUST use recorded model and tool results by default and MUST NOT execute effects. It is a deterministic simulation of recorded inputs, not a promise to regenerate model output.
- **REC-017:** A live re-execution mode MAY exist, but it MUST create a new task lineage and require normal policy and approval.

### 6.12 Timeline, artifacts, and observability

- **OBS-010:** The durable timeline MUST include accepted inputs, lifecycle transitions, context compilation, model attempts, tool/effect states, approvals, artifacts, validation, recovery, and final outcome.
- **OBS-011:** High-volume token deltas and progress frames MAY be ephemeral or compacted, but their terminal summary and artifact references MUST be durable.
- **OBS-012:** Logs, metrics, traces, and events MUST share task, run, attempt, causation, and correlation IDs.
- **OBS-013:** The owner MUST be able to inspect active leases, queue depth, pending approvals, unknown effects, provider and extension health, storage usage, migration status, and recent failures.
- **ART-010:** Artifacts MUST include media type, digest, size, origin, producer, sensitivity, retention, and access policy.
- **ART-011:** Artifact writes MUST be atomic; a database reference MUST never point to an uncommitted partial file.

### 6.13 Validation and evaluations

- **VAL-010:** Every task MUST have explicit success criteria or a recorded reason why no objective criterion applies.
- **VAL-011:** Deterministic checks such as tests, schema validation, file hashes, and service reads MUST be preferred over model judgment.
- **VAL-012:** Medium- and high-risk tasks MUST receive an independent validation run with a fresh context manifest and a task-specific rubric before success is reported.
- **VAL-013:** The validator MUST receive the request, criteria, relevant outputs, artifacts, and evidence, but MUST NOT inherit the producer's hidden working context or permissions.
- **VAL-014:** A validator MUST NOT gain broader effect permissions than the producer and SHOULD normally be read-only.
- **VAL-015:** Validation outcomes MUST be `passed`, `needs_revision`, `failed`, `inconclusive`, or `waived`, with evidence and responsible principal.
- **VAL-016:** Scenario evaluations MUST drive Mealy through its public API and MUST be runnable locally and in CI with deterministic fake providers.

### 6.14 Configuration, backup, and retention

- **CFG-010:** Configuration MUST be schema-versioned, validated before activation, and split between non-secret values and secret references.
- **CFG-011:** Effective configuration and policy bundle digests MUST be recorded at daemon start and on reload, excluding secret values.
- **CFG-012:** High-risk configuration changes MUST require approval and provide rollback.
- **DATA-010:** Retention MUST be configurable by data class, sensitivity, principal, task, channel, and legal/audit need.
- **DATA-011:** Backup MUST cover canonical state, journal, artifacts, configuration, extension manifests, and memory; secret backup MUST be opt-in and encrypted.
- **DATA-012:** Export MUST support a complete archive and scoped task, audit, artifact, and memory bundles.
- **DATA-013:** Deletion MUST distinguish user-visible tombstoning from physical erasure and document what backups or audit constraints retain.

## 7. Non-functional requirements

### 7.1 Reliability targets

- **NFR-REL-001:** After an unclean shutdown, Mealy MUST reach a recovered, queryable state without manual database editing in the ordinary case.
- **NFR-REL-002:** With 10,000 non-terminal work items and no corrupt storage, startup recovery classification SHOULD complete within 30 seconds on a contemporary desktop SSD.
- **NFR-REL-003:** The daemon MUST survive a channel, provider, extension-host, or sandbox-worker crash without losing already acknowledged input.
- **NFR-REL-004:** Every retry and timeout path MUST have a terminal bound.

### 7.2 Performance and resource targets

- **NFR-PERF-001:** A local accepted-input transaction SHOULD acknowledge within 100 ms at p95 when SQLite is healthy and no migration is running.
- **NFR-PERF-002:** Timeline subscribers MUST be resumable from a durable cursor and MUST detect gaps.
- **NFR-PERF-003:** The idle daemon SHOULD use less than 250 MiB resident memory before optional local models, browser workers, or extension hosts are started.
- **NFR-PERF-004:** No model response, tool output, or channel frame may allocate unbounded memory; every boundary MUST enforce byte and item limits.

### 7.3 Portability and operability

- **NFR-PORT-001:** The production control plane MUST support Linux on Ubuntu, Debian, Fedora, Arch, and compatible derivatives under the checked compatibility contract. Unsupported operating systems and unenforceable profiles MUST fail closed. macOS and Windows are outside the active production support and CI contract.
- **NFR-PORT-002:** Core operation MUST not require Docker, Kubernetes, a cloud account, or an external workflow service.
- **NFR-OPS-001:** A clean installation MUST provide `doctor`, `status`, backup, restore verification, and safe-mode startup commands.
- **NFR-OPS-002:** The daemon MUST support graceful drain with a bounded deadline and forced termination reporting.

### 7.4 Quality gates

- **NFR-QUAL-001:** Domain state machines, policy evaluation, recovery classification, effect semantics, and migrations MUST have unit and property tests.
- **NFR-QUAL-002:** Integration tests MUST use real SQLite transactions and process boundaries.
- **NFR-QUAL-003:** Scenario tests MUST cover restart during model call, restart before and after effect dispatch, approval expiry, stale lease fencing, duplicate channel delivery, queue bursts, provider fallback, extension crash, and storage migration.
- **NFR-QUAL-004:** Security tests MUST prove that channels cannot bypass authorization, stale workers cannot commit, arguments cannot change after approval, secrets do not enter prompts, and unsupported sandbox profiles fail closed.

## 8. Release-one acceptance boundary

The first usable vertical slice is complete only when it demonstrates all of the following through the public API:

1. A verified local principal creates a session and submits a message.
2. The message is committed to the durable inbox before acknowledgement.
3. A leased run compiles and persists an inspectable context manifest.
4. A fake or real provider produces a normalized response containing one read-only tool call.
5. Policy authorizes the tool, an isolated executor runs it, and the result is stored as an artifact when oversized.
6. A second effectful tool creates a bound approval request and parks durably.
7. Restarting the daemon preserves the task, queue, approval, timeline cursor, and context evidence.
8. Approval resumes the task without repeating completed work.
9. A deterministic validator checks the result and records evidence.
10. The final response is delivered through the durable outbox.
11. A debug replay reconstructs the recorded timeline without calling the provider or executing tools.

Plugins, vector memory, Discord, and a web UI are deliberately outside this first slice. Their contracts are designed now; their implementations follow after the durable execution core is proven.

## 9. Traceability

[`ARCHITECTURE.md`](ARCHITECTURE.md) maps these requirement IDs to components and runtime flows. Architecture decisions live under [`docs/decisions/`](docs/decisions/), and the implementation sequence lives in [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md).
