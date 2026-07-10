# Reference Agentic Systems

- Status: completed architecture review
- Reviewed: 2026-06-22
- Local clone root: `../mealy-agentic-references/`

## Method

All eight repositories from the GitHub **Agentic Systems** list were shallow-cloned, left unmodified, and pinned to the commits below. The review used repository documentation, security policies, manifests, state schemas, runtime code, and tests. Marketing claims were not accepted when source behavior contradicted them.

For each system the review asked:

1. What process owns the agent loop and durable state?
2. What are the conversation, task, run, step, and tool primitives?
3. Where are queues and recovery state stored?
4. What happens if the process dies before, during, or after a side effect?
5. What is an actual security boundary, and what is only a user guardrail?
6. How are providers, tools, channels, plugins, context, memory, and subagents separated?
7. How are protocols versioned and validated?
8. Which patterns have enough implementation and test evidence to reuse?

The analysis is architectural, not a feature score. A narrow library can provide a better boundary than a large product.

## Pin and license inventory

| System | Repository | Reviewed commit | Default branch | License/provenance |
|---|---|---|---|---|
| OpenClaw | `openclaw/openclaw` | `ebb670b2086356606eadd74c75cb98687774604d` | `main` | MIT |
| Hermes Agent | `NousResearch/hermes-agent` | `def3f6388f8a8a1c8e4e9ff415a4e6a9b8fdd626` | `main` | MIT |
| OpenCode | `anomalyco/opencode` | `823d327401ba93d24174c9feb50b5dbe4f60f646` | `dev` | MIT |
| Codex | `openai/codex` | `f774455c3a831dfab2c6f37a1f624b8097f6f2c2` | `main` | Apache-2.0 |
| Vercel AI SDK | `vercel/ai` | `8e990ff217fc15644adc6c891c10a8f5ee11376a` | `main` | Apache-2.0 |
| Eve | `vercel/eve` | `f68ecbe4b157723edfb8c3957418ba84f8a1d384` | `main` | Apache-2.0 |
| Pi | `earendil-works/pi` | `bc0db643502ba0bf1b227a97d9d5885cefc2b909` | `main` | MIT |
| Claude Code mirror | `yasasbanukaofficial/claude-code` | `a371abbe75ffa0d0a3c92290e2bbf56a7ef54367` | `main` | No license; third-party mirror claiming proprietary leaked source |

The Claude Code mirror is excluded from code reuse. It is used only as low-confidence observational evidence for general patterns also justified independently.

## 1. OpenClaw

### System shape

OpenClaw is a broad personal-assistant platform. One long-lived TypeScript Gateway owns messaging providers, a typed WebSocket control plane, nodes, web UI, sessions, cron, agents, tools, and plugins. Its agent loop serializes work per session and optionally through global lanes. Sessions use a store plus JSONL transcripts, while messaging and UI clients subscribe to live events.

### Strong patterns

- **One gateway, many thin surfaces.** WhatsApp, Telegram, Slack, Discord, native apps, CLI, nodes, and WebChat share one control plane.
- **Typed handshake and discovery.** Frames are schema-validated, the first frame must initialize/connect, and methods/events are discoverable.
- **Explicit device pairing.** Device identity, challenge signing, tokens, and non-local pairing are materially stronger than trusting a session key.
- **Per-session serialization.** A session lane plus a file-aware transcript lock prevents concurrent conversation writers; global lanes cap total work.
- **Queue semantics are named.** `steer`, `followup`, `collect`, and `interrupt` make user intent clearer than one overloaded send operation.
- **Mature lifecycle hooks and capability registry.** Provider, channel, tool, message, session, compaction, and gateway hooks have a documented order.
- **Operational clarity.** Diagnostics distinguish long-running, stalled, and stale bookkeeping, and provide recovery paths for stuck lanes.

### Gaps and pitfalls

- The command queue is explicitly a **tiny in-process queue**. Accepted burst input is not a durable scheduler primitive.
- Gateway live events are explicitly **not replayed**; clients refresh after gaps.
- The security model treats authenticated gateway callers as trusted operators. Session identifiers are routing controls, not per-user authorization, and one gateway is not intended to isolate adversarial users.
- Sandbox mode defaults off and execution is host-first when no sandbox is active.
- Native plugins load in process, are unsandboxed, and join the trusted computing base. A plugin can crash or fully compromise the gateway.
- Short-lived request deduplication and transcript locks improve ordinary reliability, but they are not a durable effect-intent/outcome protocol.
- JSONL transcripts and session metadata are strong conversation persistence but not a canonical workflow/effect journal.

### Mealy decision

Adopt the single-daemon/channel model, device-aware authentication, typed protocol, per-session ordering, bounded lanes, and manifest-first extension discovery. Replace in-memory queues with a durable inbox, make event streams cursor-resumable, default to restricted execution, and move third-party extensions out of process.

### Evidence

- [`docs/concepts/architecture.md`](https://github.com/openclaw/openclaw/blob/ebb670b2086356606eadd74c75cb98687774604d/docs/concepts/architecture.md)
- [`docs/concepts/agent-loop.md`](https://github.com/openclaw/openclaw/blob/ebb670b2086356606eadd74c75cb98687774604d/docs/concepts/agent-loop.md)
- [`docs/concepts/queue.md`](https://github.com/openclaw/openclaw/blob/ebb670b2086356606eadd74c75cb98687774604d/docs/concepts/queue.md)
- [`docs/concepts/session.md`](https://github.com/openclaw/openclaw/blob/ebb670b2086356606eadd74c75cb98687774604d/docs/concepts/session.md)
- [`docs/plugins/architecture.md`](https://github.com/openclaw/openclaw/blob/ebb670b2086356606eadd74c75cb98687774604d/docs/plugins/architecture.md)
- [`SECURITY.md`](https://github.com/openclaw/openclaw/blob/ebb670b2086356606eadd74c75cb98687774604d/SECURITY.md)

## 2. Hermes Agent

### System shape

Hermes is a Python personal agent with CLI, TUI, ACP, batch, API, cron, and a multi-platform gateway. `AIAgent` and the conversation loop centralize provider resolution, tools, retries, compression, callbacks, and persistence. Session transcripts are canonical in SQLite with FTS5; a JSON file also preserves the active session-key mapping and lifecycle flags. Tools self-register into a central registry, and multiple terminal backends provide host, container, SSH, and cloud execution choices.

### Strong patterns

- **One agent core across entry points.** CLI, gateway, ACP, cron, and batch share provider and tool behavior.
- **Provider normalization.** A shared resolver maps many vendors into a small set of API modes while preserving provider-specific adapters.
- **Practical SQLite + FTS5.** Session storage is searchable and includes corruption repair for derived FTS structures.
- **Session lifecycle documentation.** Idle/daily expiry, soft resume, stuck-loop escalation, queued gateway messages, and shutdown drain behavior are explicit.
- **Multiple execution backends.** File tools route through the terminal backend, making isolation selectable without rewriting tool logic.
- **Honest security policy.** Hermes explicitly says OS-level isolation is the only boundary against an adversarial model; approvals, redaction, and pattern scanning are heuristics.
- **Profile isolation.** Separate homes, configuration, memory, sessions, and gateway processes provide an understandable operational boundary.

### Gaps and pitfalls

- Core behavior is concentrated in very large modules (`gateway/run.py`, `run_agent.py`, and the conversation loop), increasing change coupling and making invariants difficult to localize.
- SQLite is canonical for transcripts, while `sessions.json` remains necessary for active mappings and flags. This dual persistence increases reconciliation and recovery surface.
- Gateway queue structures include in-memory pending/overflow collections, even though transcript and metadata persistence are stronger.
- The default terminal backend runs on the host. Terminal-backend isolation does not contain in-process code execution, MCP processes, plugins, hooks, or skill imports.
- Plugins and skills execute in the agent interpreter with full process privileges.
- Authorized callers inside one adapter have equal trust; per-principal capability differences require separate instances.
- Cron state uses JSON and is a separate scheduling model rather than one durable task/effect model.

### Mealy decision

Adopt the shared provider/tool core, SQLite/FTS foundation, explicit profile/config isolation, corruption backup, and security vocabulary. Avoid giant orchestration modules, mirrored authorities, host-default execution, and in-process extension imports.

### Evidence

- [`website/docs/developer-guide/architecture.md`](https://github.com/NousResearch/hermes-agent/blob/def3f6388f8a8a1c8e4e9ff415a4e6a9b8fdd626/website/docs/developer-guide/architecture.md)
- [`docs/session-lifecycle.md`](https://github.com/NousResearch/hermes-agent/blob/def3f6388f8a8a1c8e4e9ff415a4e6a9b8fdd626/docs/session-lifecycle.md)
- [`agent/conversation_loop.py`](https://github.com/NousResearch/hermes-agent/blob/def3f6388f8a8a1c8e4e9ff415a4e6a9b8fdd626/agent/conversation_loop.py)
- [`hermes_state.py`](https://github.com/NousResearch/hermes-agent/blob/def3f6388f8a8a1c8e4e9ff415a4e6a9b8fdd626/hermes_state.py)
- [`SECURITY.md`](https://github.com/NousResearch/hermes-agent/blob/def3f6388f8a8a1c8e4e9ff415a4e6a9b8fdd626/SECURITY.md)

## 3. OpenCode

### System shape

OpenCode is a TypeScript/Bun coding-agent platform with a server, desktop/web clients, project instances, SQLite/Drizzle persistence, providers, tools, permissions, plugins, snapshots, and subagents. Its current `dev` branch is moving from legacy message/state paths toward durable per-session events, aggregate sequences, event-driven input promotion, context epochs, and atomic projectors.

### Strong patterns

- **Effect service boundaries.** Runtime services and layers make dependencies and lifecycles visible, including per-project instance state and finalizers.
- **Durable aggregate sequencing.** Events use contiguous per-aggregate sequence numbers, schema versions, replay divergence checks, and atomic projector commits.
- **Atomic event plus operational projection.** A durable event can commit local projection state within the same transaction.
- **Event-sourced session input.** Admitted input, delivery mode, and promotion sequence are modeled explicitly rather than inferred from UI messages.
- **Context epochs.** A baseline, snapshot, revision, location, and agent identity are fenced and reconciled, preventing silent mid-session prompt drift.
- **Structured session primitives.** Sessions track parent, project, workspace, model, cost, tokens, permissions, revisions, and snapshots.
- **Deterministic plugin ordering and lifecycle.** Plugin hooks initialize sequentially and receive disposal.

### Gaps and pitfalls

- The branch is in a dual-write migration: legacy session messages and new durable events are emitted together in several paths. That is evidence of transition risk, not a settled simple architecture.
- A June 2026 development migration deletes event/session input/message data before rebuilding structures. This may be acceptable before release, but it demonstrates how event-model changes can become canonical-data migrations.
- The global event bus is still an in-memory EventEmitter; durable and presentation event responsibilities are not yet uniformly separated.
- Run ownership is held in an in-memory map; cold process recovery treats incomplete histories differently from continuing a live runner.
- Plugins execute in process and receive a powerful client plus optional `Bun.$`.
- The security policy states there is no sandbox. Permissions are a UX guardrail; server mode may run unauthenticated if the user enables it without a password.
- The design is optimized for coding sessions and project snapshots, not arbitrary long-running service effects with reconciliation.

### Mealy decision

Adopt aggregate sequences, replay divergence checks, durable input promotion, expected revisions, context epochs, and atomic state+journal transactions. Do not require canonical state to be rebuilt from all history, do not ship a prolonged dual-write architecture, and do not conflate a permission UI with isolation.

### Evidence

- [`packages/core/src/event.ts`](https://github.com/anomalyco/opencode/blob/823d327401ba93d24174c9feb50b5dbe4f60f646/packages/core/src/event.ts)
- [`packages/core/src/session/input.ts`](https://github.com/anomalyco/opencode/blob/823d327401ba93d24174c9feb50b5dbe4f60f646/packages/core/src/session/input.ts)
- [`packages/core/src/session/context-epoch.ts`](https://github.com/anomalyco/opencode/blob/823d327401ba93d24174c9feb50b5dbe4f60f646/packages/core/src/session/context-epoch.ts)
- [`packages/opencode/src/session/processor.ts`](https://github.com/anomalyco/opencode/blob/823d327401ba93d24174c9feb50b5dbe4f60f646/packages/opencode/src/session/processor.ts)
- [`packages/opencode/src/plugin/index.ts`](https://github.com/anomalyco/opencode/blob/823d327401ba93d24174c9feb50b5dbe4f60f646/packages/opencode/src/plugin/index.ts)
- [`SECURITY.md`](https://github.com/anomalyco/opencode/blob/823d327401ba93d24174c9feb50b5dbe4f60f646/SECURITY.md)

## 4. Codex

### System shape

Codex is a large Rust coding-agent system. `codex-core` owns thread execution, model interaction, tools, approvals, sandbox selection, context, compaction, multi-agent control, and rollout recording. `codex app-server` exposes versioned thread/turn/item semantics over a bidirectional JSON-RPC protocol with generated TypeScript and JSON Schema. Thread rollouts are stored as append-oriented files and indexed in SQLite; runtime databases hold goals, memories, graph edges, logs, and metadata.

### Strong patterns

- **Thread/turn/item model.** API consumers see precise lifecycle primitives instead of internal callbacks.
- **Generated protocol contracts.** JSON Schema and TypeScript generation tie clients to the actual server version.
- **Bounded ingress and backpressure.** Saturated request queues return an explicit retryable overload response.
- **Rich platform sandboxing.** Seatbelt, bubblewrap/Landlock, and Windows backends enforce filesystem/network profiles and fail closed when a requested split policy cannot be represented.
- **Approval and tool routing separation.** Tool specifications, routers, runtimes, sandbox transforms, and approval protocols are separated rather than embedded in one shell tool.
- **Fresh review sessions.** Guardian/approval review uses a distinct thread and constrained context; tests assert it does not inherit unrelated memory/skill bodies.
- **Rollout-before-resume behavior.** Thread history, interrupted turn markers, branching, and compaction are carefully reconstructed and tested.
- **Memory job leases.** Background extraction claims bounded work, heartbeats leases, uses retry backoff, and serializes global consolidation.
- **Corruption handling.** Runtime SQLite databases and sidecars are moved to forensic backup before fresh creation.

### Gaps and pitfalls

- Codex is principally an interactive coding runtime, not a reboot-resumable general workflow daemon. Cold resume marks an incomplete rollout turn interrupted; it does not continue arbitrary in-flight tool effects.
- General tool dispatch does not expose a uniform durable idempotency/reconciliation contract. Idempotency exists for selected operations, not as the universal effect state machine.
- Persistence is split among rollout files and several SQLite databases. This is practical at Codex scale but adds backup and consistency complexity.
- The app-server can drain live turns on restart, but forced termination still relies on persisted history rather than continuing a process-local execution stack.
- Some user-initiated shell paths intentionally run outside the thread sandbox, which is appropriate only when clearly distinguished from model-proposed execution.
- The breadth of crates and compatibility paths would be excessive for Mealy's first implementation.

### Mealy decision

Adopt the Rust control plane, explicit public lifecycle, generated schemas, bounded queues, split tool routing, capability-based sandbox selection, fresh validation context, and corruption backups. Use one transactional task/effect database initially and make every effect declare recovery semantics.

### Evidence

- [`codex-rs/app-server/README.md`](https://github.com/openai/codex/blob/f774455c3a831dfab2c6f37a1f624b8097f6f2c2/codex-rs/app-server/README.md)
- [`codex-rs/docs/protocol_v1.md`](https://github.com/openai/codex/blob/f774455c3a831dfab2c6f37a1f624b8097f6f2c2/codex-rs/docs/protocol_v1.md)
- [`codex-rs/core/src/thread_manager.rs`](https://github.com/openai/codex/blob/f774455c3a831dfab2c6f37a1f624b8097f6f2c2/codex-rs/core/src/thread_manager.rs)
- [`codex-rs/core/src/sandboxing/mod.rs`](https://github.com/openai/codex/blob/f774455c3a831dfab2c6f37a1f624b8097f6f2c2/codex-rs/core/src/sandboxing/mod.rs)
- [`codex-rs/memories/README.md`](https://github.com/openai/codex/blob/f774455c3a831dfab2c6f37a1f624b8097f6f2c2/codex-rs/memories/README.md)
- [`codex-rs/state/src/runtime/recovery.rs`](https://github.com/openai/codex/blob/f774455c3a831dfab2c6f37a1f624b8097f6f2c2/codex-rs/state/src/runtime/recovery.rs)

## 5. Vercel AI SDK

### System shape

Vercel AI SDK is a provider-neutral TypeScript library, not a durable agent service. Its core functions normalize model providers, messages, tools, streams, structured output, loop steps, UI events, approvals, and telemetry. `ToolLoopAgent` packages those primitives into an application-embedded runtime.

### Strong patterns

- **Provider specification boundary.** High-level AI functions depend on versioned model interfaces implemented by provider packages.
- **Four message layers.** UI, application model, stable language-model, and provider-specific messages are converted explicitly.
- **Well-described streaming pipeline.** Step streams, tool execution, transforms, telemetry, and consumer tees have clear ordering.
- **Bounded loops.** The default step limit prevents runaway cost; `stopWhen` and `prepareStep` allow typed control without rewriting the loop.
- **Typed tools.** Function, dynamic, provider-defined, and provider-executed tools expose their different ownership semantics.
- **Approval revalidation.** Replayed approval responses are schema-checked and policy is re-evaluated; HMAC binding is available for client-controlled message history.
- **Context mutation at step boundaries.** `prepareStep` changes the next step's message base rather than mutating an in-flight call.
- **Provider conformance tests.** Cross-provider handoff and edge-case tests acknowledge that normalization is behavior, not merely types.

### Gaps and pitfalls

- The library intentionally does not own durable conversation state, task scheduling, channel authorization, side-effect journaling, or recovery.
- Standard chat server examples reconstruct state from client-controlled messages; without signing or server state, approval responses can be forged.
- Memory is delegated to provider-defined tools, external providers, or application code. Governance and inspectability are not framework guarantees.
- A tool `execute` callback runs with the host application's authority unless the application supplies a sandbox.
- Subagent tool approvals are not supported in the documented subagent pattern.
- Provider-executed tools move effect execution outside the application's enforcement boundary and need separate trust treatment.

### Mealy decision

Adopt layered messages, versioned provider capabilities, typed tool categories, approval subject signing/binding, step-boundary context changes, bounded loops, and cross-provider conformance tests. Supply the durable application host and do not assume provider-executed tools share local policy guarantees.

### Evidence

- [`architecture/provider-abstraction.md`](https://github.com/vercel/ai/blob/8e990ff217fc15644adc6c891c10a8f5ee11376a/architecture/provider-abstraction.md)
- [`architecture/message-layers.md`](https://github.com/vercel/ai/blob/8e990ff217fc15644adc6c891c10a8f5ee11376a/architecture/message-layers.md)
- [`architecture/stream-text-loop-control.md`](https://github.com/vercel/ai/blob/8e990ff217fc15644adc6c891c10a8f5ee11376a/architecture/stream-text-loop-control.md)
- [`content/docs/03-agents/04-loop-control.mdx`](https://github.com/vercel/ai/blob/8e990ff217fc15644adc6c891c10a8f5ee11376a/content/docs/03-agents/04-loop-control.mdx)
- [`content/docs/03-agents/06-tool-approvals.mdx`](https://github.com/vercel/ai/blob/8e990ff217fc15644adc6c891c10a8f5ee11376a/content/docs/03-agents/06-tool-approvals.mdx)

## 6. Eve

### System shape

Eve is a filesystem-authored TypeScript framework for durable agents. Sessions run as long-lived Workflow SDK drivers; each turn is a child workflow, and each model/tool step is a durable checkpoint. Workflow worlds supply storage, queues, hooks, and streams. Nitro serves HTTP/channel routes, while sandbox adapters manage isolated workspaces. Human approvals and questions park the workflow on durable hooks.

### Strong patterns

- **Session/turn/step clarity.** Step results are explicit atomic persistence boundaries.
- **Durable parking.** Approvals, questions, OAuth, and subagents suspend without keeping compute or process memory alive.
- **Versioned durable snapshots.** Session snapshots have versions and migrators; runtime-only tools/models are rehydrated from the current compiled bundle.
- **Separate driver and latest turn deployment.** Long-lived identity stays stable while new turns can use updated code with compatibility controls.
- **Per-subagent durable sessions.** Child lineage, isolated context, sandbox, skills, and state are explicit.
- **Security-zone explanation.** App runtime and sandbox roles, secret residency, credential brokering, channel signature verification, and fail-closed auth are clearly documented.
- **Public-API evaluations.** Evals drive a real agent server and combine deterministic gates with optional judge scores.

### Gaps and pitfalls

- Durability depends on Workflow SDK/world semantics. That is an external runtime dependency Mealy explicitly excludes from its core.
- Eve explicitly does **not** maintain a durable FIFO per session. Burst queueing is left to a channel or app layer, which can create semantic differences across channels.
- A step interrupted mid-execution is re-run. Eve correctly tells authors to make side effects idempotent or gate them, but the framework does not universally model unknown effect outcomes.
- Tool implementations run in the trusted app runtime and can read all process secrets unless application discipline narrows them.
- Only shell/file operations cross the sandbox boundary; arbitrary authored tool code does not.
- Conversation history is carried in workflow snapshots. Very long local sessions couple workflow storage cost to message history unless compaction is excellent.
- Hosted deployment routing and workflow-world compatibility add concepts a single-node personal daemon does not need.

### Mealy decision

Adopt step checkpoints, versioned snapshots, durable parking, isolated child sessions, explicit auth context, fail-closed routes, and public-API evaluations. Implement those semantics with local SQLite leases/hooks, own the inbox centrally, and add a first-class effect outcome state instead of relying on tool authors alone.

### Evidence

- [`docs/concepts/execution-model-and-durability.md`](https://github.com/vercel/eve/blob/f68ecbe4b157723edfb8c3957418ba84f8a1d384/docs/concepts/execution-model-and-durability.md)
- [`docs/concepts/security-model.md`](https://github.com/vercel/eve/blob/f68ecbe4b157723edfb8c3957418ba84f8a1d384/docs/concepts/security-model.md)
- [`docs/concepts/sessions-runs-and-streaming.md`](https://github.com/vercel/eve/blob/f68ecbe4b157723edfb8c3957418ba84f8a1d384/docs/concepts/sessions-runs-and-streaming.md)
- [`packages/eve/src/execution/durable-session-store.ts`](https://github.com/vercel/eve/blob/f68ecbe4b157723edfb8c3957418ba84f8a1d384/packages/eve/src/execution/durable-session-store.ts)
- [`packages/eve/src/execution/turn-workflow.ts`](https://github.com/vercel/eve/blob/f68ecbe4b157723edfb8c3957418ba84f8a1d384/packages/eve/src/execution/turn-workflow.ts)
- [`docs/evals/overview.mdx`](https://github.com/vercel/eve/blob/f68ecbe4b157723edfb8c3957418ba84f8a1d384/docs/evals/overview.mdx)

## 7. Pi

### System shape

Pi is a compact TypeScript monorepo with a provider-neutral AI layer, a stateful agent core, a coding-agent harness, and a TUI. The low-level agent emits ordered lifecycle events and supports steering, follow-ups, parallel tools with deterministic result ordering, context transforms, and provider hooks. Coding-agent sessions are JSONL append-only trees with branching and compaction. A newer `AgentHarness` is being developed toward stronger persistence; its fully durable recovery document is explicitly a design target.

### Strong patterns

- **Small, understandable loop.** Agent messages, context conversion, tool events, queues, and streaming are exposed without a large service framework.
- **Parallel execution with deterministic model order.** Tools may finish concurrently while persisted results follow source call order.
- **Tree-shaped sessions.** JSONL entries support branching, labels, compaction, branch summaries, and extension state without rewriting prior history.
- **Save-point discipline.** The harness snapshots configuration for a turn and applies busy-time changes only at safe boundaries.
- **Awaited event settlement.** Persistence and hooks can be ordered without blocking the provider transport reader.
- **Excellent durability design honesty.** The design says provider streams are not resumable, unfinished non-idempotent tools must not be retried, queued writes must be durable, and recovery must start at explicit boundaries.
- **Supply-chain awareness.** Exact dependencies, lockfile review, ignored install scripts, and release smoke tests are unusually thorough.

### Gaps and pitfalls

- The fully durable harness/recovery described in `durable-harness.md` is not the current completed runtime. Several crucial items remain implementation TODOs.
- Core agent queues and state are in memory unless a host persists them.
- JSONL gives portable history but not multi-object atomicity for task/effect/approval scheduling.
- Pi intentionally has no built-in permission system or sandbox; it runs with the launching user's authority unless externally contained.
- Extensions are TypeScript loaded into the main process and can intercept/modify tools and provider payloads.
- Automatic compaction is lossy and extension-customizable; typed safety-critical carry-forward is not a general guarantee.
- The product is coding-agent-centric and delegates chat automation to another project.

### Mealy decision

Adopt the small loop, deterministic tool-result ordering, save-point semantics, branch/export ideas, and especially the conservative recovery model. Implement durable queues/effects in SQLite first; use JSONL only as an export format, and never claim a design document is runtime proof.

### Evidence

- [`packages/agent/README.md`](https://github.com/earendil-works/pi/blob/bc0db643502ba0bf1b227a97d9d5885cefc2b909/packages/agent/README.md)
- [`packages/agent/docs/agent-harness.md`](https://github.com/earendil-works/pi/blob/bc0db643502ba0bf1b227a97d9d5885cefc2b909/packages/agent/docs/agent-harness.md)
- [`packages/agent/docs/durable-harness.md`](https://github.com/earendil-works/pi/blob/bc0db643502ba0bf1b227a97d9d5885cefc2b909/packages/agent/docs/durable-harness.md)
- [`packages/coding-agent/docs/session-format.md`](https://github.com/earendil-works/pi/blob/bc0db643502ba0bf1b227a97d9d5885cefc2b909/packages/coding-agent/docs/session-format.md)
- [`SECURITY.md`](https://github.com/earendil-works/pi/blob/bc0db643502ba0bf1b227a97d9d5885cefc2b909/SECURITY.md)

## 8. Claude Code mirror

### Provenance boundary

The repository states that it is a third-party mirror reconstructed from an accidentally published source map, that the original source is proprietary Anthropic material, and that it is not an official Anthropic repository. It contains no license file. It is therefore not a permissible implementation source for Mealy.

The review is limited to general architectural observations that are independently supported by licensed references. No source, prompt, internal name, or implementation text should be copied.

### Observed system shape

The mirror presents a TypeScript/React terminal application with a `QueryEngine`, a large typed tool contract, JSONL transcript storage, session bridges, permissions, sandbox modes, MCP, plugins, memory consolidation, background tasks, and coordinator/worker orchestration.

### General patterns worth independent consideration

- The engine records accepted user input before entering the query loop, improving crash-resumable conversation history.
- Per-file queued transcript writes preserve ordering, and assistant streaming persistence is decoupled from generator progress.
- Tool metadata distinguishes irreversible operations, concurrency behavior, interruption behavior, result-storage thresholds, validation, and permissions.
- Coordinator workers receive self-contained prompts rather than implicit parent history; verification is recommended in a fresh worker.
- Memory consolidation uses time/session gates and a lock, echoing the bounded/leased background patterns also present in Codex.

### Gaps and pitfalls

- Provenance and licensing make the repository unsuitable for code or prompt reuse.
- JSONL session files can grow to multiple gigabytes; comments and safeguards around 50 MiB rewrite/read thresholds reveal operational pressure.
- Fire-and-forget transcript writes and many sidecars require careful flush and crash behavior.
- The UI, query engine, tasks, permission contexts, feature gates, and service integrations are highly coupled in one process.
- Permissions and optional sandbox behavior do not by themselves establish a universal durable effect protocol.
- Remote/local session and transcript paths introduce multiple persistence modes and reconciliation paths.

### Mealy decision

Use this repository only to corroborate already-independent design choices: persist admission before execution, queue ordered writes, give tools rich recovery metadata, pass self-contained child context, and validate with fresh context. Do not copy from it.

### Evidence

- [`README.md`](https://github.com/yasasbanukaofficial/claude-code/blob/a371abbe75ffa0d0a3c92290e2bbf56a7ef54367/README.md)
- [`src/QueryEngine.ts`](https://github.com/yasasbanukaofficial/claude-code/blob/a371abbe75ffa0d0a3c92290e2bbf56a7ef54367/src/QueryEngine.ts)
- [`src/Tool.ts`](https://github.com/yasasbanukaofficial/claude-code/blob/a371abbe75ffa0d0a3c92290e2bbf56a7ef54367/src/Tool.ts)
- [`src/utils/sessionStorage.ts`](https://github.com/yasasbanukaofficial/claude-code/blob/a371abbe75ffa0d0a3c92290e2bbf56a7ef54367/src/utils/sessionStorage.ts)

## Cross-system synthesis

### Patterns with multiple implementations

- One central runtime serving multiple clients: OpenClaw, Hermes, Codex app-server, OpenCode server, Eve.
- Explicit session/turn/step or thread/turn/item primitives: Codex, Eve, OpenCode, Pi.
- Provider-neutral core plus adapters: Vercel AI SDK, Pi, Hermes, OpenCode, Codex.
- Per-session serialization and bounded global concurrency: OpenClaw, Hermes, Codex, OpenCode.
- Append-oriented conversation history and compaction provenance: Codex, Pi, Claude Code mirror, OpenClaw.
- Fresh child context for delegation/review: Codex, Vercel AI SDK, Eve, Pi, Claude Code mirror.
- OS isolation is the real security boundary: Codex implementation; Hermes, OpenCode, Pi, and OpenClaw threat models.
- Checkpointed/leased background work: Eve, Codex memory jobs, OpenCode event sequences/context epochs.

### Gaps common enough to define Mealy

1. **Durable inbox gap:** several systems serialize turns but queue new input only in process or in channels.
2. **Effect ambiguity gap:** most systems persist tool results, but few model dispatch-before-outcome uncertainty across every tool.
3. **Plugin boundary gap:** mature extension systems commonly execute third-party code in the trusted process.
4. **Authorization gap:** personal gateways often treat an authenticated caller as a full operator and session IDs as routing only.
5. **Context evidence gap:** compaction is common; a complete item-by-item inclusion manifest is not.
6. **Memory governance gap:** file memory and automatic extraction are common; provenance, promotion, retention, and deletion policy are inconsistent.
7. **Validation gap:** review/evals exist, but durable task-specific validation evidence is rarely a core lifecycle state.
8. **Replay honesty gap:** replay often means transcript reconstruction, event re-delivery, or workflow step result reuse—not safe re-execution of arbitrary effects.

These gaps are converted into normative requirements in [`REQUIREMENTS.md`](../../REQUIREMENTS.md) and architectural decisions in [`ARCHITECTURE.md`](../../ARCHITECTURE.md).
