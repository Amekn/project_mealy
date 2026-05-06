# Software Requirements V0.0.1

This document describes the proposed software requirements for Mealy and the constraints that future architecture should follow.

## Product Direction

Mealy is a self-contained agentic framework for a reliable personal AI assistant. It starts as a single-user personal daemon with strong local security, while preserving identity, permission, and channel boundaries so multi-user deployments can be added later without redesigning the core system.

Mealy must not depend on external agent runtimes such as Codex, Claude Code, OpenClaw, Hermes, or similar systems. External LLM providers may be used, but Mealy owns the agent loop, orchestration, tools, memory, state, policy, and task lifecycle.

## Features

### Core Agent Runtime

- Agentic loop: receive user input, interpret intent, plan work, execute actions, validate results, and respond to the user.
- Task/session/workflow model: define separate IDs and lifecycles for conversation sessions, individual tasks, long-running workflows, agent runs, tool calls, approvals, artifacts, and validation passes.
- Orchestration: user-facing agents can invoke specialized internal agents with relevant context injection.
- Multi-agent support: Mealy supports more than one internal agent, with each agent having its own workspace, memory partition, identity, permissions, and task namespace.
- Parallel agent runs: tasks can be split across multiple internal agents running at the same time, with ownership rules and conflict detection.
- Task navigation: the user can interrupt, redirect, pause, resume, or cancel active tasks.

### Channels and User Access

- Channels: users can send input and receive responses through TUI, Discord, web UI, or other channel plugins.
- Thin channel clients: channels expose Mealy tasks and timelines but do not own orchestration logic or durable task state.
- User access: only authenticated and authorized users can access the system, including through Discord user IDs, web UI login, local CLI credentials, or future multi-user identity management.

### Tools, Skills, and Plugins

- Built-in tools and skills: Mealy includes first-party tools for file access, command execution, web/service calls, and project workflows, plus first-party skills such as GitHub, Obsidian, and Nextcloud workflows.
- Plugin system: plugins can extend Mealy with new channels, tools, skills, memory sources, LLM providers, and service integrations.
- Capability registry: every agent, tool, skill, plugin, LLM provider, channel, and service integration declares capabilities, permissions, health, version, config schema, and cost/latency traits.

### LLM Providers

- Provider support: Mealy supports multiple backend LLM providers such as OpenAI OAuth/API Token, llama.cpp, OpenRouter, and future local or remote providers.
- Provider routing and fallback: LLM calls can be routed by task type, privacy level, cost, latency, local/remote preference, context size, availability, and user policy.
- Replaceable provider interface: provider APIs sit behind a common internal interface so provider-specific details do not leak into orchestration code.

### Context and Memory

- Context management: Mealy manages its own context windows precisely, balancing context size, relevance, cost, latency, and quality.
- Self-compaction: Mealy can compact context during the agentic loop while preserving task continuity and auditability.
- Multi-tier memory architecture: Mealy supports workspace memory loaded during sessions, long-term semantic memory stored in a vector database, syntax/search-based memory from past session records, daily diary-style records.
- Memory governance: memory writes include provenance, namespace, retention policy, sensitivity labels, confidence, and inspection/deletion mechanisms.
- Inspectable context assembly: the system can show why each memory, file, task log, instruction, or artifact was included in an agent context.

### Durability, Recovery, and State

- Persistent runtime: Mealy runs as a system service and persists across reboot.
- Automatic interrupt recovery: interrupted conversations, tasks, workflows, and service operations are recovered after process restart or reboot with minimal manual intervention.
- Idempotent recovery: recovery must not duplicate dangerous side effects such as repeated writes, repeated commands, or repeated service mutations.
- Event ledger: Mealy keeps an append-only record of task state changes, messages, tool calls, approvals, interruptions, recovery actions, validation results, artifacts, and final answers.
- Migration and upgrade system: durable state uses schema versions, migrations, backups, and rollback strategy.

### Task Transparency and Artifacts

- User-facing task timeline: every channel exposes the same underlying task timeline with progress, interruptions, approvals, artifacts, validation status, and final results.
- Task logging: all actions performed by each agent are tracked in historical order, with logs grouped by task and session.
- Artifact store: Mealy durably stores patches, files, command outputs, screenshots, generated reports, logs, validation evidence, and final deliverables.
- Replay/debug mode: completed or failed tasks can be replayed from recorded events, inputs, tool outputs, artifacts, and decisions.

### Validation

- Independent validation: tasks are validated by a different internal agent with a fresh context window before the final solution is proposed to the user.
- Validation rubrics: validator agents check explicit success criteria, evidence, constraints, and task outputs rather than providing only a generic second opinion.
- Validation evidence: validation results are linked to task logs, artifacts, tool outputs, and user requirements.

### Security and Policy

- Policy engine: user-defined rules control filesystem access, shell execution, network access, credentials, plugins, channels, memory writes, service mutations, and escalation approvals.
- System privilege profiles: different system access levels are configurable through preconfigured security profiles such as read-only, workspace-write, networked, service-admin, and full-trust.
- Secrets manager: credentials are scoped, auditable, revocable, and never injected into prompts unless explicitly allowed.
- Mediated side effects: file writes, shell commands, network calls, service mutations, memory writes, and credential access must pass through Mealy's tool and policy layer.

### Operations and Health

- Health monitoring: Mealy tracks daemon health, provider health, plugin health, queue depth, stuck tasks, restart count, memory use, storage use, and recovery status.
- Administrative visibility: the user can inspect active sessions, queued tasks, running agents, pending approvals, recent failures, and system configuration.

## Constraints

- Self-contained runtime: Mealy owns the agent loop, orchestration, tools, skills, memory, context management, durable state, validation, policy, and task lifecycle.
- Single-user first: the first architecture targets a personal local daemon, but identity, permissions, channel authorization, and data namespaces must be designed so multi-user deployments can be added later.
- No external agent runtime dependency: Mealy must not rely on Codex, Claude Code, OpenClaw, Hermes, OpenCode, NanoClaw, or similar systems for its core runtime behavior.
- Local-first security: default operation should be safe for a personal machine, with least-privilege access and explicit escalation for risky side effects.
- Durable state is authoritative: no channel, plugin, provider, or agent process may be the source of truth for task status, memory, permissions, or workflow progress.
- Event-driven long-running work: tasks must be resumable, inspectable, interruptible, cancellable, and recoverable across process restarts.
- Channels cannot bypass policy: TUI, Discord, web UI, Slack, API clients, and future channels must all use the same authentication, authorization, task, and policy layers.
- Agents are isolated by default: sharing workspaces, memory, credentials, or permissions between agents requires explicit configuration.
- Parallel work requires ownership: multiple agents must not mutate the same files, services, or memory partitions without coordination, locks, or merge rules.
- Plugins require manifests: each plugin declares capabilities, permissions, config schema, version compatibility, event types, and health checks.
- Context is inspectable and reproducible: Mealy should be able to explain and replay the context assembled for a run, within privacy and storage limits.
- Memory is not blindly trusted: retrieved memories include source, date, scope, confidence, and sensitivity metadata; stale or sensitive memories can be filtered.
- Validation is independent: validator agents receive fresh context and structured evidence, not contaminated producer-agent context.
- Provider APIs are replaceable: LLM provider details must remain behind internal interfaces.
- Recovery is idempotent: resumed tasks must continue from recorded state without repeating already-confirmed side effects.
- Schemas are versioned: durable data formats, plugin manifests, memory records, event logs, and config files must support migrations.
