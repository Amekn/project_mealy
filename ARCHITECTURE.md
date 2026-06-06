# Mealy Architecture V0.0.1

Status: draft for review

This document describes a proposed architecture for Mealy, a self-contained agentic framework for a reliable personal AI assistant. It is intended to be refined alongside `REQUIREMENTS.md` before implementation planning begins.

## 1. Product Position

Mealy is a local-first agent runtime. It is not a wrapper around existing agent products, and it must not depend on external agent runtimes such as Codex, Claude Code, OpenClaw, Hermes, OpenCode, NanoClaw, or similar systems for its core behavior.

External LLM providers are allowed. External services, APIs, channels, and plugins are allowed. The boundary is that Mealy owns the agent loop, durable state, task lifecycle, context management, memory, tool execution, policy, orchestration, validation, and recovery.

The first target is a single-user personal daemon with strong local security. The design should still preserve identity, permission, namespace, and channel boundaries so a multi-user deployment can be added later without replacing the core model.

## 2. Primary Goals

- Provide a persistent local agent runtime that survives process restarts and machine reboots.
- Own the full agentic loop: receive input, understand intent, plan, execute, observe, validate, and respond.
- Support multiple Mealy-native agents with isolated workspaces, memory partitions, permissions, and roles.
- Support channels such as TUI, web UI, Discord, local CLI, and API clients as thin clients over one durable runtime.
- Support built-in and plugin-provided tools, skills, memory sources, channels, and LLM providers.
- Mediate every side effect through policy, approvals, logging, and durable events.
- Make task progress transparent through a shared task timeline visible from every channel.
- Provide independent validation with fresh context before final answers for substantial tasks.
- Provide replay, recovery, auditing, and debugging through an append-only event ledger.
- Keep provider APIs replaceable through internal provider interfaces.

## 3. Non-Goals

- Mealy will not embed or depend on external agent runtimes as core execution engines.
- Mealy will not let channels own workflow state or orchestration logic.
- Mealy will not let agents directly mutate files, memory, services, credentials, or network state.
- Mealy will not treat LLM memory or retrieved memories as inherently trusted.
- Mealy will not require a multi-user server deployment for the first version.
- Mealy will not require cloud services for local-first operation.

## 4. Architectural Invariants

These are the rules that should stay true even as implementation details change.

1. Mealy owns durable state.
2. Every side effect passes through the tool and policy layer.
3. Long-running work is event-driven and recoverable.
4. Channels are clients, not runtimes.
5. Agents are Mealy-native runtime instances, not external agent products.
6. Agents are isolated by default.
7. LLM providers are replaceable inference backends.
8. Context assembly is inspectable and reproducible within storage and privacy limits.
9. Memory records carry provenance, namespace, sensitivity, confidence, and retention metadata.
10. Validation uses fresh context and structured evidence.
11. Recovery is idempotent.
12. Schemas are versioned.

The central rule is:

```text
No channel, agent, plugin, tool, or provider may mutate durable state or the outside world except through Mealy's evented policy layer.
```

## 5. System Overview

At runtime, Mealy is centered on a daemon process, `mealyd`.

```text
                  +----------------------+
                  |      User            |
                  +----------+-----------+
                             |
          +------------------+------------------+
          |                  |                  |
      +---v---+          +---v---+          +---v---+
      |  TUI  |          | Web UI|          |Discord|
      +---+---+          +---+---+          +---+---+
          |                  |                  |
          +------------------+------------------+
                             |
                     +-------v--------+
                     |  Mealy API     |
                     |  auth, tasks,  |
                     |  timeline      |
                     +-------+--------+
                             |
                     +-------v--------+
                     |    mealyd      |
                     | local daemon   |
                     +-------+--------+
                             |
     +-----------------------+-----------------------+
     |                       |                       |
+----v-----+          +------v------+         +------v------+
| Agent    |          | Tool Broker |         | Context     |
| Runtime  |          | and Policy  |         | Compiler    |
+----+-----+          +------+------+         +------+------+
     |                       |                       |
     |                       |                       |
+----v-----+          +------v------+         +------v------+
| Provider |          | Plugins and |         | Memory      |
| Router   |          | Built-ins   |         | Manager     |
+----+-----+          +------+------+         +------+------+
     |                       |                       |
     +-----------------------+-----------------------+
                             |
              +--------------v--------------+
              | Durable Storage             |
              | event ledger, projections,  |
              | artifacts, memory, config   |
              +-----------------------------+
```

The daemon exposes stable APIs to channels and local clients. Internally it coordinates task state, scheduling, agent runs, policy decisions, context bundles, memory, tool execution, artifacts, and provider calls.

## 6. Runtime Topology

### 6.1 Processes

Initial process layout:

- `mealyd`: the local daemon and source of truth.
- `mealyctl`: administrative CLI for local inspection and control.
- `mealy-tui`: optional terminal UI client.
- `mealy-web`: optional local web UI client or web UI service.
- Channel workers: optional long-running connectors for Discord, Slack, or other remote channels.
- Plugin workers: optional isolated plugin processes for higher-risk or long-running integrations.

The first implementation can place many components in one binary or one service. The architecture should still preserve internal boundaries so components can move to separate processes later.

### 6.2 Local Service Model

On Linux, `mealyd` should run as a user-level systemd service by default:

```text
systemd --user
  mealyd.service
    listens on local socket / HTTP loopback
    stores data under user-owned state directories
    starts after network if networked plugins are enabled
```

The daemon should support:

- clean startup and shutdown
- health check endpoint
- readiness endpoint
- graceful task suspension on shutdown
- recovery scan on startup
- migration check before serving traffic
- bounded concurrency during recovery

### 6.3 Storage Locations

Suggested default locations:

```text
~/.local/share/mealy/
  state/
    mealy.db
    event-ledger/
    projections/
  artifacts/
    tasks/
    contexts/
    tool-output/
    validation/
  memory/
    vector/
    diary/
    records/
  plugins/
    installed/
    cache/

~/.config/mealy/
  config.toml
  agents/
  policies/
  providers/
  channels/
  plugins/

~/.cache/mealy/
  provider-cache/
  embeddings/
  temp/
```

These paths are suggestions. The important rule is to separate config, durable state, artifacts, memory, and cache.

## 7. Core Modules

### 7.1 API Layer

Responsibilities:

- Authenticate channel and client requests.
- Authorize actions against principal permissions.
- Create sessions, tasks, workflows, interrupts, approvals, and user messages.
- Stream task timelines and agent output.
- Expose administrative inspection.
- Hide internal storage layout from clients.

Suggested API surfaces:

- local CLI API
- local HTTP API
- WebSocket or server-sent events for timelines
- plugin API for registered extensions
- internal service API for daemon modules

The API should be stable before multiple channel clients are added. Channels should use the same API rather than reaching into daemon internals.

### 7.2 Identity and Access Manager

Responsibilities:

- Track principals, channel identities, agent identities, service identities, and future users.
- Map channel-specific identities to Mealy principals.
- Enforce authentication and authorization.
- Create scoped access tokens or local credentials.
- Support single-user defaults while keeping multi-user shape.

Core identity types:

```text
Principal
  A human or service identity known to Mealy.

ChannelIdentity
  A channel-specific identity such as a Discord user ID, web login,
  local CLI token, or future SSO identity.

AgentIdentity
  A Mealy-native internal agent identity with role, namespace, and policy scope.

ServiceIdentity
  A plugin or integration identity used for service access.

PermissionScope
  A named scope describing what an identity may do.
```

Single-user mode can ship with one owner principal, but the database should still store ownership and namespace fields explicitly.

### 7.3 Task Runtime

Responsibilities:

- Own task, session, workflow, and run lifecycles.
- Maintain state machines.
- Append events for all lifecycle changes.
- Coordinate interrupts, cancellation, pause/resume, recovery, and validation.
- Expose timeline projections.

Important domain objects:

```text
Session
  A conversation or channel interaction context.

Task
  A unit of work with explicit user intent, state, events, artifacts,
  agents, tool calls, approvals, and validation.

Workflow
  A long-running or multi-task process.

AgentRun
  One execution attempt by one internal agent on a task or subtask.

ToolCall
  One requested side effect or observation through a tool.

Approval
  A policy decision requiring user or rule-based authorization.

Artifact
  Durable output from an agent, tool, provider, or validation pass.

ValidationRun
  Independent review of task outputs against success criteria.
```

### 7.4 Scheduler

Responsibilities:

- Schedule agent runs, tool calls, validation runs, memory jobs, and recovery work.
- Enforce concurrency limits.
- Apply priority rules.
- Avoid resource starvation.
- Manage task queues.
- Support cancellation and preemption.

The scheduler should understand:

- task priority
- channel priority
- user-defined budgets
- provider rate limits
- tool risk class
- workspace locks
- memory locks
- recovery mode
- system resource limits

### 7.5 Agent Runtime

Responsibilities:

- Run Mealy-native agents.
- Maintain agent profiles and role policies.
- Request context bundles from the context compiler.
- Call LLM providers through the provider router.
- Interpret model output into structured runtime actions.
- Request tool calls through the tool broker.
- Emit events for progress, decisions, outputs, errors, and completion.

Agents are not separate products. They are configured runtime instances.

Agent profile fields:

```text
agent_id
name
role
description
instruction_sources
memory_namespace
workspace_namespace
policy_profile
provider_policy
context_policy
tool_capabilities
validation_requirements
max_parallel_children
budget_policy
```

Example built-in agent roles:

- coordinator: turns user intent into task plan and delegates work.
- executor: performs task steps through tools.
- researcher: gathers and summarizes information.
- code_worker: edits and tests local code.
- service_operator: interacts with configured local or remote services.
- memory_curator: evaluates memory writes and cleanup.
- validator: independently checks final task output.
- summarizer: compacts sessions, tasks, and long contexts.
- recovery_agent: assists with interrupted tasks and restart decisions.

The initial implementation does not need every role. The runtime should make these roles first-class enough that they can be added without changing the core loop.

### 7.6 Context Compiler

Responsibilities:

- Assemble model context for each agent run.
- Apply role-specific context policy.
- Include task state, relevant events, user messages, workspace memory, retrieved memory, artifacts, files, and instructions.
- Enforce context budgets.
- Produce inspectable context bundles.
- Support compaction and summarization.
- Record provenance for each context item.

The context compiler should produce a durable context bundle:

```text
ContextBundle
  context_bundle_id
  task_id
  agent_run_id
  schema_version
  token_budget
  provider_context_limit
  items[]
  excluded_items[]
  assembly_policy
  created_at
```

Each item should include:

```text
ContextItem
  item_id
  item_type
  source_type
  source_id
  namespace
  sensitivity
  confidence
  token_estimate
  inclusion_reason
  content_hash
  content_ref
```

The bundle can store large content by reference to artifacts rather than duplicating everything into the database.

### 7.7 Memory Manager

Responsibilities:

- Store and retrieve memory records.
- Separate memory by principal, agent, workspace, project, channel, and sensitivity.
- Support semantic retrieval through embeddings.
- Support syntax/search retrieval over session logs, daily diaries, and records.
- Govern proposed memory writes.
- Support memory inspection, deletion, retention, and reindexing.

Memory tiers:

```text
Workspace memory
  Project-local instructions and facts such as AGENTS.md, SOUL.md,
  project notes, repo-specific preferences, and channel configuration.

Task/session memory
  Recent conversation state, task events, summaries, decisions,
  artifacts, and unresolved follow-ups.

Long-term semantic memory
  Embedding-indexed facts and preferences for retrieval by meaning.

Long-term lexical memory
  Searchable records from previous sessions, daily diaries, logs,
  notes, and imported text sources.

Operational memory
  System health patterns, provider failures, plugin status,
  repeated task outcomes, and recovery notes.
```

Memory records should include:

```text
memory_id
namespace
owner_principal_id
agent_id
source_event_id
source_artifact_id
content
summary
tags
sensitivity
confidence
retention_policy
created_at
updated_at
expires_at
embedding_refs
search_index_refs
review_state
```

Memory write policy should distinguish:

- automatic low-risk operational summaries
- proposed user preference memories
- sensitive memories requiring approval
- memories derived from private files
- memories imported from external services
- memories that should never leave local storage

### 7.8 Tool Broker

Responsibilities:

- Register tools and tool capabilities.
- Validate tool arguments.
- Check policy before execution.
- Create approvals when needed.
- Execute built-in and plugin-provided tools.
- Capture tool outputs.
- Store artifacts.
- Append tool events.
- Enforce idempotency.

The tool broker is the only path to side effects.

Tool categories:

- observation tools: read files, inspect directories, query status
- mutation tools: write files, modify config, apply patches
- command tools: run shell commands, systemctl commands, package commands
- network tools: HTTP requests, API calls, web fetches
- service tools: GitHub, Nextcloud, Obsidian, local daemons
- memory tools: propose, write, edit, delete, and retrieve memories
- channel tools: send messages, update progress, ask for approval
- artifact tools: create, read, diff, render, or export artifacts

Each tool call should have an idempotency key. For dangerous side effects, replay should observe that the action has already completed rather than executing it again.

### 7.9 Policy Engine

Responsibilities:

- Decide whether requested actions are allowed, denied, or require approval.
- Enforce security profiles.
- Enforce principal, channel, agent, plugin, workspace, and memory scopes.
- Apply rate, cost, and budget limits.
- Emit policy decision events.

Policy inputs:

```text
requesting_identity
task_id
agent_run_id
channel_id
tool_name
tool_capability
arguments
risk_class
workspace
target_resource
secret_refs
network_destination
current_security_profile
user_rules
```

Policy outcomes:

```text
allow
deny
require_approval
require_stronger_profile
require_user_interrupt
require_validation_first
```

Suggested built-in security profiles:

- `read_only`: can inspect allowed files and task history, no mutations.
- `workspace_write`: can mutate files inside approved workspaces.
- `networked`: can make approved network calls.
- `service_user`: can use approved service credentials with scoped actions.
- `service_admin`: can mutate service configuration.
- `full_trust`: local owner mode for explicitly approved high-risk operations.

Profiles should be composable rather than one giant privilege flag.

### 7.10 Provider Router

Responsibilities:

- Provide a common interface over LLM providers.
- Route requests to configured providers.
- Apply privacy, cost, latency, capability, and context constraints.
- Track provider health, rate limits, and failures.
- Support fallback rules.
- Normalize provider responses into internal result types.

Provider interface:

```text
Provider
  provider_id
  capabilities
  models
  health
  estimate_cost(request)
  complete(request)
  stream(request)
  embed(request)
```

Provider routing criteria:

- requested modality
- context length
- tool-call support
- structured output support
- local-only requirement
- privacy level
- expected cost
- expected latency
- reliability
- current health
- user preference
- task criticality

Provider-specific APIs must not leak into the agent runtime.

### 7.11 Plugin Host

Responsibilities:

- Install, configure, load, start, stop, and update plugins.
- Validate plugin manifests.
- Expose plugin tools, channels, memory sources, providers, and skills.
- Isolate plugins according to risk class.
- Track plugin health.
- Apply migrations for plugin state.

Plugin manifest fields:

```text
plugin_id
name
version
schema_version
description
entrypoint
permissions
tools
channels
memory_sources
providers
skills
config_schema
event_types
health_checks
storage_needs
network_access
secret_refs
compatibility
```

Plugin isolation levels:

- in-process trusted first-party plugin
- child process plugin
- containerized plugin
- disabled plugin metadata only

The first version can prioritize first-party plugins, but the manifest model should exist early.

### 7.12 Skill Engine

Responsibilities:

- Represent reusable workflows and procedural knowledge.
- Match skills to task intent.
- Inject skill instructions into context through the context compiler.
- Declare required tools, permissions, memory sources, and validation rules.
- Version skills.
- Allow first-party and plugin-provided skills.

Skill manifest fields:

```text
skill_id
name
version
description
trigger_rules
instructions_ref
required_tools
required_permissions
context_policy
validation_policy
memory_policy
```

Skills are not arbitrary prompt blobs. They are runtime resources with metadata and policy.

### 7.13 Artifact Store

Responsibilities:

- Store generated files, patches, command outputs, screenshots, reports, logs, context snapshots, validation evidence, and final deliverables.
- Provide content-addressed storage where useful.
- Link artifacts to events, tasks, runs, and validation.
- Support retention policies.
- Support export and backup.

Artifact metadata:

```text
artifact_id
task_id
agent_run_id
event_id
artifact_type
content_hash
content_ref
mime_type
size
sensitivity
created_at
retention_policy
```

Artifacts should be referenced from events rather than embedded in event bodies when large.

### 7.14 Event Ledger

Responsibilities:

- Store append-only events for all meaningful state changes.
- Provide a complete audit trail.
- Support recovery.
- Support replay/debug mode.
- Feed projections for fast UI queries.
- Provide causal links between events.

Events are immutable. If state changes, append a new event.

Event envelope:

```text
event_id
schema_version
event_type
occurred_at
recorded_at
principal_id
agent_id
channel_id
session_id
task_id
workflow_id
agent_run_id
causation_id
correlation_id
idempotency_key
visibility
sensitivity
body
```

Core event families:

```text
session.*
task.*
workflow.*
agent_run.*
message.*
context.*
tool.*
approval.*
artifact.*
memory.*
provider.*
validation.*
policy.*
plugin.*
channel.*
system.*
recovery.*
```

Example events:

```text
task.created
task.started
task.paused
task.interrupted
task.resumed
task.cancelled
task.completed
task.failed

agent_run.started
agent_run.output_delta
agent_run.action_proposed
agent_run.completed
agent_run.failed

tool.requested
tool.policy_checked
tool.approval_required
tool.approved
tool.started
tool.output_recorded
tool.completed
tool.failed

context.requested
context.compiled
context.compacted

validation.requested
validation.started
validation.completed
validation.failed

recovery.scan_started
recovery.task_found
recovery.task_resumed
recovery.task_needs_user
```

### 7.15 Projection Store

Responsibilities:

- Maintain query-optimized views derived from the event ledger.
- Provide fast task lists, timelines, health views, approval inboxes, and current states.
- Rebuild from the event ledger when schema changes or corruption is detected.

Projection examples:

- current task state
- session timeline
- active agent runs
- pending approvals
- artifact index
- memory index metadata
- provider health
- plugin health
- channel connection status
- recovery queue

Projections are disposable. The ledger is authoritative.

### 7.16 Recovery Manager

Responsibilities:

- Detect incomplete work after startup.
- Classify interrupted tasks.
- Resume safe work.
- Request user approval for ambiguous or dangerous recovery.
- Avoid duplicate side effects.
- Restore scheduler state.
- Rebuild projections if necessary.

Recovery classification:

```text
completed
safe_to_resume
needs_context_rebuild
needs_user_decision
blocked_on_approval
blocked_on_tool_state
blocked_on_missing_plugin
failed_nonrecoverable
```

Recovery should not blindly continue all tasks. It should use task state, event history, idempotency keys, and policy to decide the safe next step.

### 7.17 Observability and Health

Responsibilities:

- Track daemon health.
- Track provider health and rate limit state.
- Track plugin health.
- Track queue depth and stuck tasks.
- Track storage use and migration status.
- Track memory index health.
- Track task failures and validation failures.
- Expose local admin views.

Suggested health states:

```text
healthy
degraded
recovering
blocked
maintenance_required
failed
```

Mealy should expose enough operational state that the owner can answer:

- What is running?
- What is queued?
- What is blocked?
- What is waiting for me?
- What failed recently?
- What changed on disk or in services?
- What credentials were used?
- What memory was written?

## 8. Domain State Machines

### 8.1 Task State

```text
created
  -> queued
  -> planning
  -> running
  -> waiting_for_approval
  -> waiting_for_user
  -> validating
  -> completed

running
  -> interrupted
  -> paused
  -> cancelling
  -> failed

interrupted
  -> running
  -> waiting_for_user
  -> cancelled

paused
  -> queued
  -> cancelled

cancelling
  -> cancelled

validating
  -> needs_revision
  -> completed
  -> failed

needs_revision
  -> running
  -> waiting_for_user
```

Task state should be derived from events. The current state projection can be stored for fast access, but it must be rebuildable.

### 8.2 Agent Run State

```text
created
  -> context_compiling
  -> provider_running
  -> tool_wait
  -> observing
  -> completed

provider_running
  -> interrupted
  -> failed
  -> cancelled

tool_wait
  -> provider_running
  -> failed
  -> cancelled
```

An agent run is an attempt. A task may contain multiple agent runs.

### 8.3 Tool Call State

```text
requested
  -> policy_checking
  -> approval_required
  -> approved
  -> running
  -> completed

policy_checking
  -> denied
  -> approved
  -> approval_required

approval_required
  -> approved
  -> denied
  -> expired

running
  -> completed
  -> failed
  -> cancelled
```

Tool calls that perform side effects must store enough state to support idempotent recovery.

### 8.4 Validation State

```text
requested
  -> context_compiling
  -> running
  -> passed

running
  -> failed
  -> inconclusive
  -> needs_revision
```

Validation is part of the task lifecycle, not a separate optional report.

## 9. Agentic Loop

The standard Mealy task loop:

1. Channel sends user input to the API.
2. API authenticates the channel identity and maps it to a principal.
3. Task runtime appends `message.received` and creates or updates a task.
4. Scheduler selects the next work item.
5. Coordinator agent receives a context bundle.
6. Coordinator produces a plan or direct action.
7. Agent runtime converts model output into structured actions.
8. Tool requests go to the tool broker.
9. Policy engine allows, denies, or requests approval.
10. Tool broker executes approved tools and stores outputs as events and artifacts.
11. Agent observes structured tool results.
12. Loop repeats until the task reaches a proposed final result.
13. Validation agent receives fresh context and structured evidence.
14. Validator passes, fails, or requests revision.
15. If passed, task runtime publishes final answer and artifacts.
16. All channels can display the same timeline and final state.

The loop should support streaming progress while preserving durable checkpoints.

## 10. Multi-Agent Orchestration

Mealy should support internal agent delegation without treating delegated agents as unmanaged subprocesses.

### 10.1 Delegation Model

The coordinator can create subtasks or child agent runs. Delegation requires:

- explicit task or subtask scope
- context injection policy
- expected output format
- tool permissions
- workspace ownership
- memory namespace
- budget
- validation requirement

### 10.2 Parallel Work

Parallel agents are useful for independent research, verification, or disjoint implementation work. Parallelism is dangerous when agents can mutate the same resources.

Parallel work must use:

- workspace locks
- file ownership declarations
- service mutation locks
- memory write review
- artifact-based handoff
- merge or conflict detection
- cancellation propagation

### 10.3 Agent Isolation

Each internal agent should have:

- agent identity
- role
- policy profile
- workspace namespace
- memory namespace
- context policy
- provider policy
- budget policy

Sharing is explicit. Isolation is the default.

## 11. Channels

Channels should be thin clients over the Mealy API.

### 11.1 Channel Responsibilities

Channels may:

- authenticate channel users
- send user messages
- render task timelines
- display approvals
- stream agent progress
- show artifacts
- send interrupts
- receive notifications

Channels must not:

- own task state
- execute tools directly
- bypass policy
- write memory directly
- manage agent sessions directly
- decide durable workflow state

### 11.2 Channel Types

Initial channel candidates:

- `mealyctl`: administrative CLI.
- TUI: local terminal client for active work.
- Web UI: local browser interface for task timelines, approvals, memory, and health.
- Discord: remote messaging channel with strict identity mapping.
- Slack: future plugin channel.
- Local API: scripted access for personal automation.

### 11.3 Channel Security

Each channel needs:

- channel ID
- channel type
- authentication method
- allowed principals
- allowed operations
- network exposure setting
- audit visibility
- rate limits
- message retention policy

Remote channels should default to narrower permissions than local channels.

## 12. Security Architecture

Security is a core architecture layer, not a plugin.

### 12.1 Trust Boundaries

Trust boundaries:

- user to channel
- channel to API
- API to daemon internals
- agent runtime to provider
- agent runtime to tool broker
- tool broker to local system
- plugin host to plugin
- provider router to external provider
- memory manager to retrieved memory

Every boundary should have explicit data contracts and logging.

### 12.2 Policy Enforcement Points

Policy should be enforced at:

- API request entry
- task creation
- agent run creation
- context assembly
- tool request
- provider request
- memory read
- memory write
- artifact read
- plugin load
- channel send
- recovery resume

### 12.3 Secrets

Secrets should be stored outside prompts and ordinary memory.

Secret rules:

- Agents receive secret references, not raw secrets, unless explicitly allowed.
- Tools resolve secret references at execution time.
- Secret use is recorded as metadata without leaking secret values.
- Secret scopes are tied to principals, plugins, tools, and services.
- Secret rotation and revocation should be possible.

### 12.4 Risk Classes

Actions should be classified by risk:

- harmless read
- sensitive read
- local write
- destructive local write
- network read
- network write
- service mutation
- credential access
- privileged command
- irreversible operation

Policy can use risk class to require approval or stronger profiles.

## 13. Context Architecture

### 13.1 Context Sources

Potential sources:

- current user message
- session history
- task event summary
- recent task timeline
- active plan
- artifacts
- tool outputs
- workspace files
- workspace memory
- long-term semantic memories
- long-term lexical memories
- daily diary
- channel metadata
- plugin-provided context
- system policy summaries
- agent role instructions
- skill instructions

### 13.2 Context Selection

Context selection should consider:

- relevance
- recency
- source authority
- namespace
- sensitivity
- confidence
- token cost
- provider context limit
- task phase
- agent role
- validation requirements

### 13.3 Context Compaction

Compaction should:

- preserve decisions, constraints, tool results, and unresolved issues
- avoid summarizing away safety-critical facts
- link compacted summaries to source events
- record compaction prompts, outputs, and metadata as artifacts
- allow validator agents to inspect compacted summaries and source evidence

### 13.4 Context Inspection

Users should be able to inspect:

- what was included
- what was excluded
- why it was included or excluded
- source references
- sensitivity labels
- token estimates
- compaction history

This matters for debugging wrong answers and preventing memory contamination.

## 14. Memory Architecture

### 14.1 Namespaces

Suggested namespace dimensions:

- principal
- workspace
- project
- agent
- channel
- plugin
- sensitivity
- retention policy

Namespaces let single-user Mealy behave safely today and support multi-user later.

### 14.2 Memory Lifecycle

```text
proposed
  -> accepted
  -> indexed
  -> retrieved
  -> revised
  -> expired
  -> deleted
```

Sensitive or user-preference memory should generally pass through a review step.

### 14.3 Memory Retrieval

Retrieval should combine:

- semantic vector search
- lexical search
- structured filters
- recency ranking
- namespace filtering
- sensitivity filtering
- confidence filtering

Retrieval output should include provenance and scores. The context compiler decides final inclusion.

### 14.4 Memory Correction

Users should be able to:

- inspect memory
- delete memory
- mark memory stale
- correct memory
- prevent memory from being used for certain task types
- export memory
- rebuild indexes

## 15. Plugin Architecture

Plugins extend Mealy, but they do not own Mealy.

### 15.1 Plugin Types

Plugin capabilities:

- tool provider
- channel provider
- memory source
- LLM provider
- skill provider
- artifact renderer
- notification provider
- admin panel provider

### 15.2 Plugin Permissions

Plugin permissions should be explicit and reviewable:

```text
filesystem.read
filesystem.write
network.request
command.run
secret.read
memory.read
memory.write
channel.send
task.read
task.write
artifact.read
artifact.write
provider.call
```

### 15.3 Plugin Execution

Execution options:

- trusted in-process first-party plugin
- supervised child process
- containerized plugin
- remote plugin endpoint

The architecture should support child-process plugins early, even if the first version implements only first-party plugins.

## 16. API Concepts

The exact API format can be decided later. This section records the conceptual operations that must exist.

### 16.1 Task API

```text
create_session
create_task
send_message
interrupt_task
pause_task
resume_task
cancel_task
list_tasks
get_task
stream_task_timeline
get_task_artifacts
request_validation
```

### 16.2 Approval API

```text
list_pending_approvals
get_approval
approve_action
deny_action
approve_once
approve_with_rule
expire_approval
```

### 16.3 Memory API

```text
search_memory
get_memory
propose_memory
accept_memory
reject_memory
edit_memory
delete_memory
reindex_memory
```

### 16.4 Admin API

```text
health
readiness
list_agents
list_providers
list_plugins
list_channels
list_running_tasks
list_queues
list_locks
list_recent_failures
run_recovery_scan
backup_state
export_data
```

## 17. Persistence Model

The storage technology can evolve. The logical model should remain stable.

### 17.1 Suggested Initial Storage

For a single-user local daemon:

- SQLite for relational state, projections, config metadata, event index, and queue state.
- Filesystem content-addressed storage for large artifacts.
- Local vector store for embeddings.
- Full-text search index for lexical memory and logs.

SQLite is a strong default for a local daemon because it is durable, inspectable, easy to back up, and simple to operate.

### 17.2 Ledger and Projections

The event ledger is authoritative. Projections are query optimizations.

```text
events table
  immutable event envelopes and compact bodies

projection tables
  current task state
  timeline entries
  pending approvals
  active runs
  health snapshots
  artifact index
  memory metadata
```

Projections should be rebuildable from events.

### 17.3 Migrations

Migrations must handle:

- database schema
- event schema versions
- projection schema
- plugin manifest schema
- memory record schema
- config schema
- artifact metadata schema

The daemon should refuse to start normally if required migrations fail.

## 18. Validation Architecture

Validation should be a first-class part of task completion.

### 18.1 Validator Inputs

Validator receives:

- original user request
- explicit success criteria
- final answer draft
- relevant artifacts
- relevant tool outputs
- task timeline summary
- constraints
- known risks
- validation rubric

Validator should not receive:

- producer agent hidden reasoning
- irrelevant raw context
- unfiltered memory from the producer agent

### 18.2 Validation Outcomes

```text
passed
needs_revision
failed
inconclusive
waived_by_user
```

For low-risk tasks, validation can be lightweight. For high-risk or side-effecting tasks, validation should be stricter.

### 18.3 Validation Rubrics

Rubrics should be task-specific:

- coding: tests, diffs, scope, regressions, style, security
- research: source quality, recency, citation coverage, uncertainty
- service operation: intended service changed, no unintended mutation, rollback path
- file operation: correct files touched, no unrelated edits, backup if needed
- memory write: source, accuracy, sensitivity, retention

## 19. Recovery and Replay

### 19.1 Startup Recovery

On startup:

1. Open database.
2. Acquire daemon lock.
3. Check migrations.
4. Rebuild or verify projections.
5. Scan incomplete tasks.
6. Classify each incomplete task.
7. Requeue safe tasks.
8. Mark ambiguous tasks as waiting for user.
9. Resume channel workers.
10. Publish recovery summary.

### 19.2 Idempotency

Side-effecting tool calls need:

- stable tool call ID
- idempotency key
- precondition record
- execution start event
- execution result event
- artifact references
- recovery behavior

Replay mode should never execute side effects unless explicitly configured. It should use recorded outputs by default.

### 19.3 Debug Replay

Replay can be used to answer:

- why did the agent do this?
- what context was included?
- which tool output led to the decision?
- which policy allowed the action?
- did recovery duplicate anything?
- did validation miss anything?

## 20. Operational UX

A reliable personal daemon needs good operational UX.

### 20.1 Owner Views

The owner should be able to see:

- current active tasks
- queued tasks
- paused tasks
- stuck tasks
- pending approvals
- recent tool calls
- recent memory writes
- provider health
- plugin health
- channel status
- storage usage
- recovery status

### 20.2 Approval Inbox

Approvals should be visible from every channel where the owner has permission.

Approval records should show:

- requested action
- requesting agent
- task
- risk class
- target resource
- arguments summary
- expected effect
- policy reason
- allow once / deny / create rule options

### 20.3 Task Timeline

Timeline entries should be concise but expandable:

- user message
- agent planning
- context compiled
- tool requested
- approval required
- tool completed
- artifact created
- validation started
- validation result
- final answer

The timeline is the shared user-facing representation of task state.

## 21. First-Party Built-Ins

Suggested first-party built-ins:

### 21.1 Tools

- file read
- file write through patch or structured write
- directory listing
- search
- shell command execution
- HTTP request
- local service status
- artifact creation
- memory search
- memory proposal
- approval request

### 21.2 Skills

- codebase exploration
- code editing
- test running
- GitHub workflow
- Obsidian workflow
- Nextcloud workflow
- service debugging
- research synthesis
- memory curation
- validation

### 21.3 Agents

- coordinator
- executor
- validator
- summarizer
- memory curator
- recovery assistant

The first implementation can start with fewer built-ins, but these categories should shape interfaces.

## 22. Configuration Architecture

Configuration should be explicit, versioned, inspectable, and separable from durable runtime state.

### 22.1 Configuration Categories

Suggested config categories:

- daemon settings
- API settings
- channel settings
- principal and identity mappings
- agent profiles
- provider profiles
- policy profiles
- tool settings
- plugin settings
- memory settings
- storage settings
- observability settings
- backup settings

### 22.2 Configuration Sources

Potential sources:

- static files under `~/.config/mealy/`
- environment variables for deployment-specific overrides
- local admin API for runtime changes
- channel-specific setup flows
- plugin manifests and plugin config files

The daemon should record effective configuration at startup as a system event, excluding secret values.

### 22.3 Configuration Schema

Every config file should carry:

```text
schema_version
config_type
config_id
owner_principal_id
created_at
updated_at
body
```

Provider and plugin config should distinguish public settings from secret references.

### 22.4 Configuration Changes

Configuration changes should:

- validate against schema
- record who made the change
- record before/after metadata where safe
- trigger affected components to reload
- require approval for high-risk changes
- be reversible where practical

Examples of high-risk changes:

- enabling network access
- granting plugin filesystem write access
- changing a provider to a remote model for private tasks
- granting service-admin permissions
- disabling validation for high-risk tasks

## 23. Budgets and Limits

Budgets prevent runaway tasks and make agent behavior predictable.

### 23.1 Budget Dimensions

Mealy should support limits for:

- wall-clock time
- LLM tokens
- provider cost
- tool call count
- network call count
- parallel agent count
- memory retrieval count
- artifact storage size
- command runtime
- retry count

### 23.2 Budget Scope

Budgets can apply to:

- principal
- channel
- session
- task
- workflow
- agent profile
- provider
- tool
- plugin

### 23.3 Budget Policy

When a budget is reached, policy can:

- stop the task
- pause and ask the user
- degrade to a cheaper provider
- reduce context size
- disable parallelism
- skip optional validation
- request explicit approval to continue

Budget exhaustion should be visible in the task timeline.

## 24. Data Retention, Backup, and Export

Mealy will accumulate sensitive local state. Retention and export need to be part of the architecture early.

### 24.1 Retention Classes

Suggested retention classes:

- ephemeral: safe to delete after task completion
- short_term: keep for recent task continuity
- long_term: keep until user deletes or retention expires
- audit: keep for security and recovery
- sensitive: keep with stricter access and shorter default retention
- pinned: keep until explicitly unpinned

### 24.2 Backup

Backups should include:

- config
- event ledger
- projections or rebuild instructions
- artifacts
- memory records
- memory indexes or reindex instructions
- plugin manifests
- provider and channel metadata

Backups should not include raw secrets unless the user explicitly chooses encrypted secret backup.

### 24.3 Export

Export should support:

- full local archive
- task bundle
- memory bundle
- artifact bundle
- audit bundle
- human-readable report

Task bundle export is especially useful for debugging because it can include events, context bundle metadata, artifacts, tool outputs, validation evidence, and final result.

## 25. Failure Modes

The architecture should make common failures visible and recoverable.

### 25.1 Expected Failure Types

Expected failures:

- provider unavailable
- provider rate limited
- malformed provider response
- context too large
- tool denied by policy
- tool failed
- approval expired
- plugin crashed
- channel disconnected
- daemon restarted
- migration failed
- projection corruption
- artifact missing
- memory index stale
- validation failed
- recovery ambiguity

### 25.2 Failure Handling Rules

General rules:

- Failures become events.
- User-visible failures appear in the task timeline.
- Retriable failures use bounded retries.
- Side-effecting operations are not retried unless idempotency is known.
- Provider failures can trigger fallback if policy allows.
- Plugin failures should degrade only affected capabilities.
- Projection failures should trigger rebuild from the event ledger.
- Ambiguous recovery should stop and ask the user.

### 25.3 Degraded Mode

Mealy should be able to run in degraded mode when optional systems are unavailable.

Examples:

- vector memory unavailable: continue with lexical and recent task context
- remote provider unavailable: fall back to local provider if configured
- Discord channel unavailable: keep local CLI/API usable
- plugin failed: disable plugin tools and continue core daemon
- projection stale: rebuild and temporarily serve slower direct ledger queries

## 26. Testing and Verification Strategy

Testing should match the architecture boundaries.

### 26.1 Unit Tests

Unit tests should cover:

- state machine transitions
- policy decisions
- config validation
- provider request normalization
- tool argument validation
- context item ranking
- memory record lifecycle
- event envelope validation
- migration functions

### 26.2 Integration Tests

Integration tests should cover:

- task creation through API
- event append and projection update
- timeline streaming
- tool request through policy and broker
- approval flow
- artifact creation
- provider call with mocked provider
- memory proposal and retrieval
- validation pass/fail
- daemon restart and recovery

### 26.3 Scenario Tests

Scenario tests should cover realistic workflows:

- read-only research task
- code edit task with file ownership and validation
- task interrupted by user and resumed
- daemon restarted during tool execution
- provider fails and fallback is used
- plugin denied by policy
- memory write requires review
- parallel agents attempt conflicting writes

### 26.4 Replay Tests

Replay tests should verify:

- event logs can rebuild projections
- context bundles can be reconstructed or explained
- recorded tool outputs are used instead of re-executing side effects
- idempotency keys prevent duplicate mutation
- recovery classification is stable

### 26.5 Security Tests

Security tests should verify:

- channels cannot bypass policy
- agents cannot directly execute tools
- plugins cannot access undeclared capabilities
- secrets are not inserted into prompts by default
- remote channels get narrower defaults than local channels
- memory namespace boundaries are enforced
- artifact access checks are enforced

## 27. Suggested Development Phases

This is not an implementation plan, but it records a plausible architecture path.

### Phase 0: Architecture and Data Model

- Finalize requirements.
- Finalize module boundaries.
- Define event envelope.
- Define core task/session/run/tool/approval/artifact schemas.
- Define policy decision model.
- Define provider interface.

### Phase 1: Minimal Local Daemon

- `mealyd` local daemon.
- SQLite state.
- event ledger.
- task creation.
- local CLI channel.
- basic timeline stream.
- one provider integration.
- simple coordinator/executor loop.
- read-only and workspace-write policy profiles.

### Phase 2: Tool and Policy Runtime

- tool broker.
- file and shell tools.
- approval inbox.
- artifact store.
- idempotency for side effects.
- task interruption.
- basic recovery after restart.

### Phase 3: Context and Memory

- context compiler.
- workspace memory.
- task summaries.
- memory proposal/review.
- lexical search.
- semantic memory.
- context inspector.

### Phase 4: Multi-Agent and Validation

- agent profiles.
- child agent runs.
- scheduler concurrency.
- independent validation.
- validation rubrics.
- workspace locks.
- conflict handling.

### Phase 5: Channels and Plugins

- web UI.
- Discord channel.
- plugin manifests.
- first-party plugins.
- plugin health.
- secrets manager.

### Phase 6: Hardening

- backup/export/import.
- migrations.
- replay/debug mode.
- health dashboard.
- stricter plugin isolation.
- multi-user readiness review.

## 28. Open Design Questions

These should be resolved before implementation planning.

1. Primary implementation language and runtime.
2. Whether `mealyd` should expose HTTP on loopback, Unix socket RPC, or both.
3. Initial storage stack: SQLite only, or SQLite plus separate vector/search stores from day one.
4. Exact event schema and whether event bodies are JSON, typed records, or hybrid.
5. How strict validation should be for small conversational tasks.
6. Whether memory writes are automatic, approval-based, or policy-dependent.
7. How much plugin isolation is required for v1.
8. Which LLM provider should be the first reference implementation.
9. Whether the first UI should be CLI, TUI, or local web.
10. Which built-in tools are safe enough for the first vertical slice.

## 29. Recommended First Vertical Slice

The first vertical slice should prove the architecture without building every feature.

Recommended slice:

```text
mealyctl
  -> mealyd API
  -> create task
  -> append event
  -> compile simple context
  -> call one LLM provider
  -> request one safe tool
  -> apply policy
  -> store artifact
  -> run lightweight validation
  -> complete task
  -> show timeline
  -> restart daemon
  -> recover visible task state
```

This proves:

- daemon model
- API boundary
- task lifecycle
- event ledger
- projection
- provider interface
- tool broker
- policy check
- artifact storage
- basic validation
- recovery foundation

It intentionally does not start with plugins, Discord, vector memory, or parallel agents. Those features depend on the same foundations and become safer once the core runtime is real.

## 30. Summary

Mealy should be built as a local agent operating system:

- a daemon owns state
- channels are clients
- agents are native runtime instances
- tools are mediated side-effect gateways
- policy is central
- context is compiled and inspectable
- memory is governed
- validation is independent
- events make recovery and replay possible

The architecture should stay simple enough for a personal daemon, but rigorous enough that future multi-user support, plugins, remote channels, and complex multi-agent workflows do not require redesigning the foundation.
