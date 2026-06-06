# Build Order V0.0.1

Follow the dependency order, not the feature order. Build the boring runtime spine first, then add intelligence.

## Recommended Build Order

1. Rust workspace foundation
    Set up crates, config loading, typed IDs, error handling, tracing, migrations, test layout, CI commands. Do not start with agents or UI.
2. Event ledger
    Build append-only events first. This is Mealy’s source of truth. Include event envelope, schema versioning, timestamps, causation/correlation IDs, task IDs, sensitivity, and idempotency keys.
3. Projection store
    Derive current task state, timelines, pending approvals, active runs, and artifact indexes from events. Projections must be rebuildable from the ledger.
4. Task/session/workflow model
    Implement the state machines for sessions, tasks, agent runs, tool calls, approvals, validation runs, pause/resume/cancel/interruption. Keep this deterministic and heavily tested.
5. Local daemon shell
    Build mealyd as a local service with startup, shutdown, health, readiness, daemon lock, config load, migration check, and recovery scan. At this point it does not need to call an LLM.
6. Local API and mealyctl
    Add a minimal local API and CLI: create task, list tasks, inspect task, stream timeline, interrupt task, approve/deny action. This gives you a way to operate the runtime.
7. Identity and access model
    Even single-user mode should have principals, channel identities, agent identities, permission scopes, and namespaces. Start with one owner user, but do not hardcode “there is only one user” into the storage model.
8. Policy engine
    Add allow/deny/approval decisions before you add real tools. Model read-only, workspace-write, networked, service-user, service-admin, and full-trust profiles.
9. Artifact store
    Store command outputs, generated files, context bundles, validation reports, patches, and logs. Link artifacts back to events.
10. Tool broker
    Add tools only through the broker. Start with safe tools: read file, list directory, search, write artifact. Then add workspace file write. Add shell last.
11. Approval inbox
    Risky tool calls should pause, emit events, and wait for approval. Build this before letting agents mutate anything.
12. Provider interface
    Add the common LLM provider abstraction. Start with one provider only. Keep provider-specific request/response details out of the agent runtime.
13. Minimal agent runtime
    Build one internal executor agent that can receive a task, compile simple context, call a provider, request brokered tools, observe results, and produce a final response.
14. Context compiler
    Add structured context bundles with provenance: user request, task state, selected events, artifacts, files, memories, and instructions. Make it inspectable early.
15. Validation agent
    Add independent validation with fresh context and explicit rubric. Start lightweight, but wire it into task completion from the beginning.
16. Recovery and replay
    Restart the daemon mid-task and prove it can classify incomplete work. Replay should use recorded tool outputs by default, not rerun side effects.
17. Memory system
    Add workspace memory first, then task summaries, then lexical search, then semantic memory. Do not start with vector memory; it depends on context provenance and memory governance.
18. Scheduler and multi-agent orchestration
    Once a single agent loop is reliable, add queues, budgets, child agent runs, parallelism, locks, ownership, and cancellation propagation.
19. Plugins
    Add manifests and first-party plugins after the policy/tool/provider boundaries are stable. Plugin isolation is hard to retrofit.
20. Channels
    Add TUI or local web first, then remote channels like Discord/Slack. Remote channels should come after identity, policy, approvals, and timeline APIs are solid.

## Milestones

The first real milestone should be:

mealyctl -> mealyd -> create task -> append events -> show timeline

The second should be:

task -> policy-checked safe tool -> artifact -> completed task

The third should be:

task -> provider call -> tool request -> approval -> tool result -> validation -> final answer

Do not build memory, plugins, Discord, parallel agents, or a rich UI until those three slices are boring and reliable.