# Gap Matrix

Legend: **Strong** = implemented, documented, and materially tested; **Partial** = present with a narrower scope or important caveat; **Absent/host-owned** = not a runtime guarantee. This is not a quality ranking.

| Capability | OpenClaw | Hermes | OpenCode | Codex | Vercel AI SDK | Eve | Pi | Claude mirror |
|---|---|---|---|---|---|---|---|---|
| Central runtime / thin clients | Strong | Strong | Strong | Strong app-server | Host-owned | Strong | Partial | Strong |
| Durable per-session input FIFO | In-process | Partial/in-process overflow | Strong, evolving | Partial/live queues | Host-owned | Explicitly absent | In-memory | Partial transcript queue records |
| Explicit task/run/effect model | Partial | Partial | Strong session events | Strong thread/turn/item; effect partial | Host-owned | Strong session/turn/step | Partial | Partial |
| Cold restart of active work | Session recovery, not general effects | Soft resume; turn semantics vary | Evolving | Incomplete turn becomes interrupted | Host-owned | Strong at step boundary | Design target | Transcript resume |
| Unknown non-idempotent outcome state | Absent | Absent | Absent | Partial/select tools | Host-owned | Author responsibility | Design target | Absent |
| OS sandbox default | Off by default | Optional backend/wrapper | No sandbox | Strong, platform-specific | Host-owned | Shell sandbox | None | Optional |
| Per-principal authorization | Limited trusted-operator model | Adapter allowlist; equal trust within | Server auth optional | Client/product-specific | Host-owned | Strong route/auth model | Host-owned | Product-specific |
| Out-of-process third-party plugins | No | No | No | Partial via MCP/extensions | Package/host-owned | Authored app code | No | No |
| Versioned generated protocol | Strong schemas | Mixed | Strong TypeScript schemas | Strong JSON Schema/TS | Strong provider specs | Stable HTTP types | Library types | SDK/stream types |
| Context epoch/manifest | Partial reports | Stable prompt tiers | Strong epochs; manifest partial | Strong snapshots; manifest partial | Step messages | Durable snapshots | Turn snapshots | Context UI, no full manifest |
| Governed memory lifecycle | File/plugin memory | Rich but agent-curated | Limited | Two-phase jobs, file outputs | Host/provider-owned | State/provider patterns | File/session | Auto consolidation |
| Independent validation core state | Limited | Background review pieces | Limited | Guardian/review threads | Workflow pattern only | Eval framework | Host-owned | Coordinator guidance |
| Replay without effects | Transcript/debug oriented | Transcript | Durable events evolving | Rollout reconstruction | Host-owned | Step-result replay | Session tree | Transcript replay |
| Local self-contained core | Yes | Yes | Yes | Yes | Library | Workflow world dependency | Yes | Yes |

## Design implications

The matrix supports five high-leverage choices:

1. Build the durable inbox and effect state machine before channels or plugins.
2. Use a transactional canonical store plus journal, not conversation files as the scheduler.
3. Treat OS sandbox and extension process isolation as architecture, not configuration polish.
4. Make context manifests and validation evidence durable domain objects.
5. Test recovery at every dispatch/commit boundary before describing Mealy as durable.
