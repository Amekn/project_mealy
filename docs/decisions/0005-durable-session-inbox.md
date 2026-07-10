# ADR 0005: Runtime-owned durable session inbox

Status: Accepted

## Context

OpenClaw queues concurrent messages in process. Eve explicitly asks channels/apps to queue bursts. That makes loss and ordering depend on transport behavior and violates Mealy's requirement that channels remain thin.

## Decision

Every accepted channel input is inserted into a per-session SQLite inbox with a monotonic sequence and dedupe key before acknowledgement. The core supports `queue`, `steer_at_boundary`, and `interrupt_then_queue` promotion modes.

Channel-local buffers may absorb transport pressure only until admission; they are not acknowledged durable work.

## Consequences

- All channels share ordering and recovery semantics.
- Backpressure and queue limits are core policy.
- Session drivers need promotion and cancellation state machines.
- Accepted input survives daemon and channel restarts.
