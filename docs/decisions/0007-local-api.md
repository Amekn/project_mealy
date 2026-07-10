# ADR 0007: Versioned loopback HTTP/JSON and SSE first

Status: Accepted

## Context

Codex and OpenClaw show the value of typed bidirectional protocols and explicit initialization. Mealy needs a CLI first and a browser UI later. Unix-only sockets would complicate Windows and browser access; a public listener is outside scope.

## Decision

Expose versioned HTTP/JSON commands and queries plus SSE timeline streams on loopback. Require a random local bearer credential, strict Origin policy, bounded bodies, idempotency keys, and cursor resume. Protocol DTOs live separately from domain types and generate OpenAPI.

Unix socket and named-pipe transports may be added later without changing semantics.

## Consequences

- CLI and future web UI share one adapter.
- Local browser security must be tested early.
- Bidirectional approval requests are represented as durable events plus authenticated commands, not transport callbacks.
- Remote binding remains disabled by default.
