# ADR 0001: Modular monolith with isolated workers

Status: Accepted

## Context

Mealy needs strong internal boundaries but starts as a single-user daemon. Microservices would add deployment, network, and consistency work without product value. A single in-process application, however, must not execute model-proposed commands or untrusted extensions with daemon authority.

Codex demonstrates a capable Rust core and separate execution helpers. OpenClaw, Hermes, OpenCode, and Pi show the operational cost of treating plugins as trusted in-process code.

## Decision

Use one Rust daemon with coarse domain/application/infrastructure/API crates. Run shell/filesystem/browser execution and third-party extensions in supervised child processes behind versioned protocols.

Split a module into a new crate or process only for a distinct trust boundary, compatibility contract, compile/runtime profile, or ownership cadence.

## Consequences

- Local deployment and transactions remain simple.
- Domain invariants stay testable without infrastructure.
- Worker crashes are isolatable.
- RPC and packaging for extensions arrive earlier than an in-process plugin design, by choice.
