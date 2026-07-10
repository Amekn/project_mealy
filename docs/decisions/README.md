# Architecture Decision Records

ADRs record decisions that shape multiple modules or are expensive to reverse. They describe why a decision was made, not just the chosen implementation.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-modular-monolith-and-workers.md) | Modular monolith with isolated workers | Accepted |
| [0002](0002-transactional-journal.md) | Canonical tables plus an atomic transition journal | Accepted |
| [0003](0003-effect-recovery.md) | Explicit unknown outcomes and idempotency-aware recovery | Accepted |
| [0004](0004-security-boundaries.md) | OS sandboxing and out-of-process extensions | Accepted |
| [0005](0005-durable-session-inbox.md) | Runtime-owned durable session inbox | Accepted |
| [0006](0006-context-and-memory.md) | Context manifests, epochs, and governed memory | Accepted |
| [0007](0007-local-api.md) | Versioned loopback HTTP/JSON and SSE first | Accepted |
| [0008](0008-risk-based-validation.md) | Risk-based independent validation | Accepted |

New ADRs use the next four-digit number and begin as `Proposed`. Superseding an ADR keeps the old file and links both directions.
