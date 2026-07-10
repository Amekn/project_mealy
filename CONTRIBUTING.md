# Contributing to Mealy

Mealy is at its architecture-baseline stage. Changes should advance one vertical slice from
[`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) without weakening the invariants in
[`REQUIREMENTS.md`](REQUIREMENTS.md).

## Before changing code

1. Identify the requirement IDs and accepted ADRs affected by the change.
2. Add or update an ADR before changing a cross-cutting boundary.
3. Preserve the dependency direction described in [`ARCHITECTURE.md`](ARCHITECTURE.md): domain and
   application code must not depend on infrastructure adapters.
4. Treat every external mutation as an effect with explicit policy, idempotency, and recovery
   semantics.

## Required checks

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Tests involving time, identifiers, retries, providers, or process exits should use deterministic
fakes from `mealy-testkit`. A feature is not complete until its failure and restart paths are tested.

## Documentation expectations

- Public Rust items need useful rustdoc, including error behavior.
- New external contracts belong under `schemas/` and must be versioned.
- New crash boundaries, trust boundaries, or irreversible decisions require documentation updates.
- Do not copy code or prompts from the unlicensed Claude Code mirror listed in the research report.
