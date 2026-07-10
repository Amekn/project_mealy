# Mealy

Mealy is a local-first, self-contained agent runtime for a reliable personal AI assistant.

This repository is at the **architecture baseline** stage. It contains the researched requirements, architecture, threat model, decisions, implementation plan, and the first executable domain/storage foundation. It is not yet a usable agent daemon.

## Start here

- [`REQUIREMENTS.md`](REQUIREMENTS.md) — normative requirements and release-one acceptance boundary.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — practical design and requirement traceability.
- [`docs/research/REFERENCE_SYSTEMS.md`](docs/research/REFERENCE_SYSTEMS.md) — pinned review of all eight reference systems.
- [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) — vertical phases and exit gates.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — trust boundaries and abuse cases.

## Repository map

- `apps/mealyd`: trusted daemon composition root.
- `apps/mealyctl`: local client and administration CLI.
- `crates/mealy-domain`: pure IDs and lifecycle state machines.
- `crates/mealy-application`: use cases, recovery planning, and ports.
- `crates/mealy-infrastructure`: SQLite, artifacts, processes, providers, and OS adapters.
- `crates/mealy-protocol`: versioned transport DTOs.
- `crates/mealy-api`: authenticated HTTP/SSE adapter.
- `crates/mealy-testkit`: deterministic scenario support.
- `docs`: design, decisions, research, and verification strategy.
- `schemas`: reviewed external contract fixtures.
- `tests`: integration and public-API scenarios.

## Development

The workspace is pinned by `rust-toolchain.toml`.

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

The current code now establishes the Phase 0 durability foundation and the first Phase 1 vertical
proof. Domain state machines have generative invariant tests; the initial schema covers sessions,
inbox entries, tasks, runs, fenced leases, effects, the journal, and the outbox; and file-backed
SQLite runs with WAL, foreign keys, and an explicit durability policy. An authenticated ownership
context can create a session and admit a bounded input atomically with its journal fact and
acknowledgement outbox row. Reopening the database and retrying the delivery returns the original
receipt without duplicating work.

Input promotion, scheduler operations, the local HTTP/SSE boundary, and the agent/provider loop are
not implemented yet. See the implementation plan before adding features.

## Reference clones

The eight research repositories are shallow-cloned outside this worktree at:

```text
../mealy-agentic-references/
```

Their commit pins and licenses are recorded in the research report. They are not build dependencies. The Claude Code mirror has no license and must not be used as a code source.

## License

See [`LICENSE`](LICENSE).
