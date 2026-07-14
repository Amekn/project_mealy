# Contributing to Mealy

Mealy is an active pre-1.0 release candidate with completed release-one runtime phases and ongoing
competitive capability work. Changes should advance one bounded, end-to-end slice from
[`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md) or
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

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo test --locked --workspace --doc --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --all-features --no-deps
scripts/dashboard-smoke.sh
packaging/test-packaging.sh
cargo audit --deny warnings
cargo_deny=$(scripts/fetch-cargo-deny.sh target/cargo-deny-policy)
"$cargo_deny" check
```

Tests involving time, identifiers, retries, providers, or process exits should use deterministic
fakes from `mealy-testkit`. A feature is not complete until its failure and restart paths are tested.
Run `bash -n` and `shellcheck` for changed shell entry points. Browser-boundary changes must also pass the three
pinned-runtime ignored suites documented in [`docs/TESTING.md`](docs/TESTING.md); provider/channel
credentials are never required for the ordinary deterministic gate.
On Ubuntu/Debian or the stock Ubuntu test container, also run `packaging/test-deb-packaging.sh`;
the native tag jobs additionally reject Lintian error/warning tags and run the system-installing
Debian smoke on disposable runners.
Dependency changes must also pass `cargo-deny` and the pinned reproducible license-notice gate;
the notice is generated from `about.toml` and `packaging/third-party-licenses.hbs`, not edited by
hand.

## Documentation expectations

- Public Rust items need useful rustdoc, including error behavior.
- New external contracts belong under `schemas/` and must be versioned.
- New crash boundaries, trust boundaries, or irreversible decisions require documentation updates.
- Do not copy code or prompts from the unlicensed Claude Code mirror listed in the research report.
