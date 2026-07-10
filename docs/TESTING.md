# Testing and Verification

## Test layers

### Domain unit and property tests

Fast, infrastructure-free tests cover state transitions, capability intersections, approval subject hashes, recovery classification, budget arithmetic, resource-claim ordering, and context mandatory-item rules.

Property examples:

- terminal task states never become active;
- aggregate sequence never decreases or duplicates;
- stale fencing tokens never authorize a commit;
- changing any effect subject field changes the approval digest;
- child capabilities are never broader than parent and profile grants;
- non-idempotent unknown effects never classify as automatic retry.

### Storage integration tests

Use real SQLite files, WAL, foreign keys, concurrent connections, busy timeouts, and migrations. Mock repositories cannot prove transaction or locking semantics.

Required checks:

- canonical row + event + outbox atomicity;
- rollback leaves none of the three;
- idempotent duplicate input admission;
- lease claim races and expiry;
- artifact rename/link crash cleanup;
- migration from every supported snapshot;
- backup and restore integrity.

### Process-boundary tests

Spawn the real executor/extension protocol. Verify framing, malformed messages, size limits, cancellation, timeout, stdout/stderr pressure, secret minimization, worker death, and daemon survival.

### Public-API scenarios

Scenarios start `mealyd`, drive versioned API commands, watch SSE, and assert durable database/artifact state only through supported inspection helpers.

## Crash matrix

Each boundary is tested by a deterministic failpoint before and after the action:

| Flow | Failpoints |
|---|---|
| Input | before DB begin; after inbox insert; before commit; after commit before response |
| Lease | after claim; during heartbeat; after expiry; stale result commit |
| Model | before request; after request dispatch; after full response; before normalized commit |
| Effect | before authorization; after approval; before dispatch; after external mutation; before outcome commit |
| Artifact | during stream; after flush; after rename; before/after DB link |
| Outbox | before send; after remote accept; before delivery commit |
| Compaction | after source selection; after generation; before derived record commit |
| Migration | before backup; during migration; before version marker; restore verification |

## Security matrix

- Missing/invalid local API credential.
- Disallowed browser Origin and oversized body.
- Forged channel identity and replayed webhook.
- Cross-principal session/task/artifact/memory access.
- Model text pretending to approve an effect.
- Approval replay with changed arguments, tool version, target, policy, principal, or expiry.
- Sandbox path traversal, symlink, environment, process, and network escape attempts.
- Extension requests undeclared capability/secret/network target.
- Secret canary search across provider payload, logs, journal, artifacts, and worker environment.

## Provider contract suite

Every provider adapter runs the same tests for:

- text and supported modalities;
- streaming and cancellation;
- tool-call normalization and malformed arguments;
- structured output;
- empty/partial responses and provider errors;
- context overflow;
- usage and cost fields;
- retry hints and rate limits;
- cross-provider history projection;
- no credential leakage into normalized records.

## Validation gates

CI initially runs:

```text
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
documentation link/requirement checks
schema compatibility checks
```

Later platform lanes add sandbox conformance and packaged-install scenarios. Live-provider tests are opt-in and cannot be the sole evidence for deterministic behavior.

## Requirements coverage

Scenario names include requirement IDs, for example `REC-014-corrupt-db-backup` and `TOOL-014-unknown-effect-no-retry`. A generated coverage report maps every MUST requirement to one or more tests or an explicit not-yet-implemented status.

Green tests prove only covered requirements. Completion reviews inspect the mapping instead of treating `cargo test` as proof of the entire product.
