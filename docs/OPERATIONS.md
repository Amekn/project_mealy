# Operations

Mealy's release-one control plane is a single owner-private home, one `mealyd` process, an
authenticated loopback API, and `mealyctl`. Operational commands use the same authorization and
bounded blocking pool as normal clients; they do not bypass canonical state.

## Install and start

Run directly:

```sh
mealyd --home "$HOME/.mealy"
```

Or install an owner-level service definition:

```sh
mealyctl --home "$HOME/.mealy" service install
```

The installer atomically writes an owner-private systemd user unit on Linux or LaunchAgent on
macOS and prints the explicit activation command. Reinstalling first preserves a `.previous`
rollback copy. Unsupported service-manager platforms fail explicitly instead of emitting a weaker
unit. The daemon itself remains portable; arbitrary worker execution is separately fail-closed by
the sandbox profile reported by `doctor`.

## Health, diagnostics, and traces

```sh
mealyctl --home "$HOME/.mealy" health
mealyctl --home "$HOME/.mealy" status
mealyctl --home "$HOME/.mealy" metrics
mealyctl --home "$HOME/.mealy" doctor
```

`status` exposes queue depth, non-terminal runs, active leases, pending approvals, unknown effects,
outbox state, provider/extension health, channels, storage usage, schema version, the effective
configuration/policy digests, and recent durable failures. `metrics` is the stable JSON gauge view.
Every HTTP request receives an `x-request-id`; request spans log method, URI, status, and latency.
Agent/provider/tool spans and durable events retain task/run/attempt, correlation, causation, and
policy identities. `doctor` also executes the configured routing contract with an explicit
same-trust fallback and rejects a lower-trust candidate.

`doctor` runs full SQLite and foreign-key checks, inspects artifact storage and private
permissions, and reports each sandbox profile as `enforceable` or `denied` with a reason. Release
one currently enforces `observe` and `workspace_write` through Bubblewrap on a conforming Linux
host. `networked`, `service_operator`, and `full_trust` are denied. macOS and Windows control planes
compile in CI; worker profiles remain explicitly denied until their native adapters exist.

## Safe mode and drain

Start query-only recovery mode with:

```sh
mealyd --home "$HOME/.mealy" --safe-mode
```

Safe mode does not start promotion, provider, effect, lease-reaper, or outbox workers. It rejects
canonical mutations and signed ingress while retaining queries, diagnostics, complete backup,
restore verification, export, and drain.

Begin bounded graceful drain with:

```sh
mealyctl --home "$HOME/.mealy" drain
```

Admission closes before the server and workers drain. A clean path classifies interrupted work,
records terminal process evidence, checkpoints SQLite, removes `connection.json`, and exits zero.
The configured deadline (100 ms through five minutes) or a second signal exits with status 2. A
private forced-shutdown marker is synced before exit and reconciled into `daemon_run_record` if the
SQLite mutex was unavailable.

## Task control ordering

All controls require the exact current task revision:

```sh
mealyctl --home "$HOME/.mealy" task pause TASK_ID --expected-revision REVISION
mealyctl --home "$HOME/.mealy" task resume TASK_ID --expected-revision REVISION
mealyctl --home "$HOME/.mealy" task cancel TASK_ID "owner requested stop"
```

`queue` preserves FIFO order behind the active turn. `steer-at-boundary` attaches the accepted
input to the active run's next durable safe boundary. `interrupt-then-queue` records cancellation
before leaving the accepted input at the queue head. Pause fences any active lease and classifies
its provider/tool/effect boundary in the same transaction before the task becomes `paused`;
resume derives `queued`, `running`, or `waiting` from that durable run boundary. Cancellation is
cooperative at boundaries and becomes forceful only after the configured drain/grace deadline.
Stale revisions and stale worker fences are rejected.

## Backup and restore verification

Create a complete immutable backup:

```sh
mealyctl --home "$HOME/.mealy" backup nightly-2026-07-11
mealyctl --home "$HOME/.mealy" restore-verify nightly-2026-07-11
```

The online SQLite backup covers canonical state, journal, extension manifests, memory, and artifact
metadata. Every referenced content-addressed artifact and the validated non-secret configuration
is copied and covered by `manifest.json` with exact size and SHA-256 evidence. Publication is an
atomic directory rename; an existing backup name is never replaced.

Secrets are excluded by default. To opt in, pass the encryption passphrase through an environment
variable rather than the process argument list:

```sh
export MEALY_BACKUP_PASSPHRASE='a long owner-chosen passphrase'
mealyctl --home "$HOME/.mealy" backup nightly-secret --include-secrets
mealyctl --home "$HOME/.mealy" restore-verify nightly-secret \
  --passphrase-env MEALY_BACKUP_PASSPHRASE
```

The secret archive contains `identity.json` and active brokered channel keys under Argon2id-derived
XChaCha20-Poly1305 authenticated encryption. The passphrase is never persisted. Verification first
checks every manifest file, copies the archive into a new isolated temporary home, authenticates
and decrypts secrets when present, opens the copied database, runs full integrity/foreign-key/schema
checks, validates all canonical artifact files, and proves that decrypted identity is active in the
restored registry. It never replaces the active home.

## Complete and scoped export

A secret-free complete archive and owner-scoped portable JSON bundles are available:

```sh
mealyctl --home "$HOME/.mealy" export complete-2026-07-11 complete
mealyctl --home "$HOME/.mealy" export audit-2026-07-11 audit
mealyctl --home "$HOME/.mealy" export task-case task --selector TASK_ID
mealyctl --home "$HOME/.mealy" export artifact-case artifact --selector ARTIFACT_ID
mealyctl --home "$HOME/.mealy" export memory-case memory --selector WORKSPACE_IDENTITY
```

Complete export is an atomic directory containing an online canonical SQLite snapshot, validated
non-secret configuration, every referenced artifact, and an exact digest manifest. Audit export
deduplicates all owner-visible session timelines by global cursor and includes the operational
snapshot. Task export is a validated recorded-only replay graph. Artifact export carries authorized
metadata plus base64url content. Memory export includes every revision and tombstone in the exact
workspace. Bundles are private, immutable, atomically published, and returned with byte size and
SHA-256 evidence.

## Retention, deletion, and garbage collection

`config.json` is schema-versioned and includes minimum ages by data class and sensitivity plus
principal, task, channel-binding, and legal-hold selectors. Memory records additionally carry their
own governed retention state. Release one never physically erases canonical journal/history through
the garbage collector.

The same configuration carries enforceable agent-loop budgets, per-session pending-input capacity,
and concurrency ceilings for daemon, principal, session, provider, extension, agent role, and
resource class. New tasks receive an immutable copy of the effective budget. Lease claims enforce
principal/session/role capacity transactionally; worker, provider, extension, and resource guards
enforce the remaining dimensions. Values outside their bounded schema fail startup validation.

```sh
mealyctl --home "$HOME/.mealy" garbage-collect
```

GC holds the canonical store while collecting its referenced artifact digests. It preserves every
referenced blob regardless of age and erases only configured-age temporary or unreferenced files.
User-visible memory deletion remains an immutable tombstone; backups and audit history retain what
their manifest/retention constraints require.

## Configuration activation and rollback

Only validated non-secret `config.json` is activated, and its canonical digest is recorded on every
daemon start. Release one has no runtime reload path: high-risk settings change only through an
explicit owner edit followed by a restart. Every successful effective configuration is archived as
`config-history/<DIGEST>.json`, so the prior successful value remains available.

Rollback requires the daemon to be stopped, an exact archived digest, and explicit approval:

```sh
mealyctl --home "$HOME/.mealy" config rollback CONFIG_DIGEST --approve
```

The command refuses a live home, preserves the replaced configuration, atomically restores the
digest-pinned archive, and requires a restart. The subsequent daemon start validates and records the
restored digest.

## Migrations, downgrade, and corrupt storage

Before any supported forward migration, startup read-only inspects the old schema and publishes an
online database/config snapshot under `migration-backups/`. Migrations and version markers run in
one immediate SQLite transaction, preserve canonical history, and have forward tests from each
phase snapshot. The current release-one schema version is 11.

There is no in-place automatic downgrade. Stop the daemon, retain the migrated home, and use the
matching older binary with the pre-migration `state.sqlite3`; content-addressed artifacts were not
modified by migration. For destructive future changes, use an explicit export/transform/import
plan rather than opening a newer database with an older binary.

If read-only inspection or normal open detects corrupt SQLite storage, startup copies the original
database plus every existing WAL/SHM sidecar into a timestamped owner-private `forensics/` directory
with a digest manifest. It does not truncate, rebuild, replace, or publish readiness. Repair or
restore begins only after that evidence exists.
