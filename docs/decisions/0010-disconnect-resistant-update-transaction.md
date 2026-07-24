# ADR 0010: Disconnect-resistant, health-gated release update transaction

Status: Accepted

## Context

Mealy's archive installer already verifies GitHub workflow provenance, exact tag identity,
checksums, release manifests, state-schema compatibility, and complete declared payload digests.
It atomically activates a new program slot and retains the prior same-schema slot. The daemon also
already provides immutable online backups, bounded graceful drain, owner-service installation,
health, and `doctor`.

Those safe primitives are not yet one production update. A foreground client that performs
`backup -> drain -> install -> start -> health` can be killed when its terminal disconnects,
leaving a healthy but stopped installation. A process crash between package activation and health
verification can also leave an unqualified target active without durable evidence identifying the
recovery step. Re-downloading `latest` after a check would introduce a separate target-selection
race.

The maintained reference systems support the missing shape. OpenClaw hands a running managed
service update to a detached helper outside the daemon process, stages package changes, restarts,
and verifies the resulting service and version. Hermes snapshots state before update and exposes
repair and rollback after an interrupted or unbootable change. Mealy needs the same operator
outcome without adopting mutable source-checkout updates or weakening its attested artifact
boundary.

## Decision

An approved managed-archive update is a restartable transaction with one durable owner:

1. The foreground client performs the ordinary no-mutation attested update check and pins
   `latest` to the exact verified semantic version, target, commit, and state schema.
2. It verifies that `mealy.service` is the active owner user service for the exact current
   executable and home. It copies that already-qualified client into the private transaction
   directory, records its SHA-256, and asks the trusted user service manager to launch that exact
   copy as a dedicated `mealy-update-<transaction-uuid>.service` helper outside both the daemon and
   terminal process trees. Restart never resolves through the newly activated program slot.
3. The helper independently repeats the exact candidate verification. Command-line arguments carry
   only non-secret identity; provider, channel, and backup secrets are never inherited. A private
   advisory lock serializes update helpers for one home, including after process restart.
4. Before closing admission, the helper creates a complete immutable secret-free backup. Same-schema
   program updates do not mutate durable state, so rollback does not require secret extraction or
   home replacement. The backup is recovery evidence for an unrelated storage failure, not the
   normal binary rollback mechanism.
5. A no-follow, mode-`0600`, atomically replaced transaction document records the exact installation,
   candidate, service identity, backup evidence, and monotonic phase:
   `scheduled`, `prepared`, `draining`, `stopped`, `activated`, `starting`, `verifying`,
   `committed`, `aborted`, `rolling-back`, `rolled-back`, or `recovery-failed`.
6. Drain closes admission and lets the daemon checkpoint and exit cleanly. The helper proves both
   service inactivity and home-lock availability before package mutation.
7. The already-pinned candidate is downloaded and verified again, then activated through the
   stable archive manager. A newly selected release is never substituted.
8. The helper starts the owner service and requires bounded liveness, readiness, `doctor`,
   installed-version, target-commit, and complete payload-integrity evidence from the new binaries.
   Only then does it commit the transaction.
9. A pre-mutation verification or backup failure leaves the prior service qualified and records
   `aborted`. Any later failure stops the service and restores or proves the prior same-schema slot
   through the stable manager before re-verifying the service definition, restarting, and requiring
   the same health checks. A successfully recovered update still returns a failed update result
   with explicit evidence; it is never reported as success. If service identity is damaged, the
   prior program slot is restored but remains stopped and `recovery-failed`.
10. The helper service uses restart-on-failure. On restart it reads the transaction document and
    first re-verifies its own canonical path and digest, then derives the next safe action from both
    the recorded phase and independently verified external state. Repeating a completed boundary is
    either idempotent or refused. Ambiguous package or service state becomes `recovery-failed` and
    preserves all slots, backup, journal, and logs for `mealyctl repair`.
11. A committed, aborted, or successfully rolled-back helper unlinks its private executable after
    emitting terminal evidence; its digest remains in the transaction document. Recovery-failed
    helpers are retained for inspected recovery instead of being silently removed.

Native Debian, RPM, and Arch installations remain package-manager-owned. Mealy may check the
attested target and print the exact native command, but it does not mutate `/usr`, wrap the native
transaction, or claim automatic rollback on behalf of those managers.

State-schema changes remain outside this transaction. They use the existing migration snapshot,
home-lock handoff, and cross-schema rollback protocol because a binary-slot exchange alone cannot
safely run an older schema against a newer database.

## Alternatives considered

### Run all update steps in the foreground client

Rejected. Terminal disconnect, client crash, or desktop-session interruption can strand the daemon
between stop and restart. A longer timeout does not create an independent recovery owner.

### Let the daemon replace its own executable and restart itself

Rejected. The old daemon would mutate the package tree that defines its own code and then need to
assert the health of a successor after exiting. This conflates data-plane authority, package
authority, and the recovery supervisor.

### Delegate everything to a shell installer

Rejected as the orchestration boundary. The installer remains the narrow, deterministic slot
mutation primitive, while typed client code owns authenticated backup/drain responses, service
identity, durable phase validation, and health evidence.

### Automatically update native packages

Rejected. A rootless agent must not acquire ambient root authority or compete with APT, DNF, or
Pacman locks, policy, repositories, hooks, and rollback semantics.

### Permit schema-changing automatic updates after taking a backup

Rejected. A backup does not make an older binary compatible with a migrated live home. Cross-schema
activation and rollback retain their separate exact migration transaction.

## Consequences

- An update can finish or recover after the invoking terminal disappears.
- Backup, drain, package activation, service restart, qualification, and rollback have one
  inspectable transaction identity.
- Health is a commit condition rather than optional post-update advice.
- The design adds a small user-service helper, durable update journal, bounded polling, and failure
  injection tests.
- A user service manager is required for one-command archive apply. An unmanaged or stopped daemon
  still receives a verified no-mutation plan and exact manual recovery instructions.
- The first release containing this protocol cannot retroactively make an older client
  disconnect-resistant. It can establish the boundary for every subsequent same-schema update.
