# ADR 0009: One SQLite writer, bounded snapshot readers, and bundled context evidence

Status: Accepted

## Context

Mealy is a single-owner local daemon whose canonical transitions, journal, leases, budgets, and
outbox must remain atomic. The first implementation placed one `SqliteStore` behind one
process-wide mutex. That preserved transaction order, but it also made every API history query,
recorded replay, scheduler scan, cancellation probe, and worker transition wait for the same
connection.

Retained long-soak databases exposed two independent amplifiers:

- a long compound read held the only connection and blocked unrelated canonical mutations; and
- every model attempt inserted the complete ordered context projection as many relational item
  rows, including the same bounded conversation prefix and two large indexes.

At 3.1 GB, eight simultaneous retained-history turns still completed safely after provider timing
was corrected, but one writer waited 14.05 seconds. Retrying another long soak without changing
these shapes would test the same bottleneck again.

## Decision

The daemon uses a process-local `RuntimeStore` with these explicit lanes:

1. One canonical writer connection serializes all mutations. Application transactions retain
   `BEGIN IMMEDIATE`, fencing, journal, outbox, and durability semantics.
2. A bounded pool of read-only, `query_only` connections serves compound queries. Each borrowed
   reader opens one deferred WAL snapshot and rolls it back before returning to the pool.
3. Reader capacity is derived from maximum concurrent daemon agent runs plus four control-plane
   readers. Exhaustion backpressures the bounded blocking caller; cancellation probes use a
   non-blocking read attempt and never interpret pool contention as cancellation.
   A single control-plane request must not internally fan out beyond that reserve. In particular,
   the dashboard composes its database-backed snapshot projections serially so one refresh consumes
   at most one reader at a time while every agent worker is active.
4. External provider, tool, browser, channel, and extension I/O occurs without holding a database
   connection. Provider attempt timeouts begin only when their durable preparation can commit;
   the overall run budget remains anchored before compilation and writer wait.
5. Schema 16 stores each new context manifest as one bounded canonical JSON object, compressed
   only through the existing digest-preserving durable envelope. The row records the logical
   digest and independently checked operational summaries. Sparse relational rows retain artifact
   scope, compaction identity, and governed-memory citations. Legacy row-per-item manifests remain
   immutable, readable, and replayable without an eager multi-gigabyte rewrite.
6. Full SQLite, FTS5, and foreign-key integrity diagnostics run once at the quiescent
   `RuntimeStore` startup boundary, and again for backup, restore, soak, and release validation.
   Live readiness and doctor requests inspect schema/connection invariants without invoking
   `quick_check` or `integrity_check` against concurrent FTS writes.

The admin metrics projection exposes cumulative writer/reader waits and maximum observed wait in
microseconds. These are diagnostic process-lifetime measurements, not portable service-level
guarantees.

## Alternatives considered

### Keep one mutex and increase deadlines

Rejected. This hides head-of-line blocking, consumes run budgets, and makes correctness depend on
database age. It does not address cancellation, status, or replay interference.

### Use a generic multi-writer pool

Rejected for the local SQLite adapter. WAL permits concurrent readers but still has one writer.
Multiple application writers would replace explicit queueing with `SQLITE_BUSY` races and retry
policy while weakening the single audited mutation boundary.

### One actor or database per session

Rejected for release one. It fragments global admission, schedules, ownership, resource claims,
usage, backup, migration, and journal ordering across authorities. An actor may schedule access to
one writer, but it does not remove manifest write amplification and would add an asynchronous
request protocol inside the daemon.

### Require PostgreSQL or another server database

Rejected for the supported single-owner installation. It materially increases setup, secrets,
backup, upgrade, and recovery burden. A future infrastructure adapter may use a server database
for multi-owner or remote deployments without changing application ports.

### Eagerly normalize or rewrite all legacy context rows

Rejected. A multi-gigabyte migration would create a long, failure-prone first start and needlessly
change already replayable evidence. Schema 16 is append-forward: old evidence remains in place and
new writes use the bounded bundle representation.

## Consequences

- Long history queries and replay no longer occupy the mutation lane.
- Compound API reads observe a stable snapshot instead of a mixture of revisions.
- Canonical mutations remain serialized and auditable; there is no concurrent-writer ambiguity.
- New context persistence uses one primary bundle insert rather than dozens of repeated item and
  index inserts. Sparse provenance remains relational and foreign-key constrained.
- Long-lived snapshots can delay WAL checkpoint truncation. Read operations therefore remain
  bounded, the pool is finite, and operators monitor reader wait and database/WAL growth.
- A live readiness response proves current schema and connection invariants plus the successful
  quiescent startup gate. It does not pretend that a deep integrity scan remains instantaneous or
  atomic after subsequent writes; final soak and release evidence still checks the stopped store.
- Legacy databases do not shrink automatically. Backup/restore and an explicit future offline
  compactor may reclaim historical layout space, but ordinary startup never rewrites it.
- Any future query path must choose `read`, `try_read`, `write`, or `try_write` deliberately. A
  generic process-wide `lock()` is not part of the runtime interface.
