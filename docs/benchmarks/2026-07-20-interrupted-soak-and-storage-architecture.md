# Interrupted schema-15 soak and schema-16 storage-architecture diagnostic

Date: 2026-07-20 (Pacific/Auckland)

This is negative pre-release evidence followed by a bounded dirty-worktree remediation
diagnostic. It is not a completed soak, not an attestation, and not release evidence.

## Stopped soak

The repeated 24-hour soak for clean commit `02d292c` was stopped at
2026-07-20 18:36:08 +12 at the owner's request. It produced no
`mealy.soak-report.v2`, and none of its elapsed time or completed work is carried into a future
release gate. The retained binary SHA-256 is
`fedf8a9413b646d7399fd04d153ae77a53c98d42d66f03601adf4adc3725590f`.

The retained 331,149,312-byte database returned `ok` from `PRAGMA quick_check`. At interruption it
contained 1,965 succeeded and three running tasks/runs, 3,933 completed, two dispatching, and 89
interrupted model attempts, 1,968 turns, 4,024 context manifests, and 250,202 legacy context-item
rows. Recovery evidence, rather than the interrupted live rows, determines their eventual state.

The context-item table occupied 169,857,024 bytes; its two automatic indexes occupied 23,678,976
and 13,295,616 bytes. Of 248,200 inline item rows, only 3,929 source-content digests were distinct:
63.17 repeated references per distinct digest. Inline text alone occupied 54,135,672 bytes. The
row and index fan-out, not corruption, dominated the database.

## Architectural diagnosis

The daemon used one process-wide mutex around one SQLite connection. Long status/replay/history
reads and canonical transitions therefore blocked each other. Separately, every attempt inserted
the complete context prefix into the growing legacy item table and both indexes.

A first remediation separated one canonical writer from bounded read-only WAL snapshots. On a
3.1 GB retained-home clone, eight simultaneous turns all succeeded, but the legacy context write
path still produced a 14,046,246-microsecond maximum writer wait. Several attempts exhausted their
useful dispatch window and had to be safely retired and replaced. This proved that connection
separation alone was insufficient.

Schema 16 therefore stores each new manifest as one bounded compressed, digest-bound bundle with
sparse relational artifact/compaction/memory references. It does not rewrite legacy evidence.

## Bounded retained-history result

The same 3.1 GB retained clone was migrated from schema 15 to schema 16 through the normal
pre-migration snapshot boundary. Eight simultaneous turns then succeeded with complete
recorded-only replay, zero live replay provider/tool calls, foreign-key violations `0`,
`PRAGMA quick_check` `ok`, and zero nonterminal run/task/lease residue.

Five additional eight-session rounds completed another 40 tasks and 80 model attempts. Complete
recorded-only replay passed for all newest 40 tasks. Across the resulting 96 new bundles, logical
item JSON was 5,164,020 bytes and the stored compressed envelopes were 1,091,419 bytes. Maximum
writer wait remained bounded at 626,334 microseconds; maximum reader wait was 643 microseconds
across three reader-pool waits. Compared with the 14,046,246-microsecond legacy-path observation,
maximum writer wait improved by 22.4 times on this workload.

These numbers are host- and workload-specific. The relevant result is that the exact retained
history shape completed without expired dispatch churn, replay loss, corruption, or residue. A
clean exact-package 24-hour soak is still required after the source, package, protected CI, and
live-provider gates are frozen.

## Final source-shape release-binary check

After the schema-summary columns, runtime refactor, documentation, and strict lint fixes were in
their final source shape, release binary
`9b978688f85ab67ea775848364de2186825cbf8d2fdfa3f549c7f63956bb1f38` was tested against a
fresh reflink clone of the original 3,112,955,904-byte schema-15 database. Normal startup created
the v15-to-v16 rollback snapshot and migrated the clone to schema 16.

Eight simultaneous retained-session tasks all succeeded. Each had exactly two model attempts and
one read-tool call; all eight recorded-only replays were complete with zero live provider or tool
calls. The 16 new manifests represented 1,064 logical items in 861,912 canonical bytes and
181,179 stored bytes. They wrote zero legacy item rows and eight sparse artifact references.

On this cold-start validation, the maximum writer wait was 2,574,522 microseconds and no reader
borrow waited. That is 5.45 times below the 14,046,246-microsecond legacy-path result; all provider
attempts remained dispatchable and completed without retry churn. Individual task completion was
8.12 to 8.33 seconds. After clean drain, schema version was 16, `PRAGMA quick_check` returned
`ok`, foreign-key violations were zero, and nonterminal runs and active leases were both zero.

## Hot diagnostic boundary correction

Protected CI subsequently exposed a separate control-plane issue: a terminal dashboard refresh
could ask `doctor` to run `PRAGMA quick_check` while another connection was settling an FTS5 memory
write. SQLite transiently reported `fts5: checksum mismatch for table "memory_fts"`; immediately
after the daemon stopped, both `quick_check` and `integrity_check` returned `ok` and foreign-key
violations remained zero. Repeated long diagnostics against a hot database were also an
unacceptable refresh-time cost for the retained 3.1 GB home.

The runtime now performs full SQLite, FTS5, and foreign-key verification once before opening the
reader pool or starting workers. Live readiness and doctor paths use bounded online schema and
connection checks; backup, restore, stopped-soak, and release gates retain deep integrity checks.
The dashboard also composes its six projections serially so one refresh never exceeds the
control-plane reader reserve. The real-process dashboard smoke preserves response bodies and
process logs on failure, making any future source-specific 503 actionable.

This is deliberately a bounded dirty-worktree diagnostic, not a replacement for the clean,
exact-package soak gate. Its purpose is to show that the final migration and storage shape address
the reproduced retained-history failure before consuming another day on the formal soak.
