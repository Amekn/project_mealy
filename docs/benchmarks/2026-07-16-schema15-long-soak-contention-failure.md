# Schema-15 long-soak canonical-store contention failures

Date: 2026-07-16 (Pacific/Auckland)

This is negative pre-release evidence, not a durability result. Neither attempted 24-hour soak
completed and neither produced a promotable `mealy.soak-report.v2` report. Both retained homes and
their `mealy.soak-failure.v1` reports remain available locally for diagnosis; no elapsed time or
completed turn from either attempt is carried into the next release gate.

The original auditable subject was clean commit
`c48394518f06892fce341eb91be5be0e24bfc2d6`, with `mealyd` SHA-256
`649db94894de63fb973c7d2ef7a4749100d5c9b3ca77524a0f8cbfde66c39572`. It reached
round 1,420 after about 15 hours 51 minutes and had completed 11,356 tasks before one task failed.
Its second deterministic-provider attempt was prepared at epoch millisecond `1784126323023`,
dispatched at `1784126324215`, and never committed. At `1784126333276` the run failed with
`agent loop failed: agent execution conflicted with canonical state`. The retained database was
1,948,499,968 bytes and `PRAGMA integrity_check` returned `ok`.

The final candidate then under review was clean commit
`53feae1424e6c22d6000853617b9ed2ce3e1bd94`, with `mealyd` SHA-256
`17170efc716ea9e78c6072b5f924ddf83551305406f6ce55c2d1a273d6ceffd7`. It reached
round 1,144 after 43,732.15 seconds (about 12 hours 9 minutes) and had completed 9,150 tasks before
one task failed. Its immediate `fixture.read` call started at epoch millisecond `1784133545881`
but was interrupted at `1784133553074`; the run summary was
`agent loop failed: read-tool deadline elapsed`. The retained database was 1,567,125,504 bytes and
`PRAGMA integrity_check` returned `ok`.

## Diagnosis

The agent runtime serializes canonical transitions through one mutex-protected SQLite store. The
provider and read-tool worker cancellation probe used a blocking acquisition of that same mutex.
As the append-only histories grew past 1.5 GB under eight concurrent sessions, a worker could
spend several seconds waiting merely to ask whether it was cancelled. The probe then consumed the
tool deadline, while provider completion bookkeeping could be delayed until after the durable
absolute deadline and rejected as a canonical conflict. Running the two observations concurrently
increased host and database contention, but the retained timelines exposed a runtime concurrency
defect that must remain safe under contention.

The correction makes a busy canonical mutex mean “cancellation state temporarily unavailable,”
not “cancelled”; local timeouts and the next canonical transition continue to bound and recheck
work. Provider waits are now capped by the remaining durable absolute deadline, and the provider
completion time is captured immediately at the provider boundary before progress flushing or
canonical-store reacquisition. Poisoned-store and cancellation-query errors still fail closed.

## Post-fix diagnostic

The corrected release binary was run against a copy-on-write clone of the 1.5 GB retained home.
Eight simultaneous turns succeeded first. A dense 22-round, eight-session run then completed all
176 newly admitted turns without pacing: 176 successful runs, 176 successful tools, 176 passed
validations, no retry, and no new failure. New-run latency was 5.622 seconds minimum, 10.791 seconds
mean, and 13.071 seconds maximum while status inspection deliberately added more store pressure.
The clone ended with no nonterminal run, pending input, active lease, or recent failure;
`PRAGMA integrity_check` returned `ok`.

A separate empty-home external-release-binary harness check then completed 680 turns in 121.536
seconds across eight sessions. It exercised four hard restarts, 41 exact duplicate admissions, 21
interrupted-provider recoveries, four read-tool retries, recorded-only replay, final drain, and
integrity checking. The report recorded `ok` integrity and zero nonterminal runs, pending inputs,
active leases, pending approvals, failed outbox entries, unknown effects, or other residue. This
dirty-worktree check binds daemon SHA-256
`1c47ef817b93b0cf0df011d5ad764085cc2280e02c73d9d5554e1a21d6aa45ad`; it validates the corrected
harness path but is not promotable release evidence.

This retained-history diagnostic exercises the reproduced contention boundary but is not the
release soak. The subsequent clean, non-overlapping
[schema-15 release soak](2026-07-16-schema15-release-soak.json) ran
86,425.217 seconds against the audited corrected external package daemon, completed 15,824 turns,
survived 39 hard restarts, recovered 62 interrupted-provider turns and 15 read-tool retries,
passed SQLite integrity and complete recorded-only replay, drained cleanly, and left zero residual
work. The failed durations above remain negative evidence and were not carried into that result.
