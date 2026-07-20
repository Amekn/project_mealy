# Schema-15 near-deadline provider dispatch failure

Date: 2026-07-20 (Pacific/Auckland)

This is negative pre-release evidence, not a durability result. The attempted 24-hour soak did
not produce a promotable `mealy.soak-report.v2` report, and none of its elapsed time or completed
turns is carried into the next release gate. Its retained home, log, and
`mealy.soak-failure.v1` report remain local for diagnosis.

The auditable subject was clean commit
`d678cd9a5de9564b07330004ae85f76dd58cbd4a`, with `mealyd` SHA-256
`924a29a3bbbe007d4be4eb93e0f254db58f1f4a4a45878ae799f2d0c4fc1c655`. The harness ran
35,665.04 seconds (about 9 hours 54 minutes), reached round 2,247, and completed 17,974 tasks
before one task failed. `PRAGMA quick_check` returned `ok`.

## Diagnosis

The failing deterministic-provider attempt was prepared at epoch millisecond `1784469623851`
with immutable deadline `1784469633851`. Canonical-store contention delayed the durable dispatch
transition until `1784469633808`, only 43 milliseconds before the deadline. The configured
fixture provider requires 250 milliseconds, so that dispatch could not possibly complete inside
the remaining window. The local timeout correctly treated the already-dispatched outcome as
unknown and failed safely, but the runtime should never have crossed a predictably unusable
dispatch boundary.

This differs from the earlier expired-before-dispatch defect. That correction retired an attempt
once its absolute deadline had elapsed; this run proved that the atomic decision must also account
for the selected endpoint's latency estimate before the deadline itself is reached.

## Correction and post-fix diagnostic

The runtime now reloads the immutable recorded provider request before crossing the dispatch
boundary, making the dispatch commit its final canonical-store operation before invocation. The
store atomically compares the remaining immutable deadline with the endpoint's bounded latency
estimate. An insufficient window retires the undispatched attempt, releases its reservation
without charging model calls or retries, returns the run to context compilation, and records a
replay-verifiable `provider_dispatch_window_exhausted` checkpoint. Actual post-dispatch timeouts
remain charged/unknown and fail closed.

A public-process regression uses a 1-second attempt deadline, 800 milliseconds of boundary delay,
and a 250-millisecond provider estimate. It proves that the first attempt remains undispatched,
the replacement completes with two charged model calls, no charged retry, one tool call, no live
replay execution, and complete evidence.

A separate dirty-worktree high-contention diagnostic then ran 64 simultaneous sessions for
189.932 seconds. It completed all 896 turns across 14 rounds, survived one hard restart, recovered
four interrupted-provider turns and one read-tool retry, passed complete recorded-only replay and
SQLite integrity, drained cleanly, and left zero residual work. The diagnostic daemon SHA-256 was
`d52563271fa35e03092f76c88d6a7f4526b23611679b2973262337ab88f99554`; because its source state
was dirty, it is validation evidence only and is not a release soak.
