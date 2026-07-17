# Schema-14 long-soak failure observation (superseded development runtime)

Date: 2026-07-13 (Pacific/Auckland)

This is negative dirty-worktree development evidence, not a release result. A paced 24-hour soak
was started before the schema-15 usage-reporting migration and exited after 12,122.01 seconds
(about 3 hours 22 minutes). One task reached terminal `failed` after one model attempt and one
successful read-tool charge, before a second model attempt, final response, or validation. The
task ID was `019f596e-708c-7872-aaeb-c80ed0b998f4`; SQLite task usage reported 3,632 input tokens,
8 output tokens, 98 output bytes, one cost microunit, no retry, and no remaining reservation.

The old harness asserted immediately and its temporary home was deleted during unwind, so the
terminal timeline and canonical failure summary were not retained. That evidence loss is itself a
harness defect. The current harness now writes a bounded sibling failure report containing the
task, post-admission timeline, and recorded replay before failing.

A current schema-15 diagnostic subsequently reproduced the same one-model/one-tool terminal shape
at round 221 after 345.78 seconds while other release gates contended for the host. Its retained
timeline proves that `fixture.read` entered `tool.call.started` and the run failed 1,153 milliseconds
later with `agent loop failed: read-tool deadline elapsed`. The fixture descriptor still imposed a
one-second timeout even though the run policy allowed five seconds. This proves a current timing
defect and supplies a plausible explanation for the superseded observation; it cannot prove that
the deleted schema-14 timeline had the identical cause.

The deterministic fixture reader and the similarly in-memory passive-skill resource reader now use
the normal five-second run ceiling. Recorded-only replay continues to accept both the historical
one-second skill descriptor and the corrected five-second descriptor, and fixture replay continues
to validate its exact recorded positive timeout and digest rather than substituting current policy.

The failed run cannot support any durability claim and will not be relabeled as schema-15 or
release evidence. The reproduced current-runtime defect was fixed and bounded-regression-covered,
but production readiness remained blocked until a fresh current-runtime 24-hour soak completed
cleanly. The earlier paced schema-15 run was deliberately stopped after the diagnosis because
changing the runtime invalidated it.

Initial accelerated probes on the current schema-15 runtime completed cleanly:

- one session completed 836 turns and 16 hard restarts in 600.870 seconds;
- eight sessions completed 2,144 turns and five hard restarts in 602.118 seconds; and
- a faster eight-session shape completed 1,504 turns and three hard restarts in 303.395 seconds;
- a restart-race shape completed 1,144 turns and 143 hard restarts in 302.866 seconds; and
- after the timeout correction, the exact eight-session/100-millisecond-provider/50-round-restart
  contention shape completed 2,376 turns, 297 rounds, and five hard restarts in 602.413 seconds.

Every completed probe reported SQLite integrity `ok`, complete recorded-only replay, clean drain,
and zero residual work. The corrected contention regression included 14 interrupted-provider and
two read-tool retry recoveries; its maximum task latency was 4.002 seconds while the full Rust,
archive/Debian, Lintian, clean-container install, and real-browser gates overlapped on the same host.
These probes cross the old failure's approximate per-session history depth or aggregate turn count,
but not its wall-clock duration. They regression-cover the reproduced timeout defect; they do not
erase the negative observation or replace the later clean [release soak](release-soak.json).
