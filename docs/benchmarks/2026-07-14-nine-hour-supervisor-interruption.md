# Nine-hour soak supervisor interruption (negative evidence)

This observation does **not** satisfy the 24-hour durability gate. It is retained so a large
successful workload is not mistaken for a completed run merely because its daemon state is clean.

The optimized external-binary harness started at `2026-07-14 03:51:31 +12:00` against `mealyd`
SHA-256 `119d56e3f3c329c103c36c1d9cdfb1b144c6714872e095cc1aec6f24b0ccb442`, with eight sessions,
a 250-millisecond fixture-provider delay, 30-second round pacing, and a hard restart every 50
rounds. Its durable database stopped advancing at `2026-07-14 13:05:29 +12:00`, after approximately
9 hours 14 minutes of workload.

The retained state contains:

- 7,272 succeeded tasks and runs, with zero failed or nonterminal tasks/runs;
- 7,272 released work leases and 92 leases expired by planned hard restarts;
- 21,816 delivered outbox records and zero failed outbox records;
- 19 daemon-run records, covering the initial process and 18 planned hard-restart recoveries; and
- SQLite `PRAGMA quick_check` result `ok`.

No success report or failure report was written. The final daemon-run record remains `running`
rather than carrying orderly shutdown evidence, while the database has no pending input, active
lease, failed task, or unfinished run. The host did not reboot, and the inspected kernel/service
window contained no OOM, crash, or coredump evidence. This combination is consistent with the
external supervisor terminating the harness process tree rather than a Mealy task failure, but the
available evidence cannot identify the supervisor mechanism conclusively.

Because the harness did not execute its final status/metrics assertions, recorded-only replay
sweep, clean drain, storage profile, and report publication, this observation is negative evidence
only. The full gate was restarted on 2026-07-15 inside a detached `tmux` supervisor with persistent
stdout/stderr and exit-status files. The replacement run still starts from an empty retained home
and must complete the entire 86,400-second clock.
