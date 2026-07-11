# mealyctl

Local client for the versioned API. It never opens SQLite. Normal commands do not mutate daemon
files directly; the two explicit offline owner workflows are user-service installation and
digest-pinned configuration rollback while the daemon lock is free.

The CLI covers sessions, tasks, approvals, effects, memory, compaction, extensions, signed
channels, status/metrics/doctor, safe backup and restore verification, complete/scoped export,
retention GC, bounded drain, service installation, and configuration rollback.
