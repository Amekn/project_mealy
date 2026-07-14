# Performance and soak evidence

Reports in this directory are bounded observations, not portable guarantees. Read each report's
revision, source state, build profile, target, fixture delay, pacing, duration, and host resources
before comparing it with another run. A report from a dirty worktree or Cargo integration binary
is development evidence and cannot satisfy the clean packaged-release gate.

Run the optimized public-process harness with:

```sh
scripts/run-soak.sh --release \
  --duration-seconds 300 \
  --sessions 8 \
  --restart-every-rounds 10 \
  --provider-delay-ms 250 \
  --report target/soak/five-minute.json
```

The harness uses the deterministic fixture provider so it can assert exact attempt/tool recovery
lineage without spending provider quota. It measures admission-to-terminal latency, RSS, SQLite
and artifact growth, duplicate admission, hard restart recovery, recorded-only replay, integrity,
clean drain, and residual work. Provider-account smoke is a separate opt-in gate.
An unsuccessful task now writes a sibling `REPORT.json.failure.json` with bounded task, timeline,
and replay evidence before the test fails.

For a paced 24-hour durability run, use a large enough filesystem and an explicit interval:

```sh
scripts/run-soak.sh --release \
  --duration-seconds 86400 \
  --sessions 8 \
  --restart-every-rounds 50 \
  --provider-delay-ms 250 \
  --round-interval-ms 30000 \
  --report target/soak/24-hour.json
```

The newest checked-in durability observation is the paced
[`2026-07-13-thirty-minute-paced-soak.json`](2026-07-13-thirty-minute-paced-soak.json): 2,008
completed turns across eight sessions, 12 hard restarts, 117 duplicate admissions, 47 interrupted
provider turns, SQLite integrity `ok`, and zero residual work after 1,804.862 seconds. Peak RSS was
67,116 KiB. Its 2.948-second p95 and 5.717-second p99 include concurrent workspace compilation,
real-Chrome conformance, and release-gate load on the same host, so they are resilience evidence,
not a clean latency baseline.

The checked
[`2026-07-13-storage-optimized-soak.json`](2026-07-13-storage-optimized-soak.json) is the newest
isolated 60-second storage observation. It completed 536 turns with six hard restarts, SQLite
integrity `ok`, zero residual work, and 150,680 database bytes per completed turn. Under the same
eight-session, 250-millisecond-provider, unpaced shape, the earlier
[`2026-07-13-development-soak.json`](2026-07-13-development-soak.json) recorded 214,609 bytes per
turn: the bounded durable-JSON encoding reduced this observed rate by 29.8 percent while preserving
logical request digests and recorded-only replay. This is an observation, not a storage quota or a
promise about other conversation shapes.

Soak report v2 adds SQLite page/free-space data, the 64 largest `dbstat` objects, and context-item
row/content/source attribution. Those fields distinguish compressible request/evidence payloads
from the intentionally repeated immutable context-selection rows. Provider requests and validation
context objects larger than 4 KiB are stored in a bounded zlib/base64url envelope only when it is
smaller. Digests remain over the original canonical JSON; old uncompressed rows remain readable;
declared size, decompressed size, UTF-8, JSON-object shape, and the 64/256-KiB logical ceilings are
checked before use.

The five-minute paced report remains the newest isolated throughput comparison. Every checked-in
report is deliberately marked `dirty_worktree`; use the unedited JSON as development evidence only,
and never relabel it as clean packaged-release or 24-hour durability evidence.
The [superseded schema-14 long-soak failure](2026-07-13-schema14-long-soak-failure.md) is retained
as negative evidence: it cannot satisfy a durability gate and motivated failure-report retention.
That retained path reproduced a current one-second read-tool timeout under contention. After both
in-memory read descriptors were aligned with the five-second run ceiling, the same accelerated
contention shape completed 2,376 turns in 602.413 seconds with complete replay, integrity, drain,
and zero residue. The focused regression resolves the reproduced defect, not the open 24-hour gate.

The later
[`2026-07-14-nine-hour-supervisor-interruption.md`](2026-07-14-nine-hour-supervisor-interruption.md)
is also negative evidence. Its exact external daemon completed 7,272 turns and 18 planned hard
restarts with no failed or unfinished durable work and SQLite integrity `ok`, but the external
supervisor terminated the process tree before the final assertions, drain, and report. A fresh
empty-home run under detached supervision restarted the full 86,400-second gate on 2026-07-15;
elapsed time from the interrupted attempt is not carried forward.

Non-performance release evidence in this directory follows the same honesty rule. The checked
[`2026-07-13-supply-chain-policy-audit.md`](2026-07-13-supply-chain-policy-audit.md) records the
current workflow and Rust dependency-policy gates and their first clean local result; it is still a
dirty-tree observation until a published tag runs those gates itself.
The supported-package observations separately exercise the exact dirty-tree archive and Debian
payloads on [Ubuntu 24.04](2026-07-13-ubuntu-24.04-installed-package-smoke.md) and the exact Debian
payload on [Debian 13](2026-07-13-debian-13-installed-package-smoke.md). Both are x86_64
clean-runtime-container evidence rather than published-release or native ARM64 proof.
The Ubuntu record also retains the subsequent PID-1 systemd-user investigation: it distinguishes
startup/sandbox-probe success from a real approved mutation and records the final generated-unit
effect-level pass.
The Debian record now includes a separate systemd 257 PID-1/user-manager pass of that same
package-owned approved-mutation boundary.
Both records append a 2026-07-14 repeat against the exact corrected web-policy candidate. They bind
the byte-identical audited binaries, SBOM, license notice, archive, and Debian package hashes to
fresh archive/`.deb` install smokes and real Debian 13/Ubuntu 24.04 package-owned user-service
mutations. Those packages predate the appended evidence and pending 24-hour report, so a final
documentation-inclusive reproduction is still required.
That daemon was subsequently superseded when a browser lifetime audit found completed proxy thread
handles retained until call shutdown. The replacement candidate is reproducible at `mealyd`
SHA-256 `bda5e8c4250612e6882711e70e15fa47e3f7661535160983dff906ffe1f4907e`; it reaps handlers during
the call and adds 32-concurrent/256-total connection budgets at both proxy layers. The earlier
832-turn partial run remains diagnostic only, and the full 24-hour clock must restart from the
replacement extracted package.

Later provider-contract, client-boundary, and fragmented browser-verification findings superseded
that subject. The current 24-hour subject is the exact auditable `mealyd` SHA-256
`649db94894de63fb973c7d2ef7a4749100d5c9b3ca77524a0f8cbfde66c39572`, reproduced by two clean
`c483945` builds. Its empty, disk-backed clock began at 2026-07-15 10:47:53 Pacific/Auckland.
Verifier-only commit `c797e8e` reproduced the same daemon and CLI bytes and passed all seven
protected workflow contexts. No duration or turn count from a superseded/interrupted run is
carried forward. Until this run emits and passes its final report, the checked 30-minute paced
report remains the newest positive long-form durability observation.
