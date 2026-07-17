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

The checked [release soak](release-soak.json) is the clean packaged-binary durability observation.
It ran for 86,425.217 seconds, completed 15,824 turns across eight sessions, survived 39 hard
restarts, retained 929 exact duplicate admissions, recovered 62 interrupted-provider turns and 15
read-tool retries, and finished with SQLite integrity `ok`, complete recorded-only replay, clean
drain, and zero residual work. It binds clean revision `d346803`, exact external `mealyd` SHA-256
`4db797fd085ab845b7b30752a822168c670e6420df1edb22726c3e18eba64c97`, and a retained disk-backed
Btrfs home. Peak RSS was 160,256 KiB; p95/p99 latency was 20.691/23.846 seconds while the database
grew to 2,718,826,496 bytes. These are observed durability measurements, not portable resource or
latency guarantees.

The report remains byte-for-byte identical to the harness output and therefore names its original
pre-merge commit. GitHub's required linear-history rebase rewrote that commit identity while
retaining the exact Git tree. The checked
[`release-soak-lineage.json`](release-soak-lineage.json) preserves the original commit payload,
recomputes its report-named object ID, and binds its tree to the identical-tree rebased commit that
is an ancestor of the release. The release validator independently verifies the report SHA-256,
both tree identities, reconstructed observed commit, and release ancestry; it rejects a relabeled
report or merely similar source tree.

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

The five-minute paced report remains the newest isolated throughput comparison. Except for the
explicit clean [release soak](release-soak.json), historical comparison reports are deliberately
marked `dirty_worktree`; use them as development evidence only and never relabel them as clean
packaged-release durability evidence.
The [superseded schema-14 long-soak failure](2026-07-13-schema14-long-soak-failure.md) is retained
as negative evidence: it cannot satisfy a durability gate and motivated failure-report retention.
That retained path reproduced a current one-second read-tool timeout under contention. After both
in-memory read descriptors were aligned with the five-second run ceiling, the same accelerated
contention shape completed 2,376 turns in 602.413 seconds with complete replay, integrity, drain,
and zero residue. That focused regression was followed by the clean corrected release soak above;
it is not itself substituted for the 24-hour evidence.

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
The [Fedora 44 rootless archive observation](2026-07-15-fedora-44-installed-package-smoke.md)
independently runs the exact soaking binaries through install, mandatory sandbox enforcement,
durable work, replay, usage, backup verification, drain, uninstall, and state preservation on
glibc 2.43/Bubblewrap 0.11.0. It is same-host pre-release evidence and still requires repetition
against the final public package.
The Ubuntu record also retains the subsequent PID-1 systemd-user investigation: it distinguishes
startup/sandbox-probe success from a real approved mutation and records the final generated-unit
effect-level pass.
The Debian record now includes a separate systemd 257 PID-1/user-manager pass of that same
package-owned approved-mutation boundary.
Both records append a 2026-07-14 repeat against the exact corrected web-policy candidate. They bind
the byte-identical audited binaries, SBOM, license notice, archive, and Debian package hashes to
fresh archive/`.deb` install smokes and real Debian 13/Ubuntu 24.04 package-owned user-service
mutations. Those packages predate the appended evidence and completed 24-hour report, so the
report-bearing documentation-inclusive reproduction remains a separate final packaging gate.
That daemon was subsequently superseded when a browser lifetime audit found completed proxy thread
handles retained until call shutdown. The replacement candidate is reproducible at `mealyd`
SHA-256 `bda5e8c4250612e6882711e70e15fa47e3f7661535160983dff906ffe1f4907e`; it reaps handlers during
the call and adds 32-concurrent/256-total connection budgets at both proxy layers. The earlier
832-turn partial run remains diagnostic only, and the full 24-hour clock must restart from the
replacement extracted package.

Later provider-contract, client-boundary, and fragmented browser-verification findings superseded
that subject. The resulting auditable `c483945` soak and its `53feae1` successor both stopped
without a promotable report. The retained
[schema-15 contention-failure observation](2026-07-16-schema15-long-soak-contention-failure.md)
records their 15-hour-51-minute and 12-hour-9-minute failure timelines, intact SQLite databases,
root cause, correction, and a successful 176-turn dense diagnostic against a 1.5 GB retained-home
clone. No duration or turn count from either failed run was carried forward. The corrected
`d346803` subject subsequently produced the independent-validator-accepted
[release soak](release-soak.json) above, closing the long-duration runtime gate without relabeling
either failed attempt.
