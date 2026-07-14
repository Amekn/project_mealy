# Production readiness

- Status: active release gate
- Reviewed: 2026-07-15
- Target: one-owner Linux production release, with an installable conversation-only control-plane preview
  on macOS until that platform has an enforceable tool sandbox; Windows is outside release-one scope

This document separates Mealy's completed runtime proof from a product an owner can install and use
every day. Passing the release-one architecture scenarios is necessary, but it is not sufficient
for a production claim.

## Comparison baseline

The target is practical usefulness comparable to OpenClaw and Hermes, not identical feature count.
Their current first-party documentation establishes the usability baseline:

- OpenClaw provides guided onboarding, provider/model configuration, a live gateway, a browser
  control UI, many messaging channels, persistent cron jobs, isolated browser profiles, tool
  profiles, filesystem/runtime/web tools, memory, skills, plugins, and operational probes.
- Hermes provides installer-driven setup, CLI/TUI/web surfaces, many providers, fallback chains,
  40+ tools, terminal/file/web/browser tools, several execution backends, messaging gateways,
  cron delivery, skills, MCP, memory/session search, and subagent delegation.

Sources:

- [OpenClaw features](https://docs.openclaw.ai/concepts/features)
- [OpenClaw tool profiles](https://docs.openclaw.ai/gateway/config-tools)
- [OpenClaw browser](https://docs.openclaw.ai/browser)
- [OpenClaw scheduled tasks](https://docs.openclaw.ai/cron)
- [Hermes repository overview](https://github.com/NousResearch/hermes-agent)
- [Hermes tools and toolsets](https://hermes-agent.nousresearch.com/docs/user-guide/features/tools/)
- [Hermes messaging gateway](https://hermes-agent.nousresearch.com/docs/user-guide/messaging)
- [Hermes cron](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/cron.md)
- [Hermes delegation](https://hermes-agent.nousresearch.com/docs/user-guide/features/delegation)

Mealy should retain its stronger durable queue, effect ledger, replay, authorization, governed
memory, and fail-closed extension/sandbox boundaries while closing the day-to-day capability gap.

## Claim levels

| Claim | Meaning | Current status |
|---|---|---|
| Runtime proof | Core durability and security contracts pass real process scenarios. | Passed |
| Developer preview | An engineer can build it and complete bounded real-model conversation. | Passed |
| Usable alpha | Guided setup, interactive chat, useful governed tools, and one remote channel work. | Passed |
| Production ready | Install, upgrade, recovery, secrets, automation, observability, and acceptance gates pass on supported platforms. | Not passed |
| Competitive personal agent | Browser/web, skills/MCP, delegation, memory UX, and multiple channels/providers are practically usable. | Not passed |

## Production release blockers

Every P0 row must be complete before Mealy describes itself as production ready.

GitHub `main` protection now requires a pull request, applies to administrators, requires linear
history and resolved conversations, and rejects force-pushes and deletion. Its exact required CI
contexts will be added from the first current-source PR run rather than guessing names from a
workflow that has not run remotely. The `live-provider-smoke` Environment is configured with an
explicit required owner review, but it does not contain a provider credential. The workflow also
rejects a release tag whose commit is not on `origin/main`; current protected CI and one reviewed
real-account smoke must pass before published acceptance can run.

| Area | P0 acceptance | Current evidence | Gap |
|---|---|---|---|
| Packaging | Versioned Linux packages and archives install without a Rust toolchain; checksums, provenance/SBOM, uninstall, upgrade, and rollback are documented and tested. | A tag-gated matrix workflow natively builds Linux x86_64 and ARM64 packages, performs locked strict/RustSec gates on each host, embeds and audits the exact binary dependency graphs, generates and validates pinned-Syft CycloneDX SBOMs, and reproducibly generates a frozen all-feature supported-Linux dependency license notice with pinned `cargo-about`. Both notice runs must be byte-identical, bounded, path-free, and passive before the notice becomes checksummed archive/`.deb` metadata. The workflow builds deterministic archives, root-owned Debian packages, and target checksum manifests, attests every asset, and publishes once only after both architectures succeed. Explicit macOS 15 ARM64 and Intel jobs separately test and binary-audit native builds, generate normalized SBOM/license payloads, and retain deterministic, attested conversation-only preview archives with a denied-worker capability manifest. Each `.deb` is deterministically assembled from the verified payload with no maintainer scripts, service activation, or home mutation; rootless package tests prove contents, modes, checksums, attribution identity, tamper rejection, and reproducibility, while each native runner installs, exercises, drains, removes, and proves state preservation. The stable archive manager validates host architecture, outer/inner digests, archive type/size/path/inventory, binary/version/schema identity, holds file-backed install and daemon-home locks, rolls back failed replacement, preserves matching previous binaries/metadata, swaps same-schema releases safely, and coordinates an exact-digest cross-schema slot swap with atomic reconstruction/activation of the automatic pre-migration home. Before mutation it durably journals verified original slots outside the exchanged release directories; a hard-kill test proves a subsequent stable-manager invocation compensates the interrupted exchange before retry. It uninstalls only managed program files, preserves durable state, and passes reproducibility/install/upgrade/rollback/cross-schema-orchestration/lock/tamper/wrong-architecture/uninstall tests; infrastructure and public-process proofs cover real schema-13 restoration from schema 15 with identity, secret, artifact, integrity, inherited-lock, and preserved-home checks. | No published tag/clean-host evidence yet. Debian packages are complete; RPM and distribution repositories are not claimed. |
| Onboarding and secrets | One guided command selects a provider/model, validates limits, stores only a secret reference in config, provisions an owner-private credential broker, and performs a bounded test call. | `mealyctl setup` now initializes a clean private home without booting the daemon, interactively selects `OpenAI`, Anthropic, `OpenRouter`, or literal-loopback local Responses, prompts only for non-secret model/limit/price values, imports remote credentials from a named environment variable, previews the exact non-secret settings/config digest, and requires typing `APPROVE` unless the same complete flags carry explicit non-interactive approval. It reuses the protocol-specific activation boundary: conflict-safe broker preflight, one no-tools 64-output-token/30-second/1-MiB bounded JSON/SSE probe, atomic config/history publication, secret-free JSON, and exact daemon/doctor/chat handoff. Process tests cover clean-home remote probe/brokering, interactive local setup, denial with zero provider state, and staged-probe labeling. Credentialless presets accept only literal loopback, send no authorization header, store `credential: null`, and create no broker entry. OpenRouter discovery filters account-visible text/tool models, normalizes limits/prices, and flags unsupported pricing axes; all discovery disables proxy/redirects and enforces bounded safe metadata. Failure bodies and credentials are never echoed or persisted in config. Exact fallback removal preserves the rest of the ordered chain and retains the old broker key; compatible primary replacement preserves the complete chain, while incompatible trust/locality/identity changes fail before mutation. Stopped-daemon revocation removes only unreferenced broker identities, and encrypted secret backup remains explicit. | Guided activation and controlled fallback rotation are complete. Direct OpenAI prices/remote limits still require operator verification, and OpenRouter Responses remains upstream beta and cannot settle extra pricing axes. |
| Interactive use | A first-party `chat` surface streams text/tool progress, renders approvals, supports interrupt/queue/steer, reconnects by cursor, and resumes existing sessions. | `mealyctl chat` creates/resumes sessions and keeps a bounded input reader plus per-admission watcher set active concurrently. Plain/queue, steer, interrupt, exact-subject approve/deny, `/act`, `/edit`, `/manage`, and `/run` remain available during work; accepted work is correlated by durable causation/correlation IDs, promotion polling resumes by cursor after restart, and bounded non-authoritative provider text deltas, model/tool lifecycle progress, and terminal responses are rendered without confusing adjacent turns. `session send-file` additionally admits one owner-selected no-follow regular UTF-8 text/source file up to 256 KiB under digest-bound untrusted metadata without persisting its host path, reusing normal delivery/idempotency. The daemon projects a chronological, same-epoch suffix of at most 32 successful prior user/assistant turns under a 512-KiB discovery ceiling, reserves the latest authenticated input before optional history, honors the latest compaction cutoff, and drops prior-session-derived context on epoch rotation. A public wire test proves the exact second-turn projection and zero-dispatch replay; the workspace-revocation restart test proves old assistant text cannot reintroduce revoked authority. `session list` exposes a bounded, exact-binding recent-session browser, and `chat --session-id` scans retained history to rediscover active/pending work. Terminal control characters are neutralized. A pseudo-terminal process test holds admission open, proves the next prompt remains interactive, then proves `/quit` exits without waiting; delayed-provider process exercise covers steer, interrupt, queue, cancellation, and correct attribution. | P0 acceptance is complete. A full-screen TUI is optional future UX rather than a release requirement. |
| Model providers | OpenAI Responses plus at least one independently exercised local or alternate adapter support tools, classified retry/backoff, health, explicit fallback, cancellation, limits, and exact usage/cost settlement. | Separate `OpenAI` Responses and Anthropic Messages adapters implement their distinct authentication, request/tool, terminal, SSE, error, and usage contracts. Both are byte/text/event bounded, actively cancellable every 50 ms, independently health/accounted, and governed by persisted jittered retry plus conservative unknown-outcome rules. Responses terminal-match validation and Anthropic ordered block/cumulative-usage validation feed the same non-authoritative progress and canonical result boundary. A public-process proof makes a Responses primary fail definitely, dispatches the durable retry through a streaming Anthropic fallback, verifies both protocol/credential/request shapes and endpoint histories, and replays with zero network calls. The OpenRouter preset deliberately reuses this hardened stateless Responses boundary; process tests prove its exact bearer/store/stream/model probe plus account-filtered catalog limits/pricing normalization. Process tests additionally prove remote authenticated and literal-loopback credentialless request bounds, pagination/filter behavior, credential isolation, and failure redaction. A manual read-only-permission workflow is ready to run setup probe, durable turn, health/settlement/usage/replay/leak/drain checks against any of the three real accounts. | P0 adapter, local preset, and deterministic model-discovery acceptance is complete. Running the opt-in workflow remains an external release-quality gate because no account credential is present; OpenRouter's upstream Responses contract is beta. |
| Workspace tools | The model can list, stat, read, and search only granted workspace paths; outputs are bounded/cited and traversal/symlink escapes fail closed. | Complete for the supported Linux target: stopped-daemon grant/revoke CLI, canonical logical identities, `openat2` beneath/no-symlink/no-mount enforcement, bounded list/stat/read/search, line locators, citation-gated validation, recorded replay, adversarial escape tests, and restart/revocation epoch proof. | Native non-Linux workspace enforcement remains unsupported and is explicitly denied. |
| Mutating tools | Edit/patch/write and shell/process execution require exact policy, approval where applicable, sandbox profiles, resource limits, stable effect evidence, and recovery tests across dispatch crash points. | Production `workspace.create_file`, `workspace.replace_file`, `workspace.manage_path`, and `process.run` are implemented on Linux. They use separate stopped-daemon writable/command grants; explicit `/act`, `/edit`, `/manage`, and `/run` selection; immutable writable-root and executable-digest ceilings; logical exact approval; verified argument previews; and no network/secrets/environment. Replacement additionally requires an approval-bound exact current SHA-256 and a bounded existing regular file, then accepts exactly one of complete content or at most 16 ordered exact old/new-text edits with expected occurrence counts. Path lifecycle management admits one non-recursive directory creation/removal or one digest-preconditioned no-overwrite bounded-file move/removal; it uses safe-parent resolution, namespace synchronization, destination/quarantine digest rechecks, and reconcile-only recovery. Adversarial sandbox and public-provider tests cover all operation classes, sorted two-target approval, stale/collision/symlink/non-empty denial, fresh validation, and zero-dispatch replay. Process execution remains direct with no shell/`PATH`, one pinned command mount, bounded resources, and never-retry recovery. Trusted dynamic-runtime discovery is now independently PATH-free: the exact root-controlled `/usr/bin/ldd` runs with an empty environment and `--` before the canonical worker/command path, and a release-process regression proves `PATH=/nonexistent` still exposes the sandboxed write boundary. All mutations receive fresh validation and recorded-only replay; the effect ledger's approve/deny/expiry/cancellation/crash/unknown-outcome matrix remains authoritative. | Recursive tree operations, directory moves, overwrite/chmod, and managed background-task adapters remain open. |
| Web access | Bounded search and fetch tools enforce scheme, DNS/IP, redirect, response-size, content-type, timeout, and secret rules; fetched content remains untrusted evidence with citations. | Public HTTPS/domain/origin grants, brokered Brave Search, DNS pinning plus peer verification, private/reserved/mixed-answer rejection, no proxy/redirect, strict response bounds, active-HTML removal, citation-gated validation, immutable capability ceilings, process/replay proof, local SSRF fixtures, and an opt-in direct `example.com` production-adapter check are implemented. The adversarial corpus covers named and literal/obfuscated loopback, every IPv4 special-purpose class, the current IANA IPv6 global-allocation and special-purpose boundaries, prefix-confusable active tags, quoted tag delimiters, comments, malformed blocks, numeric/common entities, and non-cascading entity decoding. | Live Brave Search still requires an owner credential and remains an external release-quality gate. |
| Remote channel | At least Telegram or Discord supports pairing/allowlists, attachments within bounds, queue/steer/interrupt, progress/final delivery, approvals, retry/dedupe, revocation, and restart. | Telegram verifies the bot live, performs a 128-bit expiring exact-code private-chat handshake, brokers and digest-pins its token, creates an exact sender/chat session, reserves updates/cursor movement, supports all controls and exact approve/deny, accepts four bounded verified text-document types, routes progress/final/approval outbox messages, and has hard-restart/revocation/remote-schedule evidence. A separate Discord API v10 adapter verifies the bot and an exact type-1 one-human DM, uses canonical string snowflakes, a setup floor, lossless saturated-page backfill, reserve-before-effect receipts, the same controls/approvals, platform rate delays, mention-free 2,000-character output, stable enforced nonces, strict ambiguous-outcome parking, restart recovery, and terminal revocation. Its public-process proof crosses a 106-message newest-first backlog, hard restart, 429 retry, nonce reuse, attacker/attachment rejection, delivery, and revocation. The signed generic webhook remains available. | P0 acceptance is complete. Telegram owns bounded text-document input; Discord is intentionally text-only. Image/audio/video, guild/group multi-user workflows, and arbitrary channel plugins remain outside the current contract. |
| Scheduling | Schedules are canonical SQLite state with timezone/missed-run policy, durable due claims, run history, pause/resume, overlap control, and channel/webhook delivery. | Canonical five-field cron definitions, IANA zones/DST, bounded `skip`/`latest` coalescing, overlap policy, leased/recoverable claims, deterministic idempotent session admission, revision-fenced lifecycle, API/CLI, status/metrics/doctor visibility, run history, safe-mode denial, remote Telegram-session delivery, and process/unit/store proofs are implemented. | P0 acceptance is complete. Editing requires cancel/create, and one-shot or sub-minute schedules remain outside the current contract. |
| Provider and extension operations | Status/doctor report configured identity, last success/failure, degraded state, rate/concurrency pressure, and actionable repair without exposing secrets. | Authenticated status/doctor expose each primary/fallback protocol, identity, model, residency, locality, streaming, live health, latency estimate, live/max concurrency, current-minute/max rate pressure, cumulative durable invocation counts, durable last success/failure timestamps, and recent failures. A restart process proof retains the exact history while returning live health to `configured_unprobed`, so stale success never masquerades as current connectivity. Doctor emits concrete secret-free repair guidance for every health class. | P0 acceptance is complete. Automated upstream credential rotation remains future convenience. |
| Configuration lifecycle | Setup and edits validate before activation, high-risk changes are approved, activation cannot split an in-flight turn, and rollback/backup behavior is tested. | Configuration mutation is deliberately a stopped-daemon transaction: every command holds the real home lock, validates the complete candidate before atomic publication, archives the prior bytes, and cannot coexist with an in-flight turn. The next start records the exact effective digest and rotates affected context epochs before dispatch. Startup validation, digest history, approved rollback, isolated backup verification, exact-digest encrypted backup activation, and exact-transition pre-migration snapshot activation through stopped-home atomic directory exchanges with untouched prior homes retained are implemented and process-tested. Complete archives and migration reconstruction also carry exact configured skill packages, content-addressed MCP executables, and every file/executable-mode bit in the configured browser bundle. Browser inspect/add/enable performs sandboxed product/CDP/render verification; disable/revoke preserves rollback bytes and web authority cannot be removed underneath an enabled browser. | P0 acceptance is complete under the stopped-daemon activation boundary. Hot reload, guided general mutation, and a visual diff remain future convenience rather than weaker alternate mutation paths. |
| Release quality | Public-API smoke, upgrade/downgrade, clean-install, backup/restore, adversarial tool, load, cancellation, soak, and optional live-provider suites pass with published measurements. | Tag-driven native Linux x86_64 and ARM64 jobs now re-run strict and RustSec gates, audit auditable binaries, publish per-target SBOMs, exercise deterministic package install/upgrade/same-schema and cross-schema rollback/uninstall, generate first-party provenance attestations, retain artifacts, and converge on one release only after both succeed. A SHA-pinned `cargo-deny` gate covers advisories, an explicit permissive-license allowlist, exact reviewed duplicate exceptions, crates.io-only sources, no wildcard dependencies, non-publishable proprietary workspace crates, and a ban on native-TLS/OpenSSL regression. Actionlint, ShellCheck, and the `zizmor` auditor reject workflow syntax, shell, unsafe trigger/permission/secret/interpolation, credential-persistence, and concurrency regressions; all external actions are full-commit pinned. A mandatory x86_64 browser job downloads the exact size/SHA-pinned Headless Shell and runs real process, stopped-home lifecycle, model-visible citation/artifact, non-read/WebSocket denial, and runtime-deleted replay proofs before publishing. The all-feature suite covers crash, sandbox, Telegram/Discord/webhook channels, schedules, extensions, native MCP lifecycle/isolation/drift/cancellation/replay, mixed-protocol provider fallback, workspace escape/revocation, and recorded replay. A public-process load/recovery gate admits 24 sessions, kills eight concurrent provider attempts, verifies stopped SQLite integrity, recovers all tasks, and proves zero-live-call replay plus zero residual operational gauges. Parallel-process stress exposed and now regression-covers shared artifact-blob timestamp races: deduplication retains the earliest verified observation instead of imposing invalid cross-transaction wall-clock order. The opt-in optimized soak harness records latency/RSS/storage, exact duplicates, post-dispatch hard restarts, charged and undispatched recovery classes, every-turn replay, integrity, drain, and residue. The checked [30-minute paced dirty-worktree observation](benchmarks/2026-07-13-thirty-minute-paced-soak.json) completed 2,008 turns across eight sessions and 12 hard restarts in 1,804.862 seconds, with 117 duplicate admissions, 47 interrupted provider turns, 67,116 KiB peak RSS, SQLite integrity `ok`, and zero residual work. Its latency includes concurrent compilation/real-browser/release-gate load and is not a clean performance baseline. | No published-tag clean-machine evidence yet; a paced 24-hour durability soak, clean packaged-release baseline on both architectures, and live-provider opt-in smoke remain open. |
| Documentation/support | Install, setup, first task, approvals, backup/restore, upgrades, incident recovery, limits, costs, security boundary, and troubleshooting are verified from a clean machine. | Quickstart, operations, and an attested package install/upgrade/same-schema/cross-schema rollback/uninstall runbook exist; credential-scoped provider discovery, encrypted backup, and migration-snapshot activation have executable offline process proofs. | The complete runbook has not yet been executed and recorded against a published release on clean supported x86_64 and ARM64 hosts. |

The first exact-candidate 24-hour attempt was externally terminated after approximately 9 hours 14
minutes. Its retained database contains 7,272 succeeded turns, 18 planned hard-restart recoveries,
zero failed or unfinished durable work, and SQLite integrity `ok`, but no final report or clean
drain. It is retained as
[negative evidence](benchmarks/2026-07-14-nine-hour-supervisor-interruption.md) and does not reduce
the required duration. A fresh empty-home run started under detached supervision on 2026-07-15.

The provider output boundary now distinguishes the larger transport envelope from canonical agent
state: an 8-MiB wire response narrows to at most 64 KiB of aggregate final text and 256 KiB of
normalized tool arguments before progress emission or persistence. Regressions prove that multiple
individually valid Anthropic stream blocks and one oversized Responses function object cannot
bypass those aggregate limits. Ordinary CLI success/error decoding independently stops at 8 MiB.
The same boundary now rejects unsafe body/header request IDs, a wrong Responses object/model, and a
wrong Anthropic terminal or streaming model. Setup probes enforce the same exact selected-model
contract before publishing configuration. Provider-controlled incomplete reasons are never copied
into Mealy error text.

The tag matrix now builds through a flag-closed source-path-remapping boundary and refuses to
retain an architecture archive until
`scripts/installed-package-smoke.sh` installs those exact auditable binaries into an empty
prefix/home, checksum-verifies the release installer, validates mandatory requirements/
architecture/security/threat-model documents, version/schema, hardened service generation, and
doctor, completes and recorded-replays durable work, checks
settled usage, creates and isolated-verifies an online backup, drains cleanly, and uninstalls while
preserving `mealy.sqlite3`. This closes the source-tree-versus-installed-payload test gap; it does
not replace the still-open published-tag and clean-host evidence.
The same native job refuses retention until the matching checksum-covered `.deb` has no Lintian
error or warning tags and proves exact payload identity, root ownership/modes, absence of
maintainer scripts, service generation, one durable task plus recorded replay, clean
drain/removal, and preservation of its user database.
Both package forms carry the complete regular-file-only documentation tree under inner digests;
the Debian layout mirrors it below `/usr/share/doc/mealy/docs` so packaged cross-references do not
silently point at missing files.
The packager rejects common Linux, macOS, and Windows user-home paths even if its caller bypasses
the release-build helper. Two current locked auditable builds from distinct Cargo homes and target
directories are byte-identical, contain dependency inventories accepted by `cargo audit bin`, and
contain only stable `/mealy/...` source identities. This closes a locally reproduced release-path
privacy and reproducibility defect; native ARM64 and attested published-build reproduction remain
tag gates.
The latest pre-evidence local package has no Lintian error or warning tags; retained informational tags are
documented in the clean-container observation and do not weaken the exact embedded release payload.
The checked [Ubuntu 24.04 clean-container observation](benchmarks/2026-07-13-ubuntu-24.04-installed-package-smoke.md)
passes that exact proof without a Rust toolchain, while remaining explicitly dirty-worktree,
unattested, x86_64-only development evidence.
The checked [Debian 13 clean-container observation](benchmarks/2026-07-13-debian-13-installed-package-smoke.md)
independently installs the exact hardened `.deb` with its sandbox profiles required, completes and
recorded-replays durable work, drains/removes cleanly, and preserves owner state. It has the same
dirty-tree, unattested, x86_64-only limitation.
A later Debian 13.5 PID-1/user-manager pass also runs the corrected generated unit from the exact
package-owned audited binaries, approves one workspace mutation, verifies the effect and file
bytes, drains, and leaves no failed user unit.
The 2026-07-14 repeats in both linked observations bind the corrected reproducible `mealyd` SHA-256
`408d5a45657b34e047122521e1d108fcc7e76ca51b237f96579d02c2869aa043` to fresh archive and Debian
install smokes plus package-owned mutations under Debian 13 systemd 257 and Ubuntu 24.04 systemd
255. Both left no failed user unit. Recording that evidence changes the embedded docs, so the
post-soak package still needs its planned final reproduction.
That web-policy candidate is now explicitly superseded: a later browser lifetime audit found that
both proxy accept loops retained completed joinable-thread handles until whole-call shutdown. The
replacement reproducible pair is `mealyd`
`bda5e8c4250612e6882711e70e15fa47e3f7661535160983dff906ffe1f4907e` and `mealyctl`
`82197a44ff30876c2e69a664d3cdc5a6cbc04a7684a8fd1909014e1c941428c0`. Its byte-identical
pre-evidence archives and Debian packages passed checksum, direct install/replay, Lintian, and
Ubuntu 24.04 package-owned systemd-mutation gates. The new daemon—not the earlier hash—is the next
24-hour soak subject.
That pair is itself now superseded by the provider normalized-output audit above. The corrected
byte-identical auditable pair is `mealyd`
`df37a01dc21f9f207ebad16164daea926626b8eabd9377ad8e51c6cf1ff95938` and `mealyctl`
`078db71891f079ae962d1cf698b7d64d1b402f6f12004d17f6a0cd1be3104c29`. Its exact daemon passed a
400-turn/five-hard-restart accelerated soak with SQLite integrity `ok` and zero residual work.
That pair is now also superseded: a deeper response-contract review found missing exact
object/model checks and reflected provider-controlled incomplete reasons. Its paced run was stopped
without promoting a report. The resulting reproducible pair is `mealyd`
`119d56e3f3c329c103c36c1d9cdfb1b144c6714872e095cc1aec6f24b0ccb442` and `mealyctl`
`0b69d5a2e4f50746ad801b71df85279468ccfb05de70a6e996f6b8183ec20c8f`. Its daemon passed a
392-turn/four-hard-restart accelerated exact-binary soak in 60.522 seconds with SQLite integrity
`ok` and zero residual work. That probe-parity CLI was then superseded by a client-only local
boundary audit: successful/error API versioning, bounded canonical error display, pre-parser
per-event SSE limits, cursor/type/body matching, terminal-safe typed JSON, canonical private-home
descriptor reads, bounded no-follow extension/native-executable inspection, and finite ordinary
and maintenance request deadlines. Two auditable builds reproduced the unchanged daemon and new
`mealyctl` SHA-256
`bccb6e45b4e4b132734f2158ac14ae1ac8f0008d633d5027ab56f95cc7490cfa`; both client binaries have
build ID `17a8d65f1af8d5c65eb11df4e9ba41607df3ef67` and their 255 embedded dependencies have no
RustSec finding. The exact current tree also passes the full strict workspace suite, disposable
MinGW Windows and GCC AArch64 Linux all-target/all-feature checks, and a real Windows PE link after
normalizing Windows canonical paths without changing either Linux binary. A fresh 24-hour clock
uses that exact unchanged daemon; final packages still wait for the long report and resulting
documentation bytes.
The checked [live public web-fetch observation](benchmarks/2026-07-13-live-public-web-fetch.md)
also passes the production no-proxy DNS-pinned adapter without credentials; Brave Search remains
unexercised because no subscription credential is present.

A private-state overlap audit additionally closed a direct-launch/service mismatch and a secret
exposure path. Workspace roots, extension host mounts, and local attachments now fail closed when
they equal, descend from, or contain the canonical daemon home; CLI, startup, public API, and
process tests cover the independent boundaries. The generated Linux unit holds the stopped-home
lock and derives exact outer-Bubblewrap writable binds from the current validated writable-workspace set,
so recommended service launches retain the same useful mutation authority without making the rest
of the owner account writable. It rejects private-temporary workspace/home paths and volatile
state filesystems, uses a private umask, links an exact custom unit path, and prevents the
intentional forced-drain exit from being restarted.
Ubuntu 24.04 systemd-user integrations exposed controls that depend on a user namespace before the
daemon command starts. The final unit delegates that filesystem/process/device isolation to an
explicit trusted `/usr/bin/bwrap` command, which Ubuntu's reviewed AppArmor profile permits, and
retains only rootless-compatible systemd controls. The new
`scripts/systemd-service-smoke.sh` regression runs in CI and both native tag jobs, requires green
observe/workspace-write profiles, approves an exact write, asserts the effect and file bytes, and
then proves bounded drain. Each tag runner repeats it after installing the just-built Debian
package, covering the root-owned package path before purge and the independent install/removal
smoke. The corrected unit also passed the same package-owned mutation proof under Debian 13.5
systemd 257. The local evidence remains dirty-tree development evidence until a tag runs those
gates on both architectures.

A superseded schema-14 dirty-runtime [long-soak attempt](benchmarks/2026-07-13-schema14-long-soak-failure.md)
failed after about 3 hours 22 minutes and lost its temporary timeline during harness unwind. It is
negative evidence, not a partial pass. The improved harness reproduced a current timing defect with
retained evidence: the in-memory fixture reader's one-second descriptor expired after 1.153 seconds
under release-gate contention even though the run allowed five seconds. The fixture and passive
skill readers now share the five-second run ceiling while historical descriptors remain replayable.
The corrected contention regression completed 2,376 turns, 297 rounds, five hard restarts, 14
interrupted-provider recoveries, and two read-tool retries in 602.413 seconds with SQLite integrity
`ok`, complete replay, clean drain, and zero residual work. A fresh current-runtime 24-hour soak is
still required; both the pre-fix schema-15 run and the later 832-turn web-policy run invalidated by
the proxy-thread lifetime audit were intentionally stopped rather than mislabeled. The
fresh run is required to select the verified extracted release daemon explicitly; its report binds
that exact executable SHA-256 instead of merely identifying a Cargo integration build. It must
also use and retain an explicit disk-backed home: a short superseded launch was stopped after the
storage audit found that the default temporary directory was RAM-backed `tmpfs` on this host.

The storage gate now has object-level attribution and bounded compatibility-preserving compression.
The checked [60-second optimized storage observation](benchmarks/2026-07-13-storage-optimized-soak.json)
completed 536 turns with six hard restarts, SQLite integrity `ok`, zero residual work, and 150,680
database bytes per completed turn. That is 29.8 percent below the prior like-shaped 214,609-byte
development observation. Logical canonical digests and legacy raw rows are unchanged; dispatch and
replay reject oversized, malformed, length-mismatched, or digest-mismatched envelopes. Immutable
context-selection row fan-out remains visible rather than being disguised as compressible content.
Schema 15 adds a partial `(completed_at_ms, id)` index for terminal runs; the bounded usage query
is forced through that reviewed index so trailing-day reports do not degrade into full-history run
scans. The v14-to-v15 migration changes no canonical row shape and has forward/integrity/query-plan
evidence.

## Competitive capability gate

These P1 capabilities close the main practical gap with the comparison systems. They may land after
the first production release, but the broader “comparable personal agent” goal is not complete
until they are usable.

| Area | Acceptance |
|---|---|
| Browser | A dedicated agent-only browser profile supports navigate, snapshot, click, type, download, screenshot, and bounded cleanup through an isolated worker; attaching a personal profile is an explicit higher-trust mode. |
| Skills | Versioned instruction/resource bundles have discovery, install, inspect, update, disable, provenance, and approval-aware tool references; skills never grant executable authority by themselves. |
| MCP | Stdio/HTTP MCP servers run out of process with reviewed tool/resource grants, secret scoping, output limits, health, revocation, and crash isolation. |
| Delegation | An agent-facing operation creates durable child runs with explicit context, model/tool/budget scopes, bounded parallelism/depth, cancellation propagation, deterministic result ordering, and owner inspection. |
| Memory UX | The assistant can propose memories, owners can approve/correct them inline, retrieval is cited, session search is usable, and background maintenance cannot silently widen trust. |
| Channels | Telegram and an explicit one-human Discord DM are production supported through the same semantic API and outbox; Slack or another work channel remains the next breadth target. |
| Providers | Provider presets cover OpenAI, Anthropic, OpenRouter, and a local OpenAI-compatible endpoint; fallback policy is owner-visible and never weakens residency/tool semantics. |
| Multimodal/media | Image/file input and image generation are separately permissioned, size bounded, artifact backed, and rendered safely across supported clients. |
| Web/dashboard | A loopback authenticated UI exposes chat, task timelines, approvals, effects, schedules, memory, extensions, provider health, costs, and recovery without creating alternate state. The conversation/control, exact 30-day and per-task usage/cost, unknown-effect recovery, keyed schedule-creation/lifecycle, governed-memory, and extension-lifecycle subsets are complete: a foreground `mealyctl` adapter aggregates canonical projections, admits durable input, renders timelines and exact approvals, cooperatively cancels tasks, and reconciles only linked `outcome_unknown` evidence. The history report binds root/delegated/validation runs to the exact owner through durable lineage, groups zero-reservation terminal settlement by UTC completion day, and validates exact browser integers; per-task usage preserves settled versus reserved provider-neutral microunits. Neither infers an invoice. Schedule creation retains a client-proposed canonical UUIDv7 across ambiguity; exact replay returns canonical state without another event and semantic drift conflicts. Lifecycle transitions remain revision fenced. The adapter also provides bounded governed-memory administration and validated extension inventory/detail plus manifest-derived health-gated enable/disable/revoke. Stable provenance/state preflights reconcile identical completed delivery without blind retry. The daemon bearer remains outside the browser behind a separate 256-bit capability, exact Host/Origin checks, strict typed/body/concurrency bounds, an 8 MiB streamed daemon-response ceiling, DNS-rebinding/CSP/no-store controls, and no arbitrary proxy. Extension install/stage/invoke, provider-invoice reconciliation, and general recovery actions remain open. |

Memory UX acceptance is complete: the REPL derives and prints the ordinary agent memory
namespace, and exposes explicit remember/list/search/status/activate/correct/expire/reject/delete
commands while other task watchers remain live. `memory remember --approve` provides the same
scriptable two-request proposal/activation workflow, generated exact-content provenance, and
recoverable IDs after partial failure. General-assistant baselines may suggest an exact
`/remember TEXT` command, must label it as a proposal, cannot claim it was stored, and direct
sensitive categories to the advanced reviewed workflow; only the authenticated owner command can
activate state. Retrieval remains cited untrusted evidence. `/history` and `session search` return
digest-linked 512-byte excerpts from canonical user/final-assistant text, are bounded to 100 newest
turns, and apply exact principal/channel-binding scope before literal matching. There is no
background memory activation path that could silently widen trust.

Skills acceptance is complete for local data-only bundles: strict offline inspection verifies a
complete no-symlink inventory and every declared digest/size without executing content; approved
install/update publishes immutable private bytes but leaves the revision disabled; enable/disable
is separately fenced to the exact manifest digest. Startup re-verifies all installed packages,
injects only bounded enabled instruction assets with manifest/asset provenance, and exposes passive
resource metadata without content. `skill.read_resource` provides bounded UTF-8/base64 chunks with
`skill://` citations and recorded replay, while `requiredTools` remain references that never widen
normal tool policy. Complete backup/restore/export and migration rollback retain the referenced
package bytes. Network marketplaces, signatures beyond owner-pinned SHA-256, and executable helpers
remain extension concerns rather than hidden skill authority.

Browser acceptance is complete for the read-only research subset, but not yet for the full
competitive row. Linux x86_64 can fetch a repository size/SHA-pinned Chrome Headless Shell,
inspect it without host network/home authority, publish the complete content-addressed inventory,
and activate it only after a live isolated CDP/navigation/render test. `browser.snapshot` uses a
new agent-only profile and private network namespace per call, a Unix-socket host proxy restricted
to the intersection of existing web destination claims and the initial exact origin plus GET/HEAD,
cross-origin redirect/subresource/link denial, CDP non-read/auth/download/upgrade/direct-socket
denial, bounded accessibility text/elements, optional 512-KiB PNG, one exact accessible GET-link
follow, one exact native form-free button activation, or one exact native non-password text/search
fill with optional selected-field-only same-origin GET, or one 512-KiB GUID-confined same-origin
attachment capture, deterministic cleanup, durable
citation/artifact evidence, and Chrome-free replay. Both proxy layers cap one call at 32 concurrent
and 256 total accepted connections, use unwind-safe concurrency leases, and join completed handlers
during the call so same-origin connection churn cannot retain thread resources until shutdown. The
download adapter normalizes integral CDP JSON number encodings but rejects fractional, negative,
or inexact progress values, and its protocol failure is independently classified. Three
consecutive fresh-process conformance runs pass after that regression fix. The
systemd unit supplies the physical-memory/swap/task cgroup boundary V8 needs. CLI lifecycle,
real-browser, real-provider, backup, migration, tamper, non-read, WebSocket, and replay tests are
mandatory in CI and release. Arbitrary clicking/keyboard events, POST or multi-control form
submission, uploads, unbounded/owner-path downloads, persistent sessions, a personal-profile trust
mode, non-x86 release evidence, and effect/approval semantics remain open; Mealy does not describe
this subset as arbitrary browser control.

MCP acceptance is complete for the first least-authority local tool subset, but not for the full
competitive row. Linux can inspect and activate native ELF stdio servers speaking exact revision
`2025-11-25`; it pins executable bytes, direct non-secret arguments, the complete paginated tool
set, and each selected full definition/schema. Startup and every call repeat discovery in a fresh
empty-environment, no-network Bubblewrap process with no home/workspace/secrets and hard protocol,
resource, time, cancellation, and output bounds. Model-visible calls are cited and durable;
recorded replay remains complete after executable removal. Stopped-daemon list/enable/disable/revoke,
safe mode, configuration history, complete backup/restore, and cross-schema rollback are
process-tested. HTTP transport, resources/prompts, server credential delegation/OAuth, intentional
workspace mounts, effectful MCP tools, long-lived session health, and non-Linux enforcement remain
open before the broader MCP gate is passed.

Delegation acceptance is complete for bounded serial child work. The provider-visible
`agent.delegate` operation validates a self-contained objective, instructions, one-to-eight
success criteria, and optional bounded object context. One transaction reserves the parent's
delegated-run and tool budgets, creates child task/run/lineage and an isolated turn, starts the
parent tool, releases its lease, and parks the parent. The normal scheduler claims the child; its
context excludes parent conversation, memory, approvals, effects, mutations, processes, and
further delegation. Its effective tools are the exact read-only intersection of current parent
authority and policy, with a separately capped three-model/two-tool/90-second budget. Terminal
child settlement records a structured `delegation://result`, releases reservations, and requeues
the parent atomically. Parent cancellation propagates to queued/in-flight children. Owner-bound
list/status API and CLI views expose lineage, authority, budget, state, and result; public-process
tests prove success, isolation, parent resume, in-flight cancellation, root/child recorded-only
replay, and context-epoch revocation. Per-parent parallelism is deliberately one and child depth is
zero; broader fan-out is not implied by the current claim.

Local text attachment acceptance is complete as a narrow input subset: chat-native `/attach PATH`
and scriptable `session send-file` open
one owner-selected no-follow regular file, allowlists UTF-8 text/source extensions, caps bytes at
256 KiB, binds basename/media/size/SHA-256 inside an untrusted frame, withholds the host path, and
uses ordinary durable delivery/idempotency. Unit, pseudo-terminal, and real-daemon smoke evidence cover symlink,
invalid UTF-8/NUL, unsupported type, oversize, prompt-shape, and admission boundaries. The broader
multimodal/media row is still open: image/audio/video input, provider modality negotiation,
artifact-backed binary transport, image generation, and safe channel/dashboard rendering are not
implemented or claimed.

## Required evidence per implementation slice

A capability is not complete when only its happy-path adapter exists. Each slice must include:

1. a versioned typed contract and validated non-secret configuration;
2. least-authority policy and credential scope;
3. byte, item, concurrency, rate, time, token, cost, and retry bounds as applicable;
4. durable preparation and terminal evidence before another step depends on it;
5. cancellation, crash, timeout, malformed-response, and restart behavior;
6. owner-facing status, diagnostics, and remediation;
7. public-API process tests plus adversarial unit/integration tests;
8. clean-install usage documentation and an honest unsupported-platform statement.

## Implementation order

The critical path is:

1. secret broker and guided provider setup;
2. streaming interactive chat and provider health/retry/fallback;
3. read-only workspace and web tools;
4. approval-gated file/shell/process tools;
5. Telegram or Discord plus durable schedules;
6. packaged install/upgrade/release pipeline;
7. load, soak, live-provider, clean-machine, and recovery acceptance;
8. effectful browser interaction, broader HTTP/resource/credential-bearing MCP, additional providers/channels,
   multimodal input, and broader dashboard administration beyond its completed
   conversation/control, task-usage/cost, unknown-effect, schedule-creation/lifecycle, governed-memory, and
   extension-lifecycle subsets.

Security or recovery failures stop feature expansion until fixed. Capability breadth does not
justify weakening the existing durable effect, authorization, replay, or sandbox invariants.
