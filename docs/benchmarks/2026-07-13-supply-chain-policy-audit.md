# Supply-chain and workflow policy audit — 2026-07-13

This is dirty-development evidence for the current local tree, not an attestation or a substitute
for the tag workflow. It records the policy gates added after diagnosing the prior GitHub Actions
failure.

## Prior remote failure diagnosis

GitHub run
[`29149482019`](https://github.com/Amekn/project_mealy/actions/runs/29149482019) tested commit
`5f52f744be8b196f604120a978478b4fd84567ce`. Its strict workspace job reached the extension-host
integration test without installing Bubblewrap and failed closed because `/usr/bin/bwrap` did not
exist. Its separate sandbox job installed Bubblewrap, but all eight sandbox tests failed their host
probe when Ubuntu's AppArmor restriction denied private loopback setup with
`RTM_NEWADDR: Operation not permitted`. The Linux, macOS, and Windows control-plane portability
jobs passed. The checkout-v4 Node 20 notices were warnings, not the test failure.

The current quality job installs Bubblewrap before the complete suite. Every Ubuntu sandbox-using
job also activates the distro's reviewed `bwrap-userns-restrict` profile while retaining the
host-wide namespace restriction, then requires an immediate private-network Bubblewrap probe.
Checkout is updated to a current full-SHA pin. These repairs pass local syntax, workflow-auditor,
package, and sandbox gates, but remain unverified by GitHub until the owner authorizes a commit and
push.

## Workflow boundary

- `actionlint` 1.7.12 passed all three workflow files with Ubuntu 24.04 ShellCheck 0.9.0.
- `zizmor` 1.26.1 passed the offline auditor profile at low-or-higher severity with no findings;
  an additional online run also reported no findings.
- Every action reference is a full commit SHA. Checkout uses `persist-credentials: false`.
- Checkout 7.0.0, artifact upload 7.0.1, and artifact download 8.0.1 use their current full-SHA
  pins; the download boundary treats an artifact digest mismatch as fatal by default.
- CI cancels superseded work per ref; releases and paid live probes use non-cancelling serialized
  groups. Every job has an explicit 20-to-180-minute ceiling appropriate to its scope instead of
  inheriting GitHub's much looser default.
- Release matrix inputs enter shell steps only through environment variables. Paid credentials are
  scoped to the reviewable `live-provider-smoke` GitHub Environment. Exact provider conditions
  expose only the selected provider's secret; an absent selected secret cannot fall through to a
  different provider credential. The live leak detector reads its fixed-string pattern through a
  pipe-backed file descriptor, so the credential is not copied into a `grep` process argument while
  proving that it stayed out of outputs and configuration.
- Ubuntu jobs keep AppArmor's host-wide unprivileged-user-namespace restriction enabled, activate
  the reviewed distro `bwrap-userns-restrict` profile explicitly, and fail before tests unless a
  private-network Bubblewrap probe succeeds. They no longer disable that mitigation globally.
- The dashboard process smoke bypasses ambient proxies, bounds every loopback connection/request,
  supplies its ephemeral capability through a private curl configuration file, and supplies the
  daemon-bearer leak pattern through a pipe-backed descriptor rather than process arguments. The
  complete dashboard smoke passed after that harness hardening.
- Branch and tag gates build the complete workspace Rustdoc surface with warnings denied in
  addition to executing doctests, so a broken intra-doc link cannot pass on executable coverage
  alone. The stricter local build completed without a warning before the workflow change.
- Ordinary branch/PR portability now includes the same native `ubuntu-24.04-arm` runner label used
  by the release matrix, so a tag is no longer the first ARM64 compile gate.
- Every immutable third-party action pin was resolved directly against its upstream repository and
  matched the annotated version comment: Checkout v7.0.0, SBOM Action v0.24.0, Attest v4.1.1,
  Upload Artifact v7.0.1, and Download Artifact v8.0.1. Each was also that repository's latest
  published release at the 2026-07-14 review.
- After correcting a Linux-only test-helper import gate, the exact current tree passed an offline
  Rust 1.96 MinGW `--workspace --all-targets --all-features` check for
  `x86_64-pc-windows-gnu` and an equivalent GCC cross-check for
  `aarch64-unknown-linux-gnu`. Native macOS/Windows results and native ARM64 runtime, package, and
  reproducibility results remain external workflow evidence.

The first auditor pass found credential persistence, missing concurrency controls, direct matrix
template expansion in shell, undocumented write/attestation permissions, and secrets outside an
Environment. Those findings were corrected before this clean result. The pinned auditor is now a
mandatory CI gate. A 2026-07-15 upstream freshness review retained Actionlint 1.7.12,
cargo-deny 0.20.2, cargo-audit 0.22.2, cargo-auditable 0.7.5, cargo-about 0.9.1, and Syft 1.46.0,
and advanced zizmor from 1.26.1 to the newly published 1.27.0 bug-fix release. The same review
confirmed Chrome for Testing stable remained 150.0.7871.115 and every SHA-pinned GitHub Action
still matched its latest upstream release.

## Rust dependency boundary

`cargo-deny` 0.20.2 passed `advisories`, `bans`, `licenses`, and `sources` for the all-feature graph
across supported Linux x86_64/ARM64, macOS x86_64/ARM64, and Windows x86_64 targets.

The checked policy:

- accepts only the explicit permissive SPDX set in `deny.toml`;
- permits only crates.io and denies unknown registries and Git dependencies;
- denies wildcard dependencies and exact-fences every internal path dependency;
- marks every proprietary workspace package non-publishable;
- bans `native-tls`, `openssl`, and `openssl-sys` from the rustls-only transport graph; and
- denies new duplicate crate generations while documenting exact legacy upstream exceptions.

The bootstrap script downloads only the official Linux musl archive for the detected x86_64 or
ARM64 architecture, bounds HTTPS redirects, connection/total time, and transfer bytes, enforces the
repository-pinned byte size and SHA-256, extracts the exact executable member, and publishes no
output path until verification succeeds. The bounded bootstrap was rerun successfully against the
exact pinned `cargo-deny 0.20.2` archive. CI and the tag workflow both execute the same checked
policy. The actionlint bootstrap independently applies an exact archive-size ceiling before its
pinned SHA-256 check.

## Dependency attribution boundary

Pinned `cargo-about` 0.9.1 ran twice in frozen/locked/offline mode over the all-feature union of the
two supported Linux targets. Both renders were byte-identical. The resulting passive HTML notice
is 37,533 bytes, covers 239 dependency package/version rows, has SHA-256
`fafe833afdd0c03c2607d010630f5d138c730216722d7b3e4af14f226f8da561`, and contains no local build
path or active/network HTML element. The release archive binds it through `PAYLOAD-SHA256SUMS` and
`BUILD-MANIFEST.json`; the Debian package additionally installs an identical documentation copy.
This is automated attribution evidence, not legal advice.

## SBOM boundary

Syft 1.46.0 ran from the exact container image
`anchore/syft@sha256:473a60e3a58e29aca3aedb3e99e787bb4ef273917e44d10fcbea4330a07320bb`
and scanned a bounded directory containing only the two auditable release executables. Two fresh
renders were independently normalized to the release version, target, commit, and source epoch;
the normalizer removed host/time identity, canonicalized binary paths and ordering, and rejected
local build paths. The post-service-fix CycloneDX documents were byte-identical, 448,964 bytes,
contained 465 component rows and 285 dependency rows, and had SHA-256
`0530e8e5e79e0143592802f43eb32089856e4e9cda0c9f43ccb3b6e1c8020c5e`. The tag workflow requests
the same scanner version through its full-SHA-pinned SBOM action and validates both executable
components before packaging.

## Release source-path and binary reproduction boundary

An independent stripped-binary inspection found that the ordinary Rust release build retained the
developer's repository and Cargo-registry paths. The release workflow now builds only through
`scripts/build-release-binaries.sh`. It rejects inherited Rust flags, remaps the account home,
Cargo home, repository, and relative source roots to stable `/mealy/...` identities, and fails if
either resulting executable still contains any exact host path. The packager separately rejects
common Linux, macOS, and Windows user-home path shapes, including a negative fixture that appends a
synthetic private build path to an otherwise valid executable.

Two fresh locked auditable release builds after the service/sandbox integration repair used
different Cargo homes and target directories. Both pairs were byte-identical:

- `mealyd`: `d3d93166fd832b9515cc2ea29aebb9382b21e2bca4b8a8e391b0739979b10ff1`
- `mealyctl`: `5a8ab5f6b8c5108193921702bf5a2b879ab6f87d850664cd65606b1149509cdb`

Neither pair contained a Linux, macOS, or Windows user-home path. `cargo audit bin` found the
embedded `cargo auditable` inventory in both promoted executables (263 and 255 dependencies,
respectively) and reported no advisory. This is same-host dirty-tree reproduction evidence; native
ARM64 and published provenance remain tag-workflow gates.
The tag workflow pins `cargo-auditable` 0.7.5; rebuilding through that wrapper produced the hashes
above. Its package-ID parser fix changed no Mealy inventory. The final source changes add the
read-only systemd ownership proof and remove one outer unit restriction that blocked secure worker
file creation.

## Trusted runtime-helper boundary

The daemon previously resolved `ldd` through the inherited `PATH`. Absence failed closed by
omitting mutating tools, but a substituted same-name program would have executed in the trusted
daemon before Bubblewrap. Runtime discovery now accepts only exact protected
`/usr/bin/ldd`, clears its environment, retains only deterministic `LC_ALL=C`, and places `--`
before the canonical worker or configured root-controlled command path. A unit test validates the
program/argument/environment construction and executes the helper. A public release-process test
starts the daemon with an otherwise empty environment and `PATH=/nonexistent`, requires `doctor`
to report `workspace_write` enforceable, and drains cleanly. The Debian package now declares
`libc-bin` explicitly rather than assuming this helper is present in the base image. A direct ELF
dependency audit also found `libgcc_s.so.1` in both exact release binaries; the package now declares
its `libgcc-s1` owner instead of relying on it being incidental base-image state.
The Debian builder now reads each real executable's exact ELF `NEEDED` set and fails if it differs
from the reviewed architecture-specific loader/libc/libgcc/libm closure. Optional browser metadata
separately suggests its audited direct libraries, a deterministic font, and the helper's
`curl`/`unzip` prerequisites without making them core daemon dependencies.

The earlier hardened archive used as a 24-hour-soak wrapper had SHA-256
`15af1d79607472ccebc50a0a4fee34a9ce12f7a34aec660cc17a66e5b818fd9d`; its extracted daemon is the
now-superseded `1a6b636c...` binary. An actual systemd-unit mutation later proved that candidate
unusable for governed file creation, so the soak was stopped and neither the archive nor its
partial runtime can satisfy a release gate.

## Generated systemd service boundary

The PID-1-container evidence below records an earlier systemd-native form of the boundary. A later
GitHub-hosted Ubuntu 24.04 user manager retained the host's default AppArmor restriction on
unprivileged user namespaces and rejected those directives before `mealyd` could start with
`218/CAPABILITIES`. The next candidate invoked trusted `/usr/bin/bwrap` directly from the rootless
unit. GitHub run `29357794460` proved that proposal was also incompatible with the host's reviewed
policy: the outer process started, but the packaged `unpriv_bwrap` child profile denied the
capabilities the nested per-tool Bubblewrap needed. The final candidate directly executes the
daemon under rootless-safe systemd process/cgroup controls and reserves Bubblewrap for the
lower-authority per-request workers. The GitHub systemd mutation job remains the authoritative
regression for that default-hardened Ubuntu host shape.

An Ubuntu 24.04 PID-1 container with a real systemd user manager reproduced four independent outer
unit incompatibilities. Overflow-UID ownership initially hid trusted installed helpers; three
namespace protections blocked Bubblewrap's nested hostname or `/proc`; and
`RestrictSUIDSGID=true` blocked the worker's secure `openat2(O_CREAT)` path after `doctor` was
already green. The final unit uses exact single-identity/read-only overflow-owner evidence,
`ProtectProc=invisible`, and `ProcSubset=pid`, and deliberately omits those incompatible
restrictions while retaining `NoNewPrivileges`, the private umask, read-only system/home views,
capability dropping, and the remaining resource/namespace controls.

`scripts/systemd-service-smoke.sh` refuses to replace an existing user unit, generates and links
the exact Mealy unit, requires observe/workspace-write sandbox enforcement, approves one exact
mutation, asserts the effect itself and file bytes, then proves bounded drain and cleans its unit
and home. It passed against both debug and the exact optimized auditable binaries above. CI runs it
after direct Bubblewrap conformance; both native tag runners run it again against their exact
release bytes. `actionlint` 1.7.12 and `zizmor` 1.26.1 were rerun after adding those workflow steps
and remained clean.
The current harness additionally refuses every non-container user manager unless
`MEALY_SYSTEMD_SMOKE_ALLOW_HOST=true` is set, bounds every manager operation, unlinks only its exact
unit, and retains an executable/cgroup-checked service PID for direct cleanup if the manager becomes
unresponsive. This guard was added after a Fedora development manager entered a pathological reload;
that host event is not package-runtime evidence.
The manager recovered without a restart after systemd 259.7 logged a 2,756,963-millisecond reload.
It then exposed 130,790 pre-existing failed user units, 130,789 of them unrelated KDE DrKonqi
coredump-launcher instances; processing that accumulated unit graph explains the reload cost. No
Mealy unit remained, rootless Podman became responsive again, and the production-candidate soak had
continued in its separate login scope. Clearing those unrelated failure records is an owner host-
maintenance decision, not part of Mealy's test cleanup.
The harness now counts failed units through the already time-bounded manager call and refuses more
than 1,024 even after host opt-in, before linking a unit or requesting reload.
The same package-owned audited binaries then passed the complete mutation proof under a separate
Debian 13.5 PID-1 container with systemd 257 and a real lingering user manager. That cross-distro
proof is still privileged-container/dirty-tree evidence, not a substitute for the native tag jobs.

## Production panic-path review

An additional Clippy pass enabled `unwrap_used`, `expect_used`, `panic`, and `unreachable` warnings
over workspace library/binary targets without compiling test targets. It found no production
`unwrap` or direct `panic!`. Each reported `expect`/`unreachable!` site was manually traced to a
dominating constructor validation, immediately preceding preflight/shape check, or enum branch
already returned above it: MCP grant accessors, sandbox command selection, governed-write scope and
grant construction, worker replacement shape, daemon broker setup, provider role normalization,
shutdown-status mapping, and offline CLI dispatch/retry exhaustion. Externally fallible I/O,
configuration, database, provider, and tool paths remain typed errors. This is a focused control-
flow review, not a proof that future callers can safely bypass those constructors.

## Optimized runtime validation boundary

The complete locked workspace matrix also passed with release optimizations, ThinLTO, stripped
symbols, every target, and every feature. All executed unit, property, integration, public-process,
sandbox, channel, provider, backup/activation, migration, and rollback tests passed. Only tests
whose contracts explicitly require the reviewed Chrome bundle, a live network credential, or the
separate long-soak harness remained ignored in that aggregate run.

The ignored browser paths were then selected individually against the size/SHA-pinned Chrome
Headless Shell 150.0.7871.115 bundle. The optimized isolated-worker conformance test, stopped-home
browser lifecycle test, and model-visible citation/artifact/replay test all passed. The official
Chrome for Testing stable metadata still identified 150.0.7871.115 after those runs. The optimized
credential-free public-HTTPS adapter test also passed against its live endpoint. Brave Search and
real model-provider smoke remain external credential-bearing gates rather than being replaced by
these checks.
Both CI and release browser jobs now install the same reviewed direct Headless Shell runtime
libraries and deterministic basic font package listed by the Debian package instead of relying on
incidental GitHub runner-image contents.
A fresh run of the shipped helper after adding HTTPS-only redirect, connection/total-time, and
transfer-size ceilings reproduced the previously reviewed bundle byte-for-byte: 287 regular files,
zero symlinks, and SHA-256
`5f848d6a8eb222ee1f9cee068573bd0bb0c5ccfaac880aec1cf44de5c4285887` for the sorted per-file
checksum inventory.

## Browser connection resource audit

A 2026-07-14 static lifetime audit found that both browser proxy accept loops limited concurrent
connections but retained every completed `JoinHandle` until the whole browser call ended. A hostile
same-origin page could repeatedly close short connections and accumulate joinable-thread resources
inside the daemon while remaining below the concurrent ceiling. The host policy proxy and the
private-network loopback relay now reap finished handlers on every accept-loop iteration, hold each
active count through an unwind-safe lease, and independently stop after 32 concurrent or 256 total
accepted connections per call. Focused unit/process regressions prove concurrency release, the total
ceiling, prompt handle reaping, and closure of connection 257.

The exact-binary soak using `mealyd`
`408d5a45657b34e047122521e1d108fcc7e76ca51b237f96579d02c2869aa043` was intentionally stopped at
832 successful turns after two forced restarts when this audit invalidated that binary. Its SQLite
integrity remained `ok`, but no partial report is release evidence. The retained diagnostic home is
named `superseded-web-policy-proxy-thread-reaping`; a new reproducible binary and a fresh full
24-hour clock are required.

Two cold auditable builds of the corrected source from distinct Cargo homes and target trees were
byte-identical: `mealyd` SHA-256
`bda5e8c4250612e6882711e70e15fa47e3f7661535160983dff906ffe1f4907e` and `mealyctl` SHA-256
`82197a44ff30876c2e69a664d3cdc5a6cbc04a7684a8fd1909014e1c941428c0`. Exact-binary RustSec scans
found 263/255 embedded dependencies and no finding; host-path and dynamic-link inventories remained
clean. Independent pinned-Syft runs produced the same 465-component/285-edge SBOM at SHA-256
`df2a65c59348397ec4e9a314ebb416fd471521fd263e583a4f27ed4a7da87a1a`, and the unchanged
37,533-byte license notice remained SHA-256
`fafe833afdd0c03c2607d010630f5d138c730216722d7b3e4af14f226f8da561`.

The two pre-evidence archives were byte-identical at SHA-256
`fd3f963188959a9fb02da3b8ea7268cc1c92a98b210564d310f9eae3d13e26cc`; the two 18,678,040-byte
Debian packages were byte-identical at SHA-256
`8981ce203a2b029883f792bd87fda5bbf56f568677ab28c8769d40857ba0d5c0`. The archive smoke completed
task `019f5bdd-c803-72f2-81f8-a403916aea0b`; an Ubuntu 24.04 direct Debian install/replay completed
task `019f5bdf-57b7-7220-9d9c-851f10937b94`, and Lintian 2.117.0 exited cleanly with error and
warning tags fatal. A separate Ubuntu systemd 255 package-owned pass completed session
`019f5be0-edce-7c63-b3bb-349447ccff54`, task
`019f5be0-ede9-7640-956a-9ec7af1c7c36`, and effect
`019f5be0-eea0-7872-abf8-b6bb4ee5449a`, then left the unit inactive/not-found with no failed unit or
daemon. These packages predate this paragraph and the pending soak report, so their hashes remain
pre-evidence rather than final release assets.

Before the long clock restarted, the extracted package daemon completed a 61.483-second accelerated
sanity run: 400 successful turns, 50 rounds, five hard restarts, 28 interrupted provider turns, five
safe read-tool retries, SQLite integrity `ok`, complete recorded replay, zero residual operational
gauges, and 52,916 KiB peak RSS. The report binds the exact `bda5e8c...` daemon and disk-backed Btrfs
home. This short result is launch evidence only; it cannot substitute for the paced 24-hour gate.

## Provider normalized-output resource audit

A subsequent 2026-07-14 provider audit found two normalization ceilings that were weaker than the
documented canonical-output boundary. Anthropic streaming limited each text block to 64 KiB but
concatenated multiple individually valid blocks without checking the aggregate. Responses parsed
function arguments under the 8-MiB response-body ceiling without its own normalized argument cap.
The former could emit and persist oversized final text; the latter could persist an oversized model
tool proposal before normal tool-schema rejection. Anthropic now accounts aggregate text before
each initial block/delta is accepted or emitted and defensively rechecks at terminal assembly.
Responses now rejects a raw function-argument string above 256 KiB before JSON parsing. Focused
regressions exercise two individually valid Anthropic blocks and one syntactically valid oversized
Responses object.

The `bda5e8c...` paced soak was intentionally interrupted when this finding invalidated its runtime.
At shutdown it contained 248/248 successful tasks and runs, 248 released leases, 744 delivered
outbox records, SQLite `quick_check` `ok`, and no failed task/run. No partial report was promoted;
the 28-MiB diagnostic home is retained as
`superseded-anthropic-stream-aggregate-bound`.

Two isolated locked auditable rebuilds were byte-identical: `mealyd` SHA-256
`df37a01dc21f9f207ebad16164daea926626b8eabd9377ad8e51c6cf1ff95938` and `mealyctl` SHA-256
`078db71891f079ae962d1cf698b7d64d1b402f6f12004d17f6a0cd1be3104c29`. Both contain only the
expected loader, libc, libgcc_s, and libm dynamic dependencies; host-path scans were clean. Exact
`cargo audit bin` inspection found 263/255 embedded dependencies and no advisory. The replacement
daemon then completed a 62.341-second accelerated run with 400 successful turns, 50 rounds, five
hard restarts, 29 interrupted provider turns, three safe read-tool retries, SQLite integrity `ok`,
complete replay, zero residual gauges, and 53,308 KiB peak RSS. A fresh 24-hour paced run now binds
the exact `df37a01d...` executable. Independent pinned-Syft inputs normalized to the same
465-component/285-edge SBOM, SHA-256
`27c3d044164e24ce3ec25a752a0712f0e12066fa073f8f80ec358ed04611fdcd`; the reproducible
37,533-byte license notice remains
`fafe833afdd0c03c2607d010630f5d138c730216722d7b3e4af14f226f8da561`. Final package hashes remain
pending the long report and resulting documentation bytes.

Two pre-evidence archives containing that pair were byte-identical at SHA-256
`27b5700152818539d33aea69ea83e54795481338271ba9f5df1b56e6bf733cff`; the corresponding Debian
packages were byte-identical at
`c057ee6345018dbfdeb6907838a8870b8998ba30b92f0462fc1695a3d81dbc62`. The archive manager smoke
completed task `019f5c05-1e63-7f13-8954-fbe18f29f40e`; a clean Ubuntu 24.04 direct Debian
install/replay completed task `019f5c05-9d59-7491-ba9c-f80f73af79d2`, and Lintian
2.117.0ubuntu1.5 exited zero with error and warning tags fatal. A separate disposable Ubuntu
24.04 systemd 255 user-manager proof approved the package-owned binaries' mutation under session
`019f5c06-5a42-72e2-83f9-6f5cfb826f93`, task
`019f5c06-5a67-7930-9cb0-c1edbea43ac0`, and effect
`019f5c06-5b10-7ab0-9f17-7ef69d0c9500`, then left the temporary unit inactive/unlinked with no
failed user unit. These packages necessarily predate this evidence paragraph and the pending long
report; they are reproducibility/install probes, not final release assets.

The prior paced exact-package soak was deliberately terminated once the service-only mutation
failure invalidated its binary. Its partial rounds and restarts are diagnostic evidence only. A
fresh 24-hour run must start from a package containing the corrected exact daemon above.

## Provider response identity and failure-redaction audit

A deeper 2026-07-14 contract review found that the Responses adapter accepted terminal envelopes
without validating the required `object` discriminator or returned model, while the Anthropic
adapter shape-checked but did not compare the returned model with the configured request. The
Responses incomplete path also copied an arbitrary provider-supplied reason into Mealy's error.
Body response IDs and request-ID headers were length-checked but not uniformly trim/control-
checked. These defects could let a misconfigured gateway pass onboarding under the wrong model or
persist/reflect provider-controlled metadata through an error or request identifier.

Runtime and onboarding now require a bounded safe response identity, `object: response` for the
Responses contract, and the exact configured model in Responses and Anthropic terminal/streaming
envelopes. Unsafe request-ID headers are discarded at both transport extraction and normalized
output assembly; unsafe body IDs fail closed. Incomplete reasons and unknown provider metadata map
only to fixed local classifications. Focused unit/process validators cover wrong object/model,
terminal and streaming Anthropic mismatch, control-bearing IDs, unsafe header fallback, and a
secret/control canary in `incomplete_details.reason`.

The `df37a01d...` paced run was intentionally stopped when this finding invalidated its subject. At
shutdown the retained home contained 304/304 successful tasks and runs, 304 released leases, 912
delivered outbox records, and SQLite `quick_check` `ok`; no report was promoted. The 38-MiB
diagnostic home is retained as `superseded-provider-response-identity-redaction`. The prior
archives, Debian packages, SBOM, and accelerated run remain useful reproduction diagnostics but
are not release assets. New reproducible hashes and a fresh accelerated/24-hour subject are
required after the complete contract fix.

Two cold-target builds using distinct Cargo homes then reproduced `mealyd` SHA-256
`119d56e3f3c329c103c36c1d9cdfb1b144c6714872e095cc1aec6f24b0ccb442`. Before the long clock, a
setup/runtime parity review found that the CLI probe still accepted any nonempty Responses output
and only a partial Anthropic stream shape. Onboarding now requires usable bounded text, no
unexpected tool call, consistent usage within the configured input/output limits, matching
Responses preview/terminal text, empty Anthropic `message_start` content, and ordered matching
content-block indexes. A public-process regression proves a wrong terminal model fails before
configuration publication or broker mutation. This CLI-only hardening left the daemon hash
unchanged and produced probe-parity `mealyctl` SHA-256
`0b69d5a2e4f50746ad801b71df85279468ccfb05de70a6e996f6b8183ec20c8f`; both binaries contain only
the expected loader/libc/libgcc_s/libm dependencies, retain no `/home` path, and expose 263/255
auditable dependencies with no RustSec finding.

A subsequent client-only local-boundary audit found one unbounded successful admission decode, an
unbounded SSE parser/unsafe raw event display, permissive structured-error display, and
check-then-reopen local descriptor/native-executable paths. The corrected client streams every
ordinary response into the shared 8-MiB decoder, requires exact successful/error API identity,
bounds each complete SSE record before parsing, checks monotonic cursor/type/body identity, and
prints only typed terminal-safe JSON. It rejects redirected or permissive Mealy homes, opens the
64-KiB descriptor and native ELF inputs with no-follow exact-file checks, caps extension manifests
at 1 MiB, and applies 30-second ordinary plus ten-minute named maintenance request ceilings while
leaving cursor-resumed SSE open-ended. Environment-held passphrases/tokens and their transient
serializable command copies are zeroized at their earliest client-side lifetime boundary. All 40
client units, strict Clippy, and every non-opt-in client process suite passed. A Windows-specific
canonicalization adapter now removes the platform's verbatim path prefix before the same exact-path
private-home check; the complete locked workspace also passed all-target/all-feature Rust 1.96
checks in disposable MinGW x86_64 Windows and GCC AArch64 Linux environments, and the corrected
client additionally linked as a stripped x86_64 PE executable. Both Linux programs also
cross-linked as stripped AArch64 PIE executables with only the expected AArch64 loader plus
libc/libgcc_s/libm contract; native AArch64 execution remains a tag-runner gate. Two independent
auditable builds kept `mealyd` exactly
`119d56e3f3c329c103c36c1d9cdfb1b144c6714872e095cc1aec6f24b0ccb442` and reproduced `mealyctl`
`bccb6e45b4e4b132734f2158ac14ae1ac8f0008d633d5027ab56f95cc7490cfa` with build ID
`17a8d65f1af8d5c65eb11df4e9ba41607df3ef67`. The new client embeds 255 dependencies and both exact
binaries remain RustSec-clean with only loader/libc/libgcc_s/libm dynamic dependencies. Both are
stripped position-independent executables with non-executable stacks, GNU RELRO, and immediate
binding. Because the daemon bytes did not change, the active paced run remains valid; the
pre-report packages above are still intentionally superseded by this CLI and the pending report
documentation. A fresh private
home then exercised those exact release binaries together: session
`019f5c62-a401-7813-b023-80d1e9f45364` admitted and completed one durable fixture turn, every CLI
response passed the exact version contract, SQLite `quick_check` returned `ok`, and bounded drain
ended the daemon cleanly. A second fresh-home smoke used session
`019f5c63-36d9-7192-aeae-7aed54e33753` to consume cursor 1 through the exact release client's new
typed/bounded SSE path before another clean drain.

The same current release pair also passed the documented interactive path under a real
pseudo-terminal. Session `019f5c80-643d-7e52-af09-a749511eec93` accepted input while keeping the
`you>` prompt active, rendered model/tool progress and a terminal fixture response, and completed
task `019f5c80-645b-74c0-9bb2-489a0c004021`. A fresh daemon process then returned that task and its
complete recorded-only replay with zero live provider/tool calls before acknowledging a clean
bounded drain.

Two client-boundary interim archives were byte-identical at SHA-256
`1282d1a87a8f7342ffb91c2820da056608819a573a4a96249d0a8f27bfafefc0` (18,566,623 bytes), and their
Debian packages were byte-identical at
`a4e3ae60df5d2d226e7b358ca3bf0f43e3a32d7ad531bba1829a0da2ff79a5c9` (18,630,614 bytes). The
checksum-driven archive installation completed task
`019f5c64-dcf3-78a1-ab57-4f938bba75a3`. A disposable Ubuntu 24.04 installation required
Bubblewrap, completed task `019f5c65-9869-7c43-853a-0a4b5684b9ca`, drained, purged the package,
and preserved state; Ubuntu Lintian again exited zero with error and warning tags fatal. These
assets validate the hardened client/install boundary but remain deliberately pre-report,
unattested x86_64 diagnostics rather than release artifacts.

The exact `119d56e3...` daemon completed a 60.522-second accelerated external-binary gate with 392
successful turns across eight sessions, 49 rounds, four hard restarts, eight interrupted provider
turns, three safe read retries, 52,716 KiB peak RSS, SQLite integrity `ok`, complete recorded
replay, and zero residual gauges. Two independent pinned-Syft 1.46.0 runs normalized to the same
465-component/285-edge CycloneDX document at SHA-256
`cf13a213e15c415a95ed7a00b531e748df418754a2e73425cf2cc1a16d58978c`; two independently generated
37,533-byte license notices remained byte-identical at
`fafe833afdd0c03c2607d010630f5d138c730216722d7b3e4af14f226f8da561`. This accelerated result and
metadata qualify the exact daemon to begin a fresh paced 24-hour run; they do not substitute for
that long report or final post-report packages.

Two pre-report archives were byte-identical at SHA-256
`f07139d4e7f84326b744bcbdf5ee7b7d13d809c7d4a34a2d3138afb12d0b3286` (18,548,788 bytes), and
their Debian packages were byte-identical at
`d7ba2b6b4ecfc86df5a1b450094ef18cdb01fdf2d198ca5995ce6b4adc4ea5d0` (18,610,982 bytes). The
checksum-matched archive installer completed schema-15 task
`019f5c2e-5154-77f2-b915-cf3e3198be3f`; a stock Ubuntu 24.04 container installed and removed the
exact `.deb` with both sandbox profiles required and completed task
`019f5c2f-0fe8-7f30-b36f-c74d2b3fb8d6`. Ubuntu Lintian exited zero with every error and warning
tag fatal. A separate disposable Ubuntu 24.04 PID-1 container running systemd 255 used the
package-owned binaries through the generated user unit, then approved and verified session
`019f5c31-7067-7043-b1a7-feca92cb4f72`, task
`019f5c31-7095-73c3-96b7-b5fa7087832b`, and effect
`019f5c31-7148-7402-9d95-8895d611174a`. Cleanup left no linked Mealy unit, failed user unit, or
daemon before the container was removed. These packages necessarily predate this evidence and the
pending long report, so they validate the package path but are not final release assets.

## Current auditable candidate pre-report reproduction

Two clean builds at commit `c483945`, using distinct Cargo homes and target directories,
reproduced the exact release binaries:

- `mealyd`: `649db94894de63fb973c7d2ef7a4749100d5c9b3ca77524a0f8cbfde66c39572`
  with 263 embedded auditable dependencies
- `mealyctl`: `e96d0012fb07b62d033d385257e3cc3a1c75f93d3a256a8804e213405c2dcf90`
  with 255 embedded auditable dependencies

`cargo audit bin` reported no finding for either exact executable. Pinned Syft 1.46.0 produced a
reproducible 448,964-byte, 465-component/285-edge normalized CycloneDX document at SHA-256
`c8407a576bd04ad4bbfad70102ade43f373eaa2268bc25f201019ade154ca7cd`. Independent third-party
notice generation reproduced a 37,533-byte file at SHA-256
`fafe833afdd0c03c2607d010630f5d138c730216722d7b3e4af14f226f8da561`.

Two complete 18,609,777-byte archives were byte-identical at SHA-256
`ccad0fa0698f4c6aa4035a7b90dd7427dba3564225036bf13c4f7904ed3a0ed5`; two complete
18,679,486-byte Debian packages were byte-identical at SHA-256
`f8261f81fff5e66916fdc86a78fe33f8b84a717c4820bec1269198310bee308f`. The checksum-driven archive
installer passed rootlessly on Fedora 44, and the exact `.deb` passed sandbox-required clean
Ubuntu 24.04 and Debian 13 install/replay/drain/removal checks. Debian 13 Lintian 2.122.0 emitted
no error or warning with both tag classes fatal.

Commit `c797e8e` changes only the systemd verification harness to tolerate the bounded pre-exec
`MainPID` transition observed on systemd 257. A clean auditable rebuild at that commit reproduced
the exact two executable hashes above. Its protected workflow
[run 29374834884](https://github.com/Amekn/project_mealy/actions/runs/29374834884) passed the strict
workspace, Linux sandbox, rendered-browser, Ubuntu x86_64/ARM64, and macOS ARM/Intel contexts.

The current long run explicitly executes the exact `mealyd` hash above. This section is still
pre-report evidence: the report and resulting documentation bytes must be included in two fresh
byte-identical packages before tag publication.

## Reproduction

```sh
cargo_deny=$(scripts/fetch-cargo-deny.sh target/cargo-deny-policy)
"$cargo_deny" check
scripts/generate-third-party-licenses.sh \
  target/cargo-about-0.9.1/bin/cargo-about target/third-party-licenses.html
scripts/build-release-binaries.sh --auditable
cargo audit bin target/release/mealyd
cargo audit bin target/release/mealyctl
scripts/systemd-service-smoke.sh target/release/mealyd target/release/mealyctl
target/actionlint-v1.7.12/actionlint -color
zizmor=$(scripts/fetch-zizmor.sh target/zizmor-1.27.0)
"$zizmor" --offline --persona auditor \
  --min-severity low --color never .github/workflows
```
