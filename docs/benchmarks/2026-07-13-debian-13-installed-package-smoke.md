# Debian 13 installed-package observation (development artifact)

Date: 2026-07-13 (Pacific/Auckland)

This local observation installed the hardened non-final
`mealy_0.1.0_amd64.deb` from the current dirty development worktree inside a newly pulled stock
Debian 13 (Trixie) slim container. The image was
`debian@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2`.
It contained no Rust toolchain or repository source. Only the candidate package and
`scripts/installed-deb-smoke.sh` were mounted read-only; Bubblewrap, CA certificates, and `jq`
were installed from the distribution repositories. The resulting runtime used glibc 2.41 and
Bubblewrap 0.11.0.

The first direct-daemon candidate package had SHA-256
`57677fc96ee2ee7301e1f7d5f694fad556f6175e2ec0cb15c9b7ddfd09a84122`. With
`MEALY_INSTALLED_SMOKE_REQUIRE_SANDBOX=true`, the smoke verified the archive identity and complete
inner checksums, rejected unexpected maintainer files, installed the root-owned relative command
links and payload, checked binary/version/schema identity, and generated the hardened owner
service definition. The installed daemon reported its observe and workspace-write sandbox
profiles enforceable, completed durable task `019f5ae6-a04b-7131-a7b8-b1f939cc7641`, replayed it
with zero live provider or tool calls, drained cleanly, removed every package-owned path, and
retained the temporary user's `mealy.sqlite3`.
Debian 13's Lintian 2.122.0 independently inspected the same package with error and warning tags
configured as fatal and emitted neither.

## Actual generated-user-service mutation

After the Ubuntu PID-1 integration exposed and closed the outer-unit mutation restrictions, a
second clean Debian 13.5 environment exercised the corrected generated unit rather than only
inspecting it. The root filesystem was the same stock local Debian image content
`sha256:84645f91e8d166d709fcef984301b2576198bf880c15eb3ce9f4c8fad305c4ea`; the derived test image
added only distribution `systemd`/D-Bus user-session support and the declared runtime/test
dependencies. It ran systemd 257.13, glibc 2.41, and Bubblewrap 0.11.0 with a real lingering user
manager.

The pre-evidence package used for the repeated pass was 18,676,086 bytes with SHA-256
`fca968c56b57b25a9f4328af36345fd341923c26d1800af66cfabb43e73c9b3f`. Its package-owned executables
were the reproducible audited candidates:

- `mealyd`: `d3d93166fd832b9515cc2ea29aebb9382b21e2bca4b8a8e391b0739979b10ff1`
- `mealyctl`: `5a8ab5f6b8c5108193921702bf5a2b879ab6f87d850664cd65606b1149509cdb`

Debian 13 Lintian again emitted no error or warning tag for this package, including its explicit
core dependency closure and optional browser/helper `Suggests` metadata.
The packaged `/usr/lib/mealy/release/fetch-browser-runtime.sh` was root-owned mode `0755` and
checksum-identical to the bounded repository helper at SHA-256
`edd42fc0165af7dbb8d7aabce0a37d1e6255226a48a4fbfd616b857ae247abcf`.

`scripts/systemd-service-smoke.sh` generated and linked the real user unit from package-owned
paths while deliberately using home and unit directories containing spaces. The running service
reported both observe and workspace-write profiles enforceable, admitted an exact approved write,
and asserted both effect success and the resulting file bytes. It completed session
`019f5b62-688b-7a80-b6ce-ffdd652e39e0`, task
`019f5b62-68c8-7822-84f8-95fa527989ca`, and effect
`019f5b62-697a-7610-95dd-203d374986f3`, then drained and removed its unit/home without leaving a
failed user service. This closes the Debian userspace/systemd-unit integration gap for the exact
runtime bytes. Recording this observation necessarily changes an embedded documentation file, so
the final post-soak package still requires its planned reproduction and smoke pass rather than
reusing this package hash.

An initial harness invocation deliberately placed the home beneath `/tmp`; service generation
rejected that volatile location before daemon start. Repeating the unchanged package with its home
under the container's persistent `/root` filesystem produced the passing result above. This also
exercised the documented fail-closed state-location boundary.

The rootless container was granted the namespace capabilities needed to exercise Bubblewrap, so
this proves the Mealy sandbox profile and Debian userspace path but not a Debian host LSM policy.
It is useful clean-runtime-host evidence only: the package came from an uncommitted dirty tree, was
not GitHub-attested or published, covered x86_64 only, and intentionally predates the completed
24-hour report. Native ARM64 and published-tag clean-host evidence remain release gates.

## 2026-07-14 corrected web-policy candidate repeat

The exact candidate was rebuilt after the bounded web adapter closed prefix-confusable HTML-tag,
quoted-delimiter, comment, cascading-entity, and current IANA non-global/reserved-address gaps.
Two auditable builds from separate Cargo homes and target trees were byte-identical:

- `mealyd`: `408d5a45657b34e047122521e1d108fcc7e76ca51b237f96579d02c2869aa043`
- `mealyctl`: `abdb04bb70bd7cfe04b86d6c921371f0418ea6c95b5a15ece150d547a54f7fa8`

The binaries contained 263 and 255 embedded `cargo auditable` dependencies respectively, had no
RustSec finding, retained no build-home path, and required only the expected loader, `libc`,
`libgcc_s`, and `libm`. Two isolated pinned-Syft runs produced the same 465-component/285-edge SBOM
at SHA-256 `384785073069d0fd600a78f7c6cb9884ae9ff026fa8cb639d0d82f3419b4053c`.
Two license-notice runs produced the same 37,533-byte file at SHA-256
`fafe833afdd0c03c2607d010630f5d138c730216722d7b3e4af14f226f8da561`.
The independently repeated archive was SHA-256
`aeca21ea4cc409e5d3d1a4adc58da1989f6a3e42e4c4ccc01f332a670228f5f8`; the repeated 18,674,806-byte
Debian package was SHA-256
`433ba9e6cfe94e88e021bfd7c2d7f128c14cc7d6f04b06d817a48ed8eec18291`.

The checksum-verified archive install smoke completed schema-15 task
`019f5b92-d1d1-7970-8e3c-ce1d4883373f`. A fresh Debian 13 PID-1 container then installed and
removed the exact `.deb` with the sandbox required, completing task
`019f5b96-00c4-7313-a769-981a95fa3470` while preserving its database. The real lingering systemd
257 user manager separately approved and verified package-owned write task
`019f5b95-4e8c-7d22-8240-a44491125af5` and effect
`019f5b95-4f46-7b42-bafb-a83819fdb0ad`, drained, and left no failed user unit. `dpkg -V` was clean
after disabling the stock slim-image rule that intentionally discards `/usr/share/doc` and
`/usr/share/man`; the package archive itself contained those paths before that image-only change.
Lintian 2.122.0 emitted informational tags only and exited successfully with error and warning tags
fatal.

This package necessarily predates this paragraph and the pending 24-hour report. Its exact daemon
bytes are the ones under soak; the final archive/`.deb` must be reproduced after the report and
documentation enter the checksummed payload. The dirty-tree, unattested, x86_64 limitations remain.
