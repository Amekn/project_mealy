# Release, install, rollback, and uninstall

Mealy's supported native worker targets are `linux-x86_64-gnu` and `linux-aarch64-gnu`. The tested
distribution contract is Ubuntu 24.04/26.04 LTS, Debian 13, and Fedora 44 on both architectures,
plus Arch Linux on x86-64. See [LINUX_SUPPORT.md](LINUX_SUPPORT.md) for the derivative boundary.
A version tag matching the Cargo workspace version runs the same strict lint/test/sandbox gates as
CI on GitHub's explicit native Ubuntu 24.04 x86-64 and ARM64 runners, including Bash/ShellCheck
validation of every packaging and operational entry point. Each runner builds locked release
binaries with their exact Rust dependency graphs embedded through
`scripts/build-release-binaries.sh`. That boundary remaps repository, Cargo-cache, and account-home
source paths to stable virtual identities; the packager independently rejects common user-home
paths. Each runner scans both `Cargo.lock` and the resulting binaries against RustSec and generates
a bounded CycloneDX SBOM with pinned Syft. Each architecture creates and attests a reproducible
archive, root-owned Debian package, RPM, target checksum manifest, and SBOM; x86-64 also creates
the official Arch package.
A tag's native x86-64 job also rejects publication unless the checked
`docs/benchmarks/release-soak.json` is a clean, retained-disk, external-release-binary report for
at least 86,400 seconds, has the exact SHA-256/version of the newly built auditable daemon, and
either names an ancestor of the tagged commit or carries the checked identical-tree rebase proof
in `docs/benchmarks/release-soak-lineage.json`. That proof preserves and rehashes the exact
report-named commit payload, requires its Git tree to equal a mapped commit tree in the release
history, and binds the unedited report SHA-256. The validator independently requires complete turn/recovery
accounting, SQLite integrity, ordered latency measurements, and zero residual work; protected CI
exercises its positive fixture and short/dirty/wrong-binary/volatile-home/residue/recovery/integrity
rejections.
A frozen, pinned `cargo-about` pass also generates the exact dependency license notice twice and
requires byte-identical output before the notice enters the checksummed package payload.
The native packages are constructed from the same verified release payload without maintainer
scripts, service activation, install hooks, or home mutation. Debian packages are additionally
rejected for any Lintian error or warning tag. Before retention, each native runner installs the
archive and its native system packages and proves binary/schema identity, hardened owner-service
generation, doctor/readiness, one durable task, recorded-only replay, usage, online backup plus
isolated restore verification, clean drain, and state-preserving removal. Clean pinned containers
then reproduce package construction on every supported distribution/architecture pair. Only after
both architecture jobs pass and the separate x86-64 pinned real-browser
process/CLI/model/replay job passes does one dependent job validate the complete merged inventory,
add and attest the common installer, retain all assets, and create the GitHub release. Public
acceptance downloads those immutable packages and repeats lifecycle smokes on clean Ubuntu,
Debian, Fedora, and Arch environments. Third-party actions are pinned by commit and supply-chain
tools by version. macOS and Windows are outside the active production and release contract.

## Repository release controls

Before creating a production tag, protect `main` and require the complete `mealy-ci` check set for
changes entering it. Configure the `live-provider-smoke` GitHub Environment with required
reviewers, then add only the provider secret needed for the reviewed manual probe (and the Brave
secret only when that independent option will run). Never place those credentials in repository,
workflow, or command-line configuration.

The copyright holder selected Apache-2.0 on 2026-07-15. The repository now carries the canonical
Apache License 2.0 text through the existing exact `license-file = "LICENSE"` inheritance, so the
choice does not introduce an unrelated package-metadata change.
A clean auditable fingerprint probe at commit `0be7f63` changed only the referenced license-file
content and reproduced the then-active soak subject exactly: `mealyd` SHA-256
`649db94894de63fb973c7d2ef7a4749100d5c9b3ca77524a0f8cbfde66c39572` and `mealyctl` SHA-256
`e96d0012fb07b62d033d385257e3cc3a1c75f93d3a256a8804e213405c2dcf90`. That soak later failed and
is superseded by the corrected candidate described in the
[negative contention observation](benchmarks/2026-07-16-schema15-long-soak-contention-failure.md).
Two clean builds then reproduced the corrected `mealyd` SHA-256
`4db797fd085ab845b7b30752a822168c670e6420df1edb22726c3e18eba64c97` and `mealyctl` SHA-256
`9f7f53894352536040594777289d86842ab25723f121332ab94e2617879b9c63`. The exact daemon completed
the historical schema-15
[release soak](benchmarks/2026-07-16-schema15-release-soak.json). Its checked
[lineage proof](benchmarks/2026-07-16-schema15-release-soak-lineage.json) preserves the unedited
report across the required linear-history rebase without relabeling its observed revision.

That historical soak qualifies only its exact schema-15 daemon. Schema 16 follows a later stopped
soak and the accepted SQLite runtime/storage redesign documented in the
[interrupted-soak remediation record](benchmarks/2026-07-20-interrupted-soak-and-storage-architecture.md).
The retained clean auditable binaries from protected schema-16 revision `9b3653f` are `mealyd`
SHA-256 `7b5d39502e96bbb03c4c33280c6355a91682234d14a5284ded83c143807a55bc` and `mealyctl`
SHA-256 `7e750893756e87d20a6092cbb55092341be41e7046e890b47fe9502ce0c1580d`.
That exact daemon completed the clean schema-16
[release soak](benchmarks/release-soak.json) for 86,409.247 seconds, 19,248 turns, and 48 hard
restarts. It recovered 51 interrupted-provider turns, resumed two undispatched model turns and two
undispatched read-tool turns, retained complete recorded-only replay and SQLite integrity `ok`,
drained cleanly, and left zero residue. The report names an ancestor of this report-bearing tree
directly, so no current lineage proof is required.
The remaining release gates are protected report CI, reviewed free-model OpenRouter acceptance,
native package/public-download verification, and attested publication.

The soak host and GitHub's Linux runner are different native link environments. A hosted-runner
rebuild is therefore audited as a source build but is not mislabeled as the byte-identical soak
subject. The x86-64 release job replaces only `target/release/mealyd` with the exact retained daemon
described by [the promotion manifest](benchmarks/release-soak-subject.json). That subject is staged
as one authenticated asset on the private draft release whose `soak-subject-<revision>` tag names
the observed revision. `scripts/fetch-release-soak-subject.sh` requires the checked repository,
numeric draft-release ID, tag, unique asset name, owner uploader, GitHub-reported SHA-256, exact size, report revision/digest,
Linux x86-64 target, and canonical daemon version before installing it. The normal binary audit,
24-hour validator, systemd service proof, SBOM, package lifecycle, checksums, provenance
attestation, immutable publication, and public clean-host acceptance then operate on that promoted
daemon. GitHub restricts a private draft to push-level access, so one short promotion job alone has
an ephemeral `contents: write` token. It validates the draft asset and publishes it only as a
one-day artifact scoped to that workflow run. The x86 package job retains `contents: read`,
downloads that exact artifact, and rechecks its type, byte count, and SHA-256 before atomic
installation and full report validation. The staging asset and workflow artifact are transport,
not weaker authority: any byte change fails before packaging.

The 2026-07-21 schema-16 freeze review advanced the exact Chrome for Testing Headless Shell pin to
stable `151.0.7922.34` (120,231,126 bytes, SHA-256
`3cfc2bd00d1bafcf8a68dc74c9c92bb7150ddc8d26ade948a776316e1cec4f14`), `actions/attest` to
commit `f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6` (`v4.2.0`), and Syft to `v1.48.0` before the
formal soak subject was built. Checkout, artifact upload/download, Cargo audit/about/auditable,
and the remaining reviewed pins were already current at that boundary.

The 2026-07-22 pre-publication refresh retained that exact browser and advanced Checkout to
commit `3d3c42e5aac5ba805825da76410c181273ba90b1` (`v7.0.1`), Syft to `v1.49.0`, and the
size/SHA-pinned offline zizmor bootstrap to `v1.28.0`. Zizmor `v1.28.0` removes the credential
[debug-logging defect](https://github.com/zizmorcore/zizmor/security/advisories/GHSA-f42p-wjw5-97qh)
in `v1.27.0`; Mealy's affected runs used explicit offline, non-verbose mode, and a token-shape scan
of their strict-job logs found no credential-shaped output.

The native tag jobs run
`scripts/validate-public-license.sh` and refuse publication if restrictive terms,
redirected/mismatched license metadata, an unsupported/mismatched license text, or a workspace
package that does not inherit the reviewed declaration remains. This is a legal-distribution gate,
not a claim that automated text checks replace legal review.

The tag workflow independently fetches `origin/main`, checks ancestry in each native package job
and again immediately before publication, and refuses unless the tagged SHA is an ancestor of that
branch; a tag on an unmerged or subsequently removed commit cannot publish. Its x86-64 job also
queries the exact `live-smoke.yml` workflow and refuses unless an owner-reviewed manual run for the
tagged commit completed successfully; evidence from another commit, workflow, event, or incomplete
run cannot qualify. Immediately before publication, the publish job repeats that exact live-run
query and renders deterministic release notes from the checked soak JSON. The renderer rejects a
mismatched tag, foreign workflow URL, short or dirty soak, incomplete workload, invalid latency
ordering, corrupt SQLite result, or residual work. The notes link the exact release and
live-provider workflow runs, commit, soak subject and daemon digest, and record the measured
duration, workload, recovery, latency, memory, storage, integrity, and residue instead of
substituting generic generated notes. On 2026-07-14, `main`
was protected with administrator enforcement, pull-request-only changes, linear history, resolved
conversations, and force-push/deletion denial. The authoritative Linux-only protection set is
`Strict workspace gate`, `Linux sandbox conformance`, `Linux rendered-browser conformance`,
`Control plane (ubuntu-24.04)`, `Control plane (ubuntu-24.04-arm)`, and
`Linux distribution compatibility`. Repository-level immutable releases and private vulnerability
reporting are enabled.
The `live-provider-smoke` Environment requires an explicit repository-owner review and now contains
owner-supplied `OPENROUTER_API_KEY` and `LOCAL_API_KEY` secrets. The checked workflow consumes only
the selected provider secret. Its default OpenRouter gate dynamically requires an exact
tool-capable `:free` model, complete zero pricing, complete token limits, and no unsupported billing
axes; it cannot silently select a paid model. The bounded activation probe uses at most 256 output
tokens, while the governed runtime proof requires and configures a 1,024-token output allowance so
the tool proposal and post-tool terminal response are both covered. The local credential is
reserved for a separately reachable local endpoint and is not exposed to public or untrusted
runners. Its optional workflow path hardcodes
the reviewed Tailnet HTTPS origin, requires explicit model/context inputs, and fixes both prices to
zero so a dispatch input cannot redirect that credential. Create the tag only after required CI,
the current durability report, and one reviewed real-account smoke are all complete.
The workflow-controlled run name records the selected provider and exact commit. The packaging and
publication jobs call the same checked selector, which rejects private/direct-provider successes,
stale commits, unsuccessful or non-manual runs, foreign workflow paths, and noncanonical run URLs;
only the reviewed `openrouter-free` run qualifies the public release.
Protected CI has a separate workflow-controlled event/SHA identity. Both release stages require a
successful `push` run on `main` from the canonical CI workflow and repository URL, so ancestry or a
green pull-request check alone cannot qualify a tag.

After publication, the same tag workflow downloads the immutable public assets without build-job
state and verifies release integrity, asset integrity, provenance, checksums, and exact inventory
on native Linux x86-64/ARM64 runners. It repeats the tokenless bootstrap plus archive and Debian
lifecycle smokes on Ubuntu 24.04, then repeats each public native package lifecycle on clean pinned
Ubuntu 26.04, Debian 13, Fedora 44, and Arch Linux environments. A release workflow is green only
after every public Linux delivery check passes.

## Verify and install a published release

Install GitHub CLI, Bubblewrap, `jq`, GNU tar/coreutils, `flock` (normally from `util-linux`), glibc
2.39 or newer, and
the normal host prerequisites from the quickstart. The shortest production path is the attested
rootless bootstrap. Download the bootstrap from the latest stable release, verify that the release
workflow signed it on a GitHub-hosted runner, and run it:

```sh
tmp=$(mktemp -d)
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --output "$tmp/install-mealy-release.sh" \
  https://github.com/Amekn/mealy/releases/latest/download/install-mealy-release.sh
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --output "$tmp/ATTESTATION-installers.sigstore.json" \
  https://github.com/Amekn/mealy/releases/latest/download/ATTESTATION-installers.sigstore.json
gh attestation verify "$tmp/install-mealy-release.sh" \
  --repo Amekn/mealy \
  --signer-workflow Amekn/mealy/.github/workflows/release.yml \
  --bundle "$tmp/ATTESTATION-installers.sigstore.json" \
  --deny-self-hosted-runners
chmod 0755 "$tmp/install-mealy-release.sh"
"$tmp/install-mealy-release.sh"
```

The canonical signer identity for new releases is `Amekn/mealy`. Historical v0.1.0 bundles were
issued before the repository rename and continue to verify only against `Amekn/project_mealy`;
do not rewrite that retained evidence or use its legacy identity for a newly published tag.

The bootstrap resolves one exact stable tag from bounded public release metadata, downloads the
matching native archive, checksum manifest, manager, a second copy of itself, and the architecture
plus common-installer Sigstore bundles. It verifies all four executable/checksum inputs offline
against the exact tag ref and release workflow before checking the complete target inventory. No
GitHub login or token is required. It delegates the actual atomic
install to that verified release manager and prints setup/service commands. Pass
`--version vX.Y.Z`, `--prefix DIR`, or `--home DIR` when the defaults are not appropriate.

For manual package selection or independent inspection, download one exact release into a new
empty directory:

```sh
VERSION=vX.Y.Z
REPOSITORY=Amekn/mealy
case "$(uname -m)" in
  x86_64|amd64)
    TARGET=linux-x86_64-gnu
    DEB_ARCH=amd64
    RPM_ARCH=x86_64
    ;;
  aarch64|arm64)
    TARGET=linux-aarch64-gnu
    DEB_ARCH=arm64
    RPM_ARCH=aarch64
    ;;
  *) echo "unsupported Linux architecture: $(uname -m)" >&2; exit 1 ;;
esac
DEB_VERSION=${VERSION#v}
DEB_VERSION=${DEB_VERSION/-/~}
mkdir -p "$HOME/Downloads/mealy-$VERSION"
cd "$HOME/Downloads/mealy-$VERSION"
gh release download "$VERSION" --repo "$REPOSITORY" \
  --pattern "mealy-*-${TARGET}.tar.gz" \
  --pattern "mealy-*-${TARGET}.cdx.json" \
  --pattern "mealy_*_${DEB_ARCH}.deb" \
  --pattern "mealy-*-1.${RPM_ARCH}.rpm" \
  --pattern "SHA256SUMS-${TARGET}" \
  --pattern "ATTESTATION-${TARGET}.sigstore.json" \
  --pattern ATTESTATION-installers.sigstore.json \
  --pattern install-mealy.sh \
  --pattern install-mealy-release.sh
if [ "$TARGET" = linux-x86_64-gnu ]; then
  gh release download "$VERSION" --repo "$REPOSITORY" \
    --pattern 'mealy-*-1-x86_64.pkg.tar.zst'
fi
```

Verify the attested checksum manifest and every asset before executing the installer. The local
checksum pass also proves that the independently downloaded installers, SBOM, and native packages
match the manifest:

```sh
ATTESTATION=(--repo "$REPOSITORY" \
  --signer-workflow "$REPOSITORY/.github/workflows/release.yml" \
  --source-ref "refs/tags/$VERSION" --deny-self-hosted-runners)
gh attestation verify "SHA256SUMS-${TARGET}" "${ATTESTATION[@]}" \
  --bundle "ATTESTATION-${TARGET}.sigstore.json"
gh attestation verify install-mealy.sh "${ATTESTATION[@]}" \
  --bundle ATTESTATION-installers.sigstore.json
gh attestation verify install-mealy-release.sh "${ATTESTATION[@]}" \
  --bundle ATTESTATION-installers.sigstore.json
gh attestation verify "mealy-${VERSION}-${TARGET}.tar.gz" "${ATTESTATION[@]}" \
  --bundle "ATTESTATION-${TARGET}.sigstore.json"
gh attestation verify "mealy-${VERSION}-${TARGET}.cdx.json" "${ATTESTATION[@]}" \
  --bundle "ATTESTATION-${TARGET}.sigstore.json"
gh attestation verify "mealy_${DEB_VERSION}_${DEB_ARCH}.deb" "${ATTESTATION[@]}" \
  --bundle "ATTESTATION-${TARGET}.sigstore.json"
gh attestation verify "mealy-${DEB_VERSION}-1.${RPM_ARCH}.rpm" "${ATTESTATION[@]}" \
  --bundle "ATTESTATION-${TARGET}.sigstore.json"
if [ "$TARGET" = linux-x86_64-gnu ]; then
  gh attestation verify "mealy-${DEB_VERSION}-1-x86_64.pkg.tar.zst" \
    "${ATTESTATION[@]}" --bundle "ATTESTATION-${TARGET}.sigstore.json"
fi
sha256sum --check --strict "SHA256SUMS-${TARGET}"
```

Install the root-owned package for the supported distribution family:

```sh
# Ubuntu 24.04/26.04 or Debian 13
sudo apt install --yes "./mealy_${DEB_VERSION}_${DEB_ARCH}.deb"

# Fedora 44
sudo dnf install --assumeyes "./mealy-${DEB_VERSION}-1.${RPM_ARCH}.rpm"

# Arch Linux x86-64
sudo pacman -U --noconfirm "./mealy-${DEB_VERSION}-1-x86_64.pkg.tar.zst"
```

The packages require glibc 2.39 or newer, Bubblewrap, CA certificates, and the matching GCC runtime
library. The Debian package additionally requires `libc-bin >= 2.39` for the exact root-controlled
`/usr/bin/ldd` runtime inspector. Every format places fixed relative command links at
`/usr/bin/mealyd` and `/usr/bin/mealyctl`, retains the actual executables and exact checksummed
release payload under `/usr/lib/mealy/release`, and exposes usage/security documents under
`/usr/share/doc/mealy`, including `third-party-licenses.html`. Installation does not start a daemon,
write a user service, inspect credentials, or create/migrate `$HOME/.mealy`.
The package builder reads the exact ELF `NEEDED` entries and rejects any new native library until
the fixed Debian dependency contract is reviewed and updated; this prevents an incidental build-
host library from silently becoming an undeclared clean-install prerequisite.
The complete checked release documentation tree is mirrored beneath `/usr/share/doc/mealy/docs` so
links from the packaged README and readiness ledger remain local and valid; stable convenience
links expose the quickstart, operations, release, and threat-model documents one level above.
Optional package metadata suggests `curl`/`unzip` for the checksummed browser fetch helper and the
dynamically linked Headless Shell runtime/font packages, but no package activates a host-wide
policy or installs a browser through a maintainer script or install hook. On Ubuntu 24.04, follow
the reviewed
`bwrap-userns-restrict` activation and probe in [`QUICKSTART.md`](QUICKSTART.md) before enabling
effect, extension, MCP, or browser tools.

Alternatively, use the owner-local archive manager. This form provides verified active/previous
slots and the coordinated cross-schema rollback workflow described below:

```sh
chmod 0755 install-mealy.sh
./install-mealy.sh install \
  --archive "mealy-${VERSION}-${TARGET}.tar.gz" \
  --checksums "SHA256SUMS-${TARGET}" \
  --verify-repository "$REPOSITORY" \
  --attestation-bundle "ATTESTATION-${TARGET}.sigstore.json" \
  --prefix "$HOME/.local" \
  --home "$HOME/.mealy"
```

The installer rejects an unexpected name, unsupported or host-mismatched architecture,
absent/duplicate checksum, digest mismatch, unsafe archive path/type, decompression bound,
untracked file, missing binary/manifest/SBOM/license notice, invalid inner payload digest, mismatched
binary/version/state-schema identity, failed provenance check against the repository's exact
`release.yml` workflow, archive-derived tag ref, and GitHub-hosted runner policy, live daemon home, or concurrent
install lock. It stages both binaries on the destination filesystem, rolls back a failed pair
replacement, and installs the matching release manifest, SBOM, dependency license notice,
checksums, manager, and usage
documents under `$HOME/.local/share/mealy`. The installed requirements, architecture, security policy, threat model, quickstart,
the complete documentation tree, README, project license, and dependency-license bytes are all rechecked before an
upgrade or rollback; packaging tests prove modified security guidance blocks replacement. The metadata includes the checksummed executable
`fetch-browser-runtime.sh`; on Linux x86_64 it retrieves only the release-pinned Chrome Headless
Shell size/SHA identity used by the mandatory browser conformance job, with HTTPS-only bounded
redirect, connection, total-time, and transfer limits. It is optional and never runs during
package installation. An upgrade retains the prior matching binaries and
metadata as `.previous`.

The installer takes the daemon's actual home lock but never starts, stops, migrates, or otherwise
mutates durable state. Pass the real custom `--home` whenever it is not `$HOME/.mealy`.

Maintainers can rerun the exact post-build package proofs before publishing:

```sh
scripts/installed-package-smoke.sh \
  "dist/mealy-v${VERSION#v}-${TARGET}.tar.gz" dist/SHA256SUMS dist/install-mealy.sh
scripts/installed-deb-smoke.sh "dist/mealy_${DEB_VERSION}_${DEB_ARCH}.deb"
scripts/systemd-service-smoke.sh target/release/mealyd target/release/mealyctl
```

Run the systemd proof in a disposable container with its own user manager when possible. Every
direct host run is refused unless the maintainer first reviews the temporary unit lifecycle and
sets `MEALY_SYSTEMD_SMOKE_ALLOW_HOST=true`; the GitHub-hosted workflow sets that same explicit opt-in
on its reviewed steps. It permits temporary unit linking, manager reload, enablement, and removal in
the current user's manager. Even with opt-in, the proof refuses a manager carrying more than 1,024
failed units before requesting reload. It is a test-maintainer command, not an installation step.

The archive script first proves the exact release installer matches its unique checksum entry, then uses
only that installer and the installed package binaries. It verifies the installed CLI generates a
sibling-daemon systemd user unit with the documented process/resource hardening and direct daemon
execution needed to preserve per-tool sandboxing, and removes its temporary prefix/home when
complete. Tag jobs set `MEALY_INSTALLED_SMOKE_REQUIRE_SANDBOX=true`, so the exact
installed daemon must also report its required observe and workspace-write sandbox profiles as
enforceable on both native Linux runners. The script does not substitute for published attestation or a clean supported
host, but prevents a source-tree-only smoke from masking a broken release payload.

The tag job also runs the Debian, RPM, and Arch installed-package smokes on their applicable native
packages. They reject maintainer scripts/install hooks and wrong architecture, re-verify the
embedded payload, install with the native package manager, check root ownership/modes and the
generated owner-service unit, complete and recorded-replay a real daemon task, drain, remove the
package, and prove the temporary user database remains.
Before packaging, each native tag runner launches the exact auditable binaries through their
generated systemd user unit. After constructing the native system packages, clean distribution
containers install each exact package and repeat the same proof from the root-owned package paths
before removing it. Both passes approve one workspace mutation,
require the effect and exact file bytes to succeed, and drain the unit. This catches an outer
service restriction that can pass startup/`doctor` yet block a secure nested worker syscall. The
standalone command requires a reachable systemd user manager, refuses to replace an existing
`mealy.service`, and requires explicit opt-in outside a disposable container.

Run `mealyctl --home "$HOME/.mealy" onboard` and the quickstart's first-chat check after a clean
install. Onboarding reviews and probes one provider before publishing the secret reference, then
installs/starts the Linux owner service and requires bounded health plus `doctor` verification.
The provider-only `setup` and `service install` commands remain available for foreground,
automation, and recovery workflows. A
checksum detects accidental corruption; the GitHub attestation ties the bytes to this repository
and release workflow. Keep the active home on a persistent local filesystem outside `/tmp` and
`/var/tmp`; Linux service installation rejects private-temporary paths and volatile
`tmpfs`/`ramfs` state instead of starting against a hidden or disposable home.

## Upgrade an existing installation

First inspect the installation, pending approvals, and unknown effects, then obtain a no-mutation,
fully attested update plan:

```sh
mealyctl install-status
mealyctl --home "$HOME/.mealy" update
mealyctl --home "$HOME/.mealy" status
```

For an owner-local archive whose plan says `updateAvailable`, `stateSchemaCompatible`, and
`applySupported` are all true, apply the exact pinned target:

```sh
mealyctl --home "$HOME/.mealy" update --approve
```

The client pins `latest` to the exact verified candidate before the second download; the bootstrap
and stable manager independently verify hosted-workflow provenance, the outer inventory, the
archive, and complete active slots. Apply verifies the exact active owner service, records and
prints a durable transaction UUID, then launches an independent restart-on-failure user-service
helper. The helper repeats candidate verification, creates an immutable secret-free backup, drains
to a stopped home, activates the slot, restarts, and requires liveness, readiness, `doctor`, exact
version/commit, and installed integrity. A failed target is stopped and the prior verified
same-schema slot is automatically restored, restarted, and qualified. The helper continues after a
terminal disconnect:

```sh
mealyctl --home "$HOME/.mealy" update-status TRANSACTION_UUID
```

A rolled-back transaction is a failed update even when recovery succeeds. Preserve a
`recovery-failed` transaction, its backup, both release slots, and the named user-service journal
before repair. This convenience update refuses state-schema changes. Use the manual verified
release and migration path below when `stateSchemaCompatible` is false.

For a native system-package installation, take and verify a backup, drain the daemon, then run the
plan's exact `nativeUpdateCommand`. The distribution package manager replaces the root-owned
program files but never restarts the owner service. Reinstall the user service definition so its
reviewed canonical executable path and rollback copy are current, then start and validate:

```sh
mealyctl --home "$HOME/.mealy" service install
systemctl --user daemon-reload
systemctl --user start mealy.service
mealyctl --home "$HOME/.mealy" health
mealyctl --home "$HOME/.mealy" status
mealyctl --home "$HOME/.mealy" doctor
```

Startup validates configuration, records the exact effective digest, creates a pre-migration
snapshot before any schema upgrade, performs migrations transactionally, and publishes readiness
only after recovery.

## Roll back a release

The owner-local archive is the supported rollback form. A native system package can be downgraded
only after draining and only when both versions support the same state schema; verify the older
asset, then use the distribution package manager's explicit downgrade operation. A `.deb`, `.rpm`,
or `.pkg.tar.zst` has no hidden previous slot and cannot coordinate a cross-schema home exchange.
If rollback guarantees are required, install through the archive manager before the upgrade.

For a binary regression where both releases support the same state schema, drain the daemon and
swap the complete active/previous slots through the installed manager:

```sh
mealyctl --home "$HOME/.mealy" rollback
mealyctl --home "$HOME/.mealy" rollback --approve
```

The operation verifies both slots, holds the daemon and installer locks, swaps both binaries and
matching metadata, verifies the result, and retains the replaced release as the next rollback
slot. Packaging acceptance installs two releases, rolls backward and forward, rejects mutation,
rejects a live daemon lock, and verifies state-preserving uninstall.

The ordinary command refuses rollback when the previous binary supports a lower state-schema
version than the active release. After a schema migration, never point that older binary at the
newer active database. Select the exact immutable snapshot created by the upgrade and inspect its
recorded transition and manifest digest:

```sh
SNAPSHOT='v14-to-v15-TIMESTAMP-SEQUENCE'
MANIFEST="$HOME/.mealy/migration-backups/$SNAPSHOT/manifest.json"
jq '{fromSchemaVersion,toSchemaVersion,createdAtMs,files}' "$MANIFEST"
DIGEST=$(sha256sum "$MANIFEST" | awk '{print $1}')
```

Compare `DIGEST` with the `manifest_digest` emitted in the upgrade's
`pre-migration rollback snapshot published` log event. Then, while the service remains stopped,
explicitly authorize the package-managed cross-schema transaction:

```sh
"$HOME/.local/share/mealy-manager.sh" rollback-migration \
  --migration-backup "$SNAPSHOT" \
  --expected-manifest-digest "$DIGEST" \
  --approve --prefix "$HOME/.local" --home "$HOME/.mealy"
```

The manager verifies both release slots and their schema identities, retains a verified copy of
the newer activation client, switches the binary/metadata slots, and passes its already-held daemon
home lock to that client without an unlock race. The client verifies the exact two-file snapshot,
SQLite integrity and foreign keys, transition identity, active owner identity, brokered channel and
provider secrets, and every artifact referenced by the older database. It materializes a complete
private sibling home and uses one same-filesystem atomic directory exchange. The complete migrated
home is retained at the `preservedHome` path in the response; a pre-exchange failure restores the
newer release slots and leaves the home unchanged.

The stable `$HOME/.local/share/mealy-manager.sh` is deliberately outside the swapped release
metadata. Before changing a slot, it durably journals the exact verified original slots and request
under `share/mealy-rollback-transaction`. Installer and home ownership use file-backed `flock`
locks, so a killed process does not leave a stale lock directory. If the manager is interrupted,
leave the service stopped and rerun the same stable command: before accepting any operation it
validates the transaction. Matching activation evidence finalizes an already completed atomic home
exchange; otherwise it restores and verifies the original release slots before retrying. Never
delete or edit the transaction directory by hand.

## Uninstall program files without deleting state

Retain and verify a backup. Inspect the plan, then explicitly apply it:

```sh
mealyctl --home "$HOME/.mealy" uninstall
mealyctl --home "$HOME/.mealy" uninstall --approve
```

Uninstall verifies the managed active and previous slots plus the stable manager. If an exact
generated owner service is loaded or present at the default destination, approved owner-local
uninstall first disables and stops it, proves the home lock is free, re-verifies and removes its
definition, and reloads the user manager. A mismatched unit fails closed. An installed but unlinked
custom destination remains an explicit `service remove --destination ...` step. Uninstall then
removes only the two binaries, rollback copies, stable manager, and package-owned
metadata/documents. It never deletes `$HOME/.mealy`, provider/Telegram/Discord credentials, SQLite,
artifacts, backups, or exports.

For Debian, RPM, and Arch installations, the plan returns the exact native removal command instead
of mutating `/usr`. Each package owns only root program/metadata paths and has no maintainer
scripts, so removal cannot delete `$HOME/.mealy`; the native package smokes prove this. The
user-created systemd unit is not package-owned, so run `mealyctl --home "$HOME/.mealy" service
remove` and repeat it with `--approve` before the printed native package command.

If `install-status` reports that only the owner-local stable manager is missing or modified,
`mealyctl repair` previews the bounded action and `mealyctl repair --approve` reconstructs it from
the complete checksum-verified active metadata copy. Any binary, manifest, bootstrap, SBOM,
license, or documentation mismatch remains a hard failure requiring a verified reinstall.

## Maintainer release checklist

1. Confirm the copyright-holder-selected canonical Apache-2.0 `LICENSE` remains inherited by every
   workspace package and run `scripts/validate-public-license.sh .`. Then make the workspace version
   and intended stable `vMAJOR.MINOR.PATCH` tag identical. The production workflow deliberately
   rejects prerelease/build metadata and leading-zero version components.
2. Compare the pinned Headless Shell version with the official
   [Chrome for Testing stable metadata](https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json).
   If the reviewed stable patch changed, update its exact archive byte count/SHA-256 and product
   identity, then repeat the fresh-process browser, model-visible replay, and lifecycle gates.
   Review the pinned GitHub Actions and SBOM/audit/policy/license build tools against their current
   upstream releases and security notes as well; an immutable pin is reproducible, not automatically
   current.
   Ensure the branch CI and packaging conformance job are green only after that review.
3. Run the paced long soak from `docs/benchmarks/README.md` against a clean revision, retain its
   unedited report as `docs/benchmarks/release-soak.json`, and run
   `scripts/validate-release-soak.sh docs/benchmarks/release-soak.json MEALYD TAG_COMMIT` against
   the exact auditable release daemon, adding
   `docs/benchmarks/release-soak-lineage.json` only when a required rebase changed the observed
   commit ID while retaining its exact Git tree. Investigate any identity, integrity, replay, residue, recovery, or
   identity failure before tagging; the tag workflow repeats this gate and cannot publish without
   it. The validator also rejects a tag when Cargo manifests, the lockfile/toolchain configuration,
   compiled application or library sources/assets/migrations, schemas, or the release-binary build
   entry point changed after the observed revision. Only evidence, packaging, workflow, and
   documentation follow-ups may advance without repeating the soak, and all still require protected
   CI. Follow [Stage the exact soak subject](CI_CD.md#stage-the-exact-soak-subject) to create the
   unique annotated staging tag, private draft release, owner-uploaded asset, and metadata-derived
   promotion manifest; validate a fresh download before opening the evidence PR.
4. Run the manual `mealy-live-provider-smoke` workflow against the exact protected commit, approve
   its `live-provider-smoke` environment deployment, and retain the successful run URL. Then create
   and push the reviewed tag. The release workflow refuses a mismatched version, a tag that does
   not point at the checked-out commit, or missing/stale live-provider workflow evidence.
5. Wait for the native Linux jobs to pass the full all-feature/doc/RustSec suites, real
   daemon/dashboard smoke, auditable locked build, exact-binary audit, SBOM/license validation,
   archive plus Debian/RPM/Arch reproducibility and lifecycle tests, asset
   attestation, remote-tag revalidation, and the single dependent `gh release create --verify-tag`
   step.
6. Wait for the post-publication native jobs to run `gh release verify` and `gh release
   verify-asset`, then repeat tokenless bootstrap, archive lifecycle, and native package acceptance
   on clean Ubuntu, Debian, Fedora, and Arch environments against only the downloaded public assets.
   Independently download and inspect the retained verification evidence before declaring the
   release complete.
7. Record clean-install, upgrade, backup/restore, rollback, uninstall, soak, and optional
   live-provider observations in the release notes. The workflow renders the exact soak metrics and
   live/release run links automatically; review that deterministic body and use the linked final
   workflow result as authority for the post-publication native install observations.

The workflow does not publish from an untagged branch or silently invent a tag. A release is
qualified only when its exact linked live-provider, tag, native-package, publication, and dependent
public clean-host jobs are all green; an untagged checkout or partial workflow run never inherits
that status.
