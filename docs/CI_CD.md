# Development and production delivery

This runbook defines Mealy's source-to-production promotion path. A build is production evidence
only when the exact commit moves through every gate below; a successful local build, pull-request
artifact, soak report, or live-provider run is not independently a release.

## Promotion model

```text
developer branch
  -> protected pull request CI
  -> protected main
  -> reviewed live-provider acceptance for that exact commit
  -> immutable semantic-version tag on that commit
  -> native build, test, package, SBOM, and provenance jobs
  -> one published GitHub release
  -> public clean-host acceptance on every published platform
```

There is no mutable staging deployment or alternate production build. The reviewed
`live-provider-smoke` GitHub environment is the external staging gate, and the tag workflow builds
production assets from the same Git commit. The checked release-soak report binds the long-running
runtime candidate to an identical release daemon. The release workflow refuses a tag that is not
on `main`, lacks exact-commit live acceptance, has stale/invalid soak evidence, or disagrees with
the workspace version.

## Developer setup and fast feedback

Install the host prerequisites in [QUICKSTART.md](QUICKSTART.md), use the repository-pinned Rust
toolchain, and keep `Cargo.lock` authoritative:

```sh
rustup show
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo test --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

Before opening a pull request, run the checks affected by the change. For a release-bound or
cross-cutting change, reproduce the strict documentation and packaging gates too:

```sh
cargo test --locked --workspace --doc --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --all-features --no-deps
scripts/validate-documentation.py --cli target/debug/mealyctl
bash -n packaging/*.sh scripts/*.sh
shellcheck packaging/*.sh scripts/*.sh
scripts/test-public-license-validator.sh
scripts/test-release-soak-validator.sh
scripts/test-release-notes.sh
packaging/test-packaging.sh
packaging/test-deb-packaging.sh
packaging/test-rpm-packaging.sh
packaging/test-arch-packaging.sh
packaging/test-signed-linux-repositories.sh
```

Linux sandbox, systemd, and rendered-browser tests need the operating-system prerequisites and
explicitly isolated test setup documented in [TESTING.md](TESTING.md). Do not weaken or skip those
boundaries to make a workstation pass.

## Code and API documentation contract

All workspace crates enable the `missing_docs` lint. Protected CI builds workspace rustdoc with
warnings denied, and tests documentation examples. It also runs the real `mealyctl --help` surface
through `scripts/validate-documentation.py`, compares every registered Axum method/path pair with
`API.md`, and resolves every tracked repository-local Markdown target and fragment. Missing or
stale API routes, undocumented public top-level commands, broken local links, empty required
documents, symlink substitutions, and repository escapes fail the same protected gate. Every
public item must explain its invariant, units, authority, error behavior, and safety boundary where
relevant. Do not use comments to promise behavior that is not enforced by an implementation or
test.

The validator's bounded `--mode package` does not require Git metadata. Release jobs run it against
each extracted Linux archive with the archive's own `mealyctl`, both immediately after the native
build and again after downloading the immutable public asset. The source-mode router
comparison remains authoritative for completeness; package mode independently proves the shipped
core/API/usage documents, local links, endpoint inventory, and CLI command table are usable from
the distribution itself.

A public transport change must update all of the following in one pull request:

1. framework-neutral DTO rustdoc in `mealy-protocol`;
2. adapter/backend contract rustdoc in `mealy-api`;
3. [API.md](API.md), including endpoint, version, retry, or cursor behavior;
4. public-API and compatibility tests;
5. usage/operations documentation when an operator-visible command or lifecycle changes.

Architecture or invariant changes additionally require the relevant ADR, `ARCHITECTURE.md`, threat
model, and requirements-coverage update. New files below `docs/` must be deliberately added to the
fail-closed release-document inventories in `packaging/build-release.sh`,
`packaging/build-deb.sh`, and `packaging/install.sh`.

## Pull request and protected-main gate

Use a short-lived branch, keep unrelated changes separate, and open a pull request against `main`.
The repository must enforce strict up-to-date status checks, linear history, resolved review
conversations, admin enforcement, and disabled force-push/deletion. These six contexts are the
required Linux production set:

- `Strict workspace gate`;
- `Linux sandbox conformance`;
- `Linux rendered-browser conformance`;
- `Control plane (ubuntu-24.04)`;
- `Control plane (ubuntu-24.04-arm)`;
- `Linux distribution compatibility`.

`.github/workflows/ci.yml` is the executable definition. The strict lane checks formatting,
workflow policy, dependency policy, dashboard JavaScript, clippy, all targets/features, doc tests,
rustdoc, checked Markdown/API/CLI documentation consistency, RustSec, generated third-party
notices, shell entry points, release evidence, and all package formats. Dedicated lanes exercise
Linux Bubblewrap/systemd and the content-pinned browser; native jobs compile Linux x86-64/ARM64,
and the distribution aggregate covers clean Ubuntu, Debian, Fedora, and Arch package builds plus
a disposable-key signed APT/DNF/Pacman repository, clean installs through every manager, and
tamper rejection.

GitHub vulnerability alerts and Dependabot security updates must remain enabled. The checked
`.github/dependabot.yml` opens bounded weekly Cargo and GitHub Actions update pull requests; those
changes receive the same protected checks and are never auto-merged around release policy.

Never merge around a red or missing context. Diagnose the first failing command from the job log,
add a regression when behavior was wrong, rerun the same command locally when practical, and let
the protected pull request rerun all contexts. A green PR is merged linearly; direct pushes to
`main` are not a release procedure.

## Main and release-candidate evidence

After merge, record the exact protected commit and require its push CI to remain green:

```sh
git fetch origin main --tags
candidate=$(git rev-parse origin/main)
git status --short
printf '%s\n' "$candidate"
gh run list --workflow ci.yml --branch main --commit "$candidate"
```

The release report at `docs/benchmarks/release-soak.json` must pass
`scripts/validate-release-soak.sh`. For release one it must represent a clean, retained-disk,
external-release-binary run of at least 86,400 seconds with complete accounting, successful
recovery/replay, SQLite integrity `ok`, clean drain, and zero residual work. If code changes alter
the release binaries or runtime/storage semantics after the soak, treat the report as stale and
repeat the required candidate validation rather than editing its measurements. The validator
enforces this boundary: Cargo manifests, the lockfile/toolchain configuration, compiled application
and library sources/assets/migrations, schemas, and the release-binary build entry point must be
unchanged between the observed revision (or its identical-tree lineage commit) and the proposed
release commit. Evidence, packaging, workflow, and documentation follow-ups remain eligible but
still receive protected CI.

For an external soak, the exact x86-64 `mealyd` subject must also be available through the checked
`docs/benchmarks/release-soak-subject.json` promotion manifest. The source is a private draft
release bound by numeric release ID under a dedicated `soak-subject-<revision>` tag, not an
unpinned URL or a pull-request artifact. Before tagging, run
`scripts/test-release-soak-subject-fetch.sh`; the real tag workflow's isolated promotion job is
the only build-side job granted an ephemeral `contents: write` token, because private drafts
require push-level visibility. It selects exactly one owner-uploaded asset, checks GitHub's
asset digest and byte count against the manifest, checks the manifest against the full soak report,
downloads it, recomputes the SHA-256, verifies `mealyd --version`, and transfers it through a
one-day artifact scoped to the same workflow run. The read-only x86 package job rechecks byte
count and SHA-256 before installation. It subsequently audits, service-tests, packages, SBOMs,
attests, publishes, and clean-host tests that exact daemon. A
hosted-runner rebuild is still required as a source/audit check, but it cannot replace the observed
binary because native link environments are not assumed byte-reproducible across distributions.

### Stage the exact soak subject

After the terminal report passes locally, stage the observed daemon as a private draft transport
asset before opening the evidence PR. This is not the public production release. Run from the
canonical repository on the Linux soak host, with an authenticated `gh` session that can create a
draft release:

```sh
repository=Amekn/mealy
report=/absolute/path/to/release-soak.json
mealyd=/absolute/path/to/the/exact/soaked/mealyd
observed=$(jq -er '.revision | select(test("^[0-9a-f]{40}$"))' "$report")
staging_tag="soak-subject-$observed"
asset_name="mealy-soak-${observed}-linux-x86_64-gnu-mealyd"
test "$(git rev-parse --verify "${observed}^{commit}")" = "$observed"
scripts/validate-release-soak.sh "$report" "$mealyd" "$(git rev-parse origin/main)"

git tag -a "$staging_tag" "$observed" -m "Mealy release soak subject $observed"
git push origin "refs/tags/$staging_tag"
staging=$(mktemp -d)
install -m 0755 "$mealyd" "$staging/$asset_name"
gh release create "$staging_tag" "$staging/$asset_name" --draft --verify-tag \
  --title "Mealy release soak subject $observed" \
  --notes "Private exact-binary transport for the validated release soak."
rm -rf -- "$staging"
```

Derive the checked manifest from GitHub's current authenticated release-list and asset metadata;
never type its ID, size, or digest from memory. Drafts do not have a stable public tag URL, so
select exactly one matching draft from the owner-visible list rather than using the public
release-by-tag endpoint:

```sh
releases=$(gh api --method GET "repos/$repository/releases" -F per_page=100)
release=$(jq -cer --arg tag "$staging_tag" '
  [.[] | select(.tag_name == $tag)]
  | if length == 1 then .[0] else error("release identity") end
  ' <<<"$releases")
release_id=$(jq -er '.id' <<<"$release")
asset=$(jq -er --arg name "$asset_name" \
  '[.assets[] | select(.name == $name)] | if length == 1 then .[0] else error("asset identity") end' \
  <<<"$release")
asset_bytes=$(jq -er '.size' <<<"$asset")
asset_digest=$(jq -er '.digest | select(test("^sha256:[0-9a-f]{64}$"))' <<<"$asset")
asset_sha256=${asset_digest#sha256:}
jq -n --arg repository "$repository" --argjson release_id "$release_id" \
  --arg release_tag "$staging_tag" --arg asset_name "$asset_name" \
  --arg asset_sha256 "$asset_sha256" --argjson asset_bytes "$asset_bytes" \
  --arg revision "$observed" '
  {
    schemaVersion: "mealy.soak-subject.v1",
    repository: $repository,
    releaseId: $release_id,
    releaseTag: $release_tag,
    assetName: $asset_name,
    assetSha256: $asset_sha256,
    assetBytes: $asset_bytes,
    revision: $revision,
    target: {os: "linux", architecture: "x86_64"}
  }
  ' >docs/benchmarks/release-soak-subject.json
```

Copy the terminal report without editing its measurements, then run
`scripts/fetch-release-soak-subject.sh` and `scripts/validate-release-soak.sh` against a fresh
download before committing either JSON file. Keep prior draft subjects for audit; their unique tags,
release IDs, and asset names prevent them from qualifying a newer manifest.

## Reviewed live-provider acceptance

The exact final commit needs a successful protected `main` push run of `.github/workflows/ci.yml`
and one successful manual run of `.github/workflows/live-smoke.yml` in the
protected `live-provider-smoke` environment. For the public release gate, use `openrouter-free`
without forcing a model:

```sh
gh workflow run live-smoke.yml --ref main \
  -f provider=openrouter-free \
  -f run_brave_search=false
```

The environment must require an owner review, admit protected branches only, and expose
`OPENROUTER_API_KEY` only as an environment secret. The workflow discovers the account-visible
catalog, selects an exact `:free` tool-capable model, requires complete zero input/output pricing
and usable token limits, and then proves setup, credential containment, a real governed read,
durable usage settlement, recorded-only replay, and clean drain. Activation keeps its no-tools
connectivity probe bounded to 256 output tokens, while live agent turns receive a 1,024-token
runtime allowance so a tool call and its post-tool final response can both become terminal. The
catalog-selected model must advertise at least that runtime output capacity. The workflow never
sends the key to a pull-request job or stores it in Mealy configuration.

After approval and completion, verify that the successful run's `headSha` is exactly the candidate
commit. The workflow-controlled run name binds the selected provider and SHA. Both the x86 package
gate and final publication gate use the checked selector to require that exact name, canonical
workflow path, successful `workflow_dispatch` result, repository run URL, and
`openrouter-free` provider. A success on an earlier commit does not qualify a later tag, and a
successful private/direct-provider run cannot substitute for the free-model gate.
`LOCAL_API_KEY`, direct paid API keys, and owner-local ChatGPT/Claude subscription bridges remain
useful additional acceptance, but should not be used for frequent CI traffic.

## Tag and publish

The workspace version and proposed tag must match. Confirm protected CI and live acceptance first,
then create one annotated stable `vMAJOR.MINOR.PATCH` tag on the exact candidate and push only that
tag. The production workflow rejects prerelease/build metadata, leading-zero components, and any
workspace-version mismatch rather than publishing them as a normal stable GitHub release:

```sh
test "$(git rev-parse origin/main)" = "$candidate"
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
tag="v$version"
git tag -a "$tag" "$candidate" -m "Mealy $tag"
git push origin "refs/tags/$tag"
```

Do not move or reuse a published version tag. A correction uses a new semantic version.

`.github/workflows/release.yml` then performs these production gates:

- revalidates license, tag ancestry/identity, soak evidence, exact protected-main CI, and
  exact-commit free-model live acceptance;
- isolates private-draft access in one ephemeral promotion job and rehashes its current-run handoff;
- repeats strict tests, sandbox/browser/service proofs, RustSec, and auditable binary inspection;
- builds native Linux x86-64 and ARM64 archives, Debian packages, and RPMs plus an x86-64 Arch
  package;
- generates per-platform CycloneDX SBOMs and third-party license notices;
- verifies reproducibility, checksums, installed archive/package behavior, upgrade/rollback, and
  state preservation;
- creates GitHub artifact attestations plus retained offline Sigstore bundles;
- creates package-manager-native signed APT, DNF, and Pacman repositories with an owner-reviewed
  signing key, attests their complete manifest, and stages the exact Pages artifact;
- assembles one exact release inventory and publishes deterministic evidence-bound notes;
- deploys the signed repositories only after the immutable GitHub release exists;
- downloads the public release on native Linux runners, verifies release/asset integrity and
  provenance, repeats clean-host installed acceptance on Ubuntu, Debian, Fedora, and Arch, and
  installs the tagged version through each public HTTPS repository before the workflow can pass.

The one-time Pages, signing Environment, offline-key, and rotation controls are in
[LINUX_REPOSITORIES.md](LINUX_REPOSITORIES.md#maintainer-activation). A missing Pages site,
unapproved signing Environment, empty key secret, base-URL mismatch, wrong fingerprint, unusable
signing subkey, invalid package identity, or failed public package-manager install blocks the tag;
there is no unsigned publication fallback.

Linux x86-64 and ARM64 are the production worker targets. Arch Linux is x86-64-only upstream;
Arch Linux ARM remains a derivative rather than an official target. macOS and Windows are outside
the active production, packaging, and CI contract.

## Verification and promotion decision

Monitor every tag job and do not announce production readiness until the workflow is fully green:

```sh
gh run list --workflow release.yml --commit "$candidate"
gh release verify "$tag" --format json
gh release view "$tag" --json tagName,targetCommitish,url,assets
```

For each downloaded asset, run `gh release verify-asset`. For archives, packages, installers, and
SBOMs, also verify the matching checksum manifest and provenance with `gh attestation verify`, the
repository, the release workflow identity, the exact tag source ref, and the retained offline
bundle. [RELEASE.md](RELEASE.md) contains the complete end-user commands.

The production decision is fail closed:

- PR or protected-main failure: fix in a new commit and repeat protected CI;
- soak invalidation: build the exact new candidate and repeat the formal soak;
- live-provider failure or SHA mismatch: do not tag; fix and rerun the reviewed gate;
- tag workflow failure before publication: do not create assets manually; fix and publish a new
  version if the tag cannot be safely removed before any release exists;
- public acceptance failure after publication: do not call that version production-ready; retain
  evidence, open a corrective change, and publish a new version rather than replacing assets.

## Roll forward, rollback, and incident evidence

Normal production change is roll-forward through the same pipeline with a new version. The managed
Linux installer retains the prior release metadata and supports `install-mealy.sh rollback`.
Schema-changing rollback requires the separately approved migration-backup activation documented
in [RELEASE.md](RELEASE.md). Uninstall preserves the owner database. Back up and verify durable
state before upgrading, and use [OPERATIONS.md](OPERATIONS.md) for drain, safe mode, diagnosis,
backup/restore, retention, and incident recovery.

Retain the pull request, protected-main run, reviewed live-provider run, release run, generated
release notes, checksums, SBOMs, attestations, and clean-host job URLs as the audit chain for each
version. Never use a local dirty build or unreviewed provider probe as a substitute.
