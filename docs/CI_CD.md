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
bash -n packaging/*.sh scripts/*.sh
shellcheck packaging/*.sh scripts/*.sh
scripts/test-public-license-validator.sh
scripts/test-release-soak-validator.sh
scripts/test-release-notes.sh
packaging/test-macos-packaging.sh
packaging/test-packaging.sh
packaging/test-deb-packaging.sh
```

Linux sandbox, systemd, and rendered-browser tests need the operating-system prerequisites and
explicitly isolated test setup documented in [TESTING.md](TESTING.md). Do not weaken or skip those
boundaries to make a workstation pass.

## Code and API documentation contract

All workspace crates enable the `missing_docs` lint. Protected CI builds workspace rustdoc with
warnings denied, and tests documentation examples. Every public item must explain its invariant,
units, authority, error behavior, and safety boundary where relevant. Do not use comments to
promise behavior that is not enforced by an implementation or test.

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
conversations, admin enforcement, and disabled force-push/deletion. These seven contexts are the
required release-one set:

- `Strict workspace gate`;
- `Linux sandbox conformance`;
- `Linux rendered-browser conformance`;
- `Control plane (ubuntu-latest)`;
- `Control plane (ubuntu-24.04-arm)`;
- `Control plane (macos-15)`;
- `Control plane (macos-15-intel)`.

`.github/workflows/ci.yml` is the executable definition. The strict lane checks formatting,
workflow policy, dependency policy, dashboard JavaScript, clippy, all targets/features, doc tests,
rustdoc, RustSec, generated third-party notices, shell entry points, release evidence, and all
package formats. Dedicated lanes exercise Linux Bubblewrap/systemd and the content-pinned browser;
native jobs compile Linux x86-64/ARM64 and macOS ARM64/Intel control planes.

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
repeat the required candidate validation rather than editing its measurements.

## Reviewed live-provider acceptance

The exact final commit needs one successful manual run of `.github/workflows/live-smoke.yml` in the
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
durable usage settlement, recorded-only replay, and clean drain. It never sends the key to a
pull-request job or stores it in Mealy configuration.

After approval and completion, verify that the successful run's `headSha` is exactly the candidate
commit. A success on an earlier commit does not qualify a later tag. `LOCAL_API_KEY`, direct paid
API keys, and owner-local ChatGPT/Claude subscription bridges are useful additional acceptance,
but they do not replace the required free OpenRouter gate and should not be used for frequent CI
traffic.

## Tag and publish

The workspace version and proposed tag must match. Confirm protected CI and live acceptance first,
then create one annotated tag on the exact candidate and push only that tag:

```sh
test "$(git rev-parse origin/main)" = "$candidate"
git tag -a v0.1.0 "$candidate" -m 'Mealy v0.1.0'
git push origin refs/tags/v0.1.0
```

Do not move or reuse a published version tag. A correction uses a new semantic version.

`.github/workflows/release.yml` then performs these production gates:

- revalidates license, tag ancestry/identity, soak evidence, and exact-commit live acceptance;
- repeats strict tests, sandbox/browser/service proofs, RustSec, and auditable binary inspection;
- builds native Linux x86-64 and ARM64 archives and Debian packages;
- builds conversation-only macOS ARM64 and Intel preview archives;
- generates per-platform CycloneDX SBOMs and third-party license notices;
- verifies reproducibility, checksums, installed archive/package behavior, upgrade/rollback, and
  state preservation;
- creates GitHub artifact attestations plus retained offline Sigstore bundles;
- assembles one exact release inventory and publishes deterministic evidence-bound notes;
- downloads the public release on all four native runners, verifies release/asset integrity and
  provenance, and repeats clean-host installed acceptance.

Linux x86-64 and ARM64 are production worker targets. macOS ARM64 and Intel packages are explicitly
conversation-only control-plane previews: conversation, replay, backup, inspection, and LaunchAgent
drain are supported, while Linux worker/tool sandbox profiles fail closed. Windows is not a
release-one target.

## Verification and promotion decision

Monitor every tag job and do not announce production readiness until the workflow is fully green:

```sh
gh run list --workflow release.yml --commit "$candidate"
gh release verify v0.1.0 --format json
gh release view v0.1.0 --json tagName,targetCommitish,url,assets
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
