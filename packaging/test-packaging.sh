#!/usr/bin/env bash
set -euo pipefail
umask 077

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-packaging-test.XXXXXX")
cleanup() {
  rm -rf "$temporary"
}
trap cleanup EXIT

release_workflow=$repository_root/.github/workflows/release.yml
if grep -Eq \
  'MEALY_INSTALLED_SMOKE_ROOT=(/tmp|/var/tmp)([[:space:]]|$)' \
  "$release_workflow"; then
  echo "release workflow places a persistent service smoke below a private temporary path" >&2
  exit 1
fi
if [[ $(grep -Fc 'install -d -m 0700 /mealy-smoke' "$release_workflow") -ne 5 \
  || $(grep -Fc 'MEALY_INSTALLED_SMOKE_ROOT=/mealy-smoke' "$release_workflow") -ne 5 ]]; then
  echo "release workflow persistent native-package smoke roots are incomplete" >&2
  exit 1
fi

public_bootstrap=$(
  sed -n \
    '/- name: Exercise the public rootless bootstrap through first chat/,/- name: Re-run exact downloaded archive and Debian lifecycle smokes/p' \
    "$release_workflow"
)
if [[ -z $public_bootstrap ]]; then
  echo "release workflow is missing public rootless first-chat acceptance" >&2
  exit 1
fi
expected_public_version="--version \"\$GITHUB_REF_NAME\""
grep -Fq -- "$expected_public_version" <<<"$public_bootstrap"
if grep -Fq -- '--repository' <<<"$public_bootstrap"; then
  echo "public rootless acceptance overrides the installer's canonical repository" >&2
  exit 1
fi
grep -Fq 'scripts/systemd-service-smoke.sh' <<<"$public_bootstrap"
expected_public_binaries="\"\$temporary/prefix/bin/mealyd\" \"\$temporary/prefix/bin/mealyctl\""
grep -Fq "$expected_public_binaries" \
  <<<"$public_bootstrap"

make_binaries() {
  local directory=$1
  local version=$2
  local marker=$3
  local schema=$4
  mkdir -p "$directory"
  for binary in mealyd mealyctl; do
    sed \
      -e "s/@BINARY@/$binary/g" \
      -e "s/@VERSION@/$version/g" \
      -e "s/@MARKER@/$marker/g" \
      -e "s/@SCHEMA@/$schema/g" \
      >"$directory/$binary" <<'SCRIPT'
#!/usr/bin/env bash
if [[ ${1-} == --version ]]; then
  printf '@BINARY@ @VERSION@\n'
elif [[ ${1-} == --print-supported-schema-version && @BINARY@ == mealyd ]]; then
  printf '@SCHEMA@\n'
elif [[ @BINARY@ == mealyctl && ${1-} == --home \
  && ${3-} == migration-home-activate ]]; then
  if [[ -n ${MEALY_TEST_MIGRATION_BLOCK_READY-} ]]; then
    printf '%s\n' "$$" >"$MEALY_TEST_MIGRATION_BLOCK_READY"
    manager_pid=$PPID
    while kill -0 "$manager_pid" 2>/dev/null; do
      sleep 0.01
    done
    exit 99
  fi
  if [[ -n ${MEALY_TEST_MIGRATION_MARKER-} ]]; then
    printf '%s\n' "$*" >"$MEALY_TEST_MIGRATION_MARKER"
  fi
  printf '{"migrationBackupName":"%s","manifestDigest":"%s","fromSchemaVersion":%s,"toSchemaVersion":%s,"preservedHome":"test-preserved-home"}\n' \
    "${4}" "${6}" "${8}" "${10}"
elif [[ @BINARY@ == mealyctl && ${1-} == --home && ${3-} == onboard \
  && -n ${MEALY_TEST_ONBOARD_LOG-} ]]; then
  printf '%s\n' "$*" >"$MEALY_TEST_ONBOARD_LOG"
  printf '{"schemaVersion":"mealy.onboard.v1","configured":true,"serviceHealthy":true}\n'
else
  printf '@BINARY@-@MARKER@\n'
fi
SCRIPT
    chmod 0755 "$directory/$binary"
  done
}

make_sbom() {
  local path=$1
  local version=$2
  local release_target=$3
  local raw="$path.raw"
  printf '%s\n' "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"serialNumber\":\"urn:uuid:00000000-0000-4000-8000-000000000000\",\"version\":1,\"metadata\":{\"timestamp\":\"2099-01-01T00:00:00Z\",\"component\":{\"name\":\"/tmp/non-reproducible\"}},\"components\":[{\"bom-ref\":\"pkg:generic/mealy@$version\",\"type\":\"application\",\"name\":\"mealy\",\"version\":\"$version\"}]}" >"$raw"
  "$repository_root/packaging/normalize-sbom.sh" "$raw" "$path" "$version" \
    "$release_target" "$commit" "$epoch"
}

run_in_pty() {
  python3 - "$@" <<'PYTHON'
import os
import pty
import sys

status = pty.spawn(sys.argv[1:])
raise SystemExit(os.waitstatus_to_exitcode(status))
PYTHON
}

commit=0123456789abcdef0123456789abcdef01234567
epoch=1700000000
case $(uname -m) in
  x86_64|amd64)
    target=linux-x86_64-gnu
    wrong_target=linux-aarch64-gnu
    ;;
  aarch64|arm64)
    target=linux-aarch64-gnu
    wrong_target=linux-x86_64-gnu
    ;;
  *)
    echo "unsupported packaging-test host architecture: $(uname -m)" >&2
    exit 1
    ;;
esac
mkdir -p "$temporary/first" "$temporary/second" "$temporary/upgrade" \
  "$temporary/schema-upgrade" "$temporary/wrong-architecture"
make_binaries "$temporary/bin-v1" 0.1.0 v1 13
make_binaries "$temporary/bin-v2" 0.2.0 v2 13
make_binaries "$temporary/bin-v3" 0.3.0 v3 14
make_sbom "$temporary/sbom-v1.json" 0.1.0 "$target"
make_sbom "$temporary/sbom-v2.json" 0.2.0 "$target"
make_sbom "$temporary/sbom-v3.json" 0.3.0 "$target"
make_sbom "$temporary/sbom-wrong-architecture.json" 0.1.0 "$wrong_target"
{
  printf '<h1>Mealy third-party licenses</h1>\n<pre>\n'
  for _ in {1..64}; do
    printf 'Deterministic third-party license fixture text for packaging tests.\n'
  done
  printf '</pre>\n'
} >"$temporary/third-party-licenses.html"

"$repository_root/packaging/build-release.sh" 0.1.0 "$target" \
  "$temporary/bin-v1" "$temporary/sbom-v1.json" "$temporary/third-party-licenses.html" \
  "$temporary/first" "$commit" "$epoch" 13 \
  >/dev/null
"$repository_root/packaging/build-release.sh" 0.1.0 "$target" \
  "$temporary/bin-v1" "$temporary/sbom-v1.json" "$temporary/third-party-licenses.html" \
  "$temporary/second" "$commit" "$epoch" 13 \
  >/dev/null
"$repository_root/packaging/build-release.sh" 0.2.0 "$target" \
  "$temporary/bin-v2" "$temporary/sbom-v2.json" "$temporary/third-party-licenses.html" \
  "$temporary/upgrade" "$commit" "$epoch" 13 \
  >/dev/null
"$repository_root/packaging/build-release.sh" 0.3.0 "$target" \
  "$temporary/bin-v3" "$temporary/sbom-v3.json" "$temporary/third-party-licenses.html" \
  "$temporary/schema-upgrade" "$commit" "$epoch" 14 \
  >/dev/null
"$repository_root/packaging/build-release.sh" 0.1.0 "$wrong_target" \
  "$temporary/bin-v1" "$temporary/sbom-wrong-architecture.json" \
  "$temporary/third-party-licenses.html" "$temporary/wrong-architecture" \
  "$commit" "$epoch" 13 \
  >/dev/null

cp "$temporary/third-party-licenses.html" "$temporary/active-license-notice.html"
printf '<script>alert(1)</script>\n' >>"$temporary/active-license-notice.html"
if "$repository_root/packaging/build-release.sh" 0.1.0 "$target" \
  "$temporary/bin-v1" "$temporary/sbom-v1.json" \
  "$temporary/active-license-notice.html" "$temporary/active-license-output" \
  "$commit" "$epoch" 13 >/dev/null 2>&1; then
  echo "release builder accepted an active third-party license notice" >&2
  exit 1
fi

cp -a "$temporary/bin-v1" "$temporary/path-leaking-bin"
printf '/home/release-builder/private/source.rs\n' >>"$temporary/path-leaking-bin/mealyd"
if "$repository_root/packaging/build-release.sh" 0.1.0 "$target" \
  "$temporary/path-leaking-bin" "$temporary/sbom-v1.json" \
  "$temporary/third-party-licenses.html" "$temporary/path-leaking-output" \
  "$commit" "$epoch" 13 >/dev/null 2>&1; then
  echo "release builder accepted a binary containing a host-specific home path" >&2
  exit 1
fi

mkdir -p "$temporary/merged-input"
for release_target in linux-x86_64-gnu linux-aarch64-gnu; do
  if [[ $release_target == "$target" ]]; then
    source_dir=$temporary/first
  else
    source_dir=$temporary/wrong-architecture
  fi
  install -m 0644 "$source_dir/mealy-v0.1.0-${release_target}.tar.gz" \
    "$temporary/merged-input/mealy-v0.1.0-${release_target}.tar.gz"
  install -m 0644 "$source_dir/mealy-v0.1.0-${release_target}.cdx.json" \
    "$temporary/merged-input/mealy-v0.1.0-${release_target}.cdx.json"
  install -m 0644 "$source_dir/SHA256SUMS" \
    "$temporary/merged-input/SHA256SUMS-${release_target}"
  case $release_target in
    linux-x86_64-gnu)
      deb="mealy_0.1.0_amd64.deb"
      rpm="mealy-0.1.0-1.x86_64.rpm"
      arch="mealy-0.1.0-1-x86_64.pkg.tar.zst"
      ;;
    linux-aarch64-gnu)
      deb="mealy_0.1.0_arm64.deb"
      rpm="mealy-0.1.0-1.aarch64.rpm"
      arch=
      ;;
  esac
  printf 'Debian package assembly fixture for %s\n' "$release_target" \
    >"$temporary/merged-input/$deb"
  printf 'RPM package assembly fixture for %s\n' "$release_target" \
    >"$temporary/merged-input/$rpm"
  if [[ -n $arch ]]; then
    printf 'Arch package assembly fixture for %s\n' "$release_target" \
      >"$temporary/merged-input/$arch"
  fi
  (
    cd "$temporary/merged-input"
    sha256sum "$deb" "$rpm" ${arch:+"$arch"} >>"SHA256SUMS-${release_target}"
    sort -k2 -o "SHA256SUMS-${release_target}" "SHA256SUMS-${release_target}"
  )
  printf 'offline provenance bundle fixture for %s\n' "$release_target" \
    >"$temporary/merged-input/ATTESTATION-${release_target}.sigstore.json"
done
"$repository_root/packaging/assemble-release.sh" 0.1.0 \
  "$temporary/merged-input" "$temporary/merged-output" >/dev/null
[[ -x $temporary/merged-output/install-mealy.sh ]]
[[ -x $temporary/merged-output/install-mealy-release.sh ]]
[[ $(find "$temporary/merged-output" -mindepth 1 -maxdepth 1 -type f | wc -l) -eq 15 ]]
cp -a "$temporary/merged-input" "$temporary/unexpected-input"
touch "$temporary/unexpected-input/unexpected"
if "$repository_root/packaging/assemble-release.sh" 0.1.0 \
  "$temporary/unexpected-input" "$temporary/unexpected-output" >/dev/null 2>&1; then
  echo "unexpected merged release asset was accepted" >&2
  exit 1
fi

cmp "$temporary/first/mealy-v0.1.0-${target}.tar.gz" \
  "$temporary/second/mealy-v0.1.0-${target}.tar.gz"
cmp "$temporary/first/install-mealy.sh" "$temporary/second/install-mealy.sh"
cmp "$temporary/first/install-mealy-release.sh" \
  "$temporary/second/install-mealy-release.sh"
cmp "$temporary/first/SHA256SUMS" "$temporary/second/SHA256SUMS"

bootstrap_release="$temporary/bootstrap-release"
bootstrap_fake_bin="$temporary/bootstrap-fake-bin"
mkdir -p "$bootstrap_release" "$bootstrap_fake_bin"
archive="mealy-v0.1.0-${target}.tar.gz"
case $target in
  linux-x86_64-gnu)
    bootstrap_deb=mealy_0.1.0_amd64.deb
    bootstrap_rpm=mealy-0.1.0-1.x86_64.rpm
    bootstrap_arch=mealy-0.1.0-1-x86_64.pkg.tar.zst
    ;;
  linux-aarch64-gnu)
    bootstrap_deb=mealy_0.1.0_arm64.deb
    bootstrap_rpm=mealy-0.1.0-1.aarch64.rpm
    bootstrap_arch=
    ;;
esac
install -m 0644 "$temporary/first/$archive" "$bootstrap_release/$archive"
install -m 0644 "$temporary/first/mealy-v0.1.0-${target}.cdx.json" \
  "$bootstrap_release/mealy-v0.1.0-${target}.cdx.json"
install -m 0755 "$temporary/first/install-mealy.sh" \
  "$bootstrap_release/install-mealy.sh"
install -m 0755 "$temporary/first/install-mealy-release.sh" \
  "$bootstrap_release/install-mealy-release.sh"
printf '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n' \
  >"$bootstrap_release/ATTESTATION-${target}.sigstore.json"
printf '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n' \
  >"$bootstrap_release/ATTESTATION-installers.sigstore.json"
printf 'bootstrap Debian fixture\n' >"$bootstrap_release/$bootstrap_deb"
printf 'bootstrap RPM fixture\n' >"$bootstrap_release/$bootstrap_rpm"
if [[ -n $bootstrap_arch ]]; then
  printf 'bootstrap Arch fixture\n' >"$bootstrap_release/$bootstrap_arch"
fi
(
  cd "$bootstrap_release"
  sha256sum "$archive" install-mealy.sh install-mealy-release.sh \
    "mealy-v0.1.0-${target}.cdx.json" "$bootstrap_deb" "$bootstrap_rpm" \
    ${bootstrap_arch:+"$bootstrap_arch"} | sort -k2 \
    >"SHA256SUMS-${target}"
)
cat >"$bootstrap_fake_bin/gh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"$MEALY_TEST_GH_LOG"
printf '\n' >>"$MEALY_TEST_GH_LOG"
case "${1-} ${2-}" in
  'attestation verify')
    if [[ ${3-} == --help ]]; then
      printf '%s\n' '      --bundle string   Path to bundle on disk'
      exit 0
    fi
    if [[ -n ${MEALY_TEST_GH_FAIL_ASSET-} && ${3-} == *"$MEALY_TEST_GH_FAIL_ASSET" ]]; then
      exit 1
    fi
    exit 0
    ;;
  *)
    echo "unexpected fake gh invocation: $*" >&2
    exit 64
    ;;
esac
SCRIPT
chmod 0755 "$bootstrap_fake_bin/gh"
cat >"$bootstrap_fake_bin/curl" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
output=
url=
while [[ $# -gt 0 ]]; do
  case $1 in
    --output)
      output=${2-}
      shift 2
      ;;
    https://*)
      url=$1
      shift
      ;;
    *)
      shift
      ;;
  esac
done
[[ -n $output && -n $url ]]
case $url in
  https://api.github.com/*/releases/latest|https://api.github.com/*/releases/tags/v0.1.0)
    jq -n \
      --arg target "$MEALY_TEST_TARGET" '
        {
          tag_name: "v0.1.0",
          draft: false,
          prerelease: false,
          assets: [
            {name: ("ATTESTATION-" + $target + ".sigstore.json")},
            {name: "ATTESTATION-installers.sigstore.json"},
            {name: ("SHA256SUMS-" + $target)},
            {name: "install-mealy-release.sh"},
            {name: "install-mealy.sh"},
            {name: ("mealy-v0.1.0-" + $target + ".tar.gz")},
            {name: ("mealy-v0.1.0-" + $target + ".cdx.json")},
            {name: (if $target == "linux-x86_64-gnu" then
              "mealy_0.1.0_amd64.deb" else "mealy_0.1.0_arm64.deb" end)},
            {name: (if $target == "linux-x86_64-gnu" then
              "mealy-0.1.0-1.x86_64.rpm" else "mealy-0.1.0-1.aarch64.rpm" end)},
            (if $target == "linux-x86_64-gnu" then
              {name: "mealy-0.1.0-1-x86_64.pkg.tar.zst"} else empty end)
          ]
        }
      ' >"$output"
    ;;
  https://github.com/*/releases/download/v0.1.0/*)
    asset=${url##*/}
    install -m 0644 "$MEALY_TEST_RELEASE_DIR/$asset" "$output"
    ;;
  *)
    echo "unexpected fake curl URL: $url" >&2
    exit 64
    ;;
esac
SCRIPT
chmod 0755 "$bootstrap_fake_bin/curl"
cat >"$bootstrap_fake_bin/getconf" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
[[ ${1-} == GNU_LIBC_VERSION ]]
printf 'glibc %s\n' "${MEALY_TEST_GLIBC_VERSION:-2.39}"
SCRIPT
chmod 0755 "$bootstrap_fake_bin/getconf"
MEALY_TEST_RELEASE_DIR="$bootstrap_release" \
MEALY_TEST_TARGET="$target" \
MEALY_TEST_GH_LOG="$temporary/bootstrap-gh.log" \
PATH="$bootstrap_fake_bin:$PATH" \
  "$repository_root/packaging/install-release.sh" \
    --version v0.1.0 \
    --prefix "$temporary/bootstrap prefix" --home "$temporary/bootstrap home" \
    >"$temporary/bootstrap-output"
[[ $("$temporary/bootstrap prefix/bin/mealyd") == mealyd-v1 ]]
[[ $("$temporary/bootstrap prefix/bin/mealyctl") == mealyctl-v1 ]]
printf -v expected_setup '  %q --home %q onboard' \
  "$temporary/bootstrap prefix/bin/mealyctl" "$temporary/bootstrap home"
grep -Fqx "$expected_setup" "$temporary/bootstrap-output"
if grep -F -- ' service install' "$temporary/bootstrap-output"; then
  echo "release installer emitted the obsolete multi-command first-run handoff" >&2
  exit 1
fi
MEALY_TEST_RELEASE_DIR="$bootstrap_release" \
MEALY_TEST_TARGET="$target" \
MEALY_TEST_GH_LOG="$temporary/bootstrap-gh-onboard.log" \
MEALY_TEST_ONBOARD_LOG="$temporary/bootstrap-onboard.log" \
PATH="$bootstrap_fake_bin:$PATH" \
  "$repository_root/packaging/install-release.sh" \
    --onboard --version v0.1.0 --repository Amekn/mealy \
    --prefix "$temporary/bootstrap onboard prefix" \
    --home "$temporary/bootstrap onboard home" -- \
    --route local --base-url 'http://127.0.0.1:11434/v1' \
    >"$temporary/bootstrap-onboard-output"
printf -v expected_onboard '%s' \
  "--home $temporary/bootstrap onboard home onboard --route local --base-url http://127.0.0.1:11434/v1"
grep -Fqx -- "$expected_onboard" "$temporary/bootstrap-onboard.log"
grep -Fqx 'Starting guided onboarding.' "$temporary/bootstrap-onboard-output"
if grep -Fq 'Next:' "$temporary/bootstrap-onboard-output"; then
  echo "explicit bootstrap onboarding also emitted a deferred handoff" >&2
  exit 1
fi
MEALY_TEST_RELEASE_DIR="$bootstrap_release" \
MEALY_TEST_TARGET="$target" \
MEALY_TEST_GH_LOG="$temporary/bootstrap-gh-auto-onboard.log" \
MEALY_TEST_ONBOARD_LOG="$temporary/bootstrap-auto-onboard.log" \
PATH="$bootstrap_fake_bin:$PATH" \
  run_in_pty "$repository_root/packaging/install-release.sh" \
    --version v0.1.0 --repository Amekn/mealy \
    --prefix "$temporary/bootstrap auto prefix" \
    --home "$temporary/bootstrap auto home" \
    >"$temporary/bootstrap-auto-onboard-output"
printf -v expected_auto_onboard '%s' \
  "--home $temporary/bootstrap auto home onboard"
grep -Fqx -- "$expected_auto_onboard" "$temporary/bootstrap-auto-onboard.log"
tr -d '\r' <"$temporary/bootstrap-auto-onboard-output" \
  >"$temporary/bootstrap-auto-onboard-normalized"
grep -Fqx 'Starting guided onboarding.' \
  "$temporary/bootstrap-auto-onboard-normalized"
mkdir -p "$temporary/bootstrap existing home"
printf '{}\n' >"$temporary/bootstrap existing home/config.json"
MEALY_TEST_RELEASE_DIR="$bootstrap_release" \
MEALY_TEST_TARGET="$target" \
MEALY_TEST_GH_LOG="$temporary/bootstrap-gh-existing.log" \
MEALY_TEST_ONBOARD_LOG="$temporary/bootstrap-existing-onboard.log" \
PATH="$bootstrap_fake_bin:$PATH" \
  run_in_pty "$repository_root/packaging/install-release.sh" \
    --version v0.1.0 --repository Amekn/mealy \
    --prefix "$temporary/bootstrap existing prefix" \
    --home "$temporary/bootstrap existing home" \
    >"$temporary/bootstrap-existing-output"
tr -d '\r' <"$temporary/bootstrap-existing-output" \
  >"$temporary/bootstrap-existing-normalized"
mv "$temporary/bootstrap-existing-normalized" \
  "$temporary/bootstrap-existing-output"
[[ ! -e $temporary/bootstrap-existing-onboard.log ]]
printf -v expected_doctor '  %q --home %q doctor' \
  "$temporary/bootstrap existing prefix/bin/mealyctl" \
  "$temporary/bootstrap existing home"
printf -v expected_chat '  %q --home %q chat' \
  "$temporary/bootstrap existing prefix/bin/mealyctl" \
  "$temporary/bootstrap existing home"
grep -Fqx "$expected_doctor" "$temporary/bootstrap-existing-output"
grep -Fqx "$expected_chat" "$temporary/bootstrap-existing-output"
if grep -Fq ' onboard' "$temporary/bootstrap-existing-output"; then
  echo "existing-home bootstrap emitted a destructive onboarding handoff" >&2
  exit 1
fi
MEALY_TEST_RELEASE_DIR="$bootstrap_release" \
MEALY_TEST_TARGET="$target" \
MEALY_TEST_GH_LOG="$temporary/bootstrap-gh-no-onboard.log" \
MEALY_TEST_ONBOARD_LOG="$temporary/bootstrap-no-onboard.log" \
PATH="$bootstrap_fake_bin:$PATH" \
  "$repository_root/packaging/install-release.sh" \
    --no-onboard --version v0.1.0 --repository Amekn/mealy \
    --prefix "$temporary/bootstrap no-onboard prefix" \
    --home "$temporary/bootstrap no-onboard home" \
    >"$temporary/bootstrap-no-onboard-output"
printf -v expected_no_onboard '  %q --home %q onboard' \
  "$temporary/bootstrap no-onboard prefix/bin/mealyctl" \
  "$temporary/bootstrap no-onboard home"
grep -Fqx "$expected_no_onboard" "$temporary/bootstrap-no-onboard-output"
[[ ! -e $temporary/bootstrap-no-onboard.log ]]
if "$repository_root/packaging/install-release.sh" --check --onboard \
  >/dev/null 2>&1; then
  echo "check-only bootstrap accepted an onboarding mutation" >&2
  exit 1
fi
if "$repository_root/packaging/install-release.sh" --no-onboard -- --route local \
  >/dev/null 2>&1; then
  echo "passive bootstrap accepted onboarding passthrough arguments" >&2
  exit 1
fi
for asset in "$archive" "SHA256SUMS-${target}" install-mealy.sh \
  install-mealy-release.sh; do
  grep -Eq "attestation verify .*${asset} .*--signer-workflow .*Amekn/mealy/.github/workflows/release.yml .*--source-ref refs/tags/v0.1.0 .*--deny-self-hosted-runners" \
    "$temporary/bootstrap-gh.log"
done
grep -Eq "attestation verify .*${archive} .*--bundle .*ATTESTATION-${target}.sigstore.json" \
  "$temporary/bootstrap-gh.log"
grep -Eq "attestation verify .*install-mealy-release.sh .*--bundle .*ATTESTATION-installers.sigstore.json" \
  "$temporary/bootstrap-gh.log"
# The bootstrap verifies the archive before execution, and the verified manager
# independently enforces the same exact workflow, tag ref, and hosted-runner
# provenance rather than accepting an arbitrary repository attestation.
[[ $(grep -Ec "attestation verify .*${archive} .*--signer-workflow .*Amekn/mealy/.github/workflows/release.yml .*--source-ref refs/tags/v0.1.0 .*--deny-self-hosted-runners" \
  "$temporary/bootstrap-gh.log") -eq 2 ]]
MEALY_TEST_RELEASE_DIR="$bootstrap_release" \
MEALY_TEST_TARGET="$target" \
MEALY_TEST_GH_LOG="$temporary/bootstrap-gh-check.log" \
PATH="$bootstrap_fake_bin:$PATH" \
  "$repository_root/packaging/install-release.sh" \
    --check --version v0.1.0 --repository Amekn/mealy \
    --prefix "$temporary/bootstrap-check-prefix" \
    --home "$temporary/bootstrap-check-home" >"$temporary/bootstrap-check.json"
jq -e --arg target "$target" '
  .schemaVersion == "mealy.update-check.v1"
  and .version == "0.1.0"
  and .target == $target
  and (.commit | test("^[0-9a-f]{40}$"))
  and .stateSchemaVersion == 13
  and .verified == true
' "$temporary/bootstrap-check.json" >/dev/null
[[ ! -e $temporary/bootstrap-check-prefix && ! -e $temporary/bootstrap-check-home ]]
if MEALY_TEST_RELEASE_DIR="$bootstrap_release" \
  MEALY_TEST_TARGET="$target" \
  MEALY_TEST_GH_LOG="$temporary/bootstrap-gh-denied.log" \
  MEALY_TEST_GH_FAIL_ASSET=install-mealy-release.sh \
  PATH="$bootstrap_fake_bin:$PATH" \
  "$repository_root/packaging/install-release.sh" \
    --version v0.1.0 --repository Amekn/mealy \
    --prefix "$temporary/bootstrap-denied-prefix" \
    --home "$temporary/bootstrap-denied-home" >/dev/null 2>&1; then
  echo "release bootstrap accepted a failed provenance verification" >&2
  exit 1
fi
[[ ! -e $temporary/bootstrap-denied-prefix ]]
if MEALY_TEST_RELEASE_DIR="$bootstrap_release" \
  MEALY_TEST_TARGET="$target" \
  MEALY_TEST_GH_LOG="$temporary/bootstrap-gh-old-glibc.log" \
  MEALY_TEST_GLIBC_VERSION=2.38 \
  PATH="$bootstrap_fake_bin:$PATH" \
  "$repository_root/packaging/install-release.sh" \
    --version v0.1.0 --repository Amekn/mealy \
    --prefix "$temporary/bootstrap-old-glibc-prefix" \
    --home "$temporary/bootstrap-old-glibc-home" >/dev/null 2>&1; then
  echo "release bootstrap accepted an unsupported glibc host" >&2
  exit 1
fi
[[ ! -e $temporary/bootstrap-old-glibc-prefix ]]

cp "$temporary/first/install-mealy.sh" "$temporary/tampered-installer.sh"
printf 'tamper\n' >>"$temporary/tampered-installer.sh"
if "$repository_root/scripts/installed-package-smoke.sh" \
  "$temporary/first/mealy-v0.1.0-${target}.tar.gz" \
  "$temporary/first/SHA256SUMS" "$temporary/tampered-installer.sh" \
  >/dev/null 2>&1; then
  echo "installed-package smoke accepted a checksum-mismatched installer" >&2
  exit 1
fi

mkdir -p "$temporary/home"
printf 'preserve durable state\n' >"$temporary/home/state.keep"
"$repository_root/packaging/install.sh" install \
  --archive "$temporary/first/mealy-v0.1.0-${target}.tar.gz" \
  --checksums "$temporary/first/SHA256SUMS" \
  --prefix "$temporary/prefix" \
  --home "$temporary/home" >/dev/null
[[ $("$temporary/prefix/bin/mealyd") == mealyd-v1 ]]
[[ $("$temporary/prefix/bin/mealyctl") == mealyctl-v1 ]]
[[ $(jq -r '.version' "$temporary/prefix/share/mealy/BUILD-MANIFEST.json") == 0.1.0 ]]
[[ -f $temporary/prefix/share/mealy/SBOM.cdx.json ]]
[[ -f $temporary/prefix/share/mealy/THIRD-PARTY-LICENSES.html ]]
[[ -f $temporary/prefix/share/mealy/docs/README.md ]]
[[ -f $temporary/prefix/share/mealy/docs/CLI.md ]]
[[ -f $temporary/prefix/share/mealy/docs/REQUIREMENTS_COVERAGE.md ]]
[[ -f $temporary/prefix/share/mealy/docs/benchmarks/README.md ]]
[[ -f $temporary/prefix/share/mealy/docs/benchmarks/release-soak-subject.json ]]
[[ -f $temporary/prefix/share/mealy/docs/decisions/README.md ]]
[[ -f $temporary/prefix/share/mealy/docs/GETTING_STARTED.md ]]
[[ -f $temporary/prefix/share/mealy/docs/research/ONBOARDING_COMPLETION_AUDIT_2026-07-24.md ]]
[[ -f $temporary/prefix/share/mealy/docs/research/PRODUCT_OPERATIONS_BENCHMARK_2026-07-24.md ]]
[[ -f $temporary/prefix/share/mealy/docs/research/REFERENCE_SYSTEMS.md ]]
[[ -f $temporary/prefix/share/mealy/docs/releases/v0.1.1.md ]]
[[ -f $temporary/prefix/share/mealy/ARCHITECTURE.md ]]
[[ -f $temporary/prefix/share/mealy/REQUIREMENTS.md ]]
[[ -f $temporary/prefix/share/mealy/SECURITY.md ]]
[[ -f $temporary/prefix/share/mealy/docs/THREAT_MODEL.md ]]
[[ -x $temporary/prefix/share/mealy/manage-install.sh ]]
[[ -x $temporary/prefix/share/mealy/manage-release.sh ]]
[[ -x $temporary/prefix/share/mealy/fetch-browser-runtime.sh ]]
[[ -x $temporary/prefix/share/mealy-manager.sh ]]

"$repository_root/packaging/install.sh" install \
  --archive "$temporary/upgrade/mealy-v0.2.0-${target}.tar.gz" \
  --checksums "$temporary/upgrade/SHA256SUMS" \
  --prefix "$temporary/prefix" \
  --home "$temporary/home" >/dev/null
[[ $("$temporary/prefix/bin/mealyd") == mealyd-v2 ]]
[[ $("$temporary/prefix/bin/mealyd.previous") == mealyd-v1 ]]
[[ $(jq -r '.version' "$temporary/prefix/share/mealy/BUILD-MANIFEST.json") == 0.2.0 ]]
[[ $(jq -r '.version' "$temporary/prefix/share/mealy.previous/BUILD-MANIFEST.json") == 0.1.0 ]]

"$temporary/prefix/share/mealy-manager.sh" rollback \
  --prefix "$temporary/prefix" --home "$temporary/home" >/dev/null
[[ $("$temporary/prefix/bin/mealyd") == mealyd-v1 ]]
[[ $("$temporary/prefix/bin/mealyd.previous") == mealyd-v2 ]]
[[ $(jq -r '.version' "$temporary/prefix/share/mealy/BUILD-MANIFEST.json") == 0.1.0 ]]
[[ $(jq -r '.version' "$temporary/prefix/share/mealy.previous/BUILD-MANIFEST.json") == 0.2.0 ]]

"$temporary/prefix/share/mealy-manager.sh" rollback \
  --prefix "$temporary/prefix" --home "$temporary/home" >/dev/null
[[ $("$temporary/prefix/bin/mealyd") == mealyd-v2 ]]
[[ $("$temporary/prefix/bin/mealyd.previous") == mealyd-v1 ]]

(
  exec 8>"$temporary/home/mealyd.lock"
  flock 8
  touch "$temporary/daemon-lock-ready"
  while [[ ! -e $temporary/release-daemon-lock ]]; do
    sleep 0.01
  done
) &
lock_process=$!
for _ in {1..100}; do
  [[ -e $temporary/daemon-lock-ready ]] && break
  sleep 0.01
done
[[ -e $temporary/daemon-lock-ready ]]
if "$temporary/prefix/share/mealy-manager.sh" rollback \
  --prefix "$temporary/prefix" --home "$temporary/home" >/dev/null 2>&1; then
  echo "rollback was allowed while the daemon home lock was held" >&2
  exit 1
fi
touch "$temporary/release-daemon-lock"
wait "$lock_process"
[[ $("$temporary/prefix/bin/mealyd") == mealyd-v2 ]]

mkdir -p "$temporary/tampered"
cp "$temporary/first/mealy-v0.1.0-${target}.tar.gz" "$temporary/tampered/"
cp "$temporary/first/SHA256SUMS" "$temporary/tampered/"
printf 'tamper' >>"$temporary/tampered/mealy-v0.1.0-${target}.tar.gz"
if "$repository_root/packaging/install.sh" install \
  --archive "$temporary/tampered/mealy-v0.1.0-${target}.tar.gz" \
  --checksums "$temporary/tampered/SHA256SUMS" \
  --prefix "$temporary/rejected" \
  --home "$temporary/home" >/dev/null 2>&1; then
  echo "tampered archive was accepted" >&2
  exit 1
fi
[[ $("$temporary/prefix/bin/mealyd") == mealyd-v2 ]]

if "$repository_root/packaging/install.sh" install \
  --archive "$temporary/wrong-architecture/mealy-v0.1.0-${wrong_target}.tar.gz" \
  --checksums "$temporary/wrong-architecture/SHA256SUMS" \
  --prefix "$temporary/wrong-architecture-prefix" \
  --home "$temporary/home" >/dev/null 2>&1; then
  echo "wrong-architecture archive was accepted" >&2
  exit 1
fi
[[ ! -e $temporary/wrong-architecture-prefix/bin/mealyd ]]

"$repository_root/packaging/install.sh" install \
  --archive "$temporary/first/mealy-v0.1.0-${target}.tar.gz" \
  --checksums "$temporary/first/SHA256SUMS" \
  --prefix "$temporary/document-tamper-prefix" \
  --home "$temporary/document-tamper-home" >/dev/null
printf 'tampered security guidance\n' \
  >>"$temporary/document-tamper-prefix/share/mealy/docs/THREAT_MODEL.md"
if "$repository_root/packaging/install.sh" install \
  --archive "$temporary/upgrade/mealy-v0.2.0-${target}.tar.gz" \
  --checksums "$temporary/upgrade/SHA256SUMS" \
  --prefix "$temporary/document-tamper-prefix" \
  --home "$temporary/document-tamper-home" >/dev/null 2>&1; then
  echo "upgrade accepted modified installed security guidance" >&2
  exit 1
fi
[[ $("$temporary/document-tamper-prefix/bin/mealyd") == mealyd-v1 ]]

cp "$temporary/prefix/bin/mealyd" "$temporary/mealyd-valid"
printf 'tamper' >>"$temporary/prefix/bin/mealyd"
if "$temporary/prefix/share/mealy-manager.sh" uninstall \
  --prefix "$temporary/prefix" --home "$temporary/home" >/dev/null 2>&1; then
  echo "uninstall accepted a modified managed binary" >&2
  exit 1
fi
cp "$temporary/mealyd-valid" "$temporary/prefix/bin/mealyd"
chmod 0755 "$temporary/prefix/bin/mealyd"

"$temporary/prefix/share/mealy-manager.sh" uninstall \
  --prefix "$temporary/prefix" --home "$temporary/home" >/dev/null
[[ ! -e $temporary/prefix/bin/mealyd ]]
[[ ! -e $temporary/prefix/bin/mealyctl ]]
[[ ! -e $temporary/prefix/bin/mealyd.previous ]]
[[ ! -e $temporary/prefix/share/mealy ]]
[[ ! -e $temporary/prefix/share/mealy-manager.sh ]]
[[ $(<"$temporary/home/state.keep") == 'preserve durable state' ]]

"$repository_root/packaging/install.sh" install \
  --archive "$temporary/upgrade/mealy-v0.2.0-${target}.tar.gz" \
  --checksums "$temporary/upgrade/SHA256SUMS" \
  --prefix "$temporary/schema-prefix" \
  --home "$temporary/home" >/dev/null
"$repository_root/packaging/install.sh" install \
  --archive "$temporary/schema-upgrade/mealy-v0.3.0-${target}.tar.gz" \
  --checksums "$temporary/schema-upgrade/SHA256SUMS" \
  --prefix "$temporary/schema-prefix" \
  --home "$temporary/home" >/dev/null
if "$temporary/schema-prefix/share/mealy-manager.sh" rollback \
  --prefix "$temporary/schema-prefix" --home "$temporary/home" >/dev/null 2>&1; then
  echo "rollback to a lower state-schema binary was accepted" >&2
  exit 1
fi
[[ $("$temporary/schema-prefix/bin/mealyd") == mealyd-v3 ]]
cross_schema_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
stable_schema_manager="$temporary/schema-prefix/share/mealy-manager.sh"
MEALY_TEST_MIGRATION_BLOCK_READY="$temporary/migration-block.ready" \
  "$stable_schema_manager" rollback-migration \
  --migration-backup v13-to-v14-test \
  --expected-manifest-digest "$cross_schema_digest" \
  --approve --prefix "$temporary/schema-prefix" --home "$temporary/home" \
  >"$temporary/interrupted-migration.log" 2>&1 &
interrupted_manager=$!
for _ in {1..500}; do
  [[ -f $temporary/migration-block.ready ]] && break
  sleep 0.01
done
[[ -f $temporary/migration-block.ready ]]
migration_child=$(<"$temporary/migration-block.ready")
kill -KILL "$interrupted_manager"
wait "$interrupted_manager" 2>/dev/null || true
for _ in {1..500}; do
  if ! kill -0 "$migration_child" 2>/dev/null; then
    break
  fi
  sleep 0.01
done
if kill -0 "$migration_child" 2>/dev/null; then
  echo "interrupted migration activation child remained live" >&2
  exit 1
fi
[[ -d $temporary/schema-prefix/share/mealy-rollback-transaction ]]

MEALY_TEST_MIGRATION_MARKER="$temporary/migration-activation.marker" \
  "$stable_schema_manager" rollback-migration \
  --migration-backup v13-to-v14-test \
  --expected-manifest-digest "$cross_schema_digest" \
  --approve --prefix "$temporary/schema-prefix" --home "$temporary/home" >/dev/null
[[ $("$temporary/schema-prefix/bin/mealyd") == mealyd-v2 ]]
[[ $("$temporary/schema-prefix/bin/mealyd.previous") == mealyd-v3 ]]
[[ $(jq -r '.version' "$temporary/schema-prefix/share/mealy/BUILD-MANIFEST.json") == 0.2.0 ]]
[[ $(jq -r '.version' "$temporary/schema-prefix/share/mealy.previous/BUILD-MANIFEST.json") == 0.3.0 ]]
[[ ! -e $temporary/schema-prefix/share/mealy-rollback-transaction ]]
migration_invocation=$(<"$temporary/migration-activation.marker")
[[ $migration_invocation == *"migration-home-activate v13-to-v14-test"* ]]
[[ $migration_invocation == *"--inherited-home-lock-stdin --approve"* ]]
"$temporary/schema-prefix/share/mealy-manager.sh" uninstall \
  --prefix "$temporary/schema-prefix" --home "$temporary/home" >/dev/null
