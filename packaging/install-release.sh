#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  cat >&2 <<'USAGE'
usage: install-mealy-release.sh [--version TAG|latest] [--check]
       [--repository OWNER/REPO] [--prefix DIR] [--home DIR]

Downloads one stable, attested Mealy release for this Linux architecture,
verifies its release-workflow provenance and complete checksum inventory, and
installs it through the release's own owner-local manager. No Rust toolchain or
root access or GitHub account is required. GitHub CLI performs offline-bundle
verification; curl reads only the public release metadata and exact assets.
--check performs the same download, provenance, checksum, and target-manifest
verification but emits bounded JSON without installing anything.
USAGE
}

version=latest
check=false
repository=Amekn/project_mealy
prefix=${HOME:+$HOME/.local}
home=${MEALY_HOME:-${HOME:+$HOME/.mealy}}
while [[ $# -gt 0 ]]; do
  case $1 in
    --version)
      version=${2-}
      shift 2
      ;;
    --check)
      check=true
      shift
      ;;
    --repository)
      repository=${2-}
      shift 2
      ;;
    --prefix)
      prefix=${2-}
      shift 2
      ;;
    --home)
      home=${2-}
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage
      exit 64
      ;;
  esac
done

if [[ $(uname -s) != Linux || -z $prefix || -z $home \
  || ! $repository =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ \
  || ( $version != latest \
    && ! $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ) ]]; then
  usage
  exit 64
fi

case $(uname -m) in
  x86_64|amd64)
    target=linux-x86_64-gnu
    debian_architecture=amd64
    rpm_architecture=x86_64
    arch_package=true
    ;;
  aarch64|arm64)
    target=linux-aarch64-gnu
    debian_architecture=arm64
    rpm_architecture=aarch64
    arch_package=false
    ;;
  *)
    echo "unsupported Linux architecture: $(uname -m)" >&2
    exit 65
    ;;
esac

for command in awk basename chmod curl find getconf gh grep jq mktemp readlink rm sha256sum sort stat \
  tar uname wc; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required release-bootstrap command is unavailable: $command" >&2
    exit 69
  }
done
if ! gh attestation verify --help 2>/dev/null | grep -Fq -- '--bundle'; then
  echo "GitHub CLI is too old; install a version with 'gh attestation verify --bundle'" >&2
  exit 69
fi
libc_identity=$(getconf GNU_LIBC_VERSION 2>/dev/null || true)
if [[ ! $libc_identity =~ ^glibc\ ([0-9]+)\.([0-9]+)(\.[0-9]+)?$ ]] \
  || (( BASH_REMATCH[1] < 2 \
    || (BASH_REMATCH[1] == 2 && BASH_REMATCH[2] < 39) )); then
  echo "Mealy's GNU/Linux release requires glibc 2.39 or newer; detected: ${libc_identity:-unknown}" >&2
  exit 65
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-release-install.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

curl_arguments=(--fail --location --silent --show-error \
  --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --connect-timeout 20 --max-time 120 --max-redirs 5)
if [[ $version == latest ]]; then
  release_url="https://api.github.com/repos/$repository/releases/latest"
else
  release_url="https://api.github.com/repos/$repository/releases/tags/$version"
fi
curl "${curl_arguments[@]}" --max-filesize 1048576 \
  --output "$temporary/release.json" "$release_url"
tag=$(jq -er 'select(.draft == false and .prerelease == false) | .tag_name' \
  "$temporary/release.json")
if [[ ! $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ \
  || ( $version != latest && $tag != "$version" ) ]]; then
  echo "requested release is absent, draft, prerelease, or has an invalid tag" >&2
  exit 65
fi

release_version=${tag#v}
debian_version=${release_version/-/~}
archive="mealy-v${release_version}-${target}.tar.gz"
checksums="SHA256SUMS-${target}"
manager=install-mealy.sh
bootstrap=install-mealy-release.sh
sbom="mealy-v${release_version}-${target}.cdx.json"
deb="mealy_${debian_version}_${debian_architecture}.deb"
rpm="mealy-${release_version}-1.${rpm_architecture}.rpm"
arch="mealy-${release_version}-1-x86_64.pkg.tar.zst"
architecture_bundle="ATTESTATION-${target}.sigstore.json"
installer_bundle=ATTESTATION-installers.sigstore.json

expected_download=$(printf '%s\n' "$archive" "$architecture_bundle" "$bootstrap" \
  "$checksums" "$installer_bundle" "$manager" | sort)
expected_release_assets=$(printf '%s\n' "$archive" "$architecture_bundle" "$bootstrap" \
  "$checksums" "$deb" "$installer_bundle" "$manager" "$rpm" "$sbom" | sort)
expected_manifest=$(printf '%s\n' "$archive" "$bootstrap" "$deb" "$manager" "$rpm" "$sbom")
expected_manifest_count=6
if [[ $arch_package == true ]]; then
  expected_release_assets=$(printf '%s\n' "$expected_release_assets" "$arch" | sort)
  expected_manifest=$(printf '%s\n' "$expected_manifest" "$arch")
  expected_manifest_count=7
fi
expected_manifest=$(printf '%s\n' "$expected_manifest" | sort)
while IFS= read -r asset; do
  if ! jq -e --arg asset "$asset" \
    '[.assets[] | select(.name == $asset)] | length == 1' \
    "$temporary/release.json" >/dev/null; then
    echo "release metadata has no unique required asset: $asset" >&2
    exit 65
  fi
done <<<"$expected_release_assets"
while IFS= read -r asset; do
  case $asset in
    "$archive") maximum=268435456 ;;
    "$checksums") maximum=1048576 ;;
    "$architecture_bundle"|"$installer_bundle") maximum=16777216 ;;
    "$manager"|"$bootstrap") maximum=2097152 ;;
  esac
  curl "${curl_arguments[@]}" --max-filesize "$maximum" \
    --output "$temporary/$asset" \
    "https://github.com/$repository/releases/download/$tag/$asset"
done <<<"$expected_download"
rm "$temporary/release.json"
actual_download=$(find "$temporary" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
if [[ $actual_download != "$expected_download" \
  || -n $(find "$temporary" -mindepth 1 -maxdepth 1 \
    \( -type l -o ! -type f \) -print -quit) ]]; then
  echo "downloaded release inventory is incomplete or contains an unsupported entry" >&2
  exit 65
fi
if [[ $(stat -c '%s' "$temporary/$archive") -gt 268435456 \
  || $(stat -c '%s' "$temporary/$checksums") -gt 1048576 \
  || $(stat -c '%s' "$temporary/$manager") -gt 2097152 \
  || $(stat -c '%s' "$temporary/$bootstrap") -gt 2097152 \
  || $(stat -c '%s' "$temporary/$architecture_bundle") -gt 16777216 \
  || $(stat -c '%s' "$temporary/$installer_bundle") -gt 16777216 ]]; then
  echo "downloaded release asset exceeds its bootstrap bound" >&2
  exit 65
fi

signer_workflow="$repository/.github/workflows/release.yml"
for asset in "$archive" "$checksums"; do
  gh attestation verify "$temporary/$asset" --repo "$repository" \
    --signer-workflow "$signer_workflow" --source-ref "refs/tags/$tag" \
    --bundle "$temporary/$architecture_bundle" \
    --deny-self-hosted-runners >/dev/null
done
for asset in "$manager" "$bootstrap"; do
  gh attestation verify "$temporary/$asset" --repo "$repository" \
    --signer-workflow "$signer_workflow" --source-ref "refs/tags/$tag" \
    --bundle "$temporary/$installer_bundle" \
    --deny-self-hosted-runners >/dev/null
done

if ! awk -v expected="$expected_manifest_count" '
    NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-f]+$/ {exit 1}
    END {if (NR != expected) exit 1}
  ' "$temporary/$checksums"; then
  echo "target checksum manifest is not canonical" >&2
  exit 65
fi
actual_manifest=$(awk '{print $2}' "$temporary/$checksums" | sort)
if [[ $actual_manifest != "$expected_manifest" ]]; then
  echo "target checksum manifest inventory does not match the release" >&2
  exit 65
fi
verification_manifest="$temporary/INSTALL-SHA256SUMS"
awk -v archive="$archive" -v bootstrap="$bootstrap" -v manager="$manager" '
  $2 == archive || $2 == bootstrap || $2 == manager {print}
' "$temporary/$checksums" >"$verification_manifest"
if [[ $(wc -l <"$verification_manifest") -ne 3 ]] \
  || ! (cd "$temporary" && sha256sum --check --strict "${verification_manifest##*/}" >/dev/null); then
  echo "downloaded release asset checksum verification failed" >&2
  exit 65
fi

manifest_member="mealy-v${release_version}-${target}/BUILD-MANIFEST.json"
if [[ $(tar -tzf "$temporary/$archive" | grep -Fxc "$manifest_member") -ne 1 ]]; then
  echo "attested release archive has no unique build manifest" >&2
  exit 65
fi
tar -xOzf "$temporary/$archive" "$manifest_member" >"$temporary/BUILD-MANIFEST.json"
if [[ $(stat -c '%s' "$temporary/BUILD-MANIFEST.json") -gt 65536 ]] \
  || ! jq -e --arg version "$release_version" --arg target "$target" '
      .schemaVersion == "mealy.release.v2"
      and .version == $version
      and .target == $target
      and (.commit | type == "string" and test("^[0-9a-f]{40}$"))
      and (.sourceDateEpoch | type == "number" and . >= 1 and floor == .)
      and (.stateSchemaVersion | type == "number" and . >= 1 and . <= 9999 and floor == .)
      and .sbom == "SBOM.cdx.json"
      and .licenses == "THIRD-PARTY-LICENSES.html"
    ' "$temporary/BUILD-MANIFEST.json" >/dev/null; then
  echo "attested release build manifest is invalid" >&2
  exit 65
fi
if [[ $check == true ]]; then
  jq -cn --arg version "$release_version" --arg target "$target" \
    --arg commit "$(jq -er '.commit' "$temporary/BUILD-MANIFEST.json")" \
    --argjson state_schema_version \
      "$(jq -er '.stateSchemaVersion' "$temporary/BUILD-MANIFEST.json")" \
    '{
      schemaVersion: "mealy.update-check.v1",
      version: $version,
      target: $target,
      commit: $commit,
      stateSchemaVersion: $state_schema_version,
      verified: true
    }'
  exit 0
fi

chmod 0755 "$temporary/$manager"
"$temporary/$manager" install \
  --archive "$temporary/$archive" \
  --checksums "$temporary/$checksums" \
  --verify-repository "$repository" \
  --attestation-bundle "$temporary/$architecture_bundle" \
  --prefix "$prefix" \
  --home "$home"

installed_prefix=$(readlink -f -- "$prefix")
installed_home=$(readlink -m -- "$home")
if [[ -z $installed_prefix || -z $installed_home ]]; then
  echo "installed Mealy handoff paths could not be canonicalized" >&2
  exit 65
fi
printf 'Installed Mealy %s for %s.\nNext:\n' "$release_version" "$target"
printf '  %q --home %q onboard\n' "$installed_prefix/bin/mealyctl" "$installed_home"
