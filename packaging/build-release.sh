#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: build-release.sh VERSION TARGET BINARY_DIR SBOM THIRD_PARTY_LICENSES OUTPUT_DIR COMMIT SOURCE_DATE_EPOCH STATE_SCHEMA_VERSION" >&2
}

if [[ $# -ne 9 ]]; then
  usage
  exit 64
fi

version=$1
target=$2
binary_dir=$3
sbom=$4
third_party_licenses=$5
output_dir=$6
commit=$7
source_date_epoch=$8
state_schema_version=$9
# Keep this path inventory synchronized with build-deb.sh and install.sh. The packaging fixtures
# deliberately fail closed when any standalone boundary omits or adds a release document.
release_documents=(
  API.md
  CI_CD.md
  CLI.md
  DOMAIN_MODEL.md
  IMPLEMENTATION_PLAN.md
  OPERATIONS.md
  PRODUCTION_READINESS.md
  QUICKSTART.md
  README.md
  RELEASE.md
  REQUIREMENTS_COVERAGE.md
  TESTING.md
  THREAT_MODEL.md
  benchmarks/2026-07-12-development-soak.json
  benchmarks/2026-07-13-debian-13-installed-package-smoke.md
  benchmarks/2026-07-13-development-soak.json
  benchmarks/2026-07-13-five-minute-paced-soak.json
  benchmarks/2026-07-13-live-public-web-fetch.md
  benchmarks/2026-07-13-schema14-long-soak-failure.md
  benchmarks/2026-07-13-storage-optimized-soak.json
  benchmarks/2026-07-13-supply-chain-policy-audit.md
  benchmarks/2026-07-13-thirty-minute-paced-soak.json
  benchmarks/2026-07-13-ubuntu-24.04-installed-package-smoke.md
  benchmarks/2026-07-14-nine-hour-supervisor-interruption.md
  benchmarks/2026-07-15-fedora-44-installed-package-smoke.md
  benchmarks/2026-07-16-schema15-long-soak-contention-failure.md
  benchmarks/2026-07-16-schema15-release-soak-lineage.json
  benchmarks/2026-07-16-schema15-release-soak.json
  benchmarks/2026-07-20-schema15-near-deadline-provider-dispatch-failure.md
  benchmarks/2026-07-20-interrupted-soak-and-storage-architecture.md
  benchmarks/README.md
  benchmarks/release-soak.json
  benchmarks/release-soak-subject.json
  decisions/0001-modular-monolith-and-workers.md
  decisions/0002-transactional-journal.md
  decisions/0003-effect-recovery.md
  decisions/0004-security-boundaries.md
  decisions/0005-durable-session-inbox.md
  decisions/0006-context-and-memory.md
  decisions/0007-local-api.md
  decisions/0008-risk-based-validation.md
  decisions/0009-sqlite-writer-and-snapshot-readers.md
  decisions/README.md
  research/GAP_MATRIX.md
  research/REFERENCE_SYSTEMS.md
)

if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] \
  || [[ ! $commit =~ ^[0-9a-f]{40}$ ]] \
  || [[ ! $source_date_epoch =~ ^[0-9]+$ ]] \
  || [[ ! $state_schema_version =~ ^[1-9][0-9]{0,3}$ ]]; then
  echo "release identity is invalid" >&2
  exit 64
fi
case $target in
  linux-x86_64-gnu|linux-aarch64-gnu) ;;
  *)
    echo "unsupported release target: $target" >&2
    exit 64
    ;;
esac

for binary in mealyd mealyctl; do
  if [[ ! -f "$binary_dir/$binary" || ! -x "$binary_dir/$binary" ]]; then
    echo "required release binary is absent or not executable: $binary" >&2
    exit 66
  fi
  if grep -aEq '/home/[^/[:cntrl:]]+/|/Users/[^/[:cntrl:]]+/|/root/|[A-Za-z]:[/\\]Users[/\\]' \
    "$binary_dir/$binary"; then
    echo "release binary contains a host-specific user-home path: $binary" >&2
    exit 65
  fi
  if [[ $("$binary_dir/$binary" --version) != "$binary $version" ]]; then
    echo "release binary version does not match package identity: $binary" >&2
    exit 65
  fi
done
if [[ $("$binary_dir/mealyd" --print-supported-schema-version) != "$state_schema_version" ]]; then
  echo "mealyd state-schema support does not match package identity" >&2
  exit 65
fi
if [[ ! -f $sbom ]]; then
  echo "required CycloneDX SBOM is absent" >&2
  exit 66
fi
if [[ -L $third_party_licenses || ! -f $third_party_licenses ]]; then
  echo "required third-party license notice is absent or not a real file" >&2
  exit 66
fi

for command in date find grep gzip install jq mktemp sha256sum sort tar wc; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required packaging command is unavailable: $command" >&2
    exit 69
  }
done
expected_sbom_timestamp=$(date --utc --date="@$source_date_epoch" '+%Y-%m-%dT%H:%M:%SZ')
if ! jq -e \
  --arg version "$version" \
  --arg target "$target" \
  --arg commit "$commit" \
  --arg timestamp "$expected_sbom_timestamp" '
    .bomFormat == "CycloneDX"
    and (.specVersion | type == "string")
    and (.version | type == "number")
    and (.components | type == "array" and length > 0)
    and (.serialNumber | type == "string" and test("^urn:uuid:[0-9a-f-]{36}$"))
    and .metadata.timestamp == $timestamp
    and .metadata.component.name == "mealy"
    and .metadata.component.version == $version
    and ([.metadata.component.properties[] | select(.name == "mealy:release:target") | .value] == [$target])
    and ([.metadata.component.properties[] | select(.name == "mealy:release:commit") | .value] == [$commit])
  ' "$sbom" >/dev/null; then
  echo "CycloneDX SBOM is invalid or empty" >&2
  exit 65
fi
if [[ $(wc -c <"$sbom") -gt 16777216 ]]; then
  echo "CycloneDX SBOM exceeds the 16 MiB package bound" >&2
  exit 65
fi
if [[ $(wc -c <"$third_party_licenses") -lt 1024 \
  || $(wc -c <"$third_party_licenses") -gt 8388608 ]] \
  || ! grep -Fq '<h1>Mealy third-party licenses</h1>' "$third_party_licenses" \
  || grep -Eiq '<(script|iframe|object|embed|form|img|link)|javascript:|http-equiv|/home/|target/' \
    "$third_party_licenses"; then
  echo "third-party license notice is invalid or outside its package bound" >&2
  exit 65
fi

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
expected_documents=$(printf '%s\n' "${release_documents[@]}" | sort)
actual_documents=$(find "$repository_root/docs" -type f -printf '%P\n' | sort)
if [[ -n $(find "$repository_root/docs" \( -type l -o ! -type f -a ! -type d \) -print -quit) \
  || $actual_documents != "$expected_documents" ]]; then
  echo "release documentation inventory is incomplete or contains an unsupported entry" >&2
  exit 65
fi
package_name="mealy-v${version}-${target}"
mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd -P)
staging=$(mktemp -d "${TMPDIR:-/tmp}/mealy-package.XXXXXX")
cleanup() {
  rm -rf "$staging"
}
trap cleanup EXIT

mkdir -p "$staging/$package_name/bin" "$staging/$package_name/docs"
install -m 0755 "$binary_dir/mealyd" "$staging/$package_name/bin/mealyd"
install -m 0755 "$binary_dir/mealyctl" "$staging/$package_name/bin/mealyctl"
install -m 0755 "$repository_root/packaging/install.sh" "$staging/$package_name/install.sh"
install -m 0755 "$repository_root/scripts/fetch-browser-runtime.sh" \
  "$staging/$package_name/fetch-browser-runtime.sh"
install -m 0644 "$repository_root/LICENSE" "$staging/$package_name/LICENSE"
install -m 0644 "$third_party_licenses" \
  "$staging/$package_name/THIRD-PARTY-LICENSES.html"
install -m 0644 "$repository_root/ARCHITECTURE.md" "$staging/$package_name/ARCHITECTURE.md"
install -m 0644 "$repository_root/README.md" "$staging/$package_name/README.md"
install -m 0644 "$repository_root/REQUIREMENTS.md" "$staging/$package_name/REQUIREMENTS.md"
install -m 0644 "$repository_root/SECURITY.md" "$staging/$package_name/SECURITY.md"
packaged_documents=()
for document in "${release_documents[@]}"; do
  install -D -m 0644 "$repository_root/docs/$document" \
    "$staging/$package_name/docs/$document"
  packaged_documents+=("docs/$document")
done
install -m 0644 "$sbom" "$staging/$package_name/SBOM.cdx.json"
printf '{"schemaVersion":"mealy.release.v2","version":"%s","target":"%s","commit":"%s","sourceDateEpoch":%s,"stateSchemaVersion":%s,"sbom":"SBOM.cdx.json","licenses":"THIRD-PARTY-LICENSES.html"}\n' \
  "$version" "$target" "$commit" "$source_date_epoch" "$state_schema_version" \
  >"$staging/$package_name/BUILD-MANIFEST.json"
(
  cd "$staging/$package_name"
  sha256sum \
    bin/mealyd \
    bin/mealyctl \
    install.sh \
    fetch-browser-runtime.sh \
    BUILD-MANIFEST.json \
    SBOM.cdx.json \
    LICENSE \
    THIRD-PARTY-LICENSES.html \
    ARCHITECTURE.md \
    README.md \
    REQUIREMENTS.md \
    SECURITY.md \
    "${packaged_documents[@]}" \
    >PAYLOAD-SHA256SUMS
)

archive="$output_dir/$package_name.tar.gz"
tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
  -C "$staging" -cf - "$package_name" | gzip -n >"$archive"
install -m 0755 "$repository_root/packaging/install.sh" "$output_dir/install-mealy.sh"
install -m 0755 "$repository_root/packaging/install-release.sh" \
  "$output_dir/install-mealy-release.sh"
sbom_asset="$output_dir/$package_name.cdx.json"
install -m 0644 "$sbom" "$sbom_asset"
(
  cd "$output_dir"
  sha256sum \
    "$(basename "$archive")" \
    install-mealy.sh \
    install-mealy-release.sh \
    "$(basename "$sbom_asset")" \
    >SHA256SUMS
)
echo "$archive"
