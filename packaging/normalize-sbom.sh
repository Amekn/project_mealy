#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: normalize-sbom.sh INPUT OUTPUT VERSION TARGET COMMIT SOURCE_DATE_EPOCH" >&2
}

if [[ $# -ne 6 ]]; then
  usage
  exit 64
fi

input=$1
output=$2
version=$3
target=$4
commit=$5
source_date_epoch=$6

if [[ ! -f $input ]] \
  || [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] \
  || [[ ! $target =~ ^[a-z0-9][a-z0-9._-]+$ ]] \
  || [[ ! $commit =~ ^[0-9a-f]{40}$ ]] \
  || [[ ! $source_date_epoch =~ ^[0-9]+$ ]]; then
  echo "SBOM normalization identity is invalid" >&2
  exit 64
fi
for command in jq sha256sum date mktemp install awk wc mkdir dirname rm; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required SBOM normalization command is unavailable: $command" >&2
    exit 69
  }
done
if [[ $(wc -c <"$input") -gt 16777216 ]]; then
  echo "raw SBOM exceeds the 16 MiB normalization bound" >&2
  exit 65
fi

timestamp=$(date --utc --date="@$source_date_epoch" '+%Y-%m-%dT%H:%M:%SZ')
identity_digest=$(printf 'mealy.release.sbom.v1|%s|%s|%s\n' "$version" "$target" "$commit" \
  | sha256sum | awk '{print $1}')
uuid="${identity_digest:0:8}-${identity_digest:8:4}-5${identity_digest:13:3}-8${identity_digest:17:3}-${identity_digest:20:12}"
temporary=$(mktemp "${TMPDIR:-/tmp}/mealy-sbom.XXXXXX")
cleanup() {
  rm -f "$temporary"
}
trap cleanup EXIT

if ! jq --compact-output --sort-keys \
  --arg serial_number "urn:uuid:$uuid" \
  --arg timestamp "$timestamp" \
  --arg version "$version" \
  --arg target "$target" \
  --arg commit "$commit" '
    if .bomFormat != "CycloneDX"
      or (.specVersion | type) != "string"
      or (.version | type) != "number"
      or (.components | type) != "array"
      or (.components | length) == 0
    then error("invalid CycloneDX input") else . end
    | .serialNumber = $serial_number
    | .metadata.timestamp = $timestamp
    | .metadata.component = {
        "bom-ref": ("mealy-release:" + $version + ":" + $target + ":" + $commit),
        "type": "application",
        "group": "Amekn",
        "name": "mealy",
        "version": $version,
        "properties": [
          {"name": "mealy:release:commit", "value": $commit},
          {"name": "mealy:release:target", "value": $target}
        ]
      }
    | .components |= map(
        if .type == "file" and (.name | endswith("/bin/mealyd")) then
          .name = "/bin/mealyd"
        elif .type == "file" and (.name | endswith("/bin/mealyctl")) then
          .name = "/bin/mealyctl"
        else . end
      )
    | .components |= sort_by(."bom-ref")
    | (.components[] | select(has("properties")) | .properties) |= sort_by(.name, .value)
    | if has("dependencies") then
        .dependencies |= sort_by(.ref)
        | (.dependencies[] | select(has("dependsOn")) | .dependsOn) |= sort
      else . end
  ' "$input" >"$temporary"; then
  echo "CycloneDX SBOM normalization failed" >&2
  exit 65
fi
if jq -e '.. | strings | select(test("^/(home|tmp|github)/"))' "$temporary" >/dev/null; then
  echo "normalized SBOM retains a local build path" >&2
  exit 65
fi
mkdir -p "$(dirname "$output")"
install -m 0644 "$temporary" "$output"
