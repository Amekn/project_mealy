#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: verify-release-payload.sh VERSION TARGET ARCHIVE SHA256SUMS DESTINATION" >&2
}

if [[ $# -ne 5 ]]; then
  usage
  exit 64
fi

version=$1
target=$2
archive=$3
checksums=$4
destination=$5

if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "system-package payload requires a stable semantic version" >&2
  exit 64
fi
case $target in
  linux-x86_64-gnu|linux-aarch64-gnu) ;;
  *)
    echo "unsupported Linux payload target: $target" >&2
    exit 64
    ;;
esac
for command in awk find grep jq mkdir readlink sed sha256sum sort tar wc; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required payload-verification command is unavailable: $command" >&2
    exit 69
  fi
done
if [[ -L $archive || ! -f $archive || -L $checksums || ! -f $checksums ]]; then
  echo "release payload inputs must be real regular files" >&2
  exit 66
fi
if [[ -e $destination ]]; then
  echo "release payload destination must not already exist" >&2
  exit 65
fi

archive=$(readlink -f "$archive")
checksums=$(readlink -f "$checksums")
archive_name="mealy-v${version}-${target}.tar.gz"
if [[ ${archive##*/} != "$archive_name" ]]; then
  echo "release archive name does not match the system-package identity" >&2
  exit 65
fi

if ! awk '
  NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-f]+$/ ||
    $2 !~ /^[A-Za-z0-9][A-Za-z0-9._-]*$/ {exit 1}
  END {if (NR == 0) exit 1}
' "$checksums"; then
  echo "release checksum manifest is malformed" >&2
  exit 65
fi
mapfile -t checksum_entries < <(awk '{print $2}' "$checksums")
if [[ ${#checksum_entries[@]} -lt 4 || ${#checksum_entries[@]} -gt 8 \
  || $(printf '%s\n' "${checksum_entries[@]}" | sort -u | wc -l) -ne ${#checksum_entries[@]} \
  || $(printf '%s\n' "${checksum_entries[@]}" | grep -Fxc "$archive_name") -ne 1 ]]; then
  echo "release checksum manifest is malformed or omits the exact archive" >&2
  exit 65
fi
archive_digest=$(awk -v archive="$archive_name" '$2 == archive {print $1}' "$checksums")
if [[ $(sha256sum "$archive" | awk '{print $1}') != "$archive_digest" ]]; then
  echo "release archive failed its outer checksum" >&2
  exit 65
fi

entries=$(tar -tzf "$archive")
listing=$(tar --numeric-owner -tvzf "$archive")
if [[ -z $entries ]] || ! printf '%s\n' "$listing" | awk '
  $1 !~ /^[-d]/ || $3 !~ /^[0-9]+$/ {exit 1}
  {count += 1; total += $3}
  count > 256 || $3 > 268435456 || total > 536870912 {exit 1}
  END {if (count == 0) exit 1}
'; then
  echo "release archive type, count, or expanded size is invalid" >&2
  exit 65
fi
unsafe=false
while IFS= read -r entry; do
  case $entry in
    /*|../*|*/../*|*/..) unsafe=true ;;
  esac
done <<<"$entries"
root_count=$(printf '%s\n' "$entries" | sed 's#^\./##' | awk -F/ 'NF {print $1}' | sort -u | wc -l)
root=$(printf '%s\n' "$entries" | sed 's#^\./##' | awk -F/ 'NF {print $1; exit}')
if [[ $unsafe == true || $root_count -ne 1 || $root != "mealy-v${version}-${target}" ]]; then
  echo "release archive root or path is invalid" >&2
  exit 65
fi

mkdir -m 0700 "$destination"
tar -xzf "$archive" -C "$destination" --no-same-owner --no-same-permissions
package="$destination/$root"
if [[ -n $(find "$package" \( -type l -o ! -type f -a ! -type d \) -print -quit) \
  || ! -f $package/PAYLOAD-SHA256SUMS ]]; then
  echo "release payload contains an unsupported file type or no inner manifest" >&2
  exit 65
fi
if ! awk '
  NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-f]+$/ {exit 1}
  END {if (NR == 0) exit 1}
' "$package/PAYLOAD-SHA256SUMS"; then
  echo "release payload checksum manifest is malformed" >&2
  exit 65
fi
mapfile -t payload_entries < <(awk '{print $2}' "$package/PAYLOAD-SHA256SUMS")
expected_inventory=$(printf '%s\n' "${payload_entries[@]}" PAYLOAD-SHA256SUMS | sort -u)
actual_inventory=$(find "$package" -type f -printf '%P\n' | sort)
if [[ ${#payload_entries[@]} -lt 16 \
  || $(printf '%s\n' "${payload_entries[@]}" | sort -u | wc -l) -ne ${#payload_entries[@]} \
  || $actual_inventory != "$expected_inventory" ]]; then
  echo "release payload inventory or inner checksums are invalid" >&2
  exit 65
fi
if ! (cd "$package" && sha256sum --check --strict PAYLOAD-SHA256SUMS >/dev/null); then
  echo "release payload inventory or inner checksums are invalid" >&2
  exit 65
fi
if [[ ! -x $package/bin/mealyd || ! -x $package/bin/mealyctl \
  || ! -x $package/install.sh || ! -x $package/fetch-browser-runtime.sh ]]; then
  echo "release payload executables are absent or not executable" >&2
  exit 65
fi
if ! jq -e --arg version "$version" --arg target "$target" '
  .schemaVersion == "mealy.release.v2"
  and .version == $version
  and .target == $target
  and (.commit | type == "string" and test("^[0-9a-f]{40}$"))
  and (.sourceDateEpoch | type == "number" and . >= 1 and floor == .)
  and (.stateSchemaVersion | type == "number" and . >= 1 and . <= 9999)
  and .sbom == "SBOM.cdx.json"
  and .licenses == "THIRD-PARTY-LICENSES.html"
' "$package/BUILD-MANIFEST.json" >/dev/null \
  || [[ $("$package/bin/mealyd" --version) != "mealyd $version" \
    || $("$package/bin/mealyctl" --version) != "mealyctl $version" \
    || $("$package/bin/mealyd" --print-supported-schema-version) \
      != "$(jq -er '.stateSchemaVersion' "$package/BUILD-MANIFEST.json")" ]]; then
  echo "release payload manifest or binary identity is invalid" >&2
  exit 65
fi

printf '%s\n' "$package"
