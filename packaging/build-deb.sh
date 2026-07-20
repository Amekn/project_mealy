#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: build-deb.sh VERSION TARGET ARCHIVE SHA256SUMS OUTPUT_DIR SOURCE_DATE_EPOCH" >&2
}

if [[ $# -ne 6 ]]; then
  usage
  exit 64
fi

version=$1
target=$2
archive=$3
checksums=$4
output_dir=$5
source_date_epoch=$6
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] \
  || [[ ! $source_date_epoch =~ ^[0-9]+$ ]]; then
  echo "Debian package identity is invalid" >&2
  exit 64
fi
case $target in
  linux-x86_64-gnu) debian_architecture=amd64 ;;
  linux-aarch64-gnu) debian_architecture=arm64 ;;
  *)
    echo "unsupported Debian package target: $target" >&2
    exit 64
    ;;
esac
debian_version=${version/-/~}
archive_name="mealy-v${version}-${target}.tar.gz"
sbom_name="mealy-v${version}-${target}.cdx.json"
deb_name="mealy_${debian_version}_${debian_architecture}.deb"
# Keep this path inventory synchronized with build-release.sh and install.sh. The packaging
# fixtures deliberately fail closed when any standalone boundary omits or adds a document.
release_documents=(
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
  benchmarks/2026-07-20-schema15-near-deadline-provider-dispatch-failure.md
  benchmarks/2026-07-20-interrupted-soak-and-storage-architecture.md
  benchmarks/README.md
  benchmarks/release-soak-lineage.json
  benchmarks/release-soak.json
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

for command in ar awk chmod cp date dirname find gzip install jq ln md5sum mkdir mktemp mv od \
  readlink rm sed sha256sum sort tar touch tr wc; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required Debian packaging command is unavailable: $command" >&2
    exit 69
  fi
done
if [[ -L $archive || ! -f $archive || -L $checksums || ! -f $checksums ]]; then
  echo "Debian package inputs must be real regular files" >&2
  exit 66
fi
archive=$(readlink -f "$archive")
checksums=$(readlink -f "$checksums")
if [[ ${archive##*/} != "$archive_name" ]]; then
  echo "release archive name does not match Debian package identity" >&2
  exit 65
fi
mkdir -p -- "$output_dir"
if [[ -L $output_dir || ! -d $output_dir ]]; then
  echo "Debian package output must be a real directory" >&2
  exit 65
fi
output_dir=$(readlink -f "$output_dir")
checksum_dir=$(readlink -f "$(dirname "$checksums")")
if [[ $checksum_dir != "$output_dir" || $archive != "$output_dir/$archive_name" ]]; then
  echo "archive, checksum manifest, and Debian output must share one directory" >&2
  exit 65
fi

mapfile -t checksum_paths < <(awk '
  NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-f]+$/ {exit 1}
  {print $2}
' "$checksums")
expected_paths=$(printf '%s\n' "$archive_name" install-mealy.sh install-mealy-release.sh \
  "$sbom_name" | sort)
actual_paths=$(printf '%s\n' "${checksum_paths[@]}" | sort -u)
if [[ ${#checksum_paths[@]} -ne 4 || $actual_paths != "$expected_paths" ]] \
  || ! (cd "$output_dir" && sha256sum --check --strict "${checksums##*/}" >/dev/null); then
  echo "pre-Debian checksum manifest is invalid" >&2
  exit 65
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-deb-build.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

entries=$(tar -tzf "$archive")
listing=$(tar --numeric-owner -tvzf "$archive")
if [[ -z $entries ]] || ! printf '%s\n' "$listing" | awk '
  $1 !~ /^[-d]/ || $3 !~ /^[0-9]+$/ {exit 1}
  {count += 1; total += $3}
  count > 64 || $3 > 268435456 || total > 536870912 {exit 1}
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
tar -xzf "$archive" -C "$temporary" --no-same-owner --no-same-permissions
package="$temporary/$root"
if [[ -n $(find "$package" \( -type l -o ! -type f -a ! -type d \) -print -quit) ]]; then
  echo "release archive extracted an unsupported file type" >&2
  exit 65
fi
expected_files=(
  bin/mealyd
  bin/mealyctl
  install.sh
  fetch-browser-runtime.sh
  BUILD-MANIFEST.json
  SBOM.cdx.json
  LICENSE
  THIRD-PARTY-LICENSES.html
  ARCHITECTURE.md
  README.md
  REQUIREMENTS.md
  SECURITY.md
  "${release_documents[@]/#/docs/}"
)
expected_inventory=$(printf '%s\n' "${expected_files[@]}" PAYLOAD-SHA256SUMS | sort)
actual_inventory=$(find "$package" -type f -printf '%P\n' | sort)
payload_inventory=$(awk '{print $2}' "$package/PAYLOAD-SHA256SUMS" | sort -u)
expected_payload=$(printf '%s\n' "${expected_files[@]}" | sort)
if [[ $actual_inventory != "$expected_inventory" || $payload_inventory != "$expected_payload" ]] \
  || ! (cd "$package" && sha256sum --check --strict PAYLOAD-SHA256SUMS >/dev/null) \
  || [[ ! -x $package/bin/mealyd || ! -x $package/bin/mealyctl \
    || ! -x $package/install.sh || ! -x $package/fetch-browser-runtime.sh ]]; then
  echo "release payload is incomplete or failed integrity verification" >&2
  exit 65
fi
if ! jq -e --arg version "$version" --arg target "$target" \
  --argjson epoch "$source_date_epoch" '
    .schemaVersion == "mealy.release.v2"
    and .version == $version
    and .target == $target
    and .sourceDateEpoch == $epoch
    and .sbom == "SBOM.cdx.json"
    and .licenses == "THIRD-PARTY-LICENSES.html"
    and (.stateSchemaVersion | type == "number" and . >= 1 and . <= 9999)
  ' "$package/BUILD-MANIFEST.json" >/dev/null; then
  echo "release manifest does not match Debian package identity" >&2
  exit 65
fi

expected_needed=$'libc.so.6\nlibgcc_s.so.1\nlibm.so.6'
case $target in
  linux-x86_64-gnu) expected_needed=$'ld-linux-x86-64.so.2\n'"$expected_needed" ;;
  linux-aarch64-gnu) expected_needed=$'ld-linux-aarch64.so.1\n'"$expected_needed" ;;
esac
for binary in mealyd mealyctl; do
  binary_path="$package/bin/$binary"
  magic=$(od -An -tx1 -N4 "$binary_path" | tr -d ' \n')
  if [[ $magic != 7f454c46 ]]; then
    continue
  fi
  if ! command -v readelf >/dev/null 2>&1; then
    echo "readelf is required to validate ELF dependency closure" >&2
    exit 69
  fi
  needed=$(readelf --wide --dynamic "$binary_path" | awk '
    $2 == "(NEEDED)" {
      sub(/^.*\[/, "")
      sub(/\].*$/, "")
      print
    }
  ' | sort)
  if [[ $needed != "$expected_needed" ]]; then
    echo "release binary $binary has an undeclared or unexpected ELF dependency set" >&2
    printf 'expected:\n%s\nactual:\n%s\n' "$expected_needed" "$needed" >&2
    exit 65
  fi
done

data_root="$temporary/data"
release_root="$data_root/usr/lib/mealy/release"
documentation="$data_root/usr/share/doc/mealy"
manuals="$data_root/usr/share/man/man1"
control_root="$temporary/control"
install -d -m 0755 "$release_root" "$data_root/usr/bin" "$documentation" "$manuals" \
  "$control_root"
cp -a "$package/." "$release_root/"
find "$release_root" -type f -exec chmod 0644 {} +
chmod 0755 "$release_root/bin/mealyd" "$release_root/bin/mealyctl" \
  "$release_root/install.sh" "$release_root/fetch-browser-runtime.sh"
ln -s ../lib/mealy/release/bin/mealyd "$data_root/usr/bin/mealyd"
ln -s ../lib/mealy/release/bin/mealyctl "$data_root/usr/bin/mealyctl"
printf '%s\n' \
  'Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/' \
  'Upstream-Name: Mealy' \
  'Source: https://github.com/Amekn/project_mealy' \
  '' \
  'Files: *' \
  'Copyright: 2026 Amekn' \
  'License: Apache-2.0' \
  ' On Debian systems, the complete text of the Apache License, Version 2.0' \
  ' can be found in /usr/share/common-licenses/Apache-2.0.' \
  >"$documentation/copyright"
chmod 0644 "$documentation/copyright"
install -m 0644 "$release_root/THIRD-PARTY-LICENSES.html" \
  "$documentation/third-party-licenses.html"
install -m 0644 "$release_root/README.md" "$documentation/README.md"
for document in "${release_documents[@]}"; do
  install -D -m 0644 "$release_root/docs/$document" "$documentation/docs/$document"
done
for document in QUICKSTART.md OPERATIONS.md RELEASE.md THREAT_MODEL.md; do
  ln -s "docs/$document" "$documentation/$document"
done

changelog_date=$(date --utc --date="@$source_date_epoch" --rfc-email)
printf '%s\n' \
  "mealy ($debian_version) unstable; urgency=medium" \
  '' \
  "  * Release Mealy $version." \
  '' \
  " -- Amekn <Amekn@users.noreply.github.com>  $changelog_date" \
  >"$documentation/changelog"
gzip --no-name --best "$documentation/changelog"
chmod 0644 "$documentation/changelog.gz"

manual_date=$(date --utc --date="@$source_date_epoch" '+%Y-%m-%d')
printf '%s\n' \
  ".TH MEALYD 1 \"$manual_date\" \"Mealy $version\" \"User Commands\"" \
  '.SH NAME' \
  'mealyd \- run the local Mealy personal-agent daemon' \
  '.SH SYNOPSIS' \
  '.B mealyd' \
  '[\fB--home\fR \fIPATH\fR] [\fB--safe-mode\fR]' \
  '.SH DESCRIPTION' \
  'Runs the single-owner, authenticated loopback daemon. The daemon owns durable sessions, tasks, policy, approvals, tools, recovery, and replay.' \
  '.SH FILES' \
  '.I ~/.mealy' \
  'is the default owner-private state directory.' \
  '.SH SECURITY' \
  'Keep the listener on loopback and require mealyctl doctor to report the needed Linux sandbox profiles enforceable.' \
  '.SH SEE ALSO' \
  '.BR mealyctl (1)' \
  >"$manuals/mealyd.1"
printf '%s\n' \
  ".TH MEALYCTL 1 \"$manual_date\" \"Mealy $version\" \"User Commands\"" \
  '.SH NAME' \
  'mealyctl \- configure and use the local Mealy agent' \
  '.SH SYNOPSIS' \
  '.B mealyctl' \
  '[\fB--home\fR \fIPATH\fR] \fICOMMAND\fR [\fIARGS\fR]' \
  '.SH DESCRIPTION' \
  'Authenticates to mealyd for setup, chat, approvals, governed tools, status, backup, recovery, service generation, and administration.' \
  '.SH COMMON COMMANDS' \
  '.BR setup , " doctor" , " chat" , " dashboard" , " status" , " backup" , " drain" , " service"' \
  '.SH FILES' \
  '.I ~/.mealy' \
  'is the default owner-private state directory.' \
  '.SH DOCUMENTATION' \
  'See /usr/share/doc/mealy/QUICKSTART.md and /usr/share/doc/mealy/OPERATIONS.md.' \
  '.SH SEE ALSO' \
  '.BR mealyd (1)' \
  >"$manuals/mealyctl.1"
gzip --no-name --best "$manuals/mealyd.1" "$manuals/mealyctl.1"
chmod 0644 "$manuals/mealyd.1.gz" "$manuals/mealyctl.1.gz"
find "$data_root" -type d -exec chmod 0755 {} +

installed_size=$(find "$data_root" -type f -printf '%D:%i %s\n' \
  | awk '!seen[$1]++ {total += $2} END {print int((total + 1023) / 1024)}')
printf '%s\n' \
  'Package: mealy' \
  "Version: $debian_version" \
  "Architecture: $debian_architecture" \
  'Maintainer: Amekn <Amekn@users.noreply.github.com>' \
  'Section: utils' \
  'Priority: optional' \
  'Depends: bubblewrap, ca-certificates, libc-bin (>= 2.39), libc6 (>= 2.39), libgcc-s1' \
  'Suggests: apparmor-profiles, apparmor-utils, curl, fonts-liberation, libasound2t64, libatk-bridge2.0-0t64, libatk1.0-0t64, libatspi2.0-0t64, libdbus-1-3, libexpat1, libgbm1, libglib2.0-0t64, libnspr4, libnss3, libudev1, libx11-6, libxcb1, libxcomposite1, libxdamage1, libxext6, libxfixes3, libxkbcommon0, libxrandr2, unzip' \
  "Installed-Size: $installed_size" \
  'Homepage: https://github.com/Amekn/project_mealy' \
  'Description: local-first durable personal agent runtime' \
  ' Mealy runs a single-owner local daemon with durable sessions, recovery,' \
  ' governed tools, approvals, memory, channels, scheduling, and replay.' \
  ' The companion client provides setup, chat, operations, and administration.' \
  >"$control_root/control"
while IFS= read -r relative; do
  (cd "$data_root" && md5sum "$relative")
done < <(find "$data_root" -type f -printf '%P\n' | sort) >"$control_root/md5sums"
chmod 0644 "$control_root/control" "$control_root/md5sums"
find "$data_root" "$control_root" -exec \
  touch --no-dereference --date="@$source_date_epoch" {} +

working="$temporary/deb"
mkdir -p "$working"
tar --sort=name --mtime="@$source_date_epoch" --clamp-mtime \
  --owner=0 --group=0 --numeric-owner --format=gnu \
  -cf "$working/control.tar" -C "$control_root" .
tar --sort=name --mtime="@$source_date_epoch" --clamp-mtime \
  --owner=0 --group=0 --numeric-owner --format=gnu \
  -cf "$working/data.tar" -C "$data_root" .
gzip --no-name --best "$working/control.tar"
gzip --no-name --best "$working/data.tar"
printf '2.0\n' >"$working/debian-binary"
touch --date="@$source_date_epoch" "$working/debian-binary" \
  "$working/control.tar.gz" "$working/data.tar.gz"
(
  cd "$working"
  ar rcsD "$deb_name" debian-binary control.tar.gz data.tar.gz
)
if [[ $(ar t "$working/$deb_name") != $'debian-binary\ncontrol.tar.gz\ndata.tar.gz' ]]; then
  echo "constructed Debian archive has an invalid member inventory" >&2
  exit 65
fi

temporary_output=$(mktemp "$output_dir/.${deb_name}.XXXXXX")
install -m 0644 "$working/$deb_name" "$temporary_output"
mv -f "$temporary_output" "$output_dir/$deb_name"
temporary_checksums=$(mktemp "$output_dir/.SHA256SUMS.XXXXXX")
(
  cd "$output_dir"
  sha256sum "$archive_name" install-mealy.sh install-mealy-release.sh "$sbom_name" \
    "$deb_name" | sort -k2
) >"$temporary_checksums"
mv -f "$temporary_checksums" "$checksums"
printf '%s/%s\n' "$output_dir" "$deb_name"
