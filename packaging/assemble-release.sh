#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: assemble-release.sh VERSION INPUT_DIR OUTPUT_DIR" >&2
}

if [[ $# -ne 3 ]]; then
  usage
  exit 64
fi

version=$1
input_dir=$2
output_dir=$3
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "release version is invalid" >&2
  exit 64
fi
debian_version=${version/-/~}
if [[ -L $input_dir || ! -d $input_dir ]]; then
  echo "release input is not a real directory" >&2
  exit 66
fi
if [[ -e $output_dir && (-L $output_dir || ! -d $output_dir) ]]; then
  echo "release output is not a real directory" >&2
  exit 65
fi

for command in find sort install sha256sum awk readlink mkdir; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required release-assembly command is unavailable: $command" >&2
    exit 69
  }
done

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
input_dir=$(readlink -f "$input_dir")
mkdir -p "$output_dir"
output_dir=$(readlink -f "$output_dir")
if [[ $input_dir == "$output_dir" ]]; then
  echo "release input and output directories must differ" >&2
  exit 65
fi
if [[ -n $(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
  echo "release output directory is not empty" >&2
  exit 65
fi

linux_targets=(linux-x86_64-gnu linux-aarch64-gnu)
expected_assets=()
for target in "${linux_targets[@]}"; do
  case $target in
    linux-x86_64-gnu)
      deb="mealy_${debian_version}_amd64.deb"
      rpm="mealy-${version}-1.x86_64.rpm"
      arch="mealy-${version}-1-x86_64.pkg.tar.zst"
      ;;
    linux-aarch64-gnu)
      deb="mealy_${debian_version}_arm64.deb"
      rpm="mealy-${version}-1.aarch64.rpm"
      arch=
      ;;
  esac
  expected_assets+=(
    "ATTESTATION-${target}.sigstore.json"
    "mealy-v${version}-${target}.tar.gz"
    "mealy-v${version}-${target}.cdx.json"
    "$deb"
    "$rpm"
    "SHA256SUMS-${target}"
  )
  if [[ -n $arch ]]; then
    expected_assets+=("$arch")
  fi
done
actual=$(find "$input_dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
expected=$(printf '%s\n' "${expected_assets[@]}" | sort)
if [[ $actual != "$expected" ]]; then
  echo "architecture-specific release inventory is incomplete or contains unexpected entries" >&2
  exit 65
fi

for asset in "${expected_assets[@]}"; do
  if [[ -L $input_dir/$asset || ! -f $input_dir/$asset ]]; then
    echo "release asset is not a real file: $asset" >&2
    exit 65
  fi
  install -m 0644 "$input_dir/$asset" "$output_dir/$asset"
done
install -m 0755 "$repository_root/packaging/install.sh" "$output_dir/install-mealy.sh"
install -m 0755 "$repository_root/packaging/install-release.sh" \
  "$output_dir/install-mealy-release.sh"

for target in "${linux_targets[@]}"; do
  checksum="SHA256SUMS-${target}"
  archive="mealy-v${version}-${target}.tar.gz"
  sbom="mealy-v${version}-${target}.cdx.json"
  case $target in
    linux-x86_64-gnu)
      deb="mealy_${debian_version}_amd64.deb"
      rpm="mealy-${version}-1.x86_64.rpm"
      arch="mealy-${version}-1-x86_64.pkg.tar.zst"
      expected_count=7
      ;;
    linux-aarch64-gnu)
      deb="mealy_${debian_version}_arm64.deb"
      rpm="mealy-${version}-1.aarch64.rpm"
      arch=
      expected_count=6
      ;;
  esac
  if ! awk -v expected="$expected_count" '
      NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-f]+$/ {exit 1}
      END {if (NR != expected) exit 1}
    ' "$output_dir/$checksum"; then
    echo "target checksum manifest is not canonical: $checksum" >&2
    exit 65
  fi
  checksum_paths=$(awk '{print $2}' "$output_dir/$checksum" | sort)
  expected_paths=$(printf '%s\n' "$archive" install-mealy.sh install-mealy-release.sh \
    "$sbom" "$deb" "$rpm" ${arch:+"$arch"} | sort)
  if [[ $checksum_paths != "$expected_paths" ]]; then
    echo "target checksum manifest inventory is not exact: $checksum" >&2
    exit 65
  fi
  if ! (cd "$output_dir" && sha256sum --check --strict "$checksum" >/dev/null); then
    echo "target checksum verification failed: $checksum" >&2
    exit 65
  fi
done

echo "$output_dir"
