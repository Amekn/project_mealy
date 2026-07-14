#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: build-release-binaries.sh [--auditable]" >&2
}

if [[ $# -gt 1 || ($# -eq 1 && $1 != --auditable) ]]; then
  usage
  exit 64
fi
if [[ -n ${RUSTFLAGS-} || -n ${CARGO_ENCODED_RUSTFLAGS-} ]]; then
  echo "release build requires an unmodified Rust flag environment" >&2
  exit 64
fi
for command in cargo grep mkdir; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "release build requires $command" >&2
    exit 69
  fi
done

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
home_root=$(cd "${HOME:?HOME must identify the build account}" && pwd -P)
mkdir -p "${CARGO_HOME:-$HOME/.cargo}" "${CARGO_TARGET_DIR:-$repository_root/target}"
cargo_home=$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)
target_root=$(cd "${CARGO_TARGET_DIR:-$repository_root/target}" && pwd -P)
export CARGO_TARGET_DIR=$target_root

# rustc applies the last matching remap. Sort absolute prefixes shortest-first so the most specific
# mapping wins even when a custom Cargo home lives inside the repository or another mapped root.
remap_from=("$home_root" "$cargo_home" "$repository_root")
remap_to=(/mealy/build-home /mealy/cargo-home /mealy/source)
for ((left = 0; left < ${#remap_from[@]}; left++)); do
  for ((right = left + 1; right < ${#remap_from[@]}; right++)); do
    if (( ${#remap_from[left]} > ${#remap_from[right]} )); then
      value=${remap_from[left]}
      remap_from[left]=${remap_from[right]}
      remap_from[right]=$value
      value=${remap_to[left]}
      remap_to[left]=${remap_to[right]}
      remap_to[right]=$value
    fi
  done
done
remaps=()
for ((index = 0; index < ${#remap_from[@]}; index++)); do
  remaps+=("--remap-path-prefix=${remap_from[index]}=${remap_to[index]}")
done
remaps+=("--remap-path-prefix=./=/mealy/source/")
printf -v encoded_rustflags '%s\x1f' "${remaps[@]}"
export CARGO_ENCODED_RUSTFLAGS=${encoded_rustflags%$'\x1f'}

cd "$repository_root"
if [[ ${1-} == --auditable ]]; then
  cargo auditable build --locked --release \
    --package mealyd --bin mealyd \
    --package mealyctl --bin mealyctl
else
  cargo build --locked --release \
    --package mealyd --bin mealyd \
    --package mealyctl --bin mealyctl
fi

for binary in mealyd mealyctl; do
  path="$target_root/release/$binary"
  if [[ ! -f $path || ! -x $path ]]; then
    echo "release build did not produce executable $binary" >&2
    exit 66
  fi
  for forbidden in "$home_root" "$cargo_home" "$repository_root"; do
    if [[ -n $forbidden ]] && grep -aFq "$forbidden" "$path"; then
      echo "release binary $binary retains a host-specific build path" >&2
      exit 65
    fi
  done
done
