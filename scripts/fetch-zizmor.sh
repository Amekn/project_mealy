#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 64
fi

readonly version=1.28.0
readonly target=x86_64-unknown-linux-gnu
readonly expected_sha256=e87b67160194884e375a46a12c57ccc904f762b53845f254fab7f17d98809c09
readonly expected_size=8883925

if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo "zizmor bootstrap supports only Linux x86_64 hosts" >&2
  exit 69
fi
for command in curl install mktemp sha256sum tar uname wc; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "missing required command: $command" >&2
    exit 69
  fi
done

readonly output_directory=$1
if [[ -L $output_directory ]]; then
  echo "output directory must not be a symbolic link" >&2
  exit 73
fi
mkdir -p -- "$output_directory"
if [[ ! -d $output_directory ]]; then
  echo "output path is not a directory" >&2
  exit 73
fi

temporary_directory=$(mktemp -d "$output_directory/.zizmor.XXXXXX")
cleanup() {
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

readonly archive_name="zizmor-${target}.tar.gz"
readonly archive="$temporary_directory/$archive_name"
curl --fail --location --silent --show-error \
  --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --connect-timeout 20 --max-time 300 --max-redirs 5 \
  --max-filesize "$expected_size" \
  "https://github.com/zizmorcore/zizmor/releases/download/v${version}/${archive_name}" \
  --output "$archive"
actual_size=$(wc -c <"$archive")
if [[ $actual_size -ne $expected_size ]]; then
  echo "zizmor archive size mismatch" >&2
  exit 65
fi
printf '%s  %s\n' "$expected_sha256" "$archive" | sha256sum --check --strict --status
if [[ $(tar -tzf "$archive") != zizmor ]]; then
  echo "zizmor archive inventory is not exact" >&2
  exit 65
fi
mkdir "$temporary_directory/extract"
tar --extract --gzip --file "$archive" --directory "$temporary_directory/extract" \
  --no-same-owner --no-same-permissions -- zizmor
readonly extracted="$temporary_directory/extract/zizmor"
if [[ ! -f $extracted || -L $extracted || ! -x $extracted ]]; then
  echo "verified zizmor archive did not contain the expected executable" >&2
  exit 65
fi
install -m 0755 "$extracted" "$output_directory/zizmor"
printf '%s/zizmor\n' "$output_directory"
