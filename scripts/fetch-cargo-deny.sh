#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 64
fi

readonly version=0.20.2
case "$(uname -m)" in
  x86_64)
    readonly target=x86_64-unknown-linux-musl
    readonly expected_sha256=9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f
    readonly expected_size=4936832
    ;;
  aarch64 | arm64)
    readonly target=aarch64-unknown-linux-musl
    readonly expected_sha256=995c82be0defc7a025cae49a2aa2644ce8245c9a3318fc4103907c6a285e8c7d
    readonly expected_size=4631618
    ;;
  *)
    echo "cargo-deny bootstrap supports only Linux x86_64 and ARM64 hosts" >&2
    exit 69
    ;;
esac

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

temporary_directory=$(mktemp -d "$output_directory/.cargo-deny.XXXXXX")
cleanup() {
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

readonly archive_name="cargo-deny-${version}-${target}.tar.gz"
readonly archive="$temporary_directory/$archive_name"
readonly member="cargo-deny-${version}-${target}/cargo-deny"
curl --fail --location --silent --show-error \
  --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --connect-timeout 20 --max-time 300 --max-redirs 5 \
  --max-filesize "$expected_size" \
  "https://github.com/EmbarkStudios/cargo-deny/releases/download/${version}/${archive_name}" \
  --output "$archive"
actual_size=$(wc -c <"$archive")
if [[ $actual_size -ne $expected_size ]]; then
  echo "cargo-deny archive size mismatch" >&2
  exit 65
fi
printf '%s  %s\n' "$expected_sha256" "$archive" | sha256sum --check --strict --status
tar -xzf "$archive" -C "$temporary_directory" "$member"
readonly extracted="$temporary_directory/$member"
if [[ ! -f $extracted || -L $extracted || ! -x $extracted ]]; then
  echo "verified cargo-deny archive did not contain the expected executable" >&2
  exit 65
fi
install -m 0755 "$extracted" "$output_directory/cargo-deny"
printf '%s/cargo-deny\n' "$output_directory"
