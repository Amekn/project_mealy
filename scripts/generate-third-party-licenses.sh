#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: generate-third-party-licenses.sh CARGO_ABOUT OUTPUT" >&2
}

if [[ $# -ne 2 ]]; then
  usage
  exit 64
fi

generator=$1
output=$2
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
for command in basename chmod cmp dirname grep mktemp mv rm wc; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required license-notice command is unavailable: $command" >&2
    exit 69
  fi
done
if [[ -L $generator || ! -f $generator || ! -x $generator \
  || $("$generator" --version) != 'cargo-about 0.9.1' ]]; then
  echo "license notice requires the exact executable cargo-about 0.9.1" >&2
  exit 65
fi
if [[ -L $repository_root/about.toml || ! -f $repository_root/about.toml \
  || -L $repository_root/packaging/third-party-licenses.hbs \
  || ! -f $repository_root/packaging/third-party-licenses.hbs ]]; then
  echo "license notice configuration or template is unavailable" >&2
  exit 66
fi

output_parent=$(dirname "$output")
if [[ -L $output_parent || ! -d $output_parent ]]; then
  echo "license notice output parent must be a real directory" >&2
  exit 65
fi
output_parent=$(cd "$output_parent" && pwd -P)
output="$output_parent/$(basename "$output")"
if [[ -L $output || (-e $output && ! -f $output) ]]; then
  echo "license notice output must be a regular file path" >&2
  exit 65
fi

first=$(mktemp "$output_parent/.third-party-licenses.first.XXXXXX")
second=$(mktemp "$output_parent/.third-party-licenses.second.XXXXXX")
cleanup() {
  rm -f -- "$first" "$second"
}
trap cleanup EXIT

generate() {
  local destination=$1
  (
    cd "$repository_root"
    "$generator" about generate --frozen --locked --workspace --all-features --fail \
      --output-file "$destination" packaging/third-party-licenses.hbs
  )
}

generate "$first"
generate "$second"
if ! cmp "$first" "$second"; then
  echo "third-party license notice generation is not reproducible" >&2
  exit 65
fi
size=$(wc -c <"$first")
if [[ $size -lt 1024 || $size -gt 8388608 ]] \
  || ! grep -Fq '<h1>Mealy third-party licenses</h1>' "$first" \
  || grep -Eiq '<(script|iframe|object|embed|form|img|link)|javascript:|http-equiv|/home/|target/' \
    "$first"; then
  echo "generated third-party license notice is invalid or outside its package bound" >&2
  exit 65
fi
chmod 0644 "$first"
mv -f "$first" "$output"
printf '%s\n' "$output"
