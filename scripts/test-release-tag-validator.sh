#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
validator="$repository_root/scripts/validate-release-tag.sh"

for fixture in 'v0.1.0 0.1.0' 'v1.0.0 1.0.0' 'v10.203.4096 10.203.4096'; do
  read -r tag version <<<"$fixture"
  "$validator" "$tag" "$version"
done

invalid_fixtures=(
  '0.1.0 0.1.0'
  'v0.1 0.1'
  'v0.1.0.0 0.1.0.0'
  'v00.1.0 00.1.0'
  'v0.01.0 0.01.0'
  'v0.1.00 0.1.00'
  'v0.1.0-rc.1 0.1.0-rc.1'
  'v0.1.0+build.1 0.1.0+build.1'
  'v0.1.0 0.1.1'
  'v1.0.0 01.0.0'
  'v1.0.0 latest'
)
for fixture in "${invalid_fixtures[@]}"; do
  read -r tag version <<<"$fixture"
  if "$validator" "$tag" "$version" >/dev/null 2>&1; then
    echo "release tag validator accepted an invalid fixture: $fixture" >&2
    exit 1
  fi
done

if "$validator" >/dev/null 2>&1 || "$validator" v0.1.0 >/dev/null 2>&1 \
  || "$validator" v0.1.0 0.1.0 unexpected >/dev/null 2>&1; then
  echo "release tag validator accepted an invalid argument count" >&2
  exit 1
fi

echo "release tag validator: ok"
