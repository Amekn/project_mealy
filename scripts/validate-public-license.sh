#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: validate-public-license.sh REPOSITORY_ROOT" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 64
fi

for command in awk find grep mapfile readlink sort stat; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required public-license validation command is unavailable: $command" >&2
    exit 69
  }
done

root=$1
if [[ -L $root || ! -d $root ]]; then
  usage
  exit 64
fi
root=$(readlink -f -- "$root")
workspace_manifest=$root/Cargo.toml
license_file=$root/LICENSE
if [[ -L $workspace_manifest || ! -f $workspace_manifest \
  || -L $license_file || ! -f $license_file ]]; then
  echo "public release requires real Cargo.toml and LICENSE files" >&2
  exit 65
fi
license_bytes=$(stat -c '%s' "$license_file")
if (( license_bytes < 512 || license_bytes > 65536 )); then
  echo "project license is empty, truncated, or exceeds its 64 KiB bound" >&2
  exit 65
fi

mapfile -t expressions < <(awk '
  $0 == "[workspace.package]" { in_package = 1; next }
  in_package && /^\[/ { exit }
  in_package && /^[[:space:]]*license[[:space:]]*=[[:space:]]*"[^"]+"[[:space:]]*$/ {
    value = $0
    sub(/^[^"]*"/, "", value)
    sub(/"[[:space:]]*$/, "", value)
    print value
  }
' "$workspace_manifest")
if [[ ${#expressions[@]} -ne 1 ]]; then
  echo "workspace.package must declare exactly one public SPDX license expression" >&2
  exit 65
fi
expression=${expressions[0]}
if awk '
  $0 == "[workspace.package]" { in_package = 1; next }
  in_package && /^\[/ { exit }
  in_package && /^[[:space:]]*license-file[[:space:]]*=/ { found = 1 }
  END { exit found ? 0 : 1 }
' "$workspace_manifest"; then
  echo "public release must use the reviewed SPDX expression, not license-file metadata" >&2
  exit 65
fi

if grep -Eiq 'all rights reserved|no license is granted to (use|copy|modify|merge|publish|distribute)' \
  "$license_file"; then
  echo "project license still contains no-use or all-rights-reserved terms" >&2
  exit 65
fi

apache=false
mit=false
case $expression in
  Apache-2.0) apache=true ;;
  MIT) mit=true ;;
  'MIT OR Apache-2.0') apache=true; mit=true ;;
  *)
    echo "unsupported public release license expression: $expression" >&2
    exit 65
    ;;
esac
if [[ $apache == true ]] \
  && { ! grep -Fq 'Apache License' "$license_file" \
    || ! grep -Fq 'Version 2.0, January 2004' "$license_file" \
    || ! grep -Fq 'http://www.apache.org/licenses/' "$license_file"; }; then
  echo "LICENSE does not contain the declared Apache-2.0 terms" >&2
  exit 65
fi
if [[ $mit == true ]] \
  && { ! grep -Fq 'Permission is hereby granted, free of charge' "$license_file" \
    || ! grep -Fq 'THE SOFTWARE IS PROVIDED "AS IS"' "$license_file"; }; then
  echo "LICENSE does not contain the declared MIT terms" >&2
  exit 65
fi

mapfile -t package_manifests < <(
  find "$root/apps" "$root/crates" -type f -name Cargo.toml -print 2>/dev/null | sort
)
if [[ ${#package_manifests[@]} -lt 1 ]]; then
  echo "public license validation found no workspace package manifests" >&2
  exit 65
fi
for manifest in "${package_manifests[@]}"; do
  if [[ -L $manifest ]] \
    || ! grep -Eq '^[[:space:]]*license\.workspace[[:space:]]*=[[:space:]]*true[[:space:]]*$' \
      "$manifest" \
    || grep -Eq '^[[:space:]]*license-file(\.workspace)?[[:space:]]*=' "$manifest"; then
    echo "workspace package does not inherit the reviewed public license: $manifest" >&2
    exit 65
  fi
done

printf 'public release license: ok (%s, %s packages)\n' \
  "$expression" "${#package_manifests[@]}"
