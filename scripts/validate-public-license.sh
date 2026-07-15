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
if (( license_bytes < 1 || license_bytes > 65536 )); then
  echo "project license is empty or exceeds its 64 KiB bound" >&2
  exit 65
fi
if grep -Eiq 'all rights reserved|no license is granted to (use|copy|modify|merge|publish|distribute)' \
  "$license_file"; then
  echo "project license still contains no-use or all-rights-reserved terms" >&2
  exit 65
fi
if (( license_bytes < 512 )); then
  echo "project license is truncated or does not contain complete terms" >&2
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
mapfile -t license_files < <(awk '
  $0 == "[workspace.package]" { in_package = 1; next }
  in_package && /^\[/ { exit }
  in_package && /^[[:space:]]*license-file[[:space:]]*=[[:space:]]*"[^"]+"[[:space:]]*$/ {
    value = $0
    sub(/^[^"]*"/, "", value)
    sub(/"[[:space:]]*$/, "", value)
    print value
  }
' "$workspace_manifest")
mapfile -t declarations < <(awk '
  $0 == "[workspace.package]" { in_package = 1; next }
  in_package && /^\[/ { exit }
  in_package && /^[[:space:]]*license(-file)?[[:space:]]*=/ { print }
' "$workspace_manifest")
if [[ ${#declarations[@]} -ne 1 ]]; then
  echo "workspace.package must contain exactly one license declaration" >&2
  exit 65
elif [[ ${#expressions[@]} -eq 1 && ${#license_files[@]} -eq 0 ]]; then
  declaration=spdx
  expression=${expressions[0]}
elif [[ ${#expressions[@]} -eq 0 && ${#license_files[@]} -eq 1 \
  && ${license_files[0]} == LICENSE ]]; then
  declaration=license-file
  expression=
else
  echo "workspace.package must declare one reviewed SPDX expression or license-file = \"LICENSE\"" >&2
  exit 65
fi

apache=false
mit=false
if grep -Fq 'Apache License' "$license_file" \
  && grep -Fq 'Version 2.0, January 2004' "$license_file" \
  && grep -Fq 'http://www.apache.org/licenses/' "$license_file"; then
  apache=true
fi
if grep -Fq 'Permission is hereby granted, free of charge' "$license_file" \
  && grep -Fq 'THE SOFTWARE IS PROVIDED "AS IS"' "$license_file"; then
  mit=true
fi
if [[ $apache == true && $mit == true ]]; then
  detected_expression='MIT OR Apache-2.0'
elif [[ $apache == true ]]; then
  detected_expression=Apache-2.0
elif [[ $mit == true ]]; then
  detected_expression=MIT
else
  echo "LICENSE does not contain complete recognized Apache-2.0 or MIT markers" >&2
  exit 65
fi
if [[ $declaration == spdx ]]; then
  case $expression in
    Apache-2.0|MIT|'MIT OR Apache-2.0') ;;
    *)
      echo "unsupported public release license expression: $expression" >&2
      exit 65
      ;;
  esac
  if [[ $expression != "$detected_expression" ]]; then
    echo "workspace SPDX expression does not match the reviewed LICENSE text" >&2
    exit 65
  fi
else
  expression=$detected_expression
fi

mapfile -t package_manifests < <(
  find "$root/apps" "$root/crates" -type f -name Cargo.toml -print 2>/dev/null | sort
)
if [[ ${#package_manifests[@]} -lt 1 ]]; then
  echo "public license validation found no workspace package manifests" >&2
  exit 65
fi
for manifest in "${package_manifests[@]}"; do
  valid_inheritance=false
  if [[ $declaration == spdx ]] \
    && grep -Eq '^[[:space:]]*license\.workspace[[:space:]]*=[[:space:]]*true[[:space:]]*$' \
      "$manifest" \
    && ! grep -Eq '^[[:space:]]*license-file(\.workspace)?[[:space:]]*=' "$manifest"; then
    valid_inheritance=true
  elif [[ $declaration == license-file ]] \
    && grep -Eq '^[[:space:]]*license-file\.workspace[[:space:]]*=[[:space:]]*true[[:space:]]*$' \
      "$manifest" \
    && ! grep -Eq '^[[:space:]]*license(\.workspace)?[[:space:]]*=' "$manifest"; then
    valid_inheritance=true
  fi
  if [[ -L $manifest || $valid_inheritance != true ]]; then
    echo "workspace package does not inherit the reviewed public license: $manifest" >&2
    exit 65
  fi
done

printf 'public release license: ok (%s via %s, %s packages)\n' \
  "$expression" "$declaration" "${#package_manifests[@]}"
