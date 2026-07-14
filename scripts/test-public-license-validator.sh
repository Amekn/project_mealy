#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
validator=$repository_root/scripts/validate-public-license.sh

for command in cp mkdir mktemp sed; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required public-license test command is unavailable: $command" >&2
    exit 69
  }
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-public-license-test.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

make_fixture() {
  local directory=$1
  local expression=$2
  local terms=$3
  mkdir -p "$directory/apps/example" "$directory/crates/example"
  printf '[workspace]\nmembers = ["apps/example", "crates/example"]\n\n[workspace.package]\nversion = "0.1.0"\nlicense = "%s"\npublish = false\n' \
    "$expression" >"$directory/Cargo.toml"
  for manifest in "$directory/apps/example/Cargo.toml" \
    "$directory/crates/example/Cargo.toml"; do
    printf '[package]\nname = "fixture"\nversion.workspace = true\nlicense.workspace = true\npublish.workspace = true\n' \
      >"$manifest"
  done
  case $terms in
    apache)
      printf 'Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/\n' \
        >"$directory/LICENSE"
      ;;
    mit)
      printf 'MIT License\nPermission is hereby granted, free of charge, to any person obtaining a copy.\nTHE SOFTWARE IS PROVIDED "AS IS".\n' \
        >"$directory/LICENSE"
      ;;
    dual)
      printf 'MIT License\nPermission is hereby granted, free of charge, to any person obtaining a copy.\nTHE SOFTWARE IS PROVIDED "AS IS".\n\nApache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/\n' \
        >"$directory/LICENSE"
      ;;
  esac
  for _ in {1..20}; do
    printf 'These fixture terms remain subject to the complete canonical license text.\n' \
      >>"$directory/LICENSE"
  done
}

make_fixture "$temporary/apache" Apache-2.0 apache
make_fixture "$temporary/mit" MIT mit
make_fixture "$temporary/dual" 'MIT OR Apache-2.0' dual
"$validator" "$temporary/apache" >/dev/null
"$validator" "$temporary/mit" >/dev/null
"$validator" "$temporary/dual" >/dev/null

expect_rejection() {
  local name=$1
  local source=$2
  local candidate=$temporary/$name
  cp -R "$source" "$candidate"
  shift 2
  "$@" "$candidate"
  if "$validator" "$candidate" >"$temporary/$name.stdout" 2>"$temporary/$name.stderr"; then
    echo "public-license validator accepted invalid $name evidence" >&2
    exit 1
  fi
}

make_restrictive() {
  printf 'All rights reserved. No license is granted to use this software.\n' >>"$1/LICENSE"
}
use_license_file() {
  sed -i 's/^license = .*/license-file = "LICENSE"/' "$1/Cargo.toml"
}
drop_package_inheritance() {
  sed -i '/license\.workspace/d' "$1/apps/example/Cargo.toml"
}
use_unsupported_expression() {
  sed -i 's/^license = .*/license = "GPL-3.0-only"/' "$1/Cargo.toml"
}

expect_rejection restrictive "$temporary/apache" make_restrictive
expect_rejection license-file "$temporary/apache" use_license_file
expect_rejection package-without-license "$temporary/apache" drop_package_inheritance
expect_rejection unsupported-expression "$temporary/apache" use_unsupported_expression

echo "public release license validator: ok"
