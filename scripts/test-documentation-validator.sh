#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: test-documentation-validator.sh MEALYCTL" >&2
  exit 64
fi

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cli=$1
if [[ -L $cli || ! -f $cli || ! -x $cli ]]; then
  echo "documentation-validator test CLI is not a real executable" >&2
  exit 66
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-documentation-validator.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

mkdir "$temporary/package"
git -C "$repository" archive --format=tar HEAD | tar -xf - -C "$temporary/package"
test ! -e "$temporary/package/.git"
rm "$temporary/package/crates/mealy-api/src/lib.rs"

"$repository/scripts/validate-documentation.py" \
  --mode package --repository "$temporary/package" --cli "$cli"

cp "$temporary/package/docs/GETTING_STARTED.md" "$temporary/GETTING_STARTED.md"
for _ in {1..161}; do
  printf 'deliberate first-run guide overflow\n' \
    >>"$temporary/package/docs/GETTING_STARTED.md"
done
set +e
guide_output=$("$repository/scripts/validate-documentation.py" \
  --mode package --repository "$temporary/package" --cli "$cli" 2>&1)
guide_status=$?
set -e
if [[ $guide_status -ne 65 ]] \
  || ! grep -Fq 'docs/GETTING_STARTED.md exceeds the 160-line first-run bound' \
    <<<"$guide_output"; then
  echo "package documentation validator accepted an overlong first-run guide" >&2
  exit 1
fi
mv "$temporary/GETTING_STARTED.md" "$temporary/package/docs/GETTING_STARTED.md"

ln -s README.md "$temporary/package/symlink.md"
set +e
symlink_output=$("$repository/scripts/validate-documentation.py" \
  --mode package --repository "$temporary/package" --cli "$cli" 2>&1)
symlink_status=$?
set -e
if [[ $symlink_status -ne 65 ]] \
  || ! grep -Fq 'packaged Markdown is not a regular file: symlink.md' <<<"$symlink_output"; then
  echo "package documentation validator accepted a Markdown symlink" >&2
  exit 1
fi
rm "$temporary/package/symlink.md"

cp "$temporary/package/docs/API.md" "$temporary/API.md"
printf '\n| \x60GET\x60 | \x60/health/live\x60 | - | duplicate fixture |\n' \
  >>"$temporary/package/docs/API.md"
set +e
endpoint_output=$("$repository/scripts/validate-documentation.py" \
  --mode package --repository "$temporary/package" --cli "$cli" 2>&1)
endpoint_status=$?
set -e
if [[ $endpoint_status -ne 65 ]] \
  || ! grep -Fq 'API.md duplicates endpoint rows: GET /health/live' \
    <<<"$endpoint_output"; then
  echo "package documentation validator accepted a duplicate API table row" >&2
  exit 1
fi
mv "$temporary/API.md" "$temporary/package/docs/API.md"

printf '\n[missing package document](docs/absent.md)\n' \
  >>"$temporary/package/README.md"
set +e
link_output=$("$repository/scripts/validate-documentation.py" \
  --mode package --repository "$temporary/package" --cli "$cli" 2>&1)
link_status=$?
set -e
if [[ $link_status -ne 65 ]] \
  || ! grep -Fq 'README.md: missing local target docs/absent.md' <<<"$link_output"; then
  echo "package documentation validator accepted a broken local link" >&2
  exit 1
fi

echo "documentation validator package-mode tests: ok"
