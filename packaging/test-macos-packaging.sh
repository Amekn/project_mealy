#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
for command in cmp python3 sha256sum tar; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required macOS packaging-test command is unavailable: $command" >&2
    exit 69
  }
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-macos-package-test.XXXXXX")
cleanup() {
  rm -rf "$temporary"
}
trap cleanup EXIT
mkdir -p "$temporary/bin" "$temporary/first" "$temporary/second"

make_binary() {
  local name=$1
  cat >"$temporary/bin/$name" <<SCRIPT
#!/usr/bin/env bash
case \${1-} in
  --version) printf '%s\\n' '$name 0.1.0' ;;
  --print-supported-schema-version) printf '%s\\n' '16' ;;
  *) exit 64 ;;
esac
SCRIPT
  chmod 0755 "$temporary/bin/$name"
}
make_binary mealyd
make_binary mealyctl

cat >"$temporary/raw-sbom.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"file","bom-ref":"file:mealyctl","name":"/private/build/bin/mealyctl"},{"type":"file","bom-ref":"file:mealyd","name":"/private/build/bin/mealyd"}],"dependencies":[]}
JSON
{
  printf '<h1>Mealy third-party licenses</h1>\n<pre>\n'
  for _ in {1..64}; do
    printf 'Deterministic third-party license fixture text for packaging tests.\n'
  done
  printf '</pre>\n'
} >"$temporary/third-party-licenses.html"

for output in first second; do
  python3 "$repository_root/packaging/build-macos-preview.py" \
    0.1.0 macos-arm64-preview "$temporary/bin" "$temporary/raw-sbom.json" \
    "$temporary/third-party-licenses.html" "$temporary/$output" \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1735689600 16 >/dev/null
done

archive=mealy-v0.1.0-macos-arm64-preview.tar.gz
sbom=mealy-v0.1.0-macos-arm64-preview.cdx.json
checksums=SHA256SUMS-macos-arm64-preview
for asset in "$archive" "$sbom" "$checksums"; do
  cmp "$temporary/first/$asset" "$temporary/second/$asset"
done
(cd "$temporary/first" && sha256sum --check --strict "$checksums" >/dev/null)

expected=$(printf '%s\n' \
  mealy-v0.1.0-macos-arm64-preview \
  mealy-v0.1.0-macos-arm64-preview/ARCHITECTURE.md \
  mealy-v0.1.0-macos-arm64-preview/BUILD-MANIFEST.json \
  mealy-v0.1.0-macos-arm64-preview/LICENSE \
  mealy-v0.1.0-macos-arm64-preview/PAYLOAD-SHA256SUMS \
  mealy-v0.1.0-macos-arm64-preview/README.md \
  mealy-v0.1.0-macos-arm64-preview/REQUIREMENTS.md \
  mealy-v0.1.0-macos-arm64-preview/SBOM.cdx.json \
  mealy-v0.1.0-macos-arm64-preview/SECURITY.md \
  mealy-v0.1.0-macos-arm64-preview/THIRD-PARTY-LICENSES.html \
  mealy-v0.1.0-macos-arm64-preview/bin \
  mealy-v0.1.0-macos-arm64-preview/bin/mealyctl \
  mealy-v0.1.0-macos-arm64-preview/bin/mealyd \
  mealy-v0.1.0-macos-arm64-preview/docs \
  mealy-v0.1.0-macos-arm64-preview/docs/API.md \
  mealy-v0.1.0-macos-arm64-preview/docs/CI_CD.md \
  mealy-v0.1.0-macos-arm64-preview/docs/CLI.md \
  mealy-v0.1.0-macos-arm64-preview/docs/OPERATIONS.md \
  mealy-v0.1.0-macos-arm64-preview/docs/PRODUCTION_READINESS.md \
  mealy-v0.1.0-macos-arm64-preview/docs/QUICKSTART.md \
  mealy-v0.1.0-macos-arm64-preview/docs/RELEASE.md | sort)
actual=$(tar -tzf "$temporary/first/$archive" | sed 's#/$##' | sort)
if [[ $actual != "$expected" ]]; then
  echo "macOS preview archive inventory is not exact" >&2
  exit 1
fi
mkdir "$temporary/extracted"
tar -xzf "$temporary/first/$archive" -C "$temporary/extracted"
package="$temporary/extracted/mealy-v0.1.0-macos-arm64-preview"
(cd "$package" && sha256sum --check --strict PAYLOAD-SHA256SUMS >/dev/null)
[[ $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["capabilityBoundary"])' \
  "$package/BUILD-MANIFEST.json") == conversation-only-control-plane-preview ]]

cp "$temporary/raw-sbom.json" "$temporary/path-leaking-sbom.json"
sed -i 's#"dependencies":\[\]#"metadata":{"tools":[{"name":"/home/release/private/build"}]},"dependencies":[]#' \
  "$temporary/path-leaking-sbom.json"
if python3 "$repository_root/packaging/build-macos-preview.py" \
  0.1.0 macos-arm64-preview "$temporary/bin" "$temporary/path-leaking-sbom.json" \
  "$temporary/third-party-licenses.html" "$temporary/rejected" \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1735689600 16 >/dev/null 2>&1; then
  echo "macOS preview builder accepted a local-path SBOM" >&2
  exit 1
fi

echo "macOS preview packaging: ok"
