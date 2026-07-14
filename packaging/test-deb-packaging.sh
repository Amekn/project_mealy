#!/usr/bin/env bash
set -euo pipefail
umask 077

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
for command in cmp dpkg-deb find jq md5sum readlink sha256sum sort stat tar; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Debian packaging test requires $command" >&2
    exit 69
  fi
done
temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-deb-packaging-test.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

case $(uname -m) in
  x86_64 | amd64)
    target=linux-x86_64-gnu
    debian_architecture=amd64
    ;;
  aarch64 | arm64)
    target=linux-aarch64-gnu
    debian_architecture=arm64
    ;;
  *)
    echo "unsupported Debian packaging test architecture" >&2
    exit 69
    ;;
esac
readonly version=0.1.0
readonly commit=0123456789abcdef0123456789abcdef01234567
readonly epoch=1700000000
readonly deb_name="mealy_${version}_${debian_architecture}.deb"
readonly archive_name="mealy-v${version}-${target}.tar.gz"

mkdir -p "$temporary/bin"
for binary in mealyd mealyctl; do
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    "if [[ \${1-} == --version ]]; then" \
    "  printf '$binary $version\\n'" \
    "elif [[ $binary == mealyd && \${1-} == --print-supported-schema-version ]]; then" \
    "  printf '15\\n'" \
    'else' \
    "  printf '$binary-debian-fixture\\n'" \
    'fi' \
    >"$temporary/bin/$binary"
  chmod 0755 "$temporary/bin/$binary"
done
printf '%s\n' \
  "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"serialNumber\":\"urn:uuid:00000000-0000-4000-8000-000000000000\",\"version\":1,\"metadata\":{\"timestamp\":\"2099-01-01T00:00:00Z\",\"component\":{\"name\":\"fixture\"}},\"components\":[{\"bom-ref\":\"pkg:generic/mealy@$version\",\"type\":\"application\",\"name\":\"mealy\",\"version\":\"$version\"}]}" \
  >"$temporary/sbom.raw.json"
{
  printf '<h1>Mealy third-party licenses</h1>\n<pre>\n'
  for _ in {1..64}; do
    printf 'Deterministic third-party license fixture text for packaging tests.\n'
  done
  printf '</pre>\n'
} >"$temporary/third-party-licenses.html"
"$repository_root/packaging/normalize-sbom.sh" \
  "$temporary/sbom.raw.json" "$temporary/sbom.json" "$version" "$target" "$commit" "$epoch"

for output in first second; do
  mkdir -p "$temporary/$output"
  "$repository_root/packaging/build-release.sh" "$version" "$target" \
    "$temporary/bin" "$temporary/sbom.json" "$temporary/third-party-licenses.html" \
    "$temporary/$output" "$commit" "$epoch" 15 \
    >/dev/null
  "$repository_root/packaging/build-deb.sh" "$version" "$target" \
    "$temporary/$output/$archive_name" "$temporary/$output/SHA256SUMS" \
    "$temporary/$output" "$epoch" >/dev/null
  (cd "$temporary/$output" && sha256sum --check --strict SHA256SUMS >/dev/null)
done
cmp "$temporary/first/$deb_name" "$temporary/second/$deb_name"
cmp "$temporary/first/SHA256SUMS" "$temporary/second/SHA256SUMS"

deb="$temporary/first/$deb_name"
[[ $(dpkg-deb --field "$deb" Package) == mealy ]]
[[ $(dpkg-deb --field "$deb" Version) == "$version" ]]
[[ $(dpkg-deb --field "$deb" Architecture) == "$debian_architecture" ]]
[[ $(dpkg-deb --field "$deb" Depends) == 'bubblewrap, ca-certificates, libc-bin (>= 2.39), libc6 (>= 2.39), libgcc-s1' ]]
[[ $(dpkg-deb --field "$deb" Suggests) == 'apparmor-profiles, apparmor-utils, curl, fonts-liberation, libasound2t64, libatk-bridge2.0-0t64, libatk1.0-0t64, libatspi2.0-0t64, libdbus-1-3, libexpat1, libgbm1, libglib2.0-0t64, libnspr4, libnss3, libudev1, libx11-6, libxcb1, libxcomposite1, libxdamage1, libxext6, libxfixes3, libxkbcommon0, libxrandr2, unzip' ]]
control_inventory=$(dpkg-deb --ctrl-tarfile "$deb" | tar -tf - | sort)
[[ $control_inventory == $'./\n./control\n./md5sums' ]]

mkdir -p "$temporary/extracted" "$temporary/control"
dpkg-deb --extract "$deb" "$temporary/extracted"
dpkg-deb --control "$deb" "$temporary/control"
release_root="$temporary/extracted/usr/lib/mealy/release"
cmp "$temporary/bin/mealyd" "$temporary/extracted/usr/bin/mealyd"
cmp "$temporary/bin/mealyctl" "$temporary/extracted/usr/bin/mealyctl"
cmp "$temporary/extracted/usr/bin/mealyd" "$release_root/bin/mealyd"
cmp "$temporary/extracted/usr/bin/mealyctl" "$release_root/bin/mealyctl"
(cd "$release_root" && sha256sum --check --strict PAYLOAD-SHA256SUMS >/dev/null)
(cd "$temporary/extracted" && md5sum --check --strict "$temporary/control/md5sums" >/dev/null)
[[ $(readlink "$temporary/extracted/usr/bin/mealyd") == ../lib/mealy/release/bin/mealyd ]]
[[ $(readlink "$temporary/extracted/usr/bin/mealyctl") == ../lib/mealy/release/bin/mealyctl ]]
[[ $(readlink "$temporary/extracted/usr/share/doc/mealy/QUICKSTART.md") == docs/QUICKSTART.md ]]
[[ $(readlink "$temporary/extracted/usr/share/doc/mealy/OPERATIONS.md") == docs/OPERATIONS.md ]]
[[ $(readlink "$temporary/extracted/usr/share/doc/mealy/RELEASE.md") == docs/RELEASE.md ]]
[[ $(readlink "$temporary/extracted/usr/share/doc/mealy/THREAT_MODEL.md") == docs/THREAT_MODEL.md ]]
[[ $(stat -Lc '%a' "$temporary/extracted/usr/bin/mealyd") == 755 ]]
[[ $(stat -Lc '%a' "$temporary/extracted/usr/bin/mealyctl") == 755 ]]
[[ $(stat -c '%a' "$release_root/fetch-browser-runtime.sh") == 755 ]]
[[ $(stat -c '%a' "$release_root/README.md") == 644 ]]
[[ $(stat -c '%a' "$temporary/extracted/usr/share/doc/mealy/copyright") == 644 ]]
cmp "$release_root/README.md" "$temporary/extracted/usr/share/doc/mealy/README.md"
cmp "$release_root/docs/README.md" \
  "$temporary/extracted/usr/share/doc/mealy/docs/README.md"
cmp "$release_root/docs/benchmarks/README.md" \
  "$temporary/extracted/usr/share/doc/mealy/docs/benchmarks/README.md"
cmp "$release_root/THIRD-PARTY-LICENSES.html" \
  "$temporary/extracted/usr/share/doc/mealy/third-party-licenses.html"
[[ $(stat -c '%a' "$temporary/extracted/usr/share/doc/mealy/third-party-licenses.html") == 644 ]]
[[ $(stat -c '%a' "$temporary/extracted/usr/share/doc/mealy/docs/README.md") == 644 ]]
[[ -f $temporary/extracted/usr/share/doc/mealy/changelog.gz ]]
[[ -f $temporary/extracted/usr/share/man/man1/mealyd.1.gz ]]
[[ -f $temporary/extracted/usr/share/man/man1/mealyctl.1.gz ]]
[[ $(stat -c '%a' "$temporary/extracted/usr/share/doc/mealy/changelog.gz") == 644 ]]
[[ $(stat -c '%a' "$temporary/extracted/usr/share/man/man1/mealyd.1.gz") == 644 ]]
[[ $(stat -c '%a' "$temporary/extracted/usr/share/man/man1/mealyctl.1.gz") == 644 ]]
symlinks=$(find "$temporary/extracted" -type l -printf '%P\n' | sort)
[[ $symlinks == $'usr/bin/mealyctl\nusr/bin/mealyd\nusr/share/doc/mealy/OPERATIONS.md\nusr/share/doc/mealy/QUICKSTART.md\nusr/share/doc/mealy/RELEASE.md\nusr/share/doc/mealy/THREAT_MODEL.md' ]]
if [[ -n $(find "$temporary/extracted" ! -type f ! -type d ! -type l -print -quit) ]]; then
  echo "Debian package contains an unsupported filesystem type" >&2
  exit 1
fi

cp -a "$temporary/first" "$temporary/tampered"
printf 'tamper\n' >>"$temporary/tampered/$archive_name"
checksum_before=$(sha256sum "$temporary/tampered/SHA256SUMS")
if "$repository_root/packaging/build-deb.sh" "$version" "$target" \
  "$temporary/tampered/$archive_name" "$temporary/tampered/SHA256SUMS" \
  "$temporary/tampered" "$epoch" >/dev/null 2>&1; then
  echo "Debian builder accepted a checksum-mismatched release archive" >&2
  exit 1
fi
[[ $(sha256sum "$temporary/tampered/SHA256SUMS") == "$checksum_before" ]]

echo "Debian package build: ok ($deb_name)"
