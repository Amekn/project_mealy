#!/usr/bin/env bash
set -euo pipefail
umask 077

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
for command in cmp cpio find grep jq rpm rpm2cpio sha256sum stat; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "RPM packaging test requires $command" >&2
    exit 69
  fi
done
temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-rpm-packaging-test.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

case $(uname -m) in
  x86_64|amd64)
    target=linux-x86_64-gnu
    rpm_architecture=x86_64
    ;;
  aarch64|arm64)
    target=linux-aarch64-gnu
    rpm_architecture=aarch64
    ;;
  *)
    echo "unsupported RPM packaging test architecture" >&2
    exit 69
    ;;
esac
readonly version=0.1.0
readonly commit=0123456789abcdef0123456789abcdef01234567
readonly epoch=1700000000
readonly archive_name="mealy-v${version}-${target}.tar.gz"
readonly rpm_name="mealy-${version}-1.${rpm_architecture}.rpm"

mkdir -p "$temporary/bin"
for binary in mealyd mealyctl; do
  {
    printf '%s\n' '#!/usr/bin/env bash'
    # shellcheck disable=SC2016
    printf 'if [[ ${1-} == --version ]]; then\n'
    printf '  printf "%s %s\\\\n"\n' "$binary" "$version"
    if [[ $binary == mealyd ]]; then
      # shellcheck disable=SC2016
      printf 'elif [[ ${1-} == --print-supported-schema-version ]]; then\n'
      printf '  printf "16\\\\n"\n'
    fi
    printf 'else\n  printf "%s-rpm-fixture\\\\n"\nfi\n' "$binary"
  } >"$temporary/bin/$binary"
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
    "$temporary/$output" "$commit" "$epoch" 16 >/dev/null
  "$repository_root/packaging/build-rpm.sh" "$version" "$target" \
    "$temporary/$output/$archive_name" "$temporary/$output/SHA256SUMS" \
    "$temporary/$output" "$epoch" >/dev/null
  (cd "$temporary/$output" && sha256sum --check --strict SHA256SUMS >/dev/null)
done
cmp "$temporary/first/$rpm_name" "$temporary/second/$rpm_name"
cmp "$temporary/first/SHA256SUMS" "$temporary/second/SHA256SUMS"

rpm_package="$temporary/first/$rpm_name"
[[ $(rpm -qp --queryformat '%{NAME} %{VERSION} %{RELEASE} %{ARCH}\n' "$rpm_package") \
  == "mealy $version 1 $rpm_architecture" ]]
[[ -z $(rpm -qp --scripts "$rpm_package") ]]
mapfile -t requirements < <(
  rpm -qp --requires "$rpm_package" | grep -Ev '^rpmlib\(' | sort
)
expected_requirements=$'bubblewrap\nca-certificates\nglibc >= 2.39\nlibgcc'
[[ $(printf '%s\n' "${requirements[@]}") == "$expected_requirements" ]]
rpm -K --nosignature "$rpm_package" >/dev/null
rpm_file_list=$(rpm -qlp "$rpm_package")
grep -Fqx /usr/lib/mealy <<<"$rpm_file_list"

mkdir "$temporary/extracted"
(
  cd "$temporary/extracted"
  rpm2cpio "$rpm_package" | cpio --quiet -idmu
)
release_root="$temporary/extracted/usr/lib/mealy/release"
cmp "$temporary/bin/mealyd" "$temporary/extracted/usr/bin/mealyd"
cmp "$temporary/bin/mealyctl" "$temporary/extracted/usr/bin/mealyctl"
cmp "$temporary/extracted/usr/bin/mealyd" "$release_root/bin/mealyd"
cmp "$temporary/extracted/usr/bin/mealyctl" "$release_root/bin/mealyctl"
(cd "$release_root" && sha256sum --check --strict PAYLOAD-SHA256SUMS >/dev/null)
[[ $(readlink "$temporary/extracted/usr/bin/mealyd") == ../lib/mealy/release/bin/mealyd ]]
[[ $(readlink "$temporary/extracted/usr/bin/mealyctl") == ../lib/mealy/release/bin/mealyctl ]]
[[ $(stat -Lc '%a' "$temporary/extracted/usr/bin/mealyd") == 755 ]]
[[ $(stat -c '%a' "$release_root/install-release.sh") == 755 ]]
[[ $(stat -c '%a' "$release_root/README.md") == 644 ]]
[[ -f $temporary/extracted/usr/share/doc/mealy/QUICKSTART.md ]]
[[ -f $temporary/extracted/usr/share/doc/mealy/GETTING_STARTED.md ]]
[[ -f $temporary/extracted/usr/share/doc/mealy/research/ONBOARDING_COMPLETION_AUDIT_2026-07-24.md ]]
[[ -f $temporary/extracted/usr/share/doc/mealy/research/PRODUCT_OPERATIONS_BENCHMARK_2026-07-24.md ]]
[[ -f $temporary/extracted/usr/share/doc/mealy/benchmarks/release-soak-subject.json ]]
if [[ -n $(find "$temporary/extracted" ! -type f ! -type d ! -type l -print -quit) ]]; then
  echo "RPM contains an unsupported filesystem type" >&2
  exit 1
fi

cp -a "$temporary/first" "$temporary/tampered"
printf 'tamper\n' >>"$temporary/tampered/$archive_name"
checksum_before=$(sha256sum "$temporary/tampered/SHA256SUMS")
if "$repository_root/packaging/build-rpm.sh" "$version" "$target" \
  "$temporary/tampered/$archive_name" "$temporary/tampered/SHA256SUMS" \
  "$temporary/tampered" "$epoch" >/dev/null 2>&1; then
  echo "RPM builder accepted a checksum-mismatched release archive" >&2
  exit 1
fi
[[ $(sha256sum "$temporary/tampered/SHA256SUMS") == "$checksum_before" ]]

cp -a "$temporary/first" "$temporary/malformed"
printf '%064d  invalid/path\n' 0 >>"$temporary/malformed/SHA256SUMS"
checksum_before=$(sha256sum "$temporary/malformed/SHA256SUMS")
if "$repository_root/packaging/build-rpm.sh" "$version" "$target" \
  "$temporary/malformed/$archive_name" "$temporary/malformed/SHA256SUMS" \
  "$temporary/malformed" "$epoch" >/dev/null 2>&1; then
  echo "RPM builder accepted a late malformed checksum entry" >&2
  exit 1
fi
[[ $(sha256sum "$temporary/malformed/SHA256SUMS") == "$checksum_before" ]]

echo "RPM package build: ok ($rpm_name)"
