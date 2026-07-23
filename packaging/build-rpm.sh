#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: build-rpm.sh VERSION TARGET ARCHIVE SHA256SUMS OUTPUT_DIR SOURCE_DATE_EPOCH" >&2
}

if [[ $# -ne 6 ]]; then
  usage
  exit 64
fi

version=$1
target=$2
archive=$3
checksums=$4
output_dir=$5
source_date_epoch=$6
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ \
  || ! $source_date_epoch =~ ^[1-9][0-9]*$ ]]; then
  echo "RPM package identity is invalid" >&2
  exit 64
fi
case $target in
  linux-x86_64-gnu)
    rpm_architecture=x86_64
    host_architecture=x86_64
    ;;
  linux-aarch64-gnu)
    rpm_architecture=aarch64
    host_architecture=aarch64
    ;;
  *)
    echo "unsupported RPM package target: $target" >&2
    exit 64
    ;;
esac
case $(uname -m) in
  amd64) detected_architecture=x86_64 ;;
  arm64) detected_architecture=aarch64 ;;
  *) detected_architecture=$(uname -m) ;;
esac
if [[ $detected_architecture != "$host_architecture" ]]; then
  echo "RPM package must be built natively for $host_architecture" >&2
  exit 65
fi
for command in awk cat cp dirname find install jq ln mkdir mktemp mv readlink rm \
  rpmbuild rpm sha256sum sort touch uname; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required RPM packaging command is unavailable: $command" >&2
    exit 69
  fi
done
mkdir -p "$output_dir"
if [[ -L $output_dir || ! -d $output_dir ]]; then
  echo "RPM package output must be a real directory" >&2
  exit 65
fi
output_dir=$(readlink -f "$output_dir")
checksums=$(readlink -f "$checksums")
if [[ $(readlink -f "$(dirname "$checksums")") != "$output_dir" ]]; then
  echo "RPM checksum manifest and output must share one directory" >&2
  exit 65
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-rpm-build.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
package=$("$repository_root/packaging/verify-release-payload.sh" \
  "$version" "$target" "$archive" "$checksums" "$temporary/payload")

topdir="$temporary/rpmbuild"
mkdir -p "$topdir/BUILD" "$topdir/BUILDROOT" "$topdir/RPMS" "$topdir/SOURCES" \
  "$topdir/SPECS" "$topdir/SRPMS"
spec="$topdir/SPECS/mealy.spec"
cat >"$spec" <<'SPEC'
Name: mealy
Version: %{mealy_version}
Release: 1
Summary: Local-first durable personal agent runtime
License: Apache-2.0
URL: https://github.com/Amekn/project_mealy
BuildArch: %{mealy_arch}
AutoReqProv: no
Requires: bubblewrap
Requires: ca-certificates
Requires: glibc >= 2.39
Requires: libgcc
Recommends: curl
Recommends: liberation-fonts
Recommends: unzip

%description
Mealy is a single-owner local agent daemon with durable sessions, recovery,
governed tools, approvals, memory, channels, scheduling, and replay.

%prep

%build

%install
install -d -m 0755 %{buildroot}/usr/lib/mealy/release
cp -a %{payload_root}/. %{buildroot}/usr/lib/mealy/release/
find %{buildroot}/usr/lib/mealy/release -type f -exec chmod 0644 {} +
chmod 0755 \
  %{buildroot}/usr/lib/mealy/release/bin/mealyd \
  %{buildroot}/usr/lib/mealy/release/bin/mealyctl \
  %{buildroot}/usr/lib/mealy/release/install.sh \
  %{buildroot}/usr/lib/mealy/release/install-release.sh \
  %{buildroot}/usr/lib/mealy/release/fetch-browser-runtime.sh
install -d -m 0755 \
  %{buildroot}/usr/bin \
  %{buildroot}/usr/share/doc/mealy \
  %{buildroot}/usr/share/licenses/mealy
ln -s ../lib/mealy/release/bin/mealyd %{buildroot}/usr/bin/mealyd
ln -s ../lib/mealy/release/bin/mealyctl %{buildroot}/usr/bin/mealyctl
cp -a %{payload_root}/docs/. %{buildroot}/usr/share/doc/mealy/
install -m 0644 %{payload_root}/README.md %{buildroot}/usr/share/doc/mealy/README.md
install -m 0644 %{payload_root}/THIRD-PARTY-LICENSES.html \
  %{buildroot}/usr/share/doc/mealy/third-party-licenses.html
install -m 0644 %{payload_root}/LICENSE %{buildroot}/usr/share/licenses/mealy/LICENSE
find %{buildroot} -exec touch --no-dereference --date="@%{source_date_epoch}" {} +

%files
%license /usr/share/licenses/mealy/LICENSE
/usr/bin/mealyd
/usr/bin/mealyctl
/usr/lib/mealy/release
%doc /usr/share/doc/mealy
SPEC

export SOURCE_DATE_EPOCH=$source_date_epoch
rpmbuild -bb "$spec" \
  --target "$rpm_architecture" \
  --define "_topdir $topdir" \
  --define "_buildhost mealy.invalid" \
  --define "_build_id_links none" \
  --define "_binary_payload w9.zstdio" \
  --define "_source_payload w9.zstdio" \
  --define "_enable_debug_packages 0" \
  --define "debug_package %{nil}" \
  --define "__os_install_post %{nil}" \
  --define "clamp_mtime_to_source_date_epoch 1" \
  --define "source_date_epoch_from_changelog 0" \
  --define "use_source_date_epoch_as_buildtime 1" \
  --define "mealy_arch $rpm_architecture" \
  --define "mealy_version $version" \
  --define "payload_root $package" \
  --define "source_date_epoch $source_date_epoch" \
  >/dev/null

mapfile -t built < <(find "$topdir/RPMS" -type f -name '*.rpm' -print)
if [[ ${#built[@]} -ne 1 ]]; then
  echo "RPM build did not produce exactly one binary package" >&2
  exit 65
fi
rpm_name="mealy-${version}-1.${rpm_architecture}.rpm"
if [[ $(rpm -qp --queryformat '%{NAME} %{VERSION} %{RELEASE} %{ARCH}\n' "${built[0]}") \
    != "mealy $version 1 $rpm_architecture" \
  || -n $(rpm -qp --scripts "${built[0]}") ]]; then
  echo "RPM identity is invalid or package contains scriptlets" >&2
  exit 65
fi
temporary_output=$(mktemp "$output_dir/.${rpm_name}.XXXXXX")
install -m 0644 "${built[0]}" "$temporary_output"
mv -f "$temporary_output" "$output_dir/$rpm_name"
temporary_checksums=$(mktemp "$output_dir/.SHA256SUMS.XXXXXX")
(
  cd "$output_dir"
  mapfile -t assets < <(find . -mindepth 1 -maxdepth 1 -type f \
    ! -name 'SHA256SUMS' ! -name '.SHA256SUMS.*' -printf '%f\n' | sort)
  sha256sum "${assets[@]}"
) >"$temporary_checksums"
mv -f "$temporary_checksums" "$checksums"
printf '%s/%s\n' "$output_dir" "$rpm_name"
