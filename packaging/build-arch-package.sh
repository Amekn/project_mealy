#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: build-arch-package.sh VERSION TARGET ARCHIVE SHA256SUMS OUTPUT_DIR SOURCE_DATE_EPOCH" >&2
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
  || ! $source_date_epoch =~ ^[1-9][0-9]*$ \
  || $target != linux-x86_64-gnu ]]; then
  echo "Arch package identity must be a stable x86-64 Linux release" >&2
  exit 64
fi
if [[ $EUID -eq 0 ]]; then
  echo "makepkg refuses root; build the Arch package as an unprivileged account" >&2
  exit 77
fi
if [[ $(uname -m) != x86_64 ]]; then
  echo "the official Arch package must be built natively on x86-64" >&2
  exit 65
fi
for command in awk bsdtar cat chmod cp dirname find flock grep install jq ln \
  makepkg mkdir mktemp mv readlink rm sha256sum sort stat touch uname; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required Arch packaging command is unavailable: $command" >&2
    exit 69
  fi
done
mkdir -p "$output_dir"
if [[ -L $output_dir || ! -d $output_dir ]]; then
  echo "Arch package output must be a real directory" >&2
  exit 65
fi
output_dir=$(readlink -f "$output_dir")
checksums=$(readlink -f "$checksums")
if [[ $(readlink -f "$(dirname "$checksums")") != "$output_dir" ]]; then
  echo "Arch checksum manifest and output must share one directory" >&2
  exit 65
fi

stable_root=${MEALY_ARCH_BUILD_ROOT:-/tmp/mealy-arch-package-build}
if [[ -L $stable_root ]]; then
  echo "canonical Arch build root must not be a symlink" >&2
  exit 65
fi
if [[ -e $stable_root ]]; then
  if [[ ! -d $stable_root || $(stat -c '%u:%a' "$stable_root") != "$EUID:700" ]]; then
    echo "canonical Arch build root must be a private directory owned by the builder" >&2
    exit 65
  fi
else
  mkdir -m 0700 "$stable_root"
fi
exec 9>"$stable_root/build.lock"
flock 9
rm -rf -- "$stable_root/work"
mkdir -m 0700 "$stable_root/work"

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-arch-payload.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
  rm -rf -- "$stable_root/work"
}
trap cleanup EXIT
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
package=$("$repository_root/packaging/verify-release-payload.sh" \
  "$version" "$target" "$archive" "$checksums" "$temporary/payload")
build="$stable_root/work"
cat >"$build/PKGBUILD" <<'PKGBUILD'
pkgname=mealy
pkgver="${MEALY_PACKAGE_VERSION:?}"
pkgrel=1
pkgdesc='Local-first durable personal agent runtime'
arch=('x86_64')
url='https://github.com/Amekn/project_mealy'
license=('Apache-2.0')
depends=('bubblewrap' 'ca-certificates' 'gcc-libs' 'glibc>=2.39')
optdepends=(
  'curl: install the optional pinned browser runtime'
  'ttf-liberation: deterministic basic fonts for the optional browser'
  'unzip: install the optional pinned browser runtime'
)
options=('!debug' '!lto' '!strip')

package() {
  install -d -m 0755 "$pkgdir/usr/lib/mealy/release"
  cp -a "${MEALY_PAYLOAD_ROOT:?}/." "$pkgdir/usr/lib/mealy/release/"
  find "$pkgdir/usr/lib/mealy/release" -type f -exec chmod 0644 {} +
  chmod 0755 \
    "$pkgdir/usr/lib/mealy/release/bin/mealyd" \
    "$pkgdir/usr/lib/mealy/release/bin/mealyctl" \
    "$pkgdir/usr/lib/mealy/release/install.sh" \
    "$pkgdir/usr/lib/mealy/release/fetch-browser-runtime.sh"
  install -d -m 0755 "$pkgdir/usr/bin" "$pkgdir/usr/share/doc/mealy"
  ln -s ../lib/mealy/release/bin/mealyd "$pkgdir/usr/bin/mealyd"
  ln -s ../lib/mealy/release/bin/mealyctl "$pkgdir/usr/bin/mealyctl"
  cp -a "$MEALY_PAYLOAD_ROOT/docs/." "$pkgdir/usr/share/doc/mealy/"
  install -m 0644 "$MEALY_PAYLOAD_ROOT/README.md" \
    "$pkgdir/usr/share/doc/mealy/README.md"
  install -m 0644 "$MEALY_PAYLOAD_ROOT/THIRD-PARTY-LICENSES.html" \
    "$pkgdir/usr/share/doc/mealy/third-party-licenses.html"
  find "$pkgdir" -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH:?}" {} +
}
PKGBUILD

export MEALY_PACKAGE_VERSION=$version
export MEALY_PAYLOAD_ROOT=$package
export SOURCE_DATE_EPOCH=$source_date_epoch
export PACKAGER='Amekn <Amekn@users.noreply.github.com>'
export PKGDEST="$temporary/packages"
mkdir -m 0700 "$PKGDEST"
(
  cd "$build"
  makepkg --cleanbuild --force --nodeps --noconfirm
) >/dev/null

mapfile -t built < <(find "$PKGDEST" -type f -name '*.pkg.tar.zst' -print)
arch_name="mealy-${version}-1-x86_64.pkg.tar.zst"
if [[ ${#built[@]} -ne 1 || ${built[0]##*/} != "$arch_name" \
  || $(bsdtar -xOf "${built[0]}" .PKGINFO | awk -F ' = ' '$1 == "pkgname" {print $2}') \
    != mealy ]]; then
  echo "Arch build did not produce one passive package with the expected identity" >&2
  exit 65
fi
if bsdtar -tf "${built[0]}" | grep -Eq '(^|/)\.INSTALL$'; then
  echo "Arch build produced a package with an install hook" >&2
  exit 65
fi
temporary_output=$(mktemp "$output_dir/.${arch_name}.XXXXXX")
install -m 0644 "${built[0]}" "$temporary_output"
mv -f "$temporary_output" "$output_dir/$arch_name"
temporary_checksums=$(mktemp "$output_dir/.SHA256SUMS.XXXXXX")
(
  cd "$output_dir"
  mapfile -t assets < <(find . -mindepth 1 -maxdepth 1 -type f \
    ! -name 'SHA256SUMS' ! -name '.SHA256SUMS.*' -printf '%f\n' | sort)
  sha256sum "${assets[@]}"
) >"$temporary_checksums"
mv -f "$temporary_checksums" "$checksums"
printf '%s/%s\n' "$output_dir" "$arch_name"
