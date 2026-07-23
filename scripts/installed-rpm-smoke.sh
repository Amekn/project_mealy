#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 1 || -L $1 || ! -f $1 ]]; then
  echo "usage: installed-rpm-smoke.sh PACKAGE.rpm" >&2
  exit 64
fi
for command in find jq mktemp readlink rpm sha256sum stat; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "installed RPM smoke requires $command" >&2
    exit 69
  fi
done
package=$(readlink -f "$1")
case $(uname -m) in
  x86_64|amd64) expected_architecture=x86_64 ;;
  aarch64|arm64) expected_architecture=aarch64 ;;
  *)
    echo "unsupported RPM smoke architecture" >&2
    exit 69
    ;;
esac
if [[ $(rpm -qp --queryformat '%{NAME} %{ARCH}\n' "$package") \
    != "mealy $expected_architecture" \
  || -n $(rpm -qp --scripts "$package") ]]; then
  echo "RPM identity does not match this host or package contains scriptlets" >&2
  exit 65
fi
if rpm -q mealy >/dev/null 2>&1 \
  || [[ -e /usr/bin/mealyd || -e /usr/bin/mealyctl || -e /usr/lib/mealy ]]; then
  echo "a Mealy RPM installation or unmanaged target path already exists" >&2
  exit 73
fi
if [[ $EUID -eq 0 ]]; then
  root_command=()
else
  if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true; then
    echo "passwordless sudo is required for the isolated RPM lifecycle smoke" >&2
    exit 77
  fi
  root_command=(sudo -n)
fi

temporary_root=${MEALY_INSTALLED_SMOKE_ROOT:-${HOME-}}
if [[ -z $temporary_root || -L $temporary_root || ! -d $temporary_root \
  || ! -w $temporary_root ]]; then
  echo "installed RPM smoke requires a writable real HOME or smoke root" >&2
  exit 69
fi
temporary=$(mktemp -d "$temporary_root/.mealy-installed-rpm-smoke.XXXXXX")
home="$temporary/home"
work="$temporary/work"
mkdir -m 0700 "$home" "$work"
package_installed=false
cleanup() {
  if [[ $package_installed == true ]]; then
    "${root_command[@]}" rpm -e mealy >/dev/null 2>&1 || true
  fi
  rm -rf -- "$temporary"
}
trap cleanup EXIT

"${root_command[@]}" rpm --install --nosignature "$package"
package_installed=true
[[ $(readlink /usr/bin/mealyd) == ../lib/mealy/release/bin/mealyd ]]
[[ $(readlink /usr/bin/mealyctl) == ../lib/mealy/release/bin/mealyctl ]]
[[ $(stat -Lc '%u:%g:%a' /usr/bin/mealyd) == 0:0:755 ]]
[[ $(stat -Lc '%u:%g:%a' /usr/bin/mealyctl) == 0:0:755 ]]
scripts_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
"$scripts_root/system-package-runtime-smoke.sh" RPM "$home" "$work"

"${root_command[@]}" rpm -e mealy
package_installed=false
[[ ! -e /usr/bin/mealyd && ! -e /usr/bin/mealyctl && ! -e /usr/lib/mealy ]]
[[ -f $home/mealy.sqlite3 ]]
trap - EXIT
rm -rf -- "$temporary"

echo "installed RPM package smoke: ok"
