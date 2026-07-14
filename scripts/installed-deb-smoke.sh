#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 1 || -L $1 || ! -f $1 ]]; then
  echo "usage: installed-deb-smoke.sh PACKAGE.deb" >&2
  exit 64
fi
for command in cmp dpkg dpkg-deb dpkg-query find grep jq mktemp readlink seq \
  sha256sum sleep sort stat tar; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "installed Debian package smoke requires $command" >&2
    exit 69
  fi
done

package=$(readlink -f "$1")
if [[ $(stat -c '%s' "$package") -gt 268435456 ]]; then
  echo "Debian package exceeds the 256 MiB smoke bound" >&2
  exit 65
fi
case $(uname -m) in
  x86_64 | amd64) expected_architecture=amd64 ;;
  aarch64 | arm64) expected_architecture=arm64 ;;
  *)
    echo "unsupported Debian package smoke architecture" >&2
    exit 69
    ;;
esac
if [[ $(dpkg-deb --field "$package" Package) != mealy \
  || $(dpkg-deb --field "$package" Architecture) != "$expected_architecture" ]]; then
  echo "Debian package identity does not match this host" >&2
  exit 65
fi
control_inventory=$(dpkg-deb --ctrl-tarfile "$package" | tar -tf - | sort)
if [[ $control_inventory != $'./\n./control\n./md5sums' ]]; then
  echo "Debian package contains unexpected maintainer control files" >&2
  exit 65
fi
if dpkg-query --show mealy >/dev/null 2>&1 \
  || [[ -e /usr/bin/mealyd || -e /usr/bin/mealyctl || -e /usr/lib/mealy \
    || -e /usr/share/doc/mealy ]]; then
  echo "a Mealy Debian installation or unmanaged target path already exists" >&2
  exit 73
fi

if [[ $EUID -eq 0 ]]; then
  root_command=()
else
  if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true; then
    echo "passwordless sudo is required for the isolated Debian install/remove smoke" >&2
    exit 77
  fi
  root_command=(sudo -n)
fi
require_sandbox=${MEALY_INSTALLED_SMOKE_REQUIRE_SANDBOX:-false}
if [[ $require_sandbox != true && $require_sandbox != false ]]; then
  echo "MEALY_INSTALLED_SMOKE_REQUIRE_SANDBOX must be true or false" >&2
  exit 64
fi

temporary_root=${MEALY_INSTALLED_SMOKE_ROOT:-${HOME-}}
if [[ -z $temporary_root || -L $temporary_root || ! -d $temporary_root \
  || ! -w $temporary_root ]]; then
  echo "installed Debian package smoke requires a writable real HOME or MEALY_INSTALLED_SMOKE_ROOT" >&2
  exit 69
fi
temporary=$(mktemp -d "$temporary_root/.mealy-installed-deb-smoke.XXXXXX")
home="$temporary/home"
daemon_pid=
package_installed=false
cleanup() {
  if [[ -n $daemon_pid ]]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  if [[ $package_installed == true ]]; then
    "${root_command[@]}" dpkg --remove mealy >/dev/null 2>&1 || true
    "${root_command[@]}" dpkg --purge mealy >/dev/null 2>&1 || true
  fi
  rm -rf -- "$temporary"
}
trap cleanup EXIT

mkdir -p "$temporary/extracted"
dpkg-deb --extract "$package" "$temporary/extracted"
symlinks=$(find "$temporary/extracted" -type l -printf '%P\n' | sort)
if [[ $symlinks != $'usr/bin/mealyctl\nusr/bin/mealyd\nusr/share/doc/mealy/OPERATIONS.md\nusr/share/doc/mealy/QUICKSTART.md\nusr/share/doc/mealy/RELEASE.md\nusr/share/doc/mealy/THREAT_MODEL.md' \
  || $(readlink "$temporary/extracted/usr/bin/mealyd") != ../lib/mealy/release/bin/mealyd \
  || $(readlink "$temporary/extracted/usr/bin/mealyctl") != ../lib/mealy/release/bin/mealyctl \
  || $(readlink "$temporary/extracted/usr/share/doc/mealy/QUICKSTART.md") != docs/QUICKSTART.md \
  || $(readlink "$temporary/extracted/usr/share/doc/mealy/OPERATIONS.md") != docs/OPERATIONS.md \
  || $(readlink "$temporary/extracted/usr/share/doc/mealy/RELEASE.md") != docs/RELEASE.md \
  || $(readlink "$temporary/extracted/usr/share/doc/mealy/THREAT_MODEL.md") != docs/THREAT_MODEL.md \
  || -n $(find "$temporary/extracted" ! -type f ! -type d ! -type l -print -quit) ]]; then
  echo "Debian package contains an unsupported filesystem type" >&2
  exit 65
fi
release="$temporary/extracted/usr/lib/mealy/release"
if [[ ! -f $release/PAYLOAD-SHA256SUMS \
  || ! -f $release/THIRD-PARTY-LICENSES.html \
  || ! -f $temporary/extracted/usr/share/doc/mealy/QUICKSTART.md \
  || ! -f $temporary/extracted/usr/share/doc/mealy/docs/README.md \
  || ! -f $temporary/extracted/usr/share/doc/mealy/docs/benchmarks/README.md \
  || ! -f $temporary/extracted/usr/share/doc/mealy/docs/research/REFERENCE_SYSTEMS.md \
  || ! -f $temporary/extracted/usr/share/doc/mealy/third-party-licenses.html \
  || ! -f $temporary/extracted/usr/share/doc/mealy/THREAT_MODEL.md ]]; then
  echo "Debian package is missing mandatory release metadata" >&2
  exit 65
fi
(cd "$release" && sha256sum --check --strict PAYLOAD-SHA256SUMS >/dev/null)
cmp "$temporary/extracted/usr/bin/mealyd" "$release/bin/mealyd"
cmp "$temporary/extracted/usr/bin/mealyctl" "$release/bin/mealyctl"
cmp "$release/THIRD-PARTY-LICENSES.html" \
  "$temporary/extracted/usr/share/doc/mealy/third-party-licenses.html"
version=$(jq -er '.version' "$release/BUILD-MANIFEST.json")
schema_version=$(jq -er '.stateSchemaVersion' "$release/BUILD-MANIFEST.json")
debian_version=${version/-/~}
if [[ $(dpkg-deb --field "$package" Version) != "$debian_version" ]]; then
  echo "Debian control version does not match the release manifest" >&2
  exit 65
fi

package_installed=true
"${root_command[@]}" dpkg --install "$package" >/dev/null
if [[ $(dpkg-query --show --showformat='${db:Status-Status}' mealy) != installed ]]; then
  echo "Debian package did not reach installed state" >&2
  exit 70
fi
[[ $(readlink /usr/bin/mealyd) == ../lib/mealy/release/bin/mealyd ]]
[[ $(readlink /usr/bin/mealyctl) == ../lib/mealy/release/bin/mealyctl ]]
[[ $(stat -Lc '%u:%g:%a' /usr/bin/mealyd) == 0:0:755 ]]
[[ $(stat -Lc '%u:%g:%a' /usr/bin/mealyctl) == 0:0:755 ]]
[[ $(stat -c '%u:%g:%a' /usr/lib/mealy/release/README.md) == 0:0:644 ]]
cmp /usr/bin/mealyd "$release/bin/mealyd"
cmp /usr/bin/mealyctl "$release/bin/mealyctl"
[[ $(/usr/bin/mealyd --version) == "mealyd $version" ]]
[[ $(/usr/bin/mealyctl --version) == "mealyctl $version" ]]
[[ $(/usr/bin/mealyd --print-supported-schema-version) == "$schema_version" ]]

mkdir -p "$home"
chmod 0700 "$home"
service=$(/usr/bin/mealyctl --home "$home" service install \
  --destination "$temporary/mealy.service")
jq -e --arg home "$home" --arg unit "$temporary/mealy.service" '
  .platform == "linux-systemd-user"
  and .daemonPath == "/usr/lib/mealy/release/bin/mealyd"
  and .home == $home
  and .serviceDefinition == $unit
  and (.activationCommand | contains("systemctl --user link"))
  and (.activationCommand | contains("systemctl --user enable --now mealy.service"))
' <<<"$service" >/dev/null
grep -Fqx 'RestartPreventExitStatus=2' "$temporary/mealy.service"
grep -Fqx 'UMask=0077' "$temporary/mealy.service"
grep -Fqx 'NoNewPrivileges=true' "$temporary/mealy.service"
grep -Fq 'ExecStart=/usr/bin/bwrap --unshare-user --unshare-pid --unshare-uts --unshare-ipc' \
  "$temporary/mealy.service"
grep -Fq -- '--cap-drop ALL --hostname mealy-daemon --ro-bind / /' \
  "$temporary/mealy.service"
grep -Fq -- '--proc /proc --dev /dev --tmpfs /tmp --tmpfs /var/tmp' \
  "$temporary/mealy.service"
if grep -Eq \
  '^(PrivateDevices|PrivateTmp|ProtectClock|ProtectControlGroups|ProtectHome|ProtectHostname|ProtectKernelLogs|ProtectKernelModules|ProtectKernelTunables|ProtectProc|ProtectSystem|ProcSubset|ReadWritePaths|RestrictSUIDSGID)=' \
  "$temporary/mealy.service"; then
  echo "installed service delegates a user-namespace restriction to systemd" >&2
  exit 65
fi
grep -Fqx 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
  "$temporary/mealy.service"
grep -Fqx 'RestrictRealtime=true' "$temporary/mealy.service"
grep -Fqx 'SystemCallArchitectures=native' "$temporary/mealy.service"
grep -Fq -- "--bind \"$home\" \"$home\"" "$temporary/mealy.service"

/usr/bin/mealyd --home "$home" --promotion-interval-ms 10 --outbox-delay-ms 0 \
  --agent-delay-ms 10 --fake-provider-delay-ms 10 \
  >"$temporary/daemon.stdout" 2>"$temporary/daemon.stderr" &
daemon_pid=$!
for _ in $(seq 1 400); do
  if [[ -s $home/connection.json ]] \
    && /usr/bin/mealyctl --home "$home" health >"$temporary/health.json" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "Debian-installed daemon exited before health" >&2
    exit 70
  fi
  sleep 0.05
done
jq -e '.apiVersion == "v1" and .live == true' "$temporary/health.json" >/dev/null
/usr/bin/mealyctl --home "$home" doctor >"$temporary/doctor.json"
jq -e '.apiVersion == "v1" and .controlPlaneReady == true' \
  "$temporary/doctor.json" >/dev/null
if [[ $require_sandbox == true ]]; then
  jq -e '
    .sandboxAvailable == true
    and any(.sandboxProfiles[]; .profile == "observe" and .status == "enforceable")
    and any(.sandboxProfiles[]; .profile == "workspace_write" and .status == "enforceable")
  ' "$temporary/doctor.json" >/dev/null
fi

session=$(/usr/bin/mealyctl --home "$home" session create)
session_id=$(jq -er '.sessionId' <<<"$session")
request="Debian installed runtime smoke $session_id"
/usr/bin/mealyctl --home "$home" session send "$session_id" "$request" \
  --idempotency-key installed-deb-runtime-smoke-1 >/dev/null
task_id=
for _ in $(seq 1 600); do
  search=$(/usr/bin/mealyctl --home "$home" session search --limit 1 "$request")
  task_id=$(jq -r '.hits[0].taskId // empty' <<<"$search")
  if [[ -n $task_id ]]; then
    task=$(/usr/bin/mealyctl --home "$home" task status "$task_id")
    status=$(jq -r '.status' <<<"$task")
    if [[ $status == succeeded || $status == failed || $status == cancelled ]]; then
      break
    fi
  fi
  sleep 0.05
done
if [[ -z $task_id ]]; then
  echo "Debian-installed runtime did not publish a task" >&2
  exit 70
fi
jq -e '
  .status == "succeeded"
  and .usage.reservedModelCalls == 0
  and .usage.reservedToolCalls == 0
  and .usage.reservedCostMicrounits == 0
' \
  <<<"$task" >/dev/null
replay=$(/usr/bin/mealyctl --home "$home" task replay "$task_id")
jq -e '
  .mode == "recorded_only"
  and .evidenceComplete == true
  and .liveProviderCalls == 0
  and .liveToolCalls == 0
' <<<"$replay" >/dev/null

/usr/bin/mealyctl --home "$home" drain >/dev/null
for _ in $(seq 1 400); do
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
if kill -0 "$daemon_pid" 2>/dev/null; then
  echo "Debian-installed daemon did not drain" >&2
  exit 70
fi
wait "$daemon_pid"
daemon_pid=
[[ -f $home/mealy.sqlite3 ]]

"${root_command[@]}" dpkg --remove mealy >/dev/null
[[ ! -e /usr/bin/mealyd && ! -e /usr/bin/mealyctl \
  && ! -e /usr/lib/mealy && ! -e /usr/share/doc/mealy ]]
[[ -f $home/mealy.sqlite3 ]]
if dpkg-query --show mealy >/dev/null 2>&1; then
  "${root_command[@]}" dpkg --purge mealy >/dev/null
fi
package_installed=false

echo "installed Debian package smoke: ok (version $version, schema $schema_version, task $task_id)"
