#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 3 || -z $1 || -L $2 || ! -d $2 || -L $3 || ! -d $3 ]]; then
  echo "usage: system-package-runtime-smoke.sh LABEL HOME WORK_DIRECTORY" >&2
  exit 64
fi
label=$1
home=$(readlink -f "$2")
work=$(readlink -f "$3")
for command in grep jq readlink seq sha256sum sleep; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "system-package runtime smoke requires $command" >&2
    exit 69
  fi
done
if [[ ! -x /usr/bin/mealyd || ! -x /usr/bin/mealyctl \
  || ! -f /usr/lib/mealy/release/BUILD-MANIFEST.json \
  || ! -f /usr/lib/mealy/release/PAYLOAD-SHA256SUMS ]]; then
  echo "system package is not installed at the canonical Mealy paths" >&2
  exit 66
fi
(cd /usr/lib/mealy/release && sha256sum --check --strict PAYLOAD-SHA256SUMS >/dev/null)
version=$(jq -er '.version' /usr/lib/mealy/release/BUILD-MANIFEST.json)
schema_version=$(jq -er '.stateSchemaVersion' /usr/lib/mealy/release/BUILD-MANIFEST.json)
[[ $(/usr/bin/mealyd --version) == "mealyd $version" ]]
[[ $(/usr/bin/mealyctl --version) == "mealyctl $version" ]]
[[ $(/usr/bin/mealyd --print-supported-schema-version) == "$schema_version" ]]
case $label in
  RPM)
    installation_kind=rpm-package
    update_mode=dnf
    ;;
  Arch)
    installation_kind=arch-package
    update_mode=pacman
    ;;
  *)
    echo "unsupported system-package smoke label: $label" >&2
    exit 64
    ;;
esac
install_status=$(/usr/bin/mealyctl install-status)
jq -e --arg kind "$installation_kind" --arg mode "$update_mode" \
  --arg version "$version" --argjson schema "$schema_version" '
    .schemaVersion == "mealy.install-status.v1"
    and .installationKind == $kind
    and .integrity == "verified"
    and .currentVersion == $version
    and .stateSchemaVersion == $schema
    and .updateMode == $mode
    and .rollbackAvailable == false
    and (.nativeUpdateCommand | type == "string" and length > 0)
    and .issues == []
  ' <<<"$install_status" >/dev/null
uninstall_plan=$(/usr/bin/mealyctl uninstall)
jq -e '
  .schemaVersion == "mealy.maintenance-plan.v1"
  and .operation == "uninstall"
  and .actionRequired == true
  and .applySupported == false
  and .preservesHome == true
  and (.nativeCommand | type == "string" and length > 0)
' <<<"$uninstall_plan" >/dev/null

chmod 0700 "$home" "$work"
service=$(/usr/bin/mealyctl --home "$home" service install \
  --destination "$work/mealy.service")
jq -e --arg home "$home" --arg unit "$work/mealy.service" '
  .platform == "linux-systemd-user"
  and .daemonPath == "/usr/lib/mealy/release/bin/mealyd"
  and .home == $home
  and .serviceDefinition == $unit
  and (.activationCommand | contains("systemctl --user"))
' <<<"$service" >/dev/null
grep -Fqx 'RestartPreventExitStatus=2' "$work/mealy.service"
grep -Fqx 'NoNewPrivileges=true' "$work/mealy.service"
grep -Fqx 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
  "$work/mealy.service"
grep -Fqx 'SystemCallArchitectures=native' "$work/mealy.service"
grep -Fqx 'MemoryMax=1536M' "$work/mealy.service"
grep -Fqx 'MemorySwapMax=0' "$work/mealy.service"
grep -Fqx 'TasksMax=384' "$work/mealy.service"

daemon_pid=
cleanup() {
  if [[ -n $daemon_pid ]]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT
/usr/bin/mealyd \
  --home "$home" \
  --promotion-interval-ms 10 \
  --outbox-delay-ms 0 \
  --agent-delay-ms 10 \
  --fake-provider-delay-ms 10 \
  >"$work/daemon.stdout" 2>"$work/daemon.stderr" &
daemon_pid=$!
for _ in $(seq 1 400); do
  if [[ -s $home/connection.json ]] \
    && /usr/bin/mealyctl --home "$home" health >"$work/health.json" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "$label-installed daemon exited before becoming live" >&2
    exit 70
  fi
  sleep 0.05
done
jq -e '.apiVersion == "v1" and .live == true' "$work/health.json" >/dev/null

/usr/bin/mealyctl --home "$home" doctor >"$work/doctor.json"
jq -e --arg schema "$schema_version" '
  .apiVersion == "v1"
  and .controlPlaneReady == true
  and (.checks.sqlite | contains("schema " + $schema + " "))
' "$work/doctor.json" >/dev/null
require_sandbox=${MEALY_INSTALLED_SMOKE_REQUIRE_SANDBOX:-false}
if [[ $require_sandbox != true && $require_sandbox != false ]]; then
  echo "MEALY_INSTALLED_SMOKE_REQUIRE_SANDBOX must be true or false" >&2
  exit 64
fi
if [[ $require_sandbox == true ]]; then
  jq -e '
    .sandboxAvailable == true
    and any(.sandboxProfiles[]; .profile == "observe" and .status == "enforceable")
    and any(.sandboxProfiles[]; .profile == "workspace_write" and .status == "enforceable")
  ' "$work/doctor.json" >/dev/null
fi

session=$(/usr/bin/mealyctl --home "$home" session create)
session_id=$(jq -er '.sessionId' <<<"$session")
request="$label installed runtime smoke $session_id"
/usr/bin/mealyctl --home "$home" session send "$session_id" "$request" \
  --idempotency-key system-package-runtime-smoke-1 >/dev/null
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
  echo "$label-installed runtime did not publish a canonical task" >&2
  exit 70
fi
jq -e '
  .status == "succeeded"
  and .usage.reservedModelCalls == 0
  and .usage.reservedToolCalls == 0
  and .usage.reservedCostMicrounits == 0
' <<<"$task" >/dev/null
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
  echo "$label-installed daemon did not complete its bounded drain" >&2
  exit 70
fi
wait "$daemon_pid"
daemon_pid=
[[ -f $home/mealy.sqlite3 ]]
trap - EXIT

echo "$label system-package runtime: ok (version $version, schema $schema_version, task $task_id)"
