#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: macos-control-plane-smoke.sh MEALYD MEALYCTL" >&2
}

if [[ $# -ne 2 || $(uname -s) != Darwin ]]; then
  usage
  exit 64
fi
for command in grep id jq launchctl mkdir mktemp plutil rm seq sleep uname; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "macOS control-plane smoke requires $command" >&2
    exit 69
  }
done

canonical_executable() {
  local input=$1 absolute directory name
  case $input in
    /*) absolute=$input ;;
    *) absolute=$PWD/$input ;;
  esac
  directory=${absolute%/*}
  name=${absolute##*/}
  directory=$(cd -P "$directory" && pwd -P)
  printf '%s/%s\n' "$directory" "$name"
}

mealyd=$(canonical_executable "$1")
mealyctl=$(canonical_executable "$2")
for binary in "$mealyd" "$mealyctl"; do
  if [[ -L $binary || ! -f $binary || ! -x $binary ]]; then
    echo "macOS control-plane smoke requires canonical executable binaries" >&2
    exit 65
  fi
done
version=$("$mealyd" --version)
version=${version#mealyd }
if [[ -z $version || $("$mealyctl" --version) != "mealyctl $version" ]]; then
  echo "macOS control-plane binary versions do not match" >&2
  exit 65
fi
schema_version=$("$mealyd" --print-supported-schema-version)
if [[ ! $schema_version =~ ^[1-9][0-9]*$ ]]; then
  echo "macOS control-plane schema identity is invalid" >&2
  exit 65
fi
case $(uname -m) in
  arm64) rust_architecture=aarch64 ;;
  x86_64) rust_architecture=x86_64 ;;
  *)
    echo "unsupported macOS control-plane architecture" >&2
    exit 69
    ;;
esac

temporary_root=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
temporary=$(mktemp -d "$temporary_root/mealy-macos-control-plane.XXXXXX")
temporary=$(cd -P "$temporary" && pwd -P)
direct_pid=
launchd_loaded=false
launchd_domain="gui/$(id -u)"
launchd_service="$launchd_domain/dev.mealy.mealyd"
cleanup() {
  if [[ $launchd_loaded == true ]]; then
    launchctl bootout "$launchd_service" >/dev/null 2>&1 || true
  fi
  if [[ -n $direct_pid ]]; then
    kill "$direct_pid" >/dev/null 2>&1 || true
    wait "$direct_pid" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$temporary"
}
trap cleanup EXIT

wait_for_health() {
  local home=$1 output=$2 pid=${3-}
  for _ in $(seq 1 400); do
    if [[ -s $home/connection.json ]] \
      && "$mealyctl" --home "$home" health >"$output" 2>/dev/null; then
      return 0
    fi
    if [[ -n $pid ]] && ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi
    sleep 0.05
  done
  return 1
}

direct_home="$temporary/direct-home"
mkdir -m 0700 "$direct_home"
"$mealyd" --home "$direct_home" --promotion-interval-ms 10 \
  --outbox-delay-ms 0 --agent-delay-ms 10 --fake-provider-delay-ms 10 \
  >"$temporary/direct.stdout" 2>"$temporary/direct.stderr" &
direct_pid=$!
if ! wait_for_health "$direct_home" "$temporary/direct-health.json" "$direct_pid"; then
  echo "macOS preview daemon did not become healthy" >&2
  exit 70
fi
jq -e '.apiVersion == "v1" and .live == true' \
  "$temporary/direct-health.json" >/dev/null

"$mealyctl" --home "$direct_home" doctor >"$temporary/direct-doctor.json"
jq -e --arg architecture "$rust_architecture" '
  .apiVersion == "v1"
  and .operatingSystem == "macos"
  and .architecture == $architecture
  and .controlPlaneReady == true
  and .sandboxAvailable == false
  and any(.sandboxProfiles[]; .profile == "observe" and .status == "denied")
  and any(.sandboxProfiles[]; .profile == "workspace_write" and .status == "denied")
' "$temporary/direct-doctor.json" >/dev/null
"$mealyctl" --home "$direct_home" status >"$temporary/direct-status.json"
jq -e --argjson schema "$schema_version" '
  .apiVersion == "v1"
  and .runStatus == "running"
  and .schemaVersion == $schema
  and .enabledActionTools == []
  and .extensionHostHealth == "unavailable_fail_closed"
' "$temporary/direct-status.json" >/dev/null

session=$("$mealyctl" --home "$direct_home" session create)
session_id=$(jq -er '.sessionId' <<<"$session")
request="macOS packaged control-plane smoke $session_id"
"$mealyctl" --home "$direct_home" session send "$session_id" "$request" \
  --idempotency-key macos-packaged-control-plane-smoke-1 >/dev/null
task_id=
for _ in $(seq 1 600); do
  search=$("$mealyctl" --home "$direct_home" session search --limit 1 "$request")
  task_id=$(jq -r '.hits[0].taskId // empty' <<<"$search")
  if [[ -n $task_id ]]; then
    task=$("$mealyctl" --home "$direct_home" task status "$task_id")
    task_status=$(jq -r '.status' <<<"$task")
    if [[ $task_status == succeeded || $task_status == failed || $task_status == cancelled ]]; then
      break
    fi
  fi
  sleep 0.05
done
if [[ -z $task_id ]]; then
  echo "macOS preview did not publish a canonical task" >&2
  exit 70
fi
jq -e '
  .apiVersion == "v1"
  and .status == "succeeded"
  and (.finalResponse | type == "string" and length > 0)
  and .usage.reservedModelCalls == 0
  and .usage.reservedToolCalls == 0
  and .usage.reservedDelegatedRuns == 0
  and .usage.reservedCostMicrounits == 0
' <<<"$task" >/dev/null
replay=$("$mealyctl" --home "$direct_home" task replay "$task_id")
jq -e '
  .apiVersion == "v1"
  and .mode == "recorded_only"
  and .evidenceComplete == true
  and .liveProviderCalls == 0
  and .liveToolCalls == 0
' <<<"$replay" >/dev/null

backup=$("$mealyctl" --home "$direct_home" backup macos-control-plane-smoke)
backup_digest=$(jq -er '.manifestDigest' <<<"$backup")
jq -e --argjson schema "$schema_version" '
  .apiVersion == "v1"
  and .name == "macos-control-plane-smoke"
  and .schemaVersion == $schema
  and .fileCount >= 2
  and .totalBytes > 0
  and .secretsIncluded == false
' <<<"$backup" >/dev/null
verification=$("$mealyctl" --home "$direct_home" restore-verify macos-control-plane-smoke)
jq -e --arg digest "$backup_digest" --argjson schema "$schema_version" '
  .apiVersion == "v1"
  and .manifestDigest == $digest
  and .schemaVersion == $schema
  and .secretsIncluded == false
' <<<"$verification" >/dev/null

"$mealyctl" --home "$direct_home" drain >/dev/null
for _ in $(seq 1 400); do
  if ! kill -0 "$direct_pid" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
if kill -0 "$direct_pid" 2>/dev/null; then
  echo "macOS preview daemon did not complete its bounded drain" >&2
  exit 70
fi
wait "$direct_pid"
direct_pid=

if [[ ${MEALY_MACOS_LAUNCHD_SMOKE_ALLOW_HOST:-false} != true ]]; then
  echo "refusing to mutate launchd without MEALY_MACOS_LAUNCHD_SMOKE_ALLOW_HOST=true" >&2
  exit 73
fi
if ! launchctl print "$launchd_domain" >/dev/null 2>&1; then
  echo "macOS launchd GUI domain is unavailable" >&2
  exit 69
fi
if launchctl print "$launchd_service" >/dev/null 2>&1; then
  echo "macOS LaunchAgent label is already loaded" >&2
  exit 73
fi

service_home="$temporary/service-home"
owner_home="$temporary/owner-home"
plist="$temporary/dev.mealy.mealyd.plist"
mkdir -m 0700 "$service_home" "$owner_home"
HOME="$owner_home" "$mealyctl" --home "$service_home" service install \
  --daemon-path "$mealyd" --destination "$plist" >"$temporary/service.json"
jq -e --arg daemon "$mealyd" --arg home "$service_home" --arg plist "$plist" '
  .platform == "macos-launch-agent"
  and .daemonPath == $daemon
  and .home == $home
  and .serviceDefinition == $plist
  and (.activationCommand | contains("launchctl bootstrap gui/$(id -u)"))
' "$temporary/service.json" >/dev/null
plutil -lint "$plist" >/dev/null
grep -Fq '<key>RunAtLoad</key><true/>' "$plist"
if grep -Fq '<key>KeepAlive</key>' "$plist"; then
  echo "macOS LaunchAgent would restart an intentional drain" >&2
  exit 65
fi

launchctl bootstrap "$launchd_domain" "$plist"
launchd_loaded=true
if ! wait_for_health "$service_home" "$temporary/service-health.json"; then
  echo "macOS LaunchAgent daemon did not become healthy" >&2
  exit 70
fi
"$mealyctl" --home "$service_home" drain >/dev/null
for _ in $(seq 1 400); do
  if [[ ! -e $service_home/connection.json ]]; then
    break
  fi
  sleep 0.05
done
sleep 3
if "$mealyctl" --home "$service_home" health >/dev/null 2>&1; then
  echo "macOS LaunchAgent restarted after intentional drain" >&2
  exit 70
fi
launchctl print "$launchd_service" >"$temporary/launchd-state.txt"
grep -Fq 'state = not running' "$temporary/launchd-state.txt"
grep -Fq 'last exit code = 0' "$temporary/launchd-state.txt"
launchctl bootout "$launchd_service"
launchd_loaded=false

echo "macOS control-plane smoke: ok (version $version, schema $schema_version, task $task_id)"
