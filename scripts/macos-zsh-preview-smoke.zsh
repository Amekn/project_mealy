#!/bin/zsh
emulate -LR zsh
setopt ERR_EXIT NO_UNSET PIPE_FAIL
export LC_ALL=C
umask 077

usage() {
  print -u2 -- "usage: macos-zsh-preview-smoke.zsh MEALYD MEALYCTL"
}

if (( $# != 2 )) || [[ $(uname -s) != Darwin ]]; then
  usage
  exit 64
fi
for command in jq mkdir mktemp plutil rm sleep uname; do
  if (( ! $+commands[$command] )); then
    print -u2 -- "macOS zsh preview smoke requires $command"
    exit 69
  fi
done

canonical_executable() {
  local input=$1 absolute directory name
  if [[ $input == /* ]]; then
    absolute=$input
  else
    absolute=$PWD/$input
  fi
  directory=${absolute:h}
  name=${absolute:t}
  directory=$(cd -P -- "$directory" && pwd -P)
  print -r -- "$directory/$name"
}

mealyd=$(canonical_executable "$1")
mealyctl=$(canonical_executable "$2")
for binary in "$mealyd" "$mealyctl"; do
  if [[ -h $binary || ! -f $binary || ! -x $binary ]]; then
    print -u2 -- "macOS zsh preview smoke requires canonical executable binaries"
    exit 65
  fi
done

version=$("$mealyd" --version)
version=${version#mealyd }
if [[ -z $version || $("$mealyctl" --version) != "mealyctl $version" ]]; then
  print -u2 -- "macOS zsh preview binary versions do not match"
  exit 65
fi
schema_version=$("$mealyd" --print-supported-schema-version)
if [[ $schema_version != <1-> ]]; then
  print -u2 -- "macOS zsh preview schema identity is invalid"
  exit 65
fi

temporary_root=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
temporary=$(mktemp -d "$temporary_root/mealy-zsh-preview.XXXXXX")
temporary=$(cd -P -- "$temporary" && pwd -P)
state_home="$temporary/state home"
owner_home="$temporary/owner home"
service_directory="$temporary/launch agent"
plist="$service_directory/dev.mealy.mealyd.plist"
daemon_pid=''
cleanup() {
  if [[ -n $daemon_pid ]]; then
    kill "$daemon_pid" >/dev/null 2>&1 || true
    wait "$daemon_pid" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$temporary"
}
trap cleanup EXIT
mkdir -m 0700 -- "$state_home" "$owner_home" "$service_directory"

"$mealyd" --home "$state_home" --promotion-interval-ms 10 \
  --outbox-delay-ms 0 --agent-delay-ms 10 --fake-provider-delay-ms 10 \
  >"$temporary/daemon.stdout" 2>"$temporary/daemon.stderr" &
daemon_pid=$!
health_file="$temporary/health.json"
healthy=false
for attempt in {1..400}; do
  if [[ -s "$state_home/connection.json" ]] \
    && "$mealyctl" --home "$state_home" health >"$health_file" 2>/dev/null; then
    healthy=true
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
if [[ $healthy != true ]]; then
  print -u2 -- "macOS zsh preview daemon did not become healthy"
  exit 70
fi
jq -e '.apiVersion == "v1" and .live == true' "$health_file" >/dev/null

doctor_file="$temporary/doctor.json"
"$mealyctl" --home "$state_home" doctor >"$doctor_file"
jq -e '
  .apiVersion == "v1"
  and .operatingSystem == "macos"
  and .controlPlaneReady == true
  and .sandboxAvailable == false
  and any(.sandboxProfiles[]; .profile == "observe" and .status == "denied")
  and any(.sandboxProfiles[]; .profile == "workspace_write" and .status == "denied")
' "$doctor_file" >/dev/null

session_json=$("$mealyctl" --home "$state_home" session create)
session_id=$(jq -er '.sessionId' <<<"$session_json")
request="zsh quoted-path preview $session_id"
"$mealyctl" --home "$state_home" session send "$session_id" "$request" \
  --idempotency-key macos-zsh-preview-smoke-1 >/dev/null
task_id=''
task_json=''
for attempt in {1..600}; do
  search_json=$("$mealyctl" --home "$state_home" session search --limit 1 "$request")
  task_id=$(jq -r '.hits[0].taskId // empty' <<<"$search_json")
  if [[ -n $task_id ]]; then
    task_json=$("$mealyctl" --home "$state_home" task status "$task_id")
    task_status=$(jq -r '.status' <<<"$task_json")
    if [[ $task_status == succeeded || $task_status == failed || $task_status == cancelled ]]; then
      break
    fi
  fi
  sleep 0.05
done
if [[ -z $task_id || -z $task_json ]]; then
  print -u2 -- "macOS zsh preview did not publish a canonical task"
  exit 70
fi
jq -e '
  .apiVersion == "v1"
  and .status == "succeeded"
  and (.finalResponse | type == "string" and length > 0)
' <<<"$task_json" >/dev/null
replay_json=$("$mealyctl" --home "$state_home" task replay "$task_id")
jq -e '
  .apiVersion == "v1"
  and .mode == "recorded_only"
  and .evidenceComplete == true
  and .liveProviderCalls == 0
  and .liveToolCalls == 0
' <<<"$replay_json" >/dev/null

"$mealyctl" --home "$state_home" drain >/dev/null
for attempt in {1..400}; do
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
if kill -0 "$daemon_pid" 2>/dev/null; then
  print -u2 -- "macOS zsh preview daemon did not complete its bounded drain"
  exit 70
fi
wait "$daemon_pid"
daemon_pid=''

service_json=$(HOME="$owner_home" "$mealyctl" --home "$state_home" service install \
  --daemon-path "$mealyd" --destination "$plist")
jq -e --arg daemon "$mealyd" --arg home "$state_home" --arg plist "$plist" '
  .platform == "macos-launch-agent"
  and .daemonPath == $daemon
  and .home == $home
  and .serviceDefinition == $plist
  and (.activationCommand | contains("launchctl bootstrap gui/$(id -u)"))
' <<<"$service_json" >/dev/null
plutil -lint "$plist" >/dev/null

print -- "macOS native-zsh preview smoke: ok (version $version, schema $schema_version, task $task_id)"
