#!/usr/bin/env bash

# Exercise one real approval-gated mutation through the generated Linux user unit.
# This catches systemd restrictions that can leave `doctor` green while
# blocking the worker's secure file-creation syscall inside Bubblewrap.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 PATH_TO_MEALYD PATH_TO_MEALYCTL" >&2
  exit 64
fi
if [[ $(uname -s) != Linux ]]; then
  echo "the systemd service smoke is Linux-only" >&2
  exit 69
fi
for command in awk dirname grep jq journalctl mktemp readlink realpath seq sleep systemctl timeout; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command is unavailable: $command" >&2
    exit 69
  fi
done
if [[ ! -d /run/systemd/system ]]; then
  echo "the host system manager is not systemd" >&2
  exit 69
fi

# This proof links a temporary unit and reloads the current user's manager. Disposable containers
# are isolated by construction; every host, including a CI runner, must opt in explicitly so a
# maintainer cannot accidentally perturb a long-lived desktop or self-hosted runner manager.
isolated_environment=false
if [[ -f /.dockerenv || -f /run/.containerenv ]]; then
  isolated_environment=true
elif command -v systemd-detect-virt >/dev/null 2>&1 \
  && systemd-detect-virt --quiet --container; then
  isolated_environment=true
fi
if [[ $isolated_environment != true && ${MEALY_SYSTEMD_SMOKE_ALLOW_HOST-} != true ]]; then
  echo "refusing to mutate a non-isolated systemd user manager" >&2
  echo "run this proof in a disposable container, or set MEALY_SYSTEMD_SMOKE_ALLOW_HOST=true after reviewing the temporary unit lifecycle" >&2
  exit 73
fi
systemctl_user() {
  timeout --foreground --signal=TERM --kill-after=5 30 systemctl --user "$@"
}

if ! systemctl_user show-environment >/dev/null 2>&1; then
  echo "the current user has no reachable systemd user manager" >&2
  exit 69
fi
failed_unit_count=$(systemctl_user list-units --failed --no-legend --plain | awk 'END {print NR}')
if [[ ! $failed_unit_count =~ ^[0-9]+$ ]] || ((failed_unit_count > 1024)); then
  echo "refusing a systemd user manager with an excessive failed-unit graph: $failed_unit_count units" >&2
  echo "retain or clear those unrelated diagnostics deliberately, then run this proof in a disposable container" >&2
  exit 73
fi
if systemctl_user cat mealy.service >/dev/null 2>&1; then
  echo "refusing to replace an existing mealy.service in this user manager" >&2
  exit 73
fi

mealyd=$(realpath -- "$1")
mealyctl=$(realpath -- "$2")
if [[ ! -x $mealyd || ! -x $mealyctl ]]; then
  echo "both supplied Mealy binaries must be executable regular files" >&2
  exit 66
fi
if [[ $(dirname -- "$mealyd") != "$(dirname -- "$mealyctl")" ]]; then
  echo "mealyd and mealyctl must be installed side by side" >&2
  exit 65
fi

home=$(mktemp -d "$HOME/.mealy systemd smoke.XXXXXX")
unit_directory=$(mktemp -d "$HOME/.mealy systemd unit.XXXXXX")
unit="$unit_directory/mealy.service"
daemon_pid=
service_pid=
linked=false

cleanup() {
  status=$?
  set +e
  if [[ $linked == true ]]; then
    link="$HOME/.config/systemd/user/mealy.service"
    if [[ -L $link && $(readlink -- "$link") == "$unit" ]]; then
      rm -- "$link"
    fi
  fi
  if [[ $status -ne 0 && $linked == true ]]; then
    timeout --foreground --signal=TERM --kill-after=2 5 \
      systemctl --user status mealy.service --no-pager >&2
    timeout --foreground --signal=TERM --kill-after=2 5 \
      journalctl --user -u mealy.service -n 100 --no-pager >&2
  fi
  if [[ -n $daemon_pid ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill "$daemon_pid" 2>/dev/null
    wait "$daemon_pid" 2>/dev/null
  fi
  if [[ $linked == true ]]; then
    timeout --foreground --signal=TERM --kill-after=2 5 \
      systemctl --user disable --now mealy.service >/dev/null 2>&1
    timeout --foreground --signal=TERM --kill-after=2 5 \
      systemctl --user daemon-reload >/dev/null 2>&1
    timeout --foreground --signal=TERM --kill-after=2 5 \
      systemctl --user reset-failed mealy.service >/dev/null 2>&1
  fi
  if [[ -n $service_pid && -e /proc/$service_pid/exe \
    && $(readlink -f -- "/proc/$service_pid/exe" 2>/dev/null) == "$mealyd" \
    && -r /proc/$service_pid/cgroup \
    && $(<"/proc/$service_pid/cgroup") == *mealy.service* ]]; then
    kill "$service_pid" 2>/dev/null
    for _ in $(seq 1 50); do
      if ! kill -0 "$service_pid" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    if kill -0 "$service_pid" 2>/dev/null; then
      kill -KILL "$service_pid" 2>/dev/null
    fi
  fi
  rm -rf -- "$home" "$unit_directory"
}
trap cleanup EXIT

# Initialize a complete default home and prove the same binaries work before
# adding systemd supervision. The daemon never receives a credential.
"$mealyd" \
  --home "$home" \
  --promotion-interval-ms 10 \
  --outbox-delay-ms 0 \
  --agent-delay-ms 10 \
  --fake-provider-delay-ms 10 \
  >"$unit_directory/direct.stdout" 2>"$unit_directory/direct.stderr" &
daemon_pid=$!
for _ in $(seq 1 400); do
  if "$mealyctl" --home "$home" health >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
"$mealyctl" --home "$home" health >/dev/null
"$mealyctl" --home "$home" drain >/dev/null
wait "$daemon_pid"
daemon_pid=

service=$(
  "$mealyctl" --home "$home" service install --destination "$unit"
)
jq -e \
  --arg daemon "$mealyd" \
  --arg home "$home" \
  --arg unit "$unit" '
    .platform == "linux-systemd-user"
    and .daemonPath == $daemon
    and .home == $home
    and .serviceDefinition == $unit
    and (.readWritePaths == [$home])
    and (.activationCommand | contains("systemctl --user link"))
    and (.activationCommand | contains("systemctl --user enable --now mealy.service"))
  ' <<<"$service" >/dev/null

grep -Fqx 'NoNewPrivileges=true' "$unit"
grep -Fqx "ExecStart=\"$mealyd\" --home \"$home\"" "$unit"
if grep -Fq 'ExecStart=/usr/bin/bwrap' "$unit"; then
  echo "generated unit wraps the daemon in Bubblewrap and prevents per-tool Bubblewrap" >&2
  exit 65
fi
if grep -Eq \
  '^(PrivateDevices|PrivateTmp|ProtectClock|ProtectControlGroups|ProtectHome|ProtectHostname|ProtectKernelLogs|ProtectKernelModules|ProtectKernelTunables|ProtectProc|ProtectSystem|ProcSubset|ReadWritePaths|RestrictSUIDSGID)=' \
  "$unit"; then
  echo "generated unit delegates a user-namespace restriction to systemd" >&2
  exit 65
fi

systemctl_user link "$unit" >/dev/null
linked=true
systemctl_user daemon-reload
systemctl_user enable --now mealy.service >/dev/null
service_pid=$(systemctl_user show mealy.service --property=MainPID --value)
if [[ ! $service_pid =~ ^[1-9][0-9]*$ ]]; then
  echo "generated service did not publish a valid main PID" >&2
  exit 70
fi
if [[ $(readlink -f -- "/proc/$service_pid/exe" 2>/dev/null) != "$mealyd" ]]; then
  echo "generated service main PID is not the exact configured daemon" >&2
  exit 70
fi
for _ in $(seq 1 400); do
  if "$mealyctl" --home "$home" health >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
"$mealyctl" --home "$home" health >/dev/null
doctor=$("$mealyctl" --home "$home" doctor)
jq -e '
  .controlPlaneReady == true
  and .sandboxAvailable == true
  and any(.sandboxProfiles[]; .profile == "observe" and .status == "enforceable")
  and any(.sandboxProfiles[]; .profile == "workspace_write" and .status == "enforceable")
' <<<"$doctor" >/dev/null

session=$("$mealyctl" --home "$home" session create)
session_id=$(jq -er '.sessionId' <<<"$session")
relative_path=systemd-service-write.txt
content='approved mutation passed through the generated systemd unit'
request=$(jq -cnr \
  --arg relative_path "$relative_path" \
  --arg content "$content" '
    "fixture.write_file " + ({
      operation: "write_file",
      relativePath: $relative_path,
      content: $content
    } | tojson)
  ')
"$mealyctl" --home "$home" session send "$session_id" "$request" \
  --idempotency-key systemd-service-mutation-1 >/dev/null

approval=
for _ in $(seq 1 400); do
  approvals=$("$mealyctl" --home "$home" approval list)
  approval=$(jq -cer --arg suffix "/$relative_path" '
    [.approvals[] | select(
      any(.subject.targetResources[]?; endswith($suffix))
    )] | if length == 1 then .[0] else empty end
  ' <<<"$approvals" 2>/dev/null || true)
  if [[ -n $approval ]]; then
    break
  fi
  sleep 0.05
done
if [[ -z $approval ]]; then
  echo "the service task did not produce its exact approval" >&2
  exit 70
fi
approval_id=$(jq -er '.approvalId' <<<"$approval")
subject_digest=$(jq -er '.subjectDigest' <<<"$approval")
effect_id=$(jq -er '.effectId' <<<"$approval")
task_id=$(jq -er '.subject.taskId' <<<"$approval")
"$mealyctl" --home "$home" approval resolve "$approval_id" approve \
  --subject-digest "$subject_digest" \
  --idempotency-key systemd-service-approval-1 >/dev/null

effect_status=
for _ in $(seq 1 400); do
  effect=$("$mealyctl" --home "$home" effect status "$effect_id")
  effect_status=$(jq -er '.status' <<<"$effect")
  case $effect_status in
    succeeded | failed | unknown | cancelled) break ;;
  esac
  sleep 0.05
done
if [[ $effect_status != succeeded ]]; then
  echo "approved service effect ended as $effect_status" >&2
  jq . <<<"$effect" >&2
  exit 70
fi
if [[ $(<"$home/fixture-workspace/$relative_path") != "$content" ]]; then
  echo "approved service effect did not create the exact expected bytes" >&2
  exit 70
fi

task_status=
for _ in $(seq 1 400); do
  task=$("$mealyctl" --home "$home" task status "$task_id")
  task_status=$(jq -er '.status' <<<"$task")
  case $task_status in
    succeeded | failed | cancelled) break ;;
  esac
  sleep 0.05
done
if [[ $task_status != succeeded ]]; then
  echo "service mutation task ended as $task_status" >&2
  jq . <<<"$task" >&2
  exit 70
fi

"$mealyctl" --home "$home" drain >/dev/null
for _ in $(seq 1 400); do
  state=$(systemctl_user show mealy.service --property=ActiveState --value)
  if [[ $state != active && $state != deactivating ]]; then
    break
  fi
  sleep 0.05
done
state=$(systemctl_user show mealy.service --property=ActiveState --value)
if [[ $state != inactive ]]; then
  echo "generated service ended in unexpected state $state after bounded drain" >&2
  exit 70
fi

jq -n \
  --arg session_id "$session_id" \
  --arg task_id "$task_id" \
  --arg effect_id "$effect_id" \
  --arg path "$relative_path" \
  '{
    serviceMutationPassed: true,
    sessionId: $session_id,
    taskId: $task_id,
    effectId: $effect_id,
    relativePath: $path
  }'
