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
default_unit="$HOME/.config/systemd/user/mealy.service"
default_unit_created=false

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
  if [[ $default_unit_created == true && -f $default_unit ]] \
    && grep -Fq "ExecStart=\"$mealyd\" --home \"$home\"" "$default_unit"; then
    timeout --foreground --signal=TERM --kill-after=2 5 \
      systemctl --user disable --now mealy.service >/dev/null 2>&1
    rm -f -- "$default_unit"
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

# Prove the ordinary clean-home journey composes subscription probing, default service
# installation/activation, authenticated health/doctor, and one durable useful turn. The fake
# official client owns no credential and is never installed outside this disposable proof.
subscription_fixture="$unit_directory/codex-subscription-fixture"
cat >"$subscription_fixture" <<'EOF'
#!/bin/sh
test -z "${OPENAI_API_KEY:-}${ANTHROPIC_API_KEY:-}${OPENROUTER_API_KEY:-}${LOCAL_API_KEY:-}" || exit 90
cat >/dev/null
printf '%s\n' \
  '{"type":"thread.started","thread_id":"systemd-onboarding-fixture"}' \
  '{"type":"item.completed","item":{"type":"agent_message","text":"{\"kind\":\"final\",\"text\":\"MEALYONBOARDINGOK\",\"toolId\":null,\"arguments\":null}"}}' \
  '{"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":5}}'
EOF
chmod 0700 "$subscription_fixture"
default_unit_created=true
onboard=$(
  OPENAI_API_KEY=must-not-reach-client \
  ANTHROPIC_API_KEY=must-not-reach-client \
  OPENROUTER_API_KEY=must-not-reach-client \
  LOCAL_API_KEY=must-not-reach-client \
    "$mealyctl" --home "$home" onboard \
      --route chatgpt-subscription \
      --executable-path "$subscription_fixture" \
      --model fixture-model \
      --context-tokens 32768 \
      --maximum-output-tokens 64 \
      --approve
)
jq -e \
  --arg daemon "$mealyd" \
  --arg home "$home" '
    .provider.protocol == "openai_subscription_cli"
    and .provider.providerId == "openai.subscription"
    and .provider.connectivityTested == true
    and .provider.secretId == null
    and .service.daemonPath == $daemon
    and .service.home == $home
    and .serviceStarted == true
    and .healthVerified == true
    and .doctor.controlPlaneReady == true
    and .doctor.sandboxAvailable == true
    and (.nextCommand | contains(" chat"))
  ' <<<"$onboard" >/dev/null
"$mealyctl" --home "$home" health >/dev/null
session=$("$mealyctl" --home "$home" session create)
onboarding_session_id=$(jq -er '.sessionId' <<<"$session")
"$mealyctl" --home "$home" session send "$onboarding_session_id" \
  "Complete the onboarding acceptance turn." \
  --idempotency-key systemd-onboarding-turn-1 >/dev/null
onboarding_task_id=
for _ in $(seq 1 400); do
  search=$("$mealyctl" --home "$home" session search MEALYONBOARDINGOK)
  onboarding_task_id=$(jq -er --arg session "$onboarding_session_id" '
    [.hits[] | select(
      .sessionId == $session
      and (.assistantExcerpt // "" | contains("MEALYONBOARDINGOK"))
    )] | if length == 1 then .[0].taskId else empty end
  ' <<<"$search" 2>/dev/null || true)
  if [[ -n $onboarding_task_id ]]; then
    break
  fi
  sleep 0.05
done
if [[ -z $onboarding_task_id ]]; then
  echo "onboarding service did not complete the first durable model turn" >&2
  exit 70
fi
onboarding_task=$("$mealyctl" --home "$home" task status "$onboarding_task_id")
jq -e '.status == "succeeded"' <<<"$onboarding_task" >/dev/null
"$mealyctl" --home "$home" drain >/dev/null
for _ in $(seq 1 400); do
  state=$(systemctl_user show mealy.service --property=ActiveState --value)
  if [[ $state != active && $state != deactivating ]]; then
    break
  fi
  sleep 0.05
done
systemctl_user disable --now mealy.service >/dev/null
if [[ ! -f $default_unit ]] \
  || ! grep -Fq "ExecStart=\"$mealyd\" --home \"$home\"" "$default_unit"; then
  echo "onboarding did not install the expected default owner unit" >&2
  exit 70
fi
systemctl_user reset-failed mealy.service >/dev/null
rm -- "$default_unit"
default_unit_created=false
systemctl_user daemon-reload
rm -rf -- "$home"
mkdir -m 0700 -- "$home"

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
observed_pid=
observed_executable=
observed_state=
for _ in $(seq 1 400); do
  observed_pid=$(systemctl_user show mealy.service --property=MainPID --value)
  observed_state=$(systemctl_user show mealy.service --property=ActiveState --value)
  observed_executable=
  if [[ $observed_pid =~ ^[1-9][0-9]*$ ]]; then
    observed_executable=$(readlink -f -- "/proc/$observed_pid/exe" 2>/dev/null || true)
    if [[ $observed_executable == "$mealyd" ]]; then
      service_pid=$observed_pid
      break
    fi
  fi
  if [[ $observed_state == failed || $observed_state == inactive ]]; then
    break
  fi
  sleep 0.05
done
if [[ -z $service_pid ]]; then
  echo "generated service did not reach the exact configured daemon" >&2
  printf 'observed state=%s pid=%s executable=%s\n' \
    "${observed_state:-unknown}" "${observed_pid:-unknown}" \
    "${observed_executable:-unavailable}" >&2
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
