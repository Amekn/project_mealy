#!/usr/bin/env bash
set -euo pipefail
umask 077

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
profile=${MEALY_DASHBOARD_SMOKE_PROFILE:-debug}

case "$profile" in
  debug)
    cargo_profile=()
    binary_directory="$repository_root/target/debug"
    ;;
  release)
    cargo_profile=(--release)
    binary_directory="$repository_root/target/release"
    ;;
  *)
    echo "MEALY_DASHBOARD_SMOKE_PROFILE must be debug or release" >&2
    exit 64
    ;;
esac

for dependency in awk curl jq ldd sed sha256sum sort; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    echo "dashboard smoke requires $dependency" >&2
    exit 69
  fi
done

dashboard_curl_config=
dashboard_curl() {
  local options=(--noproxy '*' --connect-timeout 2 --max-time 20)
  if [[ -n $dashboard_curl_config ]]; then
    options+=(--config "$dashboard_curl_config")
  fi
  command curl "${options[@]}" "$@"
}

cd "$repository_root"
cargo build --locked "${cargo_profile[@]}" -p mealyd -p mealyctl
cargo build --locked "${cargo_profile[@]}" -p mealyd --bin mealy-sample-extension
mealyd="$binary_directory/mealyd"
mealyctl="$binary_directory/mealyctl"
sample_extension="$binary_directory/mealy-sample-extension"

temporary_root=${TMPDIR:-/tmp}
home=$(mktemp -d "$temporary_root/mealy-dashboard-smoke.XXXXXX")
attachment_root=$(mktemp -d "$temporary_root/mealy-dashboard-attachment.XXXXXX")
daemon_pid=
dashboard_pid=

cleanup() {
  if [[ -n $dashboard_pid ]]; then
    kill "$dashboard_pid" 2>/dev/null || true
    wait "$dashboard_pid" 2>/dev/null || true
  fi
  if [[ -n $daemon_pid ]]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  rm -rf -- "$home" "$attachment_root"
}
trap cleanup EXIT

"$mealyd" \
  --home "$home" \
  --promotion-interval-ms 10 \
  --outbox-delay-ms 0 \
  --agent-delay-ms 10 \
  --fake-provider-delay-ms 5000 \
  >"$home/daemon.stdout" 2>"$home/daemon.stderr" &
daemon_pid=$!

for _ in $(seq 1 200); do
  if [[ -s $home/connection.json ]] && "$mealyctl" --home "$home" health >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
"$mealyctl" --home "$home" health >/dev/null

"$mealyctl" --home "$home" dashboard \
  >"$home/dashboard.stdout" 2>"$home/dashboard.stderr" &
dashboard_pid=$!
origin=
for _ in $(seq 1 200); do
  origin=$(sed -n 's/^Mealy interactive dashboard: \(.*\)\/$/\1/p' \
    "$home/dashboard.stdout" | head -1)
  if [[ -n $origin ]]; then
    break
  fi
  sleep 0.05
done
if [[ -z $origin ]]; then
  echo "dashboard did not publish its loopback origin" >&2
  exit 70
fi

dashboard_curl --fail --silent --show-error "$origin/" >"$home/index.html"
dashboard_token=$(sed -n 's/.*const DASHBOARD_TOKEN = "\([^"]*\)";.*/\1/p' \
  "$home/index.html" | head -1)
if [[ ! $dashboard_token =~ ^[A-Za-z0-9_-]{43}$ ]]; then
  echo "dashboard HTML did not contain its ephemeral capability" >&2
  exit 70
fi
dashboard_curl_config="$home/dashboard-curl.conf"
printf 'header = "X-Mealy-Dashboard: %s"\n' "$dashboard_token" >"$dashboard_curl_config"
daemon_token=$(jq -er '.bearerToken' "$home/connection.json")
contains_daemon_token() {
  grep -Fq -f <(printf '%s\n' "$daemon_token") -- "$@"
}
if contains_daemon_token "$home/index.html"; then
  echo "dashboard HTML exposed the daemon bearer" >&2
  exit 70
fi

snapshot=$(dashboard_curl --fail --silent --show-error \
  "$origin/api/snapshot")
jq -e '.apiVersion == "v1" and .status.runStatus == "running" and .status.schemaVersion == 15' \
  >/dev/null <<<"$snapshot"
if contains_daemon_token <<<"$snapshot"; then
  echo "dashboard snapshot exposed the daemon bearer" >&2
  exit 70
fi

missing_effect_id=019f0000-0000-7000-8000-0000000000e1
missing_attempt_id=019f0000-0000-7000-8000-0000000000e2
effect_status=$(dashboard_curl --silent --show-error --output "$home/effect-error.json" \
  --write-out '%{http_code}' \
  "$origin/api/effects/$missing_effect_id")
if [[ $effect_status != 404 ]]; then
  echo "dashboard effect inspection did not preserve canonical not-found state" >&2
  exit 70
fi
jq -e '.apiVersion == "v1" and .code == "dashboard_command_rejected"' \
  "$home/effect-error.json" >/dev/null

reconcile_without_origin=$(dashboard_curl --silent --show-error --output "$home/reconcile-origin-error.json" \
  --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","idempotencyKey":"real-dashboard-reconcile-origin","expectedEffectRevision":1,"outcome":"failed","evidence":{"operatorObservation":"fixture effect is absent"}}' \
  "$origin/api/effects/$missing_effect_id/attempts/$missing_attempt_id/reconcile")
if [[ $reconcile_without_origin != 403 ]]; then
  echo "dashboard effect reconciliation accepted a missing Origin" >&2
  exit 70
fi

missing_reconcile_status=$(dashboard_curl --silent --show-error --output "$home/reconcile-error.json" \
  --write-out '%{http_code}' \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","idempotencyKey":"real-dashboard-reconcile-missing","expectedEffectRevision":1,"outcome":"failed","evidence":{"operatorObservation":"fixture effect is absent"}}' \
  "$origin/api/effects/$missing_effect_id/attempts/$missing_attempt_id/reconcile")
if [[ $missing_reconcile_status != 404 ]]; then
  echo "dashboard reconciliation did not preserve canonical not-found state" >&2
  exit 70
fi
jq -e '.apiVersion == "v1" and .code == "dashboard_command_rejected"' \
  "$home/reconcile-error.json" >/dev/null
if contains_daemon_token "$home/effect-error.json" "$home/reconcile-error.json"; then
  echo "dashboard effect errors exposed the daemon bearer" >&2
  exit 70
fi

created=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1"}' \
  "$origin/api/sessions")
session_id=$(jq -er '.sessionId' <<<"$created")

admitted=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","idempotencyKey":"real-dashboard-input-1","deliveryMode":"queue","content":"hello from the real dashboard smoke"}' \
  "$origin/api/sessions/$session_id/inputs")
jq -e --arg session "$session_id" \
  '.sessionId == $session and .duplicate == false' >/dev/null <<<"$admitted"

task_id=
for _ in $(seq 1 200); do
  conversation=$(dashboard_curl --fail --silent --show-error \
    "$origin/api/sessions/$session_id/timeline?after=0&limit=200")
  task_id=$(jq -r '.activeTaskId // empty' <<<"$conversation")
  if [[ -n $task_id ]]; then
    break
  fi
  sleep 0.05
done
if [[ -z $task_id ]]; then
  echo "dashboard did not discover the real active task" >&2
  exit 70
fi

schedule_id=019f0000-0000-7000-8000-000000000090
schedule_create_body=$(jq -cn \
  --arg schedule "$schedule_id" \
  --arg session "$session_id" \
  '{apiVersion:"v1",scheduleId:$schedule,sessionId:$session,name:"dashboard lifecycle smoke",prompt:"Review the durable dashboard lifecycle evidence.",cronExpression:"0 0 1 1 *",timezone:"UTC",missedRunPolicy:"latest",overlapPolicy:"skip_if_running",misfireGraceMs:60000,allowApprovalRequiredAction:false}')
schedule_create_without_origin=$(dashboard_curl --silent --show-error \
  --output "$home/schedule-create-origin-error.json" \
  --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  --data "$schedule_create_body" \
  "$origin/api/schedules")
if [[ $schedule_create_without_origin != 403 ]]; then
  echo "dashboard schedule creation accepted a missing Origin" >&2
  exit 70
fi

schedule=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data "$schedule_create_body" \
  "$origin/api/schedules")
schedule_revision=$(jq -er '.revision' <<<"$schedule")
if [[ $schedule_revision != 0 ]]; then
  echo "new schedule did not begin at revision zero" >&2
  exit 70
fi
duplicate_schedule=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data "$schedule_create_body" \
  "$origin/api/schedules")
jq -e --argjson duplicate "$duplicate_schedule" '. == $duplicate' \
  >/dev/null <<<"$schedule"
conflicting_schedule_body=$(jq -c '.name = "conflicting dashboard schedule"' \
  <<<"$schedule_create_body")
schedule_create_conflict=$(dashboard_curl --silent --show-error \
  --output "$home/schedule-create-conflict.json" \
  --write-out '%{http_code}' \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data "$conflicting_schedule_body" \
  "$origin/api/schedules")
if [[ $schedule_create_conflict != 409 ]]; then
  echo "dashboard schedule creation did not reject a reused key with different semantics" >&2
  exit 70
fi

schedule_detail=$(dashboard_curl --fail --silent --show-error \
  "$origin/api/schedules/$schedule_id")
jq -e --arg schedule "$schedule_id" --arg session "$session_id" \
  '.scheduleId == $schedule and .sessionId == $session and .status == "active" and .revision == 0' \
  >/dev/null <<<"$schedule_detail"
schedule_runs=$(dashboard_curl --fail --silent --show-error \
  "$origin/api/schedules/$schedule_id/runs?limit=50")
jq -e --arg schedule "$schedule_id" \
  '.scheduleId == $schedule and .runs == []' >/dev/null <<<"$schedule_runs"

schedule_without_origin=$(dashboard_curl --silent --show-error --output "$home/schedule-origin-error.json" \
  --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","expectedRevision":0}' \
  "$origin/api/schedules/$schedule_id/pause")
if [[ $schedule_without_origin != 403 ]]; then
  echo "dashboard schedule lifecycle accepted a missing Origin" >&2
  exit 70
fi

paused_schedule=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","expectedRevision":0}' \
  "$origin/api/schedules/$schedule_id/pause")
jq -e --arg schedule "$schedule_id" \
  '.scheduleId == $schedule and .status == "paused" and .revision == 1' \
  >/dev/null <<<"$paused_schedule"

stale_schedule_status=$(dashboard_curl --silent --show-error --output "$home/schedule-stale-error.json" \
  --write-out '%{http_code}' \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","expectedRevision":0}' \
  "$origin/api/schedules/$schedule_id/resume")
if [[ $stale_schedule_status != 409 ]]; then
  echo "dashboard schedule lifecycle did not preserve the revision conflict" >&2
  exit 70
fi

resumed_schedule=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","expectedRevision":1}' \
  "$origin/api/schedules/$schedule_id/resume")
jq -e --arg schedule "$schedule_id" \
  '.scheduleId == $schedule and .status == "active" and .revision == 2' \
  >/dev/null <<<"$resumed_schedule"

cancelled_schedule=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","expectedRevision":2}' \
  "$origin/api/schedules/$schedule_id/cancel")
jq -e --arg schedule "$schedule_id" \
  '.scheduleId == $schedule and .status == "cancelled" and .revision == 3 and .nextDueAtMs == null' \
  >/dev/null <<<"$cancelled_schedule"
if contains_daemon_token "$home/schedule-create-origin-error.json" \
  "$home/schedule-create-conflict.json" "$home/schedule-origin-error.json" \
  "$home/schedule-stale-error.json"; then
  echo "dashboard schedule errors exposed the daemon bearer" >&2
  exit 70
fi

memory_workspace=fixture://phase2
memory_list=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","workspaceIdentity":"fixture://phase2","includeDeleted":false}' \
  "$origin/api/memories/list")
jq -e '.memories == []' >/dev/null <<<"$memory_list"

memory_proposal_body='{"apiVersion":"v1","idempotencyKey":"real-dashboard-memory-proposal-1","workspaceIdentity":"fixture://phase2","content":"Prefer concise release summaries with explicit blockers.","category":"preference","confidenceBasisPoints":8500,"sensitivity":"private","retention":"standard"}'
proposed_memory=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data "$memory_proposal_body" \
  "$origin/api/memories")
memory_id=$(jq -er '.memoryId' <<<"$proposed_memory")
memory_revision_id=$(jq -er '.revisions[0].revisionId' <<<"$proposed_memory")
jq -e '.status == "proposed" and .revision == 0 and .revisions[0].status == "proposed"' \
  >/dev/null <<<"$proposed_memory"

duplicate_memory=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data "$memory_proposal_body" \
  "$origin/api/memories")
jq -e --arg memory "$memory_id" \
  '.memoryId == $memory and .revision == 0' >/dev/null <<<"$duplicate_memory"

activate_body=$(jq -nc --arg workspace "$memory_workspace" --arg revision "$memory_revision_id" \
  '{apiVersion:"v1",workspaceIdentity:$workspace,expectedRevision:0,revisionId:$revision}')
activated_memory=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data "$activate_body" \
  "$origin/api/memories/$memory_id/activate")
jq -e '.status == "active" and .revision == 1 and .revisions[0].status == "active"' \
  >/dev/null <<<"$activated_memory"

memory_search=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","workspaceIdentity":"fixture://phase2","query":"concise","maximumSensitivity":"private","limit":20}' \
  "$origin/api/memories/search")
jq -e --arg memory "$memory_id" \
  '.hits[0].memory.memoryId == $memory and .hits[0].memory.status == "active"' \
  >/dev/null <<<"$memory_search"

pinned_memory=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","workspaceIdentity":"fixture://phase2","expectedRevision":1,"pinned":true}' \
  "$origin/api/memories/$memory_id/pin")
jq -e '.revision == 2 and .retention == "pinned"' >/dev/null <<<"$pinned_memory"
unpinned_memory=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","workspaceIdentity":"fixture://phase2","expectedRevision":2,"pinned":false}' \
  "$origin/api/memories/$memory_id/pin")
jq -e '.revision == 3 and .retention == "standard"' >/dev/null <<<"$unpinned_memory"

memory_correction_body='{"apiVersion":"v1","idempotencyKey":"real-dashboard-memory-correction-1","workspaceIdentity":"fixture://phase2","expectedRevision":3,"content":"Prefer concise release summaries with risks and blockers first.","confidenceBasisPoints":9000,"sensitivity":"private","retention":"standard"}'
corrected_memory=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data "$memory_correction_body" \
  "$origin/api/memories/$memory_id/correct")
jq -e '.status == "active" and .revision == 4 and (.revisions | length) == 2 and .revisions[0].status == "superseded" and .revisions[1].status == "active"' \
  >/dev/null <<<"$corrected_memory"
duplicate_correction=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data "$memory_correction_body" \
  "$origin/api/memories/$memory_id/correct")
jq -e '.status == "active" and .revision == 4 and (.revisions | length) == 2' \
  >/dev/null <<<"$duplicate_correction"

expired_memory=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","workspaceIdentity":"fixture://phase2","expectedRevision":4}' \
  "$origin/api/memories/$memory_id/expire")
jq -e '.status == "expired" and .revision == 5' >/dev/null <<<"$expired_memory"
deleted_memory=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","workspaceIdentity":"fixture://phase2","expectedRevision":5}' \
  "$origin/api/memories/$memory_id/delete")
jq -e '.status == "deleted" and .revision == 6 and ([.revisions[] | has("content")] | all(. == false))' \
  >/dev/null <<<"$deleted_memory"

second_memory=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","idempotencyKey":"real-dashboard-memory-proposal-2","workspaceIdentity":"fixture://phase2","content":"This proposal should remain inactive.","category":"fact","confidenceBasisPoints":7000,"sensitivity":"internal","retention":"standard"}' \
  "$origin/api/memories")
second_memory_id=$(jq -er '.memoryId' <<<"$second_memory")
rejected_memory=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","workspaceIdentity":"fixture://phase2","expectedRevision":0}' \
  "$origin/api/memories/$second_memory_id/reject")
jq -e '.status == "rejected" and .revision == 1' >/dev/null <<<"$rejected_memory"

memory_tombstones=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","workspaceIdentity":"fixture://phase2","includeDeleted":true}' \
  "$origin/api/memories/list")
jq -e --arg first "$memory_id" --arg second "$second_memory_id" \
  '(.memories | length) == 2 and .memories[0].memoryId == $first and .memories[0].status == "deleted" and .memories[1].memoryId == $second and .memories[1].status == "rejected"' \
  >/dev/null <<<"$memory_tombstones"
if contains_daemon_token <<<"$memory_tombstones"; then
  echo "dashboard memory projection exposed the daemon bearer" >&2
  exit 70
fi

cancelled=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","idempotencyKey":"real-dashboard-cancel-1","reason":"Real dashboard integration smoke completed."}' \
  "$origin/api/tasks/$task_id/cancel")
jq -e --arg task "$task_id" \
  '.taskId == $task and (.status == "cancelling" or .status == "cancelled")' \
  >/dev/null <<<"$cancelled"
task_usage=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1"}' \
  "$origin/api/tasks/$task_id/usage")
for _ in $(seq 1 200); do
  if jq -e \
    '(.status == "succeeded" or .status == "failed" or .status == "cancelled") and .usage.reservedModelCalls == 0 and .usage.reservedToolCalls == 0 and .usage.reservedDelegatedRuns == 0 and .usage.reservedInputTokens == 0 and .usage.reservedOutputTokens == 0 and .usage.reservedCostMicrounits == 0 and .usage.reservedOutputBytes == 0' \
    >/dev/null <<<"$task_usage"; then
    break
  fi
  sleep 0.05
  task_usage=$(dashboard_curl --fail --silent --show-error \
    -H "Origin: $origin" \
    -H 'Content-Type: application/json' \
    --data '{"apiVersion":"v1"}' \
    "$origin/api/tasks/$task_id/usage")
done
jq -e --arg task "$task_id" \
  '.taskId == $task and (.status == "succeeded" or .status == "failed" or .status == "cancelled") and .usage.reservedModelCalls == 0 and .usage.reservedToolCalls == 0 and .usage.reservedDelegatedRuns == 0 and .usage.reservedInputTokens == 0 and .usage.reservedOutputTokens == 0 and .usage.reservedCostMicrounits == 0 and .usage.reservedOutputBytes == 0 and (.usage.usedCostMicrounits | type) == "number" and (.usage.usedInputTokens | type) == "number" and (.usage.usedOutputTokens | type) == "number"' \
  >/dev/null <<<"$task_usage"
if contains_daemon_token <<<"$task_usage"; then
  echo "dashboard task usage exposed the daemon bearer" >&2
  exit 70
fi
terminal_snapshot=$(dashboard_curl --fail --silent --show-error \
  "$origin/api/snapshot")
task_cost=$(jq -er '.usage.usedCostMicrounits' <<<"$task_usage")
jq -e --argjson task_cost "$task_cost" \
  '.usage.apiVersion == "v1" and .usage.toMs > .usage.fromMs and (.usage.toMs - .usage.fromMs) == 2592000000 and ([.usage.buckets[].completedRuns] | add // 0) >= 1 and ([.usage.buckets[].cancelledRuns] | add // 0) >= 1 and ([.usage.buckets[].usedCostMicrounits] | add // 0) >= $task_cost' \
  >/dev/null <<<"$terminal_snapshot"
if contains_daemon_token <<<"$terminal_snapshot"; then
  echo "dashboard aggregate usage snapshot exposed the daemon bearer" >&2
  exit 70
fi
cli_usage=$("$mealyctl" --home "$home" usage --days 30)
jq -e --argjson task_cost "$task_cost" \
  '.apiVersion == "v1" and (.toMs - .fromMs) == 2592000000 and ([.buckets[].completedRuns] | add // 0) >= 1 and ([.buckets[].cancelledRuns] | add // 0) >= 1 and ([.buckets[].usedCostMicrounits] | add // 0) >= $task_cost' \
  >/dev/null <<<"$cli_usage"
if contains_daemon_token <<<"$cli_usage"; then
  echo "CLI aggregate usage report exposed the daemon bearer" >&2
  exit 70
fi
printf '# Owner attachment\n\nThis bounded text file is untrusted input.\n' \
  >"$attachment_root/owner-attachment.md"
attachment_session=$("$mealyctl" --home "$home" session create)
attachment_session_id=$(jq -er '.sessionId' <<<"$attachment_session")
if "$mealyctl" --home "$home" session send-file \
  "$attachment_session_id" "$home/config.json" \
  --prompt 'Do not expose private daemon state.' \
  --idempotency-key rejected-private-local-attachment \
  >"$home/private-attachment.stdout" 2>"$home/private-attachment.stderr"; then
  echo "CLI local attachment accepted a file from private daemon state" >&2
  exit 70
fi
attachment_admission=$("$mealyctl" --home "$home" session send-file \
  "$attachment_session_id" "$attachment_root/owner-attachment.md" \
  --prompt 'Summarize the exact untrusted attachment.' \
  --idempotency-key real-cli-local-attachment-1)
jq -e --arg session "$attachment_session_id" \
  '.apiVersion == "v1" and .sessionId == $session and .duplicate == false and .inboxSequence == 1' \
  >/dev/null <<<"$attachment_admission"
if contains_daemon_token <<<"$attachment_admission"; then
  echo "CLI local attachment admission exposed the daemon bearer" >&2
  exit 70
fi

extension_id=019f0000-0000-7000-8000-000000000060
extension_executable_digest=$(sha256sum "$sample_extension" | awk '{print $1}')
runtime_files='[]'
while IFS= read -r runtime_file; do
  runtime_digest=$(sha256sum "$runtime_file" | awk '{print $1}')
  runtime_files=$(jq -c \
    --arg host "$runtime_file" \
    --arg digest "$runtime_digest" \
    '. + [{hostPath:$host,sandboxPath:$host,digest:$digest}]' \
    <<<"$runtime_files")
done < <(
  ldd "$sample_extension" | awk '
    index($0, "=>") {
      for (field = 1; field <= NF; field += 1) {
        if ($field == "=>" && $(field + 1) ~ /^\//) print $(field + 1)
      }
      next
    }
    $1 ~ /^\// { print $1 }
  ' | sort -u
)
if [[ $(jq 'length' <<<"$runtime_files") -eq 0 ]]; then
  echo "dashboard extension smoke found no dynamic runtime files" >&2
  exit 70
fi
extension_manifest="$home/dashboard-extension-manifest.json"
jq -n \
  --arg extension_id "$extension_id" \
  --arg executable "$(basename "$sample_extension")" \
  --arg executable_digest "$extension_executable_digest" \
  --argjson runtime_files "$runtime_files" \
  '{
    schemaVersion: 1,
    extensionId: $extension_id,
    name: "dev.mealy.dashboard-smoke",
    publisher: "dev.mealy",
    version: "1.0.0",
    kinds: ["tool_service"],
    compatibility: {minimumHostApi: 1, maximumHostApi: 1},
    entryPoint: {
      executable: $executable,
      executableDigest: $executable_digest,
      runtimeFiles: $runtime_files
    },
    capabilities: [{
      capabilityId: "health",
      kind: "health",
      effectClass: "read_only",
      riskClass: "low",
      inputSchema: {
        properties: {},
        required: [],
        additionalProperties: false,
        maximumSerializedBytes: 2
      },
      outputSchema: {
        properties: {
          status: {
            valueType: "string",
            maximumLength: 32,
            minimumInteger: null,
            maximumInteger: null
          }
        },
        required: ["status"],
        additionalProperties: false,
        maximumSerializedBytes: 64
      },
      timeoutMs: 1000,
      maximumOutputBytes: 16384
    }],
    permissions: {
      filesystem: [],
      networkDestinations: [],
      secretReferences: [],
      allowProcessSpawn: false
    },
    healthCheck: {capabilityId: "health", timeoutMs: 1000, intervalMs: 5000},
    migrations: [],
    shutdown: {mode: "terminate", capabilityId: null, gracePeriodMs: 1000}
  }' >"$extension_manifest"
extension_manifest_digest=$(sha256sum "$extension_manifest" | awk '{print $1}')
installed_extension=$(
  "$mealyctl" --home "$home" extension install \
    --manifest "$extension_manifest" \
    --digest "$extension_manifest_digest" \
    --installation-root "$binary_directory"
)
jq -e --arg extension "$extension_id" \
  '.extensionId == $extension and .status == "installed" and .revision == 0 and .activeGrant == null' \
  >/dev/null <<<"$installed_extension"

extension_without_origin=$(dashboard_curl --silent --show-error --output "$home/extension-origin-error.json" \
  --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1"}' \
  "$origin/api/extensions/list")
if [[ $extension_without_origin != 403 ]]; then
  echo "dashboard extension inventory accepted a missing Origin" >&2
  exit 70
fi
extension_inventory=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1"}' \
  "$origin/api/extensions/list")
jq -e --arg extension "$extension_id" \
  '(.extensions | length) == 1 and .extensions[0].extensionId == $extension and .extensions[0].status == "installed"' \
  >/dev/null <<<"$extension_inventory"
extension_detail=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1"}' \
  "$origin/api/extensions/$extension_id/detail")
jq -e --arg digest "$extension_manifest_digest" \
  '.status == "installed" and .manifestDigest == $digest and (.manifestHistory | length) == 1' \
  >/dev/null <<<"$extension_detail"

extension_enable_body='{"apiVersion":"v1","expectedRevision":0,"capabilityIds":["health"],"mounts":[],"networkDestinations":[],"secretReferences":[],"allowProcessSpawn":false}'
enabled_extension=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data "$extension_enable_body" \
  "$origin/api/extensions/$extension_id/enable")
jq -e '.status == "enabled" and .revision == 1 and .activeGrant.capabilityIds == ["health"] and .lastHealthyAtMs != null' \
  >/dev/null <<<"$enabled_extension"
duplicate_extension_enable=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data "$extension_enable_body" \
  "$origin/api/extensions/$extension_id/enable")
jq -e '.status == "enabled" and .revision == 1' >/dev/null <<<"$duplicate_extension_enable"

disabled_extension=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","expectedRevision":1}' \
  "$origin/api/extensions/$extension_id/disable")
jq -e '.status == "disabled" and .revision == 2 and .activeGrant == null' \
  >/dev/null <<<"$disabled_extension"
duplicate_extension_disable=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","expectedRevision":1}' \
  "$origin/api/extensions/$extension_id/disable")
jq -e '.status == "disabled" and .revision == 2' >/dev/null <<<"$duplicate_extension_disable"

reenabled_extension=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","expectedRevision":2,"capabilityIds":["health"],"mounts":[],"networkDestinations":[],"secretReferences":[],"allowProcessSpawn":false}' \
  "$origin/api/extensions/$extension_id/enable")
jq -e '.status == "enabled" and .revision == 3 and .activeGrant.capabilityIds == ["health"]' \
  >/dev/null <<<"$reenabled_extension"
revoked_extension=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","expectedRevision":3}' \
  "$origin/api/extensions/$extension_id/revoke")
jq -e '.status == "revoked" and .revision == 4 and .activeGrant == null' \
  >/dev/null <<<"$revoked_extension"
duplicate_extension_revoke=$(dashboard_curl --fail --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"v1","expectedRevision":3}' \
  "$origin/api/extensions/$extension_id/revoke")
jq -e '.status == "revoked" and .revision == 4' >/dev/null <<<"$duplicate_extension_revoke"
extension_projection="$extension_inventory$extension_detail$enabled_extension$revoked_extension"
if contains_daemon_token "$home/extension-origin-error.json" \
  || contains_daemon_token <<<"$extension_projection"; then
  echo "dashboard extension projection exposed the daemon bearer" >&2
  exit 70
fi

kill "$dashboard_pid"
wait "$dashboard_pid" 2>/dev/null || true
dashboard_pid=
"$mealyctl" --home "$home" drain >/dev/null
for _ in $(seq 1 300); do
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
if kill -0 "$daemon_pid" 2>/dev/null; then
  echo "real daemon did not complete bounded drain" >&2
  exit 70
fi
wait "$daemon_pid"
daemon_pid=

printf 'dashboard smoke: ok (schema 15, session %s, task %s, schedule %s, memory %s, extension %s)\n' \
  "$session_id" "$task_id" "$schedule_id" "$memory_id" "$extension_id"
