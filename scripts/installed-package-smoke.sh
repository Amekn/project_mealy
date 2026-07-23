#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
  echo "usage: installed-package-smoke.sh ARCHIVE SHA256SUMS INSTALLER" >&2
}

if [[ $# -ne 3 || ! -f $1 || ! -f $2 || ! -f $3 || ! -x $3 \
  || -L $1 || -L $2 || -L $3 ]]; then
  usage
  exit 64
fi

for dependency in awk chmod grep jq mktemp readlink seq sha256sum sleep; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    echo "installed-package smoke requires $dependency" >&2
    exit 69
  fi
done

archive=$(readlink -f "$1")
checksums=$(readlink -f "$2")
installer=$(readlink -f "$3")
mapfile -t installer_digests < <(
  awk '$2 == "install-mealy.sh" || $2 == "*install-mealy.sh" {print $1}' "$checksums"
)
if [[ ${#installer_digests[@]} -ne 1 \
  || ! ${installer_digests[0]} =~ ^[0-9a-f]{64}$ \
  || $(sha256sum "$installer" | awk '{print $1}') != "${installer_digests[0]}" ]]; then
  echo "release installer has no unique matching checksum" >&2
  exit 65
fi
require_sandbox=${MEALY_INSTALLED_SMOKE_REQUIRE_SANDBOX:-false}
if [[ $require_sandbox != true && $require_sandbox != false ]]; then
  echo "MEALY_INSTALLED_SMOKE_REQUIRE_SANDBOX must be true or false" >&2
  exit 64
fi
temporary_root=${MEALY_INSTALLED_SMOKE_ROOT:-${HOME-}}
if [[ -z $temporary_root || -L $temporary_root || ! -d $temporary_root \
  || ! -w $temporary_root ]]; then
  echo "installed-package smoke requires a writable real HOME or MEALY_INSTALLED_SMOKE_ROOT" >&2
  exit 69
fi
temporary=$(mktemp -d "$temporary_root/.mealy-installed-package-smoke.XXXXXX")
prefix="$temporary/prefix"
home="$temporary/home"
daemon_pid=

cleanup() {
  if [[ -n $daemon_pid ]]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  rm -rf -- "$temporary"
}
trap cleanup EXIT

"$installer" install \
  --archive "$archive" \
  --checksums "$checksums" \
  --prefix "$prefix" \
  --home "$home" \
  >/dev/null

mealyd="$prefix/bin/mealyd"
mealyctl="$prefix/bin/mealyctl"
manifest="$prefix/share/mealy/BUILD-MANIFEST.json"
version=$(jq -er '.version' "$manifest")
schema_version=$(jq -er '.stateSchemaVersion' "$manifest")
[[ -f $prefix/share/mealy/ARCHITECTURE.md ]]
[[ -f $prefix/share/mealy/REQUIREMENTS.md ]]
[[ -f $prefix/share/mealy/SECURITY.md ]]
[[ -f $prefix/share/mealy/THIRD-PARTY-LICENSES.html ]]
[[ -f $prefix/share/mealy/docs/README.md ]]
[[ -f $prefix/share/mealy/docs/CLI.md ]]
[[ -f $prefix/share/mealy/docs/REQUIREMENTS_COVERAGE.md ]]
[[ -f $prefix/share/mealy/docs/TESTING.md ]]
[[ -f $prefix/share/mealy/docs/benchmarks/README.md ]]
[[ -f $prefix/share/mealy/docs/benchmarks/release-soak-subject.json ]]
[[ -f $prefix/share/mealy/docs/decisions/README.md ]]
[[ -f $prefix/share/mealy/docs/GETTING_STARTED.md ]]
[[ -f $prefix/share/mealy/docs/research/PRODUCT_OPERATIONS_BENCHMARK_2026-07-24.md ]]
[[ -f $prefix/share/mealy/docs/research/REFERENCE_SYSTEMS.md ]]
[[ -f $prefix/share/mealy/docs/THREAT_MODEL.md ]]
[[ $("$mealyd" --version) == "mealyd $version" ]]
[[ $("$mealyctl" --version) == "mealyctl $version" ]]
[[ $("$mealyd" --print-supported-schema-version) == "$schema_version" ]]
install_status=$("$mealyctl" install-status)
jq -e --arg version "$version" --argjson schema "$schema_version" '
  .schemaVersion == "mealy.install-status.v1"
  and .installationKind == "managed-archive"
  and .integrity == "verified"
  and .currentVersion == $version
  and .stateSchemaVersion == $schema
  and .updateMode == "attested-archive"
  and .rollbackAvailable == false
  and .issues == []
' <<<"$install_status" >/dev/null
"$mealyctl" completion bash >"$temporary/mealyctl.bash"
"$mealyctl" completion zsh >"$temporary/_mealyctl"
"$mealyctl" completion fish >"$temporary/mealyctl.fish"
[[ -s $temporary/mealyctl.bash && -s $temporary/_mealyctl && -s $temporary/mealyctl.fish ]]

printf 'modified manager\n' >"$prefix/share/mealy-manager.sh"
repair_plan=$("$mealyctl" repair)
jq -e '
  .schemaVersion == "mealy.maintenance-plan.v1"
  and .operation == "repair"
  and .actionRequired == true
  and .applySupported == true
  and .preservesHome == true
  and .installation.integrity == "failed"
' <<<"$repair_plan" >/dev/null
"$mealyctl" repair --approve >"$temporary/repaired-status.json"
jq -e '.integrity == "verified" and .issues == []' \
  "$temporary/repaired-status.json" >/dev/null

mkdir -p "$home"
chmod 0700 "$home"
service=$("$mealyctl" --home "$home" service install \
  --destination "$temporary/mealy.service")
jq -e --arg daemon "$mealyd" --arg home "$home" --arg unit "$temporary/mealy.service" '
  .platform == "linux-systemd-user"
  and .daemonPath == $daemon
  and .home == $home
  and .serviceDefinition == $unit
  and (.activationCommand | contains("systemctl --user link"))
  and (.activationCommand | contains("systemctl --user enable --now mealy.service"))
' <<<"$service" >/dev/null
grep -Fqx 'RestartPreventExitStatus=2' "$temporary/mealy.service"
grep -Fqx 'UMask=0077' "$temporary/mealy.service"
grep -Fqx 'NoNewPrivileges=true' "$temporary/mealy.service"
grep -Fqx "ExecStart=\"$mealyd\" --home \"$home\"" "$temporary/mealy.service"
if grep -Fq 'ExecStart=/usr/bin/bwrap' "$temporary/mealy.service"; then
  echo "installed service prevents per-tool Bubblewrap" >&2
  exit 65
fi
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
grep -Fqx 'MemoryMax=1536M' "$temporary/mealy.service"
grep -Fqx 'MemorySwapMax=0' "$temporary/mealy.service"
grep -Fqx 'TasksMax=384' "$temporary/mealy.service"

"$mealyd" \
  --home "$home" \
  --promotion-interval-ms 10 \
  --outbox-delay-ms 0 \
  --agent-delay-ms 10 \
  --fake-provider-delay-ms 10 \
  >"$temporary/daemon.stdout" 2>"$temporary/daemon.stderr" &
daemon_pid=$!

for _ in $(seq 1 400); do
  if [[ -s $home/connection.json ]] \
    && "$mealyctl" --home "$home" health >"$temporary/health.json" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "installed mealyd exited before becoming live" >&2
    exit 70
  fi
  sleep 0.05
done
jq -e '.apiVersion == "v1" and .live == true' "$temporary/health.json" >/dev/null

"$mealyctl" --home "$home" doctor >"$temporary/doctor.json"
jq -e --arg schema "$schema_version" '
  .apiVersion == "v1"
  and .controlPlaneReady == true
  and (.checks.sqlite | contains("schema " + $schema + " "))
' "$temporary/doctor.json" >/dev/null
if [[ $require_sandbox == true ]]; then
  jq -e '
    .sandboxAvailable == true
    and any(.sandboxProfiles[]; .profile == "observe" and .status == "enforceable")
    and any(.sandboxProfiles[]; .profile == "workspace_write" and .status == "enforceable")
  ' "$temporary/doctor.json" >/dev/null
fi
"$mealyctl" --home "$home" status >"$temporary/status.json"
jq -e --argjson schema "$schema_version" '
  .apiVersion == "v1"
  and .runStatus == "running"
  and .schemaVersion == $schema
  and .safeMode == false
' "$temporary/status.json" >/dev/null

session=$("$mealyctl" --home "$home" session create)
session_id=$(jq -er '.sessionId' <<<"$session")
request="installed package runtime smoke $session_id"
admission=$("$mealyctl" --home "$home" session send "$session_id" "$request" \
  --idempotency-key installed-package-runtime-smoke-1)
jq -e --arg session "$session_id" '
  .apiVersion == "v1"
  and .sessionId == $session
  and .duplicate == false
  and .inboxSequence == 1
' <<<"$admission" >/dev/null

task_id=
for _ in $(seq 1 600); do
  search=$("$mealyctl" --home "$home" session search --limit 1 "$request")
  task_id=$(jq -r '.hits[0].taskId // empty' <<<"$search")
  if [[ -n $task_id ]]; then
    task=$("$mealyctl" --home "$home" task status "$task_id")
    status=$(jq -r '.status' <<<"$task")
    if [[ $status == succeeded || $status == failed || $status == cancelled ]]; then
      break
    fi
  fi
  sleep 0.05
done
if [[ -z $task_id ]]; then
  echo "installed package did not publish a canonical task" >&2
  exit 70
fi
jq -e --arg task "$task_id" '
  .apiVersion == "v1"
  and .taskId == $task
  and .status == "succeeded"
  and (.finalResponse | type == "string" and length > 0)
  and .usage.reservedModelCalls == 0
  and .usage.reservedToolCalls == 0
  and .usage.reservedDelegatedRuns == 0
  and .usage.reservedCostMicrounits == 0
' <<<"$task" >/dev/null

replay=$("$mealyctl" --home "$home" task replay "$task_id")
jq -e --arg task "$task_id" '
  .apiVersion == "v1"
  and .taskId == $task
  and .mode == "recorded_only"
  and .evidenceComplete == true
  and .liveProviderCalls == 0
  and .liveToolCalls == 0
' <<<"$replay" >/dev/null

usage=$("$mealyctl" --home "$home" usage --days 1)
jq -e '
  .apiVersion == "v1"
  and (.toMs - .fromMs) == 86400000
  and ([.buckets[].completedRuns] | add // 0) >= 1
  and ([.buckets[].failedRuns] | add // 0) == 0
' <<<"$usage" >/dev/null

backup=$("$mealyctl" --home "$home" backup installed-package-smoke)
backup_digest=$(jq -er '.manifestDigest' <<<"$backup")
jq -e --argjson schema "$schema_version" '
  .apiVersion == "v1"
  and .name == "installed-package-smoke"
  and .schemaVersion == $schema
  and .fileCount >= 2
  and .totalBytes > 0
  and .secretsIncluded == false
' <<<"$backup" >/dev/null
verification=$("$mealyctl" --home "$home" restore-verify installed-package-smoke)
jq -e --arg digest "$backup_digest" --argjson schema "$schema_version" '
  .apiVersion == "v1"
  and .name == "installed-package-smoke"
  and .manifestDigest == $digest
  and .schemaVersion == $schema
  and .identityVerified == false
  and .secretsIncluded == false
' <<<"$verification" >/dev/null

drain=$("$mealyctl" --home "$home" drain)
jq -e '.apiVersion == "v1" and .newlyRequested == true and .deadlineMs > 0' \
  <<<"$drain" >/dev/null
for _ in $(seq 1 400); do
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
if kill -0 "$daemon_pid" 2>/dev/null; then
  echo "installed mealyd did not complete its bounded drain" >&2
  exit 70
fi
wait "$daemon_pid"
daemon_pid=

"$mealyctl" --home "$home" uninstall --approve >/dev/null
[[ ! -e $prefix/bin/mealyd && ! -e $prefix/bin/mealyctl ]]
[[ -f $home/mealy.sqlite3 ]]

echo "installed package smoke: ok (version $version, schema $schema_version, task $task_id)"
