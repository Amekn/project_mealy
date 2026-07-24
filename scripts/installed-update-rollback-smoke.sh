#!/usr/bin/env bash

# Prove that an already-qualified recovery helper can restore a real installed release after a
# newer, checksum-valid package activates but cannot become ready. The candidate client is
# deliberately unusable: rollback identity must come from the old helper's independent payload
# inspection, never from executing candidate code.

set -euo pipefail
export LC_ALL=C
umask 077

if [[ $# -ne 2 ]]; then
  echo "usage: $0 PATH_TO_RELEASE_MEALYD PATH_TO_RELEASE_MEALYCTL" >&2
  exit 64
fi
if [[ $(uname -s) != Linux ]]; then
  echo "the installed update rollback smoke is Linux-only" >&2
  exit 69
fi
for command in awk chmod date dirname find git grep gzip install journalctl jq mkdir mktemp od \
  readlink realpath rm seq sha256sum sleep sort stat systemctl tar timeout tr uname wc; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "installed update rollback smoke requires $command" >&2
    exit 69
  fi
done
if [[ ! -x /usr/bin/sleep ]]; then
  echo "installed update rollback smoke requires canonical /usr/bin/sleep" >&2
  exit 69
fi
if [[ ! -d /run/systemd/system ]]; then
  echo "the host system manager is not systemd" >&2
  exit 69
fi

isolated_environment=false
if [[ -f /.dockerenv || -f /run/.containerenv ]]; then
  isolated_environment=true
elif command -v systemd-detect-virt >/dev/null 2>&1 \
  && systemd-detect-virt --quiet --container; then
  isolated_environment=true
fi
if [[ $isolated_environment != true \
  && ${MEALY_UPDATE_ROLLBACK_SMOKE_ALLOW_HOST-} != true ]]; then
  echo "refusing to mutate a non-isolated systemd user manager" >&2
  echo "run this proof in a disposable host, or explicitly set MEALY_UPDATE_ROLLBACK_SMOKE_ALLOW_HOST=true" >&2
  exit 73
fi

systemctl_user() {
  timeout --foreground --signal=TERM --kill-after=5 30 systemctl --user "$@"
}

if ! systemctl_user show-environment >/dev/null 2>&1; then
  echo "the current user has no reachable systemd user manager" >&2
  exit 69
fi
if systemctl_user cat mealy.service >/dev/null 2>&1; then
  echo "refusing to replace an existing mealy.service in this user manager" >&2
  exit 73
fi

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
old_mealyd=$(realpath -- "$1")
old_mealyctl=$(realpath -- "$2")
if [[ ! -f $old_mealyd || ! -x $old_mealyd || ! -f $old_mealyctl \
  || ! -x $old_mealyctl || -L $old_mealyd || -L $old_mealyctl \
  || $(dirname -- "$old_mealyd") != "$(dirname -- "$old_mealyctl")" ]]; then
  echo "both supplied release binaries must be executable regular files installed side by side" >&2
  exit 66
fi
old_version=$("$old_mealyctl" --version)
old_version=${old_version#mealyctl }
if [[ ! $old_version =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "the qualified client does not report a stable release version" >&2
  exit 65
fi
candidate_version="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.$((10#${BASH_REMATCH[3]} + 1))"
schema_version=$("$old_mealyd" --print-supported-schema-version)
if [[ ! $schema_version =~ ^[1-9][0-9]{0,3}$ ]]; then
  echo "the qualified daemon reports an invalid state schema" >&2
  exit 65
fi
case $(uname -m) in
  x86_64 | amd64) target=linux-x86_64-gnu ;;
  aarch64 | arm64) target=linux-aarch64-gnu ;;
  *)
    echo "unsupported Linux architecture: $(uname -m)" >&2
    exit 65
    ;;
esac

old_commit=$(git -C "$repository_root" rev-parse --verify HEAD)
source_date_epoch=$(git -C "$repository_root" show -s --format=%ct HEAD)
if [[ ! $old_commit =~ ^[0-9a-f]{40}$ || ! $source_date_epoch =~ ^[0-9]+$ ]]; then
  echo "could not derive the checked source identity" >&2
  exit 65
fi
candidate_commit=$(printf 'f%.0s' {1..40})
if [[ $candidate_commit == "$old_commit" ]]; then
  candidate_commit=$(printf 'e%.0s' {1..40})
fi

temporary=$(mktemp -d "$HOME/.mealy-update-rollback-smoke.XXXXXX")
prefix="$temporary/prefix"
home="$temporary/home"
default_unit="$HOME/.config/systemd/user/mealy.service"
direct_pid=

cleanup() {
  status=$?
  trap - EXIT
  set +e
  if [[ $status -ne 0 ]]; then
    systemctl --user status mealy.service --no-pager >&2
    journalctl --user -u mealy.service -n 100 --no-pager >&2
  fi
  systemctl --user disable --now mealy.service >/dev/null 2>&1
  if [[ -f $default_unit ]] \
    && grep -Fq "ExecStart=\"$prefix/bin/mealyd\" --home \"$home\"" "$default_unit"; then
    rm -f -- "$default_unit"
  fi
  systemctl --user daemon-reload >/dev/null 2>&1
  systemctl --user reset-failed mealy.service >/dev/null 2>&1
  if [[ -n $direct_pid ]] && kill -0 "$direct_pid" 2>/dev/null; then
    kill "$direct_pid" 2>/dev/null
    wait "$direct_pid" 2>/dev/null
  fi
  rm -rf -- "$temporary"
  exit "$status"
}
trap cleanup EXIT

make_sbom() {
  local destination=$1
  local version=$2
  local commit=$3
  local timestamp
  timestamp=$(date --utc --date="@$source_date_epoch" '+%Y-%m-%dT%H:%M:%SZ')
  jq -n \
    --arg version "$version" \
    --arg target "$target" \
    --arg commit "$commit" \
    --arg timestamp "$timestamp" '{
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      serialNumber: "urn:uuid:00000000-0000-4000-8000-000000000001",
      version: 1,
      metadata: {
        timestamp: $timestamp,
        component: {
          type: "application",
          name: "mealy",
          version: $version,
          properties: [
            {name: "mealy:release:target", value: $target},
            {name: "mealy:release:commit", value: $commit}
          ]
        }
      },
      components: [{type: "application", name: "mealy", version: $version}]
    }' >"$destination"
}

old_binary_directory=$(dirname -- "$old_mealyctl")
candidate_binary_directory="$temporary/candidate-bin"
old_package_directory="$temporary/old-package"
candidate_package_directory="$temporary/candidate-package"
mkdir -p -- "$candidate_binary_directory" "$old_package_directory" \
  "$candidate_package_directory"
printf '%s\n' \
  '#!/bin/sh' \
  "case \${1-} in" \
  "  --version) printf '%s\\n' 'mealyd $candidate_version' ;;" \
  "  --print-supported-schema-version) printf '%s\\n' '$schema_version' ;;" \
  '  *) exec /usr/bin/sleep 45 ;;' \
  'esac' >"$candidate_binary_directory/mealyd"
printf '%s\n' \
  '#!/bin/sh' \
  "case \${1-} in" \
  "  --version) printf '%s\\n' 'mealyctl $candidate_version' ;;" \
  '  *) exit 78 ;;' \
  'esac' >"$candidate_binary_directory/mealyctl"
chmod 0755 "$candidate_binary_directory/mealyd" "$candidate_binary_directory/mealyctl"

make_sbom "$temporary/old-sbom.json" "$old_version" "$old_commit"
make_sbom "$temporary/candidate-sbom.json" "$candidate_version" "$candidate_commit"
{
  printf '<h1>Mealy third-party licenses</h1>\n<pre>\n'
  for _ in $(seq 1 64); do
    printf 'Deterministic third-party license fixture for installed rollback acceptance.\n'
  done
  printf '</pre>\n'
} >"$temporary/third-party-licenses.html"

"$repository_root/packaging/build-release.sh" \
  "$old_version" "$target" "$old_binary_directory" "$temporary/old-sbom.json" \
  "$temporary/third-party-licenses.html" "$old_package_directory" "$old_commit" \
  "$source_date_epoch" "$schema_version" >/dev/null
"$repository_root/packaging/build-release.sh" \
  "$candidate_version" "$target" "$candidate_binary_directory" \
  "$temporary/candidate-sbom.json" "$temporary/third-party-licenses.html" \
  "$candidate_package_directory" "$candidate_commit" "$source_date_epoch" \
  "$schema_version" >/dev/null

old_archive="$old_package_directory/mealy-v${old_version}-${target}.tar.gz"
candidate_archive="$candidate_package_directory/mealy-v${candidate_version}-${target}.tar.gz"
"$old_package_directory/install-mealy.sh" install \
  --archive "$old_archive" \
  --checksums "$old_package_directory/SHA256SUMS" \
  --prefix "$prefix" \
  --home "$home" >/dev/null

installed_mealyd="$prefix/bin/mealyd"
installed_mealyctl="$prefix/bin/mealyctl"
mkdir -m 0700 -- "$home"
"$installed_mealyd" \
  --home "$home" \
  --promotion-interval-ms 10 \
  --outbox-delay-ms 0 \
  --agent-delay-ms 10 \
  --fake-provider-delay-ms 10 \
  >"$temporary/direct.stdout" 2>"$temporary/direct.stderr" &
direct_pid=$!
for _ in $(seq 1 400); do
  if "$installed_mealyctl" --home "$home" health >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
"$installed_mealyctl" --home "$home" health >/dev/null
"$installed_mealyctl" --home "$home" drain >/dev/null
wait "$direct_pid"
direct_pid=

service=$("$installed_mealyctl" --home "$home" service install)
jq -e \
  --arg daemon "$installed_mealyd" \
  --arg home "$home" \
  --arg unit "$default_unit" '
    .daemonPath == $daemon
    and .home == $home
    and .serviceDefinition == $unit
  ' <<<"$service" >/dev/null
systemctl_user daemon-reload
systemctl_user enable --now mealy.service >/dev/null
for _ in $(seq 1 600); do
  if "$installed_mealyctl" --home "$home" health >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
"$installed_mealyctl" --home "$home" health >/dev/null
"$installed_mealyctl" --home "$home" doctor \
  | jq -e '.controlPlaneReady == true and .sandboxAvailable == true' >/dev/null

session=$("$installed_mealyctl" --home "$home" session create)
session_id=$(jq -er '.sessionId' <<<"$session")
marker="installed rollback acceptance $session_id"
"$installed_mealyctl" --home "$home" session send "$session_id" "$marker" \
  --idempotency-key installed-update-rollback-1 >/dev/null
task_id=
for _ in $(seq 1 600); do
  search=$("$installed_mealyctl" --home "$home" session search --limit 1 "$marker")
  task_id=$(jq -r '.hits[0].taskId // empty' <<<"$search")
  if [[ -n $task_id ]]; then
    task=$("$installed_mealyctl" --home "$home" task status "$task_id")
    if [[ $(jq -r '.status' <<<"$task") == succeeded ]]; then
      break
    fi
  fi
  sleep 0.05
done
if [[ -z $task_id ]] || [[ $(jq -r '.status' <<<"$task") != succeeded ]]; then
  echo "the installed prior release did not complete its durable acceptance turn" >&2
  exit 70
fi

milliseconds=$(date +%s%3N)
printf -v timestamp_hex '%012x' "$milliseconds"
random_hex=$(od -An -N9 -tx1 /dev/urandom | tr -d ' \n')
if [[ ! $timestamp_hex =~ ^[0-9a-f]{12}$ || ! $random_hex =~ ^[0-9a-f]{18}$ ]]; then
  echo "could not construct the UUIDv7 transaction identity" >&2
  exit 70
fi
transaction_id="${timestamp_hex:0:8}-${timestamp_hex:8:4}-7${random_hex:0:3}-a${random_hex:3:3}-${random_hex:6:12}"
backup_name="pre-update-$transaction_id"
backup=$("$installed_mealyctl" --home "$home" backup "$backup_name")
backup_digest=$(jq -er '.manifestDigest' <<<"$backup")
jq -e \
  --arg name "$backup_name" \
  --arg digest "$backup_digest" \
  --argjson schema "$schema_version" '
    .name == $name
    and .manifestDigest == $digest
    and .schemaVersion == $schema
    and .secretsIncluded == false
  ' <<<"$backup" >/dev/null

transaction_directory="$home/update-transactions"
helper="$transaction_directory/$transaction_id.helper"
transaction_path="$transaction_directory/$transaction_id.json"
mkdir -m 0700 -- "$transaction_directory"
install -m 0500 "$installed_mealyctl" "$helper"
helper_digest=$(sha256sum "$helper" | awk '{print $1}')
service_fragment=$(realpath -- "$default_unit")

"$installed_mealyctl" --home "$home" drain >/dev/null
for _ in $(seq 1 600); do
  if ! systemctl_user is-active --quiet mealy.service \
    && [[ ! -e $home/connection.json ]]; then
    break
  fi
  sleep 0.05
done
if systemctl_user is-active --quiet mealy.service || [[ -e $home/connection.json ]]; then
  echo "the prior owner service did not stop cleanly before candidate activation" >&2
  exit 70
fi

"$candidate_package_directory/install-mealy.sh" install \
  --archive "$candidate_archive" \
  --checksums "$candidate_package_directory/SHA256SUMS" \
  --prefix "$prefix" \
  --home "$home" >/dev/null

jq -n \
  --arg transaction "$transaction_id" \
  --arg home "$home" \
  --arg prefix "$prefix" \
  --arg fragment "$service_fragment" \
  --arg helper "$helper" \
  --arg helper_digest "$helper_digest" \
  --arg previous_version "$old_version" \
  --arg previous_commit "$old_commit" \
  --arg candidate_version "$candidate_version" \
  --arg target "$target" \
  --arg candidate_commit "$candidate_commit" \
  --arg backup_name "$backup_name" \
  --arg backup_digest "$backup_digest" \
  --argjson schema "$schema_version" '{
    schemaVersion: "mealy.update-transaction.v1",
    transactionId: $transaction,
    phase: "verifying",
    home: $home,
    prefix: $prefix,
    serviceFragment: $fragment,
    helperExecutable: $helper,
    helperSha256: $helper_digest,
    previousVersion: $previous_version,
    previousCommit: $previous_commit,
    candidate: {
      schemaVersion: "mealy.update-check.v1",
      version: $candidate_version,
      target: $target,
      commit: $candidate_commit,
      stateSchemaVersion: $schema,
      verified: true
    },
    backup: {
      name: $backup_name,
      manifestDigest: $backup_digest,
      stateSchemaVersion: $schema
    },
    rollbackAttempted: false
  }' >"$temporary/transaction.json"
install -m 0600 "$temporary/transaction.json" "$transaction_path"

systemctl_user start --no-block mealy.service
for _ in $(seq 1 200); do
  if systemctl_user is-active --quiet mealy.service; then
    break
  fi
  sleep 0.05
done
if ! systemctl_user is-active --quiet mealy.service; then
  echo "the deliberately unready candidate did not remain active for qualification" >&2
  exit 70
fi

timeout --foreground --signal=TERM --kill-after=5 120 \
  "$helper" --home "$home" update-transaction "$transaction_id" \
  >"$temporary/helper-result.json"
jq -e \
  --arg transaction "$transaction_id" \
  --arg candidate "$candidate_version" '
    .transactionId == $transaction
    and .phase == "rolled-back"
    and .candidate.version == $candidate
    and .failure == "updated-service-qualification-failed"
    and .rollbackAttempted == true
  ' "$temporary/helper-result.json" >/dev/null
jq -e \
  --arg transaction "$transaction_id" \
  --arg candidate "$candidate_version" '
    .transactionId == $transaction
    and .phase == "rolled-back"
    and .candidate.version == $candidate
    and .failure == "updated-service-qualification-failed"
    and .rollbackAttempted == true
  ' "$transaction_path" >/dev/null
[[ ! -e $helper ]]

install_status=$("$prefix/bin/mealyctl" install-status)
jq -e \
  --arg version "$old_version" \
  --arg commit "$old_commit" \
  --argjson schema "$schema_version" '
    .installationKind == "managed-archive"
    and .integrity == "verified"
    and .currentVersion == $version
    and .currentCommit == $commit
    and .stateSchemaVersion == $schema
    and .rollbackAvailable == true
    and .issues == []
  ' <<<"$install_status" >/dev/null
systemctl_user is-active --quiet mealy.service
"$prefix/bin/mealyctl" --home "$home" health >/dev/null
"$prefix/bin/mealyctl" --home "$home" doctor \
  | jq -e '.controlPlaneReady == true and .sandboxAvailable == true' >/dev/null
search=$("$prefix/bin/mealyctl" --home "$home" session search --limit 1 "$marker")
jq -e --arg session "$session_id" --arg task "$task_id" '
  .hits[0].sessionId == $session and .hits[0].taskId == $task
' <<<"$search" >/dev/null
"$prefix/bin/mealyctl" --home "$home" restore-verify "$backup_name" \
  | jq -e \
    --arg digest "$backup_digest" \
    --argjson schema "$schema_version" '
      .manifestDigest == $digest
      and .schemaVersion == $schema
      and .secretsIncluded == false
    ' >/dev/null

removal=$("$prefix/bin/mealyctl" --home "$home" service remove --approve)
jq -e '.removed == true and .preservesHome == true and .actionRequired == false' \
  <<<"$removal" >/dev/null
[[ ! -e $default_unit && ! -L $default_unit && -f $home/mealy.sqlite3 ]]

jq -n \
  --arg previous "$old_version" \
  --arg candidate "$candidate_version" \
  --arg transaction "$transaction_id" \
  --arg task "$task_id" '{
    installedUpdateRollbackPassed: true,
    previousVersion: $previous,
    rejectedCandidateVersion: $candidate,
    transactionId: $transaction,
    preservedTaskId: $task
  }'
