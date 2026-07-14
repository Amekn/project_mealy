#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
validator=$repository_root/scripts/validate-release-soak.sh
source_report=$repository_root/docs/benchmarks/2026-07-13-storage-optimized-soak.json

for command in git jq mktemp sha256sum; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required release-soak test command is unavailable: $command" >&2
    exit 69
  }
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-release-soak-test.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

mealyd=$temporary/mealyd
printf '#!/usr/bin/env bash\nprintf "mealyd 0.1.0\\n"\n' >"$mealyd"
chmod 0755 "$mealyd"
daemon_sha256=$(sha256sum "$mealyd")
daemon_sha256=${daemon_sha256%% *}
revision=$(git -C "$repository_root" rev-parse HEAD)
valid=$temporary/valid.json

jq \
  --arg revision "$revision" \
  --arg daemon_sha256 "$daemon_sha256" '
  .schemaVersion = "mealy.soak-report.v2"
  | .revision = $revision
  | .sourceState = "clean_revision"
  | .mealyVersion = "0.1.0"
  | .harnessMode = "external_release_binary"
  | .daemonBinarySha256 = $daemon_sha256
  | .homeStorage = {"mode": "retained", "filesystem": "ext4"}
  | .buildProfile = "release"
  | .target = {
      "os": "linux",
      "architecture": "x86_64",
      "logicalCpus": 4,
      "cpuModel": "release-validator-fixture",
      "hostMemoryKiB": 1048576
    }
  | .startedAtUnixMs = 1000
  | .finishedAtUnixMs = 86402000
  | .requestedDurationSeconds = 86400
  | .observedDurationMs = 86401000
  | .sessions = 8
  | .rounds = 10
  | .completedTurns = 80
  | .completedTurnsPerMinute = 1
  | .hardRestarts = 2
  | .interruptedProviderTurns = 1
  | .retriedReadToolTurns = 1
  | .resumedUndispatchedModelTurns = 0
  | .resumedUndispatchedReadToolTurns = 0
  | .duplicateAdmissions = 5
  | .providerDelayMs = 250
  | .roundIntervalMs = 30000
  | .latencyMs = {
      "minimum": 100,
      "mean": 200,
      "p50": 180,
      "p95": 300,
      "p99": 400,
      "maximum": 500
    }
  | .peakResidentSetKiB = 1024
  | .databaseBytesIncludingSidecars = 4096
  | .databaseBytesPerCompletedTurn = 51
  | .artifactBytes = 0
  | .sqliteIntegrity = "ok"
  | .residual = {
      "pendingInputs": 0,
      "nonterminalRuns": 0,
      "activeLeases": 0,
      "pendingApprovals": 0,
      "unknownEffects": 0,
      "failedOutbox": 0
    }
  ' "$source_report" >"$valid"

(cd "$repository_root" && "$validator" "$valid" "$mealyd" "$revision") >/dev/null

expect_rejection() {
  local name=$1
  local filter=$2
  local candidate=$temporary/$name.json
  jq "$filter" "$valid" >"$candidate"
  if (cd "$repository_root" && "$validator" "$candidate" "$mealyd" "$revision") \
    >"$temporary/$name.stdout" 2>"$temporary/$name.stderr"; then
    echo "release soak validator accepted invalid $name evidence" >&2
    exit 1
  fi
}

expect_rejection short-duration '.requestedDurationSeconds = 86399'
expect_rejection dirty-source '.sourceState = "dirty_worktree"'
expect_rejection wrong-daemon '.daemonBinarySha256 = ("0" * 64)'
expect_rejection volatile-home '.homeStorage.filesystem = "tmpfs"'
expect_rejection residual-work '.residual.nonterminalRuns = 1'
expect_rejection incomplete-turns '.completedTurns = 79'
expect_rejection missing-recovery '.interruptedProviderTurns = 0 | .retriedReadToolTurns = 0'
expect_rejection corrupt-store '.sqliteIntegrity = "malformed"'

echo "release soak validator: ok"
