#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
renderer=$repository_root/scripts/render-release-notes.sh
source_report=$repository_root/docs/benchmarks/2026-07-13-storage-optimized-soak.json

for command in cmp grep jq mktemp; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required release-note test command is unavailable: $command" >&2
    exit 69
  }
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-release-note-test.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
revision=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
daemon_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
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
  | .requestedDurationSeconds = 86400
  | .observedDurationMs = 86401234
  | .sessions = 8
  | .rounds = 10
  | .completedTurns = 80
  | .hardRestarts = 2
  | .interruptedProviderTurns = 1
  | .retriedReadToolTurns = 1
  | .resumedUndispatchedModelTurns = 0
  | .resumedUndispatchedReadToolTurns = 0
  | .duplicateAdmissions = 5
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

render() {
  local report=$1
  local output=$2
  local tag=${3:-v0.1.0}
  local live_url=${4:-https://github.com/Amekn/project_mealy/actions/runs/123}
  "$renderer" "$report" Amekn/project_mealy "$tag" "$commit" \
    "$live_url" https://github.com/Amekn/project_mealy/actions/runs/456 "$output"
}

render "$valid" "$temporary/first.md"
render "$valid" "$temporary/second.md"
cmp "$temporary/first.md" "$temporary/second.md"
grep -Fq "# Mealy v0.1.0" "$temporary/first.md"
grep -Fq "$commit" "$temporary/first.md"
grep -Fq "$revision" "$temporary/first.md"
grep -Fq "$daemon_sha256" "$temporary/first.md"
grep -Fq "86401 observed seconds (86401234 ms)" "$temporary/first.md"
grep -Fq "80 completed turns across 8 sessions and 10 rounds" "$temporary/first.md"
grep -Fq "live-provider run](https://github.com/Amekn/project_mealy/actions/runs/123)" \
  "$temporary/first.md"

expect_rejection() {
  local name=$1
  local filter=$2
  local candidate=$temporary/$name.json
  jq "$filter" "$valid" >"$candidate"
  if render "$candidate" "$temporary/$name.md" \
    >"$temporary/$name.stdout" 2>"$temporary/$name.stderr"; then
    echo "release-note renderer accepted invalid $name evidence" >&2
    exit 1
  fi
}

expect_rejection short-duration '.requestedDurationSeconds = 86399'
expect_rejection dirty-source '.sourceState = "dirty_worktree"'
expect_rejection incomplete-turns '.completedTurns = 79'
expect_rejection corrupt-store '.sqliteIntegrity = "malformed"'
expect_rejection residual-work '.residual.nonterminalRuns = 1'

if render "$valid" "$temporary/wrong-tag.md" v0.1.1 \
  >"$temporary/wrong-tag.stdout" 2>"$temporary/wrong-tag.stderr"; then
  echo "release-note renderer accepted a tag/report version mismatch" >&2
  exit 1
fi
if render "$valid" "$temporary/wrong-run.md" v0.1.0 \
  https://github.com/another/project/actions/runs/123 \
  >"$temporary/wrong-run.stdout" 2>"$temporary/wrong-run.stderr"; then
  echo "release-note renderer accepted a foreign workflow URL" >&2
  exit 1
fi

echo "release notes: ok"
