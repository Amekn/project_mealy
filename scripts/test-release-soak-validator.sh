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

lineage_repository=$temporary/lineage-repository
mkdir -p "$lineage_repository/apps/mealyd/src" "$lineage_repository/docs"
git -C "$lineage_repository" init -q
git -C "$lineage_repository" config user.name Mealy
git -C "$lineage_repository" config user.email mealy@example.invalid
printf '[workspace]\nmembers = ["apps/mealyd"]\n' >"$lineage_repository/Cargo.toml"
printf '# lock fixture\n' >"$lineage_repository/Cargo.lock"
printf 'fn main() {}\n' >"$lineage_repository/apps/mealyd/src/main.rs"
git -C "$lineage_repository" add Cargo.toml Cargo.lock apps/mealyd/src/main.rs
git -C "$lineage_repository" commit -qm 'observed source revision'
lineage_observed_revision=$(git -C "$lineage_repository" rev-parse HEAD)
lineage_tree=$(git -C "$lineage_repository" rev-parse "${lineage_observed_revision}^{tree}")
lineage_release_revision=$(printf 'rebased identical source\n' \
  | git -C "$lineage_repository" commit-tree "$lineage_tree")
git -C "$lineage_repository" update-ref refs/heads/release-lineage \
  "$lineage_release_revision"
git -C "$lineage_repository" symbolic-ref HEAD refs/heads/release-lineage
printf 'release evidence only\n' >"$lineage_repository/docs/release.md"
git -C "$lineage_repository" add docs/release.md
git -C "$lineage_repository" commit -qm 'record release evidence'
lineage_expected_revision=$(git -C "$lineage_repository" rev-parse HEAD)

lineage_valid=$temporary/lineage-valid.json
jq --arg revision "$lineage_observed_revision" '.revision = $revision' \
  "$valid" >"$lineage_valid"
lineage_valid_sha256=$(sha256sum "$lineage_valid")
lineage_valid_sha256=${lineage_valid_sha256%% *}
lineage_observed_payload=$temporary/lineage-observed-commit.txt
git -C "$lineage_repository" cat-file commit "$lineage_observed_revision" \
  >"$lineage_observed_payload"
lineage_proof=$temporary/lineage-valid-proof.json
jq -n \
  --arg report_sha256 "$lineage_valid_sha256" \
  --arg observed_revision "$lineage_observed_revision" \
  --arg observed_tree "$lineage_tree" \
  --rawfile observed_payload "$lineage_observed_payload" \
  --arg release_revision "$lineage_release_revision" '
  {
    schemaVersion: "mealy.soak-lineage.v1",
    reportSha256: $report_sha256,
    observedRevision: $observed_revision,
    observedGitTree: $observed_tree,
    observedCommitPayload: $observed_payload,
    releaseLineageRevision: $release_revision,
    releaseLineageGitTree: $observed_tree,
    transformation: "github_rebase_merge"
  }
  ' >"$lineage_proof"

(cd "$lineage_repository" \
  && "$validator" "$lineage_valid" "$mealyd" "$lineage_expected_revision" \
    "$lineage_proof") \
  >/dev/null
if (cd "$lineage_repository" \
  && "$validator" "$lineage_valid" "$mealyd" "$lineage_expected_revision") \
  >"$temporary/missing-lineage.stdout" 2>"$temporary/missing-lineage.stderr"; then
  echo "release soak validator accepted a non-ancestor report without lineage proof" >&2
  exit 1
fi

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

expect_lineage_rejection() {
  local name=$1
  local filter=$2
  local candidate=$temporary/$name.json
  jq "$filter" "$lineage_proof" >"$candidate"
  if (cd "$lineage_repository" \
    && "$validator" "$lineage_valid" "$mealyd" "$lineage_expected_revision" \
      "$candidate") \
    >"$temporary/$name.stdout" 2>"$temporary/$name.stderr"; then
    echo "release soak validator accepted invalid $name lineage evidence" >&2
    exit 1
  fi
}

expect_lineage_rejection lineage-wrong-report '.reportSha256 = ("0" * 64)'
expect_lineage_rejection lineage-wrong-observed-revision '.observedRevision = ("0" * 40)'
expect_lineage_rejection lineage-altered-commit-payload '.observedCommitPayload += "x"'
expect_lineage_rejection lineage-wrong-release-revision \
  '.releaseLineageRevision = ("0" * 40)'
expect_lineage_rejection lineage-wrong-release-tree '.releaseLineageGitTree = ("0" * 40)'
expect_lineage_rejection lineage-wrong-transformation '.transformation = "manual_relabel"'
expect_lineage_rejection lineage-extra-field '.unexpected = true'

source_repository=$temporary/source-gate-repository
mkdir -p "$source_repository/apps/mealyd/src" "$source_repository/docs"
git -C "$source_repository" init -q
printf '[workspace]\nmembers = ["apps/mealyd"]\n' >"$source_repository/Cargo.toml"
printf '# lock fixture\n' >"$source_repository/Cargo.lock"
printf 'fn main() {}\n' >"$source_repository/apps/mealyd/src/main.rs"
git -C "$source_repository" add Cargo.toml Cargo.lock apps/mealyd/src/main.rs
git -C "$source_repository" -c user.name=Mealy -c user.email=mealy@example.invalid \
  commit -qm 'observed runtime source'
source_revision=$(git -C "$source_repository" rev-parse HEAD)
source_gate_report=$temporary/source-gate-report.json
jq --arg revision "$source_revision" '.revision = $revision' \
  "$valid" >"$source_gate_report"

printf 'release evidence only\n' >"$source_repository/docs/release.md"
git -C "$source_repository" add docs/release.md
git -C "$source_repository" -c user.name=Mealy -c user.email=mealy@example.invalid \
  commit -qm 'record release evidence'
documentation_revision=$(git -C "$source_repository" rev-parse HEAD)
(cd "$source_repository" \
  && "$validator" "$source_gate_report" "$mealyd" "$documentation_revision") >/dev/null

printf 'fn main() { println!("changed"); }\n' \
  >"$source_repository/apps/mealyd/src/main.rs"
git -C "$source_repository" add apps/mealyd/src/main.rs
git -C "$source_repository" -c user.name=Mealy -c user.email=mealy@example.invalid \
  commit -qm 'change runtime source'
changed_runtime_revision=$(git -C "$source_repository" rev-parse HEAD)
if (cd "$source_repository" \
  && "$validator" "$source_gate_report" "$mealyd" "$changed_runtime_revision") \
  >"$temporary/changed-runtime.stdout" 2>"$temporary/changed-runtime.stderr"; then
  echo "release soak validator accepted changed runtime source inputs" >&2
  exit 1
fi

echo "release soak validator: ok"
