#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: validate-release-soak.sh REPORT.json MEALYD EXPECTED_COMMIT [LINEAGE.json]" >&2
}

if [[ $# -lt 3 || $# -gt 4 ]]; then
  usage
  exit 64
fi

report=$1
mealyd=$2
expected_commit=$3
lineage=${4-}

for command in git jq sha256sum stat; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required release-soak validation command is unavailable: $command" >&2
    exit 69
  }
done

if [[ -L $report || ! -f $report || -L $mealyd || ! -f $mealyd || ! -x $mealyd \
  || ! $expected_commit =~ ^[0-9a-f]{40}$ \
  || ( -n $lineage && ( -L $lineage || ! -f $lineage ) ) ]]; then
  usage
  exit 64
fi

report_bytes=$(stat -c '%s' "$report")
if (( report_bytes < 2 || report_bytes > 16 * 1024 * 1024 )); then
  echo "release soak report is empty or exceeds its 16 MiB evidence bound" >&2
  exit 65
fi

resolved_expected_commit=$(git rev-parse --verify "${expected_commit}^{commit}" 2>/dev/null || true)
if [[ $resolved_expected_commit != "$expected_commit" ]]; then
  echo "expected release commit is absent or noncanonical" >&2
  exit 65
fi

revision=$(jq -er '.revision | select(type == "string")' "$report")
if [[ ! $revision =~ ^[0-9a-f]{40}$ ]]; then
  echo "release soak revision is not a clean canonical ancestor of the release commit" >&2
  exit 65
fi

resolved_revision=$(git rev-parse --verify "${revision}^{commit}" 2>/dev/null || true)
direct_ancestor=false
if [[ $resolved_revision == "$revision" ]] \
  && git merge-base --is-ancestor "$revision" "$expected_commit"; then
  direct_ancestor=true
fi

release_lineage_revision=
if [[ -n $lineage ]]; then
  lineage_bytes=$(stat -c '%s' "$lineage")
  if (( lineage_bytes < 2 || lineage_bytes > 64 * 1024 )); then
    echo "release soak lineage proof is empty or exceeds its 64 KiB evidence bound" >&2
    exit 65
  fi
  if ! jq -e '
    (keys | sort) == [
      "observedCommitPayload",
      "observedGitTree",
      "observedRevision",
      "releaseLineageGitTree",
      "releaseLineageRevision",
      "reportSha256",
      "schemaVersion",
      "transformation"
    ]
    and .schemaVersion == "mealy.soak-lineage.v1"
    and (.reportSha256 | type == "string" and test("^[0-9a-f]{64}$"))
    and (.observedRevision | type == "string" and test("^[0-9a-f]{40}$"))
    and (.observedGitTree | type == "string" and test("^[0-9a-f]{40}$"))
    and (.observedCommitPayload | type == "string"
      and length >= 1 and length <= 4096 and (contains("\u0000") | not))
    and (.releaseLineageRevision | type == "string" and test("^[0-9a-f]{40}$"))
    and (.releaseLineageGitTree | type == "string" and test("^[0-9a-f]{40}$"))
    and .transformation == "github_rebase_merge"
  ' "$lineage" >/dev/null; then
    echo "release soak lineage proof is malformed or has unsupported fields" >&2
    exit 65
  fi

  mapfile -t lineage_fields < <(jq -er '[
    .reportSha256,
    .observedRevision,
    .observedGitTree,
    .releaseLineageRevision,
    .releaseLineageGitTree
  ] | .[]' "$lineage")
  if [[ ${#lineage_fields[@]} -ne 5 ]]; then
    echo "release soak lineage proof field extraction is incomplete" >&2
    exit 65
  fi
  lineage_report_sha256=${lineage_fields[0]}
  lineage_observed_revision=${lineage_fields[1]}
  lineage_observed_tree=${lineage_fields[2]}
  release_lineage_revision=${lineage_fields[3]}
  release_lineage_tree=${lineage_fields[4]}

  report_sha256=$(sha256sum "$report")
  report_sha256=${report_sha256%% *}
  observed_payload_oid=$(jq -j '.observedCommitPayload' "$lineage" \
    | git hash-object -t commit --stdin)
  observed_payload_tree=$(jq -jr '
    .observedCommitPayload
    | capture("^tree (?<tree>[0-9a-f]{40})\\n").tree
  ' "$lineage")
  resolved_release_lineage=$(git rev-parse --verify \
    "${release_lineage_revision}^{commit}" 2>/dev/null || true)
  resolved_release_lineage_tree=
  if [[ $resolved_release_lineage == "$release_lineage_revision" ]]; then
    resolved_release_lineage_tree=$(git rev-parse \
      "${release_lineage_revision}^{tree}" 2>/dev/null || true)
  fi

  if [[ $lineage_report_sha256 != "$report_sha256" \
    || $lineage_observed_revision != "$revision" \
    || $observed_payload_oid != "$revision" \
    || $observed_payload_tree != "$lineage_observed_tree" \
    || $resolved_release_lineage != "$release_lineage_revision" \
    || $resolved_release_lineage_tree != "$release_lineage_tree" \
    || $lineage_observed_tree != "$release_lineage_tree" ]] \
    || ! git merge-base --is-ancestor "$release_lineage_revision" "$expected_commit"; then
    echo "release soak lineage proof does not bind an identical observed tree into the release history" >&2
    exit 65
  fi
elif [[ $direct_ancestor != true ]]; then
  echo "release soak revision is not a clean canonical ancestor of the release commit" >&2
  exit 65
fi

daemon_sha256=$(sha256sum "$mealyd")
daemon_sha256=${daemon_sha256%% *}
daemon_version=$("$mealyd" --version)
if [[ ! $daemon_version =~ ^mealyd\ ([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
  echo "release daemon returned a noncanonical version" >&2
  exit 65
fi
mealy_version=${BASH_REMATCH[1]}

if ! jq -e \
  --arg revision "$revision" \
  --arg daemon_sha256 "$daemon_sha256" \
  --arg mealy_version "$mealy_version" '
  def uint:
    type == "number" and . >= 0 and floor == .;
  def positive_uint:
    uint and . > 0;
  def zero_residual:
    type == "object"
    and (keys | sort) == [
      "activeLeases",
      "failedOutbox",
      "nonterminalRuns",
      "pendingApprovals",
      "pendingInputs",
      "unknownEffects"
    ]
    and all(.[]; uint and . == 0);
  . as $report
  | .schemaVersion == "mealy.soak-report.v2"
    and .revision == $revision
    and .sourceState == "clean_revision"
    and .mealyVersion == $mealy_version
    and .harnessMode == "external_release_binary"
    and .daemonBinarySha256 == $daemon_sha256
    and .buildProfile == "release"
    and (.homeStorage | type == "object"
      and .mode == "retained"
      and (.filesystem | type == "string" and length >= 1 and length <= 64)
      and (.filesystem != "tmpfs" and .filesystem != "ramfs"
        and .filesystem != "unreported"))
    and (.target | type == "object"
      and .os == "linux"
      and .architecture == "x86_64"
      and (.logicalCpus | positive_uint)
      and (.hostMemoryKiB | positive_uint))
    and (.startedAtUnixMs | positive_uint)
    and (.finishedAtUnixMs | positive_uint)
    and (.requestedDurationSeconds | uint and . >= 86400 and . <= 604800)
    and (.observedDurationMs | uint
      and . >= ($report.requestedDurationSeconds * 1000))
    and (.finishedAtUnixMs > .startedAtUnixMs)
    and (((.finishedAtUnixMs - .startedAtUnixMs) + 300000)
      >= ($report.requestedDurationSeconds * 1000))
    and (.sessions | positive_uint and . <= 64)
    and (.rounds | positive_uint)
    and (.completedTurns | positive_uint
      and . == ($report.sessions * $report.rounds))
    and (.completedTurnsPerMinute | positive_uint)
    and (.hardRestarts | positive_uint)
    and (.interruptedProviderTurns | uint)
    and (.retriedReadToolTurns | uint)
    and (.resumedUndispatchedModelTurns | uint)
    and (.resumedUndispatchedReadToolTurns | uint)
    and ((.interruptedProviderTurns + .retriedReadToolTurns) >= .hardRestarts)
    and (.duplicateAdmissions | positive_uint)
    and (.providerDelayMs | positive_uint)
    and (.roundIntervalMs | uint and . <= 60000)
    and (.latencyMs | type == "object"
      and (.minimum | uint)
      and (.mean | uint)
      and (.p50 | uint)
      and (.p95 | uint)
      and (.p99 | uint)
      and (.maximum | uint)
      and .minimum <= .p50
      and .p50 <= .p95
      and .p95 <= .p99
      and .p99 <= .maximum
      and .minimum <= .mean
      and .mean <= .maximum)
    and (.peakResidentSetKiB | positive_uint)
    and (.databaseBytesIncludingSidecars | positive_uint)
    and (.databaseBytesPerCompletedTurn | positive_uint)
    and (.sqliteStorage | type == "object"
      and (.databaseFileBytes | positive_uint)
      and (.pageSizeBytes | positive_uint)
      and (.pageCount | positive_uint)
      and (.largestObjects | type == "array" and length > 0))
    and (.artifactBytes | uint)
    and .sqliteIntegrity == "ok"
    and (.residual | zero_residual)
  ' "$report" >/dev/null; then
  echo "release soak report does not satisfy the exact 24-hour gate" >&2
  exit 65
fi

if [[ -n $release_lineage_revision ]]; then
  printf 'release soak evidence: ok (%s via identical-tree lineage %s, %s, %s)\n' \
    "$revision" "$release_lineage_revision" "$daemon_sha256" "$mealy_version"
else
  printf 'release soak evidence: ok (%s, %s, %s)\n' \
    "$revision" "$daemon_sha256" "$mealy_version"
fi
