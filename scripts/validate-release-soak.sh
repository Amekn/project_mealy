#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: validate-release-soak.sh REPORT.json MEALYD EXPECTED_COMMIT" >&2
}

if [[ $# -ne 3 ]]; then
  usage
  exit 64
fi

report=$1
mealyd=$2
expected_commit=$3

for command in git jq sha256sum stat; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required release-soak validation command is unavailable: $command" >&2
    exit 69
  }
done

if [[ -L $report || ! -f $report || -L $mealyd || ! -f $mealyd || ! -x $mealyd \
  || ! $expected_commit =~ ^[0-9a-f]{40}$ ]]; then
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
if [[ ! $revision =~ ^[0-9a-f]{40}$ ]] \
  || [[ $(git rev-parse --verify "${revision}^{commit}" 2>/dev/null || true) != "$revision" ]] \
  || ! git merge-base --is-ancestor "$revision" "$expected_commit"; then
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

printf 'release soak evidence: ok (%s, %s, %s)\n' \
  "$revision" "$daemon_sha256" "$mealy_version"
