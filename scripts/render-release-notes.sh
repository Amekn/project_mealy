#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: render-release-notes.sh REPORT.json OWNER/REPO TAG COMMIT LIVE_RUN_URL RELEASE_RUN_URL OUTPUT.md" >&2
}

if [[ $# -ne 7 ]]; then
  usage
  exit 64
fi

report=$1
repository=$2
tag=$3
commit=$4
live_run_url=$5
release_run_url=$6
output=$7

for command in install jq mktemp stat; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required release-note command is unavailable: $command" >&2
    exit 69
  }
done

if [[ -L $report || ! -f $report || ! $repository =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ \
  || ! $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ \
  || ! $commit =~ ^[0-9a-f]{40}$ ]]; then
  usage
  exit 64
fi
version=${tag#v}
expected_run_prefix="https://github.com/$repository/actions/runs/"
for run_url in "$live_run_url" "$release_run_url"; do
  run_id=${run_url#"$expected_run_prefix"}
  if [[ $run_url != "$expected_run_prefix$run_id" || ! $run_id =~ ^[1-9][0-9]*$ ]]; then
    echo "release-note workflow URL is not canonical for $repository" >&2
    exit 65
  fi
done
report_bytes=$(stat -c '%s' "$report")
if (( report_bytes < 2 || report_bytes > 16 * 1024 * 1024 )); then
  echo "release-note soak report is empty or exceeds its 16 MiB evidence bound" >&2
  exit 65
fi

if ! jq -e --arg version "$version" '
  def uint:
    type == "number" and . >= 0 and floor == .;
  def positive_uint:
    uint and . > 0;
  . as $report
  | .schemaVersion == "mealy.soak-report.v2"
    and (.revision | type == "string" and test("^[0-9a-f]{40}$"))
    and .sourceState == "clean_revision"
    and .mealyVersion == $version
    and .harnessMode == "external_release_binary"
    and (.daemonBinarySha256 | type == "string" and test("^[0-9a-f]{64}$"))
    and .buildProfile == "release"
    and (.homeStorage.mode == "retained")
    and (.homeStorage.filesystem | type == "string"
      and test("^[A-Za-z0-9._-]{1,64}$")
      and . != "tmpfs" and . != "ramfs" and . != "unreported")
    and (.requestedDurationSeconds | uint and . >= 86400 and . <= 604800)
    and (.observedDurationMs | uint
      and . >= ($report.requestedDurationSeconds * 1000))
    and (.sessions | positive_uint and . <= 64)
    and (.rounds | positive_uint)
    and (.completedTurns | positive_uint
      and . == ($report.sessions * $report.rounds))
    and (.hardRestarts | positive_uint)
    and (.interruptedProviderTurns | uint)
    and (.retriedReadToolTurns | uint)
    and (.resumedUndispatchedModelTurns | uint)
    and (.resumedUndispatchedReadToolTurns | uint)
    and ((.interruptedProviderTurns + .retriedReadToolTurns) >= .hardRestarts)
    and (.duplicateAdmissions | positive_uint)
    and (.latencyMs.minimum | uint)
    and (.latencyMs.mean | uint)
    and (.latencyMs.p50 | uint)
    and (.latencyMs.p95 | uint)
    and (.latencyMs.p99 | uint)
    and (.latencyMs.maximum | uint)
    and (.latencyMs.minimum <= .latencyMs.p50)
    and (.latencyMs.p50 <= .latencyMs.p95)
    and (.latencyMs.p95 <= .latencyMs.p99)
    and (.latencyMs.p99 <= .latencyMs.maximum)
    and (.latencyMs.minimum <= .latencyMs.mean)
    and (.latencyMs.mean <= .latencyMs.maximum)
    and (.peakResidentSetKiB | positive_uint)
    and (.databaseBytesIncludingSidecars | positive_uint)
    and .sqliteIntegrity == "ok"
    and (.residual | type == "object"
      and (keys | sort) == [
        "activeLeases",
        "failedOutbox",
        "nonterminalRuns",
        "pendingApprovals",
        "pendingInputs",
        "unknownEffects"
      ]
      and all(.[]; uint and . == 0))
' "$report" >/dev/null; then
  echo "release-note soak report does not satisfy the publication evidence contract" >&2
  exit 65
fi

mapfile -t fields < <(jq -er '
  [
    .revision,
    .daemonBinarySha256,
    .requestedDurationSeconds,
    .observedDurationMs,
    .sessions,
    .rounds,
    .completedTurns,
    .hardRestarts,
    .interruptedProviderTurns,
    .retriedReadToolTurns,
    .resumedUndispatchedModelTurns,
    .resumedUndispatchedReadToolTurns,
    .duplicateAdmissions,
    .latencyMs.minimum,
    .latencyMs.mean,
    .latencyMs.p50,
    .latencyMs.p95,
    .latencyMs.p99,
    .latencyMs.maximum,
    .peakResidentSetKiB,
    .databaseBytesIncludingSidecars,
    .homeStorage.filesystem
  ] | .[]
' "$report")
if [[ ${#fields[@]} -ne 22 ]]; then
  echo "release-note soak report field extraction is incomplete" >&2
  exit 65
fi

revision=${fields[0]}
daemon_sha256=${fields[1]}
requested_seconds=${fields[2]}
observed_ms=${fields[3]}
sessions=${fields[4]}
rounds=${fields[5]}
completed_turns=${fields[6]}
hard_restarts=${fields[7]}
interrupted_provider=${fields[8]}
retried_reads=${fields[9]}
resumed_models=${fields[10]}
resumed_reads=${fields[11]}
duplicates=${fields[12]}
latency_min=${fields[13]}
latency_mean=${fields[14]}
latency_p50=${fields[15]}
latency_p95=${fields[16]}
latency_p99=${fields[17]}
latency_max=${fields[18]}
peak_rss=${fields[19]}
database_bytes=${fields[20]}
filesystem=${fields[21]}
observed_seconds=$((observed_ms / 1000))

temporary=$(mktemp "${TMPDIR:-/tmp}/mealy-release-notes.XXXXXX")
cleanup() {
  rm -f -- "$temporary"
}
trap cleanup EXIT

{
  printf '# Mealy %s\n\n' "$tag"
  printf '%s\n\n' 'Mealy is a local-first personal-agent runtime with durable execution, explicit policy and approval boundaries, crash recovery, replay, and owner-operated Linux packaging.'
  printf '%s\n\n' '## Supported release surfaces'
  printf '%s\n' '- Linux x86-64 and ARM64: production control plane, governed tools, sandboxed workers, rootless archive installation, and native Debian packages.'
  printf '%s\n\n' '- macOS Apple Silicon and Intel: conversation-only preview with durable state, replay, backup/restore, and LaunchAgent control; governed worker profiles remain intentionally denied.'
  printf '%s\n\n' 'Windows is outside this release contract.'
  printf '%s\n\n' '## Install and operate'
  printf 'Follow the [verified Linux quickstart](https://github.com/%s/blob/%s/docs/QUICKSTART.md#fast-verified-linux-install) or the [macOS preview procedure](https://github.com/%s/blob/%s/docs/QUICKSTART.md#macos-conversation-only-preview). The [release guide](https://github.com/%s/blob/%s/docs/RELEASE.md) covers attestation, Debian installation, upgrade, rollback, and uninstall.\n\n' \
    "$repository" "$tag" "$repository" "$tag" "$repository" "$tag"
  printf '%s\n\n' '## Exact acceptance evidence'
  printf -- "- Release commit: [\`%s\`](https://github.com/%s/commit/%s)\n" \
    "$commit" "$repository" "$commit"
  printf -- '- Protected build, package, attestation, and public-install workflow: [release run](%s)\n' \
    "$release_run_url"
  printf -- '- Owner-reviewed live-provider acceptance for the same commit: [live-provider run](%s)\n' \
    "$live_run_url"
  printf -- "- Auditable 24-hour soak subject: revision [\`%s\`](https://github.com/%s/commit/%s), \`mealyd\` SHA-256 \`%s\`\n" \
    "$revision" "$repository" "$revision" "$daemon_sha256"
  printf -- "- Soak duration: %s requested seconds; %s observed seconds (%s ms) on retained \`%s\` storage\n" \
    "$requested_seconds" "$observed_seconds" "$observed_ms" "$filesystem"
  printf -- '- Soak workload: %s completed turns across %s sessions and %s rounds; %s planned hard restarts; %s duplicate admissions\n' \
    "$completed_turns" "$sessions" "$rounds" "$hard_restarts" "$duplicates"
  printf -- '- Recovery: %s interrupted provider turns, %s retried read-tool turns, %s resumed undispatched model turns, %s resumed undispatched read-tool turns\n' \
    "$interrupted_provider" "$retried_reads" "$resumed_models" "$resumed_reads"
  printf -- '- Turn latency in milliseconds: minimum %s, mean %s, p50 %s, p95 %s, p99 %s, maximum %s\n' \
    "$latency_min" "$latency_mean" "$latency_p50" "$latency_p95" "$latency_p99" "$latency_max"
  printf -- "- Resource and terminal state: peak RSS %s KiB; SQLite plus sidecars %s bytes; integrity \`ok\`; zero pending input, nonterminal run, active lease, pending approval, unknown effect, or failed outbox residue\n" \
    "$peak_rss" "$database_bytes"
  printf -- "- Unedited soak report: [\`docs/benchmarks/release-soak.json\`](https://github.com/%s/blob/%s/docs/benchmarks/release-soak.json)\n\n" \
    "$repository" "$tag"
  printf '%s\n\n' 'The linked release workflow is the final authority: the release is complete only when its native Linux/macOS package jobs and all dependent public-download acceptance jobs are green.'
  printf '%s\n' '## Security and licensing'
  printf 'Review the tag-pinned [security policy](https://github.com/%s/blob/%s/SECURITY.md), [threat model](https://github.com/%s/blob/%s/docs/THREAT_MODEL.md), project [license](https://github.com/%s/blob/%s/LICENSE), per-asset CycloneDX SBOMs, third-party license notices, checksums, and offline Sigstore bundles before deployment.\n' \
    "$repository" "$tag" "$repository" "$tag" "$repository" "$tag"
} >"$temporary"

if [[ -L $output || ( -e $output && ! -f $output ) ]]; then
  echo "release-note output must be a real file path" >&2
  exit 65
fi
install -m 0644 "$temporary" "$output"
