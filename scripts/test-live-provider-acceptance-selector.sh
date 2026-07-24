#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
selector=$repository_root/scripts/select-live-provider-acceptance.sh

for command in jq mktemp; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required live-acceptance selector test command is unavailable: $command" >&2
    exit 69
  }
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-live-selector-test.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
repository=Amekn/mealy
server_url=https://github.com
required_title="Mealy live acceptance: openrouter-free @ $sha"
valid=$temporary/valid.json
jq -n \
  --arg sha "$sha" \
  --arg required_title "$required_title" \
  --arg repository "$repository" \
  --arg server_url "$server_url" '
  {
    workflow_runs: [
      {
        id: 100,
        head_sha: $sha,
        event: "workflow_dispatch",
        status: "completed",
        conclusion: "success",
        path: ".github/workflows/live-smoke.yml",
        name: ("Mealy live acceptance: private-responses @ " + $sha),
        display_title: ("Mealy live acceptance: private-responses @ " + $sha),
        html_url: ($server_url + "/" + $repository + "/actions/runs/100")
      },
      {
        id: 101,
        head_sha: $sha,
        event: "workflow_dispatch",
        status: "completed",
        conclusion: "success",
        path: ".github/workflows/live-smoke.yml",
        name: $required_title,
        display_title: $required_title,
        html_url: ($server_url + "/" + $repository + "/actions/runs/101")
      },
      {
        id: 102,
        head_sha: $sha,
        event: "workflow_dispatch",
        status: "completed",
        conclusion: "failure",
        path: ".github/workflows/live-smoke.yml",
        name: $required_title,
        display_title: $required_title,
        html_url: ($server_url + "/" + $repository + "/actions/runs/102")
      }
    ]
  }
  ' >"$valid"

expected_url=https://github.com/Amekn/mealy/actions/runs/101
selected_url=$("$selector" "$valid" "$sha" "$repository" "$server_url")
test "$selected_url" = "$expected_url"

expect_rejection() {
  local name=$1
  local filter=$2
  local candidate=$temporary/$name.json
  jq "$filter" "$valid" >"$candidate"
  if "$selector" "$candidate" "$sha" "$repository" "$server_url" \
    >"$temporary/$name.stdout" 2>"$temporary/$name.stderr"; then
    echo "live-acceptance selector accepted invalid $name evidence" >&2
    exit 1
  fi
}

expect_rejection private-provider-only '.workflow_runs |= map(select(.id == 100))'
expect_rejection stale-sha '.workflow_runs |= map(select(.id == 101) | .head_sha = ("b" * 40))'
expect_rejection failed-run '.workflow_runs |= map(select(.id == 101) | .conclusion = "failure")'
expect_rejection incomplete-run '.workflow_runs |= map(select(.id == 101) | .status = "in_progress")'
expect_rejection wrong-event '.workflow_runs |= map(select(.id == 101) | .event = "push")'
expect_rejection wrong-workflow '.workflow_runs |= map(select(.id == 101) | .path = ".github/workflows/ci.yml")'
expect_rejection wrong-workflow-name '.workflow_runs |= map(select(.id == 101) | .name = "another-workflow")'
expect_rejection spoofed-title '.workflow_runs |= map(select(.id == 101) | .display_title = "openrouter-free")'
expect_rejection foreign-url '.workflow_runs |= map(select(.id == 101) | .html_url = "https://github.com/another/repository/actions/runs/101")'
expect_rejection malformed-response '.workflow_runs = {}'

if "$selector" "$valid" "$sha" another/repository "$server_url" \
  >"$temporary/wrong-repository.stdout" 2>"$temporary/wrong-repository.stderr"; then
  echo "live-acceptance selector accepted a foreign repository" >&2
  exit 1
fi

echo "live-provider acceptance selector: ok"
