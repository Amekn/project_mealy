#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
selector=$repository_root/scripts/select-protected-ci-run.sh

for command in jq mktemp; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required protected-CI selector test command is unavailable: $command" >&2
    exit 69
  }
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-ci-selector-test.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
repository=Amekn/mealy
server_url=https://github.com
required_title="Mealy CI: push @ $sha"
valid=$temporary/valid.json
jq -n \
  --arg sha "$sha" \
  --arg required_title "$required_title" \
  --arg repository "$repository" \
  --arg server_url "$server_url" '
  {
    workflow_runs: [
      {
        id: 200,
        head_sha: $sha,
        head_branch: "feature",
        event: "pull_request",
        status: "completed",
        conclusion: "success",
        path: ".github/workflows/ci.yml",
        name: ("Mealy CI: pull_request @ " + $sha),
        display_title: ("Mealy CI: pull_request @ " + $sha),
        html_url: ($server_url + "/" + $repository + "/actions/runs/200")
      },
      {
        id: 201,
        head_sha: $sha,
        head_branch: "main",
        event: "push",
        status: "completed",
        conclusion: "success",
        path: ".github/workflows/ci.yml",
        name: $required_title,
        display_title: $required_title,
        html_url: ($server_url + "/" + $repository + "/actions/runs/201")
      },
      {
        id: 202,
        head_sha: $sha,
        head_branch: "main",
        event: "push",
        status: "completed",
        conclusion: "failure",
        path: ".github/workflows/ci.yml",
        name: $required_title,
        display_title: $required_title,
        html_url: ($server_url + "/" + $repository + "/actions/runs/202")
      }
    ]
  }
  ' >"$valid"

expected_url=https://github.com/Amekn/mealy/actions/runs/201
selected_url=$("$selector" "$valid" "$sha" "$repository" "$server_url")
test "$selected_url" = "$expected_url"

expect_rejection() {
  local name=$1
  local filter=$2
  local candidate=$temporary/$name.json
  jq "$filter" "$valid" >"$candidate"
  if "$selector" "$candidate" "$sha" "$repository" "$server_url" \
    >"$temporary/$name.stdout" 2>"$temporary/$name.stderr"; then
    echo "protected-CI selector accepted invalid $name evidence" >&2
    exit 1
  fi
}

expect_rejection pull-request-only '.workflow_runs |= map(select(.id == 200))'
expect_rejection stale-sha '.workflow_runs |= map(select(.id == 201) | .head_sha = ("b" * 40))'
expect_rejection wrong-branch '.workflow_runs |= map(select(.id == 201) | .head_branch = "release")'
expect_rejection failed-run '.workflow_runs |= map(select(.id == 201) | .conclusion = "failure")'
expect_rejection incomplete-run '.workflow_runs |= map(select(.id == 201) | .status = "in_progress")'
expect_rejection wrong-event '.workflow_runs |= map(select(.id == 201) | .event = "workflow_dispatch")'
expect_rejection wrong-workflow '.workflow_runs |= map(select(.id == 201) | .path = ".github/workflows/release.yml")'
expect_rejection wrong-workflow-name '.workflow_runs |= map(select(.id == 201) | .name = "another-workflow")'
expect_rejection spoofed-title '.workflow_runs |= map(select(.id == 201) | .display_title = "main CI passed")'
expect_rejection foreign-url '.workflow_runs |= map(select(.id == 201) | .html_url = "https://github.com/another/repository/actions/runs/201")'
expect_rejection malformed-response '.workflow_runs = {}'

if "$selector" "$valid" "$sha" another/repository "$server_url" \
  >"$temporary/wrong-repository.stdout" 2>"$temporary/wrong-repository.stderr"; then
  echo "protected-CI selector accepted a foreign repository" >&2
  exit 1
fi

echo "protected main CI selector: ok"
