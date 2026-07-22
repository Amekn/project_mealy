#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: select-protected-ci-run.sh RUNS.json EXPECTED_SHA REPOSITORY SERVER_URL" >&2
}

if [[ $# -ne 4 ]]; then
  usage
  exit 64
fi

runs=$1
expected_sha=$2
repository=$3
server_url=${4%/}

for command in jq stat; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required protected-CI selector command is unavailable: $command" >&2
    exit 69
  }
done

if [[ -L $runs || ! -f $runs \
  || ! $expected_sha =~ ^[0-9a-f]{40}$ \
  || ! $repository =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ \
  || ! $server_url =~ ^https://[A-Za-z0-9.-]+$ ]]; then
  usage
  exit 64
fi

runs_bytes=$(stat -c '%s' "$runs")
if (( runs_bytes < 2 || runs_bytes > 8 * 1024 * 1024 )); then
  echo "protected-CI run response is empty or exceeds its 8 MiB evidence bound" >&2
  exit 65
fi

required_title="Mealy CI: push @ $expected_sha"
if ! selected_url=$(jq -er \
  --arg sha "$expected_sha" \
  --arg repository "$repository" \
  --arg server_url "$server_url" \
  --arg required_title "$required_title" '
  .workflow_runs
  | select(type == "array")
  | [.[] | select(
      (.id | type == "number" and . > 0 and floor == .)
      and .head_sha == $sha
      and .head_branch == "main"
      and .event == "push"
      and .status == "completed"
      and .conclusion == "success"
      and .path == ".github/workflows/ci.yml"
      and .name == "mealy-ci"
      and .display_title == $required_title
      and .html_url == ($server_url + "/" + $repository
        + "/actions/runs/" + (.id | tostring))
    )]
  | sort_by(.id)
  | last
  | .html_url
  ' "$runs"); then
  echo "no successful protected main CI run matches the exact release commit" >&2
  exit 65
fi

printf '%s\n' "$selected_url"
