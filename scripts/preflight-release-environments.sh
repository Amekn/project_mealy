#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: preflight-release-environments.sh OWNER/REPOSITORY" >&2
}

if [[ $# -ne 1 || ! $1 =~ ^[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}$ ]]; then
  usage
  exit 64
fi

repository=$1
for command in gh jq mktemp stat; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required release-environment preflight command is unavailable: $command" >&2
    exit 69
  }
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-release-environment.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

capture() {
  local name=$1
  shift
  local destination=$temporary/$name.json
  "$@" >"$destination"
  local bytes
  bytes=$(stat -c '%s' "$destination")
  if (( bytes < 2 || bytes > 1048576 )); then
    echo "release-environment metadata response is empty or oversized: $name" >&2
    exit 65
  fi
}

capture repository gh api "repos/$repository"
if ! jq -e --arg repository "$repository" '
  .full_name == $repository
  and .private == false
  and .archived == false
  and .disabled == false
' "$temporary/repository.json" >/dev/null; then
  echo "release repository is missing, noncanonical, private, archived, or disabled" >&2
  exit 65
fi

capture pages gh api "repos/$repository/pages"
if ! jq -e '
  .build_type == "workflow"
  and .public == true
  and .https_enforced == true
  and (.html_url | type == "string"
    and test("^https://[A-Za-z0-9.-]+/[A-Za-z0-9._/-]*/$"))
' "$temporary/pages.json" >/dev/null; then
  echo "GitHub Pages is not a public HTTPS workflow deployment" >&2
  exit 65
fi
pages_url=$(jq -er '.html_url | rtrimstr("/")' "$temporary/pages.json")

capture signing_environment gh api \
  "repos/$repository/environments/linux-repository-signing"
if ! jq -e '
  any(.protection_rules[]?; .type == "required_reviewers"
    and (.reviewers | type == "array" and length >= 1))
  and any(.protection_rules[]?; .type == "branch_policy")
  and .deployment_branch_policy.protected_branches == false
  and .deployment_branch_policy.custom_branch_policies == true
' "$temporary/signing_environment.json" >/dev/null; then
  echo "linux-repository-signing lacks owner review or custom tag protection" >&2
  exit 65
fi

capture signing_policies gh api \
  "repos/$repository/environments/linux-repository-signing/deployment-branch-policies"
if ! jq -e '
  .branch_policies
  | type == "array"
    and length == 1
    and .[0].type == "tag"
    and .[0].name == "v*.*.*"
' "$temporary/signing_policies.json" >/dev/null; then
  echo "linux-repository-signing must admit only stable-version tags" >&2
  exit 65
fi

capture signing_variables gh variable list --repo "$repository" \
  --env linux-repository-signing --json name,value
if ! jq -e --arg pages_url "$pages_url" '
  ([.[] | select(.name == "MEALY_REPOSITORY_BASE_URL" and .value == $pages_url)]
    | length == 1)
  and
  ([.[] | select(.name == "MEALY_REPOSITORY_GPG_FINGERPRINT"
    and (.value | test("^[0-9A-F]{40}$")))]
    | length == 1)
' "$temporary/signing_variables.json" >/dev/null; then
  echo "repository base URL or 40-hex uppercase signing fingerprint is not configured exactly" >&2
  exit 65
fi
fingerprint=$(
  jq -er '.[] | select(.name == "MEALY_REPOSITORY_GPG_FINGERPRINT") | .value' \
    "$temporary/signing_variables.json"
)

capture signing_secrets gh secret list --repo "$repository" \
  --env linux-repository-signing --json name
if ! jq -e '
  [.[] | select(.name == "MEALY_REPOSITORY_GPG_PRIVATE_KEY_BASE64")]
  | length == 1
' "$temporary/signing_secrets.json" >/dev/null; then
  echo "repository signing-subkey Environment secret is not configured" >&2
  exit 65
fi

capture pages_environment gh api "repos/$repository/environments/github-pages"
if ! jq -e '
  any(.protection_rules[]?; .type == "branch_policy")
  and .deployment_branch_policy.protected_branches == false
  and .deployment_branch_policy.custom_branch_policies == true
' "$temporary/pages_environment.json" >/dev/null; then
  echo "github-pages lacks custom tag protection" >&2
  exit 65
fi

capture pages_policies gh api \
  "repos/$repository/environments/github-pages/deployment-branch-policies"
if ! jq -e '
  .branch_policies
  | type == "array"
    and length == 1
    and .[0].type == "tag"
    and .[0].name == "v*.*.*"
' "$temporary/pages_policies.json" >/dev/null; then
  echo "github-pages must admit only stable-version tags" >&2
  exit 65
fi

capture live_environment gh api "repos/$repository/environments/live-provider-smoke"
if ! jq -e '
  any(.protection_rules[]?; .type == "required_reviewers"
    and (.reviewers | type == "array" and length >= 1))
  and any(.protection_rules[]?; .type == "branch_policy")
  and .deployment_branch_policy.protected_branches == true
  and .deployment_branch_policy.custom_branch_policies == false
' "$temporary/live_environment.json" >/dev/null; then
  echo "live-provider-smoke lacks owner review or protected-branch restriction" >&2
  exit 65
fi

capture live_secrets gh secret list --repo "$repository" \
  --env live-provider-smoke --json name
if ! jq -e '
  [.[] | select(.name == "OPENROUTER_API_KEY")]
  | length == 1
' "$temporary/live_secrets.json" >/dev/null; then
  echo "free-model OpenRouter Environment secret is not configured" >&2
  exit 65
fi

printf 'release environment preflight: ok (%s, %s, signing fingerprint %s)\n' \
  "$repository" "$pages_url" "$fingerprint"
