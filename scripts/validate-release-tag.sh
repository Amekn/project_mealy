#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: validate-release-tag.sh TAG WORKSPACE_VERSION" >&2
}

if [[ $# -ne 2 ]]; then
  usage
  exit 64
fi

tag=$1
workspace_version=$2
stable_tag='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
if [[ ! $tag =~ $stable_tag || ${tag#v} != "$workspace_version" ]]; then
  echo "production releases require an exact stable vMAJOR.MINOR.PATCH tag matching the workspace version" >&2
  exit 65
fi
