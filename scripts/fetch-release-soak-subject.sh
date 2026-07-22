#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: fetch-release-soak-subject.sh MANIFEST.json REPORT.json DESTINATION REPOSITORY" >&2
}

if [[ $# -ne 4 ]]; then
  usage
  exit 64
fi

manifest=$1
report=$2
destination=$3
repository=$4

for command in chmod dirname gh jq mktemp mv rm sed sha256sum stat; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required soak-subject fetch command is unavailable: $command" >&2
    exit 69
  }
done

if [[ -L $manifest || ! -f $manifest || -L $report || ! -f $report \
  || $repository != */* || $repository == */*/* || -z ${GH_TOKEN-} ]]; then
  usage
  exit 64
fi

if ! jq -e --arg repository "$repository" '
  (keys | sort) == [
    "assetBytes",
    "assetName",
    "assetSha256",
    "releaseId",
    "releaseTag",
    "repository",
    "revision",
    "schemaVersion",
    "target"
  ]
  and .schemaVersion == "mealy.soak-subject.v1"
  and .repository == $repository
  and (.releaseId | type == "number" and floor == . and . > 0)
  and (.releaseTag | type == "string"
    and (test("^v[0-9]+\\.[0-9]+\\.[0-9]+$")
      or test("^soak-subject-[0-9a-f]{40}$"))
    and length <= 64)
  and (.assetName | type == "string"
    and test("^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$"))
  and (.assetSha256 | type == "string" and test("^[0-9a-f]{64}$"))
  and (.assetBytes | type == "number" and floor == . and . >= 1048576
    and . <= 1073741824)
  and (.revision | type == "string" and test("^[0-9a-f]{40}$"))
  and (.target | type == "object"
    and (keys | sort) == ["architecture", "os"]
    and .os == "linux"
    and .architecture == "x86_64")
' "$manifest" >/dev/null; then
  echo "release soak subject manifest is malformed or unsupported" >&2
  exit 65
fi

mapfile -t fields < <(jq -er '[
  (.releaseId | tostring),
  .releaseTag,
  .assetName,
  .assetSha256,
  (.assetBytes | tostring),
  .revision
] | .[]' "$manifest")
if [[ ${#fields[@]} -ne 6 ]]; then
  echo "release soak subject manifest extraction is incomplete" >&2
  exit 65
fi
release_id=${fields[0]}
release_tag=${fields[1]}
asset_name=${fields[2]}
asset_sha256=${fields[3]}
asset_bytes=${fields[4]}
revision=${fields[5]}

if ! jq -e --arg revision "$revision" --arg sha256 "$asset_sha256" '
  .schemaVersion == "mealy.soak-report.v2"
  and .revision == $revision
  and .sourceState == "clean_revision"
  and .harnessMode == "external_release_binary"
  and .buildProfile == "release"
  and .daemonBinarySha256 == $sha256
  and (.mealyVersion | type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))
  and .target.os == "linux"
  and .target.architecture == "x86_64"
' "$report" >/dev/null; then
  echo "release soak subject manifest does not bind the checked report" >&2
  exit 65
fi

release=$(gh api "repos/${repository}/releases/${release_id}")
owner=${repository%%/*}
if ! asset=$(jq -cer \
  --argjson release_id "$release_id" \
  --arg tag "$release_tag" \
  --arg name "$asset_name" \
  --arg owner "$owner" \
  --arg digest "sha256:${asset_sha256}" \
  --argjson bytes "$asset_bytes" '
    select(
      .id == $release_id
      and .tag_name == $tag
      and .draft == true
      and .prerelease == false
    )
    | [.assets[] | select(
        .name == $name
        and .state == "uploaded"
        and .size == $bytes
        and .digest == $digest
        and .uploader.login == $owner
      )] as $matches
    | select($matches | length == 1)
    | $matches[0]
  ' <<<"$release"); then
  echo "draft release does not expose the unique pinned soak subject" >&2
  exit 65
fi
asset_id=$(jq -er '.id | select(type == "number" and floor == . and . > 0)' <<<"$asset")

ref=$(gh api "repos/${repository}/git/ref/tags/${release_tag}")
object_type=$(jq -er '.object.type' <<<"$ref")
object_sha=$(jq -er '.object.sha' <<<"$ref")
for _ in {1..8}; do
  if [[ $object_type == commit ]]; then
    break
  fi
  if [[ $object_type != tag || ! $object_sha =~ ^[0-9a-f]{40}$ ]]; then
    echo "soak-subject staging tag does not resolve canonically" >&2
    exit 65
  fi
  tag=$(gh api "repos/${repository}/git/tags/${object_sha}")
  object_type=$(jq -er '.object.type' <<<"$tag")
  object_sha=$(jq -er '.object.sha' <<<"$tag")
done
if [[ $object_type != commit || $object_sha != "$revision" ]]; then
  echo "soak-subject staging tag does not resolve to the observed revision" >&2
  exit 65
fi

destination_parent=$(dirname "$destination")
if [[ -L $destination_parent || ! -d $destination_parent \
  || -L $destination || (-e $destination && ! -f $destination) ]]; then
  echo "soak-subject destination must be a regular file path under an existing real directory" >&2
  exit 65
fi
temporary=$(mktemp "${destination_parent}/.mealy-soak-subject.XXXXXX")
cleanup() {
  if [[ -n $temporary ]]; then
    rm -f -- "$temporary"
  fi
}
trap cleanup EXIT

gh api \
  -H 'Accept: application/octet-stream' \
  "repos/${repository}/releases/assets/${asset_id}" >"$temporary"
if [[ -L $temporary || ! -f $temporary \
  || $(stat -c '%s' "$temporary") -ne $asset_bytes ]]; then
  echo "downloaded soak subject has the wrong file type or size" >&2
  exit 65
fi
downloaded_sha256=$(sha256sum "$temporary")
downloaded_sha256=${downloaded_sha256%% *}
if [[ $downloaded_sha256 != "$asset_sha256" ]]; then
  echo "downloaded soak subject digest does not match the checked manifest" >&2
  exit 65
fi

chmod 0755 "$temporary"
version=$(
  "$temporary" --version 2>/dev/null \
    | sed -n 's/^mealyd \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$/\1/p'
)
report_version=$(jq -er '.mealyVersion' "$report")
if [[ $version != "$report_version" ]]; then
  echo "promoted soak subject returned the wrong daemon version" >&2
  exit 65
fi
mv -fT -- "$temporary" "$destination"
temporary=

printf 'promoted release soak subject: %s (%s bytes, %s)\n' \
  "$revision" "$asset_bytes" "$asset_sha256"
