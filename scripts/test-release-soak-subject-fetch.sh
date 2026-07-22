#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
fetcher="$repository_root/scripts/fetch-release-soak-subject.sh"
temporary=$(mktemp -d)
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

mkdir -p "$temporary/bin" "$temporary/output"
asset="$temporary/asset"
cat >"$asset" <<'EOF'
#!/usr/bin/env bash
if [[ ${1-} == --version ]]; then
  echo 'mealyd 0.1.0'
  exit 0
fi
exit 64
EOF
truncate -s 1048576 "$asset"
chmod 0755 "$asset"
asset_sha256=$(sha256sum "$asset")
asset_sha256=${asset_sha256%% *}
asset_bytes=$(stat -c '%s' "$asset")
revision=0123456789abcdef0123456789abcdef01234567
tag_revision=$revision
asset_name=mealy-soak-test-linux-x86_64-gnu-mealyd

jq -n \
  --arg repository Amekn/project_mealy \
  --arg name "$asset_name" \
  --arg sha256 "$asset_sha256" \
  --arg revision "$revision" \
  --argjson bytes "$asset_bytes" '
  {
    schemaVersion: "mealy.soak-subject.v1",
    repository: $repository,
    releaseId: 99,
    releaseTag: "v0.1.0",
    assetName: $name,
    assetSha256: $sha256,
    assetBytes: $bytes,
    revision: $revision,
    target: {os: "linux", architecture: "x86_64"}
  }
' >"$temporary/manifest.json"
jq -n --arg revision "$revision" --arg sha256 "$asset_sha256" '
  {
    schemaVersion: "mealy.soak-report.v2",
    revision: $revision,
    sourceState: "clean_revision",
    mealyVersion: "0.1.0",
    harnessMode: "external_release_binary",
    daemonBinarySha256: $sha256,
    buildProfile: "release",
    target: {os: "linux", architecture: "x86_64"}
  }
' >"$temporary/report.json"
jq -n \
  --arg name "$asset_name" \
  --arg owner Amekn \
  --arg digest "sha256:$asset_sha256" \
  --argjson bytes "$asset_bytes" '
  {
    id: 99,
    tag_name: "v0.1.0",
    draft: true,
    prerelease: false,
    assets: [{
      id: 42,
      name: $name,
      state: "uploaded",
      size: $bytes,
      digest: $digest,
      uploader: {login: $owner}
    }]
  }
' >"$temporary/release.json"

cat >"$temporary/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ $* == *'/releases/99'* ]]; then
  cat "$MOCK_RELEASE"
elif [[ $* == *'/git/ref/tags/v0.1.0'* ]]; then
  jq -n --arg revision "$MOCK_REVISION" '{object: {type: "commit", sha: $revision}}'
elif [[ $* == *'/releases/assets/42'* ]]; then
  cat "$MOCK_ASSET"
else
  exit 64
fi
EOF
chmod 0755 "$temporary/bin/gh"

run_fetch() {
  PATH="$temporary/bin:$PATH" \
    GH_TOKEN=test-token \
    MOCK_RELEASE="$temporary/release.json" \
    MOCK_ASSET="$asset" \
    MOCK_REVISION="$tag_revision" \
    "$fetcher" "$temporary/manifest.json" "$temporary/report.json" \
      "$temporary/output/mealyd" Amekn/project_mealy
}

run_fetch >/dev/null
test "$(sha256sum "$temporary/output/mealyd" | cut -d' ' -f1)" = "$asset_sha256"
test -x "$temporary/output/mealyd"

cp "$temporary/manifest.json" "$temporary/manifest.valid.json"
cp "$temporary/release.json" "$temporary/release.valid.json"

jq '.assetSha256 = ("0" * 64)' "$temporary/manifest.valid.json" \
  >"$temporary/manifest.json"
if run_fetch >/dev/null 2>&1; then
  echo "soak-subject fetch accepted a manifest/report digest mismatch" >&2
  exit 1
fi
cp "$temporary/manifest.valid.json" "$temporary/manifest.json"

jq '.assets[0].uploader.login = "mallory"' "$temporary/release.valid.json" \
  >"$temporary/release.json"
if run_fetch >/dev/null 2>&1; then
  echo "soak-subject fetch accepted the wrong release-asset uploader" >&2
  exit 1
fi
cp "$temporary/release.valid.json" "$temporary/release.json"

jq '.assets[0].digest = "sha256:" + ("f" * 64)' "$temporary/release.valid.json" \
  >"$temporary/release.json"
if run_fetch >/dev/null 2>&1; then
  echo "soak-subject fetch accepted the wrong remote asset digest" >&2
  exit 1
fi
cp "$temporary/release.valid.json" "$temporary/release.json"

tag_revision=ffffffffffffffffffffffffffffffffffffffff
if run_fetch >/dev/null 2>&1; then
  echo "soak-subject fetch accepted a staging tag on the wrong revision" >&2
  exit 1
fi

echo "release soak subject fetch tests: ok"
