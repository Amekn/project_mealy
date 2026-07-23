#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: validate-signed-linux-repositories.sh REPOSITORY_DIR EXPECTED_BASE_URL EXPECTED_FINGERPRINT" >&2
}

if [[ $# -ne 3 ]]; then
  usage
  exit 64
fi

repository=$1
expected_base_url=${2%/}
expected_fingerprint=${3^^}
fedora_image=${MEALY_FEDORA_IMAGE:-fedora:44@sha256:6c75d5bf57cb0fa5aa4b92c6a83c86c791644496d9ac230de7711f5b8ec3b898}

for command in awk cmp docker find gpg jq mktemp readlink rm sha256sum sort stat; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required repository-validation command is unavailable: $command" >&2
    exit 69
  fi
done
if [[ -L $repository || ! -d $repository \
  || ! $expected_fingerprint =~ ^[0-9A-F]{40}$ ]]; then
  usage
  exit 64
fi
repository=$(readlink -f "$repository")
if [[ -n $(find "$repository" \
  \( -type l -o \( ! -type f -a ! -type d \) \) -print -quit) ]]; then
  echo "repository contains a symlink or unsupported file type" >&2
  exit 65
fi

manifest=$repository/REPOSITORY-MANIFEST.json
manifest_signature=$repository/REPOSITORY-MANIFEST.json.asc
public_key=$repository/repository-signing-key.asc
for required in "$manifest" "$manifest_signature" "$public_key"; do
  if [[ -L $required || ! -f $required ]]; then
    echo "repository control file is missing" >&2
    exit 66
  fi
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-repository-validation.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT
gnupg_home=$temporary/gnupg
mkdir -m 0700 "$gnupg_home"
gpg --batch --homedir "$gnupg_home" --import "$public_key" >/dev/null 2>&1
mapfile -t public_fingerprints < <(
  gpg --batch --homedir "$gnupg_home" --with-colons --list-keys |
    awk -F: '
      $1 == "pub" {want_fingerprint = 1; next}
      want_fingerprint && $1 == "fpr" {print toupper($10); want_fingerprint = 0}
    '
)
if [[ ${#public_fingerprints[@]} -ne 1 \
  || ${public_fingerprints[0]} != "$expected_fingerprint" ]]; then
  echo "repository public key does not contain exactly the expected primary key" >&2
  exit 65
fi
gpg --batch --homedir "$gnupg_home" \
  --verify "$manifest_signature" "$manifest" >/dev/null 2>&1

if ! jq -e \
  --arg base_url "$expected_base_url" \
  --arg fingerprint "$expected_fingerprint" '
  .schemaVersion == "mealy.linux-repositories.v1"
  and (.version | type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))
  and .baseUrl == $base_url
  and (.publicationEpoch | type == "number" and floor == . and . > 0)
  and .signingFingerprint == $fingerprint
  and (.files | type == "array" and length > 0)
  and ([.files[].path] | length == (unique | length))
  and all(.files[];
    (.path | type == "string"
      and test("^[A-Za-z0-9][A-Za-z0-9._/+~-]*$")
      and (contains("..") | not))
    and (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))
    and (.bytes | type == "number" and floor == . and . > 0 and . <= 536870912))
  ' "$manifest" >/dev/null; then
  echo "repository manifest schema or identity is invalid" >&2
  exit 65
fi

expected_inventory=$temporary/expected-inventory
actual_inventory=$temporary/actual-inventory
jq -r '.files[].path' "$manifest" |
  sort >"$expected_inventory"
printf '%s\n' REPOSITORY-MANIFEST.json REPOSITORY-MANIFEST.json.asc \
  >>"$expected_inventory"
sort -u -o "$expected_inventory" "$expected_inventory"
find "$repository" -type f -printf '%P\n' | sort >"$actual_inventory"
if ! cmp -s "$expected_inventory" "$actual_inventory"; then
  echo "repository inventory differs from its signed manifest" >&2
  exit 65
fi

while IFS=$'\t' read -r path expected_sha256 expected_bytes; do
  candidate=$repository/$path
  if [[ -L $candidate || ! -f $candidate \
    || $(stat -c '%s' "$candidate") != "$expected_bytes" \
    || $(sha256sum "$candidate" | awk '{print $1}') != "$expected_sha256" ]]; then
    echo "repository file failed signed-manifest verification: $path" >&2
    exit 65
  fi
done < <(jq -r '.files[] | [.path, .sha256, (.bytes | tostring)] | @tsv' "$manifest")

apt_root=$repository/apt/dists/stable
gpg --batch --homedir "$gnupg_home" --verify "$apt_root/InRelease" >/dev/null 2>&1
gpg --batch --homedir "$gnupg_home" \
  --verify "$apt_root/Release.gpg" "$apt_root/Release" >/dev/null 2>&1
gpg --batch --homedir "$gnupg_home" --decrypt "$apt_root/InRelease" \
  >"$temporary/inrelease-release" 2>/dev/null
cmp "$apt_root/Release" "$temporary/inrelease-release"

for architecture in amd64 arm64; do
  for index in Packages Packages.gz; do
    path="main/binary-$architecture/$index"
    expected=$(awk -v path="$path" '
      $1 == "SHA256:" {in_sha256 = 1; next}
      in_sha256 && /^[A-Za-z]/ {exit}
      in_sha256 && $3 == path {print $1; exit}
    ' "$apt_root/Release")
    if [[ ! $expected =~ ^[0-9a-f]{64}$ \
      || $(sha256sum "$apt_root/$path" | awk '{print $1}') != "$expected" \
      || ! -f "$apt_root/main/binary-$architecture/by-hash/SHA256/$expected" ]]; then
      echo "APT index or by-hash object failed Release verification" >&2
      exit 65
    fi
  done
done

for architecture in x86_64 aarch64; do
  gpg --batch --homedir "$gnupg_home" \
    --verify "$repository/rpm/$architecture/repodata/repomd.xml.asc" \
    "$repository/rpm/$architecture/repodata/repomd.xml" >/dev/null 2>&1
done
gpg --batch --homedir "$gnupg_home" \
  --verify "$repository/arch/x86_64/mealy.db.sig" \
  "$repository/arch/x86_64/mealy.db" >/dev/null 2>&1
arch_package=$(find "$repository/arch/x86_64" -mindepth 1 -maxdepth 1 \
  -type f -name 'mealy-*-x86_64.pkg.tar.zst' -print)
if [[ -z $arch_package ]]; then
  echo "Arch repository package is missing" >&2
  exit 65
fi
gpg --batch --homedir "$gnupg_home" \
  --verify "$arch_package.sig" "$arch_package" >/dev/null 2>&1

docker run --rm \
  --volume "$repository:/repository:ro" \
  "$fedora_image" bash -lc '
    set -euo pipefail
    rpm --dbpath /tmp/mealy-rpmdb --initdb
    rpmkeys --dbpath /tmp/mealy-rpmdb \
      --import /repository/repository-signing-key.asc
    for package in /repository/rpm/*/*.rpm; do
      rpmkeys --dbpath /tmp/mealy-rpmdb --checksig "$package" >/dev/null
    done
  '

if [[ $(<"$repository/REPOSITORY-KEY-FINGERPRINT") != "$expected_fingerprint" \
  || $(jq -r '.baseUrl' "$manifest") != "$expected_base_url" ]]; then
  echo "repository configuration identity does not match its signed controls" >&2
  exit 65
fi
grep -Fq "URIs: $expected_base_url/apt" "$repository/mealy.sources"
grep -Fq "baseurl=$expected_base_url/rpm/\$basearch" "$repository/mealy.repo"
grep -Fq "Server = $expected_base_url/arch/\$arch" "$repository/mealy.pacman.conf"
grep -Fq 'gpgcheck=1' "$repository/mealy.repo"
grep -Fq 'repo_gpgcheck=1' "$repository/mealy.repo"
grep -Fq 'SigLevel = Required DatabaseRequired' "$repository/mealy.pacman.conf"

if grep -RIl -- 'PRIVATE KEY' "$repository" | grep -q .; then
  echo "repository contains private signing-key material" >&2
  exit 70
fi

echo "signed Linux repository validation: ok"
