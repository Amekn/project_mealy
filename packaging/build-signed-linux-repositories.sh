#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: build-signed-linux-repositories.sh VERSION RELEASE_ASSETS OUTPUT_DIR BASE_URL PUBLICATION_EPOCH PRIVATE_KEY EXPECTED_FINGERPRINT" >&2
}

if [[ $# -ne 7 ]]; then
  usage
  exit 64
fi

version=$1
assets_dir=$2
output_dir=$3
base_url=${4%/}
publication_epoch=$5
private_key=$6
expected_fingerprint=${7^^}

fedora_image=${MEALY_FEDORA_IMAGE:-fedora:44@sha256:6c75d5bf57cb0fa5aa4b92c6a83c86c791644496d9ac230de7711f5b8ec3b898}
ubuntu_image=${MEALY_UBUNTU_IMAGE:-ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90}
arch_image=${MEALY_ARCH_IMAGE:-archlinux:base-devel@sha256:412efebb0eeef0ef322ff24ad73f82b1ba2d3b12377db4c5fbe3074c7e7e8678}

if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ \
  || ! $publication_epoch =~ ^[1-9][0-9]*$ \
  || ! $expected_fingerprint =~ ^[0-9A-F]{40}$ ]]; then
  echo "repository version, publication epoch, or signing fingerprint is invalid" >&2
  exit 64
fi
https_url_pattern='^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~!$&()*+,;=:@%/-]*)?$'
file_url_pattern='^file:/[A-Za-z0-9._~!$&()*+,;=:@%/-]+$'
if [[ $base_url =~ $https_url_pattern ]]; then
  :
elif [[ ${MEALY_REPOSITORY_ALLOW_TEST_URL:-false} == true \
  && $base_url =~ $file_url_pattern ]]; then
  :
else
  echo "repository base URL must be an absolute HTTPS URL" >&2
  exit 64
fi

for command in awk chmod cp date dirname docker find gpg id install jq mkdir mktemp mv \
  readlink rm sed sha256sum sort stat tr wc; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required signed-repository command is unavailable: $command" >&2
    exit 69
  fi
done

if [[ -L $assets_dir || ! -d $assets_dir \
  || -L $private_key || ! -f $private_key ]]; then
  echo "repository assets and private key must be real local paths" >&2
  exit 66
fi
if (( $(stat -c '%s' "$private_key") < 128 || $(stat -c '%s' "$private_key") > 1048576 )); then
  echo "repository private key is empty or exceeds its 1 MiB bound" >&2
  exit 65
fi
if [[ -e $output_dir && ( -L $output_dir || ! -d $output_dir \
  || -n $(find "$output_dir" -mindepth 1 -print -quit) ) ]]; then
  echo "repository output must be absent or an empty real directory" >&2
  exit 65
fi

assets_dir=$(readlink -f "$assets_dir")
private_key=$(readlink -f "$private_key")
output_parent=$(readlink -f "$(dirname "$output_dir")")
output_name=${output_dir##*/}
if [[ -z $output_name || $output_name == . || $output_name == .. ]]; then
  echo "repository output name is invalid" >&2
  exit 64
fi
mkdir -p -- "$output_parent"

deb_amd64="mealy_${version}_amd64.deb"
deb_arm64="mealy_${version}_arm64.deb"
rpm_x86_64="mealy-${version}-1.x86_64.rpm"
rpm_aarch64="mealy-${version}-1.aarch64.rpm"
arch_x86_64="mealy-${version}-1-x86_64.pkg.tar.zst"
packages=("$deb_amd64" "$deb_arm64" "$rpm_x86_64" "$rpm_aarch64" "$arch_x86_64")
for package in "${packages[@]}"; do
  path=$assets_dir/$package
  if [[ -L $path || ! -f $path ]]; then
    echo "required release package is missing or not a regular file: $package" >&2
    exit 66
  fi
  bytes=$(stat -c '%s' "$path")
  if (( bytes < 128 || bytes > 536870912 )); then
    echo "release package is empty or exceeds its 512 MiB bound: $package" >&2
    exit 65
  fi
done

temporary=$(mktemp -d "$output_parent/.mealy-linux-repositories.XXXXXX")
gnupg_home=$temporary/gnupg
build=$temporary/site
secret_export=$temporary/repository-private-key.asc
fedora_signing_image=
cleanup() {
  chmod -R u+rwX -- "$temporary" 2>/dev/null || true
  rm -rf -- "$temporary"
  if [[ -n $fedora_signing_image ]]; then
    docker image rm "$fedora_signing_image" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
mkdir -m 0700 "$gnupg_home"
mkdir -p \
  "$build/apt/pool/main/m/mealy" \
  "$build/rpm/x86_64" \
  "$build/rpm/aarch64" \
  "$build/arch/x86_64"

gpg --batch --homedir "$gnupg_home" --import "$private_key" >/dev/null 2>&1
mapfile -t private_fingerprints < <(
  gpg --batch --homedir "$gnupg_home" --with-colons --list-secret-keys |
    awk -F: '
      $1 == "sec" {want_fingerprint = 1; next}
      want_fingerprint && $1 == "fpr" {print toupper($10); want_fingerprint = 0}
    '
)
if [[ ${#private_fingerprints[@]} -ne 1 \
  || ${private_fingerprints[0]} != "$expected_fingerprint" ]]; then
  echo "private signing key does not contain exactly the expected primary key" >&2
  exit 65
fi
if ! gpg --batch --homedir "$gnupg_home" --with-colons \
  --list-secret-keys "$expected_fingerprint" |
  awk -F: '
    ($1 == "sec" || $1 == "ssb") &&
      $2 !~ /[rde]/ && tolower($12) ~ /s/ {found = 1}
    END {exit !found}
  '; then
  echo "repository signing key is revoked, disabled, expired, or cannot sign" >&2
  exit 65
fi

gpg --batch --homedir "$gnupg_home" --armor \
  --export-options export-minimal --export "$expected_fingerprint" \
  >"$build/repository-signing-key.asc"
gpg --batch --homedir "$gnupg_home" --armor \
  --export-secret-keys "$expected_fingerprint" >"$secret_export"
chmod 0600 "$secret_export"
if grep -Fq 'PRIVATE KEY' "$build/repository-signing-key.asc"; then
  echo "public repository key export contains private material" >&2
  exit 70
fi

fedora_signing_image=$(
  docker build --quiet --build-arg BASE_IMAGE="$fedora_image" - <<'DOCKERFILE'
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
RUN dnf install --assumeyes createrepo_c gnupg2 rpm-sign \
    && dnf clean all
DOCKERFILE
)
if [[ ! $fedora_signing_image =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "ephemeral Fedora signing-tool image identity is invalid" >&2
  exit 70
fi

install -m 0644 "$assets_dir/$deb_amd64" "$build/apt/pool/main/m/mealy/$deb_amd64"
install -m 0644 "$assets_dir/$deb_arm64" "$build/apt/pool/main/m/mealy/$deb_arm64"
install -m 0644 "$assets_dir/$rpm_x86_64" "$build/rpm/x86_64/$rpm_x86_64"
install -m 0644 "$assets_dir/$rpm_aarch64" "$build/rpm/aarch64/$rpm_aarch64"
install -m 0644 "$assets_dir/$arch_x86_64" "$build/arch/x86_64/$arch_x86_64"

docker run --rm \
  --env DEBIAN_FRONTEND=noninteractive \
  --env HOST_GID="$(id -g)" \
  --env HOST_UID="$(id -u)" \
  --env PUBLICATION_EPOCH="$publication_epoch" \
  --env VERSION="$version" \
  --volume "$build:/repository" \
  "$ubuntu_image" bash -lc '
    set -euo pipefail
    trap "chown -R \"$HOST_UID:$HOST_GID\" /repository/apt 2>/dev/null || true" EXIT
    if ! command -v apt-ftparchive >/dev/null 2>&1 \
      || ! command -v dpkg-scanpackages >/dev/null 2>&1; then
      apt-get update >/dev/null
      apt-get install --yes apt-utils dpkg-dev gzip >/dev/null
    fi
    cd /repository/apt
    for architecture in amd64 arm64; do
      package=$(find pool/main/m/mealy -mindepth 1 -maxdepth 1 -type f \
        -name "mealy_*_${architecture}.deb" -print)
      test -n "$package"
      test "$(dpkg-deb --field "$package" Package)" = mealy
      test "$(dpkg-deb --field "$package" Version)" = "$VERSION"
      test "$(dpkg-deb --field "$package" Architecture)" = "$architecture"
      directory="dists/stable/main/binary-${architecture}"
      mkdir -p "$directory/by-hash/SHA256"
      dpkg-scanpackages --arch "$architecture" pool/main /dev/null \
        >"$directory/Packages"
      gzip -n -9 -c "$directory/Packages" >"$directory/Packages.gz"
      for index in Packages Packages.gz; do
        digest=$(sha256sum "$directory/$index" | cut -d " " -f 1)
        cp "$directory/$index" "$directory/by-hash/SHA256/$digest"
      done
    done
    release_date=$(date --utc --date="@$PUBLICATION_EPOCH" --rfc-email)
    valid_until_epoch=$((PUBLICATION_EPOCH + 180 * 86400))
    valid_until=$(date --utc --date="@$valid_until_epoch" --rfc-email)
    apt-ftparchive \
      -o APT::FTPArchive::Release::Origin=Mealy \
      -o APT::FTPArchive::Release::Label=Mealy \
      -o APT::FTPArchive::Release::Suite=stable \
      -o APT::FTPArchive::Release::Codename=stable \
      -o APT::FTPArchive::Release::Version=1 \
      -o APT::FTPArchive::Release::Architectures="amd64 arm64" \
      -o APT::FTPArchive::Release::Components=main \
      -o APT::FTPArchive::Release::Description="Mealy stable Linux packages" \
      -o APT::FTPArchive::Release::Acquire-By-Hash=yes \
      -o APT::FTPArchive::Release::Date="$release_date" \
      -o APT::FTPArchive::Release::Valid-Until="$valid_until" \
      release dists/stable >dists/stable/Release
    chmod -R a+rX,u+w /repository/apt
  '

docker run --rm \
  --cap-drop ALL \
  --env EXPECTED_FINGERPRINT="$expected_fingerprint" \
  --env HOME=/tmp \
  --env PUBLICATION_EPOCH="$publication_epoch" \
  --env VERSION="$version" \
  --network none \
  --read-only \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --user "$(id -u):$(id -g)" \
  --volume "$build:/repository" \
  --volume "$secret_export:/run/mealy-repository-private-key.asc:ro" \
  "$fedora_signing_image" bash -c '
    set -euo pipefail
    interfaces=(/sys/class/net/*)
    test "${#interfaces[@]}" -eq 1
    test "${interfaces[0]##*/}" = lo
    export GNUPGHOME=/tmp/mealy-repository-gnupg
    install -d -m 0700 "$GNUPGHOME"
    gpg --batch --import /run/mealy-repository-private-key.asc >/dev/null 2>&1
    actual=$(gpg --batch --with-colons --list-secret-keys |
      awk -F: '"'"'$1 == "sec" {want = 1; next} want && $1 == "fpr" {print toupper($10); exit}'"'"')
    test "$actual" = "$EXPECTED_FINGERPRINT"
    rpm --dbpath /tmp/mealy-repository-rpmdb --initdb
    rpmkeys --dbpath /tmp/mealy-repository-rpmdb \
      --import /repository/repository-signing-key.asc
    for architecture in x86_64 aarch64; do
      package=$(find "/repository/rpm/$architecture" -mindepth 1 -maxdepth 1 \
        -type f -name "*.rpm" -print)
      test -n "$package"
      identity=$(rpm -qp --queryformat "%{NAME} %{VERSION} %{RELEASE} %{ARCH}" \
        "$package")
      test "$identity" = "mealy $VERSION 1 $architecture"
      rpmsign --addsign --key-id "$EXPECTED_FINGERPRINT" \
        --define "_openpgp_sign gpg" \
        --define "_gpg_path $GNUPGHOME" \
        --define "_gpg_sign_cmd_extra_args --batch --pinentry-mode loopback" \
        "$package"
      rpmkeys --dbpath /tmp/mealy-repository-rpmdb \
        --checksig "$package" >/dev/null
      createrepo_c --checksum sha256 --revision "$PUBLICATION_EPOCH" \
        --set-timestamp-to-revision --simple-md-filenames \
        "/repository/rpm/$architecture" >/dev/null
    done
    chmod -R a+rX,u+w /repository/rpm
  '

sign_detached() {
  local source=$1
  local signature=$2
  local armor=${3:-false}
  local arguments=(
    --batch
    --yes
    --homedir "$gnupg_home"
    --local-user "$expected_fingerprint"
    --digest-algo SHA256
    --detach-sign
    --output "$signature"
  )
  if [[ $armor == true ]]; then
    arguments+=(--armor)
  fi
  gpg "${arguments[@]}" "$source"
}

apt_release=$build/apt/dists/stable/Release
gpg --batch --yes --homedir "$gnupg_home" \
  --local-user "$expected_fingerprint" --digest-algo SHA256 \
  --clearsign --output "$build/apt/dists/stable/InRelease" "$apt_release"
sign_detached "$apt_release" "$build/apt/dists/stable/Release.gpg" true
for architecture in x86_64 aarch64; do
  sign_detached \
    "$build/rpm/$architecture/repodata/repomd.xml" \
    "$build/rpm/$architecture/repodata/repomd.xml.asc" true
done
sign_detached \
  "$build/arch/x86_64/$arch_x86_64" \
  "$build/arch/x86_64/$arch_x86_64.sig"

docker run --rm \
  --env HOST_GID="$(id -g)" \
  --env HOST_UID="$(id -u)" \
  --env VERSION="$version" \
  --volume "$build:/repository" \
  "$arch_image" bash -lc '
    set -euo pipefail
    trap "chown -R \"$HOST_UID:$HOST_GID\" /repository/arch 2>/dev/null || true" EXIT
    cd /repository/arch/x86_64
    package=$(find . -mindepth 1 -maxdepth 1 -type f \
      -name "mealy-*-x86_64.pkg.tar.zst" -print)
    test -n "$package"
    test "$(bsdtar -xOf "$package" .PKGINFO |
      awk -F " = " '"'"'$1 == "pkgname" {print $2}'"'"')" = mealy
    test "$(bsdtar -xOf "$package" .PKGINFO |
      awk -F " = " '"'"'$1 == "pkgver" {print $2}'"'"')" = "$VERSION-1"
    test "$(bsdtar -xOf "$package" .PKGINFO |
      awk -F " = " '"'"'$1 == "arch" {print $2}'"'"')" = x86_64
    repo-add mealy.db.tar.gz "$package" >/dev/null
    cp --dereference mealy.db mealy.db.static
    cp --dereference mealy.files mealy.files.static
    rm -f mealy.db mealy.db.tar.gz mealy.files mealy.files.tar.gz
    mv mealy.db.static mealy.db
    mv mealy.files.static mealy.files
    chmod -R a+rX,u+w /repository/arch
  '
sign_detached "$build/arch/x86_64/mealy.db" "$build/arch/x86_64/mealy.db.sig"

{
  printf 'Types: deb\n'
  printf 'URIs: %s/apt\n' "$base_url"
  printf 'Suites: stable\n'
  printf 'Components: main\n'
  printf 'Architectures: amd64 arm64\n'
  printf 'Signed-By:\n'
  awk '{if (length($0) == 0) print "  ."; else print "  " $0}' \
    "$build/repository-signing-key.asc"
} >"$build/mealy.sources"

{
  printf '[mealy]\n'
  printf 'name=Mealy stable\n'
  printf 'baseurl=%s/rpm/%s\n' "$base_url" "\$basearch"
  printf 'enabled=1\n'
  printf 'gpgcheck=1\n'
  printf 'repo_gpgcheck=1\n'
  printf 'gpgkey=%s/repository-signing-key.asc\n' "$base_url"
} >"$build/mealy.repo"

{
  printf '[mealy]\n'
  printf 'SigLevel = Required DatabaseRequired\n'
  printf 'Server = %s/arch/%s\n' "$base_url" "\$arch"
} >"$build/mealy.pacman.conf"

printf '%s\n' "$expected_fingerprint" >"$build/REPOSITORY-KEY-FINGERPRINT"
cat >"$temporary/repository-index.template" <<'EOF'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Install Mealy on Linux</title>
<style>
:root {
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.55;
  color: #172033;
  background: #f4f6fb;
}
body {
  max-width: 72rem;
  margin: 0 auto;
  padding: 2rem 1rem 4rem;
}
header, section {
  background: #fff;
  border: 1px solid #dfe4ef;
  border-radius: 1rem;
  box-shadow: 0 .35rem 1.5rem rgba(24, 37, 66, .07);
  margin: 0 0 1rem;
  padding: clamp(1.1rem, 3vw, 2rem);
}
h1, h2, h3 { line-height: 1.2; }
h1 { margin: 0 0 .5rem; font-size: clamp(2rem, 6vw, 3.4rem); }
h2 { margin-top: 0; }
.lede { font-size: 1.15rem; max-width: 48rem; }
.badge {
  display: inline-block;
  border-radius: 999px;
  background: #e7edff;
  color: #173b8f;
  font-weight: 700;
  padding: .25rem .75rem;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 19rem), 1fr));
  gap: 1rem;
}
.card {
  border: 1px solid #dfe4ef;
  border-radius: .8rem;
  padding: 1rem;
  min-width: 0;
}
pre {
  background: #111827;
  color: #f8fafc;
  border-radius: .65rem;
  overflow-x: auto;
  padding: 1rem;
  white-space: pre;
}
code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
p code, li code {
  background: #eef1f7;
  border-radius: .25rem;
  padding: .1rem .3rem;
}
a { color: #2457c5; }
.fingerprint {
  overflow-wrap: anywhere;
  font-size: .95rem;
}
.note {
  border-left: .3rem solid #2457c5;
  padding-left: 1rem;
}
@media (prefers-color-scheme: dark) {
  :root { color: #e8edf7; background: #0d1320; }
  header, section, .card { background: #151d2d; border-color: #354058; box-shadow: none; }
  .badge { background: #243a72; color: #e6edff; }
  p code, li code { background: #263147; }
  a { color: #91b4ff; }
}
</style>
</head>
<body>
<header>
  <span class="badge">Stable @@VERSION@@</span>
  <h1>Install Mealy on Linux</h1>
  <p class="lede">Signed native packages for Ubuntu, Debian, Fedora, and Arch Linux.
  Choose your distribution, install through its normal package manager, then let one guided
  command configure the provider, owner service, health checks, and first chat.</p>
  <p class="note">These steps download small configuration files for inspection before privileged
  installation. They never pipe a remote program into a privileged shell.</p>
</header>

<section aria-labelledby="install">
  <h2 id="install">1. Install the signed package</h2>
  <div class="grid">
    <article class="card">
      <h3>Ubuntu or Debian</h3>
      <pre><code>tmp=$(mktemp)
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  @@BASE_URL@@/mealy.sources --output "$tmp"
sudo install -m 0644 "$tmp" /etc/apt/sources.list.d/mealy.sources
rm -f "$tmp"
sudo apt update
sudo apt install mealy</code></pre>
      <p>The deb822 source embeds the repository key and requires signed APT metadata.</p>
    </article>
    <article class="card">
      <h3>Fedora</h3>
      <pre><code>tmp=$(mktemp)
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  @@BASE_URL@@/mealy.repo --output "$tmp"
sudo install -m 0644 "$tmp" /etc/yum.repos.d/mealy.repo
rm -f "$tmp"
sudo dnf install mealy</code></pre>
      <p>The repository requires signatures on both RPM packages and repository metadata.</p>
    </article>
    <article class="card">
      <h3>Arch Linux</h3>
      <pre><code>tmp=$(mktemp -d)
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  @@BASE_URL@@/repository-signing-key.asc \
  --output "$tmp/repository-signing-key.asc"
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  @@BASE_URL@@/mealy.pacman.conf --output "$tmp/mealy.pacman.conf"
fingerprint=$(gpg --batch --show-keys --with-colons \
  "$tmp/repository-signing-key.asc" | awk -F: \
  '$1 == "pub" {want = 1; next} want &amp;&amp; $1 == "fpr" {print toupper($10); exit}')
test "$fingerprint" = "@@FINGERPRINT@@"
sudo pacman-key --add "$tmp/repository-signing-key.asc"
sudo pacman-key --lsign-key "$fingerprint"
sudo install -m 0644 "$tmp/mealy.pacman.conf" /etc/pacman.d/mealy.conf
grep -Fqx 'Include = /etc/pacman.d/mealy.conf' /etc/pacman.conf ||
  printf '\nInclude = /etc/pacman.d/mealy.conf\n' | sudo tee -a /etc/pacman.conf
rm -rf "$tmp"
sudo pacman -Syu mealy</code></pre>
      <p>Pacman requires signatures on the package and repository database. The command stops if
      the downloaded primary fingerprint differs from this release.</p>
    </article>
  </div>
</section>

<section aria-labelledby="onboard">
  <h2 id="onboard">2. Configure and start Mealy</h2>
  <p>Guided onboarding supports a strictly free OpenRouter model, a custom authenticated endpoint,
  a credentialless loopback server, ChatGPT or Claude subscription clients, and advanced direct
  APIs. It live-probes the selected route before starting the owner service.</p>
  <pre><code>mealyctl --version
mealyctl --home "$HOME/.mealy" onboard</code></pre>
  <p>On a fresh interactive terminal, successful onboarding opens the first durable chat after
  service health and <code>doctor</code> pass.</p>
</section>

<section aria-labelledby="return">
  <h2 id="return">3. Return, diagnose, or update</h2>
  <div class="grid">
    <article class="card">
      <h3>Continue the latest chat</h3>
      <pre><code>mealyctl --home "$HOME/.mealy" chat --continue</code></pre>
    </article>
    <article class="card">
      <h3>Check the installation</h3>
      <pre><code>mealyctl install-status
mealyctl --home "$HOME/.mealy" doctor</code></pre>
    </article>
    <article class="card">
      <h3>Review an update</h3>
      <pre><code>mealyctl --home "$HOME/.mealy" update</code></pre>
      <p>The verified plan prints the exact APT, DNF, or Pacman command; the client does not mutate
      a package-manager-owned installation behind its back.</p>
    </article>
  </div>
</section>

<section aria-labelledby="trust">
  <h2 id="trust">Repository identity and independent verification</h2>
  <p>Primary signing-key fingerprint:</p>
  <p class="fingerprint"><code>@@FINGERPRINT@@</code></p>
  <ul>
    <li><a href="REPOSITORY-MANIFEST.json">Complete signed-inventory manifest</a></li>
    <li><a href="REPOSITORY-MANIFEST.json.asc">Manifest OpenPGP signature</a></li>
    <li><a href="repository-signing-key.asc">Repository public key</a></li>
    <li><a href="REPOSITORY-KEY-FINGERPRINT">Machine-readable fingerprint</a></li>
    <li><a href="https://github.com/Amekn/mealy/blob/v@@VERSION@@/docs/LINUX_REPOSITORIES.md">Independent attestation verification and rollback guide</a></li>
    <li><a href="https://github.com/Amekn/mealy/blob/v@@VERSION@@/docs/GETTING_STARTED.md">Provider choices and first-five-minute guide</a></li>
  </ul>
  <p>Qualified targets are documented for current Ubuntu, Debian, Fedora, and Arch Linux. A
  derivative is compatibility-expected only when its libc, systemd user manager, sandbox, and
  package-manager behavior preserve that family contract.</p>
</section>
</body>
</html>
EOF
html_base_url=$(printf '%s' "$base_url" | sed 's/&/\&amp;/g')
sed_base_url=$(printf '%s' "$html_base_url" | sed 's/[\\&|]/\\&/g')
sed \
  -e "s|@@VERSION@@|$version|g" \
  -e "s|@@BASE_URL@@|$sed_base_url|g" \
  -e "s|@@FINGERPRINT@@|$expected_fingerprint|g" \
  "$temporary/repository-index.template" >"$build/index.html"

find "$build" -type d -exec chmod 0755 {} +
find "$build" -type f -exec chmod 0644 {} +
if [[ -n $(find "$build" \
  \( -type l -o \( ! -type f -a ! -type d \) \) -print -quit) ]]; then
  echo "repository output contains a symlink or unsupported file type" >&2
  exit 70
fi

manifest_rows=$temporary/manifest-rows.jsonl
while IFS= read -r relative; do
  sha256=$(sha256sum "$build/$relative" | awk '{print $1}')
  bytes=$(stat -c '%s' "$build/$relative")
  jq -cn --arg path "$relative" --arg sha256 "$sha256" --argjson bytes "$bytes" \
    '{path: $path, sha256: $sha256, bytes: $bytes}' >>"$manifest_rows"
done < <(
  find "$build" -type f -printf '%P\n' |
    sort
)
jq -s \
  --arg version "$version" \
  --arg base_url "$base_url" \
  --arg fingerprint "$expected_fingerprint" \
  --argjson publication_epoch "$publication_epoch" '
  {
    schemaVersion: "mealy.linux-repositories.v1",
    version: $version,
    baseUrl: $base_url,
    publicationEpoch: $publication_epoch,
    signingFingerprint: $fingerprint,
    files: .
  }
  ' "$manifest_rows" >"$build/REPOSITORY-MANIFEST.json"
chmod 0644 "$build/REPOSITORY-MANIFEST.json"
sign_detached \
  "$build/REPOSITORY-MANIFEST.json" \
  "$build/REPOSITORY-MANIFEST.json.asc" true
chmod 0644 "$build/REPOSITORY-MANIFEST.json.asc"

if grep -RIl -- 'PRIVATE KEY' "$build" | grep -q .; then
  echo "repository output contains private signing-key material" >&2
  exit 70
fi

if [[ -d $output_dir ]]; then
  rmdir "$output_dir"
fi
mv "$build" "$output_parent/$output_name"
trap - EXIT
cleanup
printf '%s\n' "$output_parent/$output_name"
