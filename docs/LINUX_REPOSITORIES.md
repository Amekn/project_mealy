# Signed Linux package repositories

Mealy publishes one signed package-repository site for the qualified Debian/Ubuntu, Fedora, and
Arch Linux targets. The repository path is available only after a stable release's linked workflow
shows `Publish signed Linux repositories` and every `Verify public … repository` job as green.
Until that first deployment, use the attested release bootstrap described in
[GETTING_STARTED.md](GETTING_STARTED.md).

The expected GitHub Pages address is:

```text
https://amekn.github.io/mealy
```

Do not use a mirror, shortened URL, or copied configuration whose signed manifest names a
different `baseUrl`.

## Quick package-manager setup

These paths deliberately install a small configuration file before invoking the distribution's
normal package manager. They do not pipe a remote program into a privileged shell.

### Ubuntu and Debian

```sh
tmp=$(mktemp)
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  https://amekn.github.io/mealy/mealy.sources --output "$tmp"
sudo install -m 0644 "$tmp" /etc/apt/sources.list.d/mealy.sources
rm -f "$tmp"
sudo apt update
sudo apt install mealy
```

The deb822 source embeds the repository public key and pins it with `Signed-By`. APT requires the
signed `InRelease` metadata and checks every package-index digest before accepting a package.

### Fedora

```sh
tmp=$(mktemp)
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  https://amekn.github.io/mealy/mealy.repo --output "$tmp"
sudo install -m 0644 "$tmp" /etc/yum.repos.d/mealy.repo
rm -f "$tmp"
sudo dnf install mealy
```

The configuration requires both `gpgcheck=1` and `repo_gpgcheck=1`. DNF therefore verifies the
signed repository metadata and the embedded signature on the selected RPM.

### Arch Linux

Arch requires an explicit local trust decision for a third-party repository key:

```sh
tmp=$(mktemp -d)
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  https://amekn.github.io/mealy/repository-signing-key.asc \
  --output "$tmp/repository-signing-key.asc"
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  https://amekn.github.io/mealy/mealy.pacman.conf \
  --output "$tmp/mealy.pacman.conf"
gpg --show-keys --fingerprint "$tmp/repository-signing-key.asc"
sudo pacman-key --add "$tmp/repository-signing-key.asc"
sudo pacman-key --lsign-key "$(gpg --batch --show-keys --with-colons \
  "$tmp/repository-signing-key.asc" | awk -F: \
  '$1 == "pub" {want = 1; next} want && $1 == "fpr" {print $10; exit}')"
sudo install -m 0644 "$tmp/mealy.pacman.conf" /etc/pacman.d/mealy.conf
grep -Fqx 'Include = /etc/pacman.d/mealy.conf' /etc/pacman.conf ||
  printf '\nInclude = /etc/pacman.d/mealy.conf\n' | sudo tee -a /etc/pacman.conf
rm -rf "$tmp"
sudo pacman -Syu mealy
```

The generated configuration requires `SigLevel = Required DatabaseRequired`, and both the package
and repository database carry detached signatures.

After any installation, complete the same host and provider qualification regardless of package
family:

```sh
mealyctl --version
mealyctl --home "$HOME/.mealy" onboard
mealyctl --home "$HOME/.mealy" doctor
mealyctl --home "$HOME/.mealy" chat
```

## Independent first-trust verification

The quick path relies on GitHub Pages TLS and the distribution package manager. For an independent
first trust, bind the repository key and configuration to the tagged GitHub release before
installing anything:

```sh
repository=Amekn/mealy
base_url=https://amekn.github.io/mealy
version=$(gh release view --repo "$repository" --json tagName --jq .tagName)
tmp=$(mktemp -d)
gh release download "$version" --repo "$repository" \
  --pattern ATTESTATION-linux-repositories.sigstore.json --dir "$tmp"
for file in REPOSITORY-MANIFEST.json REPOSITORY-MANIFEST.json.asc \
  repository-signing-key.asc; do
  curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    "$base_url/$file" --output "$tmp/$file"
done
gh attestation verify "$tmp/REPOSITORY-MANIFEST.json" \
  --repo "$repository" \
  --signer-workflow "$repository/.github/workflows/release.yml" \
  --source-ref "refs/tags/$version" \
  --bundle "$tmp/ATTESTATION-linux-repositories.sigstore.json" \
  --deny-self-hosted-runners
fingerprint=$(jq -er '.signingFingerprint' "$tmp/REPOSITORY-MANIFEST.json")
test "$(gpg --batch --show-keys --with-colons "$tmp/repository-signing-key.asc" |
  awk -F: '$1 == "pub" {want = 1; next}
    want && $1 == "fpr" {print toupper($10); exit}')" = "$fingerprint"
GNUPGHOME="$tmp/gnupg"
export GNUPGHOME
mkdir -m 0700 "$GNUPGHOME"
gpg --batch --import "$tmp/repository-signing-key.asc"
gpg --batch --verify "$tmp/REPOSITORY-MANIFEST.json.asc" \
  "$tmp/REPOSITORY-MANIFEST.json"
```

The GitHub attestation establishes the exact manifest produced by the release workflow. The
manifest then establishes the repository signing fingerprint plus the SHA-256 and byte count of
every published file; its OpenPGP signature provides a package-manager-native trust chain.

## Updates, rollback, and removal

The normal distribution command installs a signed newer package:

```sh
sudo apt upgrade mealy       # Ubuntu or Debian
sudo dnf upgrade mealy       # Fedora
sudo pacman -Syu mealy       # Arch
```

The repository exposes the current stable version. Immutable historical native packages remain on
their GitHub releases for an exact manual rollback; the owner-local archive manager separately
retains active and previous verified slots. Repository Release metadata is valid for 180 days, so
maintainers must publish a refreshed signed stable repository before that deadline even when no
new Mealy version is needed.

`mealyctl --home "$HOME/.mealy" update` remains the recommended preflight. It identifies the
native manager, checks compatibility, and prints the exact native command instead of mutating a
root-owned package behind the manager's back. Back up before a schema-changing release. Removing
the native package does not remove `$HOME/.mealy`; use the separately approved
`mealyctl --home "$HOME/.mealy" uninstall` lifecycle only when that retained state should also be
handled.

## Maintainer activation

Repository publication intentionally has no fallback unsigned mode. Before the first production
tag, a repository owner must complete all of these one-time controls:

1. Enable GitHub Pages with **GitHub Actions** as its source and confirm its reported base URL.
2. Create the `linux-repository-signing` Environment, admit only protected release tags, and
   require an owner review.
3. Set Environment variable `MEALY_REPOSITORY_BASE_URL` to the exact Pages URL without a trailing
   slash.
4. Generate an offline Ed25519 certification key and a separate expiring Ed25519 signing subkey.
   Record the 40-hex primary fingerprint through an independently retained owner record.
5. Set Environment variable `MEALY_REPOSITORY_GPG_FINGERPRINT` to that primary fingerprint.
6. Export only the secret subkeys, base64-encode that armored export on one line, and store it as
   Environment secret `MEALY_REPOSITORY_GPG_PRIVATE_KEY_BASE64`.
7. Protect the `github-pages` Environment so only the tagged release workflow can deploy.

One suitable offline-key ceremony, run in a new private `GNUPGHOME`, is:

```sh
gpg --quick-generate-key \
  'Mealy Linux Repository <repository@mealy.invalid>' ed25519 cert 5y
fingerprint=$(gpg --batch --with-colons --list-secret-keys |
  awk -F: '$1 == "sec" {want = 1; next}
    want && $1 == "fpr" {print toupper($10); exit}')
gpg --quick-add-key "$fingerprint" ed25519 sign 1y
gpg --armor --export-secret-subkeys "$fingerprint" | base64 -w0
```

Use a real project-controlled address in the production UID. Do not commit the output, paste it
into a workflow input, or store the offline primary secret on GitHub. The build imports the
short-lived signing material into an ephemeral keyring, requires the configured primary
fingerprint and a usable signing key, removes the exported secret before any third-party action,
and publishes only the minimal public certificate. RPM dependencies are prepared before the key is
mounted; the signing process then runs unprivileged with a read-only root, no Linux capabilities,
no privilege escalation, and no network interface beyond loopback.

The checked builder creates APT `InRelease`/`Release.gpg`, signed RPMs and `repomd.xml`, signed Arch
packages and database, a complete signed inventory, package-manager configurations, and APT
by-hash indexes. Protected CI generates a disposable certification/signing-subkey pair and proves
clean installation through all three managers plus rejection after a one-byte tamper. The tag
workflow repeats validation with the owner key, attests the manifest, deploys the exact Pages
artifact, and accepts the public HTTPS repository on native x86-64 and ARM64 runners.

Before a signing subkey expires, add its successor to the same primary certificate and replace the
GitHub secret with a new secret-subkey export. While the old subkey still signs releases, publish
the refreshed public certificate and require APT users to refresh `mealy.sources`, DNF users to
re-import the refreshed key when prompted, and Arch users to run `pacman-key --add` again. Switch
signers only after that overlap. The primary fingerprint remains stable, but clients still need
the new public subkey material. A primary-key rotation is a separate trust migration: publish and
document both certificates before changing the repository identity, retain the old key long enough
for configuration refresh, and never reuse the old fingerprint after revocation.
