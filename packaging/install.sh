#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  cat >&2 <<'USAGE'
usage: install-mealy.sh install --archive FILE --checksums FILE
       [--prefix DIR] [--home DIR] [--verify-repository OWNER/REPO]
       [--attestation-bundle FILE]
       install-mealy.sh rollback [--prefix DIR] [--home DIR]
       install-mealy.sh rollback-migration --migration-backup NAME
       --expected-manifest-digest SHA256 --approve [--prefix DIR] [--home DIR]
       install-mealy.sh uninstall [--prefix DIR] [--home DIR]

Installs, rolls back, or uninstalls a managed Mealy Linux release. Install
verifies the release checksum and optionally its GitHub provenance, using an
offline Sigstore bundle when supplied, before
extraction. Rollback restores matching previous binaries and release metadata.
Rollback-migration additionally rebuilds and atomically activates the exact
approved pre-migration home. Uninstall removes managed program files but never
deletes the Mealy home or its durable state.
USAGE
}

action=install
if [[ ${1-} == install || ${1-} == rollback || ${1-} == rollback-migration \
  || ${1-} == uninstall ]]; then
  action=$1
  shift
fi

archive=
checksums=
prefix=${HOME:+$HOME/.local}
home=${MEALY_HOME:-${HOME:+$HOME/.mealy}}
verify_repository=
attestation_bundle=
migration_backup=
expected_manifest_digest=
approve=false
# Keep this path inventory synchronized with build-release.sh and build-deb.sh. The packaging
# fixtures deliberately fail closed when any standalone boundary omits or adds a document.
release_documents=(
  API.md
  CI_CD.md
  CLI.md
  DOMAIN_MODEL.md
  GETTING_STARTED.md
  IMPLEMENTATION_PLAN.md
  LINUX_REPOSITORIES.md
  LINUX_SUPPORT.md
  OPERATIONS.md
  PRODUCTION_READINESS.md
  QUICKSTART.md
  README.md
  RELEASE.md
  REQUIREMENTS_COVERAGE.md
  TESTING.md
  THREAT_MODEL.md
  benchmarks/2026-07-12-development-soak.json
  benchmarks/2026-07-13-debian-13-installed-package-smoke.md
  benchmarks/2026-07-13-development-soak.json
  benchmarks/2026-07-13-five-minute-paced-soak.json
  benchmarks/2026-07-13-live-public-web-fetch.md
  benchmarks/2026-07-13-schema14-long-soak-failure.md
  benchmarks/2026-07-13-storage-optimized-soak.json
  benchmarks/2026-07-13-supply-chain-policy-audit.md
  benchmarks/2026-07-13-thirty-minute-paced-soak.json
  benchmarks/2026-07-13-ubuntu-24.04-installed-package-smoke.md
  benchmarks/2026-07-14-nine-hour-supervisor-interruption.md
  benchmarks/2026-07-15-fedora-44-installed-package-smoke.md
  benchmarks/2026-07-16-schema15-long-soak-contention-failure.md
  benchmarks/2026-07-16-schema15-release-soak-lineage.json
  benchmarks/2026-07-16-schema15-release-soak.json
  benchmarks/2026-07-20-schema15-near-deadline-provider-dispatch-failure.md
  benchmarks/2026-07-20-interrupted-soak-and-storage-architecture.md
  benchmarks/2026-07-24-v0.1.1-release-workflow-fixture-failure.md
  benchmarks/README.md
  benchmarks/release-soak.json
  benchmarks/release-soak-subject.json
  decisions/0001-modular-monolith-and-workers.md
  decisions/0002-transactional-journal.md
  decisions/0003-effect-recovery.md
  decisions/0004-security-boundaries.md
  decisions/0005-durable-session-inbox.md
  decisions/0006-context-and-memory.md
  decisions/0007-local-api.md
  decisions/0008-risk-based-validation.md
  decisions/0009-sqlite-writer-and-snapshot-readers.md
  decisions/0010-disconnect-resistant-update-transaction.md
  decisions/README.md
  research/GAP_MATRIX.md
  research/ONBOARDING_COMPLETION_AUDIT_2026-07-24.md
  research/PRODUCT_OPERATIONS_BENCHMARK_2026-07-24.md
  research/REFERENCE_SYSTEMS.md
)
while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive)
      archive=${2-}
      shift 2
      ;;
    --checksums)
      checksums=${2-}
      shift 2
      ;;
    --prefix)
      prefix=${2-}
      shift 2
      ;;
    --home)
      home=${2-}
      shift 2
      ;;
    --verify-repository)
      verify_repository=${2-}
      shift 2
      ;;
    --attestation-bundle)
      attestation_bundle=${2-}
      shift 2
      ;;
    --migration-backup)
      migration_backup=${2-}
      shift 2
      ;;
    --expected-manifest-digest)
      expected_manifest_digest=${2-}
      shift 2
      ;;
    --approve)
      approve=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage
      exit 64
      ;;
  esac
done

if [[ -z $prefix || -z $home ]]; then
  usage
  exit 64
fi
if [[ $action == install ]]; then
  if [[ -z $archive || -z $checksums || ! -f $archive || ! -f $checksums \
    || ( -n $attestation_bundle \
      && ( -z $verify_repository || -L $attestation_bundle || ! -f $attestation_bundle ) ) \
    || -n $migration_backup || -n $expected_manifest_digest || $approve == true ]]; then
    usage
    exit 64
  fi
elif [[ $action == rollback-migration ]]; then
  if [[ -n $archive || -n $checksums || -n $verify_repository || -n $attestation_bundle \
    || -z $migration_backup || -z $expected_manifest_digest || $approve != true \
    || ! $migration_backup =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$ \
    || $migration_backup == *\. \
    || ! $expected_manifest_digest =~ ^[0-9a-f]{64}$ ]]; then
    usage
    exit 64
  fi
elif [[ -n $archive || -n $checksums || -n $verify_repository || -n $attestation_bundle \
  || -n $migration_backup || -n $expected_manifest_digest || $approve == true ]]; then
  usage
  exit 64
fi

for command in tar gzip sha256sum awk sed sort mktemp install readlink jq find stat \
  flock cp mv rm mkdir wc basename uname chmod sync; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required installer command is unavailable: $command" >&2
    exit 69
  }
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-install.XXXXXX")
prefix_lock=
home_lock_acquired=false
cleanup() {
  rm -rf "$temporary"
}
trap cleanup EXIT

ensure_real_directory() {
  local path=$1
  if [[ -e $path && ( -L $path || ! -d $path ) ]]; then
    echo "managed installation path is not a real directory: $path" >&2
    return 1
  fi
  mkdir -p "$path"
}

ensure_real_directory "$prefix"
prefix=$(readlink -f "$prefix")
for directory in "$prefix/bin" "$prefix/share"; do
  ensure_real_directory "$directory"
done

if [[ -e $home ]]; then
  if [[ -L $home || ! -d $home ]]; then
    echo "Mealy home is not a real directory: $home" >&2
    exit 65
  fi
  home=$(readlink -f "$home")
  if [[ -L $home/mealyd.lock || (-e $home/mealyd.lock && ! -f $home/mealyd.lock) ]]; then
    echo "Mealy home lock is not a real file: $home/mealyd.lock" >&2
    exit 65
  fi
  exec 9>"$home/mealyd.lock"
  if ! flock -n 9; then
    echo "mealyd is running for $home; drain it before $action" >&2
    exit 75
  fi
  home_lock_acquired=true
fi

prefix_lock="$prefix/.mealy-install.lock"
if [[ -L $prefix_lock || (-e $prefix_lock && ! -f $prefix_lock) ]]; then
  echo "Mealy installer lock is not a real file: $prefix_lock" >&2
  exit 65
fi
exec 8>"$prefix_lock"
if ! flock -n 8; then
  echo "another Mealy install operation owns $prefix_lock" >&2
  exit 75
fi

expected_digest() {
  local metadata=$1
  local logical_path=$2
  local payload="$metadata/PAYLOAD-SHA256SUMS"
  local matches
  matches=$(awk -v path="$logical_path" '$2 == path {print $1}' "$payload")
  if [[ ! $matches =~ ^[0-9a-f]{64}$ ]]; then
    return 1
  fi
  printf '%s\n' "$matches"
}

verify_managed_slot() {
  local binary_suffix=$1
  local metadata=$2
  if [[ -L $metadata || ! -d $metadata || -L $metadata/PAYLOAD-SHA256SUMS \
    || ! -f $metadata/PAYLOAD-SHA256SUMS ]]; then
    return 1
  fi
  local logical actual expected
  for logical in bin/mealyd bin/mealyctl; do
    actual="$prefix/$logical$binary_suffix"
    if [[ -L $actual || ! -f $actual || ! -x $actual ]]; then
      return 1
    fi
    expected=$(expected_digest "$metadata" "$logical") || return 1
    [[ $(sha256sum "$actual" | awk '{print $1}') == "$expected" ]] || return 1
  done
  for logical in BUILD-MANIFEST.json SBOM.cdx.json install.sh install-release.sh \
    fetch-browser-runtime.sh \
    LICENSE THIRD-PARTY-LICENSES.html ARCHITECTURE.md README.md REQUIREMENTS.md SECURITY.md \
    "${release_documents[@]/#/docs/}"; do
    case "$logical" in
      install.sh) actual="$metadata/manage-install.sh" ;;
      install-release.sh) actual="$metadata/manage-release.sh" ;;
      fetch-browser-runtime.sh) actual="$metadata/fetch-browser-runtime.sh" ;;
      *) actual="$metadata/$logical" ;;
    esac
    if [[ -L $actual || ! -f $actual ]]; then
      return 1
    fi
    expected=$(expected_digest "$metadata" "$logical") || return 1
    [[ $(sha256sum "$actual" | awk '{print $1}') == "$expected" ]] || return 1
  done
  jq -e '
      .schemaVersion == "mealy.release.v2"
      and .sbom == "SBOM.cdx.json"
      and .licenses == "THIRD-PARTY-LICENSES.html"
      and (.stateSchemaVersion | (type == "number" and . >= 1 and . <= 9999))
    ' "$metadata/BUILD-MANIFEST.json" >/dev/null
  jq -e '.bomFormat == "CycloneDX" and (.components | type == "array" and length > 0)' \
    "$metadata/SBOM.cdx.json" >/dev/null
}

slot_state() {
  local binary_suffix=$1
  local metadata=$2
  local present=0
  [[ -e $prefix/bin/mealyd$binary_suffix || -L $prefix/bin/mealyd$binary_suffix ]] \
    && present=$((present + 1))
  [[ -e $prefix/bin/mealyctl$binary_suffix || -L $prefix/bin/mealyctl$binary_suffix ]] \
    && present=$((present + 1))
  [[ -e $metadata || -L $metadata ]] && present=$((present + 1))
  case "$present" in
    0) return 1 ;;
    3)
      if ! verify_managed_slot "$binary_suffix" "$metadata"; then
        echo "managed Mealy installation evidence is invalid for suffix '$binary_suffix'" >&2
        exit 65
      fi
      return 0
      ;;
    *)
      echo "managed Mealy installation is partial for suffix '$binary_suffix'" >&2
      exit 65
      ;;
  esac
}

copy_package_metadata() {
  local source=$1
  local destination=$2
  mkdir -p "$destination/docs"
  install -m 0644 "$source/BUILD-MANIFEST.json" "$destination/BUILD-MANIFEST.json"
  install -m 0644 "$source/SBOM.cdx.json" "$destination/SBOM.cdx.json"
  install -m 0644 "$source/PAYLOAD-SHA256SUMS" "$destination/PAYLOAD-SHA256SUMS"
  install -m 0755 "$source/install.sh" "$destination/manage-install.sh"
  install -m 0755 "$source/install-release.sh" "$destination/manage-release.sh"
  install -m 0755 "$source/fetch-browser-runtime.sh" "$destination/fetch-browser-runtime.sh"
  install -m 0644 "$source/LICENSE" "$destination/LICENSE"
  install -m 0644 "$source/THIRD-PARTY-LICENSES.html" \
    "$destination/THIRD-PARTY-LICENSES.html"
  install -m 0644 "$source/ARCHITECTURE.md" "$destination/ARCHITECTURE.md"
  install -m 0644 "$source/README.md" "$destination/README.md"
  install -m 0644 "$source/REQUIREMENTS.md" "$destination/REQUIREMENTS.md"
  install -m 0644 "$source/SECURITY.md" "$destination/SECURITY.md"
  for document in "${release_documents[@]}"; do
    install -D -m 0644 "$source/docs/$document" "$destination/docs/$document"
  done
}

install_release() {
  archive=$(readlink -f "$archive")
  checksums=$(readlink -f "$checksums")
  if [[ -n $attestation_bundle ]]; then
    attestation_bundle=$(readlink -f "$attestation_bundle")
    if [[ $(stat -c '%s' "$attestation_bundle") -gt 16777216 ]]; then
      echo "attestation bundle exceeds the 16 MiB installer bound" >&2
      exit 65
    fi
  fi
  local archive_name archive_target host_target
  archive_name=$(basename "$archive")
  if [[ ! $archive_name =~ ^mealy-v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?-(linux-(x86_64|aarch64)-gnu)\.tar\.gz$ ]]; then
    echo "release archive name is invalid" >&2
    exit 65
  fi
  archive_target=${BASH_REMATCH[2]}
  case $(uname -m) in
    x86_64|amd64) host_target=linux-x86_64-gnu ;;
    aarch64|arm64) host_target=linux-aarch64-gnu ;;
    *)
      echo "unsupported Linux host architecture: $(uname -m)" >&2
      exit 65
      ;;
  esac
  if [[ $archive_target != "$host_target" ]]; then
    echo "release target $archive_target does not match host target $host_target" >&2
    exit 65
  fi
  if [[ $(stat -c '%s' "$archive") -gt 268435456 ]]; then
    echo "release archive exceeds the 256 MiB installer bound" >&2
    exit 65
  fi
  mapfile -t checksum_matches < <(
    awk -v name="$archive_name" '$2 == name || $2 == "*" name {print $1}' "$checksums"
  )
  if [[ ${#checksum_matches[@]} -ne 1 || ! ${checksum_matches[0]} =~ ^[0-9a-f]{64}$ ]]; then
    echo "archive has no unique canonical checksum entry" >&2
    exit 65
  fi
  local actual
  actual=$(sha256sum "$archive" | awk '{print $1}')
  if [[ $actual != "${checksum_matches[0]}" ]]; then
    echo "release archive checksum mismatch" >&2
    exit 65
  fi
  if [[ -n $verify_repository ]]; then
    if [[ ! $verify_repository =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
      || ! command -v gh >/dev/null 2>&1; then
      echo "GitHub provenance verification was requested but cannot be enforced" >&2
      exit 69
    fi
    local release_tag signer_workflow
    release_tag=${archive_name#mealy-}
    release_tag=${release_tag%-"$archive_target".tar.gz}
    signer_workflow="$verify_repository/.github/workflows/release.yml"
    local bundle_arguments=()
    if [[ -n $attestation_bundle ]]; then
      bundle_arguments=(--bundle "$attestation_bundle")
    fi
    gh attestation verify "$archive" --repo "$verify_repository" \
      --signer-workflow "$signer_workflow" --source-ref "refs/tags/$release_tag" \
      --deny-self-hosted-runners "${bundle_arguments[@]}" >/dev/null
  fi

  local entries listing
  entries=$(tar -tzf "$archive")
  listing=$(tar --numeric-owner -tvzf "$archive")
  if [[ -z $entries ]] || ! printf '%s\n' "$listing" | awk '
    $1 !~ /^[-d]/ {exit 1}
    $3 !~ /^[0-9]+$/ {exit 1}
    {count += 1; total += $3}
    count > 96 || $3 > 268435456 || total > 536870912 {exit 1}
    END {if (count == 0) exit 1}
  '; then
    echo "release archive type, count, or expanded-size bound is invalid" >&2
    exit 65
  fi
  local unsafe_entry=false entry
  while IFS= read -r entry; do
    case "$entry" in
      /*|../*|*/../*|*/..)
        unsafe_entry=true
        ;;
    esac
  done <<<"$entries"
  if [[ $unsafe_entry == true ]]; then
    echo "release archive contains an unsafe path" >&2
    exit 65
  fi
  local root_count root expected_root
  root_count=$(printf '%s\n' "$entries" | sed 's#^\./##' | awk -F/ 'NF {print $1}' | sort -u | wc -l)
  root=$(printf '%s\n' "$entries" | sed 's#^\./##' | awk -F/ 'NF {print $1; exit}')
  expected_root=${archive_name%.tar.gz}
  if [[ $root_count -ne 1 || $root != "$expected_root" ]]; then
    echo "release archive root is invalid" >&2
    exit 65
  fi

  tar -xzf "$archive" -C "$temporary" --no-same-owner --no-same-permissions
  local package="$temporary/$root"
  local unsafe_extracted
  unsafe_extracted=$(find "$package" \( -type l -o ! -type f -a ! -type d \) -print -quit)
  if [[ -n $unsafe_extracted ]]; then
    echo "release archive extracted an unsupported file type" >&2
    exit 65
  fi
  local expected_files=(
    bin/mealyd
    bin/mealyctl
    install.sh
    install-release.sh
    fetch-browser-runtime.sh
    BUILD-MANIFEST.json
    SBOM.cdx.json
    LICENSE
    THIRD-PARTY-LICENSES.html
    ARCHITECTURE.md
    README.md
    REQUIREMENTS.md
    SECURITY.md
    "${release_documents[@]/#/docs/}"
  )
  for entry in "${expected_files[@]}" PAYLOAD-SHA256SUMS; do
    if [[ ! -f $package/$entry ]]; then
      echo "release archive is missing $entry" >&2
      exit 65
    fi
  done
  [[ -x $package/bin/mealyd && -x $package/bin/mealyctl && -x $package/install.sh \
    && -x $package/install-release.sh && -x $package/fetch-browser-runtime.sh ]] || {
    echo "release archive executable modes are invalid" >&2
    exit 65
  }
  mapfile -t payload_paths < <(awk '{print $2}' "$package/PAYLOAD-SHA256SUMS")
  if [[ ${#payload_paths[@]} -ne ${#expected_files[@]} ]]; then
    echo "release payload checksum inventory is invalid" >&2
    exit 65
  fi
  local sorted_expected sorted_actual
  sorted_expected=$(printf '%s\n' "${expected_files[@]}" | sort)
  sorted_actual=$(printf '%s\n' "${payload_paths[@]}" | sort -u)
  if [[ $sorted_actual != "$sorted_expected" ]]; then
    echo "release payload checksum inventory is not exact" >&2
    exit 65
  fi
  mapfile -t extracted_files < <(find "$package" -type f -printf '%P\n' | sort)
  local expected_extracted
  expected_extracted=$(printf '%s\n' "${expected_files[@]}" PAYLOAD-SHA256SUMS | sort)
  if [[ $(printf '%s\n' "${extracted_files[@]}") != "$expected_extracted" ]]; then
    echo "release archive contains an untracked file" >&2
    exit 65
  fi
  if ! (cd "$package" && sha256sum --check --strict PAYLOAD-SHA256SUMS >/dev/null); then
    echo "release payload checksum verification failed" >&2
    exit 65
  fi
  local manifest_version manifest_target
  manifest_version=$(jq -er '.version' "$package/BUILD-MANIFEST.json")
  manifest_target=$(jq -er '.target' "$package/BUILD-MANIFEST.json")
  if ! jq -e '
      .schemaVersion == "mealy.release.v2"
      and (.commit | type == "string" and test("^[0-9a-f]{40}$"))
      and (.sourceDateEpoch | (type == "number" and . >= 0))
      and (.stateSchemaVersion | (type == "number" and . >= 1 and . <= 9999))
      and .sbom == "SBOM.cdx.json"
      and .licenses == "THIRD-PARTY-LICENSES.html"
    ' "$package/BUILD-MANIFEST.json" >/dev/null \
    || [[ $root != "mealy-v${manifest_version}-${manifest_target}" ]] \
    || ! jq -e '.bomFormat == "CycloneDX" and (.components | type == "array" and length > 0)' \
      "$package/SBOM.cdx.json" >/dev/null; then
    echo "release manifest or SBOM identity is invalid" >&2
    exit 65
  fi

  local active_metadata="$prefix/share/mealy"
  local previous_metadata="$prefix/share/mealy.previous"
  local current_present=false previous_present=false
  if slot_state "" "$active_metadata"; then current_present=true; fi
  if slot_state ".previous" "$previous_metadata"; then previous_present=true; fi
  if [[ $current_present == false && $previous_present == true ]]; then
    echo "previous Mealy slot exists without a managed active installation" >&2
    exit 65
  fi

  local backup="$temporary/current-backup"
  if [[ $current_present == true ]]; then
    mkdir -p "$backup/bin"
    cp -p "$prefix/bin/mealyd" "$backup/bin/mealyd"
    cp -p "$prefix/bin/mealyctl" "$backup/bin/mealyctl"
    cp -a "$active_metadata" "$backup/mealy"
  fi
  local binary_stage_suffix=".new.$$"
  local metadata_stage="$prefix/share/.mealy.new.$$"
  install -m 0755 "$package/bin/mealyd" "$prefix/bin/mealyd$binary_stage_suffix"
  install -m 0755 "$package/bin/mealyctl" "$prefix/bin/mealyctl$binary_stage_suffix"
  copy_package_metadata "$package" "$metadata_stage"

  local installed=false
  restore_current() {
    set +e
    rm -f "$prefix/bin/mealyd$binary_stage_suffix" "$prefix/bin/mealyctl$binary_stage_suffix"
    rm -rf "$metadata_stage"
    if [[ $current_present == true ]]; then
      install -m 0755 "$backup/bin/mealyd" "$prefix/bin/mealyd"
      install -m 0755 "$backup/bin/mealyctl" "$prefix/bin/mealyctl"
      rm -rf "$active_metadata"
      cp -a "$backup/mealy" "$active_metadata"
    else
      rm -f "$prefix/bin/mealyd" "$prefix/bin/mealyctl"
      rm -rf "$active_metadata"
    fi
    if [[ $installed == true ]]; then
      rm -f "$prefix/bin/mealyd.previous" "$prefix/bin/mealyctl.previous"
      rm -rf "$previous_metadata"
    fi
    set -e
  }

  if ! mv -f "$prefix/bin/mealyd$binary_stage_suffix" "$prefix/bin/mealyd" \
    || ! mv -f "$prefix/bin/mealyctl$binary_stage_suffix" "$prefix/bin/mealyctl"; then
    restore_current
    echo "release binary replacement failed and was rolled back" >&2
    exit 74
  fi
  if ! rm -rf "$active_metadata" \
    || ! mv "$metadata_stage" "$active_metadata" \
    || ! verify_managed_slot "" "$active_metadata"; then
    restore_current
    echo "release metadata replacement failed and was rolled back" >&2
    exit 74
  fi

  if [[ $current_present == true ]]; then
    installed=true
    if ! install -m 0755 "$backup/bin/mealyd" "$prefix/bin/mealyd.previous" \
      || ! install -m 0755 "$backup/bin/mealyctl" "$prefix/bin/mealyctl.previous" \
      || ! rm -rf "$previous_metadata" \
      || ! cp -a "$backup/mealy" "$previous_metadata" \
      || ! verify_managed_slot ".previous" "$previous_metadata"; then
      restore_current
      echo "previous release preservation failed and the upgrade was rolled back" >&2
      exit 74
    fi
  elif [[ $previous_present == true ]]; then
    echo "unexpected previous installation state" >&2
    restore_current
    exit 65
  fi

  local manager_stage="$prefix/share/.mealy-manager.new.$$"
  if ! install -m 0755 "$package/install.sh" "$manager_stage" \
    || ! mv -f "$manager_stage" "$prefix/share/mealy-manager.sh"; then
    rm -f "$manager_stage"
    echo "release installed, but stable manager activation failed" >&2
    echo "use $active_metadata/manage-install.sh for repair" >&2
    exit 74
  fi

  echo "installed $root under $prefix"
  echo "managed release metadata, SBOM, and license notice: $active_metadata"
  if [[ $current_present == true ]]; then
    echo "previous matching release retained; run $prefix/share/mealy-manager.sh rollback --prefix $prefix --home $home"
  fi
}

capture_release_slots() {
  local backup=$1
  local active_metadata=$2
  local previous_metadata=$3
  mkdir -p "$backup/current/bin" "$backup/previous/bin"
  cp -p "$prefix/bin/mealyd" "$backup/current/bin/mealyd"
  cp -p "$prefix/bin/mealyctl" "$backup/current/bin/mealyctl"
  cp -a "$active_metadata" "$backup/current/mealy"
  cp -p "$prefix/bin/mealyd.previous" "$backup/previous/bin/mealyd"
  cp -p "$prefix/bin/mealyctl.previous" "$backup/previous/bin/mealyctl"
  cp -a "$previous_metadata" "$backup/previous/mealy"
}

restore_release_slots() {
  local backup=$1
  local active_metadata=$2
  local previous_metadata=$3
  local failed=false
  install -m 0755 "$backup/current/bin/mealyd" "$prefix/bin/mealyd" || failed=true
  install -m 0755 "$backup/current/bin/mealyctl" "$prefix/bin/mealyctl" || failed=true
  install -m 0755 "$backup/previous/bin/mealyd" "$prefix/bin/mealyd.previous" || failed=true
  install -m 0755 "$backup/previous/bin/mealyctl" "$prefix/bin/mealyctl.previous" || failed=true
  rm -rf "$active_metadata" "$previous_metadata" || failed=true
  cp -a "$backup/current/mealy" "$active_metadata" || failed=true
  cp -a "$backup/previous/mealy" "$previous_metadata" || failed=true
  [[ $failed == false ]]
}

exchange_release_slots() {
  local backup=$1
  local active_metadata=$2
  local previous_metadata=$3
  if ! install -m 0755 "$backup/previous/bin/mealyd" "$prefix/bin/mealyd" \
    || ! install -m 0755 "$backup/previous/bin/mealyctl" "$prefix/bin/mealyctl" \
    || ! install -m 0755 "$backup/current/bin/mealyd" "$prefix/bin/mealyd.previous" \
    || ! install -m 0755 "$backup/current/bin/mealyctl" "$prefix/bin/mealyctl.previous"; then
    restore_release_slots "$backup" "$active_metadata" "$previous_metadata" || true
    return 1
  fi
  if ! rm -rf "$active_metadata" "$previous_metadata" \
    || ! cp -a "$backup/previous/mealy" "$active_metadata" \
    || ! cp -a "$backup/current/mealy" "$previous_metadata" \
    || ! verify_managed_slot "" "$active_metadata" \
    || ! verify_managed_slot ".previous" "$previous_metadata"; then
    restore_release_slots "$backup" "$active_metadata" "$previous_metadata" || true
    return 1
  fi
}

verify_captured_release_slot() {
  local slot=$1
  local metadata="$slot/mealy"
  if [[ -L $slot || ! -d $slot || -L $slot/bin || ! -d $slot/bin \
    || -L $metadata || ! -d $metadata ]]; then
    return 1
  fi
  local logical actual expected
  for logical in bin/mealyd bin/mealyctl; do
    actual="$slot/$logical"
    if [[ -L $actual || ! -f $actual || ! -x $actual ]]; then
      return 1
    fi
    expected=$(expected_digest "$metadata" "$logical") || return 1
    [[ $(sha256sum "$actual" | awk '{print $1}') == "$expected" ]] || return 1
  done
  for logical in BUILD-MANIFEST.json SBOM.cdx.json install.sh install-release.sh \
    fetch-browser-runtime.sh \
    LICENSE THIRD-PARTY-LICENSES.html ARCHITECTURE.md README.md REQUIREMENTS.md SECURITY.md \
    "${release_documents[@]/#/docs/}"; do
    case "$logical" in
      install.sh) actual="$metadata/manage-install.sh" ;;
      install-release.sh) actual="$metadata/manage-release.sh" ;;
      fetch-browser-runtime.sh) actual="$metadata/fetch-browser-runtime.sh" ;;
      *) actual="$metadata/$logical" ;;
    esac
    if [[ -L $actual || ! -f $actual ]]; then
      return 1
    fi
    expected=$(expected_digest "$metadata" "$logical") || return 1
    [[ $(sha256sum "$actual" | awk '{print $1}') == "$expected" ]] || return 1
  done
  jq -e '
      .schemaVersion == "mealy.release.v2"
      and .licenses == "THIRD-PARTY-LICENSES.html"
      and (.stateSchemaVersion | (type == "number" and . >= 1 and . <= 9999))
    ' "$metadata/BUILD-MANIFEST.json" >/dev/null \
    && jq -e '.bomFormat == "CycloneDX" and (.components | type == "array" and length > 0)' \
      "$metadata/SBOM.cdx.json" >/dev/null
}

persist_migration_transaction_state() {
  local transaction=$1
  local state=$2
  printf '%s\n' "$state" >"$transaction/stage.new"
  chmod 0600 "$transaction/stage.new"
  mv -f "$transaction/stage.new" "$transaction/stage"
  sync -f "$transaction/stage"
  sync -f "$transaction"
}

remove_migration_transaction() {
  local transaction=$1
  rm -rf "$transaction"
  sync -f "$prefix/share"
}

recover_interrupted_migration_transaction() {
  local transaction="$prefix/share/mealy-rollback-transaction"
  if [[ ! -e $transaction && ! -L $transaction ]]; then
    return
  fi
  if [[ $home_lock_acquired != true || -L $transaction || ! -d $transaction \
    || -L $transaction/request.json || ! -f $transaction/request.json \
    || -L $transaction/stage || ! -f $transaction/stage \
    || ! -d $transaction/slots ]]; then
    echo "interrupted migration rollback evidence is unsafe or the stopped home is unavailable" >&2
    echo "retain $transaction and recover manually before any package operation" >&2
    exit 74
  fi
  if ! jq -e \
    --arg home "$home" --arg prefix "$prefix" '
      (keys | sort) == [
        "formatVersion", "fromSchemaVersion", "home", "manifestDigest",
        "migrationBackup", "prefix", "toSchemaVersion"
      ]
      and .formatVersion == 1
      and .home == $home
      and .prefix == $prefix
      and (.migrationBackup | type == "string" and length >= 1 and length <= 96)
      and (.manifestDigest | type == "string" and test("^[0-9a-f]{64}$"))
      and (.fromSchemaVersion | type == "number" and . >= 1 and . <= 9999)
      and (.toSchemaVersion | type == "number" and . >= 1 and . <= 9999)
      and .toSchemaVersion > .fromSchemaVersion
    ' "$transaction/request.json" >/dev/null \
    || ! verify_captured_release_slot "$transaction/slots/current" \
    || ! verify_captured_release_slot "$transaction/slots/previous"; then
    echo "interrupted migration rollback evidence failed integrity validation" >&2
    echo "retain $transaction and recover manually before any package operation" >&2
    exit 74
  fi
  local transaction_stage
  transaction_stage=$(<"$transaction/stage")
  if [[ $transaction_stage != prepared && $transaction_stage != slots-swapped \
    && $transaction_stage != home-activated ]]; then
    echo "interrupted migration rollback stage is invalid" >&2
    echo "retain $transaction and recover manually before any package operation" >&2
    exit 74
  fi
  local migration_name manifest_digest from_schema to_schema
  migration_name=$(jq -er '.migrationBackup' "$transaction/request.json")
  manifest_digest=$(jq -er '.manifestDigest' "$transaction/request.json")
  from_schema=$(jq -er '.fromSchemaVersion' "$transaction/request.json")
  to_schema=$(jq -er '.toSchemaVersion' "$transaction/request.json")
  local active_metadata="$prefix/share/mealy"
  local previous_metadata="$prefix/share/mealy.previous"
  local activation_complete=false
  if [[ -f $home/migration-rollback-activation.json && ! -L $home/migration-rollback-activation.json ]] \
    && jq -e \
      --arg name "$migration_name" --arg digest "$manifest_digest" \
      --argjson from "$from_schema" --argjson to "$to_schema" '
        .migrationBackupName == $name
        and .manifestDigest == $digest
        and .fromSchemaVersion == $from
        and .toSchemaVersion == $to
      ' "$home/migration-rollback-activation.json" >/dev/null \
    && verify_managed_slot "" "$active_metadata" \
    && verify_managed_slot ".previous" "$previous_metadata" \
    && [[ $(jq -er '.stateSchemaVersion' "$active_metadata/BUILD-MANIFEST.json") -eq $from_schema ]] \
    && [[ $(jq -er '.stateSchemaVersion' "$previous_metadata/BUILD-MANIFEST.json") -eq $to_schema ]]; then
    activation_complete=true
  fi
  if [[ $activation_complete == true ]]; then
    remove_migration_transaction "$transaction"
    echo "finalized an interrupted cross-schema rollback whose atomic home activation completed"
    return
  fi
  if ! restore_release_slots "$transaction/slots" "$active_metadata" "$previous_metadata" \
    || ! verify_managed_slot "" "$active_metadata" \
    || ! verify_managed_slot ".previous" "$previous_metadata" \
    || [[ $(jq -er '.stateSchemaVersion' "$active_metadata/BUILD-MANIFEST.json") -ne $to_schema ]] \
    || [[ $(jq -er '.stateSchemaVersion' "$previous_metadata/BUILD-MANIFEST.json") -ne $from_schema ]]; then
    echo "automatic compensation of an interrupted migration rollback failed" >&2
    echo "retain $transaction and recover its verified slots manually" >&2
    exit 74
  fi
  remove_migration_transaction "$transaction"
  echo "compensated an interrupted cross-schema rollback before continuing"
}

rollback_release() {
  local active_metadata="$prefix/share/mealy"
  local previous_metadata="$prefix/share/mealy.previous"
  if ! slot_state "" "$active_metadata" || ! slot_state ".previous" "$previous_metadata"; then
    echo "both valid active and previous Mealy release slots are required" >&2
    exit 66
  fi
  local active_schema previous_schema
  active_schema=$(jq -er '.stateSchemaVersion' "$active_metadata/BUILD-MANIFEST.json")
  previous_schema=$(jq -er '.stateSchemaVersion' "$previous_metadata/BUILD-MANIFEST.json")
  if [[ $previous_schema -lt $active_schema ]]; then
    echo "rollback refused: the previous binary supports state schema $previous_schema but the active release supports $active_schema" >&2
    echo "use rollback-migration with the exact automatic snapshot name and manifest digest" >&2
    exit 65
  fi
  local backup="$temporary/rollback"
  capture_release_slots "$backup" "$active_metadata" "$previous_metadata"
  if ! exchange_release_slots "$backup" "$active_metadata" "$previous_metadata"; then
    echo "release rollback failed and the original slots were restored" >&2
    exit 74
  fi
  local active_version previous_version
  active_version=$(jq -r '.version' "$active_metadata/BUILD-MANIFEST.json")
  previous_version=$(jq -r '.version' "$previous_metadata/BUILD-MANIFEST.json")
  echo "activated Mealy $active_version; Mealy $previous_version is retained as the previous slot"
}

rollback_migration_release() {
  local active_metadata="$prefix/share/mealy"
  local previous_metadata="$prefix/share/mealy.previous"
  if [[ $home_lock_acquired != true ]]; then
    echo "cross-schema rollback requires an existing stopped Mealy home" >&2
    exit 66
  fi
  if ! slot_state "" "$active_metadata" || ! slot_state ".previous" "$previous_metadata"; then
    echo "both valid active and previous Mealy release slots are required" >&2
    exit 66
  fi
  local active_schema previous_schema
  active_schema=$(jq -er '.stateSchemaVersion' "$active_metadata/BUILD-MANIFEST.json")
  previous_schema=$(jq -er '.stateSchemaVersion' "$previous_metadata/BUILD-MANIFEST.json")
  if [[ $previous_schema -ge $active_schema ]]; then
    echo "rollback-migration requires a previous release with a lower state schema; use rollback" >&2
    exit 65
  fi

  local transaction="$prefix/share/mealy-rollback-transaction"
  local transaction_stage="$prefix/share/.mealy-rollback-transaction.new.$$"
  if [[ -e $transaction || -L $transaction || -e $transaction_stage \
    || -L $transaction_stage ]]; then
    echo "migration rollback transaction destination already exists" >&2
    exit 74
  fi
  if ! (
    set -e
    mkdir -m 0700 "$transaction_stage"
    capture_release_slots "$transaction_stage/slots" "$active_metadata" "$previous_metadata"
    install -m 0755 "$prefix/bin/mealyctl" "$transaction_stage/activation-mealyctl"
    test "$(sha256sum "$transaction_stage/activation-mealyctl" | awk '{print $1}')" = \
      "$(expected_digest "$active_metadata" bin/mealyctl)"
    jq -n \
      --arg home "$home" --arg prefix "$prefix" \
      --arg migrationBackup "$migration_backup" \
      --arg manifestDigest "$expected_manifest_digest" \
      --argjson fromSchemaVersion "$previous_schema" \
      --argjson toSchemaVersion "$active_schema" '
        {
          formatVersion: 1,
          home: $home,
          prefix: $prefix,
          migrationBackup: $migrationBackup,
          manifestDigest: $manifestDigest,
          fromSchemaVersion: $fromSchemaVersion,
          toSchemaVersion: $toSchemaVersion
        }
      ' >"$transaction_stage/request.json"
    chmod 0600 "$transaction_stage/request.json"
    printf 'prepared\n' >"$transaction_stage/stage"
    chmod 0600 "$transaction_stage/stage"
    sync -f "$transaction_stage"
  ); then
    rm -rf "$transaction_stage"
    echo "could not durably prepare the migration rollback transaction" >&2
    exit 74
  fi
  mv "$transaction_stage" "$transaction"
  sync -f "$prefix/share"

  local migration_cli="$transaction/activation-mealyctl"
  local backup="$transaction/slots"
  if ! exchange_release_slots "$backup" "$active_metadata" "$previous_metadata"; then
    remove_migration_transaction "$transaction"
    echo "cross-schema release-slot exchange failed and the original slots were restored" >&2
    exit 74
  fi
  persist_migration_transaction_state "$transaction" slots-swapped

  local activation_output="$temporary/migration-activation.json"
  if ! "$migration_cli" --home "$home" migration-home-activate "$migration_backup" \
    --expected-manifest-digest "$expected_manifest_digest" \
    --expected-from-schema-version "$previous_schema" \
    --expected-to-schema-version "$active_schema" \
    --inherited-home-lock-stdin --approve <&9 >"$activation_output"; then
    if ! restore_release_slots "$backup" "$active_metadata" "$previous_metadata"; then
      echo "migration-home activation failed and release-slot compensation also failed" >&2
      echo "retain $transaction for recovery with $prefix/share/mealy-manager.sh" >&2
      exit 74
    fi
    remove_migration_transaction "$transaction"
    echo "migration-home activation failed; the original release slots were restored" >&2
    exit 74
  fi
  persist_migration_transaction_state "$transaction" home-activated
  remove_migration_transaction "$transaction"

  if jq -e \
    --arg name "$migration_backup" \
    --arg digest "$expected_manifest_digest" \
    --argjson from "$previous_schema" \
    --argjson to "$active_schema" '
      .migrationBackupName == $name
      and .manifestDigest == $digest
      and .fromSchemaVersion == $from
      and .toSchemaVersion == $to
      and (.preservedHome | type == "string" and length > 0)
    ' "$activation_output" >/dev/null; then
    jq . "$activation_output"
  else
    echo "warning: migration home was activated but its success response was not canonical" >&2
  fi
  local active_version previous_version
  active_version=$(jq -r '.version' "$active_metadata/BUILD-MANIFEST.json")
  previous_version=$(jq -r '.version' "$previous_metadata/BUILD-MANIFEST.json")
  echo "activated Mealy $active_version with state schema $previous_schema"
  echo "Mealy $previous_version and the complete migrated home are retained for forward recovery"
}

uninstall_release() {
  local active_metadata="$prefix/share/mealy"
  local previous_metadata="$prefix/share/mealy.previous"
  local current_present=false previous_present=false
  local stable_manager="$prefix/share/mealy-manager.sh"
  if slot_state "" "$active_metadata"; then current_present=true; fi
  if slot_state ".previous" "$previous_metadata"; then previous_present=true; fi
  if [[ $current_present == false ]]; then
    echo "no managed Mealy installation exists under $prefix" >&2
    exit 66
  fi
  if [[ -e $stable_manager || -L $stable_manager ]]; then
    if [[ -L $stable_manager || ! -f $stable_manager ]]; then
      echo "stable Mealy manager is not a real file" >&2
      exit 65
    fi
    local manager_digest active_manager_digest previous_manager_digest=
    manager_digest=$(sha256sum "$stable_manager" | awk '{print $1}')
    active_manager_digest=$(expected_digest "$active_metadata" install.sh)
    if [[ $previous_present == true ]]; then
      previous_manager_digest=$(expected_digest "$previous_metadata" install.sh)
    fi
    if [[ $manager_digest != "$active_manager_digest" \
      && $manager_digest != "$previous_manager_digest" ]]; then
      echo "stable Mealy manager does not match either verified release slot" >&2
      exit 65
    fi
  fi
  local backup="$temporary/uninstall"
  mkdir -p "$backup/current/bin"
  cp -p "$prefix/bin/mealyd" "$backup/current/bin/mealyd"
  cp -p "$prefix/bin/mealyctl" "$backup/current/bin/mealyctl"
  cp -a "$active_metadata" "$backup/current/mealy"
  if [[ -f $stable_manager ]]; then
    cp -p "$stable_manager" "$backup/mealy-manager.sh"
  fi
  if [[ $previous_present == true ]]; then
    mkdir -p "$backup/previous/bin"
    cp -p "$prefix/bin/mealyd.previous" "$backup/previous/bin/mealyd"
    cp -p "$prefix/bin/mealyctl.previous" "$backup/previous/bin/mealyctl"
    cp -a "$previous_metadata" "$backup/previous/mealy"
  fi
  if ! rm -f "$prefix/bin/mealyd" "$prefix/bin/mealyctl" \
    "$prefix/bin/mealyd.previous" "$prefix/bin/mealyctl.previous" \
    || ! rm -f "$stable_manager" \
    || ! rm -rf "$active_metadata" "$previous_metadata"; then
    set +e
    install -m 0755 "$backup/current/bin/mealyd" "$prefix/bin/mealyd"
    install -m 0755 "$backup/current/bin/mealyctl" "$prefix/bin/mealyctl"
    cp -a "$backup/current/mealy" "$active_metadata"
    if [[ -f $backup/mealy-manager.sh ]]; then
      install -m 0755 "$backup/mealy-manager.sh" "$stable_manager"
    fi
    if [[ $previous_present == true ]]; then
      install -m 0755 "$backup/previous/bin/mealyd" "$prefix/bin/mealyd.previous"
      install -m 0755 "$backup/previous/bin/mealyctl" "$prefix/bin/mealyctl.previous"
      cp -a "$backup/previous/mealy" "$previous_metadata"
    fi
    set -e
    echo "uninstall failed and managed files were restored" >&2
    exit 74
  fi
  echo "uninstalled managed Mealy program files from $prefix"
  echo "durable home preserved at $home"
}

recover_interrupted_migration_transaction

case "$action" in
  install) install_release ;;
  rollback) rollback_release ;;
  rollback-migration) rollback_migration_release ;;
  uninstall) uninstall_release ;;
esac
