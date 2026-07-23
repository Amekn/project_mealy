//! Install-provenance and release-slot inspection for owner-facing lifecycle operations.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};
use thiserror::Error;

const STATUS_SCHEMA_VERSION: &str = "mealy.install-status.v1";
const RELEASE_SCHEMA_VERSION: &str = "mealy.release.v2";
const MAXIMUM_MANIFEST_BYTES: u64 = 64 * 1024;
const MAXIMUM_CHECKSUM_BYTES: u64 = 1024 * 1024;
const MAXIMUM_PAYLOAD_FILES: usize = 96;
const MAXIMUM_PAYLOAD_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_UPDATE_CHECK_BYTES: usize = 64 * 1024;
const RELEASE_REPOSITORY: &str = "Amekn/project_mealy";
const STABLE_MANAGER_ISSUE: &str =
    "stable release manager is absent, redirected, or does not match a verified slot";

/// Supported installation provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum InstallationKind {
    /// Owner-local atomic release slots managed by the attested archive installer.
    ManagedArchive,
    /// A Debian-family package owns `/usr/lib/mealy/release`.
    DebianPackage,
    /// An RPM-family package owns `/usr/lib/mealy/release`.
    RpmPackage,
    /// An Arch-family package owns `/usr/lib/mealy/release`.
    ArchPackage,
    /// `/usr/lib/mealy/release` exists, but its package database is unavailable or inconsistent.
    NativePackageUnknown,
    /// A source/development binary with no published release metadata.
    Development,
    /// A binary layout not owned by a supported lifecycle backend.
    Unknown,
}

/// Result of verifying the complete active release checksum inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum IntegrityStatus {
    /// Every declared release file is a no-follow regular file with the exact signed digest.
    Verified,
    /// The installation resembles a release, but one or more invariants failed.
    Failed,
    /// No published release slot is present to verify.
    NotApplicable,
}

/// How updates are safely owned for this installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum UpdateMode {
    /// The verified owner-local release bootstrap may stage an attested archive update.
    AttestedArchive,
    /// Debian tooling owns program-file mutation.
    Apt,
    /// RPM tooling owns program-file mutation.
    Dnf,
    /// Arch tooling owns program-file mutation.
    Pacman,
    /// Native package ownership must be repaired before update.
    NativePackageRepairRequired,
    /// No production update backend owns this binary.
    Unsupported,
}

/// Bounded, non-secret installation report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InstallationStatus {
    /// Stable output contract.
    pub(crate) schema_version: &'static str,
    /// Detected install provenance.
    pub(crate) installation_kind: InstallationKind,
    /// Complete active-slot verification result.
    pub(crate) integrity: IntegrityStatus,
    /// Version declared by the active release, or the compiled version outside a release.
    pub(crate) current_version: String,
    /// Durable state schema supported by the active published release.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) state_schema_version: Option<u64>,
    /// Published release target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) target: Option<String>,
    /// Canonical executable inspected.
    pub(crate) executable: PathBuf,
    /// Active release metadata root, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) release_root: Option<PathBuf>,
    /// Owner-local prefix for a managed archive installation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) managed_prefix: Option<PathBuf>,
    /// Safely delegated update backend.
    pub(crate) update_mode: UpdateMode,
    /// Whether a complete verified previous archive slot is available.
    pub(crate) rollback_available: bool,
    /// Exact package-manager handoff for native installs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) native_update_command: Option<String>,
    /// Bounded invariant failures. Empty when integrity is verified or not applicable.
    pub(crate) issues: Vec<String>,
}

/// Fully attested target identity returned by the bundled release bootstrap.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpdateCandidate {
    /// Stable output contract.
    pub(crate) schema_version: String,
    /// Stable semantic target version without the `v` tag prefix.
    pub(crate) version: String,
    /// Exact GNU/Linux artifact target.
    pub(crate) target: String,
    /// Source commit bound into the target archive.
    pub(crate) commit: String,
    /// Durable state schema supported by the target.
    pub(crate) state_schema_version: u64,
    /// True only after provenance, checksum, and target-manifest verification.
    pub(crate) verified: bool,
}

/// Non-mutating update decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdatePlan {
    /// Stable output contract.
    pub(crate) schema_version: &'static str,
    /// Current verified installation.
    pub(crate) installation: InstallationStatus,
    /// Requested tag or `latest`.
    pub(crate) requested_version: String,
    /// Fully verified candidate.
    pub(crate) candidate: UpdateCandidate,
    /// Whether the target is strictly newer than the active version.
    pub(crate) update_available: bool,
    /// Whether the target uses the active durable-state schema.
    pub(crate) state_schema_compatible: bool,
    /// Whether this install backend can apply the candidate without a package manager.
    pub(crate) apply_supported: bool,
    /// Native package-manager handoff, when native ownership applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) native_update_command: Option<String>,
}

/// Owner-facing installed-program maintenance operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum MaintenanceOperation {
    /// Restore only bounded program-management evidence.
    Repair,
    /// Exchange verified active and previous owner-local release slots.
    Rollback,
    /// Remove program files while preserving the durable home.
    Uninstall,
}

/// Non-mutating maintenance plan.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MaintenancePlan {
    /// Stable output contract.
    pub(crate) schema_version: &'static str,
    /// Requested lifecycle operation.
    pub(crate) operation: MaintenanceOperation,
    /// Current install provenance and integrity.
    pub(crate) installation: InstallationStatus,
    /// Whether a mutation is currently necessary.
    pub(crate) action_required: bool,
    /// Whether mealyctl can safely delegate the exact mutation.
    pub(crate) apply_supported: bool,
    /// Whether the daemon must be drained and stopped before apply.
    pub(crate) requires_stopped_daemon: bool,
    /// Durable user state is never deleted by these program-file operations.
    pub(crate) preserves_home: bool,
    /// Native package-manager handoff when native ownership applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) native_command: Option<String>,
}

#[derive(Debug, Error)]
pub(crate) enum LifecycleError {
    #[error("cannot inspect the current executable: {0}")]
    CurrentExecutable(#[source] io::Error),
    #[error("published installation integrity verification failed")]
    IntegrityFailed,
    #[error("this installation has no supported release bootstrap")]
    UnsupportedUpdate,
    #[error("update version must be `latest` or a stable tag such as v1.2.3")]
    InvalidUpdateVersion,
    #[error("verified release update check failed with exit status {0}")]
    UpdateCheckFailed(String),
    #[error("verified release update check returned malformed or inconsistent data")]
    InvalidUpdateCheck,
    #[error("verified release installer failed with exit status {0}")]
    UpdateApplyFailed(String),
    #[error("owner-local update requires a managed archive installation")]
    ArchiveUpdateRequired,
    #[error("the stable release manager cannot be repaired from this installation")]
    RepairUnavailable,
    #[error("stable release manager repair failed: {0}")]
    RepairFailed(#[source] io::Error),
    #[error("managed archive {action} failed with exit status {status}")]
    ManagerActionFailed {
        /// Bounded operation name.
        action: &'static str,
        /// Numeric exit code or signal.
        status: String,
    },
    #[error("managed archive {0} is unavailable for this installation")]
    ManagerActionUnavailable(&'static str),
}

#[derive(Clone, Copy)]
pub(crate) enum ArchiveManagerAction {
    Rollback,
    Uninstall,
}

impl ArchiveManagerAction {
    const fn name(self) -> &'static str {
        match self {
            Self::Rollback => "rollback",
            Self::Uninstall => "uninstall",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseManifest {
    schema_version: String,
    version: String,
    target: String,
    commit: String,
    source_date_epoch: u64,
    state_schema_version: u64,
    sbom: String,
    licenses: String,
}

#[derive(Clone, Copy)]
enum SlotLayout<'a> {
    Archive {
        prefix: &'a Path,
        metadata: &'a Path,
        suffix: &'a str,
    },
    Native {
        root: &'a Path,
    },
}

struct SlotInspection {
    manifest: Option<ReleaseManifest>,
    issues: Vec<String>,
}

/// Inspect the executable that is actually servicing this invocation.
pub(crate) fn inspect_current_installation() -> Result<InstallationStatus, LifecycleError> {
    let executable = std::env::current_exe().map_err(LifecycleError::CurrentExecutable)?;
    let executable = fs::canonicalize(&executable).map_err(LifecycleError::CurrentExecutable)?;
    Ok(inspect_executable(&executable))
}

/// Build a no-mutation plan for repair, rollback, or uninstall.
pub(crate) fn plan_maintenance(
    operation: MaintenanceOperation,
) -> Result<MaintenancePlan, LifecycleError> {
    let installation = inspect_current_installation()?;
    let archive = installation.installation_kind == InstallationKind::ManagedArchive;
    let native_command = native_maintenance_command(&installation, operation);
    let (action_required, apply_supported, requires_stopped_daemon) = match operation {
        MaintenanceOperation::Repair => (
            installation.integrity == IntegrityStatus::Failed,
            archive
                && installation
                    .issues
                    .iter()
                    .all(|issue| issue == STABLE_MANAGER_ISSUE),
            false,
        ),
        MaintenanceOperation::Rollback => (
            installation.rollback_available,
            archive
                && installation.integrity == IntegrityStatus::Verified
                && installation.rollback_available,
            true,
        ),
        MaintenanceOperation::Uninstall => (
            matches!(
                installation.installation_kind,
                InstallationKind::ManagedArchive
                    | InstallationKind::DebianPackage
                    | InstallationKind::RpmPackage
                    | InstallationKind::ArchPackage
            ),
            archive && installation.integrity == IntegrityStatus::Verified,
            archive,
        ),
    };
    Ok(MaintenancePlan {
        schema_version: "mealy.maintenance-plan.v1",
        operation,
        installation,
        action_required,
        apply_supported,
        requires_stopped_daemon,
        preserves_home: true,
        native_command,
    })
}

/// Download and verify the requested target without mutating program files or private state.
pub(crate) fn plan_update(
    home: &Path,
    requested_version: &str,
) -> Result<UpdatePlan, LifecycleError> {
    if !valid_requested_version(requested_version) {
        return Err(LifecycleError::InvalidUpdateVersion);
    }
    let installation = inspect_current_installation()?;
    if installation.integrity != IntegrityStatus::Verified {
        return Err(LifecycleError::IntegrityFailed);
    }
    let bootstrap = update_bootstrap(&installation).ok_or(LifecycleError::UnsupportedUpdate)?;
    let canonical_home = absolute_path(home).map_err(LifecycleError::CurrentExecutable)?;
    let mut command = Command::new(bootstrap);
    command
        .arg("--check")
        .arg("--version")
        .arg(requested_version)
        .arg("--repository")
        .arg(RELEASE_REPOSITORY)
        .arg("--home")
        .arg(&canonical_home);
    if let Some(prefix) = installation.managed_prefix.as_ref() {
        command.arg("--prefix").arg(prefix);
    } else {
        command.arg("--prefix").arg("/usr");
    }
    let home_environment = std::env::var_os("HOME");
    command
        .env_clear()
        .env("PATH", lifecycle_path())
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if let Some(value) = home_environment {
        command.env("HOME", value);
    }
    let output = command
        .output()
        .map_err(|error| LifecycleError::UpdateCheckFailed(error.to_string()))?;
    if !output.status.success() {
        return Err(LifecycleError::UpdateCheckFailed(
            output
                .status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| code.to_string()),
        ));
    }
    if output.stdout.len() > MAXIMUM_UPDATE_CHECK_BYTES {
        return Err(LifecycleError::InvalidUpdateCheck);
    }
    let candidate: UpdateCandidate =
        serde_json::from_slice(&output.stdout).map_err(|_| LifecycleError::InvalidUpdateCheck)?;
    build_update_plan(installation, requested_version, candidate)
}

fn build_update_plan(
    installation: InstallationStatus,
    requested_version: &str,
    candidate: UpdateCandidate,
) -> Result<UpdatePlan, LifecycleError> {
    if candidate.schema_version != "mealy.update-check.v1"
        || !candidate.verified
        || !valid_release_version(&candidate.version)
        || !valid_sha256_commit(&candidate.commit)
        || !(1..=9999).contains(&candidate.state_schema_version)
        || installation.target.as_deref() != Some(candidate.target.as_str())
        || (requested_version != "latest"
            && requested_version.strip_prefix('v') != Some(candidate.version.as_str()))
    {
        return Err(LifecycleError::InvalidUpdateCheck);
    }
    let ordering = compare_stable_versions(&installation.current_version, &candidate.version)
        .ok_or(LifecycleError::InvalidUpdateCheck)?;
    let state_schema_compatible =
        installation.state_schema_version == Some(candidate.state_schema_version);
    let apply_supported = installation.installation_kind == InstallationKind::ManagedArchive
        && installation.update_mode == UpdateMode::AttestedArchive;
    Ok(UpdatePlan {
        schema_version: "mealy.update-plan.v1",
        requested_version: requested_version.to_owned(),
        update_available: ordering.is_lt(),
        state_schema_compatible,
        apply_supported,
        native_update_command: installation.native_update_command.clone(),
        installation,
        candidate,
    })
}

/// Apply a previously checked, strictly newer, schema-compatible archive target.
pub(crate) fn apply_archive_update(home: &Path, plan: &UpdatePlan) -> Result<(), LifecycleError> {
    if !plan.update_available
        || !plan.state_schema_compatible
        || !plan.apply_supported
        || plan.installation.integrity != IntegrityStatus::Verified
        || plan.installation.installation_kind != InstallationKind::ManagedArchive
    {
        return Err(LifecycleError::ArchiveUpdateRequired);
    }
    let prefix = plan
        .installation
        .managed_prefix
        .as_ref()
        .ok_or(LifecycleError::ArchiveUpdateRequired)?;
    let bootstrap =
        update_bootstrap(&plan.installation).ok_or(LifecycleError::ArchiveUpdateRequired)?;
    let canonical_home = absolute_path(home).map_err(LifecycleError::CurrentExecutable)?;
    let home_environment = std::env::var_os("HOME");
    let mut command = Command::new(bootstrap);
    command
        .arg("--version")
        .arg(format!("v{}", plan.candidate.version))
        .arg("--repository")
        .arg(RELEASE_REPOSITORY)
        .arg("--prefix")
        .arg(prefix)
        .arg("--home")
        .arg(canonical_home)
        .env_clear()
        .env("PATH", lifecycle_path())
        .env("LC_ALL", "C")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(value) = home_environment {
        command.env("HOME", value);
    }
    let status = command
        .status()
        .map_err(|error| LifecycleError::UpdateApplyFailed(error.to_string()))?;
    if status.success() {
        Ok(())
    } else {
        Err(LifecycleError::UpdateApplyFailed(
            status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| code.to_string()),
        ))
    }
}

fn inspect_executable(executable: &Path) -> InstallationStatus {
    let compiled_version = env!("CARGO_PKG_VERSION").to_owned();
    if let Some(prefix) = archive_prefix(executable) {
        let release_root = prefix.join("share/mealy");
        if release_root.exists() || prefix.join("share/mealy-manager.sh").exists() {
            let mut active = inspect_slot(SlotLayout::Archive {
                prefix,
                metadata: &release_root,
                suffix: "",
            });
            let previous_root = prefix.join("share/mealy.previous");
            let previous = inspect_slot(SlotLayout::Archive {
                prefix,
                metadata: &previous_root,
                suffix: ".previous",
            });
            let rollback_available = previous.manifest.is_some() && previous.issues.is_empty();
            let stable_manager = prefix.join("share/mealy-manager.sh");
            let stable_digest = digest_regular_file(&stable_manager).ok();
            let active_manager_digest = expected_slot_digest(&release_root, "install.sh");
            let previous_manager_digest = rollback_available
                .then(|| expected_slot_digest(&previous_root, "install.sh"))
                .flatten();
            if stable_digest.is_none()
                || (stable_digest != active_manager_digest
                    && stable_digest != previous_manager_digest)
            {
                active.issues.push(STABLE_MANAGER_ISSUE.to_owned());
            }
            return published_status(
                executable,
                InstallationKind::ManagedArchive,
                UpdateMode::AttestedArchive,
                Some(prefix.to_owned()),
                release_root,
                active,
                rollback_available,
                None,
            );
        }
    }

    let native_root = Path::new("/usr/lib/mealy/release");
    if executable == native_root.join("bin/mealyctl") {
        let (kind, mode, command) = native_package_owner();
        return published_status(
            executable,
            kind,
            mode,
            None,
            native_root.to_owned(),
            inspect_slot(SlotLayout::Native { root: native_root }),
            false,
            command,
        );
    }

    let kind = if executable
        .components()
        .any(|component| component.as_os_str() == "target")
    {
        InstallationKind::Development
    } else {
        InstallationKind::Unknown
    };
    InstallationStatus {
        schema_version: STATUS_SCHEMA_VERSION,
        installation_kind: kind,
        integrity: IntegrityStatus::NotApplicable,
        current_version: compiled_version,
        state_schema_version: None,
        target: None,
        executable: executable.to_owned(),
        release_root: None,
        managed_prefix: None,
        update_mode: UpdateMode::Unsupported,
        rollback_available: false,
        native_update_command: None,
        issues: Vec::new(),
    }
}

/// Restore only the stable archive manager from the complete verified active slot.
pub(crate) fn repair_archive_manager(
    installation: &InstallationStatus,
) -> Result<(), LifecycleError> {
    if installation.installation_kind != InstallationKind::ManagedArchive
        || installation
            .issues
            .iter()
            .any(|issue| issue != STABLE_MANAGER_ISSUE)
    {
        return Err(LifecycleError::RepairUnavailable);
    }
    let prefix = installation
        .managed_prefix
        .as_ref()
        .ok_or(LifecycleError::RepairUnavailable)?;
    let metadata = installation
        .release_root
        .as_ref()
        .ok_or(LifecycleError::RepairUnavailable)?;
    let active = inspect_slot(SlotLayout::Archive {
        prefix,
        metadata,
        suffix: "",
    });
    if active.manifest.is_none() || !active.issues.is_empty() {
        return Err(LifecycleError::RepairUnavailable);
    }
    let source = metadata.join("manage-install.sh");
    let source_bytes = read_bounded_regular_file(&source, 2 * 1024 * 1024)
        .map_err(LifecycleError::RepairFailed)?;
    let share = prefix.join("share");
    let share_metadata = fs::symlink_metadata(&share).map_err(LifecycleError::RepairFailed)?;
    if share_metadata.file_type().is_symlink() || !share_metadata.is_dir() {
        return Err(LifecycleError::RepairUnavailable);
    }
    let destination = share.join("mealy-manager.sh");
    let temporary = share.join(format!(".mealy-manager.repair.{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o700);
    let mut file = options
        .open(&temporary)
        .map_err(LifecycleError::RepairFailed)?;
    let result = (|| -> io::Result<()> {
        file.write_all(&source_bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &destination)?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o755))?;
        File::open(&share)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(LifecycleError::RepairFailed)?;
    if digest_regular_file(&destination).ok() != expected_slot_digest(metadata, "install.sh") {
        return Err(LifecycleError::RepairUnavailable);
    }
    Ok(())
}

/// Invoke one exact action through the verified stable archive manager.
pub(crate) fn run_archive_manager(
    installation: &InstallationStatus,
    home: &Path,
    action: ArchiveManagerAction,
) -> Result<(), LifecycleError> {
    if installation.installation_kind != InstallationKind::ManagedArchive
        || installation.integrity != IntegrityStatus::Verified
        || (matches!(action, ArchiveManagerAction::Rollback) && !installation.rollback_available)
    {
        return Err(LifecycleError::ManagerActionUnavailable(action.name()));
    }
    let prefix = installation
        .managed_prefix
        .as_ref()
        .ok_or(LifecycleError::ManagerActionUnavailable(action.name()))?;
    let manager = prefix.join("share/mealy-manager.sh");
    let canonical_home = absolute_path(home).map_err(LifecycleError::CurrentExecutable)?;
    let home_environment = std::env::var_os("HOME");
    let mut command = Command::new(manager);
    command
        .arg(action.name())
        .arg("--prefix")
        .arg(prefix)
        .arg("--home")
        .arg(canonical_home)
        .env_clear()
        .env("PATH", lifecycle_path())
        .env("LC_ALL", "C")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(value) = home_environment {
        command.env("HOME", value);
    }
    let status = command.status().map_err(LifecycleError::RepairFailed)?;
    if status.success() {
        Ok(())
    } else {
        Err(LifecycleError::ManagerActionFailed {
            action: action.name(),
            status: status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| code.to_string()),
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn published_status(
    executable: &Path,
    kind: InstallationKind,
    mode: UpdateMode,
    prefix: Option<PathBuf>,
    release_root: PathBuf,
    mut slot: SlotInspection,
    rollback_available: bool,
    native_update_command: Option<String>,
) -> InstallationStatus {
    if slot
        .manifest
        .as_ref()
        .is_some_and(|manifest| manifest.version != env!("CARGO_PKG_VERSION"))
    {
        slot.issues
            .push("active release manifest version does not match the running mealyctl".to_owned());
    }
    slot.issues.sort();
    slot.issues.dedup();
    let integrity = if slot.issues.is_empty() && slot.manifest.is_some() {
        IntegrityStatus::Verified
    } else {
        IntegrityStatus::Failed
    };
    let current_version = slot.manifest.as_ref().map_or_else(
        || env!("CARGO_PKG_VERSION").to_owned(),
        |value| value.version.clone(),
    );
    let state_schema_version = slot
        .manifest
        .as_ref()
        .map(|value| value.state_schema_version);
    let target = slot.manifest.as_ref().map(|value| value.target.clone());
    InstallationStatus {
        schema_version: STATUS_SCHEMA_VERSION,
        installation_kind: kind,
        integrity,
        current_version,
        state_schema_version,
        target,
        executable: executable.to_owned(),
        release_root: Some(release_root),
        managed_prefix: prefix,
        update_mode: mode,
        rollback_available,
        native_update_command,
        issues: slot.issues,
    }
}

fn archive_prefix(executable: &Path) -> Option<&Path> {
    if executable.file_name()?.to_str()? != "mealyctl"
        || executable.parent()?.file_name()?.to_str()? != "bin"
    {
        return None;
    }
    executable.parent()?.parent()
}

fn inspect_slot(layout: SlotLayout<'_>) -> SlotInspection {
    let metadata = match layout {
        SlotLayout::Archive { metadata, .. } => metadata,
        SlotLayout::Native { root } => root,
    };
    let mut issues = Vec::new();
    let manifest_path = metadata.join("BUILD-MANIFEST.json");
    let manifest =
        if let Ok(bytes) = read_bounded_regular_file(&manifest_path, MAXIMUM_MANIFEST_BYTES) {
            match serde_json::from_slice::<ReleaseManifest>(&bytes) {
                Ok(manifest) if valid_release_manifest(&manifest) => Some(manifest),
                Ok(_) | Err(_) => {
                    issues.push("release manifest is malformed or violates its schema".to_owned());
                    None
                }
            }
        } else {
            issues.push("release manifest is absent, redirected, or unreadable".to_owned());
            None
        };
    let checksums_path = metadata.join("PAYLOAD-SHA256SUMS");
    let Ok(entries) =
        read_bounded_regular_file(&checksums_path, MAXIMUM_CHECKSUM_BYTES).and_then(|bytes| {
            parse_checksum_manifest(&bytes)
                .map_err(|message| io::Error::new(io::ErrorKind::InvalidData, message))
        })
    else {
        issues.push("release checksum inventory is absent or non-canonical".to_owned());
        return SlotInspection { manifest, issues };
    };
    for required in [
        "bin/mealyd",
        "bin/mealyctl",
        "install.sh",
        "install-release.sh",
        "fetch-browser-runtime.sh",
        "BUILD-MANIFEST.json",
        "SBOM.cdx.json",
        "LICENSE",
        "THIRD-PARTY-LICENSES.html",
        "README.md",
    ] {
        if !entries.contains_key(required) {
            issues.push(format!("release checksum inventory omits {required}"));
        }
    }
    for (logical, expected) in &entries {
        let actual = slot_path(layout, logical);
        match digest_regular_file(&actual) {
            Ok(actual_digest) if &actual_digest == expected => {}
            Ok(_) => issues.push(format!("release file digest does not match: {logical}")),
            Err(_) => issues.push(format!(
                "release file is absent, redirected, oversized, or unreadable: {logical}"
            )),
        }
    }
    SlotInspection { manifest, issues }
}

fn slot_path(layout: SlotLayout<'_>, logical: &str) -> PathBuf {
    match layout {
        SlotLayout::Native { root } => root.join(logical),
        SlotLayout::Archive {
            prefix,
            metadata,
            suffix,
        } => match logical {
            "bin/mealyd" => prefix.join(format!("bin/mealyd{suffix}")),
            "bin/mealyctl" => prefix.join(format!("bin/mealyctl{suffix}")),
            "install.sh" => metadata.join("manage-install.sh"),
            "install-release.sh" => metadata.join("manage-release.sh"),
            _ => metadata.join(logical),
        },
    }
}

fn read_bounded_regular_file(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let file = open_no_follow(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file is not a bounded no-follow regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file is too large",
        ));
    }
    Ok(bytes)
}

fn digest_regular_file(path: &Path) -> io::Result<String> {
    let mut file = open_no_follow(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAXIMUM_PAYLOAD_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "payload is not a bounded no-follow regular file",
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "payload is too large"))?;
        if total > MAXIMUM_PAYLOAD_FILE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "payload is too large",
            ));
        }
        hasher.update(&buffer[..count]);
    }
    Ok(lowercase_hex(&hasher.finalize()))
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags, open};

    open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(Into::into)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> io::Result<File> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "redirected file is not supported",
        ));
    }
    File::open(path)
}

fn parse_checksum_manifest(bytes: &[u8]) -> Result<BTreeMap<String, String>, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "checksum inventory is not UTF-8")?;
    if text.is_empty() || !text.ends_with('\n') || text.contains('\r') {
        return Err("checksum inventory has non-canonical line endings");
    }
    let mut entries = BTreeMap::new();
    for line in text.lines() {
        let (digest, logical) = line
            .split_once("  ")
            .ok_or("checksum entry has no canonical separator")?;
        if !valid_sha256(digest)
            || logical.is_empty()
            || logical.len() > 512
            || logical.chars().any(char::is_control)
        {
            return Err("checksum entry is malformed");
        }
        let path = Path::new(logical);
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            || entries
                .insert(logical.to_owned(), digest.to_owned())
                .is_some()
        {
            return Err("checksum entry path is unsafe or duplicated");
        }
        if entries.len() > MAXIMUM_PAYLOAD_FILES {
            return Err("checksum inventory exceeds its file bound");
        }
    }
    Ok(entries)
}

fn expected_slot_digest(metadata: &Path, logical: &str) -> Option<String> {
    let bytes =
        read_bounded_regular_file(&metadata.join("PAYLOAD-SHA256SUMS"), MAXIMUM_CHECKSUM_BYTES)
            .ok()?;
    parse_checksum_manifest(&bytes).ok()?.remove(logical)
}

fn valid_release_manifest(manifest: &ReleaseManifest) -> bool {
    manifest.schema_version == RELEASE_SCHEMA_VERSION
        && valid_release_version(&manifest.version)
        && matches!(
            manifest.target.as_str(),
            "linux-x86_64-gnu" | "linux-aarch64-gnu"
        )
        && manifest.commit.len() == 40
        && manifest
            .commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && manifest.source_date_epoch > 0
        && (1..=9999).contains(&manifest.state_schema_version)
        && manifest.sbom == "SBOM.cdx.json"
        && manifest.licenses == "THIRD-PARTY-LICENSES.html"
}

fn valid_release_version(version: &str) -> bool {
    if version.is_empty() || version.len() > 64 {
        return false;
    }
    let core = version.split_once('-').map_or(version, |(core, _)| core);
    let mut parts = core.split('.');
    let valid_part = |part: &str| {
        !part.is_empty()
            && part.len() <= 10
            && part.bytes().all(|byte| byte.is_ascii_digit())
            && (part == "0" || !part.starts_with('0'))
    };
    valid_part(parts.next().unwrap_or_default())
        && valid_part(parts.next().unwrap_or_default())
        && valid_part(parts.next().unwrap_or_default())
        && parts.next().is_none()
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_sha256_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_requested_version(value: &str) -> bool {
    value == "latest" || value.strip_prefix('v').is_some_and(valid_release_version)
}

fn stable_version_numbers(value: &str) -> Option<[u64; 3]> {
    if !valid_release_version(value) || value.contains(['-', '+']) {
        return None;
    }
    let mut parts = value.split('.');
    let numbers = [
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ];
    parts.next().is_none().then_some(numbers)
}

fn compare_stable_versions(left: &str, right: &str) -> Option<std::cmp::Ordering> {
    Some(stable_version_numbers(left)?.cmp(&stable_version_numbers(right)?))
}

fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is empty or contains parent traversal",
        ));
    }
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn lifecycle_path() -> OsString {
    let mut paths = vec![
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
    ];
    if let Some(value) = std::env::var_os("PATH")
        && value.len() <= 8 * 1024
    {
        for path in std::env::split_paths(&value).take(64) {
            if path.is_absolute()
                && path
                    .components()
                    .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
                && !paths.contains(&path)
            {
                paths.push(path);
            }
        }
    }
    std::env::join_paths(paths).unwrap_or_else(|_| OsString::from("/usr/local/bin:/usr/bin:/bin"))
}

fn update_bootstrap(installation: &InstallationStatus) -> Option<PathBuf> {
    let root = installation.release_root.as_ref()?;
    let path = match installation.installation_kind {
        InstallationKind::ManagedArchive => root.join("manage-release.sh"),
        InstallationKind::DebianPackage
        | InstallationKind::RpmPackage
        | InstallationKind::ArchPackage
        | InstallationKind::NativePackageUnknown => root.join("install-release.sh"),
        InstallationKind::Development | InstallationKind::Unknown => return None,
    };
    let metadata = fs::symlink_metadata(&path).ok()?;
    (!metadata.file_type().is_symlink()
        && metadata.is_file()
        && metadata.permissions().mode() & 0o111 != 0)
        .then_some(path)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn native_package_owner() -> (InstallationKind, UpdateMode, Option<String>) {
    let probes: [(&str, &[&str], InstallationKind, UpdateMode, &str); 3] = [
        (
            "/usr/bin/dpkg-query",
            &["--show", "--showformat=${Status}", "mealy"],
            InstallationKind::DebianPackage,
            UpdateMode::Apt,
            "sudo apt update && sudo apt install --only-upgrade mealy",
        ),
        (
            "/usr/bin/rpm",
            &["--query", "mealy"],
            InstallationKind::RpmPackage,
            UpdateMode::Dnf,
            "sudo dnf upgrade mealy",
        ),
        (
            "/usr/bin/pacman",
            &["--query", "mealy"],
            InstallationKind::ArchPackage,
            UpdateMode::Pacman,
            "sudo pacman -Syu mealy",
        ),
    ];
    for (program, arguments, kind, mode, handoff) in probes {
        let path = Path::new(program);
        let Ok(metadata) = fs::symlink_metadata(path) else {
            continue;
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        let status = Command::new(path)
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if status.is_ok_and(|value| value.success()) {
            return (kind, mode, Some(handoff.to_owned()));
        }
    }
    (
        InstallationKind::NativePackageUnknown,
        UpdateMode::NativePackageRepairRequired,
        None,
    )
}

fn native_maintenance_command(
    installation: &InstallationStatus,
    operation: MaintenanceOperation,
) -> Option<String> {
    let command = match (installation.installation_kind, operation) {
        (InstallationKind::DebianPackage, MaintenanceOperation::Repair) => {
            "sudo apt install --reinstall mealy"
        }
        (InstallationKind::DebianPackage, MaintenanceOperation::Uninstall) => {
            "sudo apt remove mealy"
        }
        (InstallationKind::RpmPackage, MaintenanceOperation::Repair) => "sudo dnf reinstall mealy",
        (InstallationKind::RpmPackage, MaintenanceOperation::Uninstall) => "sudo dnf remove mealy",
        (InstallationKind::ArchPackage, MaintenanceOperation::Repair) => "sudo pacman -S mealy",
        (InstallationKind::ArchPackage, MaintenanceOperation::Uninstall) => {
            "sudo pacman -Rns mealy"
        }
        _ => return None,
    };
    Some(command.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;
    use tempfile::TempDir;

    fn fixture() -> (TempDir, PathBuf) {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let prefix = temporary.path().to_owned();
        let metadata = prefix.join("share/mealy");
        fs::create_dir_all(prefix.join("bin")).expect("bin directory");
        fs::create_dir_all(metadata.join("docs")).expect("metadata directory");
        let files = [
            ("bin/mealyd", prefix.join("bin/mealyd"), b"daemon".as_slice()),
            (
                "bin/mealyctl",
                prefix.join("bin/mealyctl"),
                b"client".as_slice(),
            ),
            (
                "install.sh",
                metadata.join("manage-install.sh"),
                b"manager".as_slice(),
            ),
            (
                "install-release.sh",
                metadata.join("manage-release.sh"),
                b"bootstrap".as_slice(),
            ),
            (
                "fetch-browser-runtime.sh",
                metadata.join("fetch-browser-runtime.sh"),
                b"browser".as_slice(),
            ),
            (
                "BUILD-MANIFEST.json",
                metadata.join("BUILD-MANIFEST.json"),
                format!(
                    "{{\"schemaVersion\":\"mealy.release.v2\",\"version\":\"{}\",\"target\":\"linux-x86_64-gnu\",\"commit\":\"{}\",\"sourceDateEpoch\":1,\"stateSchemaVersion\":15,\"sbom\":\"SBOM.cdx.json\",\"licenses\":\"THIRD-PARTY-LICENSES.html\"}}\n",
                    env!("CARGO_PKG_VERSION"),
                    "a".repeat(40)
                )
                .into_bytes()
                .leak(),
            ),
            (
                "SBOM.cdx.json",
                metadata.join("SBOM.cdx.json"),
                b"{}".as_slice(),
            ),
            ("LICENSE", metadata.join("LICENSE"), b"license".as_slice()),
            (
                "THIRD-PARTY-LICENSES.html",
                metadata.join("THIRD-PARTY-LICENSES.html"),
                b"licenses".as_slice(),
            ),
            ("README.md", metadata.join("README.md"), b"readme".as_slice()),
        ];
        let mut checksum_lines = String::new();
        for (logical, path, bytes) in files {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o700);
            options
                .open(&path)
                .expect("fixture file")
                .write_all(bytes)
                .expect("fixture bytes");
            let _ = writeln!(
                checksum_lines,
                "{}  {logical}",
                lowercase_hex(&Sha256::digest(bytes))
            );
        }
        fs::copy(
            metadata.join("manage-install.sh"),
            prefix.join("share/mealy-manager.sh"),
        )
        .expect("stable manager");
        fs::write(metadata.join("PAYLOAD-SHA256SUMS"), checksum_lines).expect("checksum inventory");
        let executable = prefix.join("bin/mealyctl");
        (temporary, executable)
    }

    #[test]
    fn verified_archive_status_binds_every_payload_file() {
        let (_temporary, executable) = fixture();
        let status = inspect_executable(&executable);
        assert_eq!(status.installation_kind, InstallationKind::ManagedArchive);
        assert_eq!(status.integrity, IntegrityStatus::Verified);
        assert_eq!(status.update_mode, UpdateMode::AttestedArchive);
        assert!(status.issues.is_empty());
    }

    #[test]
    fn changed_archive_file_fails_integrity() {
        let (_temporary, executable) = fixture();
        fs::write(executable.parent().expect("bin").join("mealyd"), b"changed")
            .expect("change daemon");
        let status = inspect_executable(&executable);
        assert_eq!(status.integrity, IntegrityStatus::Failed);
        assert!(
            status
                .issues
                .iter()
                .any(|issue| issue.contains("bin/mealyd"))
        );
    }

    #[test]
    fn stable_manager_can_be_repaired_only_from_verified_metadata() {
        let (_temporary, executable) = fixture();
        let manager = executable
            .parent()
            .expect("bin")
            .parent()
            .expect("prefix")
            .join("share/mealy-manager.sh");
        fs::write(&manager, b"changed").expect("change manager");
        let status = inspect_executable(&executable);
        assert_eq!(status.integrity, IntegrityStatus::Failed);
        assert_eq!(status.issues, vec![STABLE_MANAGER_ISSUE]);
        repair_archive_manager(&status).expect("repair manager");
        let repaired = inspect_executable(&executable);
        assert_eq!(repaired.integrity, IntegrityStatus::Verified);
    }

    #[test]
    fn checksum_paths_reject_parent_traversal_and_duplicates() {
        let digest = "a".repeat(64);
        assert!(parse_checksum_manifest(format!("{digest}  ../escape\n").as_bytes()).is_err());
        assert!(
            parse_checksum_manifest(
                format!("{digest}  README.md\n{digest}  README.md\n").as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn development_binary_has_no_mutating_backend() {
        let status = inspect_executable(Path::new("/work/mealy/target/debug/mealyctl"));
        assert_eq!(status.installation_kind, InstallationKind::Development);
        assert_eq!(status.integrity, IntegrityStatus::NotApplicable);
        assert_eq!(status.update_mode, UpdateMode::Unsupported);
    }

    #[test]
    fn stable_versions_compare_numerically() {
        assert!(compare_stable_versions("0.9.9", "0.10.0").is_some_and(std::cmp::Ordering::is_lt));
        assert!(compare_stable_versions("1.2.3", "1.2.3").is_some_and(std::cmp::Ordering::is_eq));
        assert!(compare_stable_versions("1.2.3-alpha", "1.2.3").is_none());
    }

    #[test]
    fn update_plan_requires_newer_matching_target_and_reports_schema_changes() {
        let (_temporary, executable) = fixture();
        let installation = inspect_executable(&executable);
        let candidate = UpdateCandidate {
            schema_version: "mealy.update-check.v1".to_owned(),
            version: "0.2.0".to_owned(),
            target: "linux-x86_64-gnu".to_owned(),
            commit: "b".repeat(40),
            state_schema_version: 15,
            verified: true,
        };
        let plan =
            build_update_plan(installation.clone(), "v0.2.0", candidate.clone()).expect("plan");
        assert!(plan.update_available);
        assert!(plan.state_schema_compatible);
        assert!(plan.apply_supported);

        let mut schema_change = candidate.clone();
        schema_change.state_schema_version = 16;
        let plan =
            build_update_plan(installation.clone(), "latest", schema_change).expect("schema plan");
        assert!(plan.update_available);
        assert!(!plan.state_schema_compatible);

        let mut wrong_target = candidate;
        wrong_target.target = "linux-aarch64-gnu".to_owned();
        assert!(
            build_update_plan(installation, "v0.2.0", wrong_target).is_err(),
            "a target mismatch must fail closed"
        );
    }
}
