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
use uuid::Uuid;

const STATUS_SCHEMA_VERSION: &str = "mealy.install-status.v1";
const RELEASE_SCHEMA_VERSION: &str = "mealy.release.v2";
const MAXIMUM_MANIFEST_BYTES: u64 = 64 * 1024;
const MAXIMUM_CHECKSUM_BYTES: u64 = 1024 * 1024;
const MAXIMUM_PAYLOAD_FILES: usize = 96;
const MAXIMUM_PAYLOAD_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_UPDATE_CHECK_BYTES: usize = 64 * 1024;
const MAXIMUM_UPDATE_TRANSACTION_BYTES: u64 = 64 * 1024;
const RELEASE_REPOSITORY: &str = "Amekn/mealy";
const STABLE_MANAGER_ISSUE: &str =
    "stable release manager is absent, redirected, or does not match a verified slot";

/// Supported installation provenance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InstallationStatus {
    /// Stable output contract.
    pub(crate) schema_version: String,
    /// Detected install provenance.
    pub(crate) installation_kind: InstallationKind,
    /// Complete active-slot verification result.
    pub(crate) integrity: IntegrityStatus,
    /// Version declared by the active release, or the compiled version outside a release.
    pub(crate) current_version: String,
    /// Source commit declared by the active published release.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) current_commit: Option<String>,
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

/// Durable phase of one disconnect-resistant archive update.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum UpdateTransactionPhase {
    /// Exact request was durably recorded before helper scheduling.
    Scheduled,
    /// Immutable pre-update backup completed.
    Prepared,
    /// Admission is closing and the daemon is draining.
    Draining,
    /// Owner service is inactive and the home lock is available.
    Stopped,
    /// Exact candidate slot was activated.
    Activated,
    /// The updated owner service is starting.
    Starting,
    /// Updated service is undergoing health, doctor, version, and integrity qualification.
    Verifying,
    /// Target passed every qualification gate.
    Committed,
    /// The exact request failed before program mutation; the prior service remains qualified.
    Aborted,
    /// Target failed qualification and the prior verified slot is being restored.
    RollingBack,
    /// Prior release was restored and passed qualification.
    RolledBack,
    /// Automated recovery could not establish one safe qualified slot.
    RecoveryFailed,
}

impl UpdateTransactionPhase {
    /// Whether no more automatic phase transition is expected.
    pub(crate) const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Aborted | Self::RolledBack | Self::RecoveryFailed
        )
    }
}

/// Minimal immutable-backup evidence retained by an update transaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpdateBackupEvidence {
    /// Immutable backup label.
    pub(crate) name: String,
    /// Digest of exact canonical manifest bytes.
    pub(crate) manifest_digest: String,
    /// Captured durable-state schema.
    pub(crate) state_schema_version: u64,
}

/// Durable, non-secret evidence and recovery cursor for one archive update.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpdateTransaction {
    /// Stable transaction-document contract.
    pub(crate) schema_version: String,
    /// `UUIDv7` transaction identity.
    pub(crate) transaction_id: String,
    /// Monotonic recovery phase.
    pub(crate) phase: UpdateTransactionPhase,
    /// Exact canonical daemon home.
    pub(crate) home: PathBuf,
    /// Exact owner-local installation prefix.
    pub(crate) prefix: PathBuf,
    /// Exact canonical systemd user-service fragment.
    pub(crate) service_fragment: PathBuf,
    /// Private immutable copy of the already-qualified client that owns recovery.
    pub(crate) helper_executable: PathBuf,
    /// SHA-256 of the private recovery helper.
    pub(crate) helper_sha256: String,
    /// Exact qualified version before update.
    pub(crate) previous_version: String,
    /// Exact source commit before update.
    pub(crate) previous_commit: String,
    /// Exact attested target identity.
    pub(crate) candidate: UpdateCandidate,
    /// Pre-update backup evidence once available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) backup: Option<UpdateBackupEvidence>,
    /// Bounded safe failure classification, never provider or process output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) failure: Option<String>,
    /// Whether automatic rollback was required.
    pub(crate) rollback_attempted: bool,
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
    /// Owner-local uninstall also removes a discoverable exact generated owner service.
    pub(crate) removes_verified_owner_service: bool,
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
    #[error("update transaction evidence is invalid or inconsistent")]
    InvalidUpdateTransaction,
    #[error("update transaction evidence could not be persisted: {0}")]
    UpdateTransactionIo(#[source] io::Error),
    #[error("installed release status could not be executed or validated")]
    InvalidInstalledStatus,
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

/// Inspect the active managed prefix using this already-qualified process.
///
/// Recovery must not execute the candidate client: the candidate may be precisely the component
/// that failed after activation. This path verifies the manifest and every payload digest
/// directly while the ordinary current-installation path additionally binds the manifest version
/// to the running client's compiled version.
pub(crate) fn inspect_managed_prefix(prefix: &Path) -> Result<InstallationStatus, LifecycleError> {
    let prefix = canonical_real_directory(prefix)?;
    let executable = prefix.join("bin/mealyctl");
    let metadata =
        fs::symlink_metadata(&executable).map_err(LifecycleError::UpdateTransactionIo)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(LifecycleError::InvalidInstalledStatus);
    }
    if executable
        .canonicalize()
        .map_err(LifecycleError::UpdateTransactionIo)?
        != executable
    {
        return Err(LifecycleError::InvalidInstalledStatus);
    }
    let status = inspect_archive_executable(&executable, &prefix, None);
    if status.schema_version != STATUS_SCHEMA_VERSION
        || status.installation_kind != InstallationKind::ManagedArchive
        || status.integrity != IntegrityStatus::Verified
        || status.managed_prefix.as_deref() != Some(prefix.as_path())
        || status.release_root.as_deref() != Some(prefix.join("share/mealy").as_path())
        || status.executable != executable
        || !valid_release_version(&status.current_version)
        || !status
            .current_commit
            .as_deref()
            .is_some_and(valid_sha256_commit)
        || status.state_schema_version.is_none()
        || !status
            .target
            .as_deref()
            .is_some_and(|target| matches!(target, "linux-x86_64-gnu" | "linux-aarch64-gnu"))
    {
        return Err(LifecycleError::InvalidInstalledStatus);
    }
    Ok(status)
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
        removes_verified_owner_service: operation == MaintenanceOperation::Uninstall && archive,
        native_command,
    })
}

/// Download and verify the requested target without mutating program files or private state.
pub(crate) fn plan_update(
    home: &Path,
    requested_version: &str,
) -> Result<UpdatePlan, LifecycleError> {
    plan_update_for_installation(home, requested_version, inspect_current_installation()?)
}

/// Recheck a target from a pinned managed prefix while running its private recovery helper.
pub(crate) fn plan_update_for_managed_prefix(
    home: &Path,
    requested_version: &str,
    prefix: &Path,
) -> Result<UpdatePlan, LifecycleError> {
    plan_update_for_installation(home, requested_version, inspect_managed_prefix(prefix)?)
}

fn plan_update_for_installation(
    home: &Path,
    requested_version: &str,
    installation: InstallationStatus,
) -> Result<UpdatePlan, LifecycleError> {
    if !valid_requested_version(requested_version) {
        return Err(LifecycleError::InvalidUpdateVersion);
    }
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

/// Durably record one exact archive-update request before scheduling its independent helper.
pub(crate) fn prepare_update_transaction(
    home: &Path,
    plan: &UpdatePlan,
    service_fragment: &Path,
) -> Result<UpdateTransaction, LifecycleError> {
    if !plan.update_available
        || !plan.state_schema_compatible
        || !plan.apply_supported
        || plan.installation.integrity != IntegrityStatus::Verified
        || plan.installation.installation_kind != InstallationKind::ManagedArchive
    {
        return Err(LifecycleError::ArchiveUpdateRequired);
    }
    let home = canonical_real_directory(home)?;
    let prefix = plan
        .installation
        .managed_prefix
        .as_ref()
        .ok_or(LifecycleError::ArchiveUpdateRequired)?;
    let prefix = canonical_real_directory(prefix)?;
    let service_fragment = canonical_regular_file(service_fragment)?;
    let helper_source = canonical_regular_file(&plan.installation.executable)?;
    if helper_source != prefix.join("bin/mealyctl") {
        return Err(LifecycleError::InvalidUpdateTransaction);
    }
    let previous_commit = plan
        .installation
        .current_commit
        .clone()
        .ok_or(LifecycleError::InvalidUpdateTransaction)?;
    let transaction_id = Uuid::now_v7().to_string();
    let directory = update_transaction_directory(&home)?;
    let helper_executable = directory.join(format!("{transaction_id}.helper"));
    let helper_sha256 = copy_update_helper(&helper_source, &helper_executable)?;
    let record = UpdateTransaction {
        schema_version: "mealy.update-transaction.v1".to_owned(),
        transaction_id,
        phase: UpdateTransactionPhase::Scheduled,
        home,
        prefix,
        service_fragment,
        helper_executable,
        helper_sha256,
        previous_version: plan.installation.current_version.clone(),
        previous_commit,
        candidate: plan.candidate.clone(),
        backup: None,
        failure: None,
        rollback_attempted: false,
    };
    if let Err(error) = validate_update_transaction(&record) {
        let _ = fs::remove_file(&record.helper_executable);
        return Err(error);
    }
    let destination = directory.join(format!("{}.json", record.transaction_id));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = match options.open(&destination) {
        Ok(file) => file,
        Err(error) => {
            let _ = fs::remove_file(&record.helper_executable);
            return Err(LifecycleError::UpdateTransactionIo(error));
        }
    };
    let bytes =
        serde_json::to_vec_pretty(&record).map_err(|_| LifecycleError::InvalidUpdateTransaction)?;
    if let Err(error) = file
        .write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
    {
        let _ = fs::remove_file(&destination);
        let _ = fs::remove_file(&record.helper_executable);
        return Err(LifecycleError::UpdateTransactionIo(error));
    }
    if let Err(error) = File::open(&directory).and_then(|directory| directory.sync_all()) {
        let _ = fs::remove_file(&destination);
        let _ = fs::remove_file(&record.helper_executable);
        return Err(LifecycleError::UpdateTransactionIo(error));
    }
    Ok(record)
}

/// Prove that an invocation is the exact old-client recovery copy pinned by this transaction.
pub(crate) fn verify_update_helper_identity(
    record: &UpdateTransaction,
    executable: &Path,
) -> Result<(), LifecycleError> {
    validate_update_transaction(record)?;
    let executable = canonical_regular_file(executable)?;
    let mode = fs::metadata(&executable)
        .map_err(LifecycleError::UpdateTransactionIo)?
        .permissions()
        .mode()
        & 0o777;
    if executable != record.helper_executable
        || mode != 0o500
        || digest_regular_file(&executable).map_err(LifecycleError::UpdateTransactionIo)?
            != record.helper_sha256
    {
        return Err(LifecycleError::InvalidUpdateTransaction);
    }
    Ok(())
}

/// Remove a terminal transaction's verified helper copy while retaining its durable digest record.
pub(crate) fn retire_update_helper(record: &UpdateTransaction) -> Result<(), LifecycleError> {
    if !matches!(
        record.phase,
        UpdateTransactionPhase::Committed
            | UpdateTransactionPhase::Aborted
            | UpdateTransactionPhase::RolledBack
    ) {
        return Err(LifecycleError::InvalidUpdateTransaction);
    }
    verify_update_helper_identity(record, &record.helper_executable)?;
    fs::remove_file(&record.helper_executable).map_err(LifecycleError::UpdateTransactionIo)?;
    File::open(update_transaction_directory(&record.home)?)
        .and_then(|directory| directory.sync_all())
        .map_err(LifecycleError::UpdateTransactionIo)
}

fn copy_update_helper(source: &Path, destination: &Path) -> Result<String, LifecycleError> {
    let mut input = open_no_follow(source).map_err(LifecycleError::UpdateTransactionIo)?;
    let metadata = input
        .metadata()
        .map_err(LifecycleError::UpdateTransactionIo)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAXIMUM_PAYLOAD_FILE_BYTES {
        return Err(LifecycleError::InvalidUpdateTransaction);
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o500);
    let mut output = options
        .open(destination)
        .map_err(LifecycleError::UpdateTransactionIo)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut total = 0_u64;
    let result = (|| -> io::Result<String> {
        loop {
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "update helper is too large")
                })?;
            if total > MAXIMUM_PAYLOAD_FILE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "update helper is too large",
                ));
            }
            hasher.update(&buffer[..count]);
            output.write_all(&buffer[..count])?;
        }
        if total != metadata.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "update helper changed while being copied",
            ));
        }
        output.set_permissions(fs::Permissions::from_mode(0o500))?;
        output.sync_all()?;
        Ok(lowercase_hex(&hasher.finalize()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result.map_err(LifecycleError::UpdateTransactionIo)
}

/// Load and fully validate one transaction by its canonical `UUIDv7` identity.
pub(crate) fn load_update_transaction(
    home: &Path,
    transaction_id: &str,
) -> Result<UpdateTransaction, LifecycleError> {
    validate_transaction_id(transaction_id)?;
    let home = canonical_real_directory(home)?;
    let path = home
        .join("update-transactions")
        .join(format!("{transaction_id}.json"));
    let bytes = read_bounded_regular_file(&path, MAXIMUM_UPDATE_TRANSACTION_BYTES)
        .map_err(LifecycleError::UpdateTransactionIo)?;
    let record: UpdateTransaction =
        serde_json::from_slice(&bytes).map_err(|_| LifecycleError::InvalidUpdateTransaction)?;
    validate_update_transaction(&record)?;
    if record.transaction_id != transaction_id || record.home != home {
        return Err(LifecycleError::InvalidUpdateTransaction);
    }
    Ok(record)
}

/// Atomically advance one transaction after validating immutable identity and phase ordering.
pub(crate) fn persist_update_transaction(record: &UpdateTransaction) -> Result<(), LifecycleError> {
    validate_update_transaction(record)?;
    let current = load_update_transaction(&record.home, &record.transaction_id)?;
    if !same_update_transaction_identity(&current, record)
        || !valid_update_phase_transition(current.phase, record.phase)
    {
        return Err(LifecycleError::InvalidUpdateTransaction);
    }
    let directory = update_transaction_directory(&record.home)?;
    let destination = directory.join(format!("{}.json", record.transaction_id));
    let temporary = directory.join(format!(
        ".{}.{}.new",
        record.transaction_id,
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(&temporary)
        .map_err(LifecycleError::UpdateTransactionIo)?;
    let bytes =
        serde_json::to_vec_pretty(record).map_err(|_| LifecycleError::InvalidUpdateTransaction)?;
    let result = file
        .write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temporary, &destination))
        .and_then(|()| File::open(&directory)?.sync_all());
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(LifecycleError::UpdateTransactionIo)
}

/// Exact active slot relevant to one update transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ActiveTransactionSlot {
    /// The qualified release from before the transaction.
    Previous,
    /// The checked target release.
    Candidate,
}

/// Classify which exact transaction slot is currently active.
pub(crate) fn active_transaction_slot(
    record: &UpdateTransaction,
) -> Result<ActiveTransactionSlot, LifecycleError> {
    validate_update_transaction(record)?;
    let status = inspect_managed_prefix(&record.prefix)?;
    let identity = (
        status.current_version.as_str(),
        status.current_commit.as_deref(),
        status.state_schema_version,
        status.target.as_deref(),
    );
    if identity
        == (
            record.previous_version.as_str(),
            Some(record.previous_commit.as_str()),
            Some(record.candidate.state_schema_version),
            Some(record.candidate.target.as_str()),
        )
    {
        return Ok(ActiveTransactionSlot::Previous);
    }
    if identity
        == (
            record.candidate.version.as_str(),
            Some(record.candidate.commit.as_str()),
            Some(record.candidate.state_schema_version),
            Some(record.candidate.target.as_str()),
        )
    {
        return Ok(ActiveTransactionSlot::Candidate);
    }
    Err(LifecycleError::InvalidInstalledStatus)
}

/// Restore the exact prior same-schema slot, or prove that it is already active.
pub(crate) fn rollback_update_transaction(
    record: &UpdateTransaction,
) -> Result<(), LifecycleError> {
    match active_transaction_slot(record)? {
        ActiveTransactionSlot::Previous => return Ok(()),
        ActiveTransactionSlot::Candidate => {}
    }
    let installation = inspect_managed_prefix(&record.prefix)?;
    if !installation.rollback_available {
        return Err(LifecycleError::ManagerActionUnavailable("rollback"));
    }
    run_archive_manager_inner(
        &installation,
        &record.home,
        ArchiveManagerAction::Rollback,
        true,
    )?;
    if active_transaction_slot(record)? != ActiveTransactionSlot::Previous {
        return Err(LifecycleError::InvalidInstalledStatus);
    }
    Ok(())
}

fn validate_update_transaction(record: &UpdateTransaction) -> Result<(), LifecycleError> {
    validate_transaction_id(&record.transaction_id)?;
    if record.schema_version != "mealy.update-transaction.v1"
        || !valid_absolute_path(&record.home)
        || !valid_absolute_path(&record.prefix)
        || !valid_absolute_path(&record.service_fragment)
        || record.helper_executable
            != record
                .home
                .join("update-transactions")
                .join(format!("{}.helper", record.transaction_id))
        || !valid_sha256(&record.helper_sha256)
        || !valid_release_version(&record.previous_version)
        || !valid_sha256_commit(&record.previous_commit)
        || record.candidate.schema_version != "mealy.update-check.v1"
        || !record.candidate.verified
        || !valid_release_version(&record.candidate.version)
        || !valid_sha256_commit(&record.candidate.commit)
        || !matches!(
            record.candidate.target.as_str(),
            "linux-x86_64-gnu" | "linux-aarch64-gnu"
        )
        || !(1..=9999).contains(&record.candidate.state_schema_version)
        || record.previous_commit == record.candidate.commit
        || record.failure.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > 512 || value.chars().any(char::is_control)
        })
        || record.backup.as_ref().is_some_and(|backup| {
            !valid_portable_name(&backup.name)
                || !valid_sha256(&backup.manifest_digest)
                || !(1..=9999).contains(&backup.state_schema_version)
        })
    {
        return Err(LifecycleError::InvalidUpdateTransaction);
    }
    if !matches!(
        record.phase,
        UpdateTransactionPhase::Scheduled
            | UpdateTransactionPhase::Aborted
            | UpdateTransactionPhase::RecoveryFailed
    ) && record.backup.is_none()
    {
        return Err(LifecycleError::InvalidUpdateTransaction);
    }
    if matches!(
        record.phase,
        UpdateTransactionPhase::RollingBack | UpdateTransactionPhase::RolledBack
    ) != record.rollback_attempted
        || (record.rollback_attempted
            && !matches!(
                record.phase,
                UpdateTransactionPhase::RollingBack
                    | UpdateTransactionPhase::RolledBack
                    | UpdateTransactionPhase::RecoveryFailed
            ))
    {
        return Err(LifecycleError::InvalidUpdateTransaction);
    }
    Ok(())
}

fn same_update_transaction_identity(left: &UpdateTransaction, right: &UpdateTransaction) -> bool {
    left.schema_version == right.schema_version
        && left.transaction_id == right.transaction_id
        && left.home == right.home
        && left.prefix == right.prefix
        && left.service_fragment == right.service_fragment
        && left.helper_executable == right.helper_executable
        && left.helper_sha256 == right.helper_sha256
        && left.previous_version == right.previous_version
        && left.previous_commit == right.previous_commit
        && left.candidate == right.candidate
}

fn valid_update_phase_transition(from: UpdateTransactionPhase, to: UpdateTransactionPhase) -> bool {
    if from == to {
        return true;
    }
    matches!(
        (from, to),
        (
            UpdateTransactionPhase::Scheduled,
            UpdateTransactionPhase::Prepared
                | UpdateTransactionPhase::Aborted
                | UpdateTransactionPhase::RecoveryFailed
        ) | (
            UpdateTransactionPhase::Prepared,
            UpdateTransactionPhase::Draining
                | UpdateTransactionPhase::RollingBack
                | UpdateTransactionPhase::RecoveryFailed
        ) | (
            UpdateTransactionPhase::Draining,
            UpdateTransactionPhase::Stopped
                | UpdateTransactionPhase::RollingBack
                | UpdateTransactionPhase::RecoveryFailed
        ) | (
            UpdateTransactionPhase::Stopped,
            UpdateTransactionPhase::Activated
                | UpdateTransactionPhase::RollingBack
                | UpdateTransactionPhase::RecoveryFailed
        ) | (
            UpdateTransactionPhase::Activated,
            UpdateTransactionPhase::Starting
                | UpdateTransactionPhase::RollingBack
                | UpdateTransactionPhase::RecoveryFailed
        ) | (
            UpdateTransactionPhase::Starting,
            UpdateTransactionPhase::Verifying
                | UpdateTransactionPhase::RollingBack
                | UpdateTransactionPhase::RecoveryFailed
        ) | (
            UpdateTransactionPhase::Verifying,
            UpdateTransactionPhase::Committed
                | UpdateTransactionPhase::RollingBack
                | UpdateTransactionPhase::RecoveryFailed
        ) | (
            UpdateTransactionPhase::RollingBack,
            UpdateTransactionPhase::RolledBack | UpdateTransactionPhase::RecoveryFailed
        )
    )
}

fn validate_transaction_id(value: &str) -> Result<(), LifecycleError> {
    let parsed = Uuid::parse_str(value).map_err(|_| LifecycleError::InvalidUpdateTransaction)?;
    if parsed.get_version_num() != 7 || parsed.hyphenated().to_string() != value {
        return Err(LifecycleError::InvalidUpdateTransaction);
    }
    Ok(())
}

fn valid_portable_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn canonical_real_directory(path: &Path) -> Result<PathBuf, LifecycleError> {
    let metadata = fs::symlink_metadata(path).map_err(LifecycleError::UpdateTransactionIo)?;
    let canonical = fs::canonicalize(path).map_err(LifecycleError::UpdateTransactionIo)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || !valid_absolute_path(&canonical) {
        return Err(LifecycleError::InvalidUpdateTransaction);
    }
    Ok(canonical)
}

fn canonical_regular_file(path: &Path) -> Result<PathBuf, LifecycleError> {
    let metadata = fs::symlink_metadata(path).map_err(LifecycleError::UpdateTransactionIo)?;
    let canonical = fs::canonicalize(path).map_err(LifecycleError::UpdateTransactionIo)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || !valid_absolute_path(&canonical)
    {
        return Err(LifecycleError::InvalidUpdateTransaction);
    }
    Ok(canonical)
}

fn update_transaction_directory(home: &Path) -> Result<PathBuf, LifecycleError> {
    let directory = home.join("update-transactions");
    match fs::create_dir(&directory) {
        Ok(()) => {
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(LifecycleError::UpdateTransactionIo)?;
            File::open(home)
                .and_then(|home| home.sync_all())
                .map_err(LifecycleError::UpdateTransactionIo)?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(LifecycleError::UpdateTransactionIo(error)),
    }
    let metadata = fs::symlink_metadata(&directory).map_err(LifecycleError::UpdateTransactionIo)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LifecycleError::InvalidUpdateTransaction);
    }
    Ok(directory)
}

fn inspect_executable(executable: &Path) -> InstallationStatus {
    let compiled_version = env!("CARGO_PKG_VERSION").to_owned();
    if let Some(prefix) = archive_prefix(executable) {
        let release_root = prefix.join("share/mealy");
        if release_root.exists() || prefix.join("share/mealy-manager.sh").exists() {
            return inspect_archive_executable(executable, prefix, Some(compiled_version.as_str()));
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
            Some(compiled_version.as_str()),
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
        schema_version: STATUS_SCHEMA_VERSION.to_owned(),
        installation_kind: kind,
        integrity: IntegrityStatus::NotApplicable,
        current_version: compiled_version,
        current_commit: None,
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

fn inspect_archive_executable(
    executable: &Path,
    prefix: &Path,
    running_version: Option<&str>,
) -> InstallationStatus {
    let release_root = prefix.join("share/mealy");
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
        || (stable_digest != active_manager_digest && stable_digest != previous_manager_digest)
    {
        active.issues.push(STABLE_MANAGER_ISSUE.to_owned());
    }
    published_status(
        executable,
        InstallationKind::ManagedArchive,
        UpdateMode::AttestedArchive,
        Some(prefix.to_owned()),
        release_root,
        active,
        rollback_available,
        None,
        running_version,
    )
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
    run_archive_manager_inner(installation, home, action, false)
}

fn run_archive_manager_inner(
    installation: &InstallationStatus,
    home: &Path,
    action: ArchiveManagerAction,
    machine_readable_parent: bool,
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
        .stderr(Stdio::inherit());
    if machine_readable_parent {
        command.stdout(Stdio::null());
    } else {
        command.stdout(Stdio::inherit());
    }
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
    running_version: Option<&str>,
) -> InstallationStatus {
    if slot
        .manifest
        .as_ref()
        .is_some_and(|manifest| running_version.is_some_and(|version| manifest.version != version))
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
    let current_commit = slot.manifest.as_ref().map(|value| value.commit.clone());
    let target = slot.manifest.as_ref().map(|value| value.target.clone());
    InstallationStatus {
        schema_version: STATUS_SCHEMA_VERSION.to_owned(),
        installation_kind: kind,
        integrity,
        current_version,
        current_commit,
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

pub(crate) fn read_bounded_regular_file(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
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

    fn newer_fixture_version() -> String {
        let [major, minor, patch] =
            stable_version_numbers(env!("CARGO_PKG_VERSION")).expect("stable package version");
        let patch = patch.checked_add(1).expect("fixture patch version");
        format!("{major}.{minor}.{patch}")
    }

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
    fn old_helper_inspects_new_slot_without_executing_candidate_client() {
        let (_temporary, executable) = fixture();
        let newer_version = newer_fixture_version();
        let prefix = executable
            .parent()
            .and_then(Path::parent)
            .expect("managed prefix");
        let metadata = prefix.join("share/mealy");
        let manifest_path = metadata.join("BUILD-MANIFEST.json");
        let manifest = format!(
            "{{\"schemaVersion\":\"mealy.release.v2\",\"version\":\"{newer_version}\",\"target\":\"linux-x86_64-gnu\",\"commit\":\"{}\",\"sourceDateEpoch\":1,\"stateSchemaVersion\":15,\"sbom\":\"SBOM.cdx.json\",\"licenses\":\"THIRD-PARTY-LICENSES.html\"}}\n",
            "b".repeat(40)
        );
        fs::write(&manifest_path, manifest.as_bytes()).expect("newer manifest");
        let checksum_path = metadata.join("PAYLOAD-SHA256SUMS");
        let checksums = fs::read_to_string(&checksum_path).expect("checksum inventory");
        let replacement = format!(
            "{}  BUILD-MANIFEST.json",
            lowercase_hex(&Sha256::digest(manifest.as_bytes()))
        );
        let checksums = checksums
            .lines()
            .map(|line| {
                if line.ends_with("  BUILD-MANIFEST.json") {
                    replacement.as_str()
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(checksum_path, checksums).expect("updated checksum inventory");

        let running_identity = inspect_executable(&executable);
        assert_eq!(running_identity.integrity, IntegrityStatus::Failed);
        assert!(running_identity.issues.iter().any(|issue| {
            issue.contains("active release manifest version does not match the running mealyctl")
        }));

        let recovered = inspect_managed_prefix(prefix).expect("old-helper prefix inspection");
        assert_eq!(recovered.integrity, IntegrityStatus::Verified);
        assert_eq!(recovered.current_version, newer_version);
        let expected_commit = "b".repeat(40);
        assert_eq!(
            recovered.current_commit.as_deref(),
            Some(expected_commit.as_str())
        );
        assert!(
            recovered.issues.is_empty(),
            "candidate bytes are verified directly without invoking the non-executable fixture"
        );
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
        let newer_version = newer_fixture_version();
        let requested_version = format!("v{newer_version}");
        let candidate = UpdateCandidate {
            schema_version: "mealy.update-check.v1".to_owned(),
            version: newer_version,
            target: "linux-x86_64-gnu".to_owned(),
            commit: "b".repeat(40),
            state_schema_version: 15,
            verified: true,
        };
        let plan = build_update_plan(installation.clone(), &requested_version, candidate.clone())
            .expect("plan");
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
            build_update_plan(installation, &requested_version, wrong_target).is_err(),
            "a target mismatch must fail closed"
        );
    }

    #[test]
    fn update_transaction_is_private_restartable_and_phase_fenced() {
        let (_temporary, executable) = fixture();
        let prefix = executable.parent().expect("bin").parent().expect("prefix");
        let home = prefix.join("home");
        fs::create_dir(&home).expect("home");
        let service = prefix.join("mealy.service");
        fs::write(&service, b"[Service]\n").expect("service");
        let installation = inspect_executable(&executable);
        let newer_version = newer_fixture_version();
        let requested_version = format!("v{newer_version}");
        let candidate = UpdateCandidate {
            schema_version: "mealy.update-check.v1".to_owned(),
            version: newer_version,
            target: "linux-x86_64-gnu".to_owned(),
            commit: "b".repeat(40),
            state_schema_version: 15,
            verified: true,
        };
        let plan =
            build_update_plan(installation, &requested_version, candidate).expect("update plan");
        let mut transaction =
            prepare_update_transaction(&home, &plan, &service).expect("transaction");
        assert_eq!(transaction.phase, UpdateTransactionPhase::Scheduled);
        assert_eq!(
            fs::metadata(&transaction.helper_executable)
                .expect("helper metadata")
                .permissions()
                .mode()
                & 0o777,
            0o500
        );
        verify_update_helper_identity(&transaction, &transaction.helper_executable)
            .expect("pinned private helper");
        assert!(
            verify_update_helper_identity(&transaction, &service).is_err(),
            "a different executable cannot own transaction recovery"
        );
        let path = home
            .join("update-transactions")
            .join(format!("{}.json", transaction.transaction_id));
        assert_eq!(
            fs::metadata(&path)
                .expect("transaction metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            load_update_transaction(&home, &transaction.transaction_id)
                .expect("loaded transaction"),
            transaction
        );

        transaction.backup = Some(UpdateBackupEvidence {
            name: format!("pre-update-{}", transaction.transaction_id),
            manifest_digest: "c".repeat(64),
            state_schema_version: 15,
        });
        transaction.phase = UpdateTransactionPhase::Prepared;
        persist_update_transaction(&transaction).expect("prepared phase");

        let mut skipped = transaction.clone();
        skipped.phase = UpdateTransactionPhase::Activated;
        assert!(
            persist_update_transaction(&skipped).is_err(),
            "a durable update phase cannot be skipped"
        );

        let mut changed = transaction.clone();
        changed.candidate.commit = "d".repeat(40);
        changed.phase = UpdateTransactionPhase::Draining;
        assert!(
            persist_update_transaction(&changed).is_err(),
            "immutable candidate identity cannot change"
        );

        transaction.phase = UpdateTransactionPhase::Draining;
        persist_update_transaction(&transaction).expect("draining phase");
        assert_eq!(
            load_update_transaction(&home, &transaction.transaction_id)
                .expect("advanced transaction")
                .phase,
            UpdateTransactionPhase::Draining
        );
        assert!(
            retire_update_helper(&transaction).is_err(),
            "a nonterminal transaction must retain its recovery executable"
        );
        let mut aborted =
            prepare_update_transaction(&home, &plan, &service).expect("aborted transaction");
        aborted.failure = Some("candidate-reverification-failed".to_owned());
        aborted.phase = UpdateTransactionPhase::Aborted;
        persist_update_transaction(&aborted).expect("aborted phase");
        retire_update_helper(&aborted).expect("retire terminal helper");
        assert!(!aborted.helper_executable.exists());

        fs::set_permissions(
            &transaction.helper_executable,
            fs::Permissions::from_mode(0o700),
        )
        .expect("make helper owner-writable");
        fs::write(&transaction.helper_executable, b"tampered helper").expect("tamper helper");
        assert!(
            verify_update_helper_identity(&transaction, &transaction.helper_executable).is_err(),
            "a changed helper cannot resume transaction recovery"
        );
    }

    #[test]
    fn update_transaction_failure_transitions_cover_every_mutation_boundary() {
        assert!(UpdateTransactionPhase::Aborted.is_terminal());
        assert!(valid_update_phase_transition(
            UpdateTransactionPhase::Scheduled,
            UpdateTransactionPhase::Aborted
        ));
        for phase in [
            UpdateTransactionPhase::Prepared,
            UpdateTransactionPhase::Draining,
            UpdateTransactionPhase::Stopped,
            UpdateTransactionPhase::Activated,
            UpdateTransactionPhase::Starting,
            UpdateTransactionPhase::Verifying,
        ] {
            assert!(
                valid_update_phase_transition(phase, UpdateTransactionPhase::RollingBack),
                "{phase:?} must have a durable rollback edge"
            );
        }
        for phase in [
            UpdateTransactionPhase::Committed,
            UpdateTransactionPhase::Aborted,
            UpdateTransactionPhase::RolledBack,
            UpdateTransactionPhase::RecoveryFailed,
        ] {
            assert!(
                !valid_update_phase_transition(phase, UpdateTransactionPhase::RollingBack),
                "terminal phase {phase:?} must not re-enter rollback"
            );
        }
    }
}
