use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mealy_application::{AgentLoopLimits, LeaseConcurrencyLimits, sha256_digest};
use mealy_domain::{ChannelBindingId, CorrelationId, PrincipalId};
use mealy_protocol::{API_VERSION, LocalConnectionInfo};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, SystemTime},
};
use thiserror::Error;

/// Stable local identity and secret loaded before binding the HTTP listener.
pub struct LocalIdentity {
    /// Raw fixed-length bearer credential.
    pub token: [u8; 32],
    /// Owner principal.
    pub principal_id: PrincipalId,
    /// Local CLI/device binding.
    pub channel_binding_id: ChannelBindingId,
}

/// Durable pre-exit evidence used when the `SQLite` mutex cannot be acquired at forced shutdown.
pub struct ForcedShutdownMarker {
    /// Exact daemon lifetime being terminated.
    pub start_id: CorrelationId,
    /// Bounded operator-facing cause.
    pub reason: String,
    /// Forced termination wall-clock instant.
    pub completed_at: SystemTime,
}

/// Schema-versioned non-secret daemon configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DaemonConfig {
    format_version: u32,
    drain_deadline_ms: u64,
    #[serde(default = "default_maximum_pending_inputs_per_session")]
    maximum_pending_inputs_per_session: u64,
    #[serde(default)]
    agent_loop_limits: AgentLoopLimits,
    #[serde(default)]
    concurrency_limits: ConcurrencyLimitsConfig,
    artifact_gc_minimum_age_hours: u64,
    forensic_backup_on_open_failure: bool,
    #[serde(default)]
    retention_policy: RetentionPolicyConfig,
}

/// Schema-versioned retention selectors; canonical audit history remains non-destructive.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetentionPolicyConfig {
    data_class_minimum_age_hours: BTreeMap<String, u64>,
    sensitivity_minimum_age_hours: BTreeMap<String, u64>,
    protected_principal_ids: BTreeSet<String>,
    protected_task_ids: BTreeSet<String>,
    protected_channel_binding_ids: BTreeSet<String>,
    legal_hold_labels: BTreeSet<String>,
}

/// Runtime concurrency dimensions enforced by workers, leases, and bounded adapters.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConcurrencyLimitsConfig {
    daemon_agent_runs: u32,
    principal_agent_runs: u32,
    session_agent_runs: u32,
    provider_requests: u32,
    provider_requests_per_minute: u32,
    extension_invocations: u32,
    agent_role_runs: u32,
    resource_class_invocations: u32,
}

impl Default for ConcurrencyLimitsConfig {
    fn default() -> Self {
        Self {
            daemon_agent_runs: 1,
            principal_agent_runs: 1,
            session_agent_runs: 1,
            provider_requests: 1,
            provider_requests_per_minute: 600,
            extension_invocations: 1,
            agent_role_runs: 1,
            resource_class_invocations: 1,
        }
    }
}

impl Default for RetentionPolicyConfig {
    fn default() -> Self {
        Self {
            data_class_minimum_age_hours: BTreeMap::from([
                ("canonical_audit".to_owned(), 24 * 365 * 10),
                ("temporary_artifact".to_owned(), 24),
                ("unreferenced_artifact".to_owned(), 24),
            ]),
            sensitivity_minimum_age_hours: BTreeMap::from([
                ("internal".to_owned(), 24 * 30),
                ("private".to_owned(), 24 * 365),
                ("public".to_owned(), 24),
                ("restricted".to_owned(), 24 * 365 * 10),
            ]),
            protected_principal_ids: BTreeSet::new(),
            protected_task_ids: BTreeSet::new(),
            protected_channel_binding_ids: BTreeSet::new(),
            legal_hold_labels: BTreeSet::new(),
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            format_version: 1,
            drain_deadline_ms: 10_000,
            maximum_pending_inputs_per_session: default_maximum_pending_inputs_per_session(),
            agent_loop_limits: AgentLoopLimits::default(),
            concurrency_limits: ConcurrencyLimitsConfig::default(),
            artifact_gc_minimum_age_hours: 24,
            forensic_backup_on_open_failure: true,
            retention_policy: RetentionPolicyConfig::default(),
        }
    }
}

impl DaemonConfig {
    /// Returns the bounded graceful-drain deadline.
    #[must_use]
    pub const fn drain_deadline_ms(&self) -> u64 {
        self.drain_deadline_ms
    }

    /// Returns the durable per-session pending-input capacity.
    #[must_use]
    pub const fn maximum_pending_inputs_per_session(&self) -> u64 {
        self.maximum_pending_inputs_per_session
    }

    /// Returns the validated run budget copied into newly promoted work.
    #[must_use]
    pub const fn agent_loop_limits(&self) -> AgentLoopLimits {
        self.agent_loop_limits
    }

    /// Returns the durable principal/session/role claim ceilings.
    #[must_use]
    pub const fn lease_concurrency_limits(&self) -> LeaseConcurrencyLimits {
        LeaseConcurrencyLimits {
            maximum_per_principal: self.concurrency_limits.principal_agent_runs,
            maximum_per_session: self.concurrency_limits.session_agent_runs,
            maximum_per_agent_role: self.concurrency_limits.agent_role_runs,
        }
    }

    /// Returns the maximum concurrently executing agent runs in this daemon.
    #[must_use]
    pub const fn maximum_daemon_agent_runs(&self) -> u32 {
        self.concurrency_limits.daemon_agent_runs
    }

    /// Returns the maximum concurrent requests to the configured provider.
    #[must_use]
    pub const fn maximum_provider_requests(&self) -> u32 {
        self.concurrency_limits.provider_requests
    }

    /// Returns the configured provider request-rate ceiling per minute.
    #[must_use]
    pub const fn provider_requests_per_minute(&self) -> u32 {
        self.concurrency_limits.provider_requests_per_minute
    }

    /// Returns the maximum concurrent invocations for one extension.
    #[must_use]
    pub const fn maximum_extension_invocations(&self) -> u32 {
        self.concurrency_limits.extension_invocations
    }

    /// Returns the maximum concurrent invocations for one resource class.
    #[must_use]
    pub const fn maximum_resource_class_invocations(&self) -> u32 {
        self.concurrency_limits.resource_class_invocations
    }

    /// Returns the minimum physical-erasure age for unreferenced artifacts.
    #[must_use]
    pub const fn artifact_gc_minimum_age_hours(&self) -> u64 {
        self.artifact_gc_minimum_age_hours
    }

    /// Returns whether database-open failures preserve a forensic copy automatically.
    #[must_use]
    pub const fn forensic_backup_on_open_failure(&self) -> bool {
        self.forensic_backup_on_open_failure
    }

    /// Applies a validated command-line drain deadline override to effective configuration.
    ///
    /// # Errors
    ///
    /// Returns [`LocalConfigError::InvalidConfiguration`] outside 100 ms through five minutes.
    pub fn set_drain_deadline_override(
        &mut self,
        drain_deadline_ms: Option<u64>,
    ) -> Result<(), LocalConfigError> {
        if let Some(value) = drain_deadline_ms {
            self.drain_deadline_ms = value;
        }
        self.validate()
    }

    /// Computes the canonical effective non-secret configuration digest.
    ///
    /// # Errors
    ///
    /// Returns [`LocalConfigError`] when canonical JSON encoding fails.
    pub fn digest(&self) -> Result<String, LocalConfigError> {
        Ok(sha256_digest(&serde_json::to_vec(self)?))
    }

    fn validate(&self) -> Result<(), LocalConfigError> {
        if self.format_version != 1 {
            return Err(LocalConfigError::UnsupportedConfigurationVersion(
                self.format_version,
            ));
        }
        if !(100..=300_000).contains(&self.drain_deadline_ms)
            || !(1..=1_000_000).contains(&self.maximum_pending_inputs_per_session)
            || self.agent_loop_limits.validate().is_err()
            || !self.concurrency_limits.valid()
            || self.artifact_gc_minimum_age_hours == 0
            || self.artifact_gc_minimum_age_hours > 24 * 365 * 10
            || !self.retention_policy.valid()
        {
            return Err(LocalConfigError::InvalidConfiguration);
        }
        Ok(())
    }
}

impl ConcurrencyLimitsConfig {
    fn valid(self) -> bool {
        (1..=64).contains(&self.daemon_agent_runs)
            && (1..=10_000).contains(&self.principal_agent_runs)
            && (1..=10_000).contains(&self.session_agent_runs)
            && (1..=1_024).contains(&self.provider_requests)
            && (1..=1_000_000).contains(&self.provider_requests_per_minute)
            && (1..=1_024).contains(&self.extension_invocations)
            && (1..=10_000).contains(&self.agent_role_runs)
            && (1..=1_024).contains(&self.resource_class_invocations)
            && LeaseConcurrencyLimits::new(
                self.principal_agent_runs,
                self.session_agent_runs,
                self.agent_role_runs,
            )
            .is_ok()
    }
}

const fn default_maximum_pending_inputs_per_session() -> u64 {
    1_024
}

impl RetentionPolicyConfig {
    fn valid(&self) -> bool {
        self.data_class_minimum_age_hours.len() <= 64
            && self.sensitivity_minimum_age_hours.len() <= 64
            && self.protected_principal_ids.len() <= 10_000
            && self.protected_task_ids.len() <= 10_000
            && self.protected_channel_binding_ids.len() <= 10_000
            && self.legal_hold_labels.len() <= 1_000
            && self
                .data_class_minimum_age_hours
                .iter()
                .chain(&self.sensitivity_minimum_age_hours)
                .all(|(key, hours)| {
                    valid_retention_label(key, 64) && (1..=24 * 365 * 100).contains(hours)
                })
            && self
                .protected_principal_ids
                .iter()
                .chain(&self.protected_task_ids)
                .chain(&self.protected_channel_binding_ids)
                .all(|value| valid_retention_label(value, 128))
            && self
                .legal_hold_labels
                .iter()
                .all(|value| valid_retention_label(value, 256))
    }
}

fn valid_retention_label(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

/// Loads or creates validated non-secret configuration using an atomic private write.
///
/// # Errors
///
/// Returns [`LocalConfigError`] for I/O, schema, encoding, or bound failures.
pub fn load_or_create_daemon_config(home: &Path) -> Result<DaemonConfig, LocalConfigError> {
    ensure_private_directory(home)?;
    let path = home.join("config.json");
    if path.exists() {
        let config = serde_json::from_slice::<DaemonConfig>(&fs::read(path)?)?;
        config.validate()?;
        return Ok(config);
    }
    let config = DaemonConfig::default();
    let body = serde_json::to_vec_pretty(&config)?;
    atomic_write_private(home, &path, &home.join("config.json.tmp"), &body)?;
    Ok(config)
}

/// Archives one validated effective configuration by its canonical digest for rollback.
///
/// Existing history is verified rather than replaced. Because configuration activation occurs
/// only at process start in release one, the prior successful digest remains available when an
/// owner explicitly edits high-risk settings and restarts.
///
/// # Errors
///
/// Returns [`LocalConfigError`] for digest mismatch, unsafe history, encoding, or I/O failure.
pub fn archive_effective_daemon_config(
    home: &Path,
    config: &DaemonConfig,
    digest: &str,
) -> Result<PathBuf, LocalConfigError> {
    if config.digest()? != digest {
        return Err(LocalConfigError::InvalidConfiguration);
    }
    let history = home.join("config-history");
    ensure_private_directory(&history)?;
    let path = history.join(format!("{digest}.json"));
    if path.exists() {
        let archived: DaemonConfig = serde_json::from_slice(&fs::read(&path)?)?;
        archived.validate()?;
        if archived.digest()? != digest {
            return Err(LocalConfigError::InvalidConfiguration);
        }
        return Ok(path);
    }
    let body = serde_json::to_vec_pretty(config)?;
    atomic_write_private(
        &history,
        &path,
        &history.join(format!(".{digest}.tmp")),
        &body,
    )?;
    Ok(path)
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredIdentity {
    format_version: u32,
    bearer_token: String,
    principal_id: String,
    channel_binding_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredForcedShutdownMarker {
    format_version: u32,
    start_id: String,
    reason: String,
    completed_at_ms: i64,
}

/// Atomically persists forced-shutdown intent before the process exits.
///
/// # Errors
///
/// Returns [`LocalConfigError`] for invalid evidence, encoding, or durable publication failure.
pub fn write_forced_shutdown_marker(
    home: &Path,
    start_id: CorrelationId,
    reason: &str,
    completed_at: SystemTime,
) -> Result<(), LocalConfigError> {
    if reason.is_empty()
        || reason.len() > 4_096
        || reason.trim() != reason
        || reason.chars().any(char::is_control)
    {
        return Err(LocalConfigError::InvalidForcedShutdownMarker);
    }
    let completed_at_ms = completed_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .ok_or(LocalConfigError::InvalidForcedShutdownMarker)?;
    let stored = StoredForcedShutdownMarker {
        format_version: 1,
        start_id: start_id.to_string(),
        reason: reason.to_owned(),
        completed_at_ms,
    };
    let body = serde_json::to_vec_pretty(&stored)?;
    atomic_write_private(
        home,
        &home.join("forced-shutdown.json"),
        &home.join("forced-shutdown.json.tmp"),
        &body,
    )
}

/// Loads pending forced-shutdown evidence without removing it.
///
/// # Errors
///
/// Returns [`LocalConfigError`] for malformed or unsupported evidence.
pub fn load_forced_shutdown_marker(
    home: &Path,
) -> Result<Option<ForcedShutdownMarker>, LocalConfigError> {
    let path = home.join("forced-shutdown.json");
    if !path.exists() {
        return Ok(None);
    }
    let stored: StoredForcedShutdownMarker = serde_json::from_slice(&fs::read(path)?)?;
    let start_id = CorrelationId::from_str(&stored.start_id)
        .map_err(|_| LocalConfigError::InvalidForcedShutdownMarker)?;
    if stored.format_version != 1
        || stored.completed_at_ms < 0
        || stored.reason.is_empty()
        || stored.reason.len() > 4_096
        || stored.reason.trim() != stored.reason
        || stored.reason.chars().any(char::is_control)
    {
        return Err(LocalConfigError::InvalidForcedShutdownMarker);
    }
    let completed_at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_millis(
            u64::try_from(stored.completed_at_ms)
                .map_err(|_| LocalConfigError::InvalidForcedShutdownMarker)?,
        ))
        .ok_or(LocalConfigError::InvalidForcedShutdownMarker)?;
    Ok(Some(ForcedShutdownMarker {
        start_id,
        reason: stored.reason,
        completed_at,
    }))
}

/// Removes reconciled forced-shutdown evidence and syncs the home directory.
///
/// # Errors
///
/// Returns [`LocalConfigError`] when durable removal fails.
pub fn remove_forced_shutdown_marker(home: &Path) -> Result<(), LocalConfigError> {
    match fs::remove_file(home.join("forced-shutdown.json")) {
        Ok(()) => sync_directory(home),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LocalConfigError::Io(error)),
    }
}

/// Acquires the lifetime lock that grants one daemon exclusive ownership of a home directory.
///
/// The returned file must remain open for the full daemon lifetime.
///
/// # Errors
///
/// Returns [`LocalConfigError::AlreadyRunning`] if another daemon holds the lock, or an I/O
/// failure if the lock file cannot be created or locked.
pub fn acquire_instance_lock(home: &Path) -> Result<File, LocalConfigError> {
    ensure_private_directory(home)?;
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(home.join("mealyd.lock"))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(LocalConfigError::AlreadyRunning),
        Err(std::fs::TryLockError::Error(error)) => Err(LocalConfigError::Io(error)),
    }
}

/// Creates or loads the owner-only local identity descriptor.
///
/// # Errors
///
/// Returns [`LocalConfigError`] for filesystem, JSON, secret, or ID failures.
pub fn load_or_create_identity(home: &Path) -> Result<LocalIdentity, LocalConfigError> {
    ensure_private_directory(home)?;
    let identity_path = home.join("identity.json");
    if identity_path.exists() {
        let stored: StoredIdentity = serde_json::from_slice(&fs::read(identity_path)?)?;
        if stored.format_version != 1 {
            return Err(LocalConfigError::UnsupportedIdentityVersion(
                stored.format_version,
            ));
        }
        return decode_identity(
            &stored.bearer_token,
            &stored.principal_id,
            &stored.channel_binding_id,
        );
    }

    // Migrate the original Phase 1 descriptor, which combined durable identity and endpoint data.
    let connection_path = connection_path(home);
    if connection_path.exists() {
        let info: LocalConnectionInfo = serde_json::from_slice(&fs::read(connection_path)?)?;
        let identity = decode_identity(
            &info.bearer_token,
            &info.principal_id,
            &info.channel_binding_id,
        )?;
        write_identity(home, &identity)?;
        return Ok(identity);
    }
    if home.join("mealy.sqlite3").exists() {
        return Err(LocalConfigError::MissingIdentity);
    }
    let mut token = [0_u8; 32];
    getrandom::fill(&mut token).map_err(|_| LocalConfigError::RandomUnavailable)?;
    let identity = LocalIdentity {
        token,
        principal_id: PrincipalId::new(),
        channel_binding_id: ChannelBindingId::new(),
    };
    write_identity(home, &identity)?;
    Ok(identity)
}

/// Atomically writes the active address and credential with owner-only Unix permissions.
///
/// # Errors
///
/// Returns [`LocalConfigError`] when the descriptor cannot be encoded or committed.
pub fn write_connection_info(
    home: &Path,
    base_url: String,
    identity: &LocalIdentity,
) -> Result<PathBuf, LocalConfigError> {
    ensure_private_directory(home)?;
    let path = connection_path(home);
    let temporary = home.join("connection.json.tmp");
    let info = LocalConnectionInfo {
        api_version: API_VERSION.to_owned(),
        base_url,
        bearer_token: URL_SAFE_NO_PAD.encode(identity.token),
        principal_id: identity.principal_id.to_string(),
        channel_binding_id: identity.channel_binding_id.to_string(),
    };
    let body = serde_json::to_vec_pretty(&info)?;
    atomic_write_private(home, &path, &temporary, &body)?;
    Ok(path)
}

fn write_identity(home: &Path, identity: &LocalIdentity) -> Result<(), LocalConfigError> {
    let path = home.join("identity.json");
    let temporary = home.join("identity.json.tmp");
    let stored = StoredIdentity {
        format_version: 1,
        bearer_token: URL_SAFE_NO_PAD.encode(identity.token),
        principal_id: identity.principal_id.to_string(),
        channel_binding_id: identity.channel_binding_id.to_string(),
    };
    let body = serde_json::to_vec_pretty(&stored)?;
    atomic_write_private(home, &path, &temporary, &body)
}

fn atomic_write_private(
    home: &Path,
    path: &Path,
    temporary: &Path,
    body: &[u8],
) -> Result<(), LocalConfigError> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(temporary)?;
    file.write_all(body)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    sync_directory(home)?;
    Ok(())
}

fn decode_identity(
    bearer_token: &str,
    principal_id: &str,
    channel_binding_id: &str,
) -> Result<LocalIdentity, LocalConfigError> {
    let token = URL_SAFE_NO_PAD
        .decode(bearer_token)
        .map_err(|_| LocalConfigError::InvalidCredential)?;
    Ok(LocalIdentity {
        token: <[u8; 32]>::try_from(token).map_err(|_| LocalConfigError::InvalidCredential)?,
        principal_id: PrincipalId::from_str(principal_id)
            .map_err(|_| LocalConfigError::InvalidIdentity)?,
        channel_binding_id: ChannelBindingId::from_str(channel_binding_id)
            .map_err(|_| LocalConfigError::InvalidIdentity)?,
    })
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), LocalConfigError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), LocalConfigError> {
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), LocalConfigError> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn connection_path(home: &Path) -> PathBuf {
    home.join("connection.json")
}

/// Local connection configuration failure.
#[derive(Debug, Error)]
pub enum LocalConfigError {
    /// Another daemon already owns this state directory.
    #[error("another mealyd process is already using this home directory")]
    AlreadyRunning,
    /// Filesystem operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// JSON encoding/decoding failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Existing bearer credential is malformed.
    #[error("stored local bearer credential is invalid")]
    InvalidCredential,
    /// Existing identity ID is malformed.
    #[error("stored local identity is invalid")]
    InvalidIdentity,
    /// A durable database exists but its authentication identity is absent.
    #[error(
        "durable state exists but identity.json and the legacy connection descriptor are missing"
    )]
    MissingIdentity,
    /// Stored identity format is newer or otherwise unsupported.
    #[error("stored identity format version {0} is unsupported")]
    UnsupportedIdentityVersion(u32),
    /// Stored non-secret configuration format is unsupported.
    #[error("stored daemon configuration format version {0} is unsupported")]
    UnsupportedConfigurationVersion(u32),
    /// Configuration value lies outside its enforceable operational bound.
    #[error("daemon configuration contains an invalid operational bound")]
    InvalidConfiguration,
    /// OS cryptographic randomness was unavailable.
    #[error("operating-system randomness is unavailable")]
    RandomUnavailable,
    /// Forced-shutdown marker is malformed, unsupported, or outside durable bounds.
    #[error("stored forced-shutdown evidence is invalid")]
    InvalidForcedShutdownMarker,
}

#[cfg(test)]
mod tests {
    use super::{
        archive_effective_daemon_config, load_forced_shutdown_marker, load_or_create_daemon_config,
        remove_forced_shutdown_marker, write_forced_shutdown_marker,
    };
    use mealy_domain::CorrelationId;
    use std::time::SystemTime;

    #[test]
    fn effective_config_history_and_forced_marker_are_durable_and_exact() {
        let home = tempfile::tempdir().expect("home");
        let config = load_or_create_daemon_config(home.path()).expect("config");
        assert_eq!(config.maximum_pending_inputs_per_session(), 1_024);
        assert_eq!(config.maximum_daemon_agent_runs(), 1);
        assert_eq!(config.maximum_provider_requests(), 1);
        assert_eq!(config.provider_requests_per_minute(), 600);
        assert_eq!(config.maximum_extension_invocations(), 1);
        assert_eq!(config.maximum_resource_class_invocations(), 1);
        assert_eq!(config.agent_loop_limits().maximum_model_calls, 4);
        let digest = config.digest().expect("digest");
        let history =
            archive_effective_daemon_config(home.path(), &config, &digest).expect("archive config");
        assert!(history.is_file());
        assert_eq!(
            archive_effective_daemon_config(home.path(), &config, &digest)
                .expect("idempotent archive"),
            history
        );

        let start_id = CorrelationId::new();
        write_forced_shutdown_marker(
            home.path(),
            start_id,
            "bounded drain elapsed",
            SystemTime::now(),
        )
        .expect("write marker");
        let marker = load_forced_shutdown_marker(home.path())
            .expect("load marker")
            .expect("marker present");
        assert_eq!(marker.start_id, start_id);
        assert_eq!(marker.reason, "bounded drain elapsed");
        remove_forced_shutdown_marker(home.path()).expect("remove marker");
        assert!(
            load_forced_shutdown_marker(home.path())
                .expect("marker absence")
                .is_none()
        );
    }
}
