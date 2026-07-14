use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
pub use mealy_application::ProviderConfig;
use mealy_application::{
    AgentLoopLimits, BrowserConfig, LeaseConcurrencyLimits, McpServerConfig, WebAccessConfig,
    is_sha256_digest, sha256_digest, validate_mcp_server_set, validate_provider_chain,
};
use mealy_domain::{ChannelBindingId, CorrelationId, PrincipalId};
use mealy_infrastructure::{inspect_browser_bundle, is_trusted_system_executable};
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
    #[serde(default)]
    provider: ProviderConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    provider_fallbacks: Vec<ProviderConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    workspace_roots: Vec<WorkspaceRootConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    command_tools: Vec<CommandToolConfig>,
    #[serde(default, skip_serializing_if = "is_default_web_access")]
    web_access: WebAccessConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    skills: Vec<SkillConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    mcp_servers: Vec<McpServerConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    browser: Option<BrowserConfig>,
    artifact_gc_minimum_age_hours: u64,
    forensic_backup_on_open_failure: bool,
    #[serde(default)]
    retention_policy: RetentionPolicyConfig,
}

/// One explicitly granted owner workspace exposed only through logical relative paths.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceRootConfig {
    workspace_id: String,
    root: PathBuf,
    #[serde(default, skip_serializing_if = "is_false")]
    writable: bool,
}

/// One owner-approved direct executable exposed only by logical identity and pinned bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommandToolConfig {
    command_id: String,
    executable: PathBuf,
    executable_digest: String,
}

/// One installed data-only skill revision; enabled instructions never grant tool authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillConfig {
    skill_id: String,
    version: String,
    manifest_digest: String,
    package_path: PathBuf,
    enabled: bool,
}

impl SkillConfig {
    /// Stable manifest identity.
    #[must_use]
    pub fn skill_id(&self) -> &str {
        &self.skill_id
    }

    /// Exact immutable package version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Digest of the exact installed manifest bytes.
    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// Safe home-relative immutable package directory.
    #[must_use]
    pub fn package_path(&self) -> &Path {
        &self.package_path
    }

    /// Whether reviewed instructions enter newly compiled context epochs.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
}

impl CommandToolConfig {
    /// Stable model-visible command identity.
    #[must_use]
    pub fn command_id(&self) -> &str {
        &self.command_id
    }

    /// Canonical host executable path retained only by the trusted runtime.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Lowercase SHA-256 of the exact configured executable bytes.
    #[must_use]
    pub fn executable_digest(&self) -> &str {
        &self.executable_digest
    }
}

impl WorkspaceRootConfig {
    /// Stable logical identity used in model arguments and evidence.
    #[must_use]
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    /// Absolute owner-approved host directory, never exposed to the model.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether explicit action-mode tasks may propose create-new-file effects in this workspace.
    #[must_use]
    pub const fn writable(&self) -> bool {
        self.writable
    }
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
            provider: ProviderConfig::default(),
            provider_fallbacks: Vec::new(),
            workspace_roots: Vec::new(),
            command_tools: Vec::new(),
            web_access: WebAccessConfig::default(),
            skills: Vec::new(),
            mcp_servers: Vec::new(),
            browser: None,
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

    /// Returns the validated non-secret provider selection.
    #[must_use]
    pub const fn provider(&self) -> &ProviderConfig {
        &self.provider
    }

    /// Returns the ordered, trust-compatible provider fallback configurations.
    #[must_use]
    pub fn provider_fallbacks(&self) -> &[ProviderConfig] {
        &self.provider_fallbacks
    }

    /// Returns explicitly granted workspace roots in deterministic configuration order.
    #[must_use]
    pub fn workspace_roots(&self) -> &[WorkspaceRootConfig] {
        &self.workspace_roots
    }

    /// Returns digest-pinned direct executable grants in deterministic identity order.
    #[must_use]
    pub fn command_tools(&self) -> &[CommandToolConfig] {
        &self.command_tools
    }

    /// Returns the validated non-secret web authority configuration.
    #[must_use]
    pub const fn web_access(&self) -> &WebAccessConfig {
        &self.web_access
    }

    /// Returns installed skill revisions in stable identity order.
    #[must_use]
    pub fn skills(&self) -> &[SkillConfig] {
        &self.skills
    }

    /// Returns schema-pinned local stdio MCP servers in stable identity order.
    #[must_use]
    pub fn mcp_servers(&self) -> &[McpServerConfig] {
        &self.mcp_servers
    }

    /// Returns the optional content-pinned rendered-browser runtime.
    #[must_use]
    pub const fn browser(&self) -> Option<&BrowserConfig> {
        self.browser.as_ref()
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
            || validate_provider_chain(&self.provider, &self.provider_fallbacks).is_err()
            || !valid_workspace_roots(&self.workspace_roots)
            || !valid_command_tools(&self.command_tools)
            || !self.command_tools.is_empty()
                && !self
                    .workspace_roots
                    .iter()
                    .any(WorkspaceRootConfig::writable)
            || self.web_access.validate().is_err()
            || !valid_skills(&self.skills)
            || validate_mcp_server_set(&self.mcp_servers).is_err()
            || self
                .browser
                .as_ref()
                .is_some_and(|browser| browser.validate().is_err())
            || self.browser.as_ref().is_some_and(BrowserConfig::enabled) && !self.web_access.enabled
            || self.artifact_gc_minimum_age_hours == 0
            || self.artifact_gc_minimum_age_hours > 24 * 365 * 10
            || !self.retention_policy.valid()
        {
            return Err(LocalConfigError::InvalidConfiguration);
        }
        Ok(())
    }
}

fn is_default_web_access(value: &WebAccessConfig) -> bool {
    value == &WebAccessConfig::default()
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

fn valid_workspace_roots(workspaces: &[WorkspaceRootConfig]) -> bool {
    if workspaces.len() > 16 {
        return false;
    }
    let mut identities = BTreeSet::new();
    let mut roots = BTreeSet::new();
    workspaces.iter().all(|workspace| {
        let Some(root) = workspace.root.to_str() else {
            return false;
        };
        let identity_valid = !workspace.workspace_id.is_empty()
            && workspace.workspace_id.len() <= 128
            && !workspace.workspace_id.starts_with('.')
            && workspace
                .workspace_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        let root_valid = workspace.root.is_absolute()
            && root.len() <= 4_096
            && !root.chars().any(char::is_control)
            && workspace.root.components().all(|component| {
                matches!(
                    component,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            });
        identity_valid
            && root_valid
            && identities.insert(workspace.workspace_id.as_str())
            && roots.insert(root)
    })
}

fn valid_command_tools(commands: &[CommandToolConfig]) -> bool {
    if commands.len() > 16 {
        return false;
    }
    let mut identities = BTreeSet::new();
    let mut executables = BTreeSet::new();
    let mut digests = BTreeSet::new();
    commands.iter().all(|command| {
        let Some(executable) = command.executable.to_str() else {
            return false;
        };
        !command.command_id.is_empty()
            && command.command_id.len() <= 128
            && !command.command_id.starts_with('.')
            && command
                .command_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            && command.executable.is_absolute()
            && executable.len() <= 4_096
            && !executable.chars().any(char::is_control)
            && command.executable.components().all(|component| {
                matches!(
                    component,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
            && is_sha256_digest(&command.executable_digest)
            && identities.insert(command.command_id.as_str())
            && executables.insert(executable)
            && digests.insert(command.executable_digest.as_str())
    })
}

fn valid_skills(skills: &[SkillConfig]) -> bool {
    if skills.len() > 32
        || !skills
            .windows(2)
            .all(|window| window[0].skill_id < window[1].skill_id)
    {
        return false;
    }
    let mut identities = BTreeSet::new();
    let mut package_paths = BTreeSet::new();
    skills.iter().all(|skill| {
        let expected_path = format!("skills/{}", skill.manifest_digest);
        valid_skill_identifier(&skill.skill_id, 128)
            && valid_skill_identifier(&skill.version, 128)
            && is_sha256_digest(&skill.manifest_digest)
            && skill.package_path == Path::new(&expected_path)
            && skill
                .package_path
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
            && identities.insert(skill.skill_id.as_str())
            && package_paths.insert(skill.package_path.as_path())
    })
}

fn valid_skill_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
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
        validate_workspace_root_files(home, &config.workspace_roots)?;
        validate_command_tool_files(&config.command_tools)?;
        validate_mcp_server_files(home, &config.mcp_servers)?;
        validate_browser_files(home, config.browser.as_ref())?;
        return Ok(config);
    }
    let config = DaemonConfig::default();
    let body = serde_json::to_vec_pretty(&config)?;
    atomic_write_private(home, &path, &home.join("config.json.tmp"), &body)?;
    Ok(config)
}

fn validate_workspace_root_files(
    home: &Path,
    workspaces: &[WorkspaceRootConfig],
) -> Result<(), LocalConfigError> {
    let home = fs::canonicalize(home)?;
    for workspace in workspaces {
        let canonical = fs::canonicalize(&workspace.root)?;
        let metadata = fs::symlink_metadata(&workspace.root)?;
        if canonical != workspace.root
            || metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || paths_overlap(&canonical, &home)
        {
            return Err(LocalConfigError::InvalidConfiguration);
        }
    }
    Ok(())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn validate_browser_files(
    home: &Path,
    browser: Option<&BrowserConfig>,
) -> Result<(), LocalConfigError> {
    let Some(browser) = browser else {
        return Ok(());
    };
    let home = fs::canonicalize(home)?;
    let requested = home.join(browser.bundle_path());
    let canonical = fs::canonicalize(&requested)?;
    if canonical != requested || !canonical.starts_with(&home) {
        return Err(LocalConfigError::InvalidConfiguration);
    }
    let inspection = inspect_browser_bundle(&canonical, Some(browser.bundle_digest()))
        .map_err(|_| LocalConfigError::InvalidConfiguration)?;
    if inspection.executable_digest() != browser.executable_digest() {
        return Err(LocalConfigError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_mcp_server_files(
    home: &Path,
    servers: &[McpServerConfig],
) -> Result<(), LocalConfigError> {
    let home = fs::canonicalize(home)?;
    for server in servers {
        let requested = home.join(server.executable_path());
        let canonical = fs::canonicalize(&requested)?;
        let metadata = fs::symlink_metadata(&requested)?;
        let bytes = fs::read(&requested)?;
        if canonical != requested
            || metadata.file_type().is_symlink()
            || !metadata.is_file()
            || bytes.len() < 4
            || bytes.len() > 256 * 1_024 * 1_024
            || &bytes[..4] != b"\x7fELF"
            || sha256_digest(&bytes) != server.executable_digest()
        {
            return Err(LocalConfigError::InvalidConfiguration);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(LocalConfigError::InvalidConfiguration);
            }
        }
    }
    Ok(())
}

fn validate_command_tool_files(commands: &[CommandToolConfig]) -> Result<(), LocalConfigError> {
    for command in commands {
        let canonical = fs::canonicalize(&command.executable)?;
        let metadata = fs::symlink_metadata(&canonical)?;
        let bytes = fs::read(&canonical)?;
        if canonical != command.executable
            || !metadata.is_file()
            || metadata.file_type().is_symlink()
            || !is_trusted_system_executable(&canonical)
            || bytes.len() < 4
            || bytes.len() > 256 * 1_024 * 1_024
            || &bytes[..4] != b"\x7fELF"
            || sha256_digest(&bytes) != command.executable_digest
        {
            return Err(LocalConfigError::InvalidConfiguration);
        }
    }
    Ok(())
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
    let file = open_private_instance_lock(&home.join("mealyd.lock"))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(LocalConfigError::AlreadyRunning),
        Err(std::fs::TryLockError::Error(error)) => Err(LocalConfigError::Io(error)),
    }
}

#[cfg(unix)]
fn open_private_instance_lock(path: &Path) -> Result<File, LocalConfigError> {
    use rustix::fs::{Mode, OFlags, open};

    open(
        path,
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from(0o600),
    )
    .map(File::from)
    .map_err(|error| LocalConfigError::Io(error.into()))
}

#[cfg(not(unix))]
fn open_private_instance_lock(path: &Path) -> Result<File, LocalConfigError> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    options.open(path).map_err(LocalConfigError::Io)
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
        LocalConfigError, ProviderConfig, archive_effective_daemon_config,
        load_forced_shutdown_marker, load_or_create_daemon_config, remove_forced_shutdown_marker,
        write_forced_shutdown_marker,
    };
    use mealy_application::{
        ProviderCredentialReference, default_daemon_config_document, sha256_digest,
    };
    use mealy_domain::CorrelationId;
    use serde_json::json;
    use std::{fs, time::SystemTime};

    #[test]
    fn effective_config_history_and_forced_marker_are_durable_and_exact() {
        let home = tempfile::tempdir().expect("home");
        let config = load_or_create_daemon_config(home.path()).expect("config");
        assert_eq!(
            serde_json::to_value(&config).expect("encode typed default configuration"),
            default_daemon_config_document()
        );
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

    #[test]
    fn provider_configuration_is_non_secret_bounded_and_transport_safe() {
        let local = ProviderConfig::OpenAiResponses {
            provider_id: "local.responses".to_owned(),
            base_url: "http://127.0.0.1:11434/v1".to_owned(),
            model: "local-model".to_owned(),
            credential: None,
            residency: "local".to_owned(),
            context_tokens: 32_768,
            maximum_output_tokens: 4_096,
            streaming: true,
            input_microunits_per_million_tokens: 0,
            output_microunits_per_million_tokens: 0,
            estimated_latency_ms: 50,
        };
        assert!(local.validate().is_ok());

        let remote_without_key = ProviderConfig::OpenAiResponses {
            provider_id: "openai.responses".to_owned(),
            base_url: "https://api.openai.com/v1".to_owned(),
            model: "gpt-5.6".to_owned(),
            credential: None,
            residency: "openai".to_owned(),
            context_tokens: 1_050_000,
            maximum_output_tokens: 128_000,
            streaming: true,
            input_microunits_per_million_tokens: 5_000_000,
            output_microunits_per_million_tokens: 30_000_000,
            estimated_latency_ms: 1_000,
        };
        assert!(remote_without_key.validate().is_err());

        let mut remote = remote_without_key.clone();
        let ProviderConfig::OpenAiResponses { credential, .. } = &mut remote else {
            unreachable!()
        };
        *credential = Some(ProviderCredentialReference::Broker {
            secret_id: "openai-primary".to_owned(),
        });
        assert!(remote.validate().is_ok());

        let serialized = serde_json::to_string(&remote).expect("serialize provider config");
        assert!(serialized.contains("openai-primary"));
        assert!(!serialized.contains("Bearer"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn configured_process_rejects_user_owned_executable_before_startup() {
        let home = tempfile::tempdir().expect("home");
        let workspace = tempfile::tempdir().expect("workspace");
        load_or_create_daemon_config(home.path()).expect("default config");
        let executable = home.path().join("user-owned-mkdir");
        fs::copy("/usr/bin/mkdir", &executable).expect("copy command fixture");
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o777))
                .expect("make command fixture untrusted");
        }
        let digest = sha256_digest(&fs::read(&executable).expect("read command fixture"));
        let path = home.path().join("config.json");
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read config")).expect("config JSON");
        config["workspaceRoots"] = json!([{
            "workspaceId": "project",
            "root": workspace.path().canonicalize().expect("canonical workspace"),
            "writable": true,
        }]);
        config["commandTools"] = json!([{
            "commandId": "mkdir",
            "executable": executable.canonicalize().expect("canonical command fixture"),
            "executableDigest": digest,
        }]);
        fs::write(
            path,
            serde_json::to_vec_pretty(&config).expect("encode config"),
        )
        .expect("write config");
        assert!(matches!(
            load_or_create_daemon_config(home.path()),
            Err(LocalConfigError::InvalidConfiguration)
        ));
    }

    #[test]
    fn workspace_configuration_rejects_duplicate_and_non_normalized_authority() {
        for workspace_roots in [
            json!([
                {"workspaceId": "project", "root": "/srv/project"},
                {"workspaceId": "project", "root": "/srv/other"}
            ]),
            json!([
                {"workspaceId": "project", "root": "/srv/project"},
                {"workspaceId": "other", "root": "/srv/project"}
            ]),
            json!([{"workspaceId": ".hidden", "root": "/srv/project"}]),
            json!([{"workspaceId": "project", "root": "relative/project"}]),
            json!([{"workspaceId": "project", "root": "/srv/../project"}]),
        ] {
            let home = tempfile::tempdir().expect("home");
            let config = load_or_create_daemon_config(home.path()).expect("default config");
            let mut value = serde_json::to_value(config).expect("config JSON");
            value["workspaceRoots"] = workspace_roots;
            fs::write(
                home.path().join("config.json"),
                serde_json::to_vec_pretty(&value).expect("config bytes"),
            )
            .expect("write invalid config");
            assert!(matches!(
                load_or_create_daemon_config(home.path()),
                Err(LocalConfigError::InvalidConfiguration)
            ));
        }
    }

    #[test]
    fn workspace_configuration_cannot_expose_daemon_state_or_redirected_roots() {
        let parent = tempfile::tempdir().expect("home parent");
        let home = parent.path().join("mealy-home");
        fs::create_dir(&home).expect("daemon home");
        let outside = tempfile::tempdir().expect("outside workspace");
        let config = load_or_create_daemon_config(&home).expect("default config");
        let base = serde_json::to_value(config).expect("config JSON");

        for root in [parent.path().to_path_buf(), home.clone()] {
            let mut value = base.clone();
            value["workspaceRoots"] = json!([{"workspaceId": "project", "root": root}]);
            fs::write(
                home.join("config.json"),
                serde_json::to_vec_pretty(&value).expect("config bytes"),
            )
            .expect("write overlapping config");
            assert!(matches!(
                load_or_create_daemon_config(&home),
                Err(LocalConfigError::InvalidConfiguration)
            ));
        }

        let private_child = home.join("workspace");
        fs::create_dir(&private_child).expect("private child");
        let mut child = base.clone();
        child["workspaceRoots"] = json!([{"workspaceId": "project", "root": private_child}]);
        fs::write(
            home.join("config.json"),
            serde_json::to_vec_pretty(&child).expect("child config bytes"),
        )
        .expect("write child config");
        assert!(matches!(
            load_or_create_daemon_config(&home),
            Err(LocalConfigError::InvalidConfiguration)
        ));

        let mut valid = base.clone();
        valid["workspaceRoots"] = json!([{
            "workspaceId": "project",
            "root": outside.path().canonicalize().expect("canonical outside workspace")
        }]);
        fs::write(
            home.join("config.json"),
            serde_json::to_vec_pretty(&valid).expect("valid config bytes"),
        )
        .expect("write valid config");
        assert_eq!(
            load_or_create_daemon_config(&home)
                .expect("outside workspace config")
                .workspace_roots()
                .len(),
            1
        );

        #[cfg(unix)]
        {
            let redirected = parent.path().join("redirected-workspace");
            std::os::unix::fs::symlink(outside.path(), &redirected).expect("workspace symlink");
            let mut value = base;
            value["workspaceRoots"] = json!([{"workspaceId": "project", "root": redirected}]);
            fs::write(
                home.join("config.json"),
                serde_json::to_vec_pretty(&value).expect("redirect config bytes"),
            )
            .expect("write redirected config");
            assert!(matches!(
                load_or_create_daemon_config(&home),
                Err(LocalConfigError::InvalidConfiguration)
            ));
        }
    }

    #[test]
    fn skill_configuration_is_home_relative_unique_and_digest_pinned() {
        let home = tempfile::tempdir().expect("home");
        let config = load_or_create_daemon_config(home.path()).expect("default config");
        let mut value = serde_json::to_value(config).expect("config JSON");
        let digest = "a".repeat(64);
        value["skills"] = json!([{
            "skillId": "mealy.fixture.review",
            "version": "1.0.0",
            "manifestDigest": digest,
            "packagePath": format!("skills/{digest}"),
            "enabled": false
        }]);
        fs::write(
            home.path().join("config.json"),
            serde_json::to_vec_pretty(&value).expect("config bytes"),
        )
        .expect("write config");
        let loaded = load_or_create_daemon_config(home.path()).expect("skill config");
        assert_eq!(loaded.skills().len(), 1);
        assert_eq!(loaded.skills()[0].skill_id(), "mealy.fixture.review");
        assert!(!loaded.skills()[0].enabled());

        for invalid_path in ["../skills/escape", "/tmp/skill", "skills/not-the-digest"] {
            let mut invalid = value.clone();
            invalid["skills"][0]["packagePath"] = json!(invalid_path);
            fs::write(
                home.path().join("config.json"),
                serde_json::to_vec_pretty(&invalid).expect("invalid config bytes"),
            )
            .expect("write invalid config");
            assert!(matches!(
                load_or_create_daemon_config(home.path()),
                Err(LocalConfigError::InvalidConfiguration)
            ));
        }
    }
}
