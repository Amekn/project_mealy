use crate::{EffectClass, ExtensionId, RiskClass};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Data-only extension manifest schema understood by this release.
pub const EXTENSION_MANIFEST_SCHEMA_VERSION: u32 = 1;

const MAXIMUM_IDENTITY_BYTES: usize = 255;
const MAXIMUM_VERSION_BYTES: usize = 128;
const MAXIMUM_PATH_BYTES: usize = 4_096;
const MAXIMUM_CAPABILITIES: usize = 128;
const MAXIMUM_SCHEMA_FIELDS: usize = 128;
const MAXIMUM_PERMISSIONS: usize = 128;
const MAXIMUM_MIGRATIONS: usize = 64;
const MAXIMUM_SCHEMA_BYTES: u64 = 1024 * 1024;
const MAXIMUM_CAPABILITY_TIMEOUT_MS: u64 = 300_000;
const MAXIMUM_CAPABILITY_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;
const SHA256_DIGEST_BYTES: usize = 64;

/// Canonical lifecycle state of one installed extension identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionStatus {
    /// Manifest and executable identity are installed but have no active authority.
    Installed,
    /// An exact manifest revision has an active explicit owner grant.
    Enabled,
    /// Authority is temporarily disabled while history remains intact.
    Disabled,
    /// The supervised process failed and requires bounded recovery or owner action.
    Failed,
    /// All future authority is terminally revoked without deleting historical evidence.
    Revoked,
}

/// State machine for one installed extension across upgrades and grant changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionState {
    id: ExtensionId,
    status: ExtensionStatus,
    revision: u64,
}

impl ExtensionState {
    /// Creates an installed extension with no active grant.
    #[must_use]
    pub const fn new(id: ExtensionId) -> Self {
        Self {
            id,
            status: ExtensionStatus::Installed,
            revision: 0,
        }
    }

    /// Rehydrates storage-validated state.
    #[must_use]
    pub const fn rehydrate(id: ExtensionId, status: ExtensionStatus, revision: u64) -> Self {
        Self {
            id,
            status,
            revision,
        }
    }

    /// Returns the stable extension identity.
    #[must_use]
    pub const fn id(&self) -> ExtensionId {
        self.id
    }

    /// Returns the current lifecycle status.
    #[must_use]
    pub const fn status(&self) -> ExtensionStatus {
        self.status
    }

    /// Returns the optimistic-concurrency revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Activates an exact reviewed manifest and grant.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionError`] when revoked state or revision overflow forbids activation.
    pub fn enable(&mut self) -> Result<ExtensionTransition, ExtensionError> {
        self.transition(ExtensionStatus::Enabled)
    }

    /// Temporarily removes runtime authority.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionError`] when the transition is invalid or the revision overflows.
    pub fn disable(&mut self) -> Result<ExtensionTransition, ExtensionError> {
        self.transition(ExtensionStatus::Disabled)
    }

    /// Records supervised runtime failure without widening or retaining active authority.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionError`] when the transition is invalid or the revision overflows.
    pub fn fail(&mut self) -> Result<ExtensionTransition, ExtensionError> {
        self.transition(ExtensionStatus::Failed)
    }

    /// Stages an upgrade or rollback with authority disabled pending a fresh grant.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionError`] after terminal revocation or revision overflow.
    pub fn stage_manifest(&mut self) -> Result<ExtensionTransition, ExtensionError> {
        self.transition(ExtensionStatus::Installed)
    }

    /// Terminally revokes the extension while retaining all audit evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionError`] when already revoked or the revision overflows.
    pub fn revoke(&mut self) -> Result<ExtensionTransition, ExtensionError> {
        self.transition(ExtensionStatus::Revoked)
    }

    fn transition(
        &mut self,
        target: ExtensionStatus,
    ) -> Result<ExtensionTransition, ExtensionError> {
        if !allowed(self.status, target) {
            return Err(ExtensionError::InvalidTransition {
                extension_id: self.id,
                from: self.status,
                to: target,
            });
        }
        let transition = ExtensionTransition {
            extension_id: self.id,
            from: self.status,
            to: target,
            previous_revision: self.revision,
            new_revision: self
                .revision
                .checked_add(1)
                .ok_or(ExtensionError::RevisionOverflow {
                    extension_id: self.id,
                })?,
        };
        self.status = target;
        self.revision = transition.new_revision;
        Ok(transition)
    }
}

const fn allowed(from: ExtensionStatus, to: ExtensionStatus) -> bool {
    match from {
        ExtensionStatus::Installed => matches!(
            to,
            ExtensionStatus::Enabled | ExtensionStatus::Installed | ExtensionStatus::Revoked
        ),
        ExtensionStatus::Enabled => matches!(
            to,
            ExtensionStatus::Disabled
                | ExtensionStatus::Failed
                | ExtensionStatus::Installed
                | ExtensionStatus::Revoked
        ),
        ExtensionStatus::Disabled | ExtensionStatus::Failed => matches!(
            to,
            ExtensionStatus::Enabled | ExtensionStatus::Installed | ExtensionStatus::Revoked
        ),
        ExtensionStatus::Revoked => false,
    }
}

/// Immutable evidence of one accepted extension lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtensionTransition {
    extension_id: ExtensionId,
    from: ExtensionStatus,
    to: ExtensionStatus,
    previous_revision: u64,
    new_revision: u64,
}

impl ExtensionTransition {
    /// Returns the affected extension.
    #[must_use]
    pub const fn extension_id(self) -> ExtensionId {
        self.extension_id
    }

    /// Returns the prior status.
    #[must_use]
    pub const fn from(self) -> ExtensionStatus {
        self.from
    }

    /// Returns the new status.
    #[must_use]
    pub const fn to(self) -> ExtensionStatus {
        self.to
    }

    /// Returns the optimistic revision that storage must compare.
    #[must_use]
    pub const fn previous_revision(self) -> u64 {
        self.previous_revision
    }

    /// Returns the committed revision after the transition.
    #[must_use]
    pub const fn new_revision(self) -> u64 {
        self.new_revision
    }
}

/// Broad adapter role advertised by the data-only manifest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionKind {
    /// Provider-neutral model adapter.
    ProviderAdapter,
    /// Externally authenticated message channel.
    ChannelAdapter,
    /// Typed tool implementation.
    ToolService,
    /// Governed memory source.
    MemorySource,
    /// Artifact presentation adapter.
    ArtifactRenderer,
    /// Outbound notification delivery adapter.
    NotificationSink,
}

/// Invocation kind for one manifest capability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionCapabilityKind {
    /// Read-only or effectful tool operation.
    Tool,
    /// Bounded health probe.
    Health,
    /// Channel ingress or delivery operation.
    Channel,
    /// Upgrade state migration operation.
    Migration,
    /// Graceful shutdown notification.
    Shutdown,
}

/// Primitive values supported by the intentionally small extension schema dialect.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionScalarType {
    /// UTF-8 string.
    String,
    /// Signed JSON integer.
    Integer,
    /// JSON boolean.
    Boolean,
}

/// One field in a bounded object schema.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionFieldSchema {
    /// Required primitive type.
    pub value_type: ExtensionScalarType,
    /// Maximum UTF-8 bytes for string values.
    pub maximum_length: Option<u64>,
    /// Inclusive minimum for integer values.
    pub minimum_integer: Option<i64>,
    /// Inclusive maximum for integer values.
    pub maximum_integer: Option<i64>,
}

/// Strict, bounded JSON object contract validated on both sides of extension RPC.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionObjectSchema {
    /// Named property contracts.
    pub properties: BTreeMap<String, ExtensionFieldSchema>,
    /// Properties that must be present.
    pub required: BTreeSet<String>,
    /// Whether properties absent from `properties` are accepted.
    pub additional_properties: bool,
    /// Maximum canonical serialized object bytes.
    pub maximum_serialized_bytes: u64,
}

/// One schema-validated operation declared by an extension manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionCapabilityManifest {
    /// Stable capability identifier within the extension identity.
    pub capability_id: String,
    /// Adapter-facing invocation kind.
    pub kind: ExtensionCapabilityKind,
    /// External-effect classification used by Mealy policy.
    pub effect_class: EffectClass,
    /// Risk classification used by validation and approval policy.
    pub risk_class: RiskClass,
    /// Strict request object schema.
    pub input_schema: ExtensionObjectSchema,
    /// Strict terminal response object schema.
    pub output_schema: ExtensionObjectSchema,
    /// Hard wall-clock invocation limit.
    pub timeout_ms: u64,
    /// Hard terminal-output byte limit.
    pub maximum_output_bytes: u64,
}

/// Filesystem access requested for one named logical mount.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionFilesystemAccess {
    /// Extension may only read the granted mount.
    ReadOnly,
    /// Extension may read and write the granted mount.
    ReadWrite,
}

/// One reviewable logical filesystem permission request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionFilesystemPermission {
    /// Stable logical mount name resolved by trusted policy.
    pub name: String,
    /// Requested access mode.
    pub access: ExtensionFilesystemAccess,
}

/// Complete least-authority request visible before extension code is run.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionPermissions {
    /// Named filesystem roots requiring an explicit host mapping grant.
    pub filesystem: Vec<ExtensionFilesystemPermission>,
    /// Exact outbound network destinations.
    pub network_destinations: Vec<String>,
    /// Opaque secret references, never values.
    pub secret_references: Vec<String>,
    /// Whether a capability may create child processes.
    pub allow_process_spawn: bool,
}

/// One digest-pinned dynamic runtime file exposed read-only to the worker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionRuntimeFile {
    /// Exact absolute host file requested for the runtime.
    pub host_path: String,
    /// Exact absolute path expected by the extension loader.
    pub sandbox_path: String,
    /// SHA-256 digest of the exact runtime file.
    pub digest: String,
}

/// Exact executable entry point and runtime identity material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionEntryPoint {
    /// Canonical relative path beneath the configured installation root.
    pub executable: String,
    /// SHA-256 digest of the exact executable bytes.
    pub executable_digest: String,
    /// Minimal digest-pinned loader and shared-library files.
    pub runtime_files: Vec<ExtensionRuntimeFile>,
}

/// Host API compatibility range declared without importing extension code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionCompatibility {
    /// Oldest host API revision supported by the extension.
    pub minimum_host_api: u32,
    /// Newest host API revision supported by the extension.
    pub maximum_host_api: u32,
}

/// Bounded manifest-declared health behavior.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionHealthCheck {
    /// Health capability to invoke after grants are active.
    pub capability_id: String,
    /// Maximum duration of one probe.
    pub timeout_ms: u64,
    /// Minimum interval between automatic probes.
    pub interval_ms: u64,
}

/// Versioned state migration declared by an upgrade manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionMigration {
    /// Exact predecessor extension version.
    pub from_version: String,
    /// Exact successor extension version.
    pub to_version: String,
    /// Migration capability invoked in the supervised boundary.
    pub capability_id: String,
    /// Digest of the declarative migration contract.
    pub contract_digest: String,
}

/// Declared graceful shutdown strategy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionShutdownMode {
    /// Supervisor terminates the process without an extension callback.
    Terminate,
    /// Supervisor sends a bounded shutdown RPC before termination.
    RpcThenTerminate,
}

/// Manifest-declared bounded shutdown behavior.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionShutdownBehavior {
    /// Chosen shutdown mode.
    pub mode: ExtensionShutdownMode,
    /// Shutdown capability required for RPC mode.
    pub capability_id: Option<String>,
    /// Maximum graceful period before forced termination.
    pub grace_period_ms: u64,
}

/// Complete data-only extension manifest. Deserialization never loads or executes code.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionManifest {
    /// Manifest schema revision.
    pub schema_version: u32,
    /// Stable extension identity retained across upgrades.
    pub extension_id: ExtensionId,
    /// Reverse-domain or similarly collision-resistant human identity.
    pub name: String,
    /// Reviewable publisher identity.
    pub publisher: String,
    /// Extension package version.
    pub version: String,
    /// Broad adapter roles.
    pub kinds: BTreeSet<ExtensionKind>,
    /// Supported host API range.
    pub compatibility: ExtensionCompatibility,
    /// Digest-pinned worker entry point.
    pub entry_point: ExtensionEntryPoint,
    /// Schema-validated RPC capabilities.
    pub capabilities: Vec<ExtensionCapabilityManifest>,
    /// Requested authority reviewed before activation.
    pub permissions: ExtensionPermissions,
    /// Bounded health contract.
    pub health_check: ExtensionHealthCheck,
    /// Upgrade migration declarations.
    pub migrations: Vec<ExtensionMigration>,
    /// Graceful shutdown contract.
    pub shutdown: ExtensionShutdownBehavior,
}

impl ExtensionManifest {
    /// Validates all data-only identity, compatibility, schema, permission, and lifecycle metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionError::InvalidManifest`] for malformed or unbounded data.
    pub fn validate(&self) -> Result<(), ExtensionError> {
        if self.schema_version != EXTENSION_MANIFEST_SCHEMA_VERSION
            || !valid_identity(&self.name)
            || !valid_identity(&self.publisher)
            || !valid_version(&self.version)
            || self.kinds.is_empty()
            || self.compatibility.minimum_host_api == 0
            || self.compatibility.minimum_host_api > self.compatibility.maximum_host_api
            || !valid_relative_path(&self.entry_point.executable)
            || !is_sha256_digest(&self.entry_point.executable_digest)
            || self.capabilities.is_empty()
            || self.capabilities.len() > MAXIMUM_CAPABILITIES
        {
            return Err(invalid_manifest(
                "identity, compatibility, or entry point is invalid",
            ));
        }
        validate_runtime_files(&self.entry_point.runtime_files)?;
        let mut capability_ids = BTreeSet::new();
        for capability in &self.capabilities {
            if !valid_identity(&capability.capability_id)
                || !capability_ids.insert(capability.capability_id.as_str())
                || capability.timeout_ms == 0
                || capability.timeout_ms > MAXIMUM_CAPABILITY_TIMEOUT_MS
                || capability.maximum_output_bytes == 0
                || capability.maximum_output_bytes > MAXIMUM_CAPABILITY_OUTPUT_BYTES
            {
                return Err(invalid_manifest("extension capability is invalid"));
            }
            validate_schema(&capability.input_schema)?;
            validate_schema(&capability.output_schema)?;
        }
        validate_permissions(&self.permissions)?;
        if !capability_ids.contains(self.health_check.capability_id.as_str())
            || self.health_check.timeout_ms == 0
            || self.health_check.timeout_ms > MAXIMUM_CAPABILITY_TIMEOUT_MS
            || self.health_check.interval_ms < self.health_check.timeout_ms
            || self.health_check.interval_ms > 86_400_000
        {
            return Err(invalid_manifest("extension health contract is invalid"));
        }
        let health = self
            .capabilities
            .iter()
            .find(|capability| capability.capability_id == self.health_check.capability_id)
            .ok_or_else(|| invalid_manifest("extension health capability is absent"))?;
        if health.kind != ExtensionCapabilityKind::Health
            || health.effect_class != EffectClass::ReadOnly
        {
            return Err(invalid_manifest(
                "extension health capability is not read-only",
            ));
        }
        validate_migrations(&self.migrations, &capability_ids)?;
        validate_shutdown(&self.shutdown, &self.capabilities)?;
        Ok(())
    }

    /// Returns one exact declared capability.
    #[must_use]
    pub fn capability(&self, capability_id: &str) -> Option<&ExtensionCapabilityManifest> {
        self.capabilities
            .iter()
            .find(|capability| capability.capability_id == capability_id)
    }
}

fn validate_schema(schema: &ExtensionObjectSchema) -> Result<(), ExtensionError> {
    if schema.properties.len() > MAXIMUM_SCHEMA_FIELDS
        || schema.required.len() > schema.properties.len()
        || schema.maximum_serialized_bytes == 0
        || schema.maximum_serialized_bytes > MAXIMUM_SCHEMA_BYTES
        || schema
            .required
            .iter()
            .any(|field| !schema.properties.contains_key(field))
    {
        return Err(invalid_manifest("extension object schema is invalid"));
    }
    for (name, field) in &schema.properties {
        if !valid_identity(name)
            || matches!(field.maximum_length, Some(0))
            || field.maximum_length.is_some() != (field.value_type == ExtensionScalarType::String)
            || (field.minimum_integer.is_some() || field.maximum_integer.is_some())
                != (field.value_type == ExtensionScalarType::Integer)
            || field
                .minimum_integer
                .zip(field.maximum_integer)
                .is_some_and(|(minimum, maximum)| minimum > maximum)
        {
            return Err(invalid_manifest("extension schema field is invalid"));
        }
    }
    Ok(())
}

fn validate_permissions(permissions: &ExtensionPermissions) -> Result<(), ExtensionError> {
    if permissions.filesystem.len() > MAXIMUM_PERMISSIONS
        || permissions.network_destinations.len() > MAXIMUM_PERMISSIONS
        || permissions.secret_references.len() > MAXIMUM_PERMISSIONS
    {
        return Err(invalid_manifest("extension permission count is invalid"));
    }
    let mut names = BTreeSet::new();
    if permissions
        .filesystem
        .iter()
        .any(|permission| !valid_identity(&permission.name) || !names.insert(&permission.name))
        || !strictly_sorted_valid(&permissions.network_destinations)
        || !strictly_sorted_valid(&permissions.secret_references)
    {
        return Err(invalid_manifest("extension permissions are not canonical"));
    }
    Ok(())
}

fn validate_runtime_files(files: &[ExtensionRuntimeFile]) -> Result<(), ExtensionError> {
    if files.len() > MAXIMUM_PERMISSIONS {
        return Err(invalid_manifest("extension runtime file count is invalid"));
    }
    let mut targets = BTreeSet::new();
    for file in files {
        if !valid_absolute_path(&file.host_path)
            || !valid_absolute_path(&file.sandbox_path)
            || !is_sha256_digest(&file.digest)
            || !targets.insert(file.sandbox_path.as_str())
        {
            return Err(invalid_manifest("extension runtime file is invalid"));
        }
    }
    Ok(())
}

fn validate_migrations(
    migrations: &[ExtensionMigration],
    capabilities: &BTreeSet<&str>,
) -> Result<(), ExtensionError> {
    if migrations.len() > MAXIMUM_MIGRATIONS {
        return Err(invalid_manifest("extension migration count is invalid"));
    }
    let mut edges = BTreeSet::new();
    for migration in migrations {
        if !valid_version(&migration.from_version)
            || !valid_version(&migration.to_version)
            || migration.from_version == migration.to_version
            || !capabilities.contains(migration.capability_id.as_str())
            || !is_sha256_digest(&migration.contract_digest)
            || !edges.insert((&migration.from_version, &migration.to_version))
        {
            return Err(invalid_manifest("extension migration contract is invalid"));
        }
    }
    Ok(())
}

fn validate_shutdown(
    shutdown: &ExtensionShutdownBehavior,
    capabilities: &[ExtensionCapabilityManifest],
) -> Result<(), ExtensionError> {
    if shutdown.grace_period_ms == 0 || shutdown.grace_period_ms > 60_000 {
        return Err(invalid_manifest(
            "extension shutdown grace period is invalid",
        ));
    }
    match (shutdown.mode, shutdown.capability_id.as_deref()) {
        (ExtensionShutdownMode::Terminate, None) => Ok(()),
        (ExtensionShutdownMode::RpcThenTerminate, Some(capability_id))
            if capabilities.iter().any(|capability| {
                capability.capability_id == capability_id
                    && capability.kind == ExtensionCapabilityKind::Shutdown
                    && capability.effect_class == EffectClass::ReadOnly
            }) =>
        {
            Ok(())
        }
        _ => Err(invalid_manifest("extension shutdown contract is invalid")),
    }
}

fn strictly_sorted_valid(values: &[String]) -> bool {
    values.iter().all(|value| valid_identity(value))
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_IDENTITY_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_VERSION_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}

fn valid_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_PATH_BYTES
        && !value.starts_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
        && !value.chars().any(char::is_control)
}

fn valid_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= MAXIMUM_PATH_BYTES
        && !value.contains('\\')
        && value
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
        && !value.chars().any(char::is_control)
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == SHA256_DIGEST_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid_manifest(message: impl Into<String>) -> ExtensionError {
    ExtensionError::InvalidManifest(message.into())
}

/// Invalid extension state or manifest contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ExtensionError {
    /// Lifecycle transition violates revocation or authority rules.
    #[error("extension {extension_id} cannot transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// Affected extension.
        extension_id: ExtensionId,
        /// Current state.
        from: ExtensionStatus,
        /// Requested state.
        to: ExtensionStatus,
    },
    /// Extension revision cannot advance further.
    #[error("extension {extension_id} revision overflowed")]
    RevisionOverflow {
        /// Affected extension.
        extension_id: ExtensionId,
    },
    /// Data-only manifest violates identity, schema, permission, or bound requirements.
    #[error("extension manifest is invalid: {0}")]
    InvalidManifest(String),
}

#[cfg(test)]
mod tests {
    use super::{
        EXTENSION_MANIFEST_SCHEMA_VERSION, ExtensionCapabilityKind, ExtensionCapabilityManifest,
        ExtensionCompatibility, ExtensionEntryPoint, ExtensionFieldSchema, ExtensionHealthCheck,
        ExtensionKind, ExtensionManifest, ExtensionObjectSchema, ExtensionPermissions,
        ExtensionScalarType, ExtensionShutdownBehavior, ExtensionShutdownMode, ExtensionState,
        ExtensionStatus,
    };
    use crate::{EffectClass, ExtensionId, RiskClass};
    use std::collections::{BTreeMap, BTreeSet};

    fn object_schema() -> ExtensionObjectSchema {
        ExtensionObjectSchema {
            properties: BTreeMap::from([(
                "text".to_owned(),
                ExtensionFieldSchema {
                    value_type: ExtensionScalarType::String,
                    maximum_length: Some(4_096),
                    minimum_integer: None,
                    maximum_integer: None,
                },
            )]),
            required: BTreeSet::from(["text".to_owned()]),
            additional_properties: false,
            maximum_serialized_bytes: 8_192,
        }
    }

    fn manifest() -> ExtensionManifest {
        ExtensionManifest {
            schema_version: EXTENSION_MANIFEST_SCHEMA_VERSION,
            extension_id: ExtensionId::new(),
            name: "dev.mealy.sample-text".to_owned(),
            publisher: "dev.mealy".to_owned(),
            version: "1.0.0".to_owned(),
            kinds: BTreeSet::from([ExtensionKind::ToolService]),
            compatibility: ExtensionCompatibility {
                minimum_host_api: 1,
                maximum_host_api: 1,
            },
            entry_point: ExtensionEntryPoint {
                executable: "bin/sample-extension".to_owned(),
                executable_digest: "a".repeat(64),
                runtime_files: Vec::new(),
            },
            capabilities: vec![ExtensionCapabilityManifest {
                capability_id: "health".to_owned(),
                kind: ExtensionCapabilityKind::Health,
                effect_class: EffectClass::ReadOnly,
                risk_class: RiskClass::Low,
                input_schema: ExtensionObjectSchema {
                    properties: BTreeMap::new(),
                    required: BTreeSet::new(),
                    additional_properties: false,
                    maximum_serialized_bytes: 2,
                },
                output_schema: object_schema(),
                timeout_ms: 1_000,
                maximum_output_bytes: 8_192,
            }],
            permissions: ExtensionPermissions::default(),
            health_check: ExtensionHealthCheck {
                capability_id: "health".to_owned(),
                timeout_ms: 1_000,
                interval_ms: 5_000,
            },
            migrations: Vec::new(),
            shutdown: ExtensionShutdownBehavior {
                mode: ExtensionShutdownMode::Terminate,
                capability_id: None,
                grace_period_ms: 1_000,
            },
        }
    }

    #[test]
    fn manifest_is_data_only_bounded_and_schema_checked() {
        let manifest = manifest();
        assert_eq!(manifest.validate(), Ok(()));

        let mut traversal = manifest.clone();
        traversal.entry_point.executable = "../worker".to_owned();
        assert!(traversal.validate().is_err());

        let mut unknown_health = manifest;
        unknown_health.health_check.capability_id = "missing".to_owned();
        assert!(unknown_health.validate().is_err());
    }

    #[test]
    fn revocation_is_terminal_and_upgrades_remove_authority() {
        let id = ExtensionId::new();
        let mut state = ExtensionState::new(id);
        assert_eq!(
            state.enable().expect("enable").to(),
            ExtensionStatus::Enabled
        );
        assert_eq!(
            state.stage_manifest().expect("stage upgrade").to(),
            ExtensionStatus::Installed
        );
        state.enable().expect("fresh grant");
        state.revoke().expect("revoke");
        assert!(state.enable().is_err());
        assert_eq!(state.revision(), 4);
    }
}
