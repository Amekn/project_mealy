use crate::{CancellationProbe, OwnershipContext, is_sha256_digest, sha256_digest};
use mealy_domain::{
    CorrelationId, EventId, ExtensionFilesystemAccess, ExtensionGrantId, ExtensionId,
    ExtensionInvocationId, ExtensionManifest, ExtensionObjectSchema, ExtensionScalarType,
    ExtensionStatus, PrincipalId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::SystemTime,
};
use thiserror::Error;

/// Host compatibility revision implemented by this Mealy release.
pub const EXTENSION_HOST_API_VERSION: u32 = 1;
/// Versioned extension request/response contract nested inside the isolated executor framing.
pub const EXTENSION_RPC_VERSION: &str = "mealy.extension.rpc.v1";
/// Stable policy bundle used to authorize extension manifests and grants.
pub const EXTENSION_POLICY_VERSION: &str = "mealy.extension.policy.v1";
/// Hard bound for one untrusted data-only manifest.
pub const EXTENSION_MANIFEST_MAXIMUM_BYTES: usize = 1024 * 1024;

const MAXIMUM_GRANT_MOUNTS: usize = 128;
const MAXIMUM_PATH_BYTES: usize = 4_096;

/// Parsed and validated data-only manifest plus its exact byte identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionManifestInspection {
    /// Validated semantic manifest.
    pub manifest: ExtensionManifest,
    /// Exact original UTF-8 JSON bytes retained for audit and rollback.
    pub manifest_json: String,
    /// SHA-256 digest of the exact original bytes.
    pub manifest_digest: String,
}

/// Parses and validates a digest-pinned extension manifest without loading or executing its code.
///
/// # Errors
///
/// Returns [`ExtensionManifestInspectionError`] for byte bounds, digest mismatch, JSON/schema
/// failure, or an incompatible host API range.
pub fn inspect_extension_manifest(
    bytes: &[u8],
    pinned_digest: &str,
) -> Result<ExtensionManifestInspection, ExtensionManifestInspectionError> {
    if bytes.is_empty() || bytes.len() > EXTENSION_MANIFEST_MAXIMUM_BYTES {
        return Err(ExtensionManifestInspectionError::InvalidSize);
    }
    if !is_sha256_digest(pinned_digest) || sha256_digest(bytes) != pinned_digest {
        return Err(ExtensionManifestInspectionError::DigestMismatch);
    }
    let manifest_json = std::str::from_utf8(bytes)
        .map_err(|_| ExtensionManifestInspectionError::InvalidJson)?
        .to_owned();
    let manifest = serde_json::from_slice::<ExtensionManifest>(bytes)
        .map_err(|_| ExtensionManifestInspectionError::InvalidJson)?;
    manifest
        .validate()
        .map_err(|error| ExtensionManifestInspectionError::InvalidManifest(error.to_string()))?;
    if !(manifest.compatibility.minimum_host_api..=manifest.compatibility.maximum_host_api)
        .contains(&EXTENSION_HOST_API_VERSION)
    {
        return Err(ExtensionManifestInspectionError::IncompatibleHost);
    }
    Ok(ExtensionManifestInspection {
        manifest,
        manifest_json,
        manifest_digest: pinned_digest.to_owned(),
    })
}

/// Failure while inspecting an untrusted extension manifest as inert data.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ExtensionManifestInspectionError {
    /// Manifest is empty or exceeds the hard byte limit.
    #[error("extension manifest size is invalid")]
    InvalidSize,
    /// Exact bytes do not match the owner-supplied digest pin.
    #[error("extension manifest digest does not match its pin")]
    DigestMismatch,
    /// Manifest is not strict UTF-8 JSON for the current schema.
    #[error("extension manifest JSON is invalid")]
    InvalidJson,
    /// Parsed manifest violates semantic bounds or cross-field invariants.
    #[error("extension manifest contract is invalid: {0}")]
    InvalidManifest(String),
    /// Host API revision is outside the manifest compatibility range.
    #[error("extension is incompatible with this host API")]
    IncompatibleHost,
}

/// One exact host directory mapped to a manifest-declared logical filesystem permission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionMountGrant {
    /// Logical permission name from the manifest.
    pub name: String,
    /// Granted access, never broader than the request.
    pub access: ExtensionFilesystemAccess,
    /// Exact canonical host directory selected by trusted policy.
    pub host_path: String,
    /// Exact normalized absolute worker path.
    pub sandbox_path: String,
}

/// Explicit owner-approved authority for one exact manifest digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionGrant {
    /// Stable immutable grant identity.
    pub grant_id: ExtensionGrantId,
    /// Exact extension identity.
    pub extension_id: ExtensionId,
    /// Manifest bytes this grant reviewed.
    pub manifest_digest: String,
    /// Authorized capability IDs.
    pub capability_ids: BTreeSet<String>,
    /// Explicit logical-to-host filesystem mappings.
    pub mounts: Vec<ExtensionMountGrant>,
    /// Exact authorized network destinations.
    pub network_destinations: BTreeSet<String>,
    /// Exact opaque secret references.
    pub secret_references: BTreeSet<String>,
    /// Whether child process creation is authorized.
    pub allow_process_spawn: bool,
    /// Stable policy bundle that produced the grant.
    pub policy_version: String,
    /// Authenticated owner who issued the grant.
    pub issued_by_principal_id: PrincipalId,
    /// UTC issuance time.
    pub issued_at_ms: i64,
}

impl ExtensionGrant {
    /// Validates exact ownership and proves every granted axis is a subset of manifest requests.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionGrantError`] for identity mismatch, authority widening, invalid paths, or
    /// a non-canonical policy contract.
    pub fn validate(
        &self,
        manifest: &ExtensionManifest,
        ownership: OwnershipContext,
    ) -> Result<(), ExtensionGrantError> {
        if self.extension_id != manifest.extension_id
            || !is_sha256_digest(&self.manifest_digest)
            || self.policy_version != EXTENSION_POLICY_VERSION
            || self.issued_by_principal_id != ownership.principal_id()
            || self.issued_at_ms < 0
            || self.capability_ids.is_empty()
            || self
                .capability_ids
                .iter()
                .any(|capability_id| manifest.capability(capability_id).is_none())
        {
            return Err(ExtensionGrantError::IdentityMismatch);
        }
        if self.mounts.len() > MAXIMUM_GRANT_MOUNTS {
            return Err(ExtensionGrantError::AuthorityWidening);
        }
        let requested_mounts = manifest
            .permissions
            .filesystem
            .iter()
            .map(|permission| (permission.name.as_str(), permission.access))
            .collect::<BTreeMap<_, _>>();
        let mut mount_names = BTreeSet::new();
        let mut host_paths = BTreeSet::new();
        let mut sandbox_paths = BTreeSet::new();
        for mount in &self.mounts {
            let Some(requested_access) = requested_mounts.get(mount.name.as_str()) else {
                return Err(ExtensionGrantError::AuthorityWidening);
            };
            if (*requested_access == ExtensionFilesystemAccess::ReadOnly
                && mount.access != ExtensionFilesystemAccess::ReadOnly)
                || !valid_absolute_path(&mount.host_path)
                || !valid_absolute_path(&mount.sandbox_path)
                || !mount_names.insert(mount.name.as_str())
                || !host_paths.insert(mount.host_path.as_str())
                || !sandbox_paths.insert(mount.sandbox_path.as_str())
            {
                return Err(ExtensionGrantError::InvalidMount);
            }
        }
        let requested_network = manifest
            .permissions
            .network_destinations
            .iter()
            .collect::<BTreeSet<_>>();
        let requested_secrets = manifest
            .permissions
            .secret_references
            .iter()
            .collect::<BTreeSet<_>>();
        if self
            .network_destinations
            .iter()
            .any(|destination| !requested_network.contains(destination))
            || self
                .secret_references
                .iter()
                .any(|reference| !requested_secrets.contains(reference))
            || (self.allow_process_spawn && !manifest.permissions.allow_process_spawn)
        {
            return Err(ExtensionGrantError::AuthorityWidening);
        }
        Ok(())
    }
}

/// Computes the canonical digest used to bind an extension invocation to one immutable grant.
///
/// # Errors
///
/// Returns [`ExtensionGrantError::Encoding`] when canonical JSON encoding fails.
pub fn extension_grant_digest(grant: &ExtensionGrant) -> Result<String, ExtensionGrantError> {
    serde_json::to_vec(grant)
        .map(|bytes| sha256_digest(&bytes))
        .map_err(|_| ExtensionGrantError::Encoding)
}

/// Invalid owner grant or widened extension authority.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExtensionGrantError {
    /// Extension, manifest, policy, principal, or capability identity diverged.
    #[error("extension grant identity is invalid")]
    IdentityMismatch,
    /// Filesystem mapping is malformed, ambiguous, duplicated, or broader than requested.
    #[error("extension mount grant is invalid")]
    InvalidMount,
    /// Network, secret, process, filesystem, or capability authority exceeds the manifest.
    #[error("extension grant widens manifest authority")]
    AuthorityWidening,
    /// Canonical grant JSON could not be encoded.
    #[error("extension grant could not be encoded")]
    Encoding,
}

/// Exact schema-validated request sent to one supervised extension invocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionRpcRequest {
    /// Versioned extension RPC contract.
    pub protocol_version: String,
    /// Stable bounded invocation identity.
    pub invocation_id: ExtensionInvocationId,
    /// Exact extension identity.
    pub extension_id: ExtensionId,
    /// Exact manifest byte digest.
    pub manifest_digest: String,
    /// Exact owner-grant digest.
    pub grant_digest: String,
    /// Exact manifest capability.
    pub capability_id: String,
    /// Schema-validated provider-neutral input.
    pub input: Value,
    /// Digest of canonical input JSON.
    pub input_digest: String,
}

impl ExtensionRpcRequest {
    /// Validates protocol identity, manifest/grant binding, and input schema before dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionRpcError`] for any identity, digest, capability, or schema mismatch.
    pub fn validate(
        &self,
        manifest: &ExtensionManifest,
        manifest_digest: &str,
        grant: &ExtensionGrant,
        ownership: OwnershipContext,
    ) -> Result<(), ExtensionRpcError> {
        grant
            .validate(manifest, ownership)
            .map_err(|_| ExtensionRpcError::GrantMismatch)?;
        let expected_grant_digest =
            extension_grant_digest(grant).map_err(|_| ExtensionRpcError::GrantMismatch)?;
        if self.protocol_version != EXTENSION_RPC_VERSION
            || self.extension_id != manifest.extension_id
            || self.manifest_digest != manifest_digest
            || self.manifest_digest != grant.manifest_digest
            || self.grant_digest != expected_grant_digest
            || !grant.capability_ids.contains(&self.capability_id)
            || !is_sha256_digest(&self.input_digest)
            || canonical_json_digest(&self.input)? != self.input_digest
        {
            return Err(ExtensionRpcError::IdentityMismatch);
        }
        let capability = manifest
            .capability(&self.capability_id)
            .ok_or(ExtensionRpcError::CapabilityDenied)?;
        validate_extension_object(&self.input, &capability.input_schema)
            .map_err(|_| ExtensionRpcError::InvalidInput)
    }
}

/// Exact request-bound terminal extension RPC response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionRpcResponse {
    /// Versioned extension RPC contract.
    pub protocol_version: String,
    /// Invocation copied from the request.
    pub invocation_id: ExtensionInvocationId,
    /// Extension copied from the request.
    pub extension_id: ExtensionId,
    /// Manifest digest copied from the request.
    pub manifest_digest: String,
    /// Grant digest copied from the request.
    pub grant_digest: String,
    /// Capability copied from the request.
    pub capability_id: String,
    /// Schema-validated provider-neutral terminal output.
    pub output: Value,
    /// Digest of canonical output JSON.
    pub output_digest: String,
}

/// Complete one-use request supplied to an isolated extension-host adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionDispatchRequest {
    /// Authenticated owner and channel whose grant is being exercised.
    pub ownership: OwnershipContext,
    /// Exact inert manifest revision.
    pub manifest: ExtensionManifest,
    /// Digest of the exact manifest bytes.
    pub manifest_digest: String,
    /// Exact reviewed authority grant.
    pub grant: ExtensionGrant,
    /// Exact schema-validated RPC request.
    pub rpc_request: ExtensionRpcRequest,
    /// Opaque one-use capability supplied only to the isolated process.
    pub capability_token: String,
}

impl ExtensionDispatchRequest {
    /// Validates every manifest, grant, RPC, and one-use capability binding before process launch.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionHostError::InvalidDispatch`] when any authority or identity axis
    /// diverges.
    pub fn validate(&self) -> Result<(), ExtensionHostError> {
        if self.capability_token.len() < 32
            || self.capability_token.len() > 512
            || self.capability_token.trim() != self.capability_token
            || self.capability_token.chars().any(char::is_control)
        {
            return Err(ExtensionHostError::InvalidDispatch);
        }
        self.manifest
            .validate()
            .map_err(|_| ExtensionHostError::InvalidDispatch)?;
        self.rpc_request
            .validate(
                &self.manifest,
                &self.manifest_digest,
                &self.grant,
                self.ownership,
            )
            .map_err(|_| ExtensionHostError::InvalidDispatch)
    }
}

/// Port for one bounded, supervised, out-of-process extension invocation.
pub trait ExtensionHost {
    /// Executes one exact request through its isolated worker and validates its terminal response.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionHostError`] when policy cannot be enforced, the worker fails, or its
    /// response does not bind the request.
    fn invoke(
        &self,
        request: &ExtensionDispatchRequest,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ExtensionRpcResponse, ExtensionHostError>;
}

/// Failure at the supervised extension process boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ExtensionHostError {
    /// Dispatch evidence is malformed or does not bind the exact reviewed grant.
    #[error("extension dispatch contract is invalid")]
    InvalidDispatch,
    /// Current host cannot enforce the requested extension authority.
    #[error("extension host cannot enforce the requested boundary: {0}")]
    UnsupportedHost(String),
    /// Digest-pinned executable or runtime identity changed.
    #[error("extension executable or runtime identity changed")]
    IdentityMismatch,
    /// Worker exceeded its wall-clock limit.
    #[error("extension invocation timed out")]
    TimedOut,
    /// Caller cancelled the bounded invocation.
    #[error("extension invocation was cancelled")]
    Cancelled,
    /// Worker output exceeded the declared byte/frame bound.
    #[error("extension invocation exceeded its output bound")]
    OutputLimitExceeded,
    /// Worker exited or violated the outer executor framing.
    #[error("extension worker process failed: {0}")]
    ProcessFailure(String),
    /// Worker returned a bounded classified terminal failure.
    #[error("extension capability failed: {error_class}: {error_message}")]
    WorkerFailure {
        /// Stable worker-defined failure class.
        error_class: String,
        /// Sanitized bounded explanation.
        error_message: String,
        /// Whether the capability contract permits a new durable invocation.
        retryable: bool,
    },
    /// Terminal response is forged, malformed, or violates the declared output schema.
    #[error("extension terminal response is invalid")]
    InvalidResponse,
}

/// One immutable installed manifest revision retained for upgrade rollback and audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionManifestRevisionView {
    /// Exact manifest byte digest.
    pub manifest_digest: String,
    /// Parsed validated manifest.
    pub manifest: ExtensionManifest,
    /// Exact original manifest JSON.
    pub manifest_json: String,
    /// Internal canonical installation root; never included in owner transport projections.
    pub installation_root: String,
    /// UTC install/staging time.
    pub installed_at_ms: i64,
}

/// Current owner-authorized extension projection and complete immutable manifest history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionView {
    /// Stable extension identity.
    pub extension_id: ExtensionId,
    /// Owner principal.
    pub principal_id: PrincipalId,
    /// Current authority/lifecycle state.
    pub status: ExtensionStatus,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// Exact active/staged manifest digest.
    pub current_manifest_digest: String,
    /// Current parsed manifest.
    pub manifest: ExtensionManifest,
    /// Current explicit grant, present only while enabled.
    pub active_grant: Option<ExtensionGrant>,
    /// Exact digest of the active grant.
    pub active_grant_digest: Option<String>,
    /// Complete immutable manifest revision history in installation order.
    pub manifest_history: Vec<ExtensionManifestRevisionView>,
    /// Last successful health check, if one has completed.
    pub last_healthy_at_ms: Option<i64>,
    /// Last failed health check, if one has completed.
    pub last_failure_at_ms: Option<i64>,
}

/// Atomic installation of one new digest-pinned extension identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallExtensionCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Fully inspected inert manifest bytes.
    pub inspection: ExtensionManifestInspection,
    /// Canonical internal package root verified by infrastructure.
    pub installation_root: String,
    /// `extension.installed` journal fact.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Installation time.
    pub installed_at: SystemTime,
}

/// Stages an upgrade or rollback manifest and removes old runtime authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageExtensionManifestCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Stable extension identity.
    pub extension_id: ExtensionId,
    /// Optimistic-concurrency revision.
    pub expected_revision: u64,
    /// New or historical digest-pinned manifest bytes.
    pub inspection: ExtensionManifestInspection,
    /// Canonical internal package root.
    pub installation_root: String,
    /// `extension.manifest_staged` journal fact.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Staging time.
    pub staged_at: SystemTime,
}

/// Activates an exact staged manifest under a fresh immutable owner grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnableExtensionCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Stable extension identity.
    pub extension_id: ExtensionId,
    /// Optimistic-concurrency revision.
    pub expected_revision: u64,
    /// Exact owner-reviewed grant.
    pub grant: ExtensionGrant,
    /// Digest of the request-bound successful health response returned before activation.
    pub health_output_digest: String,
    /// `extension.enabled` journal fact.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Activation time.
    pub enabled_at: SystemTime,
}

/// Temporarily removes active extension runtime authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisableExtensionCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Stable extension identity.
    pub extension_id: ExtensionId,
    /// Optimistic-concurrency revision.
    pub expected_revision: u64,
    /// `extension.disabled` journal fact.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Disable time.
    pub disabled_at: SystemTime,
}

/// Terminally revokes all future authority while retaining immutable history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevokeExtensionCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Stable extension identity.
    pub extension_id: ExtensionId,
    /// Optimistic-concurrency revision.
    pub expected_revision: u64,
    /// `extension.revoked` journal fact.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Revocation time.
    pub revoked_at: SystemTime,
}

/// Durable state of one bounded extension invocation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionInvocationStatus {
    /// Dispatch evidence committed before process launch.
    Dispatching,
    /// Valid request-bound response committed.
    Succeeded,
    /// Classified worker or response failure committed.
    Failed,
    /// Daemon recovery found an invocation without terminal evidence.
    Abandoned,
}

/// Owner-authorized immutable invocation projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionInvocationView {
    /// Stable invocation identity.
    pub invocation_id: ExtensionInvocationId,
    /// Authenticated principal that exercised the grant.
    pub principal_id: PrincipalId,
    /// Verified channel binding that conveyed the invocation.
    pub channel_binding_id: mealy_domain::ChannelBindingId,
    /// Extension identity.
    pub extension_id: ExtensionId,
    /// Exact manifest digest.
    pub manifest_digest: String,
    /// Exact grant identity.
    pub grant_id: ExtensionGrantId,
    /// Exact grant digest.
    pub grant_digest: String,
    /// Invoked capability.
    pub capability_id: String,
    /// Canonical input digest.
    pub input_digest: String,
    /// Current durable status.
    pub status: ExtensionInvocationStatus,
    /// Canonical output digest after success.
    pub output_digest: Option<String>,
    /// Exact validated response after success.
    pub response: Option<ExtensionRpcResponse>,
    /// Stable failure class after failure/abandonment.
    pub error_class: Option<String>,
    /// Sanitized failure explanation.
    pub error_message: Option<String>,
    /// Observed worker duration for terminal invocations.
    pub duration_ms: Option<u64>,
    /// UTC dispatch boundary time.
    pub started_at_ms: i64,
    /// UTC terminal boundary time.
    pub completed_at_ms: Option<i64>,
}

/// Commits extension dispatch identity before any code is executed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeginExtensionInvocationCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Stable extension identity.
    pub extension_id: ExtensionId,
    /// Exact currently enabled aggregate revision.
    pub expected_extension_revision: u64,
    /// Stable invocation identity.
    pub invocation_id: ExtensionInvocationId,
    /// Exact manifest digest.
    pub manifest_digest: String,
    /// Exact active grant identity.
    pub grant_id: ExtensionGrantId,
    /// Exact active grant digest.
    pub grant_digest: String,
    /// Exact granted capability.
    pub capability_id: String,
    /// Canonical input digest.
    pub input_digest: String,
    /// `extension.invocation_dispatching` journal fact.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Dispatch time.
    pub started_at: SystemTime,
}

/// Terminal evidence for a previously committed extension dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtensionInvocationTerminal {
    /// Exact validated response.
    Succeeded(ExtensionRpcResponse),
    /// Bounded classified failure.
    Failed {
        /// Stable failure class.
        error_class: String,
        /// Sanitized bounded explanation.
        error_message: String,
    },
    /// Startup recovery found no trustworthy terminal response.
    Abandoned,
}

/// Atomically commits one terminal extension invocation outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteExtensionInvocationCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Stable invocation identity.
    pub invocation_id: ExtensionInvocationId,
    /// Terminal result.
    pub terminal: ExtensionInvocationTerminal,
    /// Observed worker duration in milliseconds, zero for startup abandonment.
    pub duration_ms: u64,
    /// Terminal journal fact.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Terminal time.
    pub completed_at: SystemTime,
}

/// Persistence failure for extension installation, grants, health, and invocation evidence.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ExtensionStoreError {
    /// Extension or invocation is absent or hidden from the supplied owner/channel.
    #[error("extension resource was not found")]
    NotFound,
    /// Optimistic revision, manifest, grant, or lifecycle state conflicted.
    #[error("extension operation conflicts with canonical state")]
    Conflict,
    /// Input violates a manifest, grant, path, schema, or terminal-evidence contract.
    #[error("extension store contract is invalid: {0}")]
    InvalidContract(String),
    /// Persistence is temporarily unavailable.
    #[error("extension store is unavailable: {0}")]
    Unavailable(String),
    /// Stored canonical evidence violates an internal invariant.
    #[error("extension store invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port for extension installation, upgrade/rollback, revocation, and invocation evidence.
pub trait ExtensionStore {
    /// Installs a new inert extension identity with no runtime authority.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionStoreError`] when ownership, package evidence, or persistence fails.
    fn install_extension(
        &mut self,
        commit: InstallExtensionCommit,
    ) -> Result<ExtensionView, ExtensionStoreError>;

    /// Stages an upgrade or rollback and atomically removes the previous active grant.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionStoreError`] when ownership, concurrency, compatibility, or persistence
    /// fails.
    fn stage_extension_manifest(
        &mut self,
        commit: StageExtensionManifestCommit,
    ) -> Result<ExtensionView, ExtensionStoreError>;

    /// Enables an exact staged manifest using a fresh immutable owner grant.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionStoreError`] when grant validation, lifecycle, concurrency, or
    /// persistence fails.
    fn enable_extension(
        &mut self,
        commit: EnableExtensionCommit,
    ) -> Result<ExtensionView, ExtensionStoreError>;

    /// Temporarily disables the current extension and revokes its active grant.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionStoreError`] when ownership, lifecycle, concurrency, or persistence
    /// fails.
    fn disable_extension(
        &mut self,
        commit: DisableExtensionCommit,
    ) -> Result<ExtensionView, ExtensionStoreError>;

    /// Terminally revokes the extension and its active grant.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionStoreError`] when ownership, lifecycle, concurrency, or persistence
    /// fails.
    fn revoke_extension(
        &mut self,
        commit: RevokeExtensionCommit,
    ) -> Result<ExtensionView, ExtensionStoreError>;

    /// Reads one complete owner-authorized extension history.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionStoreError`] when ownership, canonical evidence, or persistence fails.
    fn extension(
        &self,
        ownership: OwnershipContext,
        extension_id: ExtensionId,
    ) -> Result<ExtensionView, ExtensionStoreError>;

    /// Lists all extensions owned by the authenticated principal.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionStoreError`] when ownership, canonical evidence, or persistence fails.
    fn extensions(
        &self,
        ownership: OwnershipContext,
    ) -> Result<Vec<ExtensionView>, ExtensionStoreError>;

    /// Commits exact dispatch evidence before launching extension code.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionStoreError`] when extension/grant authority, concurrency, or persistence
    /// fails.
    fn begin_extension_invocation(
        &mut self,
        commit: BeginExtensionInvocationCommit,
    ) -> Result<ExtensionInvocationView, ExtensionStoreError>;

    /// Commits one terminal request-bound response, failure, or recovery abandonment.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionStoreError`] when ownership, lifecycle, response evidence, or
    /// persistence fails.
    fn complete_extension_invocation(
        &mut self,
        commit: CompleteExtensionInvocationCommit,
    ) -> Result<ExtensionInvocationView, ExtensionStoreError>;

    /// Lists dispatches that lack terminal evidence for startup recovery.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionStoreError`] when canonical evidence or persistence fails.
    fn incomplete_extension_invocations(
        &self,
        limit: usize,
    ) -> Result<Vec<ExtensionInvocationView>, ExtensionStoreError>;
}

/// Startup recovery failure for interrupted extension processes.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ExtensionRecoveryError {
    /// Recovery batch limit must be from one through 1,000.
    #[error("extension recovery batch size must be between 1 and 1000")]
    InvalidBatchSize,
    /// Recovered invocation counter overflowed.
    #[error("extension recovery counter overflowed")]
    CounterOverflow,
    /// Extension persistence rejected recovery evidence.
    #[error(transparent)]
    Store(#[from] ExtensionStoreError),
}

/// Classifies every pre-dispatch-recorded invocation without terminal evidence as abandoned.
///
/// Extension invocations exposed by this proof are read-only, so startup never invents a response
/// or retries code implicitly. A future effectful extension path must recover through the effect
/// ledger's idempotency/reconciliation rules instead.
///
/// # Errors
///
/// Returns [`ExtensionRecoveryError`] for invalid bounds, counter overflow, or persistence failure.
pub fn recover_extension_invocations(
    store: &mut impl ExtensionStore,
    clock: &impl crate::Clock,
    ids: &impl crate::IdGenerator,
    batch_limit: usize,
) -> Result<u64, ExtensionRecoveryError> {
    if !(1..=1_000).contains(&batch_limit) {
        return Err(ExtensionRecoveryError::InvalidBatchSize);
    }
    let now = clock.now();
    let correlation_id = ids.generate_correlation_id();
    let mut recovered = 0_u64;
    loop {
        let incomplete = store.incomplete_extension_invocations(batch_limit)?;
        if incomplete.is_empty() {
            return Ok(recovered);
        }
        for invocation in incomplete {
            store.complete_extension_invocation(CompleteExtensionInvocationCommit {
                ownership: OwnershipContext::new(
                    invocation.principal_id,
                    invocation.channel_binding_id,
                ),
                invocation_id: invocation.invocation_id,
                terminal: ExtensionInvocationTerminal::Abandoned,
                duration_ms: 0,
                event_id: ids.generate_event_id(),
                correlation_id,
                completed_at: now,
            })?;
            recovered = recovered
                .checked_add(1)
                .ok_or(ExtensionRecoveryError::CounterOverflow)?;
        }
    }
}

impl ExtensionRpcResponse {
    /// Validates exact request binding, terminal digest, and declared output schema.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionRpcError`] for a forged identity, malformed digest, or invalid output.
    pub fn validate(
        &self,
        request: &ExtensionRpcRequest,
        manifest: &ExtensionManifest,
    ) -> Result<(), ExtensionRpcError> {
        if self.protocol_version != EXTENSION_RPC_VERSION
            || self.invocation_id != request.invocation_id
            || self.extension_id != request.extension_id
            || self.manifest_digest != request.manifest_digest
            || self.grant_digest != request.grant_digest
            || self.capability_id != request.capability_id
            || !is_sha256_digest(&self.output_digest)
            || canonical_json_digest(&self.output)? != self.output_digest
        {
            return Err(ExtensionRpcError::IdentityMismatch);
        }
        let capability = manifest
            .capability(&self.capability_id)
            .ok_or(ExtensionRpcError::CapabilityDenied)?;
        validate_extension_object(&self.output, &capability.output_schema)
            .map_err(|_| ExtensionRpcError::InvalidOutput)
    }
}

/// Validates a JSON value against the bounded extension object-schema dialect.
///
/// # Errors
///
/// Returns [`ExtensionRpcError::InvalidInput`] when the object, fields, types, bounds, or
/// serialized size diverge from the schema.
pub fn validate_extension_object(
    value: &Value,
    schema: &ExtensionObjectSchema,
) -> Result<(), ExtensionRpcError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ExtensionRpcError::InvalidInput)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > schema.maximum_serialized_bytes {
        return Err(ExtensionRpcError::InvalidInput);
    }
    let object = value.as_object().ok_or(ExtensionRpcError::InvalidInput)?;
    if schema
        .required
        .iter()
        .any(|required| !object.contains_key(required))
        || (!schema.additional_properties
            && object
                .keys()
                .any(|field| !schema.properties.contains_key(field)))
    {
        return Err(ExtensionRpcError::InvalidInput);
    }
    for (name, field) in object {
        let Some(contract) = schema.properties.get(name) else {
            continue;
        };
        let valid = match contract.value_type {
            ExtensionScalarType::String => field.as_str().is_some_and(|value| {
                contract.maximum_length.is_some_and(|maximum| {
                    u64::try_from(value.len()).unwrap_or(u64::MAX) <= maximum
                })
            }),
            ExtensionScalarType::Integer => field.as_i64().is_some_and(|value| {
                contract
                    .minimum_integer
                    .is_none_or(|minimum| value >= minimum)
                    && contract
                        .maximum_integer
                        .is_none_or(|maximum| value <= maximum)
            }),
            ExtensionScalarType::Boolean => field.is_boolean(),
        };
        if !valid {
            return Err(ExtensionRpcError::InvalidInput);
        }
    }
    Ok(())
}

fn canonical_json_digest(value: &Value) -> Result<String, ExtensionRpcError> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_digest(&bytes))
        .map_err(|_| ExtensionRpcError::InvalidInput)
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

/// Invalid or forged extension RPC request/response evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExtensionRpcError {
    /// Protocol, extension, invocation, manifest, grant, capability, or content digest diverged.
    #[error("extension RPC identity does not match the authorized request")]
    IdentityMismatch,
    /// Owner grant does not bind the exact manifest and ownership context.
    #[error("extension RPC grant is invalid")]
    GrantMismatch,
    /// Requested capability is not declared and granted.
    #[error("extension RPC capability is denied")]
    CapabilityDenied,
    /// Input violates its strict declared schema.
    #[error("extension RPC input is invalid")]
    InvalidInput,
    /// Output violates its strict declared schema.
    #[error("extension RPC output is invalid")]
    InvalidOutput,
}

#[cfg(test)]
mod tests {
    use super::{
        EXTENSION_POLICY_VERSION, EXTENSION_RPC_VERSION, ExtensionGrant,
        ExtensionManifestInspectionError, ExtensionMountGrant, ExtensionRpcError,
        ExtensionRpcRequest, ExtensionRpcResponse, extension_grant_digest,
        inspect_extension_manifest,
    };
    use crate::{OwnershipContext, sha256_digest};
    use mealy_domain::{
        ChannelBindingId, EXTENSION_MANIFEST_SCHEMA_VERSION, EffectClass, ExtensionCapabilityKind,
        ExtensionCapabilityManifest, ExtensionCompatibility, ExtensionEntryPoint,
        ExtensionFieldSchema, ExtensionFilesystemAccess, ExtensionFilesystemPermission,
        ExtensionGrantId, ExtensionHealthCheck, ExtensionId, ExtensionInvocationId, ExtensionKind,
        ExtensionManifest, ExtensionObjectSchema, ExtensionPermissions, ExtensionScalarType,
        ExtensionShutdownBehavior, ExtensionShutdownMode, PrincipalId, RiskClass,
    };
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};

    fn schema(field: &str) -> ExtensionObjectSchema {
        ExtensionObjectSchema {
            properties: BTreeMap::from([(
                field.to_owned(),
                ExtensionFieldSchema {
                    value_type: ExtensionScalarType::String,
                    maximum_length: Some(128),
                    minimum_integer: None,
                    maximum_integer: None,
                },
            )]),
            required: BTreeSet::from([field.to_owned()]),
            additional_properties: false,
            maximum_serialized_bytes: 256,
        }
    }

    fn manifest(extension_id: ExtensionId) -> ExtensionManifest {
        ExtensionManifest {
            schema_version: EXTENSION_MANIFEST_SCHEMA_VERSION,
            extension_id,
            name: "dev.mealy.test-extension".to_owned(),
            publisher: "dev.mealy".to_owned(),
            version: "1.0.0".to_owned(),
            kinds: BTreeSet::from([ExtensionKind::ToolService]),
            compatibility: ExtensionCompatibility {
                minimum_host_api: 1,
                maximum_host_api: 1,
            },
            entry_point: ExtensionEntryPoint {
                executable: "extension-worker".to_owned(),
                executable_digest: "a".repeat(64),
                runtime_files: Vec::new(),
            },
            capabilities: vec![
                ExtensionCapabilityManifest {
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
                    output_schema: schema("status"),
                    timeout_ms: 1_000,
                    maximum_output_bytes: 1_024,
                },
                ExtensionCapabilityManifest {
                    capability_id: "text_stats".to_owned(),
                    kind: ExtensionCapabilityKind::Tool,
                    effect_class: EffectClass::ReadOnly,
                    risk_class: RiskClass::Low,
                    input_schema: schema("text"),
                    output_schema: schema("digest"),
                    timeout_ms: 1_000,
                    maximum_output_bytes: 1_024,
                },
            ],
            permissions: ExtensionPermissions {
                filesystem: vec![ExtensionFilesystemPermission {
                    name: "documents".to_owned(),
                    access: ExtensionFilesystemAccess::ReadWrite,
                }],
                ..ExtensionPermissions::default()
            },
            health_check: ExtensionHealthCheck {
                capability_id: "health".to_owned(),
                timeout_ms: 500,
                interval_ms: 1_000,
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
    fn manifest_digest_pin_and_compatibility_are_checked_without_code_execution() {
        let manifest = manifest(ExtensionId::new());
        let bytes = serde_json::to_vec(&manifest).expect("manifest JSON");
        let digest = sha256_digest(&bytes);
        let inspected = inspect_extension_manifest(&bytes, &digest).expect("inspect manifest");
        assert_eq!(inspected.manifest, manifest);
        assert_eq!(inspected.manifest_json.as_bytes(), bytes);
        assert_eq!(
            inspect_extension_manifest(&bytes, &"f".repeat(64)),
            Err(ExtensionManifestInspectionError::DigestMismatch)
        );
    }

    #[test]
    fn grants_and_rpc_bind_every_identity_and_schema_axis() {
        let extension_id = ExtensionId::new();
        let manifest = manifest(extension_id);
        let principal_id = PrincipalId::new();
        let ownership = OwnershipContext::new(principal_id, ChannelBindingId::new());
        let grant = ExtensionGrant {
            grant_id: ExtensionGrantId::new(),
            extension_id,
            manifest_digest: "b".repeat(64),
            capability_ids: BTreeSet::from(["text_stats".to_owned()]),
            mounts: vec![ExtensionMountGrant {
                name: "documents".to_owned(),
                access: ExtensionFilesystemAccess::ReadOnly,
                host_path: "/tmp/mealy-extension-documents".to_owned(),
                sandbox_path: "/grants/documents".to_owned(),
            }],
            network_destinations: BTreeSet::new(),
            secret_references: BTreeSet::new(),
            allow_process_spawn: false,
            policy_version: EXTENSION_POLICY_VERSION.to_owned(),
            issued_by_principal_id: principal_id,
            issued_at_ms: 1,
        };
        grant.validate(&manifest, ownership).expect("grant");
        let grant_digest = extension_grant_digest(&grant).expect("grant digest");
        let input = json!({"text": "bounded input"});
        let request = ExtensionRpcRequest {
            protocol_version: EXTENSION_RPC_VERSION.to_owned(),
            invocation_id: ExtensionInvocationId::new(),
            extension_id,
            manifest_digest: grant.manifest_digest.clone(),
            grant_digest: grant_digest.clone(),
            capability_id: "text_stats".to_owned(),
            input_digest: sha256_digest(&serde_json::to_vec(&input).expect("input JSON")),
            input,
        };
        request
            .validate(&manifest, &grant.manifest_digest, &grant, ownership)
            .expect("request");
        let output = json!({"digest": "result"});
        let response = ExtensionRpcResponse {
            protocol_version: EXTENSION_RPC_VERSION.to_owned(),
            invocation_id: request.invocation_id,
            extension_id,
            manifest_digest: request.manifest_digest.clone(),
            grant_digest,
            capability_id: request.capability_id.clone(),
            output_digest: sha256_digest(&serde_json::to_vec(&output).expect("output JSON")),
            output,
        };
        response.validate(&request, &manifest).expect("response");

        let mut forged = response;
        forged.capability_id = "health".to_owned();
        assert_eq!(
            forged.validate(&request, &manifest),
            Err(ExtensionRpcError::IdentityMismatch)
        );
    }
}
