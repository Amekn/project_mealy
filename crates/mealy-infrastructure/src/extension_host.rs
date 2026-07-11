use crate::{LinuxBubblewrapConfig, LinuxBubblewrapExecutor, SandboxRuntimeBinding};
use mealy_application::{
    CancellationProbe, EXECUTOR_PROTOCOL_VERSION, ExecutorError, ExecutorMount, ExecutorRequest,
    ExecutorTerminal, ExtensionDispatchRequest, ExtensionHost, ExtensionHostError,
    ExtensionManifestInspection, ExtensionRpcResponse, SandboxExecutor, sha256_digest,
};
use mealy_domain::{
    AttemptId, EffectClass, EffectId, ExtensionFilesystemAccess, FencingToken, PolicyProfile,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

const MAXIMUM_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const EXTENSION_MAXIMUM_MEMORY_BYTES: u64 = 256 * 1024 * 1024;

/// Data-only, digest-verified extension package descriptor safe to retain before code execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledExtensionPackage {
    inspection: ExtensionManifestInspection,
    installation_root: PathBuf,
    executable_path: PathBuf,
    runtime_bindings: Vec<SandboxRuntimeBinding>,
    runtime_digests: Vec<(PathBuf, String)>,
}

impl InstalledExtensionPackage {
    /// Returns the validated inert manifest and exact byte digest.
    #[must_use]
    pub const fn inspection(&self) -> &ExtensionManifestInspection {
        &self.inspection
    }

    /// Returns the canonical package root for internal host construction.
    #[must_use]
    pub fn installation_root(&self) -> &Path {
        &self.installation_root
    }

    /// Returns the canonical digest-pinned extension executable.
    #[must_use]
    pub fn executable_path(&self) -> &Path {
        &self.executable_path
    }
}

/// Validates package paths and every executable/runtime digest without launching extension code.
///
/// Runtime files are limited to the package root or conventional system library directories. This
/// prevents a manifest from laundering an arbitrary sensitive host file into its runtime mount set.
///
/// # Errors
///
/// Returns [`ExtensionHostError`] when the installation root, executable, runtime path, or any
/// digest is invalid.
pub fn inspect_extension_package(
    inspection: ExtensionManifestInspection,
    installation_root: impl AsRef<Path>,
) -> Result<InstalledExtensionPackage, ExtensionHostError> {
    let requested_root = installation_root.as_ref();
    let installation_root = canonical_directory(requested_root)?;
    if installation_root != requested_root {
        return Err(unsupported(
            "extension installation root must be exact and canonical",
        ));
    }
    let requested_executable = installation_root.join(&inspection.manifest.entry_point.executable);
    let executable_path = canonical_regular_file(&requested_executable)?;
    if executable_path != requested_executable || !executable_path.starts_with(&installation_root) {
        return Err(unsupported(
            "extension executable must be a non-symlink file beneath its installation root",
        ));
    }
    if digest_file(&executable_path)? != inspection.manifest.entry_point.executable_digest {
        return Err(ExtensionHostError::IdentityMismatch);
    }

    let mut runtime_bindings = Vec::new();
    let mut runtime_digests = Vec::new();
    for runtime in &inspection.manifest.entry_point.runtime_files {
        let requested = Path::new(&runtime.host_path);
        let canonical = canonical_regular_file(requested)?;
        if !runtime_source_allowed(&canonical, &installation_root)
            || digest_file(&canonical)? != runtime.digest
        {
            return Err(ExtensionHostError::IdentityMismatch);
        }
        runtime_bindings.push(SandboxRuntimeBinding {
            host_path: canonical.clone(),
            sandbox_path: PathBuf::from(&runtime.sandbox_path),
        });
        runtime_digests.push((canonical, runtime.digest.clone()));
    }
    Ok(InstalledExtensionPackage {
        inspection,
        installation_root,
        executable_path,
        runtime_bindings,
        runtime_digests,
    })
}

/// Linux Bubblewrap extension host using the existing request-bound executor framing as its outer
/// containment transport and [`mealy_application::EXTENSION_RPC_VERSION`] as the nested adapter
/// contract.
pub struct LinuxBubblewrapExtensionHost {
    executor: LinuxBubblewrapExecutor,
    package: InstalledExtensionPackage,
}

impl LinuxBubblewrapExtensionHost {
    /// Constructs and probes the supervised process boundary for a previously inert package.
    ///
    /// This is the first operation allowed to execute extension code. The probe itself runs inside
    /// the same empty-environment, no-network, least-mount Bubblewrap boundary as real calls.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionHostError`] when the host cannot enforce the boundary or executable
    /// identity changed after package inspection.
    pub fn new(
        bubblewrap_path: impl Into<PathBuf>,
        package: InstalledExtensionPackage,
    ) -> Result<Self, ExtensionHostError> {
        verify_package_identity(&package)?;
        let executor = LinuxBubblewrapExecutor::new(LinuxBubblewrapConfig::new(
            bubblewrap_path,
            package.executable_path.clone(),
            package
                .inspection
                .manifest
                .entry_point
                .executable_digest
                .clone(),
            package.runtime_bindings.clone(),
        ))
        .map_err(map_executor_error)?;
        Ok(Self { executor, package })
    }
}

impl ExtensionHost for LinuxBubblewrapExtensionHost {
    fn invoke(
        &self,
        request: &ExtensionDispatchRequest,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ExtensionRpcResponse, ExtensionHostError> {
        request.validate()?;
        verify_package_identity(&self.package)?;
        if request.manifest != self.package.inspection.manifest
            || request.manifest_digest != self.package.inspection.manifest_digest
        {
            return Err(ExtensionHostError::IdentityMismatch);
        }
        let capability = request
            .manifest
            .capability(&request.rpc_request.capability_id)
            .ok_or(ExtensionHostError::InvalidDispatch)?;
        if capability.effect_class != EffectClass::ReadOnly
            || request.grant.allow_process_spawn
            || !request.grant.network_destinations.is_empty()
            || !request.grant.secret_references.is_empty()
            || request
                .grant
                .mounts
                .iter()
                .any(|mount| mount.access != ExtensionFilesystemAccess::ReadOnly)
        {
            return Err(unsupported(
                "direct extension invocation supports read-only capabilities without network, secrets, writable roots, or child processes",
            ));
        }
        let normalized_arguments = json!({
            "operation": "extension_rpc",
            "request": request.rpc_request,
        });
        let arguments_json = serde_json::to_string(&normalized_arguments)
            .map_err(|_| ExtensionHostError::InvalidDispatch)?;
        let mut readable_roots = request
            .grant
            .mounts
            .iter()
            .map(|mount| ExecutorMount {
                host_path: mount.host_path.clone(),
                sandbox_path: mount.sandbox_path.clone(),
            })
            .collect::<Vec<_>>();
        readable_roots.sort();
        let invocation_uuid = request.rpc_request.invocation_id.as_uuid();
        let outer_request = ExecutorRequest {
            protocol_version: EXECUTOR_PROTOCOL_VERSION.to_owned(),
            effect_id: EffectId::from_uuid(invocation_uuid),
            attempt_id: AttemptId::from_uuid(invocation_uuid),
            fencing_token: FencingToken::new(1).ok_or(ExtensionHostError::InvalidDispatch)?,
            capability_token: request.capability_token.clone(),
            executable_identity_digest: request.manifest.entry_point.executable_digest.clone(),
            profile: PolicyProfile::Observe,
            readable_roots,
            writable_roots: Vec::new(),
            network_destinations: Vec::new(),
            secret_handles: Vec::new(),
            allow_process_spawn: false,
            allowed_environment_variables: Vec::new(),
            idempotency_key: None,
            normalized_arguments,
            arguments_digest: sha256_digest(arguments_json.as_bytes()),
            maximum_duration_ms: capability.timeout_ms,
            maximum_output_bytes: capability.maximum_output_bytes,
            maximum_memory_bytes: EXTENSION_MAXIMUM_MEMORY_BYTES,
            maximum_processes: 0,
        };
        let result = self
            .executor
            .execute(&outer_request, cancellation)
            .map_err(map_executor_error)?;
        let response = match result.terminal {
            ExecutorTerminal::Succeeded { output, .. } => {
                serde_json::from_value::<ExtensionRpcResponse>(output)
                    .map_err(|_| ExtensionHostError::InvalidResponse)?
            }
            ExecutorTerminal::Failed {
                error_class,
                error_message,
                retryable,
            } => {
                return Err(ExtensionHostError::WorkerFailure {
                    error_class,
                    error_message,
                    retryable,
                });
            }
        };
        response
            .validate(&request.rpc_request, &request.manifest)
            .map_err(|_| ExtensionHostError::InvalidResponse)?;
        Ok(response)
    }
}

fn verify_package_identity(package: &InstalledExtensionPackage) -> Result<(), ExtensionHostError> {
    if digest_file(&package.executable_path)?
        != package.inspection.manifest.entry_point.executable_digest
        || package
            .runtime_digests
            .iter()
            .any(|(path, digest)| digest_file(path).as_ref() != Ok(digest))
    {
        return Err(ExtensionHostError::IdentityMismatch);
    }
    Ok(())
}

fn runtime_source_allowed(path: &Path, installation_root: &Path) -> bool {
    path.starts_with(installation_root)
        || ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]
            .iter()
            .any(|root| path.starts_with(root))
}

fn canonical_directory(path: &Path) -> Result<PathBuf, ExtensionHostError> {
    if !path.is_absolute() {
        return Err(unsupported("extension installation root is not absolute"));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| unsupported(format!("cannot inspect extension root: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(unsupported(
            "extension installation root is not a non-symlink directory",
        ));
    }
    fs::canonicalize(path)
        .map_err(|error| unsupported(format!("cannot canonicalize extension root: {error}")))
}

fn canonical_regular_file(path: &Path) -> Result<PathBuf, ExtensionHostError> {
    if !path.is_absolute() {
        return Err(unsupported("extension runtime file is not absolute"));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| unsupported(format!("cannot canonicalize extension file: {error}")))?;
    if !fs::metadata(&canonical)
        .map_err(|error| unsupported(format!("cannot inspect extension file: {error}")))?
        .is_file()
    {
        return Err(unsupported("extension runtime path is not a regular file"));
    }
    Ok(canonical)
}

fn digest_file(path: &Path) -> Result<String, ExtensionHostError> {
    let mut file = File::open(path)
        .map_err(|error| unsupported(format!("cannot open extension file: {error}")))?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 16 * 1_024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| unsupported(format!("cannot hash extension file: {error}")))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or_else(|| unsupported("extension file size overflowed"))?;
        if total > MAXIMUM_EXECUTABLE_BYTES {
            return Err(unsupported("extension file exceeds its byte bound"));
        }
        digest.update(&buffer[..read]);
    }
    let bytes = digest.finalize();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_| unsupported("extension digest could not be encoded"))?;
    }
    Ok(encoded)
}

fn map_executor_error(error: ExecutorError) -> ExtensionHostError {
    match error {
        ExecutorError::UnsupportedHost(message) | ExecutorError::Io(message) => {
            ExtensionHostError::UnsupportedHost(message)
        }
        ExecutorError::UnsupportedProfile(_) | ExecutorError::InvalidRequest(_) => {
            ExtensionHostError::InvalidDispatch
        }
        ExecutorError::ExecutableIdentityMismatch => ExtensionHostError::IdentityMismatch,
        ExecutorError::OutputLimitExceeded => ExtensionHostError::OutputLimitExceeded,
        ExecutorError::TimedOut => ExtensionHostError::TimedOut,
        ExecutorError::Cancelled => ExtensionHostError::Cancelled,
        ExecutorError::CapabilityAlreadyUsed
        | ExecutorError::MalformedFrame
        | ExecutorError::Protocol(_)
        | ExecutorError::WorkerCrashed(_) => ExtensionHostError::ProcessFailure(error.to_string()),
    }
}

fn unsupported(message: impl Into<String>) -> ExtensionHostError {
    ExtensionHostError::UnsupportedHost(message.into())
}
