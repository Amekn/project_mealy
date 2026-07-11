use mealy_application::{
    FixtureWritePolicyGrant, SandboxExecutor, ToolDescriptor, fixture_write_file_descriptor,
    sha256_digest,
};
use mealy_domain::{ChannelBindingId, PolicyProfile, PrincipalId, RunId, TaskId};
use mealy_infrastructure::{LinuxBubblewrapConfig, LinuxBubblewrapExecutor, SandboxRuntimeBinding};
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

const BUBBLEWRAP_PATH: &str = "/usr/bin/bwrap";

/// Available, host-probed Phase 3 fixture-write process boundary.
pub struct PhaseThreeRuntime {
    executor: Arc<LinuxBubblewrapExecutor>,
    descriptor: ToolDescriptor,
    worker_identity_digest: String,
    workspace_root: String,
    outcome_commit_delay: std::time::Duration,
    dispatch_commit_delay: std::time::Duration,
    observation_commit_delay: std::time::Duration,
    approval_ttl: std::time::Duration,
}

impl PhaseThreeRuntime {
    /// Uses the current daemon executable as the embedded worker, constructs its exact runtime mounts, and probes
    /// Bubblewrap before advertising any mutating capability.
    ///
    /// # Errors
    ///
    /// Returns an error when the worker, workspace, dynamic runtime, or sandbox backend cannot be
    /// represented exactly. Callers must then omit the write tool and fail closed.
    pub fn discover(
        home: &Path,
        outcome_commit_delay: std::time::Duration,
        dispatch_commit_delay: std::time::Duration,
        observation_commit_delay: std::time::Duration,
        approval_ttl: std::time::Duration,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let workspace = home.join("fixture-workspace");
        fs::create_dir_all(&workspace)?;
        let workspace = fs::canonicalize(workspace)?;
        let worker = embedded_worker_path()?;
        let worker_identity_digest = sha256_digest(&fs::read(&worker)?);
        let bubblewrap = fs::canonicalize(BUBBLEWRAP_PATH)?;
        let executor = LinuxBubblewrapExecutor::new(LinuxBubblewrapConfig::new(
            bubblewrap,
            worker.clone(),
            worker_identity_digest.clone(),
            runtime_bindings(&worker)?,
        ))?;
        let workspace_root = workspace
            .to_str()
            .ok_or("fixture workspace path is not UTF-8")?
            .to_owned();
        let descriptor = fixture_write_file_descriptor(&worker_identity_digest)?;
        Ok(Self {
            executor: Arc::new(executor),
            descriptor,
            worker_identity_digest,
            workspace_root,
            outcome_commit_delay,
            dispatch_commit_delay,
            observation_commit_delay,
            approval_ttl,
        })
    }

    /// Exact generic descriptor advertised to the deterministic provider.
    #[must_use]
    pub fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    /// Exact canonical host workspace authorized by the fixture proof.
    #[must_use]
    pub fn workspace_root(&self) -> &str {
        &self.workspace_root
    }

    /// Reconstructs the deterministic grant whose complete material is retained by the effect.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn grant(
        &self,
        principal_id: PrincipalId,
        channel_binding_id: ChannelBindingId,
        task_id: TaskId,
        run_id: RunId,
        valid_from_ms: i64,
        expires_at_ms: i64,
    ) -> FixtureWritePolicyGrant {
        FixtureWritePolicyGrant {
            principal_id,
            channel_binding_id,
            task_id,
            run_id,
            tool_descriptor_digest: self.descriptor.descriptor_digest.clone(),
            worker_identity_digest: self.worker_identity_digest.clone(),
            workspace_root: self.workspace_root.clone(),
            capability: mealy_application::FIXTURE_WRITE_CAPABILITY.to_owned(),
            profile: PolicyProfile::WorkspaceWrite,
            valid_from_ms,
            expires_at_ms,
        }
    }

    /// Executes through the already-probed out-of-process sandbox adapter.
    #[must_use]
    pub fn executor(&self) -> Arc<dyn SandboxExecutor> {
        self.executor.clone()
    }

    /// Test-only delay between external completion and its durable outcome boundary.
    #[must_use]
    pub fn outcome_commit_delay(&self) -> std::time::Duration {
        self.outcome_commit_delay
    }

    /// Test-only delay between durable preparation and the external dispatch boundary.
    #[must_use]
    pub fn dispatch_commit_delay(&self) -> std::time::Duration {
        self.dispatch_commit_delay
    }

    /// Test-only delay between terminal effect evidence and its model-facing observation.
    #[must_use]
    pub fn observation_commit_delay(&self) -> std::time::Duration {
        self.observation_commit_delay
    }

    /// Lifetime assigned to each deterministic fixture-write approval request.
    #[must_use]
    pub fn approval_ttl(&self) -> std::time::Duration {
        self.approval_ttl
    }
}

fn embedded_worker_path() -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
    Ok(fs::canonicalize(std::env::current_exe()?)?)
}

fn runtime_bindings(
    worker: &Path,
) -> Result<Vec<SandboxRuntimeBinding>, Box<dyn Error + Send + Sync>> {
    let output = Command::new("ldd").arg(worker).output()?;
    if !output.status.success() {
        return Err("ldd could not inspect the fixture worker".into());
    }
    let output = String::from_utf8(output.stdout)?;
    let mut bindings = BTreeMap::new();
    for line in output.lines() {
        let candidate = line.split_once("=>").map_or_else(
            || line.split_whitespace().next(),
            |(_, right)| right.split_whitespace().next(),
        );
        let Some(candidate) = candidate.filter(|value| value.starts_with('/')) else {
            continue;
        };
        let sandbox_path = PathBuf::from(candidate);
        bindings.insert(
            sandbox_path.clone(),
            SandboxRuntimeBinding {
                host_path: sandbox_path.clone(),
                sandbox_path,
            },
        );
    }
    if bindings.is_empty() {
        return Err("fixture worker has no discoverable dynamic runtime files".into());
    }
    Ok(bindings.into_values().collect())
}
