use mealy_application::{
    ApprovalRequestView, ApprovalSubject, ExecutorRequest, FixtureWriteDispatch,
    FixtureWritePolicyGrant, PolicyEvaluation, PolicyRequest, ProcessRunDispatch,
    ProcessRunPolicyGrant, SandboxExecutor, ToolDescriptor, WorkspaceCreateDispatch,
    WorkspaceCreatePolicyGrant, WorkspaceManageDispatch, WorkspaceManagePolicyGrant,
    WorkspaceReplaceDispatch, WorkspaceReplacePolicyGrant, build_fixture_write_executor_request,
    build_process_run_executor_request, build_workspace_create_executor_request,
    build_workspace_manage_executor_request, build_workspace_replace_executor_request,
    evaluate_fixture_write_policy, evaluate_process_run_policy, evaluate_workspace_create_policy,
    evaluate_workspace_manage_policy, evaluate_workspace_replace_policy,
    fixture_write_approval_subject, fixture_write_file_descriptor,
    normalize_fixture_write_file_arguments, normalize_process_run_arguments,
    normalize_workspace_create_file_arguments, normalize_workspace_manage_path_arguments,
    normalize_workspace_replace_file_arguments, process_run_approval_subject,
    process_run_descriptor, sha256_digest, workspace_create_approval_subject,
    workspace_create_file_descriptor, workspace_manage_approval_subject,
    workspace_manage_path_descriptor, workspace_replace_approval_subject,
    workspace_replace_file_descriptor,
};
use mealy_domain::{
    AttemptId, ChannelBindingId, EffectId, FencingToken, PolicyProfile, PrincipalId, RunId, TaskId,
};
use mealy_infrastructure::{
    LinuxBubblewrapConfig, LinuxBubblewrapExecutor, SandboxRuntimeBinding,
    is_trusted_system_executable,
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

const BUBBLEWRAP_PATH: &str = "/usr/bin/bwrap";
const DYNAMIC_LINKER_INSPECTOR_PATH: &str = "/usr/bin/ldd";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteRuntimeKind {
    Fixture,
    WorkspaceCreate,
}

/// Complete policy scope derived from one already-normalized write request.
pub struct WritePolicyScope {
    pub workspace_id: Option<String>,
    pub workspace_root: String,
    pub target_resources: Vec<String>,
    pub resource_claims: Vec<String>,
    pub command_id: Option<String>,
    pub command_identity_digest: Option<String>,
    pub requested_capability: &'static str,
    pub policy_version: &'static str,
}

/// Exact runtime grant reconstructed from durable request and configured authority.
pub enum RuntimeWriteGrant {
    Fixture(FixtureWritePolicyGrant),
    WorkspaceCreate(WorkspaceCreatePolicyGrant),
    WorkspaceManage(WorkspaceManagePolicyGrant),
    WorkspaceReplace(WorkspaceReplacePolicyGrant),
    ProcessRun(ProcessRunPolicyGrant),
}

/// One canonical executable and digest approved by stopped-daemon configuration.
pub struct ProcessCommandBinding {
    pub command_id: String,
    pub executable: PathBuf,
    pub executable_digest: String,
}

struct RuntimeCommand {
    executable: PathBuf,
    executable_digest: String,
}

/// Available, host-probed approval-gated workspace-write process boundary.
pub struct PhaseThreeRuntime {
    executor: Arc<LinuxBubblewrapExecutor>,
    descriptors: BTreeMap<String, ToolDescriptor>,
    worker_identity_digest: String,
    workspace_roots: BTreeMap<String, String>,
    commands: BTreeMap<String, RuntimeCommand>,
    kind: WriteRuntimeKind,
    outcome_commit_delay: std::time::Duration,
    dispatch_commit_delay: std::time::Duration,
    observation_commit_delay: std::time::Duration,
    approval_ttl: std::time::Duration,
}

impl PhaseThreeRuntime {
    /// Constructs the deterministic fixture proof runtime.
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
            runtime_bindings(&worker, &BTreeMap::new())?,
        ))?;
        let workspace_root = workspace
            .to_str()
            .ok_or("fixture workspace path is not UTF-8")?
            .to_owned();
        let descriptor = fixture_write_file_descriptor(&worker_identity_digest)?;
        Ok(Self {
            executor: Arc::new(executor),
            descriptors: BTreeMap::from([(descriptor.tool_id.clone(), descriptor)]),
            worker_identity_digest,
            workspace_roots: BTreeMap::from([("fixture".to_owned(), workspace_root)]),
            commands: BTreeMap::new(),
            kind: WriteRuntimeKind::Fixture,
            outcome_commit_delay,
            dispatch_commit_delay,
            observation_commit_delay,
            approval_ttl,
        })
    }

    /// Constructs a production create-new-file runtime over exact pre-approved workspace roots.
    ///
    /// # Errors
    ///
    /// Returns an error when a root, worker, runtime dependency, or Bubblewrap boundary cannot be
    /// represented exactly. The caller must then omit all mutating tools.
    pub fn discover_workspace(
        workspaces: impl IntoIterator<Item = (String, PathBuf)>,
        commands: impl IntoIterator<Item = ProcessCommandBinding>,
        outcome_commit_delay: std::time::Duration,
        dispatch_commit_delay: std::time::Duration,
        observation_commit_delay: std::time::Duration,
        approval_ttl: std::time::Duration,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let mut workspace_roots = BTreeMap::new();
        for (workspace_id, root) in workspaces {
            let root = fs::canonicalize(root)?;
            let metadata = fs::symlink_metadata(&root)?;
            let root_text = root
                .to_str()
                .ok_or("writable workspace path is not UTF-8")?
                .to_owned();
            if workspace_id.is_empty()
                || workspace_id.len() > 128
                || workspace_id.starts_with('.')
                || workspace_id.bytes().any(|byte| {
                    !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b'-')
                })
                || !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || workspace_roots.insert(workspace_id, root_text).is_some()
            {
                return Err("writable workspace grant is invalid".into());
            }
        }
        if workspace_roots.is_empty() {
            return Err("no writable workspace roots were configured".into());
        }
        let commands = validate_runtime_commands(commands)?;
        let worker = embedded_worker_path()?;
        let worker_identity_digest = sha256_digest(&fs::read(&worker)?);
        let bubblewrap = fs::canonicalize(BUBBLEWRAP_PATH)?;
        let runtime_bindings = runtime_bindings(&worker, &commands)?;
        let executor = LinuxBubblewrapExecutor::new(LinuxBubblewrapConfig::new(
            bubblewrap,
            worker.clone(),
            worker_identity_digest.clone(),
            runtime_bindings,
        ))?;
        let create_descriptor = workspace_create_file_descriptor(&worker_identity_digest)?;
        let mut descriptors =
            BTreeMap::from([(create_descriptor.tool_id.clone(), create_descriptor)]);
        let replace_descriptor = workspace_replace_file_descriptor(&worker_identity_digest)?;
        descriptors.insert(replace_descriptor.tool_id.clone(), replace_descriptor);
        let manage_descriptor = workspace_manage_path_descriptor(&worker_identity_digest)?;
        descriptors.insert(manage_descriptor.tool_id.clone(), manage_descriptor);
        if !commands.is_empty() {
            let process_descriptor = process_run_descriptor(&worker_identity_digest)?;
            descriptors.insert(process_descriptor.tool_id.clone(), process_descriptor);
        }
        Ok(Self {
            executor: Arc::new(executor),
            descriptors,
            worker_identity_digest,
            workspace_roots,
            commands,
            kind: WriteRuntimeKind::WorkspaceCreate,
            outcome_commit_delay,
            dispatch_commit_delay,
            observation_commit_delay,
            approval_ttl,
        })
    }

    /// Exact configured effect descriptor by stable tool identity.
    #[must_use]
    pub fn descriptor_for(&self, tool_id: &str) -> Option<&ToolDescriptor> {
        self.descriptors.get(tool_id)
    }

    /// All configured effect descriptors in stable tool-identity order.
    #[must_use]
    pub fn descriptors(&self) -> Vec<&ToolDescriptor> {
        self.descriptors.values().collect()
    }

    /// Configured logical command identities in stable order.
    #[must_use]
    pub fn command_ids(&self) -> Vec<String> {
        self.commands.keys().cloned().collect()
    }

    /// Configured executable digest for one logical command identity.
    #[must_use]
    pub fn command_identity_digest(&self, command_id: &str) -> Option<&str> {
        self.commands
            .get(command_id)
            .map(|command| command.executable_digest.as_str())
    }

    /// First canonical host root, used only in bounded operator diagnostics.
    #[must_use]
    pub fn workspace_root(&self) -> &str {
        self.workspace_roots
            .values()
            .next()
            .map(String::as_str)
            .expect("runtime construction requires one workspace root")
    }

    /// Logical workspace identities available to this runtime.
    #[must_use]
    pub fn workspace_ids(&self) -> Vec<String> {
        self.workspace_roots.keys().cloned().collect()
    }

    /// Whether this is the deterministic fixture-only contract.
    #[must_use]
    pub const fn is_fixture(&self) -> bool {
        matches!(self.kind, WriteRuntimeKind::Fixture)
    }

    /// Strictly normalizes arguments for the active contract.
    pub fn normalize_arguments(
        &self,
        tool_id: &str,
        arguments: &Value,
    ) -> Result<Value, Box<dyn Error + Send + Sync>> {
        if self.descriptor_for(tool_id).is_none() {
            return Err("effect tool is not configured".into());
        }
        match tool_id {
            mealy_application::FIXTURE_WRITE_FILE_TOOL_ID if self.is_fixture() => {
                Ok(normalize_fixture_write_file_arguments(arguments)?)
            }
            mealy_application::WORKSPACE_CREATE_FILE_TOOL_ID if !self.is_fixture() => {
                Ok(normalize_workspace_create_file_arguments(arguments)?)
            }
            mealy_application::WORKSPACE_REPLACE_FILE_TOOL_ID if !self.is_fixture() => {
                Ok(normalize_workspace_replace_file_arguments(arguments)?)
            }
            mealy_application::WORKSPACE_MANAGE_PATH_TOOL_ID if !self.is_fixture() => {
                Ok(normalize_workspace_manage_path_arguments(arguments)?)
            }
            mealy_application::PROCESS_RUN_TOOL_ID if !self.is_fixture() => {
                Ok(normalize_process_run_arguments(arguments)?)
            }
            _ => Err("effect tool does not match the runtime profile".into()),
        }
    }

    /// Resolves normalized logical arguments to the exact configured host and approval scope.
    pub fn policy_scope(
        &self,
        tool_id: &str,
        normalized_arguments: &Value,
    ) -> Result<WritePolicyScope, Box<dyn Error + Send + Sync>> {
        match tool_id {
            mealy_application::FIXTURE_WRITE_FILE_TOOL_ID if self.is_fixture() => {
                let relative_path = normalized_arguments
                    .get("relativePath")
                    .and_then(Value::as_str)
                    .ok_or("normalized write path is absent")?;
                let workspace_root = self.workspace_root().to_owned();
                let target = format!("{workspace_root}/{relative_path}");
                Ok(WritePolicyScope {
                    workspace_id: None,
                    workspace_root,
                    resource_claims: vec![format!("workspace-write:{target}")],
                    target_resources: vec![target],
                    command_id: None,
                    command_identity_digest: None,
                    requested_capability: mealy_application::FIXTURE_WRITE_CAPABILITY,
                    policy_version: mealy_application::FIXTURE_POLICY_VERSION,
                })
            }
            mealy_application::WORKSPACE_CREATE_FILE_TOOL_ID if !self.is_fixture() => self
                .workspace_mutation_policy_scope(
                    normalized_arguments,
                    "workspace-create",
                    mealy_application::WORKSPACE_CREATE_CAPABILITY,
                    mealy_application::WORKSPACE_CREATE_POLICY_VERSION,
                ),
            mealy_application::WORKSPACE_REPLACE_FILE_TOOL_ID if !self.is_fixture() => self
                .workspace_mutation_policy_scope(
                    normalized_arguments,
                    "workspace-replace",
                    mealy_application::WORKSPACE_REPLACE_CAPABILITY,
                    mealy_application::WORKSPACE_REPLACE_POLICY_VERSION,
                ),
            mealy_application::WORKSPACE_MANAGE_PATH_TOOL_ID if !self.is_fixture() => {
                self.workspace_manage_policy_scope(normalized_arguments)
            }
            mealy_application::PROCESS_RUN_TOOL_ID if !self.is_fixture() => {
                let command_id = normalized_arguments
                    .get("commandId")
                    .and_then(Value::as_str)
                    .ok_or("normalized command identity is absent")?;
                let command = self
                    .commands
                    .get(command_id)
                    .ok_or("requested command is not configured")?;
                if sha256_digest(&fs::read(&command.executable)?) != command.executable_digest {
                    return Err("configured command executable identity changed".into());
                }
                let workspace_id = normalized_arguments
                    .get("workspaceId")
                    .and_then(Value::as_str)
                    .ok_or("normalized workspace identity is absent")?;
                let workspace_root = self
                    .workspace_roots
                    .get(workspace_id)
                    .ok_or("requested workspace is not writable")?
                    .clone();
                let working_directory = normalized_arguments
                    .get("workingDirectory")
                    .and_then(Value::as_str)
                    .ok_or("normalized working directory is absent")?;
                let command_target = format!(
                    "command://{command_id}@sha256:{}",
                    command.executable_digest
                );
                let workspace_target = if working_directory.is_empty() {
                    format!("workspace://{workspace_id}/")
                } else {
                    format!("workspace://{workspace_id}/{working_directory}")
                };
                let mut target_resources = vec![command_target, workspace_target.clone()];
                target_resources.sort();
                let mut resource_claims = vec![
                    format!("process-executable:sha256:{}", command.executable_digest),
                    format!("workspace-process:{workspace_target}"),
                ];
                resource_claims.sort();
                Ok(WritePolicyScope {
                    workspace_id: Some(workspace_id.to_owned()),
                    workspace_root,
                    target_resources,
                    resource_claims,
                    command_id: Some(command_id.to_owned()),
                    command_identity_digest: Some(command.executable_digest.clone()),
                    requested_capability: mealy_application::PROCESS_RUN_CAPABILITY,
                    policy_version: mealy_application::PROCESS_RUN_POLICY_VERSION,
                })
            }
            _ => Err("effect tool does not match configured runtime authority".into()),
        }
    }

    fn workspace_mutation_policy_scope(
        &self,
        normalized_arguments: &Value,
        claim_prefix: &str,
        requested_capability: &'static str,
        policy_version: &'static str,
    ) -> Result<WritePolicyScope, Box<dyn Error + Send + Sync>> {
        let relative_path = normalized_arguments
            .get("relativePath")
            .and_then(Value::as_str)
            .ok_or("normalized workspace-mutation path is absent")?;
        let workspace_id = normalized_arguments
            .get("workspaceId")
            .and_then(Value::as_str)
            .ok_or("normalized workspace identity is absent")?;
        let workspace_root = self
            .workspace_roots
            .get(workspace_id)
            .ok_or("requested workspace is not writable")?
            .clone();
        let target = format!("workspace://{workspace_id}/{relative_path}");
        Ok(WritePolicyScope {
            workspace_id: Some(workspace_id.to_owned()),
            workspace_root,
            resource_claims: vec![format!("{claim_prefix}:{target}")],
            target_resources: vec![target],
            command_id: None,
            command_identity_digest: None,
            requested_capability,
            policy_version,
        })
    }

    fn workspace_manage_policy_scope(
        &self,
        normalized_arguments: &Value,
    ) -> Result<WritePolicyScope, Box<dyn Error + Send + Sync>> {
        let workspace_id = normalized_arguments
            .get("workspaceId")
            .and_then(Value::as_str)
            .ok_or("normalized workspace identity is absent")?;
        let workspace_root = self
            .workspace_roots
            .get(workspace_id)
            .ok_or("requested workspace is not writable")?
            .clone();
        let operation = normalized_arguments
            .get("operation")
            .and_then(Value::as_str)
            .ok_or("normalized workspace-manage operation is absent")?;
        let mut target_resources = if operation == mealy_application::WORKSPACE_MOVE_FILE_OPERATION
        {
            ["sourcePath", "destinationPath"]
                .into_iter()
                .map(|field| {
                    normalized_arguments
                        .get(field)
                        .and_then(Value::as_str)
                        .map(|path| format!("workspace://{workspace_id}/{path}"))
                        .ok_or("normalized workspace-move path is absent")
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            let relative_path = normalized_arguments
                .get("relativePath")
                .and_then(Value::as_str)
                .ok_or("normalized workspace-manage path is absent")?;
            vec![format!("workspace://{workspace_id}/{relative_path}")]
        };
        target_resources.sort();
        let resource_claims = target_resources
            .iter()
            .map(|target| format!("workspace-manage:{target}"))
            .collect();
        Ok(WritePolicyScope {
            workspace_id: Some(workspace_id.to_owned()),
            workspace_root,
            target_resources,
            resource_claims,
            command_id: None,
            command_identity_digest: None,
            requested_capability: mealy_application::WORKSPACE_MANAGE_CAPABILITY,
            policy_version: mealy_application::WORKSPACE_MANAGE_POLICY_VERSION,
        })
    }

    /// Reconstructs the deterministic grant whose complete material is retained by the effect.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn grant(
        &self,
        tool_id: &str,
        principal_id: PrincipalId,
        channel_binding_id: ChannelBindingId,
        task_id: TaskId,
        run_id: RunId,
        valid_from_ms: i64,
        expires_at_ms: i64,
        scope: &WritePolicyScope,
    ) -> RuntimeWriteGrant {
        let descriptor = self
            .descriptor_for(tool_id)
            .expect("grant is built only for a configured descriptor");
        match tool_id {
            mealy_application::FIXTURE_WRITE_FILE_TOOL_ID if self.is_fixture() => {
                RuntimeWriteGrant::Fixture(FixtureWritePolicyGrant {
                    principal_id,
                    channel_binding_id,
                    task_id,
                    run_id,
                    tool_descriptor_digest: descriptor.descriptor_digest.clone(),
                    worker_identity_digest: self.worker_identity_digest.clone(),
                    workspace_root: scope.workspace_root.clone(),
                    capability: mealy_application::FIXTURE_WRITE_CAPABILITY.to_owned(),
                    profile: PolicyProfile::WorkspaceWrite,
                    valid_from_ms,
                    expires_at_ms,
                })
            }
            mealy_application::WORKSPACE_CREATE_FILE_TOOL_ID if !self.is_fixture() => {
                RuntimeWriteGrant::WorkspaceCreate(WorkspaceCreatePolicyGrant {
                    principal_id,
                    channel_binding_id,
                    task_id,
                    run_id,
                    tool_descriptor_digest: descriptor.descriptor_digest.clone(),
                    worker_identity_digest: self.worker_identity_digest.clone(),
                    workspace_id: scope
                        .workspace_id
                        .clone()
                        .expect("production scope always carries workspace identity"),
                    workspace_root: scope.workspace_root.clone(),
                    valid_from_ms,
                    expires_at_ms,
                })
            }
            mealy_application::WORKSPACE_REPLACE_FILE_TOOL_ID if !self.is_fixture() => {
                RuntimeWriteGrant::WorkspaceReplace(WorkspaceReplacePolicyGrant {
                    principal_id,
                    channel_binding_id,
                    task_id,
                    run_id,
                    tool_descriptor_digest: descriptor.descriptor_digest.clone(),
                    worker_identity_digest: self.worker_identity_digest.clone(),
                    workspace_id: scope
                        .workspace_id
                        .clone()
                        .expect("production scope always carries workspace identity"),
                    workspace_root: scope.workspace_root.clone(),
                    valid_from_ms,
                    expires_at_ms,
                })
            }
            mealy_application::WORKSPACE_MANAGE_PATH_TOOL_ID if !self.is_fixture() => {
                RuntimeWriteGrant::WorkspaceManage(WorkspaceManagePolicyGrant {
                    principal_id,
                    channel_binding_id,
                    task_id,
                    run_id,
                    tool_descriptor_digest: descriptor.descriptor_digest.clone(),
                    worker_identity_digest: self.worker_identity_digest.clone(),
                    workspace_id: scope
                        .workspace_id
                        .clone()
                        .expect("production scope always carries workspace identity"),
                    workspace_root: scope.workspace_root.clone(),
                    valid_from_ms,
                    expires_at_ms,
                })
            }
            mealy_application::PROCESS_RUN_TOOL_ID if !self.is_fixture() => {
                RuntimeWriteGrant::ProcessRun(ProcessRunPolicyGrant {
                    principal_id,
                    channel_binding_id,
                    task_id,
                    run_id,
                    tool_descriptor_digest: descriptor.descriptor_digest.clone(),
                    worker_identity_digest: self.worker_identity_digest.clone(),
                    command_id: scope
                        .command_id
                        .clone()
                        .expect("process scope carries command identity"),
                    command_identity_digest: scope
                        .command_identity_digest
                        .clone()
                        .expect("process scope carries executable identity"),
                    workspace_id: scope
                        .workspace_id
                        .clone()
                        .expect("process scope carries workspace identity"),
                    workspace_root: scope.workspace_root.clone(),
                    valid_from_ms,
                    expires_at_ms,
                })
            }
            _ => unreachable!("grant requires a configured runtime contract"),
        }
    }

    /// Re-evaluates the exact active contract against reconstructed configured authority.
    #[must_use]
    pub fn evaluate_policy(
        &self,
        request: &PolicyRequest,
        grant: &RuntimeWriteGrant,
    ) -> PolicyEvaluation {
        match (request.tool.tool_id.as_str(), grant) {
            (mealy_application::FIXTURE_WRITE_FILE_TOOL_ID, RuntimeWriteGrant::Fixture(grant))
                if self.is_fixture() =>
            {
                evaluate_fixture_write_policy(request, grant)
            }
            (
                mealy_application::WORKSPACE_CREATE_FILE_TOOL_ID,
                RuntimeWriteGrant::WorkspaceCreate(grant),
            ) if !self.is_fixture() => evaluate_workspace_create_policy(request, grant),
            (
                mealy_application::WORKSPACE_REPLACE_FILE_TOOL_ID,
                RuntimeWriteGrant::WorkspaceReplace(grant),
            ) if !self.is_fixture() => evaluate_workspace_replace_policy(request, grant),
            (
                mealy_application::WORKSPACE_MANAGE_PATH_TOOL_ID,
                RuntimeWriteGrant::WorkspaceManage(grant),
            ) if !self.is_fixture() => evaluate_workspace_manage_policy(request, grant),
            (mealy_application::PROCESS_RUN_TOOL_ID, RuntimeWriteGrant::ProcessRun(grant))
                if !self.is_fixture() =>
            {
                evaluate_process_run_policy(request, grant)
            }
            _ => PolicyEvaluation {
                decision: mealy_application::PolicyDecision::Deny,
                obligations: mealy_application::PolicyObligations {
                    profile: PolicyProfile::WorkspaceWrite,
                    readable_paths: Vec::new(),
                    writable_paths: Vec::new(),
                    allowed_executable_identity_digests: Vec::new(),
                    allow_process_spawn: false,
                    allowed_environment_variables: Vec::new(),
                    network_destinations: Vec::new(),
                    secret_references: Vec::new(),
                    argument_rewrite: None,
                    redactions: Vec::new(),
                    maximum_duration_ms: 0,
                    maximum_output_bytes: 0,
                    maximum_memory_bytes: 0,
                    maximum_processes: 0,
                    validator_required: true,
                },
                policy_version: request.policy_version.clone(),
                explanation: "runtime_write_contract_mismatch".to_owned(),
            },
        }
    }

    /// Builds the exact approval subject for the active contract.
    pub fn approval_subject(
        &self,
        effect_id: EffectId,
        request: &PolicyRequest,
        expires_at_ms: i64,
    ) -> Result<ApprovalSubject, Box<dyn Error + Send + Sync>> {
        match request.tool.tool_id.as_str() {
            mealy_application::FIXTURE_WRITE_FILE_TOOL_ID if self.is_fixture() => Ok(
                fixture_write_approval_subject(effect_id, request, expires_at_ms)?,
            ),
            mealy_application::WORKSPACE_CREATE_FILE_TOOL_ID if !self.is_fixture() => Ok(
                workspace_create_approval_subject(effect_id, request, expires_at_ms)?,
            ),
            mealy_application::WORKSPACE_REPLACE_FILE_TOOL_ID if !self.is_fixture() => Ok(
                workspace_replace_approval_subject(effect_id, request, expires_at_ms)?,
            ),
            mealy_application::WORKSPACE_MANAGE_PATH_TOOL_ID if !self.is_fixture() => Ok(
                workspace_manage_approval_subject(effect_id, request, expires_at_ms)?,
            ),
            mealy_application::PROCESS_RUN_TOOL_ID if !self.is_fixture() => Ok(
                process_run_approval_subject(effect_id, request, expires_at_ms)?,
            ),
            _ => Err("approval request does not match configured runtime authority".into()),
        }
    }

    /// Builds an exact one-shot executor request for the active approved contract.
    #[allow(clippy::too_many_arguments)]
    pub fn executor_request(
        &self,
        policy_request: &PolicyRequest,
        policy_evaluation: &PolicyEvaluation,
        grant: &RuntimeWriteGrant,
        approval: &ApprovalRequestView,
        effect_id: EffectId,
        attempt_id: AttemptId,
        fencing_token: FencingToken,
        capability_token: &str,
        dispatched_at_ms: i64,
    ) -> Result<ExecutorRequest, Box<dyn Error + Send + Sync>> {
        match (policy_request.tool.tool_id.as_str(), grant) {
            (mealy_application::FIXTURE_WRITE_FILE_TOOL_ID, RuntimeWriteGrant::Fixture(grant))
                if self.is_fixture() =>
            {
                Ok(build_fixture_write_executor_request(
                    FixtureWriteDispatch {
                        policy_request,
                        policy_evaluation,
                        grant,
                        approval,
                        effect_id,
                        attempt_id,
                        fencing_token,
                        capability_token,
                        dispatched_at_ms,
                    },
                )?)
            }
            (
                mealy_application::WORKSPACE_CREATE_FILE_TOOL_ID,
                RuntimeWriteGrant::WorkspaceCreate(grant),
            ) if !self.is_fixture() => Ok(build_workspace_create_executor_request(
                WorkspaceCreateDispatch {
                    policy_request,
                    policy_evaluation,
                    grant,
                    approval,
                    effect_id,
                    attempt_id,
                    fencing_token,
                    capability_token,
                    dispatched_at_ms,
                },
            )?),
            (
                mealy_application::WORKSPACE_REPLACE_FILE_TOOL_ID,
                RuntimeWriteGrant::WorkspaceReplace(grant),
            ) if !self.is_fixture() => Ok(build_workspace_replace_executor_request(
                WorkspaceReplaceDispatch {
                    policy_request,
                    policy_evaluation,
                    grant,
                    approval,
                    effect_id,
                    attempt_id,
                    fencing_token,
                    capability_token,
                    dispatched_at_ms,
                },
            )?),
            (
                mealy_application::WORKSPACE_MANAGE_PATH_TOOL_ID,
                RuntimeWriteGrant::WorkspaceManage(grant),
            ) if !self.is_fixture() => Ok(build_workspace_manage_executor_request(
                WorkspaceManageDispatch {
                    policy_request,
                    policy_evaluation,
                    grant,
                    approval,
                    effect_id,
                    attempt_id,
                    fencing_token,
                    capability_token,
                    dispatched_at_ms,
                },
            )?),
            (mealy_application::PROCESS_RUN_TOOL_ID, RuntimeWriteGrant::ProcessRun(grant))
                if !self.is_fixture() =>
            {
                Ok(build_process_run_executor_request(ProcessRunDispatch {
                    policy_request,
                    policy_evaluation,
                    grant,
                    approval,
                    effect_id,
                    attempt_id,
                    fencing_token,
                    capability_token,
                    dispatched_at_ms,
                })?)
            }
            _ => Err("runtime write contract does not match its grant".into()),
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
    commands: &BTreeMap<String, RuntimeCommand>,
) -> Result<Vec<SandboxRuntimeBinding>, Box<dyn Error + Send + Sync>> {
    let mut bindings = BTreeMap::new();
    add_dynamic_bindings(worker, true, &mut bindings)?;
    for (command_id, command) in commands {
        add_dynamic_bindings(&command.executable, false, &mut bindings)?;
        let sandbox_path = PathBuf::from(format!("/commands/{command_id}"));
        if bindings
            .insert(
                sandbox_path.clone(),
                SandboxRuntimeBinding {
                    host_path: command.executable.clone(),
                    sandbox_path,
                    identity_digest: Some(command.executable_digest.clone()),
                },
            )
            .is_some()
        {
            return Err("command sandbox path collides with a runtime binding".into());
        }
    }
    if bindings.is_empty() {
        return Err("worker has no discoverable dynamic runtime files".into());
    }
    Ok(bindings.into_values().collect())
}

fn add_dynamic_bindings(
    executable: &Path,
    required: bool,
    bindings: &mut BTreeMap<PathBuf, SandboxRuntimeBinding>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let output = dynamic_linker_inspector_command(executable)?.output()?;
    if !output.status.success() {
        if required {
            return Err("ldd could not inspect the trusted worker".into());
        }
        return Ok(());
    }
    let output = String::from_utf8(output.stdout)?;
    for line in output.lines() {
        for (host_path, sandbox_path) in dynamic_linker_bindings(line) {
            bindings.insert(
                sandbox_path.clone(),
                SandboxRuntimeBinding {
                    host_path,
                    sandbox_path,
                    identity_digest: None,
                },
            );
        }
    }
    Ok(())
}

fn dynamic_linker_bindings(line: &str) -> Vec<(PathBuf, PathBuf)> {
    let Some((left, right)) = line.split_once("=>") else {
        return line
            .split_whitespace()
            .next()
            .filter(|candidate| candidate.starts_with('/'))
            .map(|candidate| {
                let path = PathBuf::from(candidate);
                vec![(path.clone(), path)]
            })
            .unwrap_or_default();
    };
    let Some(resolved) = right
        .split_whitespace()
        .next()
        .filter(|candidate| candidate.starts_with('/'))
    else {
        return Vec::new();
    };
    let host_path = PathBuf::from(resolved);
    let mut bindings = vec![(host_path.clone(), host_path.clone())];
    if let Some(alias) = left
        .split_whitespace()
        .next()
        .filter(|candidate| candidate.starts_with('/') && *candidate != resolved)
    {
        bindings.push((host_path, PathBuf::from(alias)));
    }
    bindings
}

fn dynamic_linker_inspector_command(
    executable: &Path,
) -> Result<Command, Box<dyn Error + Send + Sync>> {
    let inspector = Path::new(DYNAMIC_LINKER_INSPECTOR_PATH);
    if !is_trusted_system_executable(inspector) {
        return Err("dynamic-linker inspector is not an exact trusted system executable".into());
    }
    let mut command = Command::new(inspector);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .arg("--")
        .arg(executable);
    Ok(command)
}

fn validate_runtime_commands(
    commands: impl IntoIterator<Item = ProcessCommandBinding>,
) -> Result<BTreeMap<String, RuntimeCommand>, Box<dyn Error + Send + Sync>> {
    let mut validated = BTreeMap::new();
    let mut paths = std::collections::BTreeSet::new();
    let mut digests = std::collections::BTreeSet::new();
    for command in commands {
        let executable = fs::canonicalize(&command.executable)?;
        let metadata = fs::symlink_metadata(&executable)?;
        let bytes = fs::read(&executable)?;
        if command.command_id.is_empty()
            || command.command_id.len() > 128
            || command.command_id.starts_with('.')
            || command
                .command_id
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b'-'))
            || executable != command.executable
            || !metadata.is_file()
            || metadata.file_type().is_symlink()
            || !is_trusted_system_executable(&executable)
            || bytes.len() < 4
            || &bytes[..4] != b"\x7fELF"
            || sha256_digest(&bytes) != command.executable_digest
            || !paths.insert(executable.clone())
            || !digests.insert(command.executable_digest.clone())
            || validated
                .insert(
                    command.command_id,
                    RuntimeCommand {
                        executable,
                        executable_digest: command.executable_digest,
                    },
                )
                .is_some()
        {
            return Err("configured direct executable is invalid".into());
        }
    }
    Ok(validated)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{
        DYNAMIC_LINKER_INSPECTOR_PATH, dynamic_linker_bindings, dynamic_linker_inspector_command,
    };
    use std::{
        ffi::OsStr,
        path::{Path, PathBuf},
    };

    #[test]
    fn dynamic_linker_bindings_preserve_an_absolute_interpreter_alias() {
        assert_eq!(
            dynamic_linker_bindings(
                "/lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x1234)"
            ),
            vec![
                (
                    PathBuf::from("/usr/lib64/ld-linux-x86-64.so.2"),
                    PathBuf::from("/usr/lib64/ld-linux-x86-64.so.2"),
                ),
                (
                    PathBuf::from("/usr/lib64/ld-linux-x86-64.so.2"),
                    PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
                ),
            ]
        );
        assert_eq!(
            dynamic_linker_bindings("libc.so.6 => /usr/lib/libc.so.6 (0x5678)"),
            vec![(
                PathBuf::from("/usr/lib/libc.so.6"),
                PathBuf::from("/usr/lib/libc.so.6"),
            )]
        );
        assert!(dynamic_linker_bindings("libmissing.so => not found").is_empty());
    }

    #[test]
    fn dynamic_linker_inspection_uses_one_absolute_helper_and_bounded_environment() {
        let executable = std::env::current_exe().expect("current test executable");
        let mut command =
            dynamic_linker_inspector_command(&executable).expect("trusted linker inspector");
        assert_eq!(
            command.get_program(),
            OsStr::new(DYNAMIC_LINKER_INSPECTOR_PATH)
        );
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [OsStr::new("--"), executable.as_os_str()]
        );
        assert_eq!(
            command.get_envs().collect::<Vec<_>>(),
            [(OsStr::new("LC_ALL"), Some(OsStr::new("C")))]
        );
        assert!(Path::new(DYNAMIC_LINKER_INSPECTOR_PATH).is_absolute());
        let output = command.output().expect("inspect test executable");
        assert!(output.status.success(), "ldd stderr: {:?}", output.stderr);
        assert!(!output.stdout.is_empty());
    }
}
