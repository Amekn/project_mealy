use crate::{
    ApprovalRequestView, ApprovalSubject, ApprovalSubjectError, ExecutorMount, ExecutorRequest,
    ExecutorRequestError, PolicyDecision, PolicyEvaluation, PolicyObligations, PolicyRequest,
    PolicyRequestError, ToolConcurrency, ToolDescriptor, ToolDescriptorValidationError,
    canonical_arguments_digest, is_sha256_digest, sha256_digest,
};
use mealy_domain::{
    ApprovalDecision, ApprovalStatus, AttemptId, EffectClass, EffectId, ExecutorKind, FencingToken,
    IdempotencyClass, PolicyProfile, PrincipalId, RecoveryStrategy, RiskClass, RunId, TaskId,
};
use serde_json::{Value, json};
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// Explicit admitted-input prefix selecting path lifecycle mode.
pub const WORKSPACE_MANAGE_INPUT_PREFIX: &str = "/manage ";
/// Stable production tool identity for exact path lifecycle operations.
pub const WORKSPACE_MANAGE_PATH_TOOL_ID: &str = "workspace.manage_path";
/// Create one absent directory beneath an already-existing safe parent.
pub const WORKSPACE_CREATE_DIRECTORY_OPERATION: &str = "create_directory";
/// Move one digest-matched regular file to an absent destination.
pub const WORKSPACE_MOVE_FILE_OPERATION: &str = "move_file";
/// Remove one bounded digest-matched regular file.
pub const WORKSPACE_REMOVE_FILE_OPERATION: &str = "remove_file";
/// Remove one exact empty directory without recursive authority.
pub const WORKSPACE_REMOVE_EMPTY_DIRECTORY_OPERATION: &str = "remove_empty_directory";
/// Logical capability required by the path lifecycle contract.
pub const WORKSPACE_MANAGE_CAPABILITY: &str = "write:workspace:manage";
/// Policy identity retained with each path lifecycle effect.
pub const WORKSPACE_MANAGE_POLICY_VERSION: &str = "mealy.workspace-manage.policy.v1";

const TOOL_VERSION: &str = "1";
const SANDBOX_ROOT: &str = "/workspace";
const MAXIMUM_DURATION_MS: u64 = 2_000;
const MAXIMUM_OUTPUT_BYTES: u64 = 16 * 1_024;
const MAXIMUM_MEMORY_BYTES: u64 = 256 * 1_024 * 1_024;
const MAXIMUM_RELATIVE_PATH_BYTES: usize = 256;
const MAXIMUM_WORKSPACE_ROOT_BYTES: usize = 4_096;

/// Exact configured authority for one approval-gated path lifecycle operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceManagePolicyGrant {
    /// Authenticated owner principal.
    pub principal_id: PrincipalId,
    /// Verified local or channel binding conveying the request.
    pub channel_binding_id: mealy_domain::ChannelBindingId,
    /// Exact owning task.
    pub task_id: TaskId,
    /// Exact owning run.
    pub run_id: RunId,
    /// Digest of the sole accepted descriptor.
    pub tool_descriptor_digest: String,
    /// Digest of the trusted worker executable bytes.
    pub worker_identity_digest: String,
    /// Logical writable workspace identity.
    pub workspace_id: String,
    /// Canonical host root mounted writable only for this attempt.
    pub workspace_root: String,
    /// Inclusive policy evaluation boundary.
    pub valid_from_ms: i64,
    /// Exclusive grant expiry.
    pub expires_at_ms: i64,
}

impl WorkspaceManagePolicyGrant {
    /// Validates every immutable grant dimension.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceManageContractError::InvalidGrant`] for malformed or widened authority.
    pub fn validate(&self) -> Result<(), WorkspaceManageContractError> {
        if self.valid_from_ms < 0
            || self.expires_at_ms <= self.valid_from_ms
            || !canonical_workspace_id(&self.workspace_id)
            || !canonical_workspace_root(&self.workspace_root)
            || !is_sha256_digest(&self.worker_identity_digest)
        {
            return Err(WorkspaceManageContractError::InvalidGrant);
        }
        let descriptor = workspace_manage_path_descriptor(&self.worker_identity_digest)
            .map_err(|_| WorkspaceManageContractError::InvalidGrant)?;
        if descriptor.descriptor_digest != self.tool_descriptor_digest {
            return Err(WorkspaceManageContractError::InvalidGrant);
        }
        Ok(())
    }
}

/// Inputs needed to build one approved, fenced path lifecycle executor request.
#[derive(Clone, Copy)]
pub struct WorkspaceManageDispatch<'a> {
    /// Durable normalized policy input.
    pub policy_request: &'a PolicyRequest,
    /// Durable approval-gated policy result.
    pub policy_evaluation: &'a PolicyEvaluation,
    /// Reconstructed exact configured grant.
    pub grant: &'a WorkspaceManagePolicyGrant,
    /// Current durable owner approval.
    pub approval: &'a ApprovalRequestView,
    /// Effect receiving one-shot authority.
    pub effect_id: EffectId,
    /// Prepared attempt receiving one-shot authority.
    pub attempt_id: AttemptId,
    /// Current durable run fence.
    pub fencing_token: FencingToken,
    /// Opaque invocation-only capability token.
    pub capability_token: &'a str,
    /// Dispatch time used for exclusive-expiry enforcement.
    pub dispatched_at_ms: i64,
}

/// Builds the exact path lifecycle descriptor bound to trusted worker bytes.
///
/// # Errors
///
/// Returns [`WorkspaceManageContractError`] when the digest or descriptor is not canonical.
#[allow(clippy::too_many_lines)]
pub fn workspace_manage_path_descriptor(
    worker_identity_digest: &str,
) -> Result<ToolDescriptor, WorkspaceManageContractError> {
    if !is_sha256_digest(worker_identity_digest) {
        return Err(WorkspaceManageContractError::InvalidWorkerIdentity);
    }
    let workspace_id = json!({
        "maxLength": 128,
        "minLength": 1,
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]*$",
        "type": "string"
    });
    let relative_path = json!({
        "maxLength": MAXIMUM_RELATIVE_PATH_BYTES,
        "minLength": 1,
        "pattern": "^[A-Za-z0-9._/-]+$",
        "type": "string"
    });
    let digest = json!({"pattern": "^[0-9a-f]{64}$", "type": "string"});
    let input_schema = json!({
        "oneOf": [
            {
                "additionalProperties": false,
                "properties": {
                    "operation": {"const": WORKSPACE_CREATE_DIRECTORY_OPERATION, "type": "string"},
                    "relativePath": relative_path,
                    "workspaceId": workspace_id
                },
                "required": ["operation", "relativePath", "workspaceId"],
                "type": "object"
            },
            {
                "additionalProperties": false,
                "properties": {
                    "destinationPath": relative_path,
                    "expectedSourceDigest": digest,
                    "operation": {"const": WORKSPACE_MOVE_FILE_OPERATION, "type": "string"},
                    "sourcePath": relative_path,
                    "workspaceId": workspace_id
                },
                "required": ["destinationPath", "expectedSourceDigest", "operation", "sourcePath", "workspaceId"],
                "type": "object"
            },
            {
                "additionalProperties": false,
                "properties": {
                    "expectedCurrentDigest": digest,
                    "operation": {"const": WORKSPACE_REMOVE_FILE_OPERATION, "type": "string"},
                    "relativePath": relative_path,
                    "workspaceId": workspace_id
                },
                "required": ["expectedCurrentDigest", "operation", "relativePath", "workspaceId"],
                "type": "object"
            },
            {
                "additionalProperties": false,
                "properties": {
                    "operation": {"const": WORKSPACE_REMOVE_EMPTY_DIRECTORY_OPERATION, "type": "string"},
                    "relativePath": relative_path,
                    "workspaceId": workspace_id
                },
                "required": ["operation", "relativePath", "workspaceId"],
                "type": "object"
            }
        ]
    });
    let output_schema = json!({
        "oneOf": [
            {
                "additionalProperties": false,
                "properties": {
                    "operation": {"const": WORKSPACE_CREATE_DIRECTORY_OPERATION, "type": "string"},
                    "relativePath": {"type": "string"}
                },
                "required": ["operation", "relativePath"],
                "type": "object"
            },
            {
                "additionalProperties": false,
                "properties": {
                    "contentDigest": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
                    "destinationPath": {"type": "string"},
                    "operation": {"const": WORKSPACE_MOVE_FILE_OPERATION, "type": "string"},
                    "sourcePath": {"type": "string"}
                },
                "required": ["contentDigest", "destinationPath", "operation", "sourcePath"],
                "type": "object"
            },
            {
                "additionalProperties": false,
                "properties": {
                    "contentDigest": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
                    "operation": {"const": WORKSPACE_REMOVE_FILE_OPERATION, "type": "string"},
                    "relativePath": {"type": "string"}
                },
                "required": ["contentDigest", "operation", "relativePath"],
                "type": "object"
            },
            {
                "additionalProperties": false,
                "properties": {
                    "operation": {"const": WORKSPACE_REMOVE_EMPTY_DIRECTORY_OPERATION, "type": "string"},
                    "relativePath": {"type": "string"}
                },
                "required": ["operation", "relativePath"],
                "type": "object"
            }
        ]
    });
    let mut descriptor = ToolDescriptor {
        tool_id: WORKSPACE_MANAGE_PATH_TOOL_ID.to_owned(),
        version: TOOL_VERSION.to_owned(),
        input_schema_digest: sha256_digest(input_schema.to_string().as_bytes()),
        output_schema_digest: sha256_digest(output_schema.to_string().as_bytes()),
        input_schema,
        output_schema,
        descriptor_digest: String::new(),
        effect_class: EffectClass::NonIdempotent,
        risk_class: RiskClass::Medium,
        required_capabilities: vec![WORKSPACE_MANAGE_CAPABILITY.to_owned()],
        timeout: Duration::from_millis(MAXIMUM_DURATION_MS),
        maximum_output_bytes: MAXIMUM_OUTPUT_BYTES,
        concurrency: ToolConcurrency::Serial,
        conflict_key_templates: vec!["workspace-manage:{workspaceId}".to_owned()],
        idempotency: IdempotencyClass::NonIdempotent,
        recovery: RecoveryStrategy::Reconcile,
        executor: ExecutorKind::Sandbox,
        executable_identity_digest: worker_identity_digest.to_owned(),
    };
    descriptor.descriptor_digest = descriptor.computed_descriptor_digest()?;
    descriptor.validate()?;
    Ok(descriptor)
}

/// Strictly normalizes model-facing path lifecycle arguments.
///
/// # Errors
///
/// Returns [`WorkspaceManageArgumentError`] for missing, extra, unsafe, or unbounded data.
pub fn normalize_workspace_manage_path_arguments(
    arguments: &Value,
) -> Result<Value, WorkspaceManageArgumentError> {
    let object = arguments
        .as_object()
        .ok_or(WorkspaceManageArgumentError::ExpectedObject)?;
    let operation = object
        .get("operation")
        .and_then(Value::as_str)
        .ok_or(WorkspaceManageArgumentError::InvalidOperation)?;
    let workspace_id = object
        .get("workspaceId")
        .and_then(Value::as_str)
        .filter(|value| canonical_workspace_id(value))
        .ok_or(WorkspaceManageArgumentError::InvalidWorkspaceId)?;
    match operation {
        WORKSPACE_CREATE_DIRECTORY_OPERATION | WORKSPACE_REMOVE_EMPTY_DIRECTORY_OPERATION => {
            require_exact_fields(object, &["operation", "relativePath", "workspaceId"])?;
            let relative_path = relative_path(object, "relativePath")?;
            Ok(json!({
                "operation": operation,
                "relativePath": relative_path,
                "workspaceId": workspace_id,
            }))
        }
        WORKSPACE_MOVE_FILE_OPERATION => {
            require_exact_fields(
                object,
                &[
                    "destinationPath",
                    "expectedSourceDigest",
                    "operation",
                    "sourcePath",
                    "workspaceId",
                ],
            )?;
            let source_path = relative_path(object, "sourcePath")?;
            let destination_path = relative_path(object, "destinationPath")?;
            if source_path == destination_path {
                return Err(WorkspaceManageArgumentError::SameMovePath);
            }
            let expected_source_digest = digest_field(object, "expectedSourceDigest")?;
            Ok(json!({
                "destinationPath": destination_path,
                "expectedSourceDigest": expected_source_digest,
                "operation": operation,
                "sourcePath": source_path,
                "workspaceId": workspace_id,
            }))
        }
        WORKSPACE_REMOVE_FILE_OPERATION => {
            require_exact_fields(
                object,
                &[
                    "expectedCurrentDigest",
                    "operation",
                    "relativePath",
                    "workspaceId",
                ],
            )?;
            let relative_path = relative_path(object, "relativePath")?;
            let expected_current_digest = digest_field(object, "expectedCurrentDigest")?;
            Ok(json!({
                "expectedCurrentDigest": expected_current_digest,
                "operation": operation,
                "relativePath": relative_path,
                "workspaceId": workspace_id,
            }))
        }
        _ => Err(WorkspaceManageArgumentError::InvalidOperation),
    }
}

fn require_exact_fields(
    object: &serde_json::Map<String, Value>,
    fields: &[&str],
) -> Result<(), WorkspaceManageArgumentError> {
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(WorkspaceManageArgumentError::InvalidShape);
    }
    Ok(())
}

fn relative_path<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, WorkspaceManageArgumentError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| canonical_relative_path(value))
        .ok_or(WorkspaceManageArgumentError::InvalidRelativePath { field })
}

fn digest_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, WorkspaceManageArgumentError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| is_sha256_digest(value))
        .ok_or(WorkspaceManageArgumentError::InvalidDigest { field })
}

/// Evaluates the exact path lifecycle rule and denies every mismatch.
#[must_use]
pub fn evaluate_workspace_manage_policy(
    request: &PolicyRequest,
    grant: &WorkspaceManagePolicyGrant,
) -> PolicyEvaluation {
    let deny = |reason: &str| denied_evaluation(request, reason);
    if request.validate().is_err() || grant.validate().is_err() {
        return deny("invalid_workspace_manage_request");
    }
    if request.principal_id != grant.principal_id
        || request.channel_binding_id != grant.channel_binding_id
        || request.task_id != grant.task_id
        || request.run_id != grant.run_id
        || request.evaluated_at_ms < grant.valid_from_ms
        || request.evaluated_at_ms >= grant.expires_at_ms
    {
        return deny("workspace_manage_scope_not_granted");
    }
    let Ok(validated) = validate_contract_request(request) else {
        return deny("no_matching_workspace_manage_rule");
    };
    if validated.workspace_id != grant.workspace_id
        || validated.workspace_root != grant.workspace_root
        || request.tool.descriptor_digest != grant.tool_descriptor_digest
        || request.tool.executable_identity_digest != grant.worker_identity_digest
    {
        return deny("no_matching_workspace_manage_rule");
    }
    PolicyEvaluation {
        decision: PolicyDecision::RequireApproval,
        obligations: expected_obligations(&validated.workspace_root, &grant.worker_identity_digest),
        policy_version: WORKSPACE_MANAGE_POLICY_VERSION.to_owned(),
        explanation: "workspace_manage_requires_approval".to_owned(),
    }
}

/// Constructs the immutable owner-facing path lifecycle approval subject.
///
/// # Errors
///
/// Returns [`WorkspaceManageContractError`] for invalid contract or expiry evidence.
pub fn workspace_manage_approval_subject(
    effect_id: EffectId,
    request: &PolicyRequest,
    expires_at_ms: i64,
) -> Result<ApprovalSubject, WorkspaceManageContractError> {
    let validated = validate_contract_request(request)?;
    if expires_at_ms <= request.evaluated_at_ms {
        return Err(WorkspaceManageContractError::InvalidApproval);
    }
    let subject = ApprovalSubject {
        principal_id: request.principal_id,
        task_id: request.task_id,
        effect_id,
        tool_id: request.tool.tool_id.clone(),
        tool_version: request.tool.version.clone(),
        canonical_arguments_digest: canonical_arguments_digest(&validated.normalized_arguments),
        capability_scope: WORKSPACE_MANAGE_CAPABILITY.to_owned(),
        target_resources: request.target_resources.clone(),
        executable_identity_digest: request.tool.executable_identity_digest.clone(),
        policy_version: WORKSPACE_MANAGE_POLICY_VERSION.to_owned(),
        expires_at_ms,
    };
    subject.validate()?;
    Ok(subject)
}

/// Builds a one-shot sandbox request exactly equal to approved path lifecycle obligations.
///
/// # Errors
///
/// Returns [`WorkspaceManageContractError`] for stale or divergent policy, approval, or dispatch
/// evidence.
pub fn build_workspace_manage_executor_request(
    dispatch: WorkspaceManageDispatch<'_>,
) -> Result<ExecutorRequest, WorkspaceManageContractError> {
    dispatch.grant.validate()?;
    let validated = validate_contract_request(dispatch.policy_request)?;
    let expected = evaluate_workspace_manage_policy(dispatch.policy_request, dispatch.grant);
    let obligations = expected_obligations(
        &validated.workspace_root,
        &dispatch.policy_request.tool.executable_identity_digest,
    );
    if expected.decision != PolicyDecision::RequireApproval
        || dispatch.policy_evaluation != &expected
        || dispatch.policy_evaluation.obligations != obligations
    {
        return Err(WorkspaceManageContractError::AuthorizationMismatch);
    }
    if dispatch.dispatched_at_ms < dispatch.policy_request.evaluated_at_ms
        || dispatch.dispatched_at_ms < 0
        || dispatch.dispatched_at_ms >= dispatch.approval.subject.expires_at_ms
    {
        return Err(WorkspaceManageContractError::InvalidDispatchTime);
    }
    let (Some(requested_at_ms), Some(resolved_at_ms)) = (
        system_time_milliseconds(dispatch.approval.requested_at),
        dispatch
            .approval
            .resolved_at
            .and_then(system_time_milliseconds),
    ) else {
        return Err(WorkspaceManageContractError::InvalidApproval);
    };
    let expected_subject = workspace_manage_approval_subject(
        dispatch.effect_id,
        dispatch.policy_request,
        dispatch.grant.expires_at_ms,
    )?;
    if requested_at_ms > resolved_at_ms
        || resolved_at_ms > dispatch.dispatched_at_ms
        || dispatch.approval.effect_id != dispatch.effect_id
        || dispatch.approval.status != ApprovalStatus::Approved
        || dispatch.approval.decision != Some(ApprovalDecision::Approve)
        || dispatch.approval.subject != expected_subject
        || dispatch.approval.subject_digest != expected_subject.subject_digest()?
    {
        return Err(WorkspaceManageContractError::InvalidApproval);
    }
    let request = ExecutorRequest {
        protocol_version: crate::EXECUTOR_PROTOCOL_VERSION.to_owned(),
        effect_id: dispatch.effect_id,
        attempt_id: dispatch.attempt_id,
        fencing_token: dispatch.fencing_token,
        capability_token: dispatch.capability_token.to_owned(),
        executable_identity_digest: dispatch
            .policy_request
            .tool
            .executable_identity_digest
            .clone(),
        profile: PolicyProfile::WorkspaceWrite,
        readable_roots: Vec::new(),
        writable_roots: vec![ExecutorMount {
            host_path: validated.workspace_root,
            sandbox_path: SANDBOX_ROOT.to_owned(),
        }],
        network_destinations: Vec::new(),
        secret_handles: Vec::new(),
        allow_process_spawn: false,
        allowed_environment_variables: Vec::new(),
        idempotency_key: None,
        arguments_digest: sha256_digest(validated.normalized_arguments.to_string().as_bytes()),
        normalized_arguments: validated.normalized_arguments,
        maximum_duration_ms: MAXIMUM_DURATION_MS,
        maximum_output_bytes: MAXIMUM_OUTPUT_BYTES,
        maximum_memory_bytes: MAXIMUM_MEMORY_BYTES,
        maximum_processes: 0,
    };
    request.validate()?;
    Ok(request)
}

struct ValidatedWorkspaceManage {
    normalized_arguments: Value,
    workspace_id: String,
    workspace_root: String,
}

fn validate_contract_request(
    request: &PolicyRequest,
) -> Result<ValidatedWorkspaceManage, WorkspaceManageContractError> {
    request.validate()?;
    if request.policy_version != WORKSPACE_MANAGE_POLICY_VERSION
        || request.agent_role != "assistant"
        || request.task_risk != RiskClass::Medium
        || request.requested_capability != WORKSPACE_MANAGE_CAPABILITY
        || request.requested_profile != PolicyProfile::WorkspaceWrite
        || request.enforceable_profiles != [PolicyProfile::WorkspaceWrite]
        || !request.secret_references.is_empty()
        || !request.network_destinations.is_empty()
        || request.workspace_roots.len() != 1
    {
        return Err(WorkspaceManageContractError::AuthorizationMismatch);
    }
    let expected_descriptor =
        workspace_manage_path_descriptor(&request.tool.executable_identity_digest)?;
    if request.tool != expected_descriptor {
        return Err(WorkspaceManageContractError::AuthorizationMismatch);
    }
    let normalized_arguments =
        normalize_workspace_manage_path_arguments(&request.normalized_arguments)?;
    if normalized_arguments != request.normalized_arguments {
        return Err(WorkspaceManageContractError::AuthorizationMismatch);
    }
    let workspace_id = normalized_arguments["workspaceId"]
        .as_str()
        .ok_or(WorkspaceManageContractError::AuthorizationMismatch)?
        .to_owned();
    let workspace_root = request.workspace_roots[0].clone();
    if !canonical_workspace_root(&workspace_root) {
        return Err(WorkspaceManageContractError::InvalidWorkspaceRoot);
    }
    let (target_resources, resource_claims) = expected_resources(&normalized_arguments)?;
    if request.target_resources != target_resources || request.resource_claims != resource_claims {
        return Err(WorkspaceManageContractError::AuthorizationMismatch);
    }
    Ok(ValidatedWorkspaceManage {
        normalized_arguments,
        workspace_id,
        workspace_root,
    })
}

fn expected_resources(
    arguments: &Value,
) -> Result<(Vec<String>, Vec<String>), WorkspaceManageContractError> {
    let workspace_id = arguments["workspaceId"]
        .as_str()
        .ok_or(WorkspaceManageContractError::AuthorizationMismatch)?;
    let operation = arguments["operation"]
        .as_str()
        .ok_or(WorkspaceManageContractError::AuthorizationMismatch)?;
    let mut target_resources = match operation {
        WORKSPACE_MOVE_FILE_OPERATION => vec![
            format!(
                "workspace://{workspace_id}/{}",
                arguments["sourcePath"]
                    .as_str()
                    .ok_or(WorkspaceManageContractError::AuthorizationMismatch)?
            ),
            format!(
                "workspace://{workspace_id}/{}",
                arguments["destinationPath"]
                    .as_str()
                    .ok_or(WorkspaceManageContractError::AuthorizationMismatch)?
            ),
        ],
        WORKSPACE_CREATE_DIRECTORY_OPERATION
        | WORKSPACE_REMOVE_FILE_OPERATION
        | WORKSPACE_REMOVE_EMPTY_DIRECTORY_OPERATION => vec![format!(
            "workspace://{workspace_id}/{}",
            arguments["relativePath"]
                .as_str()
                .ok_or(WorkspaceManageContractError::AuthorizationMismatch)?
        )],
        _ => return Err(WorkspaceManageContractError::AuthorizationMismatch),
    };
    target_resources.sort();
    let resource_claims = target_resources
        .iter()
        .map(|target| format!("workspace-manage:{target}"))
        .collect();
    Ok((target_resources, resource_claims))
}

fn expected_obligations(root: &str, worker_digest: &str) -> PolicyObligations {
    PolicyObligations {
        profile: PolicyProfile::WorkspaceWrite,
        readable_paths: Vec::new(),
        writable_paths: vec![root.to_owned()],
        allowed_executable_identity_digests: vec![worker_digest.to_owned()],
        allow_process_spawn: false,
        allowed_environment_variables: Vec::new(),
        network_destinations: Vec::new(),
        secret_references: Vec::new(),
        argument_rewrite: None,
        redactions: Vec::new(),
        maximum_duration_ms: MAXIMUM_DURATION_MS,
        maximum_output_bytes: MAXIMUM_OUTPUT_BYTES,
        maximum_memory_bytes: MAXIMUM_MEMORY_BYTES,
        maximum_processes: 0,
        validator_required: true,
    }
}

fn denied_evaluation(request: &PolicyRequest, explanation: &str) -> PolicyEvaluation {
    PolicyEvaluation {
        decision: PolicyDecision::Deny,
        obligations: PolicyObligations {
            profile: request.requested_profile,
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
        policy_version: WORKSPACE_MANAGE_POLICY_VERSION.to_owned(),
        explanation: explanation.to_owned(),
    }
}

fn canonical_workspace_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn canonical_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_RELATIVE_PATH_BYTES
        && value.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn canonical_workspace_root(value: &str) -> bool {
    value.len() >= 2
        && value.len() <= MAXIMUM_WORKSPACE_ROOT_BYTES
        && value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains('\0')
        && value.chars().all(|character| !character.is_control())
        && value
            .split('/')
            .skip(1)
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn system_time_milliseconds(value: SystemTime) -> Option<i64> {
    value
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
}

/// Invalid production path lifecycle argument shape or value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkspaceManageArgumentError {
    /// Arguments were not represented by one JSON object.
    #[error("workspace manage arguments must be an object")]
    ExpectedObject,
    /// Required fields were missing or undeclared fields were present.
    #[error("workspace manage arguments do not match one exact operation shape")]
    InvalidShape,
    /// Operation was absent, mistyped, or unsupported.
    #[error("workspace manage operation is invalid")]
    InvalidOperation,
    /// Workspace identity was absent, unsafe, or noncanonical.
    #[error("workspace manage workspace identity is invalid")]
    InvalidWorkspaceId,
    /// One relative path was absent, unsafe, or noncanonical.
    #[error("workspace manage {field} is invalid")]
    InvalidRelativePath {
        /// Stable field identity.
        field: &'static str,
    },
    /// One file-content digest precondition was absent or malformed.
    #[error("workspace manage {field} is invalid")]
    InvalidDigest {
        /// Stable field identity.
        field: &'static str,
    },
    /// A move attempted to use the same source and destination.
    #[error("workspace move source and destination must differ")]
    SameMovePath,
}

/// Invalid descriptor, policy, approval, or executor evidence for path lifecycle management.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkspaceManageContractError {
    /// Trusted worker digest was not canonical lowercase SHA-256.
    #[error("workspace manage worker identity is invalid")]
    InvalidWorkerIdentity,
    /// Configured grant was malformed or widened the fixed contract.
    #[error("workspace manage policy grant is invalid")]
    InvalidGrant,
    /// Host root was not a canonical bounded absolute path.
    #[error("workspace manage workspace root is invalid")]
    InvalidWorkspaceRoot,
    /// Request, policy outcome, or obligations diverged from the fixed contract.
    #[error("workspace manage authorization evidence does not match")]
    AuthorizationMismatch,
    /// Approval was missing, stale, denied, or bound to different evidence.
    #[error("workspace manage approval evidence is invalid")]
    InvalidApproval,
    /// Dispatch occurred before evaluation or at/after exclusive expiry.
    #[error("workspace manage dispatch time is invalid")]
    InvalidDispatchTime,
    /// Generic tool descriptor evidence was invalid.
    #[error(transparent)]
    Descriptor(#[from] ToolDescriptorValidationError),
    /// Normalized model arguments were invalid.
    #[error(transparent)]
    Arguments(#[from] WorkspaceManageArgumentError),
    /// Generic policy request evidence was invalid.
    #[error(transparent)]
    Policy(#[from] PolicyRequestError),
    /// Approval subject evidence was invalid.
    #[error(transparent)]
    Approval(#[from] ApprovalSubjectError),
    /// Executor request evidence was invalid.
    #[error(transparent)]
    Executor(#[from] ExecutorRequestError),
}

#[cfg(test)]
mod tests {
    use super::{
        WORKSPACE_CREATE_DIRECTORY_OPERATION, WORKSPACE_MANAGE_CAPABILITY,
        WORKSPACE_MANAGE_PATH_TOOL_ID, WORKSPACE_MANAGE_POLICY_VERSION,
        WORKSPACE_MOVE_FILE_OPERATION, WORKSPACE_REMOVE_EMPTY_DIRECTORY_OPERATION,
        WORKSPACE_REMOVE_FILE_OPERATION, WorkspaceManagePolicyGrant,
        evaluate_workspace_manage_policy, normalize_workspace_manage_path_arguments,
        workspace_manage_approval_subject, workspace_manage_path_descriptor,
    };
    use crate::{PolicyDecision, PolicyRequest, sha256_digest};
    use mealy_domain::{
        ChannelBindingId, EffectClass, EffectId, IdempotencyClass, PolicyProfile, PrincipalId,
        RecoveryStrategy, RiskClass, RunId, TaskId,
    };
    use serde_json::json;

    fn request_and_grant() -> (PolicyRequest, WorkspaceManagePolicyGrant) {
        let principal_id = PrincipalId::new();
        let channel_binding_id = ChannelBindingId::new();
        let task_id = TaskId::new();
        let run_id = RunId::new();
        let worker = sha256_digest(b"worker");
        let tool = workspace_manage_path_descriptor(&worker).expect("descriptor");
        let arguments = json!({
            "destinationPath": "archive/report.txt",
            "expectedSourceDigest": sha256_digest(b"report"),
            "operation": WORKSPACE_MOVE_FILE_OPERATION,
            "sourcePath": "drafts/report.txt",
            "workspaceId": "project",
        });
        let grant = WorkspaceManagePolicyGrant {
            principal_id,
            channel_binding_id,
            task_id,
            run_id,
            tool_descriptor_digest: tool.descriptor_digest.clone(),
            worker_identity_digest: worker,
            workspace_id: "project".to_owned(),
            workspace_root: "/srv/project".to_owned(),
            valid_from_ms: 100,
            expires_at_ms: 1_000,
        };
        let request = PolicyRequest {
            principal_id,
            channel_binding_id,
            task_id,
            run_id,
            agent_role: "assistant".to_owned(),
            task_risk: RiskClass::Medium,
            tool,
            normalized_arguments: arguments,
            target_resources: vec![
                "workspace://project/archive/report.txt".to_owned(),
                "workspace://project/drafts/report.txt".to_owned(),
            ],
            workspace_roots: vec!["/srv/project".to_owned()],
            resource_claims: vec![
                "workspace-manage:workspace://project/archive/report.txt".to_owned(),
                "workspace-manage:workspace://project/drafts/report.txt".to_owned(),
            ],
            secret_references: Vec::new(),
            network_destinations: Vec::new(),
            requested_capability: WORKSPACE_MANAGE_CAPABILITY.to_owned(),
            requested_profile: PolicyProfile::WorkspaceWrite,
            enforceable_profiles: vec![PolicyProfile::WorkspaceWrite],
            evaluated_at_ms: 500,
            policy_version: WORKSPACE_MANAGE_POLICY_VERSION.to_owned(),
        };
        (request, grant)
    }

    #[test]
    fn descriptor_and_all_operation_shapes_are_conservative_and_exact() {
        let descriptor =
            workspace_manage_path_descriptor(&sha256_digest(b"worker")).expect("descriptor");
        assert_eq!(descriptor.tool_id, WORKSPACE_MANAGE_PATH_TOOL_ID);
        assert_eq!(descriptor.effect_class, EffectClass::NonIdempotent);
        assert_eq!(descriptor.idempotency, IdempotencyClass::NonIdempotent);
        assert_eq!(descriptor.recovery, RecoveryStrategy::Reconcile);
        for arguments in [
            json!({
                "operation": WORKSPACE_CREATE_DIRECTORY_OPERATION,
                "relativePath": "archive/2026",
                "workspaceId": "project"
            }),
            json!({
                "destinationPath": "archive/report.txt",
                "expectedSourceDigest": sha256_digest(b"report"),
                "operation": WORKSPACE_MOVE_FILE_OPERATION,
                "sourcePath": "drafts/report.txt",
                "workspaceId": "project"
            }),
            json!({
                "expectedCurrentDigest": sha256_digest(b"obsolete"),
                "operation": WORKSPACE_REMOVE_FILE_OPERATION,
                "relativePath": "obsolete.txt",
                "workspaceId": "project"
            }),
            json!({
                "operation": WORKSPACE_REMOVE_EMPTY_DIRECTORY_OPERATION,
                "relativePath": "old-empty",
                "workspaceId": "project"
            }),
        ] {
            assert_eq!(
                normalize_workspace_manage_path_arguments(&arguments).expect("normalize"),
                arguments
            );
        }
        assert!(
            normalize_workspace_manage_path_arguments(&json!({
                "operation": WORKSPACE_CREATE_DIRECTORY_OPERATION,
                "relativePath": "../escape",
                "workspaceId": "project"
            }))
            .is_err()
        );
        assert!(
            normalize_workspace_manage_path_arguments(&json!({
                "destinationPath": "same.txt",
                "expectedSourceDigest": sha256_digest(b"same"),
                "operation": WORKSPACE_MOVE_FILE_OPERATION,
                "sourcePath": "same.txt",
                "workspaceId": "project"
            }))
            .is_err()
        );
    }

    #[test]
    fn policy_and_subject_bind_both_move_paths_and_digest() {
        let (request, grant) = request_and_grant();
        grant.validate().expect("grant");
        assert_eq!(
            evaluate_workspace_manage_policy(&request, &grant).decision,
            PolicyDecision::RequireApproval
        );
        let subject = workspace_manage_approval_subject(EffectId::new(), &request, 1_000)
            .expect("approval subject");
        assert_eq!(subject.target_resources, request.target_resources);

        let mut changed = request.clone();
        changed.normalized_arguments["expectedSourceDigest"] = json!(sha256_digest(b"changed"));
        let changed_subject = workspace_manage_approval_subject(EffectId::new(), &changed, 1_000)
            .expect("changed subject");
        assert_ne!(
            subject.canonical_arguments_digest,
            changed_subject.canonical_arguments_digest
        );
        changed.target_resources.swap(0, 1);
        assert_eq!(
            evaluate_workspace_manage_policy(&changed, &grant).decision,
            PolicyDecision::Deny
        );
    }
}
