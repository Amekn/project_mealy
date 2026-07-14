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

/// Explicit admitted-input prefix selecting high-risk direct-process mode.
pub const PROCESS_RUN_INPUT_PREFIX: &str = "/run ";
/// Stable model-visible direct-process tool identity.
pub const PROCESS_RUN_TOOL_ID: &str = "process.run";
/// Worker protocol operation for one allowlisted process.
pub const PROCESS_RUN_OPERATION: &str = "run_process";
/// Logical capability required by the direct-process contract.
pub const PROCESS_RUN_CAPABILITY: &str = "execute:allowlisted-process";
/// Policy identity retained with every direct-process effect.
pub const PROCESS_RUN_POLICY_VERSION: &str = "mealy.process-run.policy.v1";

const TOOL_VERSION: &str = "1";
const SANDBOX_ROOT: &str = "/workspace";
const MAXIMUM_DURATION_MS: u64 = 10_000;
const MAXIMUM_OUTPUT_BYTES: u64 = 48 * 1_024;
const MAXIMUM_MEMORY_BYTES: u64 = 512 * 1_024 * 1_024;
const MAXIMUM_PROCESSES: u32 = 16;
const MAXIMUM_ARGUMENTS: usize = 32;
const MAXIMUM_ARGUMENT_BYTES: usize = 512;
const MAXIMUM_TOTAL_ARGUMENT_BYTES: usize = 8 * 1_024;
const MAXIMUM_WORKING_DIRECTORY_BYTES: usize = 256;
const MAXIMUM_WORKSPACE_ROOT_BYTES: usize = 4_096;
const EXPLANATION: &str = "allowlisted_process_requires_approval";

/// Exact configured authority for one approved command in one writable workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessRunPolicyGrant {
    /// Authenticated owner principal.
    pub principal_id: PrincipalId,
    /// Verified input channel binding.
    pub channel_binding_id: mealy_domain::ChannelBindingId,
    /// Exact owning task.
    pub task_id: TaskId,
    /// Exact owning run.
    pub run_id: RunId,
    /// Digest of the sole accepted generic tool descriptor.
    pub tool_descriptor_digest: String,
    /// Digest of the trusted protocol worker.
    pub worker_identity_digest: String,
    /// Stable logical command identity.
    pub command_id: String,
    /// Digest of the exact child executable bytes.
    pub command_identity_digest: String,
    /// Logical writable workspace identity.
    pub workspace_id: String,
    /// Canonical host workspace root.
    pub workspace_root: String,
    /// Inclusive policy evaluation boundary.
    pub valid_from_ms: i64,
    /// Exclusive grant expiry.
    pub expires_at_ms: i64,
}

impl ProcessRunPolicyGrant {
    /// Validates every configured and caller-specific grant dimension.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessRunContractError::InvalidGrant`] for malformed or widened authority.
    pub fn validate(&self) -> Result<(), ProcessRunContractError> {
        if self.valid_from_ms < 0
            || self.expires_at_ms <= self.valid_from_ms
            || !canonical_id(&self.command_id)
            || !canonical_id(&self.workspace_id)
            || !canonical_workspace_root(&self.workspace_root)
            || !is_sha256_digest(&self.worker_identity_digest)
            || !is_sha256_digest(&self.command_identity_digest)
        {
            return Err(ProcessRunContractError::InvalidGrant);
        }
        let descriptor = process_run_descriptor(&self.worker_identity_digest)
            .map_err(|_| ProcessRunContractError::InvalidGrant)?;
        if descriptor.descriptor_digest != self.tool_descriptor_digest {
            return Err(ProcessRunContractError::InvalidGrant);
        }
        Ok(())
    }
}

/// Evidence needed to build one approved, fenced process executor request.
#[derive(Clone, Copy)]
pub struct ProcessRunDispatch<'a> {
    /// Durable normalized policy request.
    pub policy_request: &'a PolicyRequest,
    /// Durable policy decision and obligations.
    pub policy_evaluation: &'a PolicyEvaluation,
    /// Reconstructed current configured grant.
    pub grant: &'a ProcessRunPolicyGrant,
    /// Current exact owner approval.
    pub approval: &'a ApprovalRequestView,
    /// Governed effect identity.
    pub effect_id: EffectId,
    /// Fresh dispatch attempt identity.
    pub attempt_id: AttemptId,
    /// Current durable run fence.
    pub fencing_token: FencingToken,
    /// Invocation-only one-use capability.
    pub capability_token: &'a str,
    /// Dispatch time for exclusive-expiry enforcement.
    pub dispatched_at_ms: i64,
}

/// Builds the direct-process descriptor bound to the trusted worker bytes.
///
/// # Errors
///
/// Returns [`ProcessRunContractError`] when the worker digest or descriptor is not canonical.
pub fn process_run_descriptor(
    worker_identity_digest: &str,
) -> Result<ToolDescriptor, ProcessRunContractError> {
    if !is_sha256_digest(worker_identity_digest) {
        return Err(ProcessRunContractError::InvalidWorkerIdentity);
    }
    let input_schema = json!({
        "additionalProperties": false,
        "properties": {
            "arguments": {
                "items": {"maxLength": MAXIMUM_ARGUMENT_BYTES, "type": "string"},
                "maxItems": MAXIMUM_ARGUMENTS,
                "type": "array"
            },
            "commandId": {
                "maxLength": 128,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]*$",
                "type": "string"
            },
            "operation": {"const": PROCESS_RUN_OPERATION, "type": "string"},
            "workingDirectory": {
                "maxLength": MAXIMUM_WORKING_DIRECTORY_BYTES,
                "pattern": "^$|^[A-Za-z0-9._/-]+$",
                "type": "string"
            },
            "workspaceId": {
                "maxLength": 128,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]*$",
                "type": "string"
            }
        },
        "required": ["arguments", "commandId", "operation", "workingDirectory", "workspaceId"],
        "type": "object"
    });
    let output_schema = json!({
        "additionalProperties": false,
        "properties": {
            "exitCode": {"type": ["integer", "null"]},
            "stderr": {"type": "string"},
            "stderrDigest": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "stderrTruncated": {"type": "boolean"},
            "stderrUtf8": {"type": "boolean"},
            "stdout": {"type": "string"},
            "stdoutDigest": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "stdoutTruncated": {"type": "boolean"},
            "stdoutUtf8": {"type": "boolean"}
        },
        "required": ["exitCode", "stderr", "stderrDigest", "stderrTruncated", "stderrUtf8", "stdout", "stdoutDigest", "stdoutTruncated", "stdoutUtf8"],
        "type": "object"
    });
    let mut descriptor = ToolDescriptor {
        tool_id: PROCESS_RUN_TOOL_ID.to_owned(),
        version: TOOL_VERSION.to_owned(),
        input_schema_digest: sha256_digest(input_schema.to_string().as_bytes()),
        output_schema_digest: sha256_digest(output_schema.to_string().as_bytes()),
        input_schema,
        output_schema,
        descriptor_digest: String::new(),
        effect_class: EffectClass::NonIdempotent,
        risk_class: RiskClass::High,
        required_capabilities: vec![PROCESS_RUN_CAPABILITY.to_owned()],
        timeout: Duration::from_millis(MAXIMUM_DURATION_MS),
        maximum_output_bytes: MAXIMUM_OUTPUT_BYTES,
        concurrency: ToolConcurrency::Serial,
        conflict_key_templates: vec!["process:{workspaceId}:{commandId}".to_owned()],
        idempotency: IdempotencyClass::NonIdempotent,
        recovery: RecoveryStrategy::NeverRetry,
        executor: ExecutorKind::Sandbox,
        executable_identity_digest: worker_identity_digest.to_owned(),
    };
    descriptor.descriptor_digest = descriptor.computed_descriptor_digest()?;
    descriptor.validate()?;
    Ok(descriptor)
}

/// Strictly normalizes one direct-process model argument envelope.
///
/// # Errors
///
/// Returns [`ProcessRunArgumentError`] for a missing, extra, unsafe, or unbounded field.
pub fn normalize_process_run_arguments(
    arguments: &Value,
) -> Result<Value, ProcessRunArgumentError> {
    let object = arguments
        .as_object()
        .ok_or(ProcessRunArgumentError::ExpectedObject)?;
    if object.len() != 5
        || ![
            "arguments",
            "commandId",
            "operation",
            "workingDirectory",
            "workspaceId",
        ]
        .iter()
        .all(|field| object.contains_key(*field))
    {
        return Err(ProcessRunArgumentError::InvalidShape);
    }
    if object.get("operation").and_then(Value::as_str) != Some(PROCESS_RUN_OPERATION) {
        return Err(ProcessRunArgumentError::InvalidOperation);
    }
    let command_id = object
        .get("commandId")
        .and_then(Value::as_str)
        .filter(|value| canonical_id(value))
        .ok_or(ProcessRunArgumentError::InvalidCommandId)?;
    let workspace_id = object
        .get("workspaceId")
        .and_then(Value::as_str)
        .filter(|value| canonical_id(value))
        .ok_or(ProcessRunArgumentError::InvalidWorkspaceId)?;
    let working_directory = object
        .get("workingDirectory")
        .and_then(Value::as_str)
        .filter(|value| canonical_working_directory(value))
        .ok_or(ProcessRunArgumentError::InvalidWorkingDirectory)?;
    let arguments = object
        .get("arguments")
        .and_then(Value::as_array)
        .filter(|values| values.len() <= MAXIMUM_ARGUMENTS)
        .ok_or(ProcessRunArgumentError::InvalidArguments)?;
    let mut normalized_arguments = Vec::with_capacity(arguments.len());
    let mut total_bytes = 0_usize;
    for argument in arguments {
        let argument = argument
            .as_str()
            .filter(|value| {
                value.len() <= MAXIMUM_ARGUMENT_BYTES
                    && !value.contains('\0')
                    && !value.chars().any(char::is_control)
            })
            .ok_or(ProcessRunArgumentError::InvalidArguments)?;
        total_bytes = total_bytes.saturating_add(argument.len());
        if total_bytes > MAXIMUM_TOTAL_ARGUMENT_BYTES {
            return Err(ProcessRunArgumentError::InvalidArguments);
        }
        normalized_arguments.push(argument);
    }
    Ok(json!({
        "arguments": normalized_arguments,
        "commandId": command_id,
        "operation": PROCESS_RUN_OPERATION,
        "workingDirectory": working_directory,
        "workspaceId": workspace_id,
    }))
}

/// Evaluates the exact high-risk allowlisted-process policy.
#[must_use]
pub fn evaluate_process_run_policy(
    request: &PolicyRequest,
    grant: &ProcessRunPolicyGrant,
) -> PolicyEvaluation {
    let deny = |reason: &str| denied_evaluation(request, reason);
    if request.validate().is_err() || grant.validate().is_err() {
        return deny("invalid_process_run_request");
    }
    if request.principal_id != grant.principal_id
        || request.channel_binding_id != grant.channel_binding_id
        || request.task_id != grant.task_id
        || request.run_id != grant.run_id
        || request.evaluated_at_ms < grant.valid_from_ms
        || request.evaluated_at_ms >= grant.expires_at_ms
    {
        return deny("process_run_scope_not_granted");
    }
    let Ok(validated) = validate_contract_request(request) else {
        return deny("no_matching_process_run_rule");
    };
    if validated.command_id != grant.command_id
        || validated.command_identity_digest != grant.command_identity_digest
        || validated.workspace_id != grant.workspace_id
        || validated.workspace_root != grant.workspace_root
        || request.tool.descriptor_digest != grant.tool_descriptor_digest
        || request.tool.executable_identity_digest != grant.worker_identity_digest
    {
        return deny("no_matching_process_run_rule");
    }
    PolicyEvaluation {
        decision: PolicyDecision::RequireApproval,
        obligations: expected_obligations(
            &validated.workspace_root,
            &grant.worker_identity_digest,
            &grant.command_identity_digest,
        ),
        policy_version: PROCESS_RUN_POLICY_VERSION.to_owned(),
        explanation: EXPLANATION.to_owned(),
    }
}

/// Constructs the immutable owner-facing process approval subject.
///
/// # Errors
///
/// Returns [`ProcessRunContractError`] for invalid contract or expiry evidence.
pub fn process_run_approval_subject(
    effect_id: EffectId,
    request: &PolicyRequest,
    expires_at_ms: i64,
) -> Result<ApprovalSubject, ProcessRunContractError> {
    let validated = validate_contract_request(request)?;
    if expires_at_ms <= request.evaluated_at_ms {
        return Err(ProcessRunContractError::InvalidApproval);
    }
    let subject = ApprovalSubject {
        principal_id: request.principal_id,
        task_id: request.task_id,
        effect_id,
        tool_id: request.tool.tool_id.clone(),
        tool_version: request.tool.version.clone(),
        canonical_arguments_digest: canonical_arguments_digest(&validated.normalized_arguments),
        capability_scope: PROCESS_RUN_CAPABILITY.to_owned(),
        target_resources: request.target_resources.clone(),
        executable_identity_digest: request.tool.executable_identity_digest.clone(),
        policy_version: PROCESS_RUN_POLICY_VERSION.to_owned(),
        expires_at_ms,
    };
    subject.validate()?;
    Ok(subject)
}

/// Builds one approved no-network/no-secret direct-process sandbox request.
///
/// # Errors
///
/// Returns [`ProcessRunContractError`] for stale or divergent policy, approval, grant, or
/// dispatch evidence.
pub fn build_process_run_executor_request(
    dispatch: ProcessRunDispatch<'_>,
) -> Result<ExecutorRequest, ProcessRunContractError> {
    dispatch.grant.validate()?;
    let validated = validate_contract_request(dispatch.policy_request)?;
    let expected = evaluate_process_run_policy(dispatch.policy_request, dispatch.grant);
    let obligations = expected_obligations(
        &validated.workspace_root,
        &dispatch.grant.worker_identity_digest,
        &dispatch.grant.command_identity_digest,
    );
    if expected.decision != PolicyDecision::RequireApproval
        || dispatch.policy_evaluation != &expected
        || dispatch.policy_evaluation.obligations != obligations
    {
        return Err(ProcessRunContractError::AuthorizationMismatch);
    }
    if dispatch.dispatched_at_ms < dispatch.policy_request.evaluated_at_ms
        || dispatch.dispatched_at_ms < 0
        || dispatch.dispatched_at_ms >= dispatch.approval.subject.expires_at_ms
    {
        return Err(ProcessRunContractError::InvalidDispatchTime);
    }
    let (Some(requested_at_ms), Some(resolved_at_ms)) = (
        system_time_milliseconds(dispatch.approval.requested_at),
        dispatch
            .approval
            .resolved_at
            .and_then(system_time_milliseconds),
    ) else {
        return Err(ProcessRunContractError::InvalidApproval);
    };
    let expected_subject = process_run_approval_subject(
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
        return Err(ProcessRunContractError::InvalidApproval);
    }
    let request = ExecutorRequest {
        protocol_version: crate::EXECUTOR_PROTOCOL_VERSION.to_owned(),
        effect_id: dispatch.effect_id,
        attempt_id: dispatch.attempt_id,
        fencing_token: dispatch.fencing_token,
        capability_token: dispatch.capability_token.to_owned(),
        executable_identity_digest: dispatch.grant.worker_identity_digest.clone(),
        profile: PolicyProfile::WorkspaceWrite,
        readable_roots: Vec::new(),
        writable_roots: vec![ExecutorMount {
            host_path: validated.workspace_root,
            sandbox_path: SANDBOX_ROOT.to_owned(),
        }],
        network_destinations: Vec::new(),
        secret_handles: Vec::new(),
        allow_process_spawn: true,
        allowed_environment_variables: Vec::new(),
        idempotency_key: None,
        arguments_digest: sha256_digest(validated.normalized_arguments.to_string().as_bytes()),
        normalized_arguments: validated.normalized_arguments,
        maximum_duration_ms: MAXIMUM_DURATION_MS,
        maximum_output_bytes: MAXIMUM_OUTPUT_BYTES,
        maximum_memory_bytes: MAXIMUM_MEMORY_BYTES,
        maximum_processes: MAXIMUM_PROCESSES,
    };
    request.validate()?;
    Ok(request)
}

struct ValidatedProcessRun {
    normalized_arguments: Value,
    command_id: String,
    command_identity_digest: String,
    workspace_id: String,
    workspace_root: String,
}

fn validate_contract_request(
    request: &PolicyRequest,
) -> Result<ValidatedProcessRun, ProcessRunContractError> {
    request.validate()?;
    if request.policy_version != PROCESS_RUN_POLICY_VERSION
        || request.agent_role != "assistant"
        || request.task_risk != RiskClass::High
        || request.requested_capability != PROCESS_RUN_CAPABILITY
        || request.requested_profile != PolicyProfile::WorkspaceWrite
        || request.enforceable_profiles != [PolicyProfile::WorkspaceWrite]
        || !request.secret_references.is_empty()
        || !request.network_destinations.is_empty()
        || request.workspace_roots.len() != 1
    {
        return Err(ProcessRunContractError::AuthorizationMismatch);
    }
    let descriptor = process_run_descriptor(&request.tool.executable_identity_digest)?;
    if request.tool != descriptor {
        return Err(ProcessRunContractError::AuthorizationMismatch);
    }
    let normalized_arguments = normalize_process_run_arguments(&request.normalized_arguments)?;
    if normalized_arguments != request.normalized_arguments {
        return Err(ProcessRunContractError::AuthorizationMismatch);
    }
    let command_id = normalized_arguments["commandId"]
        .as_str()
        .ok_or(ProcessRunContractError::AuthorizationMismatch)?
        .to_owned();
    let workspace_id = normalized_arguments["workspaceId"]
        .as_str()
        .ok_or(ProcessRunContractError::AuthorizationMismatch)?
        .to_owned();
    let working_directory = normalized_arguments["workingDirectory"]
        .as_str()
        .ok_or(ProcessRunContractError::AuthorizationMismatch)?;
    let workspace_root = request.workspace_roots[0].clone();
    if !canonical_workspace_root(&workspace_root) {
        return Err(ProcessRunContractError::InvalidWorkspaceRoot);
    }
    let command_prefix = format!("command://{command_id}@sha256:");
    let command_target = request
        .target_resources
        .iter()
        .find(|target| target.starts_with(&command_prefix))
        .ok_or(ProcessRunContractError::AuthorizationMismatch)?;
    let command_identity_digest = command_target
        .strip_prefix(&command_prefix)
        .filter(|digest| is_sha256_digest(digest))
        .ok_or(ProcessRunContractError::AuthorizationMismatch)?
        .to_owned();
    let workspace_target = if working_directory.is_empty() {
        format!("workspace://{workspace_id}/")
    } else {
        format!("workspace://{workspace_id}/{working_directory}")
    };
    let mut targets = vec![command_target.clone(), workspace_target.clone()];
    targets.sort();
    let mut claims = vec![
        format!("process-executable:sha256:{command_identity_digest}"),
        format!("workspace-process:{workspace_target}"),
    ];
    claims.sort();
    if request.target_resources != targets || request.resource_claims != claims {
        return Err(ProcessRunContractError::AuthorizationMismatch);
    }
    Ok(ValidatedProcessRun {
        normalized_arguments,
        command_id,
        command_identity_digest,
        workspace_id,
        workspace_root,
    })
}

fn expected_obligations(
    workspace_root: &str,
    worker_digest: &str,
    command_digest: &str,
) -> PolicyObligations {
    let mut executable_digests = vec![worker_digest.to_owned(), command_digest.to_owned()];
    executable_digests.sort();
    executable_digests.dedup();
    PolicyObligations {
        profile: PolicyProfile::WorkspaceWrite,
        readable_paths: Vec::new(),
        writable_paths: vec![workspace_root.to_owned()],
        allowed_executable_identity_digests: executable_digests,
        allow_process_spawn: true,
        allowed_environment_variables: Vec::new(),
        network_destinations: Vec::new(),
        secret_references: Vec::new(),
        argument_rewrite: None,
        redactions: Vec::new(),
        maximum_duration_ms: MAXIMUM_DURATION_MS,
        maximum_output_bytes: MAXIMUM_OUTPUT_BYTES,
        maximum_memory_bytes: MAXIMUM_MEMORY_BYTES,
        maximum_processes: MAXIMUM_PROCESSES,
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
        policy_version: PROCESS_RUN_POLICY_VERSION.to_owned(),
        explanation: explanation.to_owned(),
    }
}

fn canonical_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn canonical_working_directory(value: &str) -> bool {
    value.len() <= MAXIMUM_WORKING_DIRECTORY_BYTES
        && (value.is_empty()
            || value.split('/').all(|segment| {
                !segment.is_empty()
                    && segment != "."
                    && segment != ".."
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            }))
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

/// Invalid direct-process model argument shape or value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProcessRunArgumentError {
    /// Arguments were not one JSON object.
    #[error("process arguments must be an object")]
    ExpectedObject,
    /// Required fields were missing or undeclared fields were present.
    #[error("process arguments have an invalid shape")]
    InvalidShape,
    /// Worker operation was absent or divergent.
    #[error("process operation is invalid")]
    InvalidOperation,
    /// Logical command identity was invalid.
    #[error("process command identity is invalid")]
    InvalidCommandId,
    /// Logical workspace identity was invalid.
    #[error("process workspace identity is invalid")]
    InvalidWorkspaceId,
    /// Working directory was absolute, traversing, or unbounded.
    #[error("process working directory is invalid")]
    InvalidWorkingDirectory,
    /// Argument vector was mistyped, unsafe, or unbounded.
    #[error("process argument vector is invalid")]
    InvalidArguments,
}

/// Invalid descriptor, grant, policy, approval, or dispatch evidence for a direct process.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProcessRunContractError {
    /// Trusted protocol worker identity was invalid.
    #[error("process worker identity is invalid")]
    InvalidWorkerIdentity,
    /// Configured grant was malformed or widened the fixed contract.
    #[error("process policy grant is invalid")]
    InvalidGrant,
    /// Workspace root was not a canonical bounded absolute host path.
    #[error("process workspace root is invalid")]
    InvalidWorkspaceRoot,
    /// Request, policy, or obligations did not match the fixed contract.
    #[error("process authorization evidence does not match")]
    AuthorizationMismatch,
    /// Approval evidence was missing, stale, or bound to another subject.
    #[error("process approval evidence is invalid")]
    InvalidApproval,
    /// Dispatch occurred outside the approved time boundary.
    #[error("process dispatch time is invalid")]
    InvalidDispatchTime,
    /// Generic descriptor evidence was invalid.
    #[error(transparent)]
    Descriptor(#[from] ToolDescriptorValidationError),
    /// Normalized process arguments were invalid.
    #[error(transparent)]
    Arguments(#[from] ProcessRunArgumentError),
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
        PROCESS_RUN_CAPABILITY, PROCESS_RUN_OPERATION, ProcessRunPolicyGrant,
        evaluate_process_run_policy, normalize_process_run_arguments, process_run_descriptor,
    };
    use crate::{PolicyDecision, PolicyRequest, sha256_digest};
    use mealy_domain::{ChannelBindingId, PolicyProfile, PrincipalId, RiskClass, RunId, TaskId};
    use serde_json::json;

    fn request_and_grant() -> (PolicyRequest, ProcessRunPolicyGrant) {
        let principal_id = PrincipalId::new();
        let channel_binding_id = ChannelBindingId::new();
        let task_id = TaskId::new();
        let run_id = RunId::new();
        let worker = sha256_digest(b"worker");
        let command = sha256_digest(b"command");
        let tool = process_run_descriptor(&worker).expect("descriptor");
        let grant = ProcessRunPolicyGrant {
            principal_id,
            channel_binding_id,
            task_id,
            run_id,
            tool_descriptor_digest: tool.descriptor_digest.clone(),
            worker_identity_digest: worker,
            command_id: "formatter".to_owned(),
            command_identity_digest: command.clone(),
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
            task_risk: RiskClass::High,
            tool,
            normalized_arguments: json!({
                "arguments": ["--check"],
                "commandId": "formatter",
                "operation": PROCESS_RUN_OPERATION,
                "workingDirectory": "src",
                "workspaceId": "project",
            }),
            target_resources: vec![
                format!("command://formatter@sha256:{command}"),
                "workspace://project/src".to_owned(),
            ],
            workspace_roots: vec!["/srv/project".to_owned()],
            resource_claims: vec![
                format!("process-executable:sha256:{command}"),
                "workspace-process:workspace://project/src".to_owned(),
            ],
            secret_references: Vec::new(),
            network_destinations: Vec::new(),
            requested_capability: PROCESS_RUN_CAPABILITY.to_owned(),
            requested_profile: PolicyProfile::WorkspaceWrite,
            enforceable_profiles: vec![PolicyProfile::WorkspaceWrite],
            evaluated_at_ms: 500,
            policy_version: super::PROCESS_RUN_POLICY_VERSION.to_owned(),
        };
        (request, grant)
    }

    #[test]
    fn arguments_are_direct_bounded_and_shell_free() {
        let (request, _) = request_and_grant();
        assert_eq!(
            normalize_process_run_arguments(&request.normalized_arguments).expect("arguments"),
            request.normalized_arguments
        );
        let mut invalid = request.normalized_arguments;
        invalid["workingDirectory"] = json!("../escape");
        assert!(normalize_process_run_arguments(&invalid).is_err());
    }

    #[test]
    fn exact_command_digest_and_workspace_require_approval() {
        let (request, grant) = request_and_grant();
        let evaluation = evaluate_process_run_policy(&request, &grant);
        assert_eq!(evaluation.decision, PolicyDecision::RequireApproval);
        assert!(evaluation.obligations.allow_process_spawn);
        assert_eq!(evaluation.obligations.maximum_processes, 16);
        let mut changed = request;
        changed.target_resources[0] =
            format!("command://formatter@sha256:{}", sha256_digest(b"other"));
        assert_eq!(
            evaluate_process_run_policy(&changed, &grant).decision,
            PolicyDecision::Deny
        );
    }
}
