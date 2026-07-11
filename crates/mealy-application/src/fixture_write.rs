use crate::{
    ApprovalRequestView, ApprovalSubject, ApprovalSubjectError, ExecutorMount, ExecutorRequest,
    ExecutorRequestError, FIXTURE_POLICY_VERSION, PolicyDecision, PolicyEvaluation,
    PolicyObligations, PolicyRequest, PolicyRequestError, ToolConcurrency, ToolDescriptor,
    ToolDescriptorValidationError, canonical_arguments_digest, derive_effect_idempotency_key,
    is_sha256_digest, sha256_digest,
};
use mealy_domain::{
    ApprovalDecision, ApprovalStatus, AttemptId, EffectClass, EffectId, ExecutorKind, FencingToken,
    IdempotencyClass, PolicyProfile, PrincipalId, RecoveryStrategy, RiskClass, RunId, TaskId,
};
use serde_json::{Value, json};
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// Stable tool identity for the sandboxed fixture write proof.
pub const FIXTURE_WRITE_FILE_TOOL_ID: &str = "fixture.write_file";
/// Canonical admitted-input prefix selecting the fixture-write agent path.
pub const FIXTURE_WRITE_INPUT_PREFIX: &str = "fixture.write_file ";
/// Exact operation understood by the trusted fixture worker.
pub const FIXTURE_WRITE_FILE_OPERATION: &str = "write_file";
/// Logical capability required by the fixture write contract.
pub const FIXTURE_WRITE_CAPABILITY: &str = "write:workspace";
/// Fixed sandbox mount point for the one writable workspace root.
pub const FIXTURE_WRITE_SANDBOX_ROOT: &str = "/workspace";
/// Hard wall-clock bound selected by the fixture contract.
pub const FIXTURE_WRITE_MAXIMUM_DURATION_MS: u64 = 2_000;
/// Hard aggregate worker-output bound selected by the fixture contract.
pub const FIXTURE_WRITE_MAXIMUM_OUTPUT_BYTES: u64 = 16 * 1_024;
/// Hard virtual-address-space bound selected by the fixture contract.
pub const FIXTURE_WRITE_MAXIMUM_MEMORY_BYTES: u64 = 256 * 1_024 * 1_024;
/// Maximum number of Unicode scalar values accepted as fixture file content.
pub const FIXTURE_WRITE_MAXIMUM_CONTENT_CHARACTERS: usize = 8 * 1_024;

const FIXTURE_WRITE_TOOL_VERSION: &str = "1";
const FIXTURE_WRITE_MAXIMUM_CONTENT_BYTES: usize = 48 * 1_024;
const FIXTURE_WRITE_MAXIMUM_RELATIVE_PATH_BYTES: usize = 256;
const FIXTURE_WRITE_MAXIMUM_WORKSPACE_PATH_BYTES: usize = 512;
const FIXTURE_WRITE_EXPLANATION: &str = "fixture_write_requires_approval";

/// Exact grant for proposing one approval-gated fixture write in one workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureWritePolicyGrant {
    /// Only this principal may propose the write.
    pub principal_id: PrincipalId,
    /// Only this verified channel binding may convey the proposal.
    pub channel_binding_id: mealy_domain::ChannelBindingId,
    /// Task to which the write is scoped.
    pub task_id: TaskId,
    /// Agent run to which the write is scoped.
    pub run_id: RunId,
    /// Exact generic descriptor digest accepted by the grant.
    pub tool_descriptor_digest: String,
    /// SHA-256 identity of the exact trusted fixture worker bytes.
    pub worker_identity_digest: String,
    /// Exact canonical host workspace that may become writable after approval.
    pub workspace_root: String,
    /// Exact logical capability accepted by this grant.
    pub capability: String,
    /// Exact enforceable sandbox profile accepted by this grant.
    pub profile: PolicyProfile,
    /// First evaluation time accepted by the grant.
    pub valid_from_ms: i64,
    /// Exclusive expiry of the grant.
    pub expires_at_ms: i64,
}

impl FixtureWritePolicyGrant {
    /// Validates every fixed and caller-supplied grant boundary.
    ///
    /// # Errors
    ///
    /// Returns [`FixtureWriteContractError::InvalidGrant`] when any grant field could widen the
    /// deterministic fixture contract.
    pub fn validate(&self) -> Result<(), FixtureWriteContractError> {
        if self.valid_from_ms < 0
            || self.expires_at_ms <= self.valid_from_ms
            || !canonical_workspace_root(&self.workspace_root)
            || self.capability != FIXTURE_WRITE_CAPABILITY
            || self.profile != PolicyProfile::WorkspaceWrite
            || !is_sha256_digest(&self.worker_identity_digest)
        {
            return Err(FixtureWriteContractError::InvalidGrant);
        }
        let descriptor = fixture_write_file_descriptor(&self.worker_identity_digest)
            .map_err(|_| FixtureWriteContractError::InvalidGrant)?;
        if self.tool_descriptor_digest != descriptor.descriptor_digest {
            return Err(FixtureWriteContractError::InvalidGrant);
        }
        Ok(())
    }
}

/// Inputs needed to build one approved, fenced fixture-write executor request.
#[derive(Clone, Copy)]
pub struct FixtureWriteDispatch<'a> {
    /// Exact deterministic policy input retained with the effect.
    pub policy_request: &'a PolicyRequest,
    /// Exact approval-gated policy outcome retained with the effect.
    pub policy_evaluation: &'a PolicyEvaluation,
    /// Exact grant against which the retained policy outcome is re-evaluated.
    pub grant: &'a FixtureWritePolicyGrant,
    /// Current durable approval projection for the exact subject.
    pub approval: &'a ApprovalRequestView,
    /// Effect whose stable key and approval subject are being dispatched.
    pub effect_id: EffectId,
    /// Fresh bounded attempt receiving this one-use capability.
    pub attempt_id: AttemptId,
    /// Current lease fence copied into worker evidence.
    pub fencing_token: FencingToken,
    /// Opaque one-use capability presented only to the worker invocation.
    pub capability_token: &'a str,
    /// Dispatch time used to enforce the approval subject's exclusive expiry.
    pub dispatched_at_ms: i64,
}

/// Builds the exact generic descriptor for the trusted sandbox fixture worker.
///
/// The digest argument is lowercase hexadecimal SHA-256 over the exact worker executable bytes.
///
/// # Errors
///
/// Returns [`FixtureWriteContractError`] when the worker digest or constructed descriptor is not
/// canonical.
pub fn fixture_write_file_descriptor(
    worker_identity_digest: &str,
) -> Result<ToolDescriptor, FixtureWriteContractError> {
    if !is_sha256_digest(worker_identity_digest) {
        return Err(FixtureWriteContractError::InvalidWorkerIdentity);
    }
    let input_schema = json!({
        "additionalProperties": false,
        "properties": {
            "content": {
                "maxLength": FIXTURE_WRITE_MAXIMUM_CONTENT_CHARACTERS,
                "type": "string"
            },
            "operation": {
                "const": FIXTURE_WRITE_FILE_OPERATION,
                "type": "string"
            },
            "relativePath": {
                "maxLength": FIXTURE_WRITE_MAXIMUM_RELATIVE_PATH_BYTES,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9._/-]+$",
                "type": "string"
            }
        },
        "required": ["content", "operation", "relativePath"],
        "type": "object"
    });
    let output_schema = json!({
        "additionalProperties": false,
        "properties": {
            "bytesWritten": {"minimum": 0, "type": "integer"},
            "contentDigest": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "relativePath": {"type": "string"}
        },
        "required": ["bytesWritten", "contentDigest", "relativePath"],
        "type": "object"
    });
    let mut descriptor = ToolDescriptor {
        tool_id: FIXTURE_WRITE_FILE_TOOL_ID.to_owned(),
        version: FIXTURE_WRITE_TOOL_VERSION.to_owned(),
        input_schema_digest: sha256_digest(input_schema.to_string().as_bytes()),
        output_schema_digest: sha256_digest(output_schema.to_string().as_bytes()),
        input_schema,
        output_schema,
        descriptor_digest: String::new(),
        effect_class: EffectClass::Idempotent,
        risk_class: RiskClass::Medium,
        required_capabilities: vec![FIXTURE_WRITE_CAPABILITY.to_owned()],
        timeout: Duration::from_millis(FIXTURE_WRITE_MAXIMUM_DURATION_MS),
        maximum_output_bytes: FIXTURE_WRITE_MAXIMUM_OUTPUT_BYTES,
        concurrency: ToolConcurrency::Serial,
        conflict_key_templates: vec!["workspace-write:{relativePath}".to_owned()],
        idempotency: IdempotencyClass::Keyed,
        recovery: RecoveryStrategy::NeverRetry,
        executor: ExecutorKind::Sandbox,
        executable_identity_digest: worker_identity_digest.to_owned(),
    };
    descriptor.descriptor_digest = descriptor.computed_descriptor_digest()?;
    descriptor.validate()?;
    Ok(descriptor)
}

/// Normalizes and validates the exact fixture worker argument envelope.
///
/// # Errors
///
/// Returns [`FixtureWriteArgumentError`] for a missing, extra, mistyped, unsafe, or unbounded
/// field.
pub fn normalize_fixture_write_file_arguments(
    arguments: &Value,
) -> Result<Value, FixtureWriteArgumentError> {
    let object = arguments
        .as_object()
        .ok_or(FixtureWriteArgumentError::ExpectedObject)?;
    if object.len() != 3
        || !["content", "operation", "relativePath"]
            .iter()
            .all(|field| object.contains_key(*field))
    {
        return Err(FixtureWriteArgumentError::InvalidShape);
    }
    let operation = object
        .get("operation")
        .and_then(Value::as_str)
        .ok_or(FixtureWriteArgumentError::InvalidOperation)?;
    if operation != FIXTURE_WRITE_FILE_OPERATION {
        return Err(FixtureWriteArgumentError::InvalidOperation);
    }
    let relative_path = object
        .get("relativePath")
        .and_then(Value::as_str)
        .ok_or(FixtureWriteArgumentError::InvalidRelativePath)?;
    if !canonical_relative_path(relative_path) {
        return Err(FixtureWriteArgumentError::InvalidRelativePath);
    }
    let content = object
        .get("content")
        .and_then(Value::as_str)
        .ok_or(FixtureWriteArgumentError::InvalidContent)?;
    if content.chars().count() > FIXTURE_WRITE_MAXIMUM_CONTENT_CHARACTERS
        || content.len() > FIXTURE_WRITE_MAXIMUM_CONTENT_BYTES
    {
        return Err(FixtureWriteArgumentError::InvalidContent);
    }
    Ok(json!({
        "content": content,
        "operation": FIXTURE_WRITE_FILE_OPERATION,
        "relativePath": relative_path,
    }))
}

/// Evaluates the exact approval-gated fixture write rule and denies every mismatch.
#[must_use]
pub fn evaluate_fixture_write_policy(
    request: &PolicyRequest,
    grant: &FixtureWritePolicyGrant,
) -> PolicyEvaluation {
    let deny = |explanation: &str| denied_evaluation(request, explanation);
    if request.validate().is_err() || grant.validate().is_err() {
        return deny("invalid_fixture_write_request");
    }
    if request.principal_id != grant.principal_id
        || request.channel_binding_id != grant.channel_binding_id
        || request.task_id != grant.task_id
        || request.run_id != grant.run_id
    {
        return deny("fixture_write_scope_not_granted");
    }
    if request.evaluated_at_ms < grant.valid_from_ms
        || request.evaluated_at_ms >= grant.expires_at_ms
    {
        return deny("fixture_write_grant_not_current");
    }
    let Ok(validated) = validate_contract_request(request) else {
        return deny("no_matching_fixture_write_rule");
    };
    if validated.workspace_root != grant.workspace_root
        || request.tool.descriptor_digest != grant.tool_descriptor_digest
        || request.tool.executable_identity_digest != grant.worker_identity_digest
        || request.requested_capability != grant.capability
        || request.requested_profile != grant.profile
    {
        return deny("no_matching_fixture_write_rule");
    }
    PolicyEvaluation {
        decision: PolicyDecision::RequireApproval,
        obligations: expected_obligations(&validated.workspace_root, &grant.worker_identity_digest),
        policy_version: FIXTURE_POLICY_VERSION.to_owned(),
        explanation: FIXTURE_WRITE_EXPLANATION.to_owned(),
    }
}

/// Constructs the immutable owner-facing approval subject for one fixture write.
///
/// # Errors
///
/// Returns [`FixtureWriteContractError`] when the request is not the exact fixture write contract
/// or the approval expiry does not follow its policy evaluation time.
pub fn fixture_write_approval_subject(
    effect_id: EffectId,
    request: &PolicyRequest,
    expires_at_ms: i64,
) -> Result<ApprovalSubject, FixtureWriteContractError> {
    let validated = validate_contract_request(request)?;
    if expires_at_ms <= request.evaluated_at_ms {
        return Err(FixtureWriteContractError::InvalidApproval);
    }
    let subject = ApprovalSubject {
        principal_id: request.principal_id,
        task_id: request.task_id,
        effect_id,
        tool_id: request.tool.tool_id.clone(),
        tool_version: request.tool.version.clone(),
        canonical_arguments_digest: canonical_arguments_digest(&validated.normalized_arguments),
        capability_scope: FIXTURE_WRITE_CAPABILITY.to_owned(),
        target_resources: request.target_resources.clone(),
        executable_identity_digest: request.tool.executable_identity_digest.clone(),
        policy_version: FIXTURE_POLICY_VERSION.to_owned(),
        expires_at_ms,
    };
    subject.validate()?;
    Ok(subject)
}

/// Builds one request whose authority is exactly equal to the approved policy obligations.
///
/// # Errors
///
/// Returns [`FixtureWriteContractError`] when policy, approval, token, fence, arguments, or any
/// obligation is missing, stale, or broader than the fixture contract.
pub fn build_fixture_write_executor_request(
    dispatch: FixtureWriteDispatch<'_>,
) -> Result<ExecutorRequest, FixtureWriteContractError> {
    dispatch.grant.validate()?;
    let validated = validate_contract_request(dispatch.policy_request)?;
    let expected_evaluation =
        evaluate_fixture_write_policy(dispatch.policy_request, dispatch.grant);
    let expected_obligations = expected_obligations(
        &validated.workspace_root,
        &dispatch.policy_request.tool.executable_identity_digest,
    );
    if expected_evaluation.decision != PolicyDecision::RequireApproval
        || dispatch.policy_evaluation != &expected_evaluation
        || dispatch.policy_evaluation.obligations != expected_obligations
    {
        return Err(FixtureWriteContractError::AuthorizationMismatch);
    }
    if dispatch.dispatched_at_ms < dispatch.policy_request.evaluated_at_ms
        || dispatch.dispatched_at_ms < 0
        || dispatch.dispatched_at_ms >= dispatch.approval.subject.expires_at_ms
    {
        return Err(FixtureWriteContractError::InvalidDispatchTime);
    }
    let (Some(requested_at_ms), Some(resolved_at_ms)) = (
        system_time_milliseconds(dispatch.approval.requested_at),
        dispatch
            .approval
            .resolved_at
            .and_then(system_time_milliseconds),
    ) else {
        return Err(FixtureWriteContractError::InvalidApproval);
    };
    if requested_at_ms > resolved_at_ms || resolved_at_ms > dispatch.dispatched_at_ms {
        return Err(FixtureWriteContractError::InvalidApproval);
    }
    let expected_subject = fixture_write_approval_subject(
        dispatch.effect_id,
        dispatch.policy_request,
        dispatch.grant.expires_at_ms,
    )?;
    if dispatch.approval.effect_id != dispatch.effect_id
        || dispatch.approval.status != ApprovalStatus::Approved
        || dispatch.approval.decision != Some(ApprovalDecision::Approve)
        || dispatch.approval.resolved_at.is_none()
        || dispatch.approval.subject != expected_subject
        || dispatch.approval.subject_digest != expected_subject.subject_digest()?
    {
        return Err(FixtureWriteContractError::InvalidApproval);
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
        profile: expected_obligations.profile,
        readable_roots: Vec::new(),
        writable_roots: vec![ExecutorMount {
            host_path: validated.workspace_root,
            sandbox_path: FIXTURE_WRITE_SANDBOX_ROOT.to_owned(),
        }],
        network_destinations: Vec::new(),
        secret_handles: Vec::new(),
        allow_process_spawn: false,
        allowed_environment_variables: Vec::new(),
        idempotency_key: Some(derive_effect_idempotency_key(dispatch.effect_id)),
        arguments_digest: sha256_digest(validated.normalized_arguments.to_string().as_bytes()),
        normalized_arguments: validated.normalized_arguments,
        maximum_duration_ms: expected_obligations.maximum_duration_ms,
        maximum_output_bytes: expected_obligations.maximum_output_bytes,
        maximum_memory_bytes: expected_obligations.maximum_memory_bytes,
        maximum_processes: expected_obligations.maximum_processes,
    };
    request.validate()?;
    Ok(request)
}

#[derive(Debug)]
struct ValidatedFixtureWrite {
    normalized_arguments: Value,
    workspace_root: String,
}

fn validate_contract_request(
    request: &PolicyRequest,
) -> Result<ValidatedFixtureWrite, FixtureWriteContractError> {
    request.validate()?;
    if request.policy_version != FIXTURE_POLICY_VERSION
        || request.agent_role != "assistant"
        || request.task_risk != RiskClass::Medium
        || request.requested_capability != FIXTURE_WRITE_CAPABILITY
        || request.requested_profile != PolicyProfile::WorkspaceWrite
        || request.enforceable_profiles != [PolicyProfile::WorkspaceWrite]
        || !request.secret_references.is_empty()
        || !request.network_destinations.is_empty()
    {
        return Err(FixtureWriteContractError::AuthorizationMismatch);
    }
    let expected_descriptor =
        fixture_write_file_descriptor(&request.tool.executable_identity_digest)?;
    if request.tool != expected_descriptor {
        return Err(FixtureWriteContractError::AuthorizationMismatch);
    }
    let normalized_arguments =
        normalize_fixture_write_file_arguments(&request.normalized_arguments)?;
    if normalized_arguments != request.normalized_arguments || request.workspace_roots.len() != 1 {
        return Err(FixtureWriteContractError::AuthorizationMismatch);
    }
    let workspace_root = request.workspace_roots[0].clone();
    if !canonical_workspace_root(&workspace_root) {
        return Err(FixtureWriteContractError::InvalidWorkspaceRoot);
    }
    let relative_path = normalized_arguments["relativePath"]
        .as_str()
        .ok_or(FixtureWriteContractError::AuthorizationMismatch)?;
    let target = format!("{workspace_root}/{relative_path}");
    let claim = format!("workspace-write:{target}");
    if request.target_resources != [target] || request.resource_claims != [claim] {
        return Err(FixtureWriteContractError::AuthorizationMismatch);
    }
    Ok(ValidatedFixtureWrite {
        normalized_arguments,
        workspace_root,
    })
}

fn expected_obligations(workspace_root: &str, worker_identity_digest: &str) -> PolicyObligations {
    PolicyObligations {
        profile: PolicyProfile::WorkspaceWrite,
        readable_paths: Vec::new(),
        writable_paths: vec![workspace_root.to_owned()],
        allowed_executable_identity_digests: vec![worker_identity_digest.to_owned()],
        allow_process_spawn: false,
        allowed_environment_variables: Vec::new(),
        network_destinations: Vec::new(),
        secret_references: Vec::new(),
        argument_rewrite: None,
        redactions: Vec::new(),
        maximum_duration_ms: FIXTURE_WRITE_MAXIMUM_DURATION_MS,
        maximum_output_bytes: FIXTURE_WRITE_MAXIMUM_OUTPUT_BYTES,
        maximum_memory_bytes: FIXTURE_WRITE_MAXIMUM_MEMORY_BYTES,
        maximum_processes: 0,
        validator_required: false,
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
            validator_required: false,
        },
        policy_version: request.policy_version.clone(),
        explanation: explanation.to_owned(),
    }
}

fn canonical_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= FIXTURE_WRITE_MAXIMUM_RELATIVE_PATH_BYTES
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
        && value.len() <= FIXTURE_WRITE_MAXIMUM_WORKSPACE_PATH_BYTES
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

/// Invalid fixture-write argument shape or value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FixtureWriteArgumentError {
    /// Arguments were not represented by one JSON object.
    #[error("fixture write arguments must be an object")]
    ExpectedObject,
    /// Required fields were missing or undeclared fields were present.
    #[error("fixture write arguments must contain exactly operation, relativePath, and content")]
    InvalidShape,
    /// Operation was missing, mistyped, or not the trusted worker operation.
    #[error("fixture write operation is invalid")]
    InvalidOperation,
    /// Relative path was missing, mistyped, unsafe, noncanonical, or oversized.
    #[error("fixture write relative path is invalid")]
    InvalidRelativePath,
    /// Content was missing, mistyped, or oversized.
    #[error("fixture write content is invalid")]
    InvalidContent,
}

/// Invalid descriptor, policy, approval, or executor evidence for a fixture write.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FixtureWriteContractError {
    /// Worker identity was not canonical lowercase SHA-256 evidence.
    #[error("fixture write worker identity is invalid")]
    InvalidWorkerIdentity,
    /// Configured grant was malformed or wider than the fixed fixture contract.
    #[error("fixture write policy grant is invalid")]
    InvalidGrant,
    /// Workspace root was not a bounded canonical absolute host path.
    #[error("fixture write workspace root is invalid")]
    InvalidWorkspaceRoot,
    /// Policy result or obligations did not exactly match the fixed contract.
    #[error("fixture write authorization evidence does not match")]
    AuthorizationMismatch,
    /// Durable approval did not approve the exact current subject.
    #[error("fixture write approval evidence is invalid")]
    InvalidApproval,
    /// Dispatch was before policy evaluation or at/after approval expiry.
    #[error("fixture write dispatch time is invalid")]
    InvalidDispatchTime,
    /// Generic descriptor evidence was invalid.
    #[error(transparent)]
    Descriptor(#[from] ToolDescriptorValidationError),
    /// Normalized write arguments were invalid.
    #[error(transparent)]
    Arguments(#[from] FixtureWriteArgumentError),
    /// Deterministic policy request evidence was invalid.
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
        FIXTURE_WRITE_CAPABILITY, FIXTURE_WRITE_EXPLANATION, FIXTURE_WRITE_FILE_OPERATION,
        FIXTURE_WRITE_FILE_TOOL_ID, FIXTURE_WRITE_MAXIMUM_CONTENT_CHARACTERS,
        FIXTURE_WRITE_MAXIMUM_DURATION_MS, FIXTURE_WRITE_MAXIMUM_MEMORY_BYTES,
        FIXTURE_WRITE_MAXIMUM_OUTPUT_BYTES, FIXTURE_WRITE_SANDBOX_ROOT, FixtureWriteArgumentError,
        FixtureWriteContractError, FixtureWriteDispatch, FixtureWritePolicyGrant,
        build_fixture_write_executor_request, evaluate_fixture_write_policy,
        fixture_write_approval_subject, fixture_write_file_descriptor,
        normalize_fixture_write_file_arguments,
    };
    use crate::{
        ApprovalRequestView, PolicyDecision, PolicyEvaluation, PolicyRequest,
        canonical_arguments_digest, derive_effect_idempotency_key, sha256_digest,
    };
    use mealy_domain::{
        ApprovalDecision, ApprovalId, ApprovalStatus, AttemptId, ChannelBindingId, EffectClass,
        EffectId, ExecutorKind, FencingToken, IdempotencyClass, PolicyProfile, PrincipalId,
        RecoveryStrategy, RiskClass, RunId, TaskId,
    };
    use serde_json::{Value, json};
    use std::time::{Duration, SystemTime};

    const WORKSPACE_ROOT: &str = "/var/lib/mealy/workspaces/fixture";

    fn worker_digest() -> String {
        sha256_digest(b"exact mealy fixture worker bytes")
    }

    fn arguments() -> Value {
        json!({
            "content": "approved fixture content",
            "operation": FIXTURE_WRITE_FILE_OPERATION,
            "relativePath": "reports/result.txt",
        })
    }

    fn request_and_grant() -> (PolicyRequest, FixtureWritePolicyGrant) {
        let principal_id = PrincipalId::new();
        let channel_binding_id = ChannelBindingId::new();
        let task_id = TaskId::new();
        let run_id = RunId::new();
        let worker_identity_digest = worker_digest();
        let tool = fixture_write_file_descriptor(&worker_identity_digest).expect("descriptor");
        let grant = FixtureWritePolicyGrant {
            principal_id,
            channel_binding_id,
            task_id,
            run_id,
            tool_descriptor_digest: tool.descriptor_digest.clone(),
            worker_identity_digest,
            workspace_root: WORKSPACE_ROOT.to_owned(),
            capability: FIXTURE_WRITE_CAPABILITY.to_owned(),
            profile: PolicyProfile::WorkspaceWrite,
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
            normalized_arguments: arguments(),
            target_resources: vec![format!("{WORKSPACE_ROOT}/reports/result.txt")],
            workspace_roots: vec![WORKSPACE_ROOT.to_owned()],
            resource_claims: vec![format!(
                "workspace-write:{WORKSPACE_ROOT}/reports/result.txt"
            )],
            secret_references: Vec::new(),
            network_destinations: Vec::new(),
            requested_capability: FIXTURE_WRITE_CAPABILITY.to_owned(),
            requested_profile: PolicyProfile::WorkspaceWrite,
            enforceable_profiles: vec![PolicyProfile::WorkspaceWrite],
            evaluated_at_ms: 500,
            policy_version: crate::FIXTURE_POLICY_VERSION.to_owned(),
        };
        (request, grant)
    }

    fn approved_evidence(
        request: &PolicyRequest,
        grant: &FixtureWritePolicyGrant,
        effect_id: EffectId,
    ) -> (PolicyEvaluation, ApprovalRequestView) {
        let evaluation = evaluate_fixture_write_policy(request, grant);
        let subject = fixture_write_approval_subject(effect_id, request, grant.expires_at_ms)
            .expect("approval subject");
        let subject_digest = subject.subject_digest().expect("subject digest");
        (
            evaluation,
            ApprovalRequestView {
                approval_id: ApprovalId::new(),
                effect_id,
                subject,
                subject_digest,
                status: ApprovalStatus::Approved,
                decision: Some(ApprovalDecision::Approve),
                requested_at: SystemTime::UNIX_EPOCH + Duration::from_millis(500),
                resolved_at: Some(SystemTime::UNIX_EPOCH + Duration::from_millis(600)),
            },
        )
    }

    fn dispatch<'a>(
        request: &'a PolicyRequest,
        evaluation: &'a PolicyEvaluation,
        approval: &'a ApprovalRequestView,
        grant: &'a FixtureWritePolicyGrant,
        effect_id: EffectId,
    ) -> FixtureWriteDispatch<'a> {
        FixtureWriteDispatch {
            policy_request: request,
            policy_evaluation: evaluation,
            grant,
            approval,
            effect_id,
            attempt_id: AttemptId::new(),
            fencing_token: FencingToken::new(7).expect("nonzero fence"),
            capability_token: "fixture-write-one-use-capability-token-0001",
            dispatched_at_ms: 700,
        }
    }

    fn reseal_approval(approval: &mut ApprovalRequestView) {
        approval.subject_digest = approval.subject.subject_digest().expect("valid subject");
    }

    #[test]
    fn descriptor_is_exact_and_bound_to_worker_bytes() {
        let digest = worker_digest();
        let descriptor = fixture_write_file_descriptor(&digest).expect("descriptor");
        descriptor.validate().expect("valid descriptor");
        assert_eq!(descriptor.tool_id, FIXTURE_WRITE_FILE_TOOL_ID);
        assert_eq!(descriptor.effect_class, EffectClass::Idempotent);
        assert_eq!(descriptor.risk_class, RiskClass::Medium);
        assert_eq!(descriptor.required_capabilities, [FIXTURE_WRITE_CAPABILITY]);
        assert_eq!(descriptor.timeout, Duration::from_secs(2));
        assert_eq!(
            descriptor.maximum_output_bytes,
            FIXTURE_WRITE_MAXIMUM_OUTPUT_BYTES
        );
        assert_eq!(descriptor.idempotency, IdempotencyClass::Keyed);
        assert_eq!(descriptor.recovery, RecoveryStrategy::NeverRetry);
        assert_eq!(descriptor.executor, ExecutorKind::Sandbox);
        assert_eq!(descriptor.executable_identity_digest, digest);
        assert_eq!(descriptor.input_schema["additionalProperties"], false);

        assert_eq!(
            fixture_write_file_descriptor("not-a-digest"),
            Err(FixtureWriteContractError::InvalidWorkerIdentity)
        );
        let other = fixture_write_file_descriptor(&sha256_digest(b"other worker"))
            .expect("other descriptor");
        assert_ne!(descriptor.descriptor_digest, other.descriptor_digest);
    }

    #[test]
    fn arguments_are_strictly_normalized_and_bounded() {
        let normalized = normalize_fixture_write_file_arguments(&arguments()).expect("arguments");
        assert_eq!(normalized, arguments());

        let invalid = [
            Value::Null,
            json!({}),
            json!({"operation": "write_file", "relativePath": "a"}),
            json!({"operation": "write_file", "relativePath": "a", "content": "", "extra": true}),
            json!({"operation": 1, "relativePath": "a", "content": ""}),
            json!({"operation": "read", "relativePath": "a", "content": ""}),
            json!({"operation": "write_file", "relativePath": 1, "content": ""}),
            json!({"operation": "write_file", "relativePath": "", "content": ""}),
            json!({"operation": "write_file", "relativePath": "/absolute", "content": ""}),
            json!({"operation": "write_file", "relativePath": "../escape", "content": ""}),
            json!({"operation": "write_file", "relativePath": "a/./b", "content": ""}),
            json!({"operation": "write_file", "relativePath": "a//b", "content": ""}),
            json!({"operation": "write_file", "relativePath": "a\\b", "content": ""}),
            json!({"operation": "write_file", "relativePath": "a", "content": 1}),
            json!({
                "operation": "write_file",
                "relativePath": "a",
                "content": "x".repeat(FIXTURE_WRITE_MAXIMUM_CONTENT_CHARACTERS + 1),
            }),
        ];
        for candidate in invalid {
            assert!(
                normalize_fixture_write_file_arguments(&candidate).is_err(),
                "accepted invalid arguments: {candidate}"
            );
        }
        assert_eq!(
            normalize_fixture_write_file_arguments(&json!([])),
            Err(FixtureWriteArgumentError::ExpectedObject)
        );
    }

    #[test]
    fn exact_policy_match_requires_approval_with_least_privilege_obligations() {
        let (request, grant) = request_and_grant();
        let evaluation = evaluate_fixture_write_policy(&request, &grant);
        assert_eq!(evaluation.decision, PolicyDecision::RequireApproval);
        assert_eq!(evaluation.explanation, FIXTURE_WRITE_EXPLANATION);
        let obligations = evaluation.obligations;
        assert_eq!(obligations.profile, PolicyProfile::WorkspaceWrite);
        assert!(obligations.readable_paths.is_empty());
        assert_eq!(obligations.writable_paths, [WORKSPACE_ROOT]);
        assert_eq!(
            obligations.allowed_executable_identity_digests,
            [worker_digest()]
        );
        assert!(!obligations.allow_process_spawn);
        assert!(obligations.allowed_environment_variables.is_empty());
        assert!(obligations.network_destinations.is_empty());
        assert!(obligations.secret_references.is_empty());
        assert_eq!(obligations.argument_rewrite, None);
        assert!(obligations.redactions.is_empty());
        assert_eq!(
            obligations.maximum_duration_ms,
            FIXTURE_WRITE_MAXIMUM_DURATION_MS
        );
        assert_eq!(
            obligations.maximum_output_bytes,
            FIXTURE_WRITE_MAXIMUM_OUTPUT_BYTES
        );
        assert_eq!(
            obligations.maximum_memory_bytes,
            FIXTURE_WRITE_MAXIMUM_MEMORY_BYTES
        );
        assert_eq!(obligations.maximum_processes, 0);
        assert!(!obligations.validator_required);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_policy_request_axis_mutation_fails_closed() {
        let (original, grant) = request_and_grant();
        let mut mutations = Vec::new();

        let mut changed = original.clone();
        changed.principal_id = PrincipalId::new();
        mutations.push(("principal", changed));
        let mut changed = original.clone();
        changed.channel_binding_id = ChannelBindingId::new();
        mutations.push(("channel", changed));
        let mut changed = original.clone();
        changed.task_id = TaskId::new();
        mutations.push(("task", changed));
        let mut changed = original.clone();
        changed.run_id = RunId::new();
        mutations.push(("run", changed));
        let mut changed = original.clone();
        changed.agent_role = "reviewer".to_owned();
        mutations.push(("agent role", changed));
        let mut changed = original.clone();
        changed.task_risk = RiskClass::High;
        mutations.push(("task risk", changed));
        let mut changed = original.clone();
        changed.tool = fixture_write_file_descriptor(&sha256_digest(b"other worker"))
            .expect("other descriptor");
        mutations.push(("descriptor", changed));
        let mut changed = original.clone();
        changed.normalized_arguments["operation"] = json!("other");
        mutations.push(("operation", changed));
        let mut changed = original.clone();
        changed.normalized_arguments["relativePath"] = json!("reports/other.txt");
        mutations.push(("relative path evidence", changed));
        let mut changed = original.clone();
        changed.target_resources = vec![format!("{WORKSPACE_ROOT}/other.txt")];
        mutations.push(("target", changed));
        let mut changed = original.clone();
        changed.workspace_roots = vec!["/var/lib/mealy/workspaces/other".to_owned()];
        mutations.push(("workspace", changed));
        let mut changed = original.clone();
        changed.resource_claims = vec!["workspace-write:other".to_owned()];
        mutations.push(("resource claim", changed));
        let mut changed = original.clone();
        changed.secret_references = vec!["secret://fixture".to_owned()];
        mutations.push(("secret", changed));
        let mut changed = original.clone();
        changed.network_destinations = vec!["example.invalid:443".to_owned()];
        mutations.push(("network", changed));
        let mut changed = original.clone();
        changed.requested_capability = "write:other".to_owned();
        mutations.push(("capability", changed));
        let mut changed = original.clone();
        changed.requested_profile = PolicyProfile::FullTrust;
        changed.enforceable_profiles =
            vec![PolicyProfile::WorkspaceWrite, PolicyProfile::FullTrust];
        mutations.push(("profile", changed));
        let mut changed = original.clone();
        changed.enforceable_profiles = vec![PolicyProfile::Observe, PolicyProfile::WorkspaceWrite];
        mutations.push(("host profile evidence", changed));
        let mut changed = original.clone();
        changed.evaluated_at_ms = grant.expires_at_ms;
        mutations.push(("time", changed));
        let mut changed = original;
        changed.policy_version = "unknown-policy".to_owned();
        mutations.push(("policy version", changed));

        for (axis, mutation) in mutations {
            let evaluation = evaluate_fixture_write_policy(&mutation, &grant);
            assert_eq!(
                evaluation.decision,
                PolicyDecision::Deny,
                "{axis} mutation did not deny"
            );
            assert_eq!(evaluation.obligations.maximum_duration_ms, 0);
            assert_eq!(evaluation.obligations.maximum_output_bytes, 0);
            assert_eq!(evaluation.obligations.maximum_memory_bytes, 0);
            assert!(evaluation.obligations.writable_paths.is_empty());
            assert!(
                evaluation
                    .obligations
                    .allowed_executable_identity_digests
                    .is_empty()
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_grant_axis_mutation_fails_closed() {
        let (request, original) = request_and_grant();
        let mut mutations = Vec::new();
        let mut changed = original.clone();
        changed.principal_id = PrincipalId::new();
        mutations.push(("principal", changed));
        let mut changed = original.clone();
        changed.channel_binding_id = ChannelBindingId::new();
        mutations.push(("channel", changed));
        let mut changed = original.clone();
        changed.task_id = TaskId::new();
        mutations.push(("task", changed));
        let mut changed = original.clone();
        changed.run_id = RunId::new();
        mutations.push(("run", changed));
        let mut changed = original.clone();
        changed.tool_descriptor_digest = sha256_digest(b"other descriptor");
        mutations.push(("descriptor", changed));
        let mut changed = original.clone();
        changed.worker_identity_digest = sha256_digest(b"other worker");
        mutations.push(("worker", changed));
        let mut changed = original.clone();
        changed.workspace_root = "/var/lib/mealy/workspaces/other".to_owned();
        mutations.push(("workspace", changed));
        let mut changed = original.clone();
        changed.capability = "write:other".to_owned();
        mutations.push(("capability", changed));
        let mut changed = original.clone();
        changed.profile = PolicyProfile::FullTrust;
        mutations.push(("profile", changed));
        let mut changed = original.clone();
        changed.valid_from_ms = 600;
        mutations.push(("not yet valid", changed));
        let mut changed = original;
        changed.expires_at_ms = 500;
        mutations.push(("expired", changed));

        for (axis, mutation) in mutations {
            assert_eq!(
                evaluate_fixture_write_policy(&request, &mutation).decision,
                PolicyDecision::Deny,
                "{axis} grant mutation did not deny"
            );
        }
    }

    #[test]
    fn approval_subject_binds_exact_content_and_target() {
        let (request, grant) = request_and_grant();
        let effect_id = EffectId::new();
        let original = fixture_write_approval_subject(effect_id, &request, grant.expires_at_ms)
            .expect("subject");
        assert_eq!(
            original.canonical_arguments_digest,
            canonical_arguments_digest(&request.normalized_arguments)
        );

        let mut changed = request;
        changed.normalized_arguments["content"] = json!("different approved content");
        assert_eq!(
            evaluate_fixture_write_policy(&changed, &grant).decision,
            PolicyDecision::RequireApproval
        );
        let changed_subject =
            fixture_write_approval_subject(effect_id, &changed, grant.expires_at_ms)
                .expect("changed subject");
        assert_ne!(
            original.subject_digest().expect("original digest"),
            changed_subject.subject_digest().expect("changed digest")
        );
    }

    #[test]
    fn executor_builder_maps_only_exact_approved_obligations() {
        let (request, grant) = request_and_grant();
        let effect_id = EffectId::new();
        let (evaluation, approval) = approved_evidence(&request, &grant, effect_id);
        let executor = build_fixture_write_executor_request(dispatch(
            &request,
            &evaluation,
            &approval,
            &grant,
            effect_id,
        ))
        .expect("executor request");
        executor.validate().expect("valid executor request");
        assert_eq!(executor.effect_id, effect_id);
        assert_eq!(executor.fencing_token.get(), 7);
        assert_eq!(executor.profile, PolicyProfile::WorkspaceWrite);
        assert!(executor.readable_roots.is_empty());
        assert_eq!(executor.writable_roots.len(), 1);
        assert_eq!(executor.writable_roots[0].host_path, WORKSPACE_ROOT);
        assert_eq!(
            executor.writable_roots[0].sandbox_path,
            FIXTURE_WRITE_SANDBOX_ROOT
        );
        assert_eq!(executor.executable_identity_digest, worker_digest());
        assert!(executor.network_destinations.is_empty());
        assert!(executor.secret_handles.is_empty());
        assert!(!executor.allow_process_spawn);
        assert!(executor.allowed_environment_variables.is_empty());
        assert_eq!(
            executor.idempotency_key,
            Some(derive_effect_idempotency_key(effect_id))
        );
        assert_eq!(executor.normalized_arguments, arguments());
        assert_eq!(
            executor.maximum_duration_ms,
            FIXTURE_WRITE_MAXIMUM_DURATION_MS
        );
        assert_eq!(
            executor.maximum_output_bytes,
            FIXTURE_WRITE_MAXIMUM_OUTPUT_BYTES
        );
        assert_eq!(
            executor.maximum_memory_bytes,
            FIXTURE_WRITE_MAXIMUM_MEMORY_BYTES
        );
        assert_eq!(executor.maximum_processes, 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_obligation_expansion_is_rejected() {
        let (request, grant) = request_and_grant();
        let effect_id = EffectId::new();
        let (original, approval) = approved_evidence(&request, &grant, effect_id);
        let mut mutations = Vec::new();

        let mut changed = original.clone();
        changed.obligations.profile = PolicyProfile::FullTrust;
        mutations.push(("profile", changed));
        let mut changed = original.clone();
        changed.obligations.readable_paths = vec![WORKSPACE_ROOT.to_owned()];
        mutations.push(("read path", changed));
        let mut changed = original.clone();
        changed.obligations.writable_paths.push("/other".to_owned());
        mutations.push(("write path", changed));
        let mut changed = original.clone();
        changed
            .obligations
            .allowed_executable_identity_digests
            .push(sha256_digest(b"other worker"));
        mutations.push(("executable", changed));
        let mut changed = original.clone();
        changed.obligations.allow_process_spawn = true;
        mutations.push(("spawn", changed));
        let mut changed = original.clone();
        changed.obligations.allowed_environment_variables = vec!["HOME".to_owned()];
        mutations.push(("environment", changed));
        let mut changed = original.clone();
        changed.obligations.network_destinations = vec!["example.invalid:443".to_owned()];
        mutations.push(("network", changed));
        let mut changed = original.clone();
        changed.obligations.secret_references = vec!["secret://fixture".to_owned()];
        mutations.push(("secret", changed));
        let mut changed = original.clone();
        changed.obligations.argument_rewrite = Some(arguments());
        mutations.push(("argument rewrite", changed));
        let mut changed = original.clone();
        changed.obligations.redactions = vec!["content".to_owned()];
        mutations.push(("redactions", changed));
        let mut changed = original.clone();
        changed.obligations.maximum_duration_ms += 1;
        mutations.push(("duration", changed));
        let mut changed = original.clone();
        changed.obligations.maximum_output_bytes += 1;
        mutations.push(("output", changed));
        let mut changed = original.clone();
        changed.obligations.maximum_memory_bytes += 1;
        mutations.push(("memory", changed));
        let mut changed = original.clone();
        changed.obligations.maximum_processes = 1;
        mutations.push(("processes", changed));
        let mut changed = original.clone();
        changed.obligations.validator_required = true;
        mutations.push(("validator", changed));
        let mut changed = original.clone();
        changed.decision = PolicyDecision::Allow;
        mutations.push(("decision", changed));
        let mut changed = original.clone();
        changed.policy_version = "other-policy".to_owned();
        mutations.push(("policy version", changed));
        let mut changed = original;
        changed.explanation = "other".to_owned();
        mutations.push(("explanation", changed));

        for (axis, mutation) in mutations {
            assert_eq!(
                build_fixture_write_executor_request(dispatch(
                    &request, &mutation, &approval, &grant, effect_id,
                )),
                Err(FixtureWriteContractError::AuthorizationMismatch),
                "{axis} obligation mutation was accepted"
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_approval_subject_axis_mutation_is_rejected() {
        let (request, grant) = request_and_grant();
        let effect_id = EffectId::new();
        let (evaluation, original) = approved_evidence(&request, &grant, effect_id);
        let mut mutations = Vec::new();

        let mut changed = original.clone();
        changed.effect_id = EffectId::new();
        mutations.push(("view effect", changed));
        let mut changed = original.clone();
        changed.subject.principal_id = PrincipalId::new();
        reseal_approval(&mut changed);
        mutations.push(("principal", changed));
        let mut changed = original.clone();
        changed.subject.task_id = TaskId::new();
        reseal_approval(&mut changed);
        mutations.push(("task", changed));
        let mut changed = original.clone();
        changed.subject.effect_id = EffectId::new();
        reseal_approval(&mut changed);
        mutations.push(("subject effect", changed));
        let mut changed = original.clone();
        changed.subject.tool_id.push_str(".changed");
        reseal_approval(&mut changed);
        mutations.push(("tool ID", changed));
        let mut changed = original.clone();
        changed.subject.tool_version.push_str(".changed");
        reseal_approval(&mut changed);
        mutations.push(("tool version", changed));
        let mut changed = original.clone();
        changed.subject.canonical_arguments_digest = sha256_digest(b"other arguments");
        reseal_approval(&mut changed);
        mutations.push(("arguments", changed));
        let mut changed = original.clone();
        changed.subject.capability_scope = "write:other".to_owned();
        reseal_approval(&mut changed);
        mutations.push(("capability", changed));
        let mut changed = original.clone();
        changed
            .subject
            .target_resources
            .push(format!("{WORKSPACE_ROOT}/reports/second.txt"));
        changed.subject.target_resources.sort();
        reseal_approval(&mut changed);
        mutations.push(("target", changed));
        let mut changed = original.clone();
        changed.subject.executable_identity_digest = sha256_digest(b"other worker");
        reseal_approval(&mut changed);
        mutations.push(("worker", changed));
        let mut changed = original.clone();
        changed.subject.policy_version = "other-policy".to_owned();
        reseal_approval(&mut changed);
        mutations.push(("policy", changed));
        let mut changed = original.clone();
        changed.subject.expires_at_ms += 1;
        reseal_approval(&mut changed);
        mutations.push(("expiry", changed));
        let mut changed = original.clone();
        changed.subject_digest = sha256_digest(b"forged digest");
        mutations.push(("subject digest", changed));
        let mut changed = original.clone();
        changed.status = ApprovalStatus::Pending;
        mutations.push(("status", changed));
        let mut changed = original.clone();
        changed.decision = Some(ApprovalDecision::Deny);
        mutations.push(("decision", changed));
        let mut changed = original.clone();
        changed.resolved_at = None;
        mutations.push(("resolution", changed));
        let mut changed = original;
        changed.resolved_at = Some(SystemTime::UNIX_EPOCH + Duration::from_millis(800));
        mutations.push(("resolution time", changed));

        for (axis, mutation) in mutations {
            assert_eq!(
                build_fixture_write_executor_request(dispatch(
                    &request,
                    &evaluation,
                    &mutation,
                    &grant,
                    effect_id,
                )),
                Err(FixtureWriteContractError::InvalidApproval),
                "{axis} approval mutation was accepted"
            );
        }
    }

    #[test]
    fn stale_or_mutated_approval_and_capability_fail_closed() {
        let (request, grant) = request_and_grant();
        let effect_id = EffectId::new();
        let (evaluation, original) = approved_evidence(&request, &grant, effect_id);

        let mut changed = original.clone();
        changed.status = ApprovalStatus::Pending;
        assert_eq!(
            build_fixture_write_executor_request(dispatch(
                &request,
                &evaluation,
                &changed,
                &grant,
                effect_id,
            )),
            Err(FixtureWriteContractError::InvalidApproval)
        );
        let mut changed = original.clone();
        changed.decision = Some(ApprovalDecision::Deny);
        assert_eq!(
            build_fixture_write_executor_request(dispatch(
                &request,
                &evaluation,
                &changed,
                &grant,
                effect_id,
            )),
            Err(FixtureWriteContractError::InvalidApproval)
        );
        let mut changed = original.clone();
        changed.subject.canonical_arguments_digest = sha256_digest(b"other arguments");
        changed.subject_digest = changed.subject.subject_digest().expect("resealed subject");
        assert_eq!(
            build_fixture_write_executor_request(dispatch(
                &request,
                &evaluation,
                &changed,
                &grant,
                effect_id,
            )),
            Err(FixtureWriteContractError::InvalidApproval)
        );
        let mut changed = original.clone();
        changed.subject_digest = sha256_digest(b"forged subject digest");
        assert_eq!(
            build_fixture_write_executor_request(dispatch(
                &request,
                &evaluation,
                &changed,
                &grant,
                effect_id,
            )),
            Err(FixtureWriteContractError::InvalidApproval)
        );

        let mut stale = dispatch(&request, &evaluation, &original, &grant, effect_id);
        stale.dispatched_at_ms = original.subject.expires_at_ms;
        assert_eq!(
            build_fixture_write_executor_request(stale),
            Err(FixtureWriteContractError::InvalidDispatchTime)
        );
        let mut bad_token = dispatch(&request, &evaluation, &original, &grant, effect_id);
        bad_token.capability_token = "short";
        assert!(matches!(
            build_fixture_write_executor_request(bad_token),
            Err(FixtureWriteContractError::Executor(_))
        ));
    }
}
