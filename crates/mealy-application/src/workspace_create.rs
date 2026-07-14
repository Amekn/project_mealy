use crate::{
    ApprovalRequestView, ApprovalSubject, ApprovalSubjectError, ExecutorMount, ExecutorRequest,
    ExecutorRequestError, PolicyDecision, PolicyEvaluation, PolicyObligations, PolicyRequest,
    PolicyRequestError, ToolConcurrency, ToolDescriptor, ToolDescriptorValidationError,
    canonical_arguments_digest, derive_effect_idempotency_key, is_sha256_digest, sha256_digest,
};
use mealy_domain::{
    ApprovalDecision, ApprovalStatus, AttemptId, EffectClass, EffectId, ExecutorKind, FencingToken,
    IdempotencyClass, PolicyProfile, PrincipalId, RecoveryStrategy, RiskClass, RunId, TaskId,
};
use serde_json::{Value, json};
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// Explicit admitted-input prefix selecting production action mode.
pub const WORKSPACE_ACTION_INPUT_PREFIX: &str = "/act ";
/// Explicit admitted-input prefix selecting existing-file replacement mode.
pub const WORKSPACE_EDIT_INPUT_PREFIX: &str = "/edit ";
/// Stable production tool identity for create-new-file mutations.
pub const WORKSPACE_CREATE_FILE_TOOL_ID: &str = "workspace.create_file";
/// Exact operation understood by the trusted sandbox worker.
pub const WORKSPACE_CREATE_FILE_OPERATION: &str = "write_file";
/// Logical capability required by the create-new-file contract.
pub const WORKSPACE_CREATE_CAPABILITY: &str = "write:workspace:create";
/// Policy identity retained with each production workspace-create effect.
pub const WORKSPACE_CREATE_POLICY_VERSION: &str = "mealy.workspace-create.policy.v1";
/// Maximum number of Unicode scalar values accepted as file content.
pub const WORKSPACE_CREATE_MAXIMUM_CONTENT_CHARACTERS: usize = 8 * 1_024;
/// Stable production tool identity for optimistic existing-file replacement.
pub const WORKSPACE_REPLACE_FILE_TOOL_ID: &str = "workspace.replace_file";
/// Exact operation understood by the trusted sandbox worker for replacement.
pub const WORKSPACE_REPLACE_FILE_OPERATION: &str = "replace_file";
/// Logical capability required by the existing-file replacement contract.
pub const WORKSPACE_REPLACE_CAPABILITY: &str = "write:workspace:replace";
/// Policy identity retained with each production workspace-replace effect.
pub const WORKSPACE_REPLACE_POLICY_VERSION: &str = "mealy.workspace-replace.policy.v1";
/// Maximum ordered exact-text replacements accepted by one approved edit.
pub const WORKSPACE_REPLACE_MAXIMUM_EDITS: usize = 16;
/// Maximum Unicode scalar values accepted in either side of one exact replacement.
pub const WORKSPACE_REPLACE_MAXIMUM_EDIT_TEXT_CHARACTERS: usize = 8 * 1_024;
/// Maximum expected non-overlapping occurrences for one exact replacement.
pub const WORKSPACE_REPLACE_MAXIMUM_EXPECTED_OCCURRENCES: u64 = 32;

const CREATE_TOOL_VERSION: &str = "1";
const REPLACE_TOOL_VERSION: &str = "2";
const SANDBOX_ROOT: &str = "/workspace";
const MAXIMUM_DURATION_MS: u64 = 2_000;
const MAXIMUM_OUTPUT_BYTES: u64 = 16 * 1_024;
const MAXIMUM_MEMORY_BYTES: u64 = 256 * 1_024 * 1_024;
const MAXIMUM_CONTENT_BYTES: usize = 48 * 1_024;
const MAXIMUM_RELATIVE_PATH_BYTES: usize = 256;
const MAXIMUM_WORKSPACE_ROOT_BYTES: usize = 4_096;
const EXPLANATION: &str = "workspace_create_requires_approval";

/// Exact configured authority for one approval-gated create in one writable workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceCreatePolicyGrant {
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

impl WorkspaceCreatePolicyGrant {
    /// Validates every immutable grant dimension.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceCreateContractError::InvalidGrant`] for any malformed or widened grant.
    pub fn validate(&self) -> Result<(), WorkspaceCreateContractError> {
        if self.valid_from_ms < 0
            || self.expires_at_ms <= self.valid_from_ms
            || !canonical_workspace_id(&self.workspace_id)
            || !canonical_workspace_root(&self.workspace_root)
            || !is_sha256_digest(&self.worker_identity_digest)
        {
            return Err(WorkspaceCreateContractError::InvalidGrant);
        }
        let descriptor = workspace_create_file_descriptor(&self.worker_identity_digest)
            .map_err(|_| WorkspaceCreateContractError::InvalidGrant)?;
        if descriptor.descriptor_digest != self.tool_descriptor_digest {
            return Err(WorkspaceCreateContractError::InvalidGrant);
        }
        Ok(())
    }
}

/// Inputs needed to build one approved, fenced workspace-create executor request.
#[derive(Clone, Copy)]
pub struct WorkspaceCreateDispatch<'a> {
    /// Durable normalized policy input.
    pub policy_request: &'a PolicyRequest,
    /// Durable approval-gated policy result.
    pub policy_evaluation: &'a PolicyEvaluation,
    /// Reconstructed exact configured grant.
    pub grant: &'a WorkspaceCreatePolicyGrant,
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

/// Exact configured authority for one approval-gated replacement in one writable workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceReplacePolicyGrant {
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

impl WorkspaceReplacePolicyGrant {
    /// Validates every immutable replacement-grant dimension.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceReplaceContractError::InvalidGrant`] for malformed or widened grants.
    pub fn validate(&self) -> Result<(), WorkspaceReplaceContractError> {
        if self.valid_from_ms < 0
            || self.expires_at_ms <= self.valid_from_ms
            || !canonical_workspace_id(&self.workspace_id)
            || !canonical_workspace_root(&self.workspace_root)
            || !is_sha256_digest(&self.worker_identity_digest)
        {
            return Err(WorkspaceReplaceContractError::InvalidGrant);
        }
        let descriptor = workspace_replace_file_descriptor(&self.worker_identity_digest)
            .map_err(|_| WorkspaceReplaceContractError::InvalidGrant)?;
        if descriptor.descriptor_digest != self.tool_descriptor_digest {
            return Err(WorkspaceReplaceContractError::InvalidGrant);
        }
        Ok(())
    }
}

/// Inputs needed to build one approved, fenced workspace-replace executor request.
#[derive(Clone, Copy)]
pub struct WorkspaceReplaceDispatch<'a> {
    /// Durable normalized policy input.
    pub policy_request: &'a PolicyRequest,
    /// Durable approval-gated policy result.
    pub policy_evaluation: &'a PolicyEvaluation,
    /// Reconstructed exact configured grant.
    pub grant: &'a WorkspaceReplacePolicyGrant,
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

/// Builds the exact descriptor bound to the trusted worker bytes.
///
/// # Errors
///
/// Returns [`WorkspaceCreateContractError`] when the digest or descriptor is not canonical.
pub fn workspace_create_file_descriptor(
    worker_identity_digest: &str,
) -> Result<ToolDescriptor, WorkspaceCreateContractError> {
    if !is_sha256_digest(worker_identity_digest) {
        return Err(WorkspaceCreateContractError::InvalidWorkerIdentity);
    }
    let input_schema = json!({
        "additionalProperties": false,
        "properties": {
            "content": {"maxLength": WORKSPACE_CREATE_MAXIMUM_CONTENT_CHARACTERS, "type": "string"},
            "operation": {"const": WORKSPACE_CREATE_FILE_OPERATION, "type": "string"},
            "relativePath": {
                "maxLength": MAXIMUM_RELATIVE_PATH_BYTES,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9._/-]+$",
                "type": "string"
            },
            "workspaceId": {
                "maxLength": 128,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]*$",
                "type": "string"
            }
        },
        "required": ["content", "operation", "relativePath", "workspaceId"],
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
        tool_id: WORKSPACE_CREATE_FILE_TOOL_ID.to_owned(),
        version: CREATE_TOOL_VERSION.to_owned(),
        input_schema_digest: sha256_digest(input_schema.to_string().as_bytes()),
        output_schema_digest: sha256_digest(output_schema.to_string().as_bytes()),
        input_schema,
        output_schema,
        descriptor_digest: String::new(),
        effect_class: EffectClass::Idempotent,
        risk_class: RiskClass::Medium,
        required_capabilities: vec![WORKSPACE_CREATE_CAPABILITY.to_owned()],
        timeout: Duration::from_millis(MAXIMUM_DURATION_MS),
        maximum_output_bytes: MAXIMUM_OUTPUT_BYTES,
        concurrency: ToolConcurrency::Serial,
        conflict_key_templates: vec!["workspace-create:{workspaceId}:{relativePath}".to_owned()],
        idempotency: IdempotencyClass::Keyed,
        recovery: RecoveryStrategy::NeverRetry,
        executor: ExecutorKind::Sandbox,
        executable_identity_digest: worker_identity_digest.to_owned(),
    };
    descriptor.descriptor_digest = descriptor.computed_descriptor_digest()?;
    descriptor.validate()?;
    Ok(descriptor)
}

/// Builds the exact existing-file replacement descriptor bound to trusted worker bytes.
///
/// # Errors
///
/// Returns [`WorkspaceReplaceContractError`] when the digest or descriptor is not canonical.
pub fn workspace_replace_file_descriptor(
    worker_identity_digest: &str,
) -> Result<ToolDescriptor, WorkspaceReplaceContractError> {
    if !is_sha256_digest(worker_identity_digest) {
        return Err(WorkspaceReplaceContractError::InvalidWorkerIdentity);
    }
    let input_schema = json!({
        "additionalProperties": false,
        "oneOf": [
            {"required": ["content"]},
            {"required": ["replacements"]}
        ],
        "properties": {
            "content": {"maxLength": WORKSPACE_CREATE_MAXIMUM_CONTENT_CHARACTERS, "type": "string"},
            "expectedCurrentDigest": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "operation": {"const": WORKSPACE_REPLACE_FILE_OPERATION, "type": "string"},
            "relativePath": {
                "maxLength": MAXIMUM_RELATIVE_PATH_BYTES,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9._/-]+$",
                "type": "string"
            },
            "replacements": {
                "items": {
                    "additionalProperties": false,
                    "properties": {
                        "expectedOccurrences": {
                            "maximum": WORKSPACE_REPLACE_MAXIMUM_EXPECTED_OCCURRENCES,
                            "minimum": 1,
                            "type": "integer"
                        },
                        "newText": {
                            "maxLength": WORKSPACE_REPLACE_MAXIMUM_EDIT_TEXT_CHARACTERS,
                            "type": "string"
                        },
                        "oldText": {
                            "maxLength": WORKSPACE_REPLACE_MAXIMUM_EDIT_TEXT_CHARACTERS,
                            "minLength": 1,
                            "type": "string"
                        }
                    },
                    "required": ["expectedOccurrences", "newText", "oldText"],
                    "type": "object"
                },
                "maxItems": WORKSPACE_REPLACE_MAXIMUM_EDITS,
                "minItems": 1,
                "type": "array"
            },
            "workspaceId": {
                "maxLength": 128,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]*$",
                "type": "string"
            }
        },
        "required": ["expectedCurrentDigest", "operation", "relativePath", "workspaceId"],
        "type": "object"
    });
    let output_schema = json!({
        "additionalProperties": false,
        "properties": {
            "bytesWritten": {"minimum": 0, "type": "integer"},
            "contentDigest": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "previousContentDigest": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "relativePath": {"type": "string"}
        },
        "required": ["bytesWritten", "contentDigest", "previousContentDigest", "relativePath"],
        "type": "object"
    });
    let mut descriptor = ToolDescriptor {
        tool_id: WORKSPACE_REPLACE_FILE_TOOL_ID.to_owned(),
        version: REPLACE_TOOL_VERSION.to_owned(),
        input_schema_digest: sha256_digest(input_schema.to_string().as_bytes()),
        output_schema_digest: sha256_digest(output_schema.to_string().as_bytes()),
        input_schema,
        output_schema,
        descriptor_digest: String::new(),
        effect_class: EffectClass::Idempotent,
        risk_class: RiskClass::Medium,
        required_capabilities: vec![WORKSPACE_REPLACE_CAPABILITY.to_owned()],
        timeout: Duration::from_millis(MAXIMUM_DURATION_MS),
        maximum_output_bytes: MAXIMUM_OUTPUT_BYTES,
        concurrency: ToolConcurrency::Serial,
        conflict_key_templates: vec!["workspace-replace:{workspaceId}:{relativePath}".to_owned()],
        idempotency: IdempotencyClass::Keyed,
        recovery: RecoveryStrategy::NeverRetry,
        executor: ExecutorKind::Sandbox,
        executable_identity_digest: worker_identity_digest.to_owned(),
    };
    descriptor.descriptor_digest = descriptor.computed_descriptor_digest()?;
    descriptor.validate()?;
    Ok(descriptor)
}

/// Strictly normalizes the model-facing production create arguments.
///
/// # Errors
///
/// Returns [`WorkspaceCreateArgumentError`] for any missing, extra, unsafe, or unbounded field.
pub fn normalize_workspace_create_file_arguments(
    arguments: &Value,
) -> Result<Value, WorkspaceCreateArgumentError> {
    let object = arguments
        .as_object()
        .ok_or(WorkspaceCreateArgumentError::ExpectedObject)?;
    if object.len() != 4
        || !["content", "operation", "relativePath", "workspaceId"]
            .iter()
            .all(|field| object.contains_key(*field))
    {
        return Err(WorkspaceCreateArgumentError::InvalidShape);
    }
    if object.get("operation").and_then(Value::as_str) != Some(WORKSPACE_CREATE_FILE_OPERATION) {
        return Err(WorkspaceCreateArgumentError::InvalidOperation);
    }
    let workspace_id = object
        .get("workspaceId")
        .and_then(Value::as_str)
        .filter(|value| canonical_workspace_id(value))
        .ok_or(WorkspaceCreateArgumentError::InvalidWorkspaceId)?;
    let relative_path = object
        .get("relativePath")
        .and_then(Value::as_str)
        .filter(|value| canonical_relative_path(value))
        .ok_or(WorkspaceCreateArgumentError::InvalidRelativePath)?;
    let content = object
        .get("content")
        .and_then(Value::as_str)
        .filter(|value| {
            value.chars().count() <= WORKSPACE_CREATE_MAXIMUM_CONTENT_CHARACTERS
                && value.len() <= MAXIMUM_CONTENT_BYTES
        })
        .ok_or(WorkspaceCreateArgumentError::InvalidContent)?;
    Ok(json!({
        "content": content,
        "operation": WORKSPACE_CREATE_FILE_OPERATION,
        "relativePath": relative_path,
        "workspaceId": workspace_id,
    }))
}

/// Strictly normalizes model-facing existing-file replacement arguments.
///
/// # Errors
///
/// Returns [`WorkspaceReplaceArgumentError`] for missing, extra, unsafe, stale, or unbounded data.
pub fn normalize_workspace_replace_file_arguments(
    arguments: &Value,
) -> Result<Value, WorkspaceReplaceArgumentError> {
    let object = arguments
        .as_object()
        .ok_or(WorkspaceReplaceArgumentError::ExpectedObject)?;
    if object.len() != 5
        || ![
            "expectedCurrentDigest",
            "operation",
            "relativePath",
            "workspaceId",
        ]
        .iter()
        .all(|field| object.contains_key(*field))
        || object.contains_key("content") == object.contains_key("replacements")
    {
        return Err(WorkspaceReplaceArgumentError::InvalidShape);
    }
    if object.get("operation").and_then(Value::as_str) != Some(WORKSPACE_REPLACE_FILE_OPERATION) {
        return Err(WorkspaceReplaceArgumentError::InvalidOperation);
    }
    let workspace_id = object
        .get("workspaceId")
        .and_then(Value::as_str)
        .filter(|value| canonical_workspace_id(value))
        .ok_or(WorkspaceReplaceArgumentError::InvalidWorkspaceId)?;
    let relative_path = object
        .get("relativePath")
        .and_then(Value::as_str)
        .filter(|value| canonical_relative_path(value))
        .ok_or(WorkspaceReplaceArgumentError::InvalidRelativePath)?;
    let expected_current_digest = object
        .get("expectedCurrentDigest")
        .and_then(Value::as_str)
        .filter(|value| is_sha256_digest(value))
        .ok_or(WorkspaceReplaceArgumentError::InvalidExpectedCurrentDigest)?;
    if let Some(content) = object.get("content") {
        let content = content
            .as_str()
            .filter(|value| {
                value.chars().count() <= WORKSPACE_CREATE_MAXIMUM_CONTENT_CHARACTERS
                    && value.len() <= MAXIMUM_CONTENT_BYTES
            })
            .ok_or(WorkspaceReplaceArgumentError::InvalidContent)?;
        return Ok(json!({
            "content": content,
            "expectedCurrentDigest": expected_current_digest,
            "operation": WORKSPACE_REPLACE_FILE_OPERATION,
            "relativePath": relative_path,
            "workspaceId": workspace_id,
        }));
    }
    let normalized = normalize_exact_replacements(
        object
            .get("replacements")
            .ok_or(WorkspaceReplaceArgumentError::InvalidReplacements)?,
    )?;
    Ok(json!({
        "expectedCurrentDigest": expected_current_digest,
        "operation": WORKSPACE_REPLACE_FILE_OPERATION,
        "relativePath": relative_path,
        "replacements": normalized,
        "workspaceId": workspace_id,
    }))
}

fn normalize_exact_replacements(
    replacements: &Value,
) -> Result<Vec<Value>, WorkspaceReplaceArgumentError> {
    let replacements = replacements
        .as_array()
        .filter(|items| !items.is_empty() && items.len() <= WORKSPACE_REPLACE_MAXIMUM_EDITS)
        .ok_or(WorkspaceReplaceArgumentError::InvalidReplacements)?;
    let mut normalized = Vec::with_capacity(replacements.len());
    let mut total_bytes = 0_usize;
    for replacement in replacements {
        let replacement = replacement
            .as_object()
            .filter(|object| {
                object.len() == 3
                    && ["expectedOccurrences", "newText", "oldText"]
                        .iter()
                        .all(|field| object.contains_key(*field))
            })
            .ok_or(WorkspaceReplaceArgumentError::InvalidReplacements)?;
        let old_text = replacement
            .get("oldText")
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty()
                    && value.chars().count() <= WORKSPACE_REPLACE_MAXIMUM_EDIT_TEXT_CHARACTERS
            })
            .ok_or(WorkspaceReplaceArgumentError::InvalidReplacements)?;
        let new_text = replacement
            .get("newText")
            .and_then(Value::as_str)
            .filter(|value| value.chars().count() <= WORKSPACE_REPLACE_MAXIMUM_EDIT_TEXT_CHARACTERS)
            .ok_or(WorkspaceReplaceArgumentError::InvalidReplacements)?;
        let expected_occurrences = replacement
            .get("expectedOccurrences")
            .and_then(Value::as_u64)
            .filter(|value| (1..=WORKSPACE_REPLACE_MAXIMUM_EXPECTED_OCCURRENCES).contains(value))
            .ok_or(WorkspaceReplaceArgumentError::InvalidReplacements)?;
        total_bytes = total_bytes
            .checked_add(old_text.len())
            .and_then(|value| value.checked_add(new_text.len()))
            .filter(|value| *value <= MAXIMUM_CONTENT_BYTES)
            .ok_or(WorkspaceReplaceArgumentError::InvalidReplacements)?;
        normalized.push(json!({
            "expectedOccurrences": expected_occurrences,
            "newText": new_text,
            "oldText": old_text,
        }));
    }
    Ok(normalized)
}

/// Evaluates the exact production create rule and denies every mismatch.
#[must_use]
pub fn evaluate_workspace_create_policy(
    request: &PolicyRequest,
    grant: &WorkspaceCreatePolicyGrant,
) -> PolicyEvaluation {
    let deny = |reason: &str| denied_evaluation(request, reason);
    if request.validate().is_err() || grant.validate().is_err() {
        return deny("invalid_workspace_create_request");
    }
    if request.principal_id != grant.principal_id
        || request.channel_binding_id != grant.channel_binding_id
        || request.task_id != grant.task_id
        || request.run_id != grant.run_id
        || request.evaluated_at_ms < grant.valid_from_ms
        || request.evaluated_at_ms >= grant.expires_at_ms
    {
        return deny("workspace_create_scope_not_granted");
    }
    let Ok(validated) = validate_contract_request(request) else {
        return deny("no_matching_workspace_create_rule");
    };
    if validated.workspace_id != grant.workspace_id
        || validated.workspace_root != grant.workspace_root
        || request.tool.descriptor_digest != grant.tool_descriptor_digest
        || request.tool.executable_identity_digest != grant.worker_identity_digest
    {
        return deny("no_matching_workspace_create_rule");
    }
    PolicyEvaluation {
        decision: PolicyDecision::RequireApproval,
        obligations: expected_obligations(&validated.workspace_root, &grant.worker_identity_digest),
        policy_version: WORKSPACE_CREATE_POLICY_VERSION.to_owned(),
        explanation: EXPLANATION.to_owned(),
    }
}

/// Constructs the immutable owner-facing approval subject.
///
/// # Errors
///
/// Returns [`WorkspaceCreateContractError`] for invalid contract or expiry evidence.
pub fn workspace_create_approval_subject(
    effect_id: EffectId,
    request: &PolicyRequest,
    expires_at_ms: i64,
) -> Result<ApprovalSubject, WorkspaceCreateContractError> {
    let validated = validate_contract_request(request)?;
    if expires_at_ms <= request.evaluated_at_ms {
        return Err(WorkspaceCreateContractError::InvalidApproval);
    }
    let subject = ApprovalSubject {
        principal_id: request.principal_id,
        task_id: request.task_id,
        effect_id,
        tool_id: request.tool.tool_id.clone(),
        tool_version: request.tool.version.clone(),
        canonical_arguments_digest: canonical_arguments_digest(&validated.normalized_arguments),
        capability_scope: WORKSPACE_CREATE_CAPABILITY.to_owned(),
        target_resources: request.target_resources.clone(),
        executable_identity_digest: request.tool.executable_identity_digest.clone(),
        policy_version: WORKSPACE_CREATE_POLICY_VERSION.to_owned(),
        expires_at_ms,
    };
    subject.validate()?;
    Ok(subject)
}

/// Builds a one-shot sandbox request exactly equal to approved obligations.
///
/// # Errors
///
/// Returns [`WorkspaceCreateContractError`] for stale or divergent policy, approval, or dispatch
/// evidence.
pub fn build_workspace_create_executor_request(
    dispatch: WorkspaceCreateDispatch<'_>,
) -> Result<ExecutorRequest, WorkspaceCreateContractError> {
    dispatch.grant.validate()?;
    let validated = validate_contract_request(dispatch.policy_request)?;
    let expected = evaluate_workspace_create_policy(dispatch.policy_request, dispatch.grant);
    let obligations = expected_obligations(
        &validated.workspace_root,
        &dispatch.policy_request.tool.executable_identity_digest,
    );
    if expected.decision != PolicyDecision::RequireApproval
        || dispatch.policy_evaluation != &expected
        || dispatch.policy_evaluation.obligations != obligations
    {
        return Err(WorkspaceCreateContractError::AuthorizationMismatch);
    }
    if dispatch.dispatched_at_ms < dispatch.policy_request.evaluated_at_ms
        || dispatch.dispatched_at_ms < 0
        || dispatch.dispatched_at_ms >= dispatch.approval.subject.expires_at_ms
    {
        return Err(WorkspaceCreateContractError::InvalidDispatchTime);
    }
    let (Some(requested_at_ms), Some(resolved_at_ms)) = (
        system_time_milliseconds(dispatch.approval.requested_at),
        dispatch
            .approval
            .resolved_at
            .and_then(system_time_milliseconds),
    ) else {
        return Err(WorkspaceCreateContractError::InvalidApproval);
    };
    let expected_subject = workspace_create_approval_subject(
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
        return Err(WorkspaceCreateContractError::InvalidApproval);
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
        idempotency_key: Some(derive_effect_idempotency_key(dispatch.effect_id)),
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

/// Evaluates the exact optimistic replacement rule and denies every mismatch.
#[must_use]
pub fn evaluate_workspace_replace_policy(
    request: &PolicyRequest,
    grant: &WorkspaceReplacePolicyGrant,
) -> PolicyEvaluation {
    let deny = |reason: &str| denied_replace_evaluation(request, reason);
    if request.validate().is_err() || grant.validate().is_err() {
        return deny("invalid_workspace_replace_request");
    }
    if request.principal_id != grant.principal_id
        || request.channel_binding_id != grant.channel_binding_id
        || request.task_id != grant.task_id
        || request.run_id != grant.run_id
        || request.evaluated_at_ms < grant.valid_from_ms
        || request.evaluated_at_ms >= grant.expires_at_ms
    {
        return deny("workspace_replace_scope_not_granted");
    }
    let Ok(validated) = validate_replace_contract_request(request) else {
        return deny("no_matching_workspace_replace_rule");
    };
    if validated.workspace_id != grant.workspace_id
        || validated.workspace_root != grant.workspace_root
        || request.tool.descriptor_digest != grant.tool_descriptor_digest
        || request.tool.executable_identity_digest != grant.worker_identity_digest
    {
        return deny("no_matching_workspace_replace_rule");
    }
    PolicyEvaluation {
        decision: PolicyDecision::RequireApproval,
        obligations: expected_obligations(&validated.workspace_root, &grant.worker_identity_digest),
        policy_version: WORKSPACE_REPLACE_POLICY_VERSION.to_owned(),
        explanation: "workspace_replace_requires_approval".to_owned(),
    }
}

/// Constructs the immutable owner-facing replacement approval subject.
///
/// # Errors
///
/// Returns [`WorkspaceReplaceContractError`] for invalid contract or expiry evidence.
pub fn workspace_replace_approval_subject(
    effect_id: EffectId,
    request: &PolicyRequest,
    expires_at_ms: i64,
) -> Result<ApprovalSubject, WorkspaceReplaceContractError> {
    let validated = validate_replace_contract_request(request)?;
    if expires_at_ms <= request.evaluated_at_ms {
        return Err(WorkspaceReplaceContractError::InvalidApproval);
    }
    let subject = ApprovalSubject {
        principal_id: request.principal_id,
        task_id: request.task_id,
        effect_id,
        tool_id: request.tool.tool_id.clone(),
        tool_version: request.tool.version.clone(),
        canonical_arguments_digest: canonical_arguments_digest(&validated.normalized_arguments),
        capability_scope: WORKSPACE_REPLACE_CAPABILITY.to_owned(),
        target_resources: request.target_resources.clone(),
        executable_identity_digest: request.tool.executable_identity_digest.clone(),
        policy_version: WORKSPACE_REPLACE_POLICY_VERSION.to_owned(),
        expires_at_ms,
    };
    subject.validate()?;
    Ok(subject)
}

/// Builds a one-shot sandbox request exactly equal to approved replacement obligations.
///
/// # Errors
///
/// Returns [`WorkspaceReplaceContractError`] for stale or divergent policy, approval, or dispatch
/// evidence.
pub fn build_workspace_replace_executor_request(
    dispatch: WorkspaceReplaceDispatch<'_>,
) -> Result<ExecutorRequest, WorkspaceReplaceContractError> {
    dispatch.grant.validate()?;
    let validated = validate_replace_contract_request(dispatch.policy_request)?;
    let expected = evaluate_workspace_replace_policy(dispatch.policy_request, dispatch.grant);
    let obligations = expected_obligations(
        &validated.workspace_root,
        &dispatch.policy_request.tool.executable_identity_digest,
    );
    if expected.decision != PolicyDecision::RequireApproval
        || dispatch.policy_evaluation != &expected
        || dispatch.policy_evaluation.obligations != obligations
    {
        return Err(WorkspaceReplaceContractError::AuthorizationMismatch);
    }
    if dispatch.dispatched_at_ms < dispatch.policy_request.evaluated_at_ms
        || dispatch.dispatched_at_ms < 0
        || dispatch.dispatched_at_ms >= dispatch.approval.subject.expires_at_ms
    {
        return Err(WorkspaceReplaceContractError::InvalidDispatchTime);
    }
    let (Some(requested_at_ms), Some(resolved_at_ms)) = (
        system_time_milliseconds(dispatch.approval.requested_at),
        dispatch
            .approval
            .resolved_at
            .and_then(system_time_milliseconds),
    ) else {
        return Err(WorkspaceReplaceContractError::InvalidApproval);
    };
    let expected_subject = workspace_replace_approval_subject(
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
        return Err(WorkspaceReplaceContractError::InvalidApproval);
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
        idempotency_key: Some(derive_effect_idempotency_key(dispatch.effect_id)),
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

struct ValidatedWorkspaceReplace {
    normalized_arguments: Value,
    workspace_id: String,
    workspace_root: String,
}

fn validate_replace_contract_request(
    request: &PolicyRequest,
) -> Result<ValidatedWorkspaceReplace, WorkspaceReplaceContractError> {
    request.validate()?;
    if request.policy_version != WORKSPACE_REPLACE_POLICY_VERSION
        || request.agent_role != "assistant"
        || request.task_risk != RiskClass::Medium
        || request.requested_capability != WORKSPACE_REPLACE_CAPABILITY
        || request.requested_profile != PolicyProfile::WorkspaceWrite
        || request.enforceable_profiles != [PolicyProfile::WorkspaceWrite]
        || !request.secret_references.is_empty()
        || !request.network_destinations.is_empty()
        || request.workspace_roots.len() != 1
    {
        return Err(WorkspaceReplaceContractError::AuthorizationMismatch);
    }
    let expected_descriptor =
        workspace_replace_file_descriptor(&request.tool.executable_identity_digest)?;
    if request.tool != expected_descriptor {
        return Err(WorkspaceReplaceContractError::AuthorizationMismatch);
    }
    let normalized_arguments =
        normalize_workspace_replace_file_arguments(&request.normalized_arguments)?;
    if normalized_arguments != request.normalized_arguments {
        return Err(WorkspaceReplaceContractError::AuthorizationMismatch);
    }
    let workspace_id = normalized_arguments["workspaceId"]
        .as_str()
        .ok_or(WorkspaceReplaceContractError::AuthorizationMismatch)?
        .to_owned();
    let relative_path = normalized_arguments["relativePath"]
        .as_str()
        .ok_or(WorkspaceReplaceContractError::AuthorizationMismatch)?;
    let workspace_root = request.workspace_roots[0].clone();
    if !canonical_workspace_root(&workspace_root) {
        return Err(WorkspaceReplaceContractError::InvalidWorkspaceRoot);
    }
    let target = format!("workspace://{workspace_id}/{relative_path}");
    let claim = format!("workspace-replace:{target}");
    if request.target_resources != [target] || request.resource_claims != [claim] {
        return Err(WorkspaceReplaceContractError::AuthorizationMismatch);
    }
    Ok(ValidatedWorkspaceReplace {
        normalized_arguments,
        workspace_id,
        workspace_root,
    })
}

struct ValidatedWorkspaceCreate {
    normalized_arguments: Value,
    workspace_id: String,
    workspace_root: String,
}

fn validate_contract_request(
    request: &PolicyRequest,
) -> Result<ValidatedWorkspaceCreate, WorkspaceCreateContractError> {
    request.validate()?;
    if request.policy_version != WORKSPACE_CREATE_POLICY_VERSION
        || request.agent_role != "assistant"
        || request.task_risk != RiskClass::Medium
        || request.requested_capability != WORKSPACE_CREATE_CAPABILITY
        || request.requested_profile != PolicyProfile::WorkspaceWrite
        || request.enforceable_profiles != [PolicyProfile::WorkspaceWrite]
        || !request.secret_references.is_empty()
        || !request.network_destinations.is_empty()
        || request.workspace_roots.len() != 1
    {
        return Err(WorkspaceCreateContractError::AuthorizationMismatch);
    }
    let expected_descriptor =
        workspace_create_file_descriptor(&request.tool.executable_identity_digest)?;
    if request.tool != expected_descriptor {
        return Err(WorkspaceCreateContractError::AuthorizationMismatch);
    }
    let normalized_arguments =
        normalize_workspace_create_file_arguments(&request.normalized_arguments)?;
    if normalized_arguments != request.normalized_arguments {
        return Err(WorkspaceCreateContractError::AuthorizationMismatch);
    }
    let workspace_id = normalized_arguments["workspaceId"]
        .as_str()
        .ok_or(WorkspaceCreateContractError::AuthorizationMismatch)?
        .to_owned();
    let relative_path = normalized_arguments["relativePath"]
        .as_str()
        .ok_or(WorkspaceCreateContractError::AuthorizationMismatch)?;
    let workspace_root = request.workspace_roots[0].clone();
    if !canonical_workspace_root(&workspace_root) {
        return Err(WorkspaceCreateContractError::InvalidWorkspaceRoot);
    }
    let target = format!("workspace://{workspace_id}/{relative_path}");
    let claim = format!("workspace-create:{target}");
    if request.target_resources != [target] || request.resource_claims != [claim] {
        return Err(WorkspaceCreateContractError::AuthorizationMismatch);
    }
    Ok(ValidatedWorkspaceCreate {
        normalized_arguments,
        workspace_id,
        workspace_root,
    })
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
        policy_version: WORKSPACE_CREATE_POLICY_VERSION.to_owned(),
        explanation: explanation.to_owned(),
    }
}

fn denied_replace_evaluation(request: &PolicyRequest, explanation: &str) -> PolicyEvaluation {
    let mut evaluation = denied_evaluation(request, explanation);
    WORKSPACE_REPLACE_POLICY_VERSION.clone_into(&mut evaluation.policy_version);
    evaluation
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

/// Invalid production workspace-create argument shape or value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkspaceCreateArgumentError {
    /// Arguments were not represented by one JSON object.
    #[error("workspace create arguments must be an object")]
    ExpectedObject,
    /// Required fields were missing or undeclared fields were present.
    #[error(
        "workspace create arguments must contain exactly workspaceId, operation, relativePath, and content"
    )]
    InvalidShape,
    /// Operation was absent, mistyped, or not the trusted worker operation.
    #[error("workspace create operation is invalid")]
    InvalidOperation,
    /// Workspace identity was absent, unsafe, or noncanonical.
    #[error("workspace create workspace identity is invalid")]
    InvalidWorkspaceId,
    /// Relative target path was absent, unsafe, or noncanonical.
    #[error("workspace create relative path is invalid")]
    InvalidRelativePath,
    /// Content was mistyped or exceeded its character or byte bound.
    #[error("workspace create content is invalid")]
    InvalidContent,
}

/// Invalid descriptor, policy, approval, or executor evidence for a production workspace create.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkspaceCreateContractError {
    /// Trusted worker digest was not canonical lowercase SHA-256.
    #[error("workspace create worker identity is invalid")]
    InvalidWorkerIdentity,
    /// Configured grant was malformed or widened the fixed contract.
    #[error("workspace create policy grant is invalid")]
    InvalidGrant,
    /// Host root was not a canonical bounded absolute path.
    #[error("workspace create workspace root is invalid")]
    InvalidWorkspaceRoot,
    /// Request, policy outcome, or obligations diverged from the fixed contract.
    #[error("workspace create authorization evidence does not match")]
    AuthorizationMismatch,
    /// Approval was missing, stale, denied, or bound to different evidence.
    #[error("workspace create approval evidence is invalid")]
    InvalidApproval,
    /// Dispatch occurred before evaluation or at/after exclusive expiry.
    #[error("workspace create dispatch time is invalid")]
    InvalidDispatchTime,
    /// Generic tool descriptor evidence was invalid.
    #[error(transparent)]
    Descriptor(#[from] ToolDescriptorValidationError),
    /// Normalized model arguments were invalid.
    #[error(transparent)]
    Arguments(#[from] WorkspaceCreateArgumentError),
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

/// Invalid production workspace-replace argument shape or value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkspaceReplaceArgumentError {
    /// Arguments were not represented by one JSON object.
    #[error("workspace replace arguments must be an object")]
    ExpectedObject,
    /// Required fields were missing or undeclared fields were present.
    #[error(
        "workspace replace arguments must contain workspaceId, operation, relativePath, expectedCurrentDigest, and exactly one of content or replacements"
    )]
    InvalidShape,
    /// Operation was absent, mistyped, or not the trusted worker operation.
    #[error("workspace replace operation is invalid")]
    InvalidOperation,
    /// Workspace identity was absent, unsafe, or noncanonical.
    #[error("workspace replace workspace identity is invalid")]
    InvalidWorkspaceId,
    /// Relative target path was absent, unsafe, or noncanonical.
    #[error("workspace replace relative path is invalid")]
    InvalidRelativePath,
    /// Optimistic current-content precondition was absent or not canonical SHA-256.
    #[error("workspace replace current-content digest is invalid")]
    InvalidExpectedCurrentDigest,
    /// Replacement content was mistyped or exceeded its character or byte bound.
    #[error("workspace replace content is invalid")]
    InvalidContent,
    /// Ordered exact-text replacements were mistyped, empty, excessive, or unbounded.
    #[error("workspace replace exact-text replacements are invalid")]
    InvalidReplacements,
}

/// Invalid descriptor, policy, approval, or executor evidence for a production replacement.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkspaceReplaceContractError {
    /// Trusted worker digest was not canonical lowercase SHA-256.
    #[error("workspace replace worker identity is invalid")]
    InvalidWorkerIdentity,
    /// Configured grant was malformed or widened the fixed contract.
    #[error("workspace replace policy grant is invalid")]
    InvalidGrant,
    /// Host root was not a canonical bounded absolute path.
    #[error("workspace replace workspace root is invalid")]
    InvalidWorkspaceRoot,
    /// Request, policy outcome, or obligations diverged from the fixed contract.
    #[error("workspace replace authorization evidence does not match")]
    AuthorizationMismatch,
    /// Approval was missing, stale, denied, or bound to different evidence.
    #[error("workspace replace approval evidence is invalid")]
    InvalidApproval,
    /// Dispatch occurred before evaluation or at/after exclusive expiry.
    #[error("workspace replace dispatch time is invalid")]
    InvalidDispatchTime,
    /// Generic tool descriptor evidence was invalid.
    #[error(transparent)]
    Descriptor(#[from] ToolDescriptorValidationError),
    /// Normalized model arguments were invalid.
    #[error(transparent)]
    Arguments(#[from] WorkspaceReplaceArgumentError),
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
        WORKSPACE_CREATE_CAPABILITY, WORKSPACE_CREATE_FILE_OPERATION,
        WORKSPACE_CREATE_FILE_TOOL_ID, WORKSPACE_REPLACE_CAPABILITY,
        WORKSPACE_REPLACE_FILE_OPERATION, WORKSPACE_REPLACE_FILE_TOOL_ID,
        WorkspaceCreatePolicyGrant, WorkspaceReplacePolicyGrant, evaluate_workspace_create_policy,
        evaluate_workspace_replace_policy, normalize_workspace_create_file_arguments,
        normalize_workspace_replace_file_arguments, workspace_create_file_descriptor,
        workspace_replace_approval_subject, workspace_replace_file_descriptor,
    };
    use crate::{PolicyDecision, PolicyRequest, sha256_digest};
    use mealy_domain::{
        ChannelBindingId, EffectId, PolicyProfile, PrincipalId, RiskClass, RunId, TaskId,
    };
    use serde_json::json;

    fn request_and_grant() -> (PolicyRequest, WorkspaceCreatePolicyGrant) {
        let principal_id = PrincipalId::new();
        let channel_binding_id = ChannelBindingId::new();
        let task_id = TaskId::new();
        let run_id = RunId::new();
        let worker = sha256_digest(b"worker");
        let tool = workspace_create_file_descriptor(&worker).expect("descriptor");
        let arguments = json!({
            "content": "hello",
            "operation": WORKSPACE_CREATE_FILE_OPERATION,
            "relativePath": "notes/new.txt",
            "workspaceId": "project",
        });
        let grant = WorkspaceCreatePolicyGrant {
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
            target_resources: vec!["workspace://project/notes/new.txt".to_owned()],
            workspace_roots: vec!["/srv/project".to_owned()],
            resource_claims: vec!["workspace-create:workspace://project/notes/new.txt".to_owned()],
            secret_references: Vec::new(),
            network_destinations: Vec::new(),
            requested_capability: WORKSPACE_CREATE_CAPABILITY.to_owned(),
            requested_profile: PolicyProfile::WorkspaceWrite,
            enforceable_profiles: vec![PolicyProfile::WorkspaceWrite],
            evaluated_at_ms: 500,
            policy_version: super::WORKSPACE_CREATE_POLICY_VERSION.to_owned(),
        };
        (request, grant)
    }

    fn replace_request_and_grant() -> (PolicyRequest, WorkspaceReplacePolicyGrant) {
        let principal_id = PrincipalId::new();
        let channel_binding_id = ChannelBindingId::new();
        let task_id = TaskId::new();
        let run_id = RunId::new();
        let worker = sha256_digest(b"worker");
        let tool = workspace_replace_file_descriptor(&worker).expect("descriptor");
        let arguments = json!({
            "content": "replacement",
            "expectedCurrentDigest": sha256_digest(b"current"),
            "operation": WORKSPACE_REPLACE_FILE_OPERATION,
            "relativePath": "notes/existing.txt",
            "workspaceId": "project",
        });
        let grant = WorkspaceReplacePolicyGrant {
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
            target_resources: vec!["workspace://project/notes/existing.txt".to_owned()],
            workspace_roots: vec!["/srv/project".to_owned()],
            resource_claims: vec![
                "workspace-replace:workspace://project/notes/existing.txt".to_owned(),
            ],
            secret_references: Vec::new(),
            network_destinations: Vec::new(),
            requested_capability: WORKSPACE_REPLACE_CAPABILITY.to_owned(),
            requested_profile: PolicyProfile::WorkspaceWrite,
            enforceable_profiles: vec![PolicyProfile::WorkspaceWrite],
            evaluated_at_ms: 500,
            policy_version: super::WORKSPACE_REPLACE_POLICY_VERSION.to_owned(),
        };
        (request, grant)
    }

    #[test]
    fn descriptor_and_arguments_are_exact() {
        let descriptor =
            workspace_create_file_descriptor(&sha256_digest(b"worker")).expect("descriptor");
        assert_eq!(descriptor.tool_id, WORKSPACE_CREATE_FILE_TOOL_ID);
        let (_, grant) = request_and_grant();
        grant.validate().expect("grant");
        assert!(
            normalize_workspace_create_file_arguments(&json!({
                "content": "x",
                "operation": "write_file",
                "relativePath": "a.txt",
                "workspaceId": "project",
            }))
            .is_ok()
        );
        assert!(
            normalize_workspace_create_file_arguments(&json!({
                "content": "x",
                "operation": "write_file",
                "relativePath": "../escape",
                "workspaceId": "project",
            }))
            .is_err()
        );
    }

    #[test]
    fn exact_policy_requires_approval_and_scope_mutations_deny() {
        let (request, grant) = request_and_grant();
        let evaluation = evaluate_workspace_create_policy(&request, &grant);
        assert_eq!(evaluation.decision, PolicyDecision::RequireApproval);
        assert!(evaluation.obligations.validator_required);
        assert_eq!(evaluation.obligations.writable_paths, ["/srv/project"]);

        let mut changed = request.clone();
        changed.normalized_arguments["workspaceId"] = json!("other");
        assert_eq!(
            evaluate_workspace_create_policy(&changed, &grant).decision,
            PolicyDecision::Deny
        );
    }

    #[test]
    fn replacement_requires_a_canonical_current_digest_and_binds_it_to_policy() {
        let descriptor =
            workspace_replace_file_descriptor(&sha256_digest(b"worker")).expect("descriptor");
        assert_eq!(descriptor.tool_id, WORKSPACE_REPLACE_FILE_TOOL_ID);
        assert!(
            normalize_workspace_replace_file_arguments(&json!({
                "content": "new",
                "expectedCurrentDigest": sha256_digest(b"old"),
                "operation": WORKSPACE_REPLACE_FILE_OPERATION,
                "relativePath": "existing.txt",
                "workspaceId": "project",
            }))
            .is_ok()
        );
        let exact_patch = normalize_workspace_replace_file_arguments(&json!({
            "expectedCurrentDigest": sha256_digest(b"old"),
            "operation": WORKSPACE_REPLACE_FILE_OPERATION,
            "relativePath": "existing.txt",
            "replacements": [{
                "expectedOccurrences": 1,
                "newText": "new release",
                "oldText": "old release"
            }],
            "workspaceId": "project",
        }))
        .expect("normalize exact patch");
        assert_eq!(exact_patch["replacements"][0]["expectedOccurrences"], 1);
        assert!(
            normalize_workspace_replace_file_arguments(&json!({
                "content": "ambiguous full replacement",
                "expectedCurrentDigest": sha256_digest(b"old"),
                "operation": WORKSPACE_REPLACE_FILE_OPERATION,
                "relativePath": "existing.txt",
                "replacements": [{
                    "expectedOccurrences": 1,
                    "newText": "new",
                    "oldText": "old"
                }],
                "workspaceId": "project",
            }))
            .is_err()
        );
        assert!(
            normalize_workspace_replace_file_arguments(&json!({
                "expectedCurrentDigest": sha256_digest(b"old"),
                "operation": WORKSPACE_REPLACE_FILE_OPERATION,
                "relativePath": "existing.txt",
                "replacements": [{
                    "expectedOccurrences": 0,
                    "newText": "new",
                    "oldText": "old"
                }],
                "workspaceId": "project",
            }))
            .is_err()
        );
        let (request, grant) = replace_request_and_grant();
        grant.validate().expect("replace grant");
        assert_eq!(
            evaluate_workspace_replace_policy(&request, &grant).decision,
            PolicyDecision::RequireApproval
        );
        let original_subject = workspace_replace_approval_subject(EffectId::new(), &request, 1_000)
            .expect("original subject");
        let mut stale_or_forged = request.clone();
        stale_or_forged.normalized_arguments["expectedCurrentDigest"] =
            json!(sha256_digest(b"different"));
        let changed_subject =
            workspace_replace_approval_subject(EffectId::new(), &stale_or_forged, 1_000)
                .expect("changed subject");
        assert_ne!(
            original_subject.canonical_arguments_digest,
            changed_subject.canonical_arguments_digest
        );
        stale_or_forged.requested_capability = WORKSPACE_CREATE_CAPABILITY.to_owned();
        assert_eq!(
            evaluate_workspace_replace_policy(&stale_or_forged, &grant).decision,
            PolicyDecision::Deny
        );
    }
}
