use crate::{
    ToolConcurrency, ToolDescriptor, ToolDescriptorValidationError, validate_fixture_read_arguments,
};
use mealy_domain::{
    ChannelBindingId, EffectClass, ExecutorKind, IdempotencyClass, PolicyProfile, PrincipalId,
    RecoveryStrategy, RiskClass, RunId, TaskId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Policy bundle understood by the deterministic Phase 3 fixture evaluator.
pub const FIXTURE_POLICY_VERSION: &str = "mealy.fixture-policy.v1";

/// Authorization result returned by deterministic policy code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    /// No matching grant permits the exact request.
    Deny,
    /// The exact request is authorized with the returned obligations.
    Allow,
    /// An authenticated approval bound to the exact request is required.
    RequireApproval,
}

/// Independently enforceable restrictions attached to a policy decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyObligations {
    /// Sandbox posture that the executor must enforce.
    pub profile: PolicyProfile,
    /// Logical host paths visible for reads.
    pub readable_paths: Vec<String>,
    /// Logical host paths visible for writes.
    pub writable_paths: Vec<String>,
    /// Executable identities that may be launched.
    pub allowed_executable_identity_digests: Vec<String>,
    /// Whether the executor may create child processes.
    pub allow_process_spawn: bool,
    /// Environment variable names that may be inherited or supplied.
    pub allowed_environment_variables: Vec<String>,
    /// Network destinations visible to the executor.
    pub network_destinations: Vec<String>,
    /// Secret reference IDs that may be resolved for this invocation.
    pub secret_references: Vec<String>,
    /// Optional policy-normalized argument replacement.
    pub argument_rewrite: Option<serde_json::Value>,
    /// Output fields or selectors that must be redacted.
    pub redactions: Vec<String>,
    /// Maximum wall-clock execution duration.
    pub maximum_duration_ms: u64,
    /// Maximum output bytes accepted from the executor.
    pub maximum_output_bytes: u64,
    /// Maximum executor memory in bytes; zero denies a child executor process.
    pub maximum_memory_bytes: u64,
    /// Maximum child processes; zero denies process creation.
    pub maximum_processes: u32,
    /// Whether successful task completion requires validator evidence.
    pub validator_required: bool,
}

impl PolicyObligations {
    fn deny_all(profile: PolicyProfile) -> Self {
        Self {
            profile,
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
        }
    }
}

/// Complete deterministic input to a policy decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRequest {
    /// Authenticated principal proposing the effect.
    pub principal_id: PrincipalId,
    /// Verified channel-to-principal binding.
    pub channel_binding_id: ChannelBindingId,
    /// Task whose risk and capability ceiling apply.
    pub task_id: TaskId,
    /// Agent run proposing the tool call.
    pub run_id: RunId,
    /// Stable agent role selected for the run.
    pub agent_role: String,
    /// Policy-visible task impact.
    pub task_risk: RiskClass,
    /// Complete immutable tool contract.
    pub tool: ToolDescriptor,
    /// Schema-validated normalized arguments.
    pub normalized_arguments: serde_json::Value,
    /// Canonical sorted set of resources targeted by the invocation.
    pub target_resources: Vec<String>,
    /// Canonical sorted set of workspace roots visible to policy.
    pub workspace_roots: Vec<String>,
    /// Canonical sorted set of scheduler resource claims.
    pub resource_claims: Vec<String>,
    /// Opaque secret references requested by the invocation.
    pub secret_references: Vec<String>,
    /// Canonical sorted set of requested network destinations.
    pub network_destinations: Vec<String>,
    /// Exact logical capability being requested.
    pub requested_capability: String,
    /// Requested executor security posture.
    pub requested_profile: PolicyProfile,
    /// Canonical sorted set of profiles the current host can enforce.
    pub enforceable_profiles: Vec<PolicyProfile>,
    /// Policy evaluation time as Unix epoch milliseconds.
    pub evaluated_at_ms: i64,
    /// Exact policy bundle version selected for evaluation.
    pub policy_version: String,
}

impl PolicyRequest {
    /// Validates deterministic request shape before policy matching.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyRequestError`] for malformed tool evidence, strings, sets, or time.
    pub fn validate(&self) -> Result<(), PolicyRequestError> {
        self.tool.validate()?;
        validate_field("agent_role", &self.agent_role)?;
        validate_field("requested_capability", &self.requested_capability)?;
        validate_field("policy_version", &self.policy_version)?;
        validate_string_set("target_resources", &self.target_resources, true)?;
        validate_string_set("workspace_roots", &self.workspace_roots, false)?;
        validate_string_set("resource_claims", &self.resource_claims, false)?;
        validate_string_set("secret_references", &self.secret_references, false)?;
        validate_string_set("network_destinations", &self.network_destinations, false)?;
        if self.enforceable_profiles.is_empty()
            || self
                .enforceable_profiles
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(PolicyRequestError::NonCanonicalProfiles);
        }
        if self.evaluated_at_ms < 0 {
            return Err(PolicyRequestError::InvalidEvaluationTime);
        }
        Ok(())
    }
}

/// Exact allow-list entry used by the deterministic fixture proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixturePolicyGrant {
    /// Only this principal is trusted by the fixture rule.
    pub principal_id: PrincipalId,
    /// Only this authenticated channel binding is trusted by the fixture rule.
    pub channel_binding_id: ChannelBindingId,
    /// Task scoped to this fixture proof.
    pub task_id: TaskId,
    /// Agent run scoped to this fixture proof.
    pub run_id: RunId,
    /// Exact generic descriptor digest granted by the fixture rule.
    pub tool_descriptor_digest: String,
    /// First evaluation time accepted by the rule.
    pub valid_from_ms: i64,
    /// Exclusive expiry of the fixture rule.
    pub expires_at_ms: i64,
}

impl FixturePolicyGrant {
    /// Validates that the configured evaluation window is nonempty.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyRequestError::InvalidGrantWindow`] for an invalid interval.
    pub fn validate(&self) -> Result<(), PolicyRequestError> {
        if self.valid_from_ms < 0 || self.expires_at_ms <= self.valid_from_ms {
            Err(PolicyRequestError::InvalidGrantWindow)
        } else if !crate::is_sha256_digest(&self.tool_descriptor_digest) {
            Err(PolicyRequestError::InvalidGrantToolDigest)
        } else {
            Ok(())
        }
    }
}

/// Policy result plus stable owner-inspectable evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyEvaluation {
    /// Authorization outcome.
    pub decision: PolicyDecision,
    /// Restrictions that remain mandatory after allow or approval.
    pub obligations: PolicyObligations,
    /// Exact evaluated bundle version.
    pub policy_version: String,
    /// Stable first-party explanation code.
    pub explanation: String,
}

/// Evaluates the one least-privilege fixture-read rule and denies every unmatched request.
///
/// This evaluator intentionally has no ambient filesystem, environment, network, clock, or model
/// input. Unsupported profiles, including unenforceable profiles, fail closed.
#[must_use]
pub fn evaluate_fixture_policy(
    request: &PolicyRequest,
    grant: &FixturePolicyGrant,
) -> PolicyEvaluation {
    let deny = |explanation: &str| PolicyEvaluation {
        decision: PolicyDecision::Deny,
        obligations: PolicyObligations::deny_all(request.requested_profile),
        policy_version: request.policy_version.clone(),
        explanation: explanation.to_owned(),
    };
    if request.validate().is_err() || grant.validate().is_err() {
        return deny("invalid_request");
    }
    if request.policy_version != FIXTURE_POLICY_VERSION {
        return deny("unsupported_policy_version");
    }
    if request.principal_id != grant.principal_id
        || request.channel_binding_id != grant.channel_binding_id
        || request.task_id != grant.task_id
        || request.run_id != grant.run_id
    {
        return deny("request_owner_or_scope_not_granted");
    }
    if request.evaluated_at_ms < grant.valid_from_ms
        || request.evaluated_at_ms >= grant.expires_at_ms
    {
        return deny("grant_not_current");
    }
    if !request
        .enforceable_profiles
        .contains(&request.requested_profile)
    {
        return deny("profile_not_enforceable");
    }
    let resource = validate_fixture_read_arguments(&request.normalized_arguments).ok();
    let fixture_contract_matches = request.agent_role == "assistant"
        && request.task_risk == RiskClass::Low
        && request.tool.tool_id == "fixture.read"
        && request.tool.descriptor_digest == grant.tool_descriptor_digest
        && request.tool.effect_class == EffectClass::ReadOnly
        && request.tool.risk_class == RiskClass::Low
        && request.tool.idempotency == IdempotencyClass::Pure
        && request.tool.recovery == RecoveryStrategy::Retry
        && request.tool.executor == ExecutorKind::Builtin
        && request.tool.concurrency == ToolConcurrency::Serial
        && request.requested_capability == "observe:fixture"
        && request.tool.required_capabilities == [request.requested_capability.clone()]
        && request.requested_profile == PolicyProfile::Observe
        && request.workspace_roots.is_empty()
        && request.resource_claims.is_empty()
        && request.secret_references.is_empty()
        && request.network_destinations.is_empty()
        && resource.is_some_and(|resource| request.target_resources == [resource]);
    if !fixture_contract_matches {
        return deny("no_matching_allow_rule");
    }

    let Ok(maximum_duration_ms) = u64::try_from(request.tool.timeout.as_millis()) else {
        return deny("invalid_request");
    };
    PolicyEvaluation {
        decision: PolicyDecision::Allow,
        obligations: PolicyObligations {
            profile: PolicyProfile::Observe,
            readable_paths: Vec::new(),
            writable_paths: Vec::new(),
            allowed_executable_identity_digests: vec![
                request.tool.executable_identity_digest.clone(),
            ],
            allow_process_spawn: false,
            allowed_environment_variables: Vec::new(),
            network_destinations: Vec::new(),
            secret_references: Vec::new(),
            argument_rewrite: None,
            redactions: Vec::new(),
            maximum_duration_ms,
            maximum_output_bytes: request.tool.maximum_output_bytes,
            maximum_memory_bytes: 0,
            maximum_processes: 0,
            validator_required: false,
        },
        policy_version: request.policy_version.clone(),
        explanation: "fixture_read_allowed".to_owned(),
    }
}

fn validate_field(field: &'static str, value: &str) -> Result<(), PolicyRequestError> {
    if value.is_empty() || value.len() > 512 {
        Err(PolicyRequestError::InvalidField { field })
    } else {
        Ok(())
    }
}

fn validate_string_set(
    field: &'static str,
    values: &[String],
    required: bool,
) -> Result<(), PolicyRequestError> {
    if required && values.is_empty()
        || values
            .iter()
            .any(|value| value.is_empty() || value.len() > 1_024)
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        Err(PolicyRequestError::NonCanonicalSet { field })
    } else {
        Ok(())
    }
}

/// Invalid deterministic policy input.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PolicyRequestError {
    /// The tool contract or its digest evidence is invalid.
    #[error(transparent)]
    Tool(#[from] ToolDescriptorValidationError),
    /// A required string is empty or oversized.
    #[error("policy request field {field} is empty or oversized")]
    InvalidField {
        /// Invalid field name.
        field: &'static str,
    },
    /// A set-like request field is not sorted, unique, and bounded.
    #[error("policy request set {field} is not canonical")]
    NonCanonicalSet {
        /// Invalid field name.
        field: &'static str,
    },
    /// Host-enforceable profiles are empty, unsorted, or duplicated.
    #[error("policy request enforceable profiles are not canonical")]
    NonCanonicalProfiles,
    /// Evaluation time precedes the Unix epoch.
    #[error("policy evaluation time is invalid")]
    InvalidEvaluationTime,
    /// Fixture grant window is empty or precedes the Unix epoch.
    #[error("fixture policy grant window is invalid")]
    InvalidGrantWindow,
    /// Fixture grant does not bind a canonical generic descriptor digest.
    #[error("fixture policy grant tool descriptor digest is invalid")]
    InvalidGrantToolDigest,
}

#[cfg(test)]
mod tests {
    use super::{
        FIXTURE_POLICY_VERSION, FixturePolicyGrant, PolicyDecision, PolicyRequest,
        evaluate_fixture_policy,
    };
    use crate::{ReadToolDescriptor, ToolDescriptor, sha256_digest};
    use mealy_domain::{ChannelBindingId, PolicyProfile, PrincipalId, RiskClass, RunId, TaskId};
    use std::time::Duration;

    fn fixture_descriptor() -> ToolDescriptor {
        let input_schema = serde_json::json!({
            "type": "object",
            "required": ["resourceId"],
        });
        let mut legacy = ReadToolDescriptor {
            tool_id: "fixture.read".to_owned(),
            version: "1".to_owned(),
            schema_digest: sha256_digest(input_schema.to_string().as_bytes()),
            input_schema,
            output_schema: serde_json::json!({"type": "object"}),
            descriptor_digest: String::new(),
            effect_class: "read_only".to_owned(),
            risk_class: "low".to_owned(),
            required_capability: "observe:fixture".to_owned(),
            timeout: Duration::from_secs(1),
            maximum_output_bytes: 1_024,
            conflict_key_template: "fixture-read:{resourceId}".to_owned(),
            recovery: "retry".to_owned(),
        };
        legacy.descriptor_digest = legacy
            .computed_descriptor_digest()
            .expect("compute Phase 2 descriptor digest");
        ToolDescriptor::try_from(legacy).expect("convert fixture descriptor")
    }

    fn request_and_grant() -> (PolicyRequest, FixturePolicyGrant) {
        let principal_id = PrincipalId::new();
        let channel_binding_id = ChannelBindingId::new();
        let task_id = TaskId::new();
        let run_id = RunId::new();
        let tool = fixture_descriptor();
        let grant = FixturePolicyGrant {
            principal_id,
            channel_binding_id,
            task_id,
            run_id,
            tool_descriptor_digest: tool.descriptor_digest.clone(),
            valid_from_ms: 100,
            expires_at_ms: 1_000,
        };
        let request = PolicyRequest {
            principal_id,
            channel_binding_id,
            task_id,
            run_id,
            agent_role: "assistant".to_owned(),
            task_risk: RiskClass::Low,
            tool,
            normalized_arguments: serde_json::json!({
                "resourceId": "fixture://phase3/report",
            }),
            target_resources: vec!["fixture://phase3/report".to_owned()],
            workspace_roots: Vec::new(),
            resource_claims: Vec::new(),
            secret_references: Vec::new(),
            network_destinations: Vec::new(),
            requested_capability: "observe:fixture".to_owned(),
            requested_profile: PolicyProfile::Observe,
            enforceable_profiles: vec![PolicyProfile::Observe],
            evaluated_at_ms: 500,
            policy_version: FIXTURE_POLICY_VERSION.to_owned(),
        };
        (request, grant)
    }

    #[test]
    fn exact_fixture_read_is_allowed_with_deny_by_default_obligations() {
        let (request, grant) = request_and_grant();
        let evaluation = evaluate_fixture_policy(&request, &grant);
        assert_eq!(evaluation.decision, PolicyDecision::Allow);
        assert_eq!(evaluation.explanation, "fixture_read_allowed");
        assert_eq!(evaluation.obligations.profile, PolicyProfile::Observe);
        assert!(evaluation.obligations.readable_paths.is_empty());
        assert!(evaluation.obligations.writable_paths.is_empty());
        assert!(!evaluation.obligations.allow_process_spawn);
        assert!(evaluation.obligations.network_destinations.is_empty());
        assert_eq!(evaluation.obligations.maximum_duration_ms, 1_000);
        assert_eq!(evaluation.obligations.maximum_output_bytes, 1_024);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_policy_input_axis_is_evaluated_and_mutation_denies() {
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
        mutations.push(("agent", changed));
        let mut changed = original.clone();
        changed.task_risk = RiskClass::Medium;
        mutations.push(("task risk", changed));
        let mut changed = original.clone();
        changed.tool.executable_identity_digest = sha256_digest(b"changed executable");
        changed.tool.descriptor_digest = changed
            .tool
            .computed_descriptor_digest()
            .expect("reseal changed tool");
        mutations.push(("tool", changed));
        let mut changed = original.clone();
        changed.normalized_arguments = serde_json::json!({
            "resourceId": "fixture://phase3/other",
        });
        mutations.push(("arguments", changed));
        let mut changed = original.clone();
        changed.target_resources = vec!["fixture://phase3/other".to_owned()];
        mutations.push(("target resource", changed));
        let mut changed = original.clone();
        changed.workspace_roots = vec!["workspace://root".to_owned()];
        mutations.push(("workspace", changed));
        let mut changed = original.clone();
        changed.resource_claims = vec!["workspace-write:root".to_owned()];
        mutations.push(("resource claims", changed));
        let mut changed = original.clone();
        changed.secret_references = vec!["secret://fixture".to_owned()];
        mutations.push(("secret references", changed));
        let mut changed = original.clone();
        changed.network_destinations = vec!["https://example.invalid".to_owned()];
        mutations.push(("network", changed));
        let mut changed = original.clone();
        changed.requested_capability = "observe:other".to_owned();
        mutations.push(("capability", changed));
        let mut changed = original.clone();
        changed.requested_profile = PolicyProfile::FullTrust;
        changed.enforceable_profiles = vec![PolicyProfile::Observe, PolicyProfile::FullTrust];
        mutations.push(("profile", changed));
        let mut changed = original.clone();
        changed.enforceable_profiles = vec![PolicyProfile::Networked];
        mutations.push(("host enforcement", changed));
        let mut changed = original.clone();
        changed.evaluated_at_ms = grant.expires_at_ms;
        mutations.push(("time", changed));
        let mut changed = original;
        changed.policy_version = "unknown-policy".to_owned();
        mutations.push(("policy version", changed));

        for (axis, mutation) in mutations {
            let evaluation = evaluate_fixture_policy(&mutation, &grant);
            assert_eq!(
                evaluation.decision,
                PolicyDecision::Deny,
                "{axis} mutation was not denied"
            );
            assert_eq!(evaluation.obligations.maximum_duration_ms, 0);
            assert_eq!(evaluation.obligations.maximum_output_bytes, 0);
            assert!(
                evaluation
                    .obligations
                    .allowed_executable_identity_digests
                    .is_empty()
            );
        }
    }
}
