use crate::{is_sha256_digest, sha256_digest};
use mealy_domain::{EffectId, PrincipalId, TaskId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Version included in every approval subject digest.
pub const APPROVAL_SUBJECT_CONTRACT_VERSION: &str = "mealy.approval-subject.v1";
/// Namespace used for downstream idempotency keys derived from effect identity.
pub const EFFECT_IDEMPOTENCY_KEY_PREFIX: &str = "mealy-effect-v1";

/// Exact immutable subject authorized or denied by an approval command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalSubject {
    /// Principal whose authority is being extended.
    pub principal_id: PrincipalId,
    /// Task that owns the proposed effect.
    pub task_id: TaskId,
    /// Effect that may be dispatched after approval.
    pub effect_id: EffectId,
    /// Stable tool identity.
    pub tool_id: String,
    /// Exact tool contract version.
    pub tool_version: String,
    /// SHA-256 digest of the exact normalized arguments.
    pub canonical_arguments_digest: String,
    /// Exact requested capability scope.
    pub capability_scope: String,
    /// Canonical sorted set of target resources.
    pub target_resources: Vec<String>,
    /// SHA-256 digest of the executable, built-in, extension, or provider identity.
    pub executable_identity_digest: String,
    /// Exact policy bundle version whose decision requested approval.
    pub policy_version: String,
    /// Approval expiry as Unix epoch milliseconds.
    pub expires_at_ms: i64,
}

impl ApprovalSubject {
    /// Validates every approval-bound field without consulting ambient state.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalSubjectError`] for an invalid digest, string, resource set, or expiry.
    pub fn validate(&self) -> Result<(), ApprovalSubjectError> {
        validate_field("tool_id", &self.tool_id)?;
        validate_field("tool_version", &self.tool_version)?;
        validate_field("capability_scope", &self.capability_scope)?;
        validate_field("policy_version", &self.policy_version)?;
        if !is_sha256_digest(&self.canonical_arguments_digest) {
            return Err(ApprovalSubjectError::InvalidArgumentsDigest);
        }
        if !is_sha256_digest(&self.executable_identity_digest) {
            return Err(ApprovalSubjectError::InvalidExecutableIdentityDigest);
        }
        if self.target_resources.is_empty()
            || self
                .target_resources
                .iter()
                .any(|resource| resource.is_empty() || resource.len() > 1_024)
            || self
                .target_resources
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(ApprovalSubjectError::NonCanonicalTargetResources);
        }
        if self.expires_at_ms <= 0 {
            return Err(ApprovalSubjectError::InvalidExpiry);
        }
        Ok(())
    }

    /// Returns canonical versioned JSON material containing every approval-bound field.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalSubjectError`] when the subject is malformed.
    pub fn canonical_material(&self) -> Result<serde_json::Value, ApprovalSubjectError> {
        self.validate()?;
        Ok(serde_json::json!({
            "contractVersion": APPROVAL_SUBJECT_CONTRACT_VERSION,
            "principalId": self.principal_id,
            "taskId": self.task_id,
            "effectId": self.effect_id,
            "toolIdentity": {
                "toolId": self.tool_id,
                "version": self.tool_version,
            },
            "canonicalArgumentsDigest": self.canonical_arguments_digest,
            "capabilityScope": self.capability_scope,
            "targetResources": self.target_resources,
            "executableIdentityDigest": self.executable_identity_digest,
            "policyVersion": self.policy_version,
            "expiresAtMs": self.expires_at_ms,
        }))
    }

    /// Computes the SHA-256 approval subject digest.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalSubjectError`] when the subject is malformed.
    pub fn subject_digest(&self) -> Result<String, ApprovalSubjectError> {
        Ok(sha256_digest(
            self.canonical_material()?.to_string().as_bytes(),
        ))
    }
}

/// Computes a deterministic digest over normalized JSON arguments.
#[must_use]
pub fn canonical_arguments_digest(arguments: &serde_json::Value) -> String {
    sha256_digest(canonical_json(arguments).to_string().as_bytes())
}

/// Derives the stable downstream idempotency key for one effect.
///
/// The function is pure: every retry of the same effect receives the exact same key, while a new
/// effect ID necessarily receives a different key.
#[must_use]
pub fn derive_effect_idempotency_key(effect_id: EffectId) -> String {
    format!("{EFFECT_IDEMPOTENCY_KEY_PREFIX}:{effect_id}")
}

fn canonical_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(object) => {
            let mut fields: Vec<_> = object.iter().collect();
            fields.sort_unstable_by_key(|(key, _)| *key);
            let mut canonical = serde_json::Map::new();
            for (key, value) in fields {
                canonical.insert(key.clone(), canonical_json(value));
            }
            serde_json::Value::Object(canonical)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(canonical_json).collect())
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => value.clone(),
    }
}

fn validate_field(field: &'static str, value: &str) -> Result<(), ApprovalSubjectError> {
    if value.is_empty() || value.len() > 512 {
        Err(ApprovalSubjectError::InvalidField { field })
    } else {
        Ok(())
    }
}

/// Malformed or non-canonical approval subject.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ApprovalSubjectError {
    /// A required string is empty or oversized.
    #[error("approval subject field {field} is empty or oversized")]
    InvalidField {
        /// Invalid field name.
        field: &'static str,
    },
    /// Normalized arguments are not represented by a canonical SHA-256 digest.
    #[error("approval subject arguments digest is invalid")]
    InvalidArgumentsDigest,
    /// Executable identity is not represented by a canonical SHA-256 digest.
    #[error("approval subject executable identity digest is invalid")]
    InvalidExecutableIdentityDigest,
    /// Target resources are empty, unsorted, duplicated, or malformed.
    #[error("approval subject target resources are not canonical")]
    NonCanonicalTargetResources,
    /// Expiry is not a positive Unix epoch millisecond value.
    #[error("approval subject expiry is invalid")]
    InvalidExpiry,
}

#[cfg(test)]
mod tests {
    use super::{
        APPROVAL_SUBJECT_CONTRACT_VERSION, ApprovalSubject, canonical_arguments_digest,
        derive_effect_idempotency_key,
    };
    use crate::sha256_digest;
    use mealy_domain::{EffectId, PrincipalId, TaskId};

    fn subject() -> ApprovalSubject {
        ApprovalSubject {
            principal_id: PrincipalId::new(),
            task_id: TaskId::new(),
            effect_id: EffectId::new(),
            tool_id: "service.update".to_owned(),
            tool_version: "2".to_owned(),
            canonical_arguments_digest: canonical_arguments_digest(&serde_json::json!({
                "resourceId": "service://example/item",
                "value": 7,
            })),
            capability_scope: "service:item:update".to_owned(),
            target_resources: vec![
                "service://example/item".to_owned(),
                "service://example/ledger".to_owned(),
            ],
            executable_identity_digest: sha256_digest(b"service-update-v2"),
            policy_version: "policy-7".to_owned(),
            expires_at_ms: 9_000,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_bound_field_mutation_changes_the_subject_digest() {
        let original = subject();
        let original_digest = original.subject_digest().expect("valid original subject");
        let material = original.canonical_material().expect("canonical material");
        assert_eq!(
            material["contractVersion"],
            APPROVAL_SUBJECT_CONTRACT_VERSION
        );

        let mut mutations = Vec::new();
        let mut changed = original.clone();
        changed.principal_id = PrincipalId::new();
        mutations.push(("principal", changed));
        let mut changed = original.clone();
        changed.task_id = TaskId::new();
        mutations.push(("task", changed));
        let mut changed = original.clone();
        changed.effect_id = EffectId::new();
        mutations.push(("effect", changed));
        let mut changed = original.clone();
        changed.tool_id.push_str(".changed");
        mutations.push(("tool ID", changed));
        let mut changed = original.clone();
        changed.tool_version.push_str(".1");
        mutations.push(("tool version", changed));
        let mut changed = original.clone();
        changed.canonical_arguments_digest = canonical_arguments_digest(&serde_json::json!({
            "resourceId": "service://example/item",
            "value": 8,
        }));
        mutations.push(("arguments", changed));
        let mut changed = original.clone();
        changed.capability_scope.push_str(":admin");
        mutations.push(("capability scope", changed));
        let mut changed = original.clone();
        changed
            .target_resources
            .push("service://example/third".to_owned());
        mutations.push(("target resources", changed));
        let mut changed = original.clone();
        changed.executable_identity_digest = sha256_digest(b"service-update-v3");
        mutations.push(("executable identity", changed));
        let mut changed = original.clone();
        changed.policy_version.push_str(".changed");
        mutations.push(("policy version", changed));
        let mut changed = original;
        changed.expires_at_ms += 1;
        mutations.push(("expiry", changed));

        for (field, mutation) in mutations {
            assert_ne!(
                mutation.subject_digest().expect("valid mutated subject"),
                original_digest,
                "{field} was not bound"
            );
        }
    }

    #[test]
    fn normalized_json_and_effect_keys_are_stable() {
        let left: serde_json::Value =
            serde_json::from_str(r#"{"b":2,"a":1}"#).expect("parse left arguments");
        let right: serde_json::Value =
            serde_json::from_str(r#"{"a":1,"b":2}"#).expect("parse right arguments");
        assert_eq!(
            canonical_arguments_digest(&left),
            canonical_arguments_digest(&right)
        );

        let effect_id = EffectId::new();
        let key = derive_effect_idempotency_key(effect_id);
        assert_eq!(key, derive_effect_idempotency_key(effect_id));
        assert_ne!(key, derive_effect_idempotency_key(EffectId::new()));
        assert!(key.ends_with(&effect_id.to_string()));
    }
}
