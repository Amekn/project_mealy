use mealy_domain::{
    ArtifactId, CompactionId, ContextEpochId, ContextItemId, ContextManifestId, MemoryId,
    MemoryRevisionId, RunId, SessionId, TurnId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AgentContextSource, IdGenerator, MessageRole, NormalizedMessage, OwnershipContext,
    is_sha256_digest, sha256_digest,
};

/// Immutable baseline used while compiling requests for one session turn.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextEpoch {
    /// Epoch identity.
    pub epoch_id: ContextEpochId,
    /// Owning session.
    pub session_id: SessionId,
    /// Monotonic number within the session.
    pub epoch_number: u64,
    /// Versioned system-instruction baseline.
    pub baseline_version: String,
    /// SHA-256 digest of the baseline text.
    pub baseline_digest: String,
    /// Bounded baseline instructions.
    pub baseline_text: String,
    /// Versioned, non-secret effective agent profile.
    pub agent_profile: serde_json::Value,
    /// Digest of non-secret effective configuration.
    pub config_digest: String,
    /// Digest of the policy bundle used for selection.
    pub policy_digest: String,
    /// Logical workspace identity, never a host path.
    pub workspace_identity: String,
    /// Commit timestamp in Unix milliseconds.
    pub created_at_ms: i64,
}

/// Durable context selection outcome for one candidate item.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextDisposition {
    /// Content was included in the provider projection.
    Included,
    /// Content was not selected.
    Excluded,
    /// The item is visible as evidence, but its content is withheld.
    Redacted,
}

impl ContextDisposition {
    /// Stable storage representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Included => "included",
            Self::Excluded => "excluded",
            Self::Redacted => "redacted",
        }
    }
}

/// One ordered, inspectable context candidate and its policy decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextManifestItem {
    /// Stable item identity.
    pub item_id: ContextItemId,
    /// Zero-based deterministic order.
    pub ordinal: u64,
    /// Selection outcome.
    pub disposition: ContextDisposition,
    /// Typed source class such as `baseline`, `user`, or `tool`.
    pub source_type: String,
    /// Safe logical locator, never an ambient secret or unrestricted path.
    pub source_locator: String,
    /// Digest of canonical source content.
    pub source_content_digest: String,
    /// Digest after deterministic transformation.
    pub rendered_content_digest: String,
    /// Bounded reason for inclusion or exclusion.
    pub inclusion_reason: String,
    /// Sensitivity classification.
    pub sensitivity: String,
    /// Deterministic token estimate.
    pub token_estimate: u64,
    /// Transformation identifier.
    pub transformation: String,
    /// Bounded policy decision explanation.
    pub policy_decision: String,
    /// Bounded inline content when included.
    pub content: Option<String>,
    /// Committed artifact when included content exceeds the inline threshold.
    pub content_artifact_id: Option<ArtifactId>,
    /// Exact cited memory revision when this included item is untrusted retrieved evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_evidence: Option<ContextMemoryEvidence>,
    /// Exact derived compaction artifact when this included item replaces older history tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compaction_id: Option<CompactionId>,
}

/// One immutable source digest cited by a retrieved memory revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextMemorySourceCitation {
    /// One-based source ordinal on the immutable revision.
    pub source_ordinal: u64,
    /// Canonical source content digest.
    pub source_digest: String,
}

/// Exact governed-memory evidence attached to one included context item.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextMemoryEvidence {
    /// Logical memory identity.
    pub memory_id: MemoryId,
    /// Exact active revision used during compilation.
    pub revision_id: MemoryRevisionId,
    /// Immutable provenance citations retained in the manifest.
    pub sources: Vec<ContextMemorySourceCitation>,
}

/// Exact immutable provider projection for one model attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextManifest {
    /// Manifest identity.
    pub manifest_id: ContextManifestId,
    /// Owning run.
    pub run_id: RunId,
    /// Owning turn.
    pub turn_id: TurnId,
    /// Immutable baseline epoch.
    pub epoch_id: ContextEpochId,
    /// One-based agent-loop iteration.
    pub iteration: u64,
    /// Deterministic compiler version.
    pub compiler_version: String,
    /// Provider residency constraint.
    pub provider_residency: String,
    /// Maximum context tokens.
    pub token_budget: u64,
    /// Sum of included item estimates.
    pub total_token_estimate: u64,
    /// Digest of the ordered tool schema set.
    pub tool_schema_set_digest: String,
    /// Policy bundle version.
    pub policy_version: String,
    /// Digest of the complete ordered provider projection.
    pub projection_digest: String,
    /// Included, excluded, and redacted candidates in deterministic order.
    pub items: Vec<ContextManifestItem>,
    /// Commit timestamp in Unix milliseconds.
    pub created_at_ms: i64,
}

/// One ordered item in an owner-authorized, path-safe context-manifest projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextManifestEvidenceItem {
    /// Stable item identity.
    pub item_id: ContextItemId,
    /// Contiguous zero-based position in the manifest.
    pub ordinal: u64,
    /// Included, excluded, or redacted selection outcome.
    pub disposition: ContextDisposition,
    /// Typed source class.
    pub source_type: String,
    /// Safe logical locator; local and artifact-store paths are rejected.
    pub source_locator: String,
    /// Digest of canonical source content.
    pub source_content_digest: String,
    /// Digest after the recorded deterministic transformation.
    pub rendered_content_digest: String,
    /// Recorded reason for inclusion, exclusion, or redaction.
    pub inclusion_reason: String,
    /// Sensitivity classification.
    pub sensitivity: String,
    /// Deterministic token estimate.
    pub token_estimate: u64,
    /// Recorded transformation identifier.
    pub transformation: String,
    /// Recorded policy decision explanation.
    pub policy_decision: String,
    /// Authorized inline content, present only for an included item.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Authorized artifact reference, present only for an included oversized item.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_artifact_id: Option<ArtifactId>,
    /// Exact cited memory revision and immutable sources, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_evidence: Option<ContextMemoryEvidence>,
    /// Exact derived compaction represented by this item, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compaction_id: Option<CompactionId>,
}

/// Owner-authorized, path-safe inspection view of one immutable context manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextManifestEvidence {
    /// Manifest identity.
    pub manifest_id: ContextManifestId,
    /// Owning run.
    pub run_id: RunId,
    /// Owning turn.
    pub turn_id: TurnId,
    /// Immutable baseline epoch.
    pub epoch_id: ContextEpochId,
    /// One-based loop iteration.
    pub iteration: u64,
    /// Deterministic compiler version.
    pub compiler_version: String,
    /// Provider residency constraint.
    pub provider_residency: String,
    /// Maximum compiled context tokens.
    pub token_budget: u64,
    /// Sum of included-item token estimates.
    pub total_token_estimate: u64,
    /// Digest of the ordered tool-schema set.
    pub tool_schema_set_digest: String,
    /// Policy bundle version.
    pub policy_version: String,
    /// Digest of the exact provider projection.
    pub projection_digest: String,
    /// Included, excluded, and redacted items in committed order.
    pub items: Vec<ContextManifestEvidenceItem>,
    /// Commit timestamp in Unix milliseconds.
    pub created_at_ms: i64,
}

/// Failure from an owner-authorized context-manifest evidence read.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContextManifestEvidenceStoreError {
    /// Manifest does not exist or is deliberately hidden from the supplied owner and channel.
    #[error("context manifest evidence was not found")]
    NotFound,
    /// Persistence could not complete the projection.
    #[error("context manifest evidence store is unavailable: {0}")]
    Unavailable(String),
    /// Stored evidence violates ordering, content, digest, or path-safety invariants.
    #[error("context manifest evidence invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port for owner-authorized context-manifest inspection.
pub trait ContextManifestEvidenceStore {
    /// Returns one complete manifest projection after owner and channel authorization.
    ///
    /// # Errors
    ///
    /// Returns [`ContextManifestEvidenceStoreError`] when the manifest is absent, unauthorized,
    /// unavailable, or internally inconsistent.
    fn context_manifest_evidence(
        &self,
        ownership: OwnershipContext,
        manifest_id: ContextManifestId,
    ) -> Result<ContextManifestEvidence, ContextManifestEvidenceStoreError>;
}

/// Validates ordering, path safety, digest consistency, and withheld-content invariants.
///
/// # Errors
///
/// Returns [`ContextManifestEvidenceStoreError::InvariantViolation`] when evidence cannot be
/// projected safely.
pub fn validate_context_manifest_evidence(
    evidence: &ContextManifestEvidence,
) -> Result<(), ContextManifestEvidenceStoreError> {
    if evidence.iteration == 0 || evidence.token_budget == 0 || evidence.created_at_ms < 0 {
        return Err(context_evidence_invariant(
            "manifest bounds or timestamp are invalid",
        ));
    }
    if !is_sha256_digest(&evidence.tool_schema_set_digest)
        || !is_sha256_digest(&evidence.projection_digest)
    {
        return Err(context_evidence_invariant(
            "manifest digest is not canonical SHA-256",
        ));
    }

    let mut included_tokens = 0_u64;
    for (expected_ordinal, item) in evidence.items.iter().enumerate() {
        if item.ordinal
            != u64::try_from(expected_ordinal)
                .map_err(|_| context_evidence_invariant("manifest ordinal is out of range"))?
        {
            return Err(context_evidence_invariant(
                "manifest item order is not contiguous",
            ));
        }
        if !safe_logical_locator(&item.source_locator) {
            return Err(context_evidence_invariant(
                "context source locator is not path-safe",
            ));
        }
        if !is_sha256_digest(&item.source_content_digest)
            || !is_sha256_digest(&item.rendered_content_digest)
        {
            return Err(context_evidence_invariant(
                "context item digest is not canonical SHA-256",
            ));
        }

        match item.disposition {
            ContextDisposition::Included => {
                if item.content.is_some() == item.content_artifact_id.is_some() {
                    return Err(context_evidence_invariant(
                        "included context item has an invalid content representation",
                    ));
                }
                if let Some(content) = &item.content
                    && sha256_digest(content.as_bytes()) != item.rendered_content_digest
                {
                    return Err(context_evidence_invariant(
                        "included context content digest does not match",
                    ));
                }
                included_tokens = included_tokens
                    .checked_add(item.token_estimate)
                    .ok_or_else(|| {
                        context_evidence_invariant("included context token total overflowed")
                    })?;
                validate_phase_five_context_evidence(
                    &item.source_type,
                    item.memory_evidence.as_ref(),
                    item.compaction_id,
                )?;
            }
            ContextDisposition::Excluded | ContextDisposition::Redacted => {
                if item.content.is_some() || item.content_artifact_id.is_some() {
                    return Err(context_evidence_invariant(
                        "withheld context item carried content",
                    ));
                }
                if item.memory_evidence.is_some() || item.compaction_id.is_some() {
                    return Err(context_evidence_invariant(
                        "withheld context item carried inclusion-only provenance",
                    ));
                }
            }
        }
    }
    if included_tokens != evidence.total_token_estimate || included_tokens > evidence.token_budget {
        return Err(context_evidence_invariant(
            "context token estimates are inconsistent",
        ));
    }
    Ok(())
}

fn validate_phase_five_context_evidence(
    source_type: &str,
    memory_evidence: Option<&ContextMemoryEvidence>,
    compaction_id: Option<CompactionId>,
) -> Result<(), ContextManifestEvidenceStoreError> {
    match source_type {
        "memory" => {
            let Some(evidence) = memory_evidence else {
                return Err(context_evidence_invariant(
                    "included memory lacks immutable citations",
                ));
            };
            if compaction_id.is_some()
                || evidence.sources.is_empty()
                || evidence.sources.len() > 64
                || evidence.sources.iter().enumerate().any(|(index, source)| {
                    source.source_ordinal
                        != u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1)
                        || !is_sha256_digest(&source.source_digest)
                })
            {
                return Err(context_evidence_invariant(
                    "included memory citation evidence is invalid",
                ));
            }
        }
        "compaction" if compaction_id.is_some() && memory_evidence.is_none() => {}
        "compaction" => {
            return Err(context_evidence_invariant(
                "included compaction lacks exact artifact provenance",
            ));
        }
        _ if memory_evidence.is_none() && compaction_id.is_none() => {}
        _ => {
            return Err(context_evidence_invariant(
                "context provenance does not match its source type",
            ));
        }
    }
    Ok(())
}

fn safe_logical_locator(locator: &str) -> bool {
    let Some((scheme, remainder)) = locator.split_once("://") else {
        return false;
    };
    if scheme.is_empty()
        || scheme.eq_ignore_ascii_case("file")
        || !scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        || remainder.is_empty()
        || remainder.starts_with('/')
        || locator.contains('\\')
    {
        return false;
    }
    let windows_drive_path = remainder
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        && remainder.as_bytes().get(1) == Some(&b':');
    !windows_drive_path && !remainder.split('/').any(|segment| segment == "..")
}

fn context_evidence_invariant(message: impl Into<String>) -> ContextManifestEvidenceStoreError {
    ContextManifestEvidenceStoreError::InvariantViolation(message.into())
}

/// Context compilation failure before provider dispatch.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContextError {
    /// An included item had neither or both storage representations.
    #[error("included context item must have exactly one content representation")]
    InvalidIncludedContent,
    /// Withheld content incorrectly carried a representation.
    #[error("excluded or redacted context item cannot carry content")]
    WithheldContentPresent,
    /// Included material exceeded the configured context budget.
    #[error("context token estimate {actual} exceeds maximum {maximum}")]
    TokenBudgetExceeded {
        /// Estimated included tokens.
        actual: u64,
        /// Configured maximum.
        maximum: u64,
    },
    /// Declared aggregate did not equal the deterministic sum of included items.
    #[error("context token estimate {declared} does not equal included item total {actual}")]
    TokenEstimateMismatch {
        /// Manifest aggregate.
        declared: u64,
        /// Sum of included items.
        actual: u64,
    },
    /// Context commit time could not be represented as Unix milliseconds.
    #[error("context commit time cannot be represented")]
    InvalidCommitTime,
    /// The mandatory system baseline alone exceeds the provider budget.
    #[error("system baseline exceeds the context token budget")]
    BaselineExceedsBudget,
    /// Provider-neutral projection could not be encoded for hashing.
    #[error("context provider projection cannot be encoded")]
    ProjectionEncoding,
}

/// Deterministic compiler output used for both persistence and the normalized provider request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledContext {
    /// Complete inspectable immutable manifest.
    pub manifest: ContextManifest,
    /// Exact ordered messages projected to the provider.
    pub messages: Vec<NormalizedMessage>,
}

/// Compiles authorized sources under a fixed epoch and token budget.
///
/// Candidate order is stable: the mandatory baseline, then the supplied canonical sources. Items
/// that do not fit remain visible as excluded evidence instead of silently disappearing.
///
/// # Errors
///
/// Returns [`ContextError`] when the baseline cannot fit or time cannot be represented.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn compile_context(
    ids: &impl IdGenerator,
    run_id: RunId,
    turn_id: TurnId,
    epoch: &ContextEpoch,
    iteration: u64,
    sources: &[AgentContextSource],
    token_budget: u64,
    provider_residency: &str,
    tool_schema_set_digest: &str,
    policy_version: &str,
    created_at: std::time::SystemTime,
) -> Result<CompiledContext, ContextError> {
    let created_at_ms = i64::try_from(
        created_at
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|_| ContextError::InvalidCommitTime)?
            .as_millis(),
    )
    .map_err(|_| ContextError::InvalidCommitTime)?;
    let baseline_tokens = estimate_tokens(&epoch.baseline_text);
    if baseline_tokens > token_budget {
        return Err(ContextError::BaselineExceedsBudget);
    }
    let mut total = baseline_tokens;
    let mut messages = vec![NormalizedMessage {
        role: MessageRole::System,
        content: epoch.baseline_text.clone(),
        tool_call_id: None,
    }];
    let mut items = vec![ContextManifestItem {
        item_id: ids.generate_context_item_id(),
        ordinal: 0,
        disposition: ContextDisposition::Included,
        source_type: "baseline".to_owned(),
        source_locator: format!("baseline://{}", epoch.baseline_version),
        source_content_digest: epoch.baseline_digest.clone(),
        rendered_content_digest: epoch.baseline_digest.clone(),
        inclusion_reason: "mandatory versioned turn baseline".to_owned(),
        sensitivity: "internal".to_owned(),
        token_estimate: baseline_tokens,
        transformation: "identity".to_owned(),
        policy_decision: "allow: mandatory baseline".to_owned(),
        content: Some(epoch.baseline_text.clone()),
        content_artifact_id: None,
        memory_evidence: None,
        compaction_id: None,
    }];
    for (index, source) in sources.iter().enumerate() {
        let token_estimate = estimate_tokens(&source.message.content);
        let rendered_digest = sha256_digest(source.message.content.as_bytes());
        let included = total
            .checked_add(token_estimate)
            .is_some_and(|candidate| candidate <= token_budget);
        if included {
            total = total.saturating_add(token_estimate);
            messages.push(source.message.clone());
        }
        items.push(ContextManifestItem {
            item_id: ids.generate_context_item_id(),
            ordinal: u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1),
            disposition: if included {
                ContextDisposition::Included
            } else {
                ContextDisposition::Excluded
            },
            source_type: source.source_type.clone(),
            source_locator: source.source_locator.clone(),
            source_content_digest: source.source_content_digest.clone(),
            rendered_content_digest: rendered_digest,
            inclusion_reason: if included {
                "authorized canonical source within token budget".to_owned()
            } else {
                "excluded by deterministic token budget".to_owned()
            },
            sensitivity: source.sensitivity.clone(),
            token_estimate,
            transformation: "identity".to_owned(),
            policy_decision: if included {
                "allow: owner session context".to_owned()
            } else {
                "exclude: context budget".to_owned()
            },
            content: (included && source.content_artifact_id.is_none())
                .then(|| source.message.content.clone()),
            content_artifact_id: included.then_some(source.content_artifact_id).flatten(),
            memory_evidence: included.then(|| source.memory_evidence.clone()).flatten(),
            compaction_id: included.then_some(source.compaction_id).flatten(),
        });
    }
    let projection = serde_json::json!({
        "epochId": epoch.epoch_id,
        "iteration": iteration,
        "messages": messages,
        "toolSchemaSetDigest": tool_schema_set_digest,
        "policyVersion": policy_version,
        "providerResidency": provider_residency,
    });
    let projection_digest = sha256_digest(
        serde_json::to_string(&projection)
            .map_err(|_| ContextError::ProjectionEncoding)?
            .as_bytes(),
    );
    let manifest = ContextManifest {
        manifest_id: ids.generate_context_manifest_id(),
        run_id,
        turn_id,
        epoch_id: epoch.epoch_id,
        iteration,
        compiler_version: "mealy.context.v1".to_owned(),
        provider_residency: provider_residency.to_owned(),
        token_budget,
        total_token_estimate: total,
        tool_schema_set_digest: tool_schema_set_digest.to_owned(),
        policy_version: policy_version.to_owned(),
        projection_digest,
        items,
        created_at_ms,
    };
    validate_context_manifest(&manifest)?;
    Ok(CompiledContext { manifest, messages })
}

/// Validates representation and aggregate-budget invariants for a manifest.
///
/// # Errors
///
/// Returns [`ContextError`] when content representation or budget invariants fail.
pub fn validate_context_manifest(manifest: &ContextManifest) -> Result<(), ContextError> {
    let mut total = 0_u64;
    for item in &manifest.items {
        match item.disposition {
            ContextDisposition::Included => {
                if item.content.is_some() == item.content_artifact_id.is_some() {
                    return Err(ContextError::InvalidIncludedContent);
                }
                total = total.saturating_add(item.token_estimate);
                validate_phase_five_context_evidence(
                    &item.source_type,
                    item.memory_evidence.as_ref(),
                    item.compaction_id,
                )
                .map_err(|_| ContextError::InvalidIncludedContent)?;
            }
            ContextDisposition::Excluded | ContextDisposition::Redacted => {
                if item.content.is_some()
                    || item.content_artifact_id.is_some()
                    || item.memory_evidence.is_some()
                    || item.compaction_id.is_some()
                {
                    return Err(ContextError::WithheldContentPresent);
                }
            }
        }
    }
    if total != manifest.total_token_estimate {
        return Err(ContextError::TokenEstimateMismatch {
            declared: manifest.total_token_estimate,
            actual: total,
        });
    }
    if total > manifest.token_budget {
        return Err(ContextError::TokenBudgetExceeded {
            actual: total,
            maximum: manifest.token_budget,
        });
    }
    Ok(())
}

/// Deterministic conservative estimate used by the Phase 2 fake provider contract.
///
/// Production adapters may replace this with a model-specific tokenizer while retaining the
/// recorded estimate and compiler version.
#[must_use]
pub fn estimate_tokens(text: &str) -> u64 {
    u64::try_from(text.len()).unwrap_or(u64::MAX).div_ceil(4)
}

#[cfg(test)]
mod tests {
    use super::{
        ContextDisposition, ContextManifestEvidence, ContextManifestEvidenceItem,
        ContextManifestEvidenceStoreError, estimate_tokens, sha256_digest,
        validate_context_manifest_evidence,
    };
    use mealy_domain::{ContextEpochId, ContextItemId, ContextManifestId, RunId, TurnId};

    #[test]
    fn token_estimate_rounds_up_utf8_bytes() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("abcd"), 1);
        assert_eq!(estimate_tokens("abcde"), 2);
        assert_eq!(estimate_tokens("食"), 1);
    }

    #[test]
    fn evidence_rejects_local_paths_and_withheld_content() {
        let content = "included".to_owned();
        let mut evidence = ContextManifestEvidence {
            manifest_id: ContextManifestId::new(),
            run_id: RunId::new(),
            turn_id: TurnId::new(),
            epoch_id: ContextEpochId::new(),
            iteration: 1,
            compiler_version: "v1".to_owned(),
            provider_residency: "local".to_owned(),
            token_budget: 10,
            total_token_estimate: 2,
            tool_schema_set_digest:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            policy_version: "v1".to_owned(),
            projection_digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
            items: vec![ContextManifestEvidenceItem {
                item_id: ContextItemId::new(),
                ordinal: 0,
                disposition: ContextDisposition::Included,
                source_type: "baseline".to_owned(),
                source_locator: "baseline://v1".to_owned(),
                source_content_digest: sha256_digest(content.as_bytes()),
                rendered_content_digest: sha256_digest(content.as_bytes()),
                inclusion_reason: "mandatory".to_owned(),
                sensitivity: "internal".to_owned(),
                token_estimate: 2,
                transformation: "identity".to_owned(),
                policy_decision: "allow".to_owned(),
                content: Some(content),
                content_artifact_id: None,
                memory_evidence: None,
                compaction_id: None,
            }],
            created_at_ms: 1,
        };
        validate_context_manifest_evidence(&evidence).expect("valid evidence");

        evidence.items[0].source_locator = "file:///private/artifacts/blob".to_owned();
        assert!(matches!(
            validate_context_manifest_evidence(&evidence),
            Err(ContextManifestEvidenceStoreError::InvariantViolation(_))
        ));
        evidence.items[0].source_locator = "baseline://v1".to_owned();
        evidence.items[0].disposition = ContextDisposition::Redacted;
        assert!(matches!(
            validate_context_manifest_evidence(&evidence),
            Err(ContextManifestEvidenceStoreError::InvariantViolation(_))
        ));
    }
}
