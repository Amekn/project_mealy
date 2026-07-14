use crate::{CancellationProbe, sha256_digest};
use mealy_domain::{EffectClass, ExecutorKind, IdempotencyClass, RecoveryStrategy, RiskClass};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Version bound into the digest of every generic tool descriptor.
pub const TOOL_DESCRIPTOR_CONTRACT_VERSION: &str = "mealy.tool-descriptor.v1";

/// Whether calls to a tool may be scheduled concurrently.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolConcurrency {
    /// At most one call may execute at a time.
    Serial,
    /// Calls may overlap when their expanded conflict keys do not conflict.
    Parallel,
}

/// Complete, provider-neutral contract for a selectable tool.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDescriptor {
    /// Stable tool identity.
    pub tool_id: String,
    /// Contract version.
    pub version: String,
    /// Normalized input JSON Schema.
    pub input_schema: serde_json::Value,
    /// Normalized output JSON Schema.
    pub output_schema: serde_json::Value,
    /// Digest of the normalized input schema.
    pub input_schema_digest: String,
    /// Digest of the normalized output schema.
    pub output_schema_digest: String,
    /// Digest of [`Self::canonical_material`].
    pub descriptor_digest: String,
    /// Whether the operation can mutate an external system.
    pub effect_class: EffectClass,
    /// Policy-visible impact classification.
    pub risk_class: RiskClass,
    /// Canonical sorted set of logical capabilities required for dispatch.
    pub required_capabilities: Vec<String>,
    /// Hard execution timeout.
    #[serde(with = "duration_milliseconds")]
    pub timeout: Duration,
    /// Hard output bound before an artifact commit.
    pub maximum_output_bytes: u64,
    /// Declared concurrency behavior.
    pub concurrency: ToolConcurrency,
    /// Canonical sorted set of deterministic conflict-key templates.
    pub conflict_key_templates: Vec<String>,
    /// Downstream repetition guarantee.
    pub idempotency: IdempotencyClass,
    /// Recovery behavior after an interrupted boundary.
    pub recovery: RecoveryStrategy,
    /// Runtime boundary responsible for execution.
    pub executor: ExecutorKind,
    /// Digest of the executable, built-in implementation, provider, or extension identity.
    pub executable_identity_digest: String,
}

impl ToolDescriptor {
    /// Returns versioned canonical material containing every contract field except its own digest.
    ///
    /// # Errors
    ///
    /// Returns [`ToolDescriptorValidationError::TimeoutOverflow`] when the timeout cannot fit the
    /// persisted millisecond representation.
    pub fn canonical_material(&self) -> Result<serde_json::Value, ToolDescriptorValidationError> {
        let timeout_ms = u64::try_from(self.timeout.as_millis())
            .map_err(|_| ToolDescriptorValidationError::TimeoutOverflow)?;
        Ok(serde_json::json!({
            "contractVersion": TOOL_DESCRIPTOR_CONTRACT_VERSION,
            "toolId": self.tool_id,
            "version": self.version,
            "inputSchema": self.input_schema,
            "outputSchema": self.output_schema,
            "inputSchemaDigest": self.input_schema_digest,
            "outputSchemaDigest": self.output_schema_digest,
            "effectClass": self.effect_class,
            "riskClass": self.risk_class,
            "requiredCapabilities": self.required_capabilities,
            "timeoutMs": timeout_ms,
            "maximumOutputBytes": self.maximum_output_bytes,
            "concurrency": self.concurrency,
            "conflictKeyTemplates": self.conflict_key_templates,
            "idempotency": self.idempotency,
            "recovery": self.recovery,
            "executor": self.executor,
            "executableIdentityDigest": self.executable_identity_digest,
        }))
    }

    /// Recomputes the versioned canonical descriptor digest.
    ///
    /// # Errors
    ///
    /// Returns [`ToolDescriptorValidationError::TimeoutOverflow`] for an unrepresentable timeout.
    pub fn computed_descriptor_digest(&self) -> Result<String, ToolDescriptorValidationError> {
        Ok(sha256_digest(
            self.canonical_material()?.to_string().as_bytes(),
        ))
    }

    /// Validates canonical evidence, bounded fields, and every legal semantic combination.
    ///
    /// # Errors
    ///
    /// Returns [`ToolDescriptorValidationError`] when any field or combination fails closed.
    pub fn validate(&self) -> Result<(), ToolDescriptorValidationError> {
        validate_bounded_field("tool_id", &self.tool_id, 256)?;
        validate_bounded_field("version", &self.version, 128)?;
        validate_canonical_set("required_capabilities", &self.required_capabilities, true)?;
        validate_canonical_set(
            "conflict_key_templates",
            &self.conflict_key_templates,
            false,
        )?;
        if self.timeout.is_zero() {
            return Err(ToolDescriptorValidationError::ZeroTimeout);
        }
        let _timeout_ms = u64::try_from(self.timeout.as_millis())
            .map_err(|_| ToolDescriptorValidationError::TimeoutOverflow)?;
        if self.maximum_output_bytes == 0 {
            return Err(ToolDescriptorValidationError::ZeroOutputLimit);
        }
        if let ExecutorKind::Extension(extension_id) = &self.executor {
            ExecutorKind::extension(extension_id.clone())?;
        }
        if !crate::is_sha256_digest(&self.executable_identity_digest) {
            return Err(ToolDescriptorValidationError::InvalidExecutableIdentityDigest);
        }
        let input_digest = sha256_digest(self.input_schema.to_string().as_bytes());
        if input_digest != self.input_schema_digest {
            return Err(ToolDescriptorValidationError::InputSchemaDigestMismatch);
        }
        let output_digest = sha256_digest(self.output_schema.to_string().as_bytes());
        if output_digest != self.output_schema_digest {
            return Err(ToolDescriptorValidationError::OutputSchemaDigestMismatch);
        }
        if !legal_effect_contract(self.effect_class, self.idempotency, self.recovery) {
            return Err(ToolDescriptorValidationError::IllegalEffectContract);
        }
        if self.effect_class.is_mutating()
            && self.concurrency == ToolConcurrency::Parallel
            && self.conflict_key_templates.is_empty()
        {
            return Err(ToolDescriptorValidationError::MissingParallelConflictKey);
        }
        if self.computed_descriptor_digest()? != self.descriptor_digest {
            return Err(ToolDescriptorValidationError::DescriptorDigestMismatch);
        }
        Ok(())
    }
}

impl TryFrom<&ReadToolDescriptor> for ToolDescriptor {
    type Error = ToolDescriptorValidationError;

    fn try_from(legacy: &ReadToolDescriptor) -> Result<Self, Self::Error> {
        legacy.validate_evidence()?;
        if legacy.effect_class != "read_only" || legacy.recovery != "retry" {
            return Err(ToolDescriptorValidationError::InvalidLegacyContract);
        }
        let risk_class = match legacy.risk_class.as_str() {
            "low" => RiskClass::Low,
            "medium" => RiskClass::Medium,
            "high" => RiskClass::High,
            _ => return Err(ToolDescriptorValidationError::InvalidLegacyContract),
        };
        let output_schema_digest = sha256_digest(legacy.output_schema.to_string().as_bytes());
        let mut descriptor = Self {
            tool_id: legacy.tool_id.clone(),
            version: legacy.version.clone(),
            input_schema: legacy.input_schema.clone(),
            output_schema: legacy.output_schema.clone(),
            input_schema_digest: legacy.schema_digest.clone(),
            output_schema_digest,
            descriptor_digest: String::new(),
            effect_class: EffectClass::ReadOnly,
            risk_class,
            required_capabilities: vec![legacy.required_capability.clone()],
            timeout: legacy.timeout,
            maximum_output_bytes: legacy.maximum_output_bytes,
            concurrency: ToolConcurrency::Serial,
            conflict_key_templates: vec![legacy.conflict_key_template.clone()],
            idempotency: IdempotencyClass::Pure,
            recovery: RecoveryStrategy::Retry,
            executor: ExecutorKind::Builtin,
            executable_identity_digest: legacy.descriptor_digest.clone(),
        };
        descriptor.descriptor_digest = descriptor.computed_descriptor_digest()?;
        descriptor.validate()?;
        Ok(descriptor)
    }
}

impl TryFrom<ReadToolDescriptor> for ToolDescriptor {
    type Error = ToolDescriptorValidationError;

    fn try_from(legacy: ReadToolDescriptor) -> Result<Self, Self::Error> {
        Self::try_from(&legacy)
    }
}

const fn legal_effect_contract(
    effect_class: EffectClass,
    idempotency: IdempotencyClass,
    recovery: RecoveryStrategy,
) -> bool {
    matches!(
        (effect_class, idempotency, recovery),
        (
            EffectClass::ReadOnly,
            IdempotencyClass::Pure,
            RecoveryStrategy::Retry
        ) | (
            EffectClass::Idempotent | EffectClass::Reversible,
            IdempotencyClass::Idempotent,
            RecoveryStrategy::Retry | RecoveryStrategy::NeverRetry,
        ) | (
            EffectClass::Idempotent | EffectClass::Reversible,
            IdempotencyClass::Keyed,
            RecoveryStrategy::Retry | RecoveryStrategy::Reconcile | RecoveryStrategy::NeverRetry,
        ) | (
            EffectClass::NonIdempotent | EffectClass::Reversible,
            IdempotencyClass::NonIdempotent,
            RecoveryStrategy::Reconcile | RecoveryStrategy::NeverRetry,
        ) | (
            EffectClass::Reversible,
            IdempotencyClass::Idempotent
                | IdempotencyClass::Keyed
                | IdempotencyClass::NonIdempotent,
            RecoveryStrategy::Compensate,
        )
    )
}

fn validate_bounded_field(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), ToolDescriptorValidationError> {
    if value.is_empty() || value.len() > maximum {
        Err(ToolDescriptorValidationError::InvalidBoundedField { field })
    } else {
        Ok(())
    }
}

fn validate_canonical_set(
    field: &'static str,
    values: &[String],
    required: bool,
) -> Result<(), ToolDescriptorValidationError> {
    if required && values.is_empty()
        || values
            .iter()
            .any(|value| value.is_empty() || value.len() > 512)
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        Err(ToolDescriptorValidationError::NonCanonicalSet { field })
    } else {
        Ok(())
    }
}

/// Invalid generic tool contract or canonical descriptor evidence.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ToolDescriptorValidationError {
    /// A legacy descriptor failed its Phase 2 evidence check.
    #[error(transparent)]
    LegacyEvidence(#[from] ToolDescriptorEvidenceError),
    /// A legacy string classification cannot be converted without guessing.
    #[error("Phase 2 read-tool descriptor is not a supported read-only contract")]
    InvalidLegacyContract,
    /// A required bounded string is empty or oversized.
    #[error("tool descriptor field {field} is empty or oversized")]
    InvalidBoundedField {
        /// Invalid field name.
        field: &'static str,
    },
    /// A set-like field is empty when required, unsorted, duplicated, or contains bad values.
    #[error("tool descriptor set {field} is not canonical")]
    NonCanonicalSet {
        /// Invalid field name.
        field: &'static str,
    },
    /// The timeout is zero.
    #[error("tool descriptor timeout must be positive")]
    ZeroTimeout,
    /// The timeout does not fit the persisted millisecond representation.
    #[error("tool descriptor timeout exceeds the canonical millisecond representation")]
    TimeoutOverflow,
    /// The output byte limit is zero.
    #[error("tool descriptor output limit must be positive")]
    ZeroOutputLimit,
    /// An extension executor contains an invalid extension identity.
    #[error(transparent)]
    InvalidExecutor(#[from] mealy_domain::ExecutorKindError),
    /// The executable identity is not a canonical SHA-256 digest.
    #[error("tool executable identity is not a canonical SHA-256 digest")]
    InvalidExecutableIdentityDigest,
    /// The input schema digest does not match the normalized input schema.
    #[error("tool input-schema digest mismatch")]
    InputSchemaDigestMismatch,
    /// The output schema digest does not match the normalized output schema.
    #[error("tool output-schema digest mismatch")]
    OutputSchemaDigestMismatch,
    /// Effect, idempotency, and recovery declarations are not jointly safe.
    #[error("tool effect, idempotency, and recovery declarations are incompatible")]
    IllegalEffectContract,
    /// Parallel mutation has no conflict-key declaration.
    #[error("parallel mutating tool requires at least one conflict-key template")]
    MissingParallelConflictKey,
    /// The descriptor digest does not bind the complete generic contract.
    #[error("tool descriptor digest mismatch")]
    DescriptorDigestMismatch,
}

/// Complete declaration for the Phase 2 fixture-only read tool.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadToolDescriptor {
    /// Stable tool identity.
    pub tool_id: String,
    /// Contract version.
    pub version: String,
    /// Normalized input JSON Schema.
    pub input_schema: serde_json::Value,
    /// Normalized output JSON Schema.
    pub output_schema: serde_json::Value,
    /// Digest of [`Self::canonical_material`], which includes every contract field except this
    /// self-referential digest.
    pub descriptor_digest: String,
    /// Digest of the normalized input schema.
    pub schema_digest: String,
    /// Must remain `read_only` for this port.
    pub effect_class: String,
    /// Declared risk classification.
    pub risk_class: String,
    /// Required logical capability.
    pub required_capability: String,
    /// Hard execution timeout.
    #[serde(with = "duration_milliseconds")]
    pub timeout: Duration,
    /// Hard output bound before an artifact commit.
    pub maximum_output_bytes: u64,
    /// Deterministic conflict-key template.
    pub conflict_key_template: String,
    /// Recovery classification, `retry` for the pure fixture tool.
    pub recovery: String,
}

impl ReadToolDescriptor {
    /// Returns the versioned canonical material bound by [`Self::descriptor_digest`].
    ///
    /// The digest itself is deliberately excluded to avoid a self-referential encoding.
    ///
    /// # Errors
    ///
    /// Returns [`ToolDescriptorEvidenceError::TimeoutOverflow`] when the duration cannot be
    /// represented by the persisted millisecond contract.
    pub fn canonical_material(&self) -> Result<serde_json::Value, ToolDescriptorEvidenceError> {
        let timeout_ms = u64::try_from(self.timeout.as_millis())
            .map_err(|_| ToolDescriptorEvidenceError::TimeoutOverflow)?;
        Ok(serde_json::json!({
            "toolId": self.tool_id,
            "version": self.version,
            "inputSchema": self.input_schema,
            "outputSchema": self.output_schema,
            "schemaDigest": self.schema_digest,
            "effectClass": self.effect_class,
            "riskClass": self.risk_class,
            "requiredCapability": self.required_capability,
            "timeoutMs": timeout_ms,
            "maximumOutputBytes": self.maximum_output_bytes,
            "conflictKeyTemplate": self.conflict_key_template,
            "recovery": self.recovery,
        }))
    }

    /// Serializes the canonical digest material used for durable descriptor evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ToolDescriptorEvidenceError`] when the timeout is not representable.
    pub fn canonical_material_json(&self) -> Result<String, ToolDescriptorEvidenceError> {
        Ok(self.canonical_material()?.to_string())
    }

    /// Recomputes the canonical descriptor digest.
    ///
    /// # Errors
    ///
    /// Returns [`ToolDescriptorEvidenceError`] when the timeout is not representable.
    pub fn computed_descriptor_digest(&self) -> Result<String, ToolDescriptorEvidenceError> {
        Ok(sha256_digest(self.canonical_material_json()?.as_bytes()))
    }

    /// Verifies the input-schema and complete canonical descriptor digests.
    ///
    /// # Errors
    ///
    /// Returns [`ToolDescriptorEvidenceError`] for unrepresentable or mismatched evidence.
    pub fn validate_evidence(&self) -> Result<(), ToolDescriptorEvidenceError> {
        let schema_digest = sha256_digest(self.input_schema.to_string().as_bytes());
        if schema_digest != self.schema_digest {
            return Err(ToolDescriptorEvidenceError::SchemaDigestMismatch);
        }
        if self.computed_descriptor_digest()? != self.descriptor_digest {
            return Err(ToolDescriptorEvidenceError::DescriptorDigestMismatch);
        }
        Ok(())
    }
}

/// Invalid canonical evidence attached to a tool descriptor.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ToolDescriptorEvidenceError {
    /// The hard timeout exceeded the persisted millisecond representation.
    #[error("read-tool timeout exceeds the canonical millisecond representation")]
    TimeoutOverflow,
    /// The recorded input-schema digest does not match its canonical JSON.
    #[error("read-tool input-schema digest mismatch")]
    SchemaDigestMismatch,
    /// The recorded descriptor digest does not match its canonical material.
    #[error("read-tool descriptor digest mismatch")]
    DescriptorDigestMismatch,
}

/// Bounded normalized read result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadToolOutput {
    /// Media type of the returned bytes.
    pub media_type: String,
    /// Exact output bytes.
    pub bytes: Vec<u8>,
    /// Safe logical source locator such as `fixture://phase2/report`.
    pub source_locator: String,
}

/// Classified read-tool failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReadToolError {
    /// Arguments do not conform to the declared schema.
    #[error("invalid read-tool arguments: {0}")]
    InvalidArguments(String),
    /// The granted logical resource does not exist.
    #[error("logical resource not found")]
    NotFound,
    /// Cancellation was observed at a safe boundary.
    #[error("read tool cancelled")]
    Cancelled,
    /// Output exceeded the declared hard bound.
    #[error("read-tool output {actual} bytes exceeds maximum {maximum}")]
    OutputTooLarge {
        /// Actual byte count.
        actual: u64,
        /// Configured hard maximum.
        maximum: u64,
    },
    /// The trusted adapter failed without exposing sensitive internals.
    #[error("read tool unavailable: {0}")]
    Unavailable(String),
}

/// Narrow read-only tool boundary with no ambient filesystem, environment, shell, or network.
pub trait ReadOnlyTool: Send + Sync + 'static {
    /// Returns the immutable descriptor bound into model requests.
    fn descriptor(&self) -> ReadToolDescriptor;

    /// Validates the exact argument shape before durable tool preparation.
    ///
    /// # Errors
    ///
    /// Returns [`ReadToolError`] without performing I/O or changing external state.
    fn validate_arguments(&self, arguments: &serde_json::Value) -> Result<(), ReadToolError>;

    /// Executes validated logical-resource arguments.
    ///
    /// # Errors
    ///
    /// Returns [`ReadToolError`] for validation, cancellation, bounds, or adapter failures.
    fn execute(
        &self,
        arguments: &serde_json::Value,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ReadToolOutput, ReadToolError>;
}

/// Validates the exact Phase 2 logical fixture-read argument shape without executing the tool.
///
/// # Errors
///
/// Returns [`ReadToolError::InvalidArguments`] for extra fields, non-string values, traversal
/// segments, path syntax, or any non-`fixture://` locator.
pub fn validate_fixture_read_arguments(
    arguments: &serde_json::Value,
) -> Result<&str, ReadToolError> {
    let object = arguments.as_object().ok_or_else(|| {
        ReadToolError::InvalidArguments("expected one object field named resourceId".to_owned())
    })?;
    if object.len() != 1 {
        return Err(ReadToolError::InvalidArguments(
            "expected exactly one field named resourceId".to_owned(),
        ));
    }
    let resource_id = object
        .get("resourceId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ReadToolError::InvalidArguments("resourceId must be a string".to_owned()))?;
    let valid = resource_id.len() <= 256
        && resource_id
            .strip_prefix("fixture://")
            .is_some_and(|logical_name| {
                !logical_name.is_empty()
                    && logical_name.split('/').all(|segment| {
                        !segment.is_empty()
                            && segment != "."
                            && segment != ".."
                            && segment.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                            })
                    })
            });
    if !valid {
        return Err(ReadToolError::InvalidArguments(
            "resourceId must be a canonical fixture locator".to_owned(),
        ));
    }
    Ok(resource_id)
}

mod duration_milliseconds {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let millis = u64::try_from(value.as_millis()).map_err(serde::ser::Error::custom)?;
        serializer.serialize_u64(millis)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        u64::deserialize(deserializer).map(Duration::from_millis)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ReadToolDescriptor, ToolConcurrency, ToolDescriptor, ToolDescriptorEvidenceError,
        ToolDescriptorValidationError,
    };
    use crate::sha256_digest;
    use mealy_domain::{EffectClass, ExecutorKind, IdempotencyClass, RecoveryStrategy, RiskClass};
    use std::time::Duration;

    fn descriptor() -> ReadToolDescriptor {
        let input_schema = serde_json::json!({
            "type": "object",
            "required": ["resourceId"],
        });
        let mut descriptor = ReadToolDescriptor {
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
        descriptor.descriptor_digest = descriptor
            .computed_descriptor_digest()
            .expect("descriptor digest");
        descriptor
    }

    #[test]
    fn canonical_descriptor_material_excludes_its_own_digest_and_detects_drift() {
        let mut descriptor = descriptor();
        let material = descriptor.canonical_material().expect("canonical material");
        assert_eq!(material.get("descriptorDigest"), None);
        assert_eq!(material["timeoutMs"].as_u64(), Some(1_000));
        descriptor.validate_evidence().expect("valid evidence");

        descriptor.maximum_output_bytes += 1;
        assert_eq!(
            descriptor.validate_evidence(),
            Err(ToolDescriptorEvidenceError::DescriptorDigestMismatch)
        );
    }

    #[test]
    fn phase_two_read_descriptor_converts_without_weakening_its_contract() {
        let legacy = descriptor();
        let generic = ToolDescriptor::try_from(&legacy).expect("convert read descriptor");
        generic.validate().expect("valid generic descriptor");
        assert_eq!(generic.tool_id, legacy.tool_id);
        assert_eq!(generic.effect_class, EffectClass::ReadOnly);
        assert_eq!(generic.idempotency, IdempotencyClass::Pure);
        assert_eq!(generic.recovery, RecoveryStrategy::Retry);
        assert_eq!(generic.executor, ExecutorKind::Builtin);
        assert_eq!(generic.required_capabilities, [legacy.required_capability]);
        assert_eq!(generic.executable_identity_digest, legacy.descriptor_digest);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn effect_idempotency_recovery_matrix_is_exhaustive_and_fail_closed() {
        let effects = [
            EffectClass::ReadOnly,
            EffectClass::Reversible,
            EffectClass::Idempotent,
            EffectClass::NonIdempotent,
        ];
        let idempotencies = [
            IdempotencyClass::Pure,
            IdempotencyClass::Idempotent,
            IdempotencyClass::Keyed,
            IdempotencyClass::NonIdempotent,
        ];
        let recoveries = [
            RecoveryStrategy::Retry,
            RecoveryStrategy::Reconcile,
            RecoveryStrategy::Compensate,
            RecoveryStrategy::NeverRetry,
        ];
        let allowed = [
            (
                EffectClass::ReadOnly,
                IdempotencyClass::Pure,
                RecoveryStrategy::Retry,
            ),
            (
                EffectClass::Idempotent,
                IdempotencyClass::Idempotent,
                RecoveryStrategy::Retry,
            ),
            (
                EffectClass::Idempotent,
                IdempotencyClass::Idempotent,
                RecoveryStrategy::NeverRetry,
            ),
            (
                EffectClass::Idempotent,
                IdempotencyClass::Keyed,
                RecoveryStrategy::Retry,
            ),
            (
                EffectClass::Idempotent,
                IdempotencyClass::Keyed,
                RecoveryStrategy::Reconcile,
            ),
            (
                EffectClass::Idempotent,
                IdempotencyClass::Keyed,
                RecoveryStrategy::NeverRetry,
            ),
            (
                EffectClass::NonIdempotent,
                IdempotencyClass::NonIdempotent,
                RecoveryStrategy::Reconcile,
            ),
            (
                EffectClass::NonIdempotent,
                IdempotencyClass::NonIdempotent,
                RecoveryStrategy::NeverRetry,
            ),
            (
                EffectClass::Reversible,
                IdempotencyClass::Idempotent,
                RecoveryStrategy::Retry,
            ),
            (
                EffectClass::Reversible,
                IdempotencyClass::Idempotent,
                RecoveryStrategy::Compensate,
            ),
            (
                EffectClass::Reversible,
                IdempotencyClass::Idempotent,
                RecoveryStrategy::NeverRetry,
            ),
            (
                EffectClass::Reversible,
                IdempotencyClass::Keyed,
                RecoveryStrategy::Retry,
            ),
            (
                EffectClass::Reversible,
                IdempotencyClass::Keyed,
                RecoveryStrategy::Reconcile,
            ),
            (
                EffectClass::Reversible,
                IdempotencyClass::Keyed,
                RecoveryStrategy::Compensate,
            ),
            (
                EffectClass::Reversible,
                IdempotencyClass::Keyed,
                RecoveryStrategy::NeverRetry,
            ),
            (
                EffectClass::Reversible,
                IdempotencyClass::NonIdempotent,
                RecoveryStrategy::Reconcile,
            ),
            (
                EffectClass::Reversible,
                IdempotencyClass::NonIdempotent,
                RecoveryStrategy::Compensate,
            ),
            (
                EffectClass::Reversible,
                IdempotencyClass::NonIdempotent,
                RecoveryStrategy::NeverRetry,
            ),
        ];
        let base = ToolDescriptor::try_from(descriptor()).expect("convert base descriptor");

        for effect in effects {
            for idempotency in idempotencies {
                for recovery in recoveries {
                    let mut candidate = base.clone();
                    candidate.effect_class = effect;
                    candidate.idempotency = idempotency;
                    candidate.recovery = recovery;
                    candidate.descriptor_digest = candidate
                        .computed_descriptor_digest()
                        .expect("compute candidate digest");
                    let valid = candidate.validate().is_ok();
                    assert_eq!(
                        valid,
                        allowed.contains(&(effect, idempotency, recovery)),
                        "unexpected legality for {effect:?}/{idempotency:?}/{recovery:?}"
                    );
                }
            }
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn canonical_digest_binds_every_generic_descriptor_field() {
        let original = ToolDescriptor::try_from(descriptor()).expect("convert descriptor");
        let original_digest = original
            .computed_descriptor_digest()
            .expect("compute original digest");
        assert!(
            original
                .canonical_material()
                .expect("canonical material")
                .get("descriptorDigest")
                .is_none()
        );

        let mut mutations = Vec::new();
        let mut changed = original.clone();
        changed.tool_id.push_str(".changed");
        mutations.push(("tool ID", changed));
        let mut changed = original.clone();
        changed.version.push_str(".1");
        mutations.push(("version", changed));
        let mut changed = original.clone();
        changed.input_schema = serde_json::json!({"type": "string"});
        mutations.push(("input schema", changed));
        let mut changed = original.clone();
        changed.output_schema = serde_json::json!({"type": "string"});
        mutations.push(("output schema", changed));
        let mut changed = original.clone();
        changed.input_schema_digest = sha256_digest(b"changed input schema digest");
        mutations.push(("input schema digest", changed));
        let mut changed = original.clone();
        changed.output_schema_digest = sha256_digest(b"changed output schema digest");
        mutations.push(("output schema digest", changed));
        let mut changed = original.clone();
        changed.effect_class = EffectClass::Idempotent;
        mutations.push(("effect class", changed));
        let mut changed = original.clone();
        changed.risk_class = RiskClass::Medium;
        mutations.push(("risk class", changed));
        let mut changed = original.clone();
        changed
            .required_capabilities
            .push("observe:other".to_owned());
        mutations.push(("capabilities", changed));
        let mut changed = original.clone();
        changed.timeout += Duration::from_millis(1);
        mutations.push(("timeout", changed));
        let mut changed = original.clone();
        changed.maximum_output_bytes += 1;
        mutations.push(("output limit", changed));
        let mut changed = original.clone();
        changed.concurrency = ToolConcurrency::Parallel;
        mutations.push(("concurrency", changed));
        let mut changed = original.clone();
        changed
            .conflict_key_templates
            .push("fixture-read:{other}".to_owned());
        mutations.push(("conflict keys", changed));
        let mut changed = original.clone();
        changed.idempotency = IdempotencyClass::Idempotent;
        mutations.push(("idempotency", changed));
        let mut changed = original.clone();
        changed.recovery = RecoveryStrategy::NeverRetry;
        mutations.push(("recovery", changed));
        let mut changed = original.clone();
        changed.executor = ExecutorKind::Sandbox;
        mutations.push(("executor", changed));
        let mut changed = original;
        changed.executable_identity_digest = sha256_digest(b"changed executable");
        mutations.push(("executable identity", changed));

        for (field, mutation) in mutations {
            assert_ne!(
                mutation
                    .computed_descriptor_digest()
                    .expect("compute mutated digest"),
                original_digest,
                "{field} was not bound"
            );
        }
    }

    #[test]
    fn parallel_mutation_requires_a_conflict_key() {
        let mut descriptor =
            ToolDescriptor::try_from(descriptor()).expect("convert read descriptor");
        descriptor.effect_class = EffectClass::Idempotent;
        descriptor.idempotency = IdempotencyClass::Idempotent;
        descriptor.concurrency = ToolConcurrency::Parallel;
        descriptor.conflict_key_templates.clear();
        descriptor.descriptor_digest = descriptor
            .computed_descriptor_digest()
            .expect("compute descriptor digest");
        assert_eq!(
            descriptor.validate(),
            Err(ToolDescriptorValidationError::MissingParallelConflictKey)
        );
    }
}
