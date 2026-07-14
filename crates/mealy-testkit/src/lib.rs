//! Deterministic helpers for Mealy tests.

use mealy_application::{
    CancellationProbe, Clock, IdGenerator, ModelProvider, ProviderCapabilities, ProviderError,
    ProviderErrorClass, ProviderFailureDisposition, ProviderOutput, ProviderPricing,
    ProviderRequest, ProviderResponse, ReadOnlyTool, ReadToolDescriptor, ReadToolError,
    ReadToolOutput, sha256_digest,
};
use mealy_domain::{
    ApprovalId, ArtifactId, AttemptId, ChannelBindingId, CompactionId, ContextEpochId,
    ContextItemId, ContextManifestId, CorrelationId, DelegationId, EffectId, EventId,
    ExtensionGrantId, ExtensionId, ExtensionInvocationId, InboxEntryId, LeaseId, MemoryId,
    MemoryRevisionId, MessageId, OutboxId, RunId, SessionId, TaskId, ToolCallId, TurnId,
    ValidationId, WorkerId,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{
        Mutex,
        atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use uuid::Uuid;

const UUID_V7_MAX_EPOCH_MS: u64 = (1_u64 << 48) - 1;
const UUID_V7_COUNTER_LOW_MASK: u64 = (1_u64 << 62) - 1;
const MAXIMUM_FIXTURE_RESOURCES: usize = 256;
const MAXIMUM_FIXTURE_RESOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_FIXTURE_ID_BYTES: usize = 256;
const MAXIMUM_FIXTURE_MEDIA_TYPE_BYTES: usize = 128;

#[derive(Debug)]
struct ScriptedProviderState {
    outputs: VecDeque<Result<ProviderOutput, ProviderError>>,
    requests: Vec<ProviderRequest>,
}

/// Deterministic, countable provider fake that returns a fixed in-memory output sequence.
///
/// The fake performs no filesystem, environment, network, credential, or clock access. It records
/// normalized requests only in memory so tests can verify exactly what crossed the provider port.
#[derive(Debug)]
pub struct ScriptedFakeProvider {
    capabilities: ProviderCapabilities,
    state: Mutex<ScriptedProviderState>,
    invocation_count: AtomicUsize,
}

impl ScriptedFakeProvider {
    /// Creates a local tool-capable fake with the supplied terminal results in FIFO order.
    #[must_use]
    pub fn new(outputs: impl IntoIterator<Item = Result<ProviderOutput, ProviderError>>) -> Self {
        Self::with_capabilities(default_fake_capabilities(), outputs)
    }

    /// Creates a fake with an explicit immutable capability snapshot.
    ///
    /// This customization is intended for provider contract tests; it does not load executable or
    /// data-driven scripts from outside the test process.
    #[must_use]
    pub fn with_capabilities(
        capabilities: ProviderCapabilities,
        outputs: impl IntoIterator<Item = Result<ProviderOutput, ProviderError>>,
    ) -> Self {
        Self {
            capabilities,
            state: Mutex::new(ScriptedProviderState {
                outputs: outputs.into_iter().collect(),
                requests: Vec::new(),
            }),
            invocation_count: AtomicUsize::new(0),
        }
    }

    /// Returns how many times the provider completion port was invoked, including rejected calls.
    #[must_use]
    pub fn invocation_count(&self) -> usize {
        self.invocation_count.load(Ordering::SeqCst)
    }

    /// Returns how many scripted terminal results have not yet been consumed.
    #[must_use]
    pub fn remaining_outputs(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .outputs
            .len()
    }

    /// Returns a snapshot of normalized requests in invocation order.
    #[must_use]
    pub fn recorded_requests(&self) -> Vec<ProviderRequest> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .requests
            .clone()
    }
}

impl ModelProvider for ScriptedFakeProvider {
    fn capabilities(&self) -> ProviderCapabilities {
        self.capabilities.clone()
    }

    fn complete(
        &self,
        request: &ProviderRequest,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ProviderOutput, ProviderError> {
        self.invocation_count.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().map_err(|_| {
            provider_error(
                ProviderErrorClass::Unavailable,
                "scripted fake provider state is unavailable",
                true,
            )
        })?;
        state.requests.push(request.clone());
        validate_request(&self.capabilities, request)?;
        if cancellation.is_cancelled() {
            return Err(provider_error(
                ProviderErrorClass::Cancelled,
                "scripted fake provider observed cancellation",
                false,
            ));
        }
        let output = state.outputs.pop_front().ok_or_else(|| {
            provider_error(
                ProviderErrorClass::InvalidRequest,
                "scripted fake provider received an unexpected extra call",
                false,
            )
        })??;
        drop(state);
        validate_output(request, &output)?;
        Ok(output)
    }
}

fn default_fake_capabilities() -> ProviderCapabilities {
    ProviderCapabilities {
        contract_version: "mealy.provider.v1".to_owned(),
        provider_id: "fake.scripted".to_owned(),
        model_id: "fake-scripted-v1".to_owned(),
        input_modalities: BTreeSet::from(["text".to_owned()]),
        context_tokens: 16_384,
        maximum_output_tokens: 4_096,
        tool_calling: true,
        structured_output: true,
        reasoning_controls: BTreeSet::from(["none".to_owned()]),
        streaming: false,
        residency: "local-test".to_owned(),
        local: true,
        pricing: ProviderPricing::default(),
        maximum_concurrent_requests: 1,
        requests_per_minute: 600,
        retry_after_hints: true,
    }
}

fn validate_request(
    capabilities: &ProviderCapabilities,
    request: &ProviderRequest,
) -> Result<(), ProviderError> {
    if request.provider_id != capabilities.provider_id || request.model_id != capabilities.model_id
    {
        return Err(provider_error(
            ProviderErrorClass::InvalidRequest,
            "normalized request selected a different provider or model",
            false,
        ));
    }
    if request.messages.is_empty() {
        return Err(provider_error(
            ProviderErrorClass::InvalidRequest,
            "normalized request contains no messages",
            false,
        ));
    }
    if request.maximum_output_tokens == 0
        || request.maximum_output_tokens > capabilities.maximum_output_tokens
    {
        return Err(provider_error(
            ProviderErrorClass::InvalidRequest,
            "normalized output-token bound is outside provider capabilities",
            false,
        ));
    }
    if request.deadline_at_ms <= 0 {
        return Err(provider_error(
            ProviderErrorClass::InvalidRequest,
            "normalized provider deadline is invalid",
            false,
        ));
    }
    if !request.tools.is_empty() && !capabilities.tool_calling {
        return Err(provider_error(
            ProviderErrorClass::InvalidRequest,
            "normalized request supplied tools to a provider without tool calling",
            false,
        ));
    }
    Ok(())
}

fn validate_output(
    request: &ProviderRequest,
    output: &ProviderOutput,
) -> Result<(), ProviderError> {
    let expected_total = output
        .usage
        .input_tokens
        .checked_add(output.usage.output_tokens)
        .ok_or_else(|| invalid_response("scripted usage total overflowed"))?;
    if output.usage.total_tokens != expected_total {
        return Err(invalid_response("scripted usage total is inconsistent"));
    }
    if output.usage.output_tokens > request.maximum_output_tokens {
        return Err(invalid_response(
            "scripted output exceeds the normalized token bound",
        ));
    }
    if output.finish_reason.is_empty() {
        return Err(invalid_response("scripted finish reason is empty"));
    }
    match &output.response {
        ProviderResponse::Final { text } if text.is_empty() => {
            Err(invalid_response("scripted final response is empty"))
        }
        ProviderResponse::ToolCall { tool_id, .. }
            if !request.tools.iter().any(|tool| tool.tool_id == *tool_id) =>
        {
            Err(invalid_response(
                "scripted response requested an undeclared tool",
            ))
        }
        ProviderResponse::Final { .. } | ProviderResponse::ToolCall { .. } => Ok(()),
    }
}

fn invalid_response(message: &'static str) -> ProviderError {
    provider_error(ProviderErrorClass::InvalidResponse, message, false)
}

fn provider_error(
    class: ProviderErrorClass,
    message: &'static str,
    retryable: bool,
) -> ProviderError {
    ProviderError {
        class,
        message: message.to_owned(),
        retryable,
        disposition: ProviderFailureDisposition::Known,
    }
}

/// One immutable logical resource available to [`FixtureReadTool`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureResource {
    media_type: String,
    bytes: Vec<u8>,
}

impl FixtureResource {
    /// Creates an in-memory fixture resource. The tool constructor validates all hard limits.
    #[must_use]
    pub fn new(media_type: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            media_type: media_type.into(),
            bytes: bytes.into(),
        }
    }

    /// Returns the fixture media type.
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Returns the immutable fixture bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Invalid bounded configuration for [`FixtureReadTool`].
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FixtureToolConfigurationError {
    /// An output limit must be positive.
    #[error("fixture read-tool output limit must be positive")]
    ZeroOutputLimit,
    /// The in-memory fixture count exceeded its hard test boundary.
    #[error("fixture read tool supports at most {maximum} resources")]
    TooManyResources {
        /// Hard resource-count boundary.
        maximum: usize,
    },
    /// A logical ID was not a canonical `fixture://` locator.
    #[error("fixture resource ID is invalid")]
    InvalidResourceId,
    /// Two resources used the same canonical logical ID.
    #[error("fixture resource ID is duplicated")]
    DuplicateResourceId,
    /// A resource media type was empty, malformed, or too large.
    #[error("fixture resource media type is invalid")]
    InvalidMediaType,
    /// One configured resource exceeded the fake's absolute memory boundary.
    #[error("fixture resource {actual} bytes exceeds hard maximum {maximum}")]
    ResourceTooLarge {
        /// Actual configured bytes.
        actual: usize,
        /// Absolute per-resource boundary.
        maximum: usize,
    },
    /// The fixed descriptor could not be encoded for hashing.
    #[error("fixture read-tool descriptor could not be encoded")]
    DescriptorEncoding,
}

/// Countable fixture-only read tool backed exclusively by immutable in-memory logical resources.
///
/// Resource IDs are exact `fixture://` keys. They are never interpreted as paths or URLs, and the
/// adapter performs no filesystem, environment, process, credential, clock, or network access.
#[derive(Debug)]
pub struct FixtureReadTool {
    descriptor: ReadToolDescriptor,
    resources: BTreeMap<String, FixtureResource>,
    invocation_count: AtomicUsize,
    requested_resource_ids: Mutex<Vec<String>>,
}

impl FixtureReadTool {
    /// Creates a bounded fixture tool from immutable logical resources.
    ///
    /// # Errors
    ///
    /// Returns [`FixtureToolConfigurationError`] for non-canonical IDs, duplicates, malformed media
    /// types, zero output limits, or configuration exceeding hard memory/count boundaries.
    pub fn new(
        resources: impl IntoIterator<Item = (String, FixtureResource)>,
        maximum_output_bytes: u64,
    ) -> Result<Self, FixtureToolConfigurationError> {
        if maximum_output_bytes == 0 {
            return Err(FixtureToolConfigurationError::ZeroOutputLimit);
        }
        let mut bounded_resources = BTreeMap::new();
        for (index, (resource_id, resource)) in resources.into_iter().enumerate() {
            if index >= MAXIMUM_FIXTURE_RESOURCES {
                return Err(FixtureToolConfigurationError::TooManyResources {
                    maximum: MAXIMUM_FIXTURE_RESOURCES,
                });
            }
            if !valid_fixture_resource_id(&resource_id) {
                return Err(FixtureToolConfigurationError::InvalidResourceId);
            }
            if !valid_media_type(&resource.media_type) {
                return Err(FixtureToolConfigurationError::InvalidMediaType);
            }
            if resource.bytes.len() > MAXIMUM_FIXTURE_RESOURCE_BYTES {
                return Err(FixtureToolConfigurationError::ResourceTooLarge {
                    actual: resource.bytes.len(),
                    maximum: MAXIMUM_FIXTURE_RESOURCE_BYTES,
                });
            }
            if bounded_resources.insert(resource_id, resource).is_some() {
                return Err(FixtureToolConfigurationError::DuplicateResourceId);
            }
        }
        Ok(Self {
            descriptor: fixture_descriptor(maximum_output_bytes)?,
            resources: bounded_resources,
            invocation_count: AtomicUsize::new(0),
            requested_resource_ids: Mutex::new(Vec::new()),
        })
    }

    /// Returns how many execution requests reached the tool, including rejected requests.
    #[must_use]
    pub fn invocation_count(&self) -> usize {
        self.invocation_count.load(Ordering::SeqCst)
    }

    /// Returns valid logical resource IDs requested so far, in execution order.
    #[must_use]
    pub fn requested_resource_ids(&self) -> Vec<String> {
        self.requested_resource_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl ReadOnlyTool for FixtureReadTool {
    fn descriptor(&self) -> ReadToolDescriptor {
        self.descriptor.clone()
    }

    fn validate_arguments(&self, arguments: &serde_json::Value) -> Result<(), ReadToolError> {
        parse_resource_id(arguments).map(|_| ())
    }

    fn execute(
        &self,
        arguments: &serde_json::Value,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ReadToolOutput, ReadToolError> {
        self.invocation_count.fetch_add(1, Ordering::SeqCst);
        let resource_id = parse_resource_id(arguments)?;
        self.requested_resource_ids
            .lock()
            .map_err(|_| {
                ReadToolError::Unavailable("fixture request recorder is unavailable".to_owned())
            })?
            .push(resource_id.to_owned());
        if cancellation.is_cancelled() {
            return Err(ReadToolError::Cancelled);
        }
        let resource = self
            .resources
            .get(resource_id)
            .ok_or(ReadToolError::NotFound)?;
        let actual = u64::try_from(resource.bytes.len()).map_err(|_| {
            ReadToolError::Unavailable("fixture size cannot be represented".to_owned())
        })?;
        if actual > self.descriptor.maximum_output_bytes {
            return Err(ReadToolError::OutputTooLarge {
                actual,
                maximum: self.descriptor.maximum_output_bytes,
            });
        }
        Ok(ReadToolOutput {
            media_type: resource.media_type.clone(),
            bytes: resource.bytes.clone(),
            source_locator: resource_id.to_owned(),
        })
    }
}

fn parse_resource_id(arguments: &serde_json::Value) -> Result<&str, ReadToolError> {
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
    if !valid_fixture_resource_id(resource_id) {
        return Err(ReadToolError::InvalidArguments(
            "resourceId must be a canonical fixture locator".to_owned(),
        ));
    }
    Ok(resource_id)
}

fn valid_fixture_resource_id(resource_id: &str) -> bool {
    if resource_id.len() > MAXIMUM_FIXTURE_ID_BYTES {
        return false;
    }
    resource_id
        .strip_prefix("fixture://")
        .is_some_and(|logical_name| {
            !logical_name.is_empty()
                && logical_name.split('/').all(|segment| {
                    !segment.is_empty()
                        && segment != "."
                        && segment != ".."
                        && segment.bytes().next().is_some_and(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
                        })
                        && segment.bytes().skip(1).all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                        })
                })
        })
}

fn valid_media_type(media_type: &str) -> bool {
    if media_type.is_empty() || media_type.len() > MAXIMUM_FIXTURE_MEDIA_TYPE_BYTES {
        return false;
    }
    let Some((top_level, subtype)) = media_type.split_once('/') else {
        return false;
    };
    !top_level.is_empty()
        && !subtype.is_empty()
        && !subtype.contains('/')
        && media_type
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
}

fn fixture_descriptor(
    maximum_output_bytes: u64,
) -> Result<ReadToolDescriptor, FixtureToolConfigurationError> {
    let input_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "resourceId": {
                "type": "string",
                "pattern": "^fixture://[A-Za-z0-9_-][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_-][A-Za-z0-9_.-]*)*$",
            },
        },
        "required": ["resourceId"],
        "additionalProperties": false,
    });
    let output_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "mediaType": { "type": "string" },
            "sourceLocator": { "type": "string" },
            "bytes": { "type": "string", "contentEncoding": "base64" },
        },
        "required": ["mediaType", "sourceLocator", "bytes"],
        "additionalProperties": false,
    });
    let schema_digest = digest_json(&input_schema)?;
    let mut descriptor = ReadToolDescriptor {
        tool_id: "fixture.read".to_owned(),
        version: "1".to_owned(),
        input_schema,
        output_schema,
        descriptor_digest: String::new(),
        schema_digest,
        effect_class: "read_only".to_owned(),
        risk_class: "low".to_owned(),
        required_capability: "observe:fixture".to_owned(),
        timeout: Duration::from_secs(1),
        maximum_output_bytes,
        conflict_key_template: "fixture-read:{resourceId}".to_owned(),
        recovery: "retry".to_owned(),
    };
    descriptor.descriptor_digest = descriptor
        .computed_descriptor_digest()
        .map_err(|_| FixtureToolConfigurationError::DescriptorEncoding)?;
    Ok(descriptor)
}

fn digest_json(value: &serde_json::Value) -> Result<String, FixtureToolConfigurationError> {
    serde_json::to_vec(value)
        .map(|encoded| sha256_digest(&encoded))
        .map_err(|_| FixtureToolConfigurationError::DescriptorEncoding)
}

/// Thread-safe manually advanced UTC epoch-millisecond clock.
#[derive(Debug)]
pub struct TestClock {
    now_ms: AtomicI64,
}

impl TestClock {
    /// Creates a clock at a fixed epoch-millisecond value.
    #[must_use]
    pub const fn new(now_ms: i64) -> Self {
        Self {
            now_ms: AtomicI64::new(now_ms),
        }
    }

    /// Reads the current deterministic time.
    #[must_use]
    pub fn now_ms(&self) -> i64 {
        self.now_ms.load(Ordering::SeqCst)
    }

    /// Advances the clock and returns the resulting value.
    pub fn advance_ms(&self, delta_ms: i64) -> i64 {
        self.now_ms.fetch_add(delta_ms, Ordering::SeqCst) + delta_ms
    }
}

impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        let now_ms = self.now_ms();
        let offset = Duration::from_millis(now_ms.unsigned_abs());
        if now_ms.is_negative() {
            UNIX_EPOCH
                .checked_sub(offset)
                .expect("test clock instant must be representable")
        } else {
            UNIX_EPOCH
                .checked_add(offset)
                .expect("test clock instant must be representable")
        }
    }
}

/// Thread-safe deterministic generator for UUIDv7-backed domain identifiers.
#[derive(Debug)]
pub struct TestIdGenerator {
    epoch_ms: u64,
    counter: AtomicU64,
}

impl TestIdGenerator {
    /// Creates a generator at a fixed Unix epoch in milliseconds with a zero counter.
    ///
    /// # Panics
    ///
    /// Panics when `epoch_ms` exceeds the 48-bit timestamp field available in `UUIDv7`.
    #[must_use]
    pub const fn new(epoch_ms: u64) -> Self {
        assert!(
            epoch_ms <= UUID_V7_MAX_EPOCH_MS,
            "test ID epoch exceeds the UUIDv7 timestamp range"
        );
        Self {
            epoch_ms,
            counter: AtomicU64::new(0),
        }
    }

    fn next_uuid(&self) -> Uuid {
        let counter = self
            .counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
            .expect("test ID counter exhausted");

        let timestamp = u128::from(self.epoch_ms) << 80;
        let version = 7_u128 << 76;
        let counter_high = u128::from(counter >> 62) << 64;
        let rfc_4122_variant = 0b10_u128 << 62;
        let counter_low = u128::from(counter & UUID_V7_COUNTER_LOW_MASK);

        Uuid::from_u128(timestamp | version | counter_high | rfc_4122_variant | counter_low)
    }
}

impl IdGenerator for TestIdGenerator {
    fn generate_channel_binding_id(&self) -> ChannelBindingId {
        ChannelBindingId::from_uuid(self.next_uuid())
    }

    fn generate_session_id(&self) -> SessionId {
        SessionId::from_uuid(self.next_uuid())
    }

    fn generate_inbox_entry_id(&self) -> InboxEntryId {
        InboxEntryId::from_uuid(self.next_uuid())
    }

    fn generate_event_id(&self) -> EventId {
        EventId::from_uuid(self.next_uuid())
    }

    fn generate_outbox_id(&self) -> OutboxId {
        OutboxId::from_uuid(self.next_uuid())
    }

    fn generate_correlation_id(&self) -> CorrelationId {
        CorrelationId::from_uuid(self.next_uuid())
    }

    fn generate_turn_id(&self) -> TurnId {
        TurnId::from_uuid(self.next_uuid())
    }

    fn generate_task_id(&self) -> TaskId {
        TaskId::from_uuid(self.next_uuid())
    }

    fn generate_run_id(&self) -> RunId {
        RunId::from_uuid(self.next_uuid())
    }

    fn generate_lease_id(&self) -> LeaseId {
        LeaseId::from_uuid(self.next_uuid())
    }

    fn generate_worker_id(&self) -> WorkerId {
        WorkerId::from_uuid(self.next_uuid())
    }

    fn generate_attempt_id(&self) -> AttemptId {
        AttemptId::from_uuid(self.next_uuid())
    }

    fn generate_tool_call_id(&self) -> ToolCallId {
        ToolCallId::from_uuid(self.next_uuid())
    }

    fn generate_artifact_id(&self) -> ArtifactId {
        ArtifactId::from_uuid(self.next_uuid())
    }

    fn generate_context_epoch_id(&self) -> ContextEpochId {
        ContextEpochId::from_uuid(self.next_uuid())
    }

    fn generate_context_manifest_id(&self) -> ContextManifestId {
        ContextManifestId::from_uuid(self.next_uuid())
    }

    fn generate_context_item_id(&self) -> ContextItemId {
        ContextItemId::from_uuid(self.next_uuid())
    }

    fn generate_message_id(&self) -> MessageId {
        MessageId::from_uuid(self.next_uuid())
    }

    fn generate_effect_id(&self) -> EffectId {
        EffectId::from_uuid(self.next_uuid())
    }

    fn generate_approval_id(&self) -> ApprovalId {
        ApprovalId::from_uuid(self.next_uuid())
    }

    fn generate_validation_id(&self) -> ValidationId {
        ValidationId::from_uuid(self.next_uuid())
    }

    fn generate_delegation_id(&self) -> DelegationId {
        DelegationId::from_uuid(self.next_uuid())
    }

    fn generate_memory_id(&self) -> MemoryId {
        MemoryId::from_uuid(self.next_uuid())
    }

    fn generate_memory_revision_id(&self) -> MemoryRevisionId {
        MemoryRevisionId::from_uuid(self.next_uuid())
    }

    fn generate_compaction_id(&self) -> CompactionId {
        CompactionId::from_uuid(self.next_uuid())
    }

    fn generate_extension_id(&self) -> ExtensionId {
        ExtensionId::from_uuid(self.next_uuid())
    }

    fn generate_extension_grant_id(&self) -> ExtensionGrantId {
        ExtensionGrantId::from_uuid(self.next_uuid())
    }

    fn generate_extension_invocation_id(&self) -> ExtensionInvocationId {
        ExtensionInvocationId::from_uuid(self.next_uuid())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FixtureReadTool, FixtureResource, FixtureToolConfigurationError, ScriptedFakeProvider,
        TestClock, TestIdGenerator,
    };
    use mealy_application::{
        CancellationProbe, Clock, IdGenerator, MessageRole, ModelProvider, ModelUsage,
        NormalizedMessage, ProviderErrorClass, ProviderOutput, ProviderRequest, ProviderResponse,
        ProviderToolDefinition, ReadOnlyTool, ReadToolError,
    };
    use mealy_domain::{
        ApprovalId, ArtifactId, AttemptId, CompactionId, ContextEpochId, ContextItemId,
        ContextManifestId, CorrelationId, DelegationId, EffectId, EventId, ExtensionGrantId,
        ExtensionId, ExtensionInvocationId, InboxEntryId, LeaseId, MemoryId, MemoryRevisionId,
        MessageId, OutboxId, RunId, SessionId, TaskId, ToolCallId, TurnId, ValidationId, WorkerId,
    };
    use std::{
        collections::HashSet,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Duration,
    };
    use uuid::{Uuid, Variant};

    const EPOCH_MS: u64 = 1_700_000_000_123;

    #[derive(Default)]
    struct TestCancellation(AtomicBool);

    impl TestCancellation {
        fn set(&self, value: bool) {
            self.0.store(value, Ordering::SeqCst);
        }
    }

    impl CancellationProbe for TestCancellation {
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn request(provider: &ScriptedFakeProvider) -> ProviderRequest {
        let capabilities = provider.capabilities();
        ProviderRequest {
            run_id: RunId::new(),
            attempt_id: AttemptId::new(),
            context_manifest_id: ContextManifestId::new(),
            provider_id: capabilities.provider_id,
            model_id: capabilities.model_id,
            messages: vec![NormalizedMessage {
                role: MessageRole::User,
                content: "read the fixture".to_owned(),
                tool_call_id: None,
            }],
            tools: vec![ProviderToolDefinition {
                tool_id: "fixture.read".to_owned(),
                version: "1".to_owned(),
                description: "Reads one logical in-memory fixture resource".to_owned(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": { "resourceId": { "type": "string" } },
                    "required": ["resourceId"],
                    "additionalProperties": false,
                }),
                schema_digest: "0".repeat(64),
            }],
            maximum_output_tokens: 32,
            deadline_at_ms: 1_900_000_000_000,
        }
    }

    fn final_output(text: &str) -> ProviderOutput {
        ProviderOutput {
            response: ProviderResponse::Final {
                text: text.to_owned(),
            },
            finish_reason: "stop".to_owned(),
            usage: ModelUsage {
                input_tokens: 5,
                output_tokens: 2,
                total_tokens: 7,
                cost_microunits: 0,
            },
            provider_request_id: Some("fake-request".to_owned()),
        }
    }

    fn tool_output(tool_id: &str) -> ProviderOutput {
        ProviderOutput {
            response: ProviderResponse::ToolCall {
                tool_id: tool_id.to_owned(),
                arguments: serde_json::json!({ "resourceId": "fixture://phase2/report" }),
            },
            finish_reason: "tool_call".to_owned(),
            usage: ModelUsage {
                input_tokens: 4,
                output_tokens: 1,
                total_tokens: 5,
                cost_microunits: 0,
            },
            provider_request_id: Some("fake-request".to_owned()),
        }
    }

    fn generate_all_types(generator: &TestIdGenerator) -> [Uuid; 27] {
        let session_id: SessionId = generator.generate_session_id();
        let inbox_entry_id: InboxEntryId = generator.generate_inbox_entry_id();
        let event_id: EventId = generator.generate_event_id();
        let outbox_id: OutboxId = generator.generate_outbox_id();
        let correlation_id: CorrelationId = generator.generate_correlation_id();
        let turn_id: TurnId = generator.generate_turn_id();
        let task_id: TaskId = generator.generate_task_id();
        let run_id: RunId = generator.generate_run_id();
        let lease_id: LeaseId = generator.generate_lease_id();
        let worker_id: WorkerId = generator.generate_worker_id();
        let attempt_id: AttemptId = generator.generate_attempt_id();
        let tool_call_id: ToolCallId = generator.generate_tool_call_id();
        let artifact_id: ArtifactId = generator.generate_artifact_id();
        let context_epoch_id: ContextEpochId = generator.generate_context_epoch_id();
        let context_manifest_id: ContextManifestId = generator.generate_context_manifest_id();
        let context_item_id: ContextItemId = generator.generate_context_item_id();
        let message_id: MessageId = generator.generate_message_id();
        let effect_id: EffectId = generator.generate_effect_id();
        let approval_id: ApprovalId = generator.generate_approval_id();
        let validation_id: ValidationId = generator.generate_validation_id();
        let delegation_id: DelegationId = generator.generate_delegation_id();
        let memory_id: MemoryId = generator.generate_memory_id();
        let memory_revision_id: MemoryRevisionId = generator.generate_memory_revision_id();
        let compaction_id: CompactionId = generator.generate_compaction_id();
        let extension_id: ExtensionId = generator.generate_extension_id();
        let extension_grant_id: ExtensionGrantId = generator.generate_extension_grant_id();
        let extension_invocation_id: ExtensionInvocationId =
            generator.generate_extension_invocation_id();

        [
            session_id.as_uuid(),
            inbox_entry_id.as_uuid(),
            event_id.as_uuid(),
            outbox_id.as_uuid(),
            correlation_id.as_uuid(),
            turn_id.as_uuid(),
            task_id.as_uuid(),
            run_id.as_uuid(),
            lease_id.as_uuid(),
            worker_id.as_uuid(),
            attempt_id.as_uuid(),
            tool_call_id.as_uuid(),
            artifact_id.as_uuid(),
            context_epoch_id.as_uuid(),
            context_manifest_id.as_uuid(),
            context_item_id.as_uuid(),
            message_id.as_uuid(),
            effect_id.as_uuid(),
            approval_id.as_uuid(),
            validation_id.as_uuid(),
            delegation_id.as_uuid(),
            memory_id.as_uuid(),
            memory_revision_id.as_uuid(),
            compaction_id.as_uuid(),
            extension_id.as_uuid(),
            extension_grant_id.as_uuid(),
            extension_invocation_id.as_uuid(),
        ]
    }

    #[test]
    fn scripted_provider_returns_fifo_outputs_and_records_normalized_requests() {
        let expected_tool = tool_output("fixture.read");
        let expected_final = final_output("fixture content observed");
        let provider =
            ScriptedFakeProvider::new([Ok(expected_tool.clone()), Ok(expected_final.clone())]);
        let request = request(&provider);
        let cancellation = TestCancellation::default();

        assert_eq!(
            provider
                .complete(&request, &cancellation)
                .expect("first scripted output"),
            expected_tool
        );
        assert_eq!(
            provider
                .complete(&request, &cancellation)
                .expect("second scripted output"),
            expected_final
        );
        assert_eq!(provider.invocation_count(), 2);
        assert_eq!(provider.remaining_outputs(), 0);
        assert_eq!(provider.recorded_requests(), vec![request.clone(), request]);
    }

    #[test]
    fn cancellation_is_counted_without_consuming_the_next_output() {
        let expected = final_output("still available");
        let provider = ScriptedFakeProvider::new([Ok(expected.clone())]);
        let request = request(&provider);
        let cancellation = TestCancellation::default();
        cancellation.set(true);

        let cancelled = provider
            .complete(&request, &cancellation)
            .expect_err("cancelled call must not dispatch");
        assert_eq!(cancelled.class, ProviderErrorClass::Cancelled);
        assert_eq!(provider.invocation_count(), 1);
        assert_eq!(provider.remaining_outputs(), 1);

        cancellation.set(false);
        assert_eq!(
            provider
                .complete(&request, &cancellation)
                .expect("output remains after cancellation"),
            expected
        );
        assert_eq!(provider.invocation_count(), 2);
    }

    #[test]
    fn invalid_selection_and_extra_calls_fail_closed() {
        let expected = final_output("one output");
        let provider = ScriptedFakeProvider::new([Ok(expected.clone())]);
        let mut invalid = request(&provider);
        invalid.provider_id = "different-provider".to_owned();
        let cancellation = TestCancellation::default();

        let selection_error = provider
            .complete(&invalid, &cancellation)
            .expect_err("provider mismatch must fail");
        assert_eq!(selection_error.class, ProviderErrorClass::InvalidRequest);
        assert_eq!(provider.remaining_outputs(), 1);

        let valid = request(&provider);
        assert_eq!(
            provider
                .complete(&valid, &cancellation)
                .expect("valid call consumes the only output"),
            expected
        );
        let exhausted = provider
            .complete(&valid, &cancellation)
            .expect_err("extra call must fail closed");
        assert_eq!(exhausted.class, ProviderErrorClass::InvalidRequest);
        assert_eq!(provider.invocation_count(), 3);
    }

    #[test]
    fn scripted_provider_rejects_an_undeclared_tool_response() {
        let provider = ScriptedFakeProvider::new([Ok(tool_output("host.read-arbitrary-path"))]);
        let request = request(&provider);

        let error = provider
            .complete(&request, &TestCancellation::default())
            .expect_err("undeclared tool must not cross the normalized boundary");
        assert_eq!(error.class, ProviderErrorClass::InvalidResponse);
        assert_eq!(provider.remaining_outputs(), 0);
    }

    #[test]
    fn fixture_tool_reads_only_an_exact_in_memory_logical_resource() {
        let tool = FixtureReadTool::new(
            [(
                "fixture://phase2/report".to_owned(),
                FixtureResource::new("text/plain", b"bounded fixture report".to_vec()),
            )],
            1_024,
        )
        .expect("valid fixture tool");
        let descriptor = tool.descriptor();
        assert_eq!(descriptor.tool_id, "fixture.read");
        assert_eq!(descriptor.effect_class, "read_only");
        assert_eq!(descriptor.required_capability, "observe:fixture");
        assert_eq!(descriptor.descriptor_digest.len(), 64);
        assert_eq!(descriptor.schema_digest.len(), 64);

        let output = tool
            .execute(
                &serde_json::json!({ "resourceId": "fixture://phase2/report" }),
                &TestCancellation::default(),
            )
            .expect("configured logical resource should be readable");
        assert_eq!(output.media_type, "text/plain");
        assert_eq!(output.bytes, b"bounded fixture report");
        assert_eq!(output.source_locator, "fixture://phase2/report");
        assert_eq!(tool.invocation_count(), 1);
        assert_eq!(
            tool.requested_resource_ids(),
            vec!["fixture://phase2/report"]
        );
    }

    #[test]
    fn fixture_tool_rejects_non_logical_and_ambiguous_arguments() {
        let tool = FixtureReadTool::new([], 1_024).expect("empty fixture map is valid");
        let invalid_arguments = [
            serde_json::json!("fixture://phase2/report"),
            serde_json::json!({}),
            serde_json::json!({ "resourceId": "/etc/passwd" }),
            serde_json::json!({ "resourceId": "fixture://phase2/../secret" }),
            serde_json::json!({
                "resourceId": "fixture://phase2/report",
                "unexpected": true,
            }),
        ];

        for arguments in invalid_arguments {
            assert!(matches!(
                tool.execute(&arguments, &TestCancellation::default()),
                Err(ReadToolError::InvalidArguments(_))
            ));
        }
        assert_eq!(tool.invocation_count(), 5);
        assert!(tool.requested_resource_ids().is_empty());
    }

    #[test]
    fn fixture_tool_classifies_not_found_cancellation_and_output_bounds() {
        let tool = FixtureReadTool::new(
            [(
                "fixture://phase2/large".to_owned(),
                FixtureResource::new("text/plain", b"six!!".to_vec()),
            )],
            3,
        )
        .expect("valid bounded fixture tool");
        assert_eq!(
            tool.execute(
                &serde_json::json!({ "resourceId": "fixture://phase2/missing" }),
                &TestCancellation::default(),
            ),
            Err(ReadToolError::NotFound)
        );

        let cancellation = TestCancellation::default();
        cancellation.set(true);
        assert_eq!(
            tool.execute(
                &serde_json::json!({ "resourceId": "fixture://phase2/large" }),
                &cancellation,
            ),
            Err(ReadToolError::Cancelled)
        );
        cancellation.set(false);
        assert_eq!(
            tool.execute(
                &serde_json::json!({ "resourceId": "fixture://phase2/large" }),
                &cancellation,
            ),
            Err(ReadToolError::OutputTooLarge {
                actual: 5,
                maximum: 3,
            })
        );
        assert_eq!(tool.invocation_count(), 3);
    }

    #[test]
    fn fixture_tool_configuration_fails_closed() {
        assert_eq!(
            FixtureReadTool::new([], 0).expect_err("zero output limit must fail"),
            FixtureToolConfigurationError::ZeroOutputLimit
        );
        assert_eq!(
            FixtureReadTool::new(
                [(
                    "../../secret".to_owned(),
                    FixtureResource::new("text/plain", Vec::new()),
                )],
                10,
            )
            .expect_err("host-like path must fail"),
            FixtureToolConfigurationError::InvalidResourceId
        );
        assert_eq!(
            FixtureReadTool::new(
                [
                    (
                        "fixture://duplicate".to_owned(),
                        FixtureResource::new("text/plain", Vec::new()),
                    ),
                    (
                        "fixture://duplicate".to_owned(),
                        FixtureResource::new("text/plain", Vec::new()),
                    ),
                ],
                10,
            )
            .expect_err("duplicate logical resource must fail"),
            FixtureToolConfigurationError::DuplicateResourceId
        );
        assert_eq!(
            FixtureReadTool::new(
                [(
                    "fixture://bad-media".to_owned(),
                    FixtureResource::new("not a media type", Vec::new()),
                )],
                10,
            )
            .expect_err("malformed media type must fail"),
            FixtureToolConfigurationError::InvalidMediaType
        );
    }

    #[test]
    fn clock_advances_only_when_requested() {
        let clock = TestClock::new(100);
        assert_eq!(clock.now_ms(), 100);
        assert_eq!(clock.advance_ms(25), 125);
        assert_eq!(clock.now_ms(), 125);
    }

    #[test]
    fn clock_trait_converts_milliseconds_to_system_time() {
        let clock = TestClock::new(1_250);
        assert_eq!(
            Clock::now(&clock),
            std::time::UNIX_EPOCH + Duration::from_millis(1_250)
        );

        clock.advance_ms(-1_500);
        assert_eq!(
            Clock::now(&clock),
            std::time::UNIX_EPOCH - Duration::from_millis(250)
        );
    }

    #[test]
    fn id_sequence_is_repeatable_for_a_fixed_epoch() {
        let first = TestIdGenerator::new(EPOCH_MS);
        let second = TestIdGenerator::new(EPOCH_MS);

        assert_eq!(generate_all_types(&first), generate_all_types(&second));
        assert_eq!(generate_all_types(&first), generate_all_types(&second));
    }

    #[test]
    fn every_id_type_is_unique_and_uuid_v7() {
        let generator = TestIdGenerator::new(EPOCH_MS);
        let ids = generate_all_types(&generator);
        let unique = ids.into_iter().collect::<HashSet<_>>();

        assert_eq!(unique.len(), ids.len());
        for id in ids {
            assert_eq!(id.get_version_num(), 7);
            assert_eq!(id.get_variant(), Variant::RFC4122);
        }
    }

    #[test]
    fn concurrent_generation_remains_unique() {
        const THREADS: usize = 8;
        const IDS_PER_THREAD: usize = 128;

        let generator = Arc::new(TestIdGenerator::new(EPOCH_MS));
        let handles = (0..THREADS)
            .map(|_| {
                let generator = Arc::clone(&generator);
                thread::spawn(move || {
                    (0..IDS_PER_THREAD)
                        .map(|_| generator.generate_event_id().as_uuid())
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();

        let ids = handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("ID generation thread must finish"))
            .collect::<Vec<_>>();
        let unique = ids.iter().copied().collect::<HashSet<_>>();

        assert_eq!(ids.len(), THREADS * IDS_PER_THREAD);
        assert_eq!(unique.len(), ids.len());
    }
}
