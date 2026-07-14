//! Trusted, fixture-only built-in adapter used by the deterministic local provider proof.

use mealy_application::{
    CancellationProbe, ReadOnlyTool, ReadToolDescriptor, ReadToolError, ReadToolOutput,
    sha256_digest,
};
use std::{
    collections::BTreeMap,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use thiserror::Error;

const MAXIMUM_FIXTURE_RESOURCES: usize = 256;
const MAXIMUM_FIXTURE_RESOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_FIXTURE_ID_BYTES: usize = 256;
const MAXIMUM_FIXTURE_MEDIA_TYPE_BYTES: usize = 128;
// Keep the deterministic in-memory adapter at the normal run ceiling so host scheduler delay
// cannot silently shorten the configured policy. A one-second descriptor made a side-effect-free
// read fail terminally after 1.15 seconds of unrelated host contention.
const FIXTURE_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// One immutable logical resource exposed to the built-in fixture reader.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureResource {
    media_type: String,
    bytes: Vec<u8>,
}

impl FixtureResource {
    /// Creates an in-memory resource. [`FixtureReadTool::new`] validates its hard limits.
    #[must_use]
    pub fn new(media_type: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            media_type: media_type.into(),
            bytes: bytes.into(),
        }
    }
}

/// Invalid bounded configuration for [`FixtureReadTool`].
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FixtureToolConfigurationError {
    /// An output limit must be positive.
    #[error("fixture read-tool output limit must be positive")]
    ZeroOutputLimit,
    /// The immutable resource count exceeded its hard bound.
    #[error("fixture read tool supports at most {maximum} resources")]
    TooManyResources {
        /// Hard resource-count boundary.
        maximum: usize,
    },
    /// A logical ID was not a canonical `fixture://` locator.
    #[error("fixture resource ID is invalid")]
    InvalidResourceId,
    /// Two resources used the same logical ID.
    #[error("fixture resource ID is duplicated")]
    DuplicateResourceId,
    /// A media type was empty, malformed, or too large.
    #[error("fixture resource media type is invalid")]
    InvalidMediaType,
    /// One resource exceeded the adapter's absolute memory bound.
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

/// Countable built-in read tool backed only by immutable logical resources.
///
/// Resource IDs are never interpreted as paths or URLs. This adapter performs no filesystem,
/// environment, process, credential, clock, or network access.
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
    /// Returns [`FixtureToolConfigurationError`] for malformed or over-bound configuration.
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

    /// Returns the number of requests that reached the adapter.
    #[must_use]
    pub fn invocation_count(&self) -> usize {
        self.invocation_count.load(Ordering::SeqCst)
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
    resource_id.len() <= MAXIMUM_FIXTURE_ID_BYTES
        && resource_id
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
        timeout: FIXTURE_READ_TIMEOUT,
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

#[cfg(test)]
mod tests {
    use super::{FIXTURE_READ_TIMEOUT, FixtureReadTool, FixtureResource};
    use mealy_application::{CancellationProbe, ReadOnlyTool};

    struct NotCancelled;

    impl CancellationProbe for NotCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    #[test]
    fn fixture_adapter_reads_only_its_declared_logical_resource() {
        let tool = FixtureReadTool::new(
            [(
                "fixture://report".to_owned(),
                FixtureResource::new("text/plain", b"evidence".to_vec()),
            )],
            1_024,
        )
        .expect("valid fixture tool");
        let output = tool
            .execute(
                &serde_json::json!({"resourceId": "fixture://report"}),
                &NotCancelled,
            )
            .expect("read logical fixture");
        assert_eq!(output.bytes, b"evidence");
        assert_eq!(tool.invocation_count(), 1);
        let descriptor = tool.descriptor();
        assert_eq!(descriptor.timeout, FIXTURE_READ_TIMEOUT);
        descriptor
            .validate_evidence()
            .expect("fixture descriptor evidence should be canonical");
    }
}
