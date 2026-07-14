use crate::{ReadToolDescriptor, ReadToolError, sha256_digest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use thiserror::Error;
use url::Url;

/// Model-visible read-only rendered-browser tool identity.
pub const BROWSER_SNAPSHOT_TOOL_ID: &str = "browser.snapshot";
/// Stable Chrome `DevTools` Protocol revision required by the first browser boundary.
pub const BROWSER_CDP_PROTOCOL_VERSION: &str = "1.3";
/// Maximum installed Chrome Headless Shell bundle files.
pub const BROWSER_MAXIMUM_BUNDLE_FILES: usize = 512;
/// Maximum aggregate installed browser bundle bytes.
pub const BROWSER_MAXIMUM_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;
/// Maximum one browser bundle file.
pub const BROWSER_MAXIMUM_BUNDLE_FILE_BYTES: u64 = 256 * 1024 * 1024;

const BROWSER_MINIMUM_CHROME_MAJOR_VERSION: u64 = 132;
const BROWSER_MAXIMUM_CHROME_MAJOR_VERSION: u64 = 999;
const BROWSER_MAXIMUM_WAIT_MS: u64 = 5_000;
const BROWSER_MAXIMUM_TEXT_BYTES: usize = 128 * 1024;
const BROWSER_DEFAULT_TEXT_BYTES: usize = 64 * 1024;
const BROWSER_MAXIMUM_ELEMENTS: usize = 128;
const BROWSER_DEFAULT_ELEMENTS: usize = 64;
const BROWSER_MAXIMUM_FILL_VALUE_BYTES: usize = 4 * 1024;
const BROWSER_MAXIMUM_SCREENSHOT_BYTES: u64 = 512 * 1024;
const BROWSER_MAXIMUM_DOWNLOAD_BYTES: u64 = 512 * 1024;
const BROWSER_MAXIMUM_OUTPUT_BYTES: u64 = 1024 * 1024;

/// One installed, content-addressed Chrome Headless Shell runtime.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserConfig {
    enabled: bool,
    bundle_path: String,
    bundle_digest: String,
    executable_relative_path: String,
    executable_digest: String,
    product: String,
    protocol_version: String,
}

impl BrowserConfig {
    /// Constructs an exact installed browser runtime configuration.
    ///
    /// # Errors
    ///
    /// Returns [`BrowserConfigError`] for an unsafe path, digest, product, or protocol identity.
    pub fn new(
        enabled: bool,
        bundle_path: String,
        bundle_digest: String,
        executable_relative_path: String,
        executable_digest: String,
        product: String,
        protocol_version: String,
    ) -> Result<Self, BrowserConfigError> {
        let config = Self {
            enabled,
            bundle_path,
            bundle_digest,
            executable_relative_path,
            executable_digest,
            product,
            protocol_version,
        };
        config.validate()?;
        Ok(config)
    }

    /// Whether new model contexts may expose the browser tool.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Owner-private Mealy-home-relative content-addressed bundle path.
    #[must_use]
    pub fn bundle_path(&self) -> &str {
        &self.bundle_path
    }

    /// Digest of the complete canonical bundle inventory.
    #[must_use]
    pub fn bundle_digest(&self) -> &str {
        &self.bundle_digest
    }

    /// Exact executable path relative to the bundle root.
    #[must_use]
    pub fn executable_relative_path(&self) -> &str {
        &self.executable_relative_path
    }

    /// Digest of the exact Chrome Headless Shell executable bytes.
    #[must_use]
    pub fn executable_digest(&self) -> &str {
        &self.executable_digest
    }

    /// Exact CDP-reported headless-browser product and four-component version string.
    #[must_use]
    pub fn product(&self) -> &str {
        &self.product
    }

    /// Exact stable CDP protocol revision.
    #[must_use]
    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }

    /// Returns an enabled/disabled copy without weakening any content identity.
    #[must_use]
    pub fn with_enabled(&self, enabled: bool) -> Self {
        let mut changed = self.clone();
        changed.enabled = enabled;
        changed
    }

    /// Validates configuration loaded from durable non-secret state.
    ///
    /// # Errors
    ///
    /// Returns [`BrowserConfigError`] when any path or identity is non-canonical.
    pub fn validate(&self) -> Result<(), BrowserConfigError> {
        if !crate::is_sha256_digest(&self.bundle_digest)
            || !crate::is_sha256_digest(&self.executable_digest)
            || self.bundle_path != format!("browser-runtimes/{}", self.bundle_digest)
            || !safe_relative_path(&self.bundle_path)
            || self.executable_relative_path != "chrome-headless-shell"
            || !safe_relative_path(&self.executable_relative_path)
            || !valid_browser_product(&self.product)
            || self.protocol_version != BROWSER_CDP_PROTOCOL_VERSION
        {
            return Err(BrowserConfigError::Invalid);
        }
        Ok(())
    }
}

/// One stable accessible-link selection used by the read-only follow-link operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserLinkTarget {
    name: String,
    #[serde(default = "default_occurrence")]
    occurrence: usize,
}

/// One exact accessible element that may be activated inside the read-only browser boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserElementTarget {
    role: String,
    name: String,
    #[serde(default = "default_occurrence")]
    occurrence: usize,
}

impl BrowserElementTarget {
    /// Exact supported accessible role (`link` or form-free `button`).
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Exact accessible element name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// One-based occurrence among exact role/name matches.
    #[must_use]
    pub const fn occurrence(&self) -> usize {
        self.occurrence
    }
}

/// One exact accessible text control filled without dispatching page input/change events.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserFillTarget {
    role: String,
    name: String,
    #[serde(default = "default_occurrence")]
    occurrence: usize,
    value: String,
    #[serde(default)]
    submit_get_form: bool,
}

impl BrowserFillTarget {
    /// Exact supported accessible role (`textbox` or `searchbox`).
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Exact accessible element name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// One-based occurrence among exact role/name matches.
    #[must_use]
    pub const fn occurrence(&self) -> usize {
        self.occurrence
    }

    /// Exact bounded value set through a captured native value setter.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Whether Mealy should construct a same-origin GET using only this named control.
    #[must_use]
    pub const fn submit_get_form(&self) -> bool {
        self.submit_get_form
    }
}

impl BrowserLinkTarget {
    /// Exact accessible link name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// One-based occurrence among exact accessible-name matches.
    #[must_use]
    pub const fn occurrence(&self) -> usize {
        self.occurrence
    }
}

/// Strict normalized request passed to the isolated rendered-browser worker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserSnapshotRequest {
    url: String,
    #[serde(default)]
    wait_ms: u64,
    #[serde(default = "default_text_bytes")]
    maximum_text_bytes: usize,
    #[serde(default = "default_elements")]
    maximum_elements: usize,
    #[serde(default)]
    capture_screenshot: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    follow_link: Option<BrowserLinkTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    activate_element: Option<BrowserElementTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fill_element: Option<BrowserFillTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    download_link: Option<BrowserLinkTarget>,
}

impl BrowserSnapshotRequest {
    /// Canonical initial HTTP(S) URL and durable source locator.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Bounded post-load rendering delay.
    #[must_use]
    pub const fn wait_ms(&self) -> u64 {
        self.wait_ms
    }

    /// Maximum normalized visible text bytes.
    #[must_use]
    pub const fn maximum_text_bytes(&self) -> usize {
        self.maximum_text_bytes
    }

    /// Maximum normalized accessible element records.
    #[must_use]
    pub const fn maximum_elements(&self) -> usize {
        self.maximum_elements
    }

    /// Whether a bounded PNG preview is requested in the durable JSON result.
    #[must_use]
    pub const fn capture_screenshot(&self) -> bool {
        self.capture_screenshot
    }

    /// Optional exact accessible link followed as a GET-only navigation.
    #[must_use]
    pub const fn follow_link(&self) -> Option<&BrowserLinkTarget> {
        self.follow_link.as_ref()
    }

    /// Optional exact same-origin GET link or form-free button activated once.
    #[must_use]
    pub const fn activate_element(&self) -> Option<&BrowserElementTarget> {
        self.activate_element.as_ref()
    }

    /// Optional exact non-password text control filled once, with an optional safe GET submit.
    #[must_use]
    pub const fn fill_element(&self) -> Option<&BrowserFillTarget> {
        self.fill_element.as_ref()
    }

    /// Optional exact accessible same-origin link captured as a bounded ephemeral download.
    #[must_use]
    pub const fn download_link(&self) -> Option<&BrowserLinkTarget> {
        self.download_link.as_ref()
    }
}

fn default_occurrence() -> usize {
    1
}

fn default_text_bytes() -> usize {
    BROWSER_DEFAULT_TEXT_BYTES
}

fn default_elements() -> usize {
    BROWSER_DEFAULT_ELEMENTS
}

/// Parses and validates exact browser snapshot arguments before a process is launched.
///
/// # Errors
///
/// Returns [`ReadToolError::InvalidArguments`] for a malformed URL, unsafe bound, or ambiguous
/// follow-link target.
pub fn validate_browser_snapshot_arguments(
    arguments: &Value,
) -> Result<BrowserSnapshotRequest, ReadToolError> {
    let mut request = serde_json::from_value::<BrowserSnapshotRequest>(arguments.clone())
        .map_err(|_| invalid_arguments("browser arguments do not match the exact schema"))?;
    let url = canonical_browser_url(&request.url)?;
    if request.wait_ms > BROWSER_MAXIMUM_WAIT_MS
        || !(1..=BROWSER_MAXIMUM_TEXT_BYTES).contains(&request.maximum_text_bytes)
        || !(1..=BROWSER_MAXIMUM_ELEMENTS).contains(&request.maximum_elements)
        || request.follow_link.as_ref().is_some_and(|target| {
            !valid_browser_element_name(&target.name) || !(1..=32).contains(&target.occurrence)
        })
        || request.activate_element.as_ref().is_some_and(|target| {
            !matches!(target.role.as_str(), "link" | "button")
                || !valid_browser_element_name(&target.name)
                || !(1..=32).contains(&target.occurrence)
        })
        || request.fill_element.as_ref().is_some_and(|target| {
            !matches!(target.role.as_str(), "textbox" | "searchbox")
                || !valid_browser_element_name(&target.name)
                || !(1..=32).contains(&target.occurrence)
                || target.value.len() > BROWSER_MAXIMUM_FILL_VALUE_BYTES
                || target
                    .value
                    .chars()
                    .any(|character| character.is_control() && character != '\n')
        })
        || request.download_link.as_ref().is_some_and(|target| {
            !valid_browser_element_name(&target.name) || !(1..=32).contains(&target.occurrence)
        })
        || request.capture_screenshot && request.download_link.is_some()
        || usize::from(request.follow_link.is_some())
            + usize::from(request.activate_element.is_some())
            + usize::from(request.fill_element.is_some())
            + usize::from(request.download_link.is_some())
            > 1
    {
        return Err(invalid_arguments("browser argument bound is invalid"));
    }
    request.url = url;
    Ok(request)
}

/// Builds the immutable rendered-browser read-tool descriptor.
///
/// # Errors
///
/// Returns a descriptor evidence error when canonical material cannot be represented.
pub fn browser_snapshot_descriptor()
-> Result<ReadToolDescriptor, crate::ToolDescriptorEvidenceError> {
    let input_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "url": {"type": "string", "minLength": 1, "maxLength": 4096},
            "waitMs": {"type": "integer", "minimum": 0, "maximum": BROWSER_MAXIMUM_WAIT_MS},
            "maximumTextBytes": {"type": "integer", "minimum": 1, "maximum": BROWSER_MAXIMUM_TEXT_BYTES},
            "maximumElements": {"type": "integer", "minimum": 1, "maximum": BROWSER_MAXIMUM_ELEMENTS},
            "captureScreenshot": {"type": "boolean"},
            "followLink": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "name": {"type": "string", "minLength": 1, "maxLength": 1024},
                    "occurrence": {"type": "integer", "minimum": 1, "maximum": 32}
                },
                "required": ["name"]
            },
            "activateElement": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "role": {"enum": ["link", "button"]},
                    "name": {"type": "string", "minLength": 1, "maxLength": 1024},
                    "occurrence": {"type": "integer", "minimum": 1, "maximum": 32}
                },
                "required": ["role", "name"]
            },
            "fillElement": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "role": {"enum": ["textbox", "searchbox"]},
                    "name": {"type": "string", "minLength": 1, "maxLength": 1024},
                    "occurrence": {"type": "integer", "minimum": 1, "maximum": 32},
                    "value": {"type": "string", "maxLength": BROWSER_MAXIMUM_FILL_VALUE_BYTES},
                    "submitGetForm": {"type": "boolean"}
                },
                "required": ["role", "name", "value"]
            },
            "downloadLink": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "name": {"type": "string", "minLength": 1, "maxLength": 1024},
                    "occurrence": {"type": "integer", "minimum": 1, "maximum": 32}
                },
                "required": ["name"]
            }
        },
        "required": ["url"]
    });
    let output_schema = browser_snapshot_output_schema();
    let schema_digest = sha256_digest(input_schema.to_string().as_bytes());
    let mut descriptor = ReadToolDescriptor {
        tool_id: BROWSER_SNAPSHOT_TOOL_ID.to_owned(),
        version: "4".to_owned(),
        input_schema,
        output_schema,
        descriptor_digest: String::new(),
        schema_digest,
        effect_class: "read_only".to_owned(),
        risk_class: "medium".to_owned(),
        required_capability: "network:browser".to_owned(),
        timeout: Duration::from_secs(30),
        maximum_output_bytes: BROWSER_MAXIMUM_OUTPUT_BYTES,
        conflict_key_template: "browser.snapshot:{url}".to_owned(),
        recovery: "retry".to_owned(),
    };
    descriptor.descriptor_digest = descriptor.computed_descriptor_digest()?;
    Ok(descriptor)
}

fn browser_snapshot_output_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "activatedElement": {
                "oneOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "name": {"type": "string", "minLength": 1, "maxLength": 1024},
                            "occurrence": {"type": "integer", "minimum": 1, "maximum": 32},
                            "role": {"enum": ["link", "button"]}
                        },
                        "required": ["name", "occurrence", "role"]
                    }
                ]
            },
            "browserProduct": {"type": "string", "pattern": "^HeadlessChrome/[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$", "maxLength": 128},
            "download": browser_download_output_schema(),
            "elements": {
                "type": "array",
                "maxItems": BROWSER_MAXIMUM_ELEMENTS,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "name": {"type": "string", "minLength": 1, "maxLength": 1024},
                        "occurrence": {"type": "integer", "minimum": 1},
                        "role": {
                            "enum": [
                                "link", "button", "textbox", "searchbox", "checkbox",
                                "radio", "combobox", "menuitem", "tab", "switch",
                                "slider", "option"
                            ]
                        }
                    },
                    "required": ["name", "occurrence", "role"]
                }
            },
            "finalUrl": {"type": "string", "minLength": 1, "maxLength": 4096},
            "filledElement": browser_filled_element_output_schema(),
            "followedLink": {
                "oneOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "name": {"type": "string", "minLength": 1, "maxLength": 1024},
                            "occurrence": {"type": "integer", "minimum": 1, "maximum": 32},
                            "url": {"type": "string", "minLength": 1, "maxLength": 4096}
                        },
                        "required": ["name", "occurrence", "url"]
                    }
                ]
            },
            "protocolVersion": {"const": BROWSER_CDP_PROTOCOL_VERSION},
            "screenshot": {
                "oneOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "dataBase64": {"type": "string", "maxLength": 699_052},
                            "mediaType": {"const": "image/png"},
                            "sha256Digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                            "sizeBytes": {"type": "integer", "minimum": 8, "maximum": BROWSER_MAXIMUM_SCREENSHOT_BYTES}
                        },
                        "required": ["dataBase64", "mediaType", "sha256Digest", "sizeBytes"]
                    }
                ]
            },
            "sourceLocator": {"type": "string", "minLength": 1, "maxLength": 4096},
            "text": {"type": "string", "maxLength": BROWSER_MAXIMUM_TEXT_BYTES},
            "title": {"type": "string", "maxLength": 4096},
            "truncatedElements": {"type": "boolean"},
            "truncatedText": {"type": "boolean"}
        },
        "required": [
            "activatedElement", "browserProduct", "download", "elements", "filledElement",
            "finalUrl", "followedLink", "protocolVersion", "screenshot", "sourceLocator",
            "text", "title", "truncatedElements", "truncatedText"
        ]
    })
}

fn browser_download_output_schema() -> Value {
    json!({
        "oneOf": [
            {"type": "null"},
            {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "dataBase64": {"type": "string", "maxLength": 699_052},
                    "mediaType": {"const": "application/octet-stream"},
                    "sha256Digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "sizeBytes": {"type": "integer", "minimum": 0, "maximum": BROWSER_MAXIMUM_DOWNLOAD_BYTES},
                    "url": {"type": "string", "minLength": 1, "maxLength": 4096}
                },
                "required": ["dataBase64", "mediaType", "sha256Digest", "sizeBytes", "url"]
            }
        ]
    })
}

fn browser_filled_element_output_schema() -> Value {
    json!({
        "oneOf": [
            {"type": "null"},
            {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "name": {"type": "string", "minLength": 1, "maxLength": 1024},
                    "occurrence": {"type": "integer", "minimum": 1, "maximum": 32},
                    "role": {"enum": ["textbox", "searchbox"]},
                    "submittedGetForm": {"type": "boolean"},
                    "submittedUrl": {
                        "oneOf": [
                            {"type": "null"},
                            {"type": "string", "minLength": 1, "maxLength": 4096}
                        ]
                    },
                    "valueBytes": {"type": "integer", "minimum": 0, "maximum": BROWSER_MAXIMUM_FILL_VALUE_BYTES},
                    "valueSha256Digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                },
                "required": [
                    "name", "occurrence", "role", "submittedGetForm", "submittedUrl",
                    "valueBytes", "valueSha256Digest"
                ]
            }
        ]
    })
}

fn valid_browser_element_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1_024
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value.split_whitespace().collect::<Vec<_>>().join(" ") == value
}

/// Maximum decoded PNG bytes admitted into one browser result.
#[must_use]
pub const fn browser_maximum_screenshot_bytes() -> u64 {
    BROWSER_MAXIMUM_SCREENSHOT_BYTES
}

fn canonical_browser_url(value: &str) -> Result<String, ReadToolError> {
    if value.is_empty() || value.len() > 4_096 || value.trim() != value {
        return Err(invalid_arguments("browser URL is invalid"));
    }
    let url = Url::parse(value).map_err(|_| invalid_arguments("browser URL is invalid"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
        || !matches!(url.scheme(), "http" | "https")
    {
        return Err(invalid_arguments("browser URL is invalid"));
    }
    Ok(url.to_string())
}

fn valid_browser_product(value: &str) -> bool {
    let Some(version) = value.strip_prefix("HeadlessChrome/") else {
        return false;
    };
    if value.len() > 128 || value.chars().any(char::is_control) {
        return false;
    }
    let components = version.split('.').collect::<Vec<_>>();
    if components.len() != 4
        || components.iter().any(|component| {
            component.is_empty()
                || !component.bytes().all(|byte| byte.is_ascii_digit())
                || (component.len() > 1 && component.starts_with('0'))
        })
    {
        return false;
    }
    components[0].parse::<u64>().is_ok_and(|major| {
        (BROWSER_MINIMUM_CHROME_MAJOR_VERSION..=BROWSER_MAXIMUM_CHROME_MAJOR_VERSION)
            .contains(&major)
    }) && components[1..]
        .iter()
        .all(|component| component.parse::<u64>().is_ok())
}

fn safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn invalid_arguments(message: &str) -> ReadToolError {
    ReadToolError::InvalidArguments(message.to_owned())
}

/// Invalid installed browser runtime configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BrowserConfigError {
    /// Path, digest, product, or protocol identity is malformed or unsupported.
    #[error("browser runtime configuration is invalid")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::{
        BROWSER_CDP_PROTOCOL_VERSION, BrowserConfig, browser_snapshot_descriptor,
        validate_browser_snapshot_arguments,
    };
    use serde_json::json;

    #[test]
    fn browser_configuration_and_descriptor_are_exact_and_separate_from_personal_profiles() {
        let digest = "a".repeat(64);
        let config = BrowserConfig::new(
            true,
            format!("browser-runtimes/{digest}"),
            digest.clone(),
            "chrome-headless-shell".to_owned(),
            "b".repeat(64),
            "HeadlessChrome/150.0.7871.115".to_owned(),
            BROWSER_CDP_PROTOCOL_VERSION.to_owned(),
        )
        .expect("valid config");
        assert!(config.enabled());
        let descriptor = browser_snapshot_descriptor().expect("descriptor");
        assert_eq!(descriptor.tool_id, "browser.snapshot");
        assert_eq!(descriptor.version, "4");
        assert_eq!(descriptor.required_capability, "network:browser");
        assert_eq!(descriptor.effect_class, "read_only");
        assert_eq!(descriptor.risk_class, "medium");
        assert!(
            BrowserConfig::new(
                true,
                format!("browser-runtimes/{digest}"),
                digest,
                "chrome-headless-shell".to_owned(),
                "b".repeat(64),
                "HeadlessChrome/0150.0.7871.115".to_owned(),
                BROWSER_CDP_PROTOCOL_VERSION.to_owned(),
            )
            .is_err()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn browser_arguments_are_canonical_bounded_and_get_only() {
        let request = validate_browser_snapshot_arguments(&json!({
            "url": "https://example.com/path",
            "waitMs": 250,
            "maximumTextBytes": 4096,
            "maximumElements": 12,
            "captureScreenshot": true,
            "followLink": {"name": "Details", "occurrence": 2}
        }))
        .expect("valid request");
        assert_eq!(request.url(), "https://example.com/path");
        assert_eq!(request.follow_link().expect("link").occurrence(), 2);
        let activation = validate_browser_snapshot_arguments(&json!({
            "url": "https://example.com/path",
            "activateElement": {"role": "button", "name": "Show details"}
        }))
        .expect("valid activation");
        assert_eq!(
            activation.activate_element().expect("activation").role(),
            "button"
        );
        let fill = validate_browser_snapshot_arguments(&json!({
            "url": "https://example.com/search",
            "fillElement": {
                "role": "searchbox",
                "name": "Query",
                "value": "durable browser evidence",
                "submitGetForm": true
            }
        }))
        .expect("valid safe GET form fill");
        let fill_target = fill.fill_element().expect("fill target");
        assert_eq!(fill_target.role(), "searchbox");
        assert_eq!(fill_target.value(), "durable browser evidence");
        assert!(fill_target.submit_get_form());
        let download = validate_browser_snapshot_arguments(&json!({
            "url": "https://example.com/files",
            "downloadLink": {"name": "Export evidence"}
        }))
        .expect("valid bounded download target");
        assert_eq!(
            download.download_link().expect("download target").name(),
            "Export evidence"
        );
        assert!(
            validate_browser_snapshot_arguments(
                &json!({"url": "file:///etc/passwd", "captureScreenshot": false})
            )
            .is_err()
        );
        assert!(
            validate_browser_snapshot_arguments(&json!({
                "url": "https://example.com/",
                "followLink": {"name": "Submit\nnow"}
            }))
            .is_err()
        );
        assert!(
            validate_browser_snapshot_arguments(&json!({
                "url": "https://example.com/",
                "captureScreenshot": true,
                "downloadLink": {"name": "Oversized combined evidence"}
            }))
            .is_err()
        );
        assert!(
            validate_browser_snapshot_arguments(&json!({
                "url": "https://example.com/",
                "fillElement": {"role": "textbox", "name": "Unsafe", "value": "bad\u{0}value"}
            }))
            .is_err()
        );
        assert!(
            validate_browser_snapshot_arguments(&json!({
                "url": "https://example.com/",
                "activateElement": {"role": "button", "name": "Details"},
                "fillElement": {"role": "textbox", "name": "Query", "value": "evidence"}
            }))
            .is_err()
        );
        assert!(
            validate_browser_snapshot_arguments(&json!({
                "url": "https://example.com/",
                "followLink": {"name": "Repeated  whitespace"}
            }))
            .is_err()
        );
        assert!(
            validate_browser_snapshot_arguments(&json!({
                "url": "https://example.com/",
                "activateElement": {"role": "textbox", "name": "Unsafe"}
            }))
            .is_err()
        );
        assert!(
            validate_browser_snapshot_arguments(&json!({
                "url": "https://example.com/",
                "followLink": {"name": "Details"},
                "activateElement": {"role": "link", "name": "Details"}
            }))
            .is_err()
        );
    }

    #[test]
    fn browser_output_schema_accepts_only_the_exact_replay_shape() {
        let descriptor = browser_snapshot_descriptor().expect("descriptor");
        let validator = jsonschema::validator_for(&descriptor.output_schema).expect("schema");
        let output = json!({
            "activatedElement": null,
            "browserProduct": "HeadlessChrome/150.0.7871.115",
            "download": null,
            "elements": [{"name": "Details", "occurrence": 1, "role": "link"}],
            "filledElement": null,
            "finalUrl": "https://example.com/",
            "followedLink": null,
            "protocolVersion": "1.3",
            "screenshot": null,
            "sourceLocator": "https://example.com/",
            "text": "Example",
            "title": "Example",
            "truncatedElements": false,
            "truncatedText": false
        });
        assert!(validator.is_valid(&output));
        let mut extra = output.clone();
        extra["untrustedExtra"] = json!(true);
        assert!(!validator.is_valid(&extra));
        let mut invalid_role = output;
        invalid_role["elements"][0]["role"] = json!("dialog");
        assert!(!validator.is_valid(&invalid_role));
    }
}
