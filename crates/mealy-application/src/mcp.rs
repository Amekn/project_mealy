use crate::{ReadToolDescriptor, ReadToolError, sha256_digest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path, time::Duration};
use thiserror::Error;

/// Exact MCP protocol revision implemented by Mealy's local stdio client.
pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
/// Maximum owner-reviewed tools exposed from one configured MCP server.
pub const MCP_MAXIMUM_TOOLS_PER_SERVER: usize = 64;
/// Maximum direct, non-secret process arguments for one configured MCP server.
pub const MCP_MAXIMUM_ARGUMENTS: usize = 64;
/// Maximum canonical bytes retained for one advertised MCP tool definition.
pub const MCP_MAXIMUM_DEFINITION_BYTES: usize = 256 * 1024;

/// Maximum independently configured local stdio MCP servers.
pub const MCP_MAXIMUM_SERVERS: usize = 16;
const MCP_MAXIMUM_ARGUMENT_BYTES: usize = 4_096;
const MCP_MAXIMUM_ARGUMENT_TOTAL_BYTES: usize = 32 * 1024;
const MCP_MAXIMUM_OUTPUT_BYTES: u64 = 1024 * 1024;
const MCP_MAXIMUM_TOOL_ARGUMENT_BYTES: usize = 64 * 1024;
const MCP_MAXIMUM_TIMEOUT_MS: u64 = 60_000;
const MCP_MINIMUM_TIMEOUT_MS: u64 = 100;

/// One exact MCP tool definition reviewed and granted by the owner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpToolGrant {
    definition: Value,
    definition_digest: String,
    timeout_ms: u64,
    maximum_output_bytes: u64,
}

impl McpToolGrant {
    /// Constructs a grant from one freshly discovered, exact server definition.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] when the definition, JSON Schema, timeout, or output bound is
    /// unsafe or cannot be represented by the supported MCP subset.
    pub fn new(
        definition: Value,
        timeout_ms: u64,
        maximum_output_bytes: u64,
    ) -> Result<Self, McpConfigError> {
        let definition_digest = mcp_tool_definition_digest(&definition)?;
        let grant = Self {
            definition,
            definition_digest,
            timeout_ms,
            maximum_output_bytes,
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Exact server-advertised tool definition, including otherwise untrusted annotations.
    #[must_use]
    pub const fn definition(&self) -> &Value {
        &self.definition
    }

    /// SHA-256 of the canonical complete advertised definition.
    #[must_use]
    pub fn definition_digest(&self) -> &str {
        &self.definition_digest
    }

    /// Remote, server-local tool name.
    ///
    /// # Panics
    ///
    /// Panics only if trusted code calls this accessor on a value that has bypassed `validate`.
    /// Normal construction and configuration loading validate the complete grant first.
    #[must_use]
    pub fn remote_name(&self) -> &str {
        self.definition
            .get("name")
            .and_then(Value::as_str)
            .expect("validated MCP tool grant always has a name")
    }

    /// Bounded server description retained as untrusted model-facing metadata.
    #[must_use]
    pub fn description(&self) -> &str {
        self.definition
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("Invokes an owner-reviewed read-only MCP tool")
    }

    /// Exact advertised input JSON Schema.
    ///
    /// # Panics
    ///
    /// Panics only if trusted code calls this accessor on a value that has bypassed `validate`.
    /// Normal construction and configuration loading validate the complete grant first.
    #[must_use]
    pub fn input_schema(&self) -> &Value {
        self.definition
            .get("inputSchema")
            .expect("validated MCP tool grant always has an input schema")
    }

    /// Per-call wall-clock ceiling.
    #[must_use]
    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    /// Maximum normalized terminal result bytes.
    #[must_use]
    pub const fn maximum_output_bytes(&self) -> u64 {
        self.maximum_output_bytes
    }

    fn validate(&self) -> Result<(), McpConfigError> {
        inspect_mcp_tool_definition(&self.definition)?;
        if mcp_tool_definition_digest(&self.definition)? != self.definition_digest
            || !(MCP_MINIMUM_TIMEOUT_MS..=MCP_MAXIMUM_TIMEOUT_MS).contains(&self.timeout_ms)
            || !(1..=MCP_MAXIMUM_OUTPUT_BYTES).contains(&self.maximum_output_bytes)
        {
            return Err(McpConfigError::InvalidToolGrant);
        }
        Ok(())
    }
}

/// One schema-versioned, non-secret, digest-pinned local stdio MCP server grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpServerConfig {
    server_id: String,
    executable_path: String,
    executable_digest: String,
    arguments: Vec<String>,
    toolset_digest: String,
    enabled: bool,
    tools: Vec<McpToolGrant>,
}

impl McpServerConfig {
    /// Constructs a complete owner-reviewed local stdio server configuration.
    ///
    /// `executable_path` is a private Mealy-home-relative content-addressed path. Server code is
    /// never selected through `PATH` and receives no ambient environment or network authority.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] for invalid identity, executable evidence, arguments, tool
    /// definitions, ordering, or bounds.
    pub fn new(
        server_id: String,
        executable_path: String,
        executable_digest: String,
        arguments: Vec<String>,
        toolset_digest: String,
        enabled: bool,
        mut tools: Vec<McpToolGrant>,
    ) -> Result<Self, McpConfigError> {
        tools.sort_by(|left, right| left.remote_name().cmp(right.remote_name()));
        let config = Self {
            server_id,
            executable_path,
            executable_digest,
            arguments,
            toolset_digest,
            enabled,
            tools,
        };
        config.validate()?;
        Ok(config)
    }

    /// Stable logical server identity.
    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// Private Mealy-home-relative content-addressed executable path.
    #[must_use]
    pub fn executable_path(&self) -> &str {
        &self.executable_path
    }

    /// SHA-256 of the exact installed executable bytes.
    #[must_use]
    pub fn executable_digest(&self) -> &str {
        &self.executable_digest
    }

    /// Direct non-secret server arguments, with no shell or expansion.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// SHA-256 binding the negotiated protocol revision and complete advertised tool list.
    #[must_use]
    pub fn toolset_digest(&self) -> &str {
        &self.toolset_digest
    }

    /// Whether the server is activated for new context epochs.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Exact owner-reviewed tool grants in remote-name order.
    #[must_use]
    pub fn tools(&self) -> &[McpToolGrant] {
        &self.tools
    }

    /// Returns an enabled/disabled copy while preserving exact reviewed evidence.
    #[must_use]
    pub fn with_enabled(&self, enabled: bool) -> Self {
        let mut changed = self.clone();
        changed.enabled = enabled;
        changed
    }

    /// Model-visible collision-resistant tool identity for one granted remote name.
    #[must_use]
    pub fn exposed_tool_id(&self, remote_name: &str) -> String {
        format!("mcp.{}.{}", self.server_id, remote_name)
    }

    /// Validates a complete server configuration loaded from durable non-secret configuration.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] for malformed or non-canonical state.
    pub fn validate(&self) -> Result<(), McpConfigError> {
        if !valid_mcp_name(&self.server_id, 32)
            || !crate::is_sha256_digest(&self.executable_digest)
            || self.executable_path != format!("mcp-servers/{}/server", self.executable_digest)
            || !safe_relative_path(&self.executable_path)
            || !crate::is_sha256_digest(&self.toolset_digest)
            || self.arguments.len() > MCP_MAXIMUM_ARGUMENTS
            || self
                .arguments
                .iter()
                .any(|argument| invalid_argument(argument))
            || self.arguments.iter().map(String::len).sum::<usize>()
                > MCP_MAXIMUM_ARGUMENT_TOTAL_BYTES
            || self.tools.is_empty()
            || self.tools.len() > MCP_MAXIMUM_TOOLS_PER_SERVER
        {
            return Err(McpConfigError::InvalidServer);
        }
        let mut names = BTreeSet::new();
        for tool in &self.tools {
            tool.validate()?;
            if !names.insert(tool.remote_name())
                || self.exposed_tool_id(tool.remote_name()).len() > 128
            {
                return Err(McpConfigError::InvalidServer);
            }
        }
        if !self
            .tools
            .windows(2)
            .all(|window| window[0].remote_name() < window[1].remote_name())
        {
            return Err(McpConfigError::InvalidServer);
        }
        Ok(())
    }
}

/// Validated projection of one server-advertised tool.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpToolInspection {
    /// Exact full server definition.
    pub definition: Value,
    /// Canonical definition digest.
    pub definition_digest: String,
}

/// Bounded result of MCP initialization and complete paginated tool discovery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpServerDiscovery {
    /// Exact negotiated protocol revision.
    pub protocol_version: String,
    /// Bounded server implementation metadata returned at initialization.
    pub server_info: Value,
    /// Complete validated tools in name order.
    pub tools: Vec<McpToolInspection>,
}

impl McpServerDiscovery {
    /// Validates protocol identity, metadata bounds, tool definitions, digests, uniqueness, and
    /// canonical ordering.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] when discovery evidence is malformed or oversized.
    pub fn validate(&self) -> Result<(), McpConfigError> {
        if self.protocol_version != MCP_PROTOCOL_VERSION
            || !self.server_info.is_object()
            || serde_json::to_vec(&self.server_info)
                .map_err(|_| McpConfigError::InvalidDiscovery)?
                .len()
                > 64 * 1024
            || self.tools.is_empty()
            || self.tools.len() > MCP_MAXIMUM_TOOLS_PER_SERVER
        {
            return Err(McpConfigError::InvalidDiscovery);
        }
        let mut prior = None;
        for tool in &self.tools {
            let inspected = inspect_mcp_tool_definition(&tool.definition)?;
            if mcp_tool_definition_digest(&tool.definition)? != tool.definition_digest
                || prior.is_some_and(|name| name >= inspected.name)
            {
                return Err(McpConfigError::InvalidDiscovery);
            }
            prior = Some(inspected.name);
        }
        Ok(())
    }

    /// Finds one exact remote tool definition.
    #[must_use]
    pub fn tool(&self, remote_name: &str) -> Option<&McpToolInspection> {
        self.tools
            .iter()
            .find(|tool| tool.definition.get("name").and_then(Value::as_str) == Some(remote_name))
    }

    /// Digests the exact negotiated revision and complete canonical advertised tool set.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] when discovery evidence is invalid.
    pub fn toolset_digest(&self) -> Result<String, McpConfigError> {
        self.validate()?;
        Ok(sha256_digest(
            json!({
                "contractVersion": "mealy.mcp-toolset.v1",
                "protocolVersion": self.protocol_version,
                "tools": self.tools,
            })
            .to_string()
            .as_bytes(),
        ))
    }
}

struct InspectedDefinition<'a> {
    name: &'a str,
}

/// Computes the canonical complete MCP tool-definition digest after strict inspection.
///
/// # Errors
///
/// Returns [`McpConfigError`] for an invalid, oversized, remotely-resolving, or unsupported schema.
pub fn mcp_tool_definition_digest(definition: &Value) -> Result<String, McpConfigError> {
    inspect_mcp_tool_definition(definition)?;
    let bytes =
        serde_json::to_vec(definition).map_err(|_| McpConfigError::InvalidToolDefinition)?;
    Ok(sha256_digest(&bytes))
}

fn inspect_mcp_tool_definition(
    definition: &Value,
) -> Result<InspectedDefinition<'_>, McpConfigError> {
    let object = definition
        .as_object()
        .ok_or(McpConfigError::InvalidToolDefinition)?;
    let bytes =
        serde_json::to_vec(definition).map_err(|_| McpConfigError::InvalidToolDefinition)?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| valid_mcp_name(name, 64))
        .ok_or(McpConfigError::InvalidToolDefinition)?;
    if bytes.len() > MCP_MAXIMUM_DEFINITION_BYTES
        || object.get("description").is_some_and(|description| {
            description
                .as_str()
                .is_none_or(|text| text.len() > 4_096 || text.chars().any(char::is_control))
        })
        || object
            .get("execution")
            .and_then(|execution| execution.get("taskSupport"))
            .and_then(Value::as_str)
            == Some("required")
    {
        return Err(McpConfigError::InvalidToolDefinition);
    }
    let schema = object
        .get("inputSchema")
        .filter(|schema| schema.is_object())
        .ok_or(McpConfigError::InvalidToolDefinition)?;
    if schema.get("type").and_then(Value::as_str) != Some("object")
        || contains_external_schema_reference(schema)
        || jsonschema::validator_for(schema).is_err()
    {
        return Err(McpConfigError::InvalidToolSchema);
    }
    if let Some(output_schema) = object.get("outputSchema")
        && (!output_schema.is_object()
            || contains_external_schema_reference(output_schema)
            || jsonschema::validator_for(output_schema).is_err())
    {
        return Err(McpConfigError::InvalidToolSchema);
    }
    Ok(InspectedDefinition { name })
}

/// Validates one exact model-proposed argument object against the pinned MCP JSON Schema.
///
/// # Errors
///
/// Returns [`ReadToolError::InvalidArguments`] before any MCP process is launched.
pub fn validate_mcp_tool_arguments(
    grant: &McpToolGrant,
    arguments: &Value,
) -> Result<(), ReadToolError> {
    if !arguments.is_object() {
        return Err(ReadToolError::InvalidArguments(
            "MCP tool arguments must be a JSON object".to_owned(),
        ));
    }
    let serialized = serde_json::to_vec(arguments)
        .map_err(|_| ReadToolError::InvalidArguments("arguments are not JSON".to_owned()))?;
    if serialized.len() > MCP_MAXIMUM_TOOL_ARGUMENT_BYTES {
        return Err(ReadToolError::InvalidArguments(
            "MCP tool arguments exceed the hard byte bound".to_owned(),
        ));
    }
    let validator = jsonschema::validator_for(grant.input_schema()).map_err(|_| {
        ReadToolError::Unavailable("pinned MCP input schema is no longer valid".to_owned())
    })?;
    validator.validate(arguments).map_err(|error| {
        ReadToolError::InvalidArguments(format!("MCP input schema rejected arguments: {error}"))
    })
}

/// Builds the immutable Mealy read-tool descriptor for one exact configured MCP grant.
///
/// # Errors
///
/// Returns a descriptor evidence error when canonical material cannot be represented.
pub fn mcp_read_tool_descriptor(
    server: &McpServerConfig,
    grant: &McpToolGrant,
) -> Result<ReadToolDescriptor, crate::ToolDescriptorEvidenceError> {
    let mut input_schema = grant.input_schema().clone();
    if let Some(object) = input_schema.as_object_mut() {
        object
            .entry("description")
            .or_insert_with(|| Value::String(grant.description().to_owned()));
    }
    let output_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "serverId": {"type": "string"},
            "toolName": {"type": "string"},
            "definitionDigest": {"type": "string"},
            "sourceLocator": {"type": "string"},
            "isError": {"type": "boolean"},
            "content": {"type": "array", "items": {"type": "object"}},
            "structuredContent": {}
        },
        "required": ["serverId", "toolName", "definitionDigest", "sourceLocator", "isError", "content"]
    });
    let schema_digest = sha256_digest(input_schema.to_string().as_bytes());
    let executable_identity_digest = sha256_digest(
        json!({
            "contractVersion": "mealy.mcp-stdio-tool.v1",
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "serverId": server.server_id(),
            "serverExecutableDigest": server.executable_digest(),
            "serverArguments": server.arguments(),
            "serverToolsetDigest": server.toolset_digest(),
            "toolDefinitionDigest": grant.definition_digest(),
        })
        .to_string()
        .as_bytes(),
    );
    let mut descriptor = ReadToolDescriptor {
        tool_id: server.exposed_tool_id(grant.remote_name()),
        version: format!(
            "{}+{}",
            MCP_PROTOCOL_VERSION,
            &executable_identity_digest[..16]
        ),
        input_schema,
        output_schema,
        descriptor_digest: String::new(),
        schema_digest,
        effect_class: "read_only".to_owned(),
        risk_class: "medium".to_owned(),
        required_capability: format!(
            "mcp.invoke:{}:{}:sha256:{executable_identity_digest}",
            server.server_id(),
            grant.remote_name()
        ),
        timeout: Duration::from_millis(grant.timeout_ms()),
        maximum_output_bytes: grant.maximum_output_bytes(),
        conflict_key_template: format!("mcp://{}/{}", server.server_id(), grant.remote_name()),
        recovery: "retry".to_owned(),
    };
    descriptor.descriptor_digest = descriptor.computed_descriptor_digest()?;
    Ok(descriptor)
}

fn contains_external_schema_reference(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            (key == "$ref"
                && value
                    .as_str()
                    .is_none_or(|reference| !reference.starts_with('#')))
                || (key == "$id")
                || contains_external_schema_reference(value)
        }),
        Value::Array(values) => values.iter().any(contains_external_schema_reference),
        _ => false,
    }
}

fn valid_mcp_name(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn invalid_argument(value: &str) -> bool {
    value.len() > MCP_MAXIMUM_ARGUMENT_BYTES
        || value.contains('\0')
        || value.chars().any(char::is_control)
}

fn safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

/// Invalid MCP configuration, discovery, schema, or owner grant evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpConfigError {
    /// Server identity, executable evidence, arguments, ordering, or bounds are invalid.
    #[error("MCP server configuration is invalid")]
    InvalidServer,
    /// Tool grant bounds or definition binding are invalid.
    #[error("MCP tool grant is invalid")]
    InvalidToolGrant,
    /// Advertised tool definition is malformed, oversized, or unsupported.
    #[error("MCP tool definition is invalid")]
    InvalidToolDefinition,
    /// Input/output JSON Schema is invalid or attempts external resolution.
    #[error("MCP tool JSON Schema is invalid or not self-contained")]
    InvalidToolSchema,
    /// Negotiated discovery evidence is invalid or non-canonical.
    #[error("MCP server discovery evidence is invalid")]
    InvalidDiscovery,
}

/// Validates deterministic identity ordering for a complete configured server list.
///
/// # Errors
///
/// Returns [`McpConfigError`] when the set exceeds its bound, is not in canonical unique server
/// identity order, or contains an invalid server/grant.
pub fn validate_mcp_server_set(servers: &[McpServerConfig]) -> Result<(), McpConfigError> {
    if servers.len() > MCP_MAXIMUM_SERVERS
        || !servers
            .windows(2)
            .all(|window| window[0].server_id() < window[1].server_id())
    {
        return Err(McpConfigError::InvalidServer);
    }
    for server in servers {
        server.validate()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        MCP_PROTOCOL_VERSION, McpServerConfig, McpServerDiscovery, McpToolGrant, McpToolInspection,
        mcp_read_tool_descriptor, validate_mcp_tool_arguments,
    };
    use serde_json::json;

    fn definition(name: &str) -> serde_json::Value {
        json!({
            "name": name,
            "description": "Adds two integers without external effects",
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "left": {"type": "integer"},
                    "right": {"type": "integer"}
                },
                "required": ["left", "right"]
            },
            "annotations": {"readOnlyHint": false}
        })
    }

    #[test]
    fn owner_grant_pins_complete_definition_and_builds_descriptor() {
        let grant = McpToolGrant::new(definition("add"), 5_000, 64 * 1024).expect("grant");
        let executable_digest = "a".repeat(64);
        let discovery = McpServerDiscovery {
            protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
            server_info: json!({"name": "fixture", "version": "1"}),
            tools: vec![McpToolInspection {
                definition: grant.definition().clone(),
                definition_digest: grant.definition_digest().to_owned(),
            }],
        };
        let server = McpServerConfig::new(
            "math".to_owned(),
            format!("mcp-servers/{executable_digest}/server"),
            executable_digest,
            Vec::new(),
            discovery.toolset_digest().expect("toolset digest"),
            true,
            vec![grant.clone()],
        )
        .expect("server");
        let descriptor = mcp_read_tool_descriptor(&server, &grant).expect("descriptor");
        descriptor.validate_evidence().expect("evidence");
        assert_eq!(descriptor.tool_id, "mcp.math.add");
        assert!(validate_mcp_tool_arguments(&grant, &json!({"left": 1, "right": 2})).is_ok());
        assert!(validate_mcp_tool_arguments(&grant, &json!({"left": 1})).is_err());
    }

    #[test]
    fn remote_schema_resolution_and_task_required_tools_fail_closed() {
        let mut remote = definition("remote");
        remote["inputSchema"] = json!({"type": "object", "$ref": "https://example.test/x"});
        assert!(McpToolGrant::new(remote, 1_000, 1_024).is_err());

        let mut task = definition("task");
        task["execution"] = json!({"taskSupport": "required"});
        assert!(McpToolGrant::new(task, 1_000, 1_024).is_err());
    }

    #[test]
    fn discovery_requires_unique_canonical_tool_order() {
        let right = McpToolGrant::new(definition("right"), 1_000, 1_024).expect("right");
        let left = McpToolGrant::new(definition("left"), 1_000, 1_024).expect("left");
        let discovery = McpServerDiscovery {
            protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
            server_info: json!({"name": "fixture", "version": "1"}),
            tools: vec![
                McpToolInspection {
                    definition: left.definition().clone(),
                    definition_digest: left.definition_digest().to_owned(),
                },
                McpToolInspection {
                    definition: right.definition().clone(),
                    definition_digest: right.definition_digest().to_owned(),
                },
            ],
        };
        assert_eq!(discovery.validate(), Ok(()));
        let mut reversed = discovery;
        reversed.tools.reverse();
        assert!(reversed.validate().is_err());
    }
}
