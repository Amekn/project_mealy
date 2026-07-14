use mealy_application::{
    CancellationProbe, MCP_MAXIMUM_TOOLS_PER_SERVER, MCP_PROTOCOL_VERSION, McpServerConfig,
    McpServerDiscovery, McpToolGrant, McpToolInspection, ReadOnlyTool, ReadToolDescriptor,
    ReadToolError, ReadToolOutput, mcp_read_tool_descriptor, mcp_tool_definition_digest,
    sha256_digest, validate_mcp_tool_arguments,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use thiserror::Error;

const MCP_LAUNCHER_ARGUMENT: &str = "--mcp-stdio-launcher";
const MCP_SANDBOX_LAUNCHER: &str = "/runtime/mealy-mcp-launcher";
const MCP_SANDBOX_SERVER: &str = "/mcp/server";
const MCP_MAXIMUM_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const MCP_MAXIMUM_MESSAGE_BYTES: usize = 1024 * 1024;
const MCP_MAXIMUM_STDOUT_BYTES: usize = 4 * 1024 * 1024;
const MCP_MAXIMUM_STDERR_BYTES: u64 = 64 * 1024;
const MCP_MAXIMUM_MESSAGES: usize = 256;
const MCP_MAXIMUM_LIST_PAGES: usize = 16;
const MCP_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
const MCP_POLL_INTERVAL: Duration = Duration::from_millis(5);
const MCP_SHUTDOWN_GRACE: Duration = Duration::from_millis(250);

/// Reads the complete tool list from one digest-pinned MCP executable inside the hardened local
/// stdio sandbox. Discovery executes server code, so callers must require explicit owner intent.
///
/// # Errors
///
/// Returns [`McpHostError`] for executable identity changes, unavailable sandbox enforcement,
/// timeout, malformed MCP, unsupported protocol/capabilities, or unbounded output.
pub fn discover_mcp_stdio_server(
    bubblewrap_path: impl AsRef<Path>,
    launcher_path: impl AsRef<Path>,
    server_id: &str,
    executable_path: impl AsRef<Path>,
    executable_digest: &str,
    arguments: &[String],
) -> Result<McpServerDiscovery, McpHostError> {
    let endpoint = McpStdioEndpoint::new(
        bubblewrap_path.as_ref(),
        launcher_path.as_ref(),
        server_id,
        executable_path.as_ref(),
        executable_digest,
        arguments,
    )?;
    endpoint.discover(&NeverCancelled, MCP_DISCOVERY_TIMEOUT)
}

/// Builds and startup-verifies every enabled MCP tool before it can enter a model context epoch.
///
/// Disabled servers are validated by the daemon configuration layer but are never launched. Every
/// enabled server must reproduce the exact protocol/toolset digest and every exact reviewed tool
/// definition, otherwise startup fails closed.
///
/// # Errors
///
/// Returns [`McpHostError`] when installed content, the sandbox, discovery, or a grant pin fails.
pub fn load_mcp_read_tools(
    home: &Path,
    bubblewrap_path: &Path,
    launcher_path: &Path,
    servers: &[McpServerConfig],
) -> Result<Vec<McpReadTool>, McpHostError> {
    let home = fs::canonicalize(home)
        .map_err(|error| McpHostError::Io(format!("cannot canonicalize Mealy home: {error}")))?;
    let mut result = Vec::new();
    for server in servers.iter().filter(|server| server.enabled()) {
        server
            .validate()
            .map_err(|_| McpHostError::InvalidConfiguration)?;
        let requested = home.join(server.executable_path());
        let endpoint = Arc::new(McpStdioEndpoint::new(
            bubblewrap_path,
            launcher_path,
            server.server_id(),
            &requested,
            server.executable_digest(),
            server.arguments(),
        )?);
        let discovery = endpoint.discover(&NeverCancelled, MCP_DISCOVERY_TIMEOUT)?;
        verify_discovery(server, &discovery)?;
        for grant in server.tools() {
            result.push(McpReadTool::new(
                Arc::clone(&endpoint),
                server.clone(),
                grant.clone(),
            )?);
        }
    }
    result.sort_by(|left, right| left.descriptor.tool_id.cmp(&right.descriptor.tool_id));
    if result
        .windows(2)
        .any(|window| window[0].descriptor.tool_id == window[1].descriptor.tool_id)
    {
        return Err(McpHostError::InvalidConfiguration);
    }
    Ok(result)
}

fn verify_discovery(
    server: &McpServerConfig,
    discovery: &McpServerDiscovery,
) -> Result<(), McpHostError> {
    if discovery
        .toolset_digest()
        .map_err(|_| McpHostError::InvalidProtocol)?
        != server.toolset_digest()
    {
        return Err(McpHostError::ToolsetDrift);
    }
    for grant in server.tools() {
        let Some(discovered) = discovery.tool(grant.remote_name()) else {
            return Err(McpHostError::ToolsetDrift);
        };
        if discovered.definition_digest != grant.definition_digest()
            || discovered.definition != *grant.definition()
        {
            return Err(McpHostError::ToolsetDrift);
        }
    }
    Ok(())
}

/// One model-visible, read-only MCP tool backed by a fresh isolated stdio session per call.
pub struct McpReadTool {
    endpoint: Arc<McpStdioEndpoint>,
    server: McpServerConfig,
    grant: McpToolGrant,
    descriptor: ReadToolDescriptor,
}

impl std::fmt::Debug for McpReadTool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpReadTool")
            .field("tool_id", &self.descriptor.tool_id)
            .field("definition_digest", &self.grant.definition_digest())
            .finish_non_exhaustive()
    }
}

impl McpReadTool {
    fn new(
        endpoint: Arc<McpStdioEndpoint>,
        server: McpServerConfig,
        grant: McpToolGrant,
    ) -> Result<Self, McpHostError> {
        let descriptor = mcp_read_tool_descriptor(&server, &grant)
            .map_err(|_| McpHostError::InvalidConfiguration)?;
        descriptor
            .validate_evidence()
            .map_err(|_| McpHostError::InvalidConfiguration)?;
        Ok(Self {
            endpoint,
            server,
            grant,
            descriptor,
        })
    }
}

impl ReadOnlyTool for McpReadTool {
    fn descriptor(&self) -> ReadToolDescriptor {
        self.descriptor.clone()
    }

    fn validate_arguments(&self, arguments: &Value) -> Result<(), ReadToolError> {
        validate_mcp_tool_arguments(&self.grant, arguments)
    }

    fn execute(
        &self,
        arguments: &Value,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ReadToolOutput, ReadToolError> {
        self.validate_arguments(arguments)?;
        let output = self
            .endpoint
            .call(
                &self.server,
                &self.grant,
                arguments,
                cancellation,
                Duration::from_millis(self.grant.timeout_ms()),
            )
            .map_err(|error| map_read_error(error, self.grant.maximum_output_bytes()))?;
        let bytes = serde_json::to_vec(&output).map_err(|_| {
            ReadToolError::Unavailable("MCP result normalization failed".to_owned())
        })?;
        let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if actual > self.grant.maximum_output_bytes() {
            return Err(ReadToolError::OutputTooLarge {
                actual,
                maximum: self.grant.maximum_output_bytes(),
            });
        }
        Ok(ReadToolOutput {
            media_type: "application/json".to_owned(),
            bytes,
            source_locator: format!(
                "mcp://{}/{}",
                self.server.server_id(),
                self.grant.remote_name()
            ),
        })
    }
}

fn map_read_error(error: McpHostError, maximum: u64) -> ReadToolError {
    match error {
        McpHostError::Cancelled => ReadToolError::Cancelled,
        McpHostError::OutputLimitExceeded => ReadToolError::OutputTooLarge {
            actual: maximum.saturating_add(1),
            maximum,
        },
        McpHostError::RemoteToolError(message) => {
            ReadToolError::Unavailable(format!("MCP server rejected the tool call: {message}"))
        }
        McpHostError::TimedOut => ReadToolError::Unavailable("MCP call timed out".to_owned()),
        McpHostError::IdentityMismatch => {
            ReadToolError::Unavailable("MCP executable identity changed".to_owned())
        }
        McpHostError::ToolsetDrift => {
            ReadToolError::Unavailable("MCP advertised tool set changed".to_owned())
        }
        McpHostError::InvalidConfiguration
        | McpHostError::UnsupportedHost(_)
        | McpHostError::Io(_)
        | McpHostError::InvalidProtocol
        | McpHostError::ProcessFailed => {
            ReadToolError::Unavailable("MCP process boundary is unavailable".to_owned())
        }
    }
}

#[derive(Debug)]
struct McpStdioEndpoint {
    bubblewrap_path: PathBuf,
    launcher_path: PathBuf,
    launcher_digest: String,
    executable_path: PathBuf,
    executable_digest: String,
    arguments: Vec<String>,
}

impl McpStdioEndpoint {
    fn new(
        bubblewrap_path: &Path,
        launcher_path: &Path,
        server_id: &str,
        executable_path: &Path,
        executable_digest: &str,
        arguments: &[String],
    ) -> Result<Self, McpHostError> {
        if !cfg!(target_os = "linux") {
            return Err(McpHostError::UnsupportedHost(
                "local MCP stdio isolation currently requires Linux Bubblewrap".to_owned(),
            ));
        }
        if server_id.is_empty()
            || server_id.len() > 32
            || server_id
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'-' | b'.'))
            || !mealy_application::is_sha256_digest(executable_digest)
            || arguments.len() > mealy_application::MCP_MAXIMUM_ARGUMENTS
            || arguments.iter().any(|argument| {
                argument.len() > 4_096
                    || argument.contains('\0')
                    || argument.chars().any(char::is_control)
            })
        {
            return Err(McpHostError::InvalidConfiguration);
        }
        let bubblewrap_path = exact_canonical_file(bubblewrap_path)?;
        if !crate::is_trusted_system_executable(&bubblewrap_path) {
            return Err(McpHostError::UnsupportedHost(
                "Bubblewrap is not installed as a trusted system executable".to_owned(),
            ));
        }
        let launcher_path = exact_canonical_file(launcher_path)?;
        let launcher_digest = digest_executable(&launcher_path)?;
        let executable_path = exact_canonical_file(executable_path)?;
        if digest_executable(&executable_path)? != executable_digest {
            return Err(McpHostError::IdentityMismatch);
        }
        Ok(Self {
            bubblewrap_path,
            launcher_path,
            launcher_digest,
            executable_path,
            executable_digest: executable_digest.to_owned(),
            arguments: arguments.to_vec(),
        })
    }

    fn verify_identity(&self) -> Result<(), McpHostError> {
        if digest_executable(&self.launcher_path)? != self.launcher_digest
            || digest_executable(&self.executable_path)? != self.executable_digest
        {
            return Err(McpHostError::IdentityMismatch);
        }
        Ok(())
    }

    fn discover(
        &self,
        cancellation: &dyn CancellationProbe,
        timeout: Duration,
    ) -> Result<McpServerDiscovery, McpHostError> {
        self.verify_identity()?;
        let mut session = McpSession::spawn(self, cancellation, timeout)?;
        let discovery = session.initialize_and_discover(cancellation)?;
        session.shutdown();
        Ok(discovery)
    }

    fn call(
        &self,
        server: &McpServerConfig,
        grant: &McpToolGrant,
        arguments: &Value,
        cancellation: &dyn CancellationProbe,
        timeout: Duration,
    ) -> Result<Value, McpHostError> {
        self.verify_identity()?;
        let mut session = McpSession::spawn(self, cancellation, timeout)?;
        let discovery = session.initialize_and_discover(cancellation)?;
        verify_discovery(server, &discovery)?;
        let result = session.request(
            10_000,
            "tools/call",
            &json!({"name": grant.remote_name(), "arguments": arguments}),
            cancellation,
            true,
        )?;
        let normalized = normalize_tool_result(&result, server, grant)?;
        session.shutdown();
        Ok(normalized)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.bubblewrap_path);
        command.env_clear().args([
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--cap-drop",
            "ALL",
            "--hostname",
            "mealy-mcp",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/runtime",
            "--dir",
            "/mcp",
        ]);
        for (source, target) in runtime_directory_mounts() {
            command.arg("--ro-bind").arg(source).arg(target);
        }
        command
            .arg("--ro-bind")
            .arg(&self.launcher_path)
            .arg(MCP_SANDBOX_LAUNCHER)
            .arg("--ro-bind")
            .arg(&self.executable_path)
            .arg(MCP_SANDBOX_SERVER)
            .arg("--chdir")
            .arg("/tmp")
            .arg("--")
            .arg(MCP_SANDBOX_LAUNCHER)
            .arg(MCP_LAUNCHER_ARGUMENT)
            .args(&self.arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

fn runtime_directory_mounts() -> Vec<(PathBuf, PathBuf)> {
    ["/usr/lib", "/usr/lib64", "/lib", "/lib64"]
        .into_iter()
        .filter_map(|target| {
            let requested = Path::new(target);
            requested
                .exists()
                .then(|| fs::canonicalize(requested).ok())
                .flatten()
                .map(|source| (source, PathBuf::from(target)))
        })
        .collect()
}

struct McpSession {
    child: Child,
    input: Option<ChildStdin>,
    output: mpsc::Receiver<ReaderEvent>,
    output_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<()>>,
    stderr_exceeded: Arc<AtomicBool>,
    stderr_failed: Arc<AtomicBool>,
    started: Instant,
    timeout: Duration,
    messages: usize,
}

impl McpSession {
    fn spawn(
        endpoint: &McpStdioEndpoint,
        cancellation: &dyn CancellationProbe,
        timeout: Duration,
    ) -> Result<Self, McpHostError> {
        if timeout.is_zero() || timeout > Duration::from_mins(1) {
            return Err(McpHostError::InvalidConfiguration);
        }
        if cancellation.is_cancelled() {
            return Err(McpHostError::Cancelled);
        }
        let started = Instant::now();
        let mut child = endpoint
            .command()
            .spawn()
            .map_err(|error| McpHostError::Io(format!("MCP sandbox spawn failed: {error}")))?;
        let (Some(input), Some(output), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            terminate_child(&mut child);
            return Err(McpHostError::Io("MCP process pipe is absent".to_owned()));
        };
        // The protocol reader has a hard aggregate byte bound, so an unbounded channel is still
        // memory-bounded. More importantly, it cannot deadlock process teardown if a hostile
        // server fills a small synchronous queue while the request path is already failing.
        let (sender, receiver) = mpsc::channel();
        let output_thread = match thread::Builder::new()
            .name("mealy-mcp-stdout".to_owned())
            .spawn(move || capture_protocol_lines(output, &sender))
        {
            Ok(handle) => handle,
            Err(error) => {
                terminate_child(&mut child);
                return Err(McpHostError::Io(format!(
                    "MCP stdout reader failed: {error}"
                )));
            }
        };
        let stderr_exceeded = Arc::new(AtomicBool::new(false));
        let stderr_failed = Arc::new(AtomicBool::new(false));
        let thread_exceeded = Arc::clone(&stderr_exceeded);
        let thread_failed = Arc::clone(&stderr_failed);
        let stderr_thread = match thread::Builder::new()
            .name("mealy-mcp-stderr".to_owned())
            .spawn(move || {
                let mut bytes = Vec::new();
                let result = stderr
                    .take(MCP_MAXIMUM_STDERR_BYTES.saturating_add(1))
                    .read_to_end(&mut bytes);
                if result.is_err() {
                    thread_failed.store(true, Ordering::Release);
                }
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MCP_MAXIMUM_STDERR_BYTES {
                    thread_exceeded.store(true, Ordering::Release);
                }
            }) {
            Ok(handle) => handle,
            Err(error) => {
                terminate_child(&mut child);
                drop(receiver);
                let _ = output_thread.join();
                return Err(McpHostError::Io(format!(
                    "MCP stderr reader failed: {error}"
                )));
            }
        };
        Ok(Self {
            child,
            input: Some(input),
            output: receiver,
            output_thread: Some(output_thread),
            stderr_thread: Some(stderr_thread),
            stderr_exceeded,
            stderr_failed,
            started,
            timeout,
            messages: 0,
        })
    }

    fn initialize_and_discover(
        &mut self,
        cancellation: &dyn CancellationProbe,
    ) -> Result<McpServerDiscovery, McpHostError> {
        let initialized = self.request(
            1,
            "initialize",
            &json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "mealy",
                    "title": "Mealy governed MCP client",
                    "version": env!("CARGO_PKG_VERSION"),
                    "description": "Schema-pinned read-only local stdio MCP boundary"
                }
            }),
            cancellation,
            false,
        )?;
        let protocol_version = initialized
            .get("protocolVersion")
            .and_then(Value::as_str)
            .filter(|version| *version == MCP_PROTOCOL_VERSION)
            .ok_or(McpHostError::InvalidProtocol)?
            .to_owned();
        if !initialized
            .get("capabilities")
            .and_then(|capabilities| capabilities.get("tools"))
            .is_some_and(Value::is_object)
        {
            return Err(McpHostError::InvalidProtocol);
        }
        let server_info = initialized
            .get("serverInfo")
            .filter(|value| value.is_object())
            .cloned()
            .ok_or(McpHostError::InvalidProtocol)?;
        self.notify("notifications/initialized", None)?;

        let mut cursor = None;
        let mut seen_cursors = BTreeSet::new();
        let mut tools = Vec::new();
        for page in 0..MCP_MAXIMUM_LIST_PAGES {
            let id = u64::try_from(page).unwrap_or(u64::MAX).saturating_add(2);
            let params = cursor
                .as_ref()
                .map_or_else(|| json!({}), |value| json!({"cursor": value}));
            let listed = self.request(id, "tools/list", &params, cancellation, true)?;
            let page_tools = listed
                .get("tools")
                .and_then(Value::as_array)
                .ok_or(McpHostError::InvalidProtocol)?;
            if tools.len().saturating_add(page_tools.len()) > MCP_MAXIMUM_TOOLS_PER_SERVER {
                return Err(McpHostError::OutputLimitExceeded);
            }
            for definition in page_tools {
                tools.push(McpToolInspection {
                    definition: definition.clone(),
                    definition_digest: mcp_tool_definition_digest(definition)
                        .map_err(|_| McpHostError::InvalidProtocol)?,
                });
            }
            cursor = listed
                .get("nextCursor")
                .map(|value| {
                    value
                        .as_str()
                        .filter(|cursor| {
                            !cursor.is_empty()
                                && cursor.len() <= 1_024
                                && !cursor.chars().any(char::is_control)
                        })
                        .map(str::to_owned)
                        .ok_or(McpHostError::InvalidProtocol)
                })
                .transpose()?;
            let Some(next) = &cursor else {
                break;
            };
            if !seen_cursors.insert(next.clone()) || page + 1 == MCP_MAXIMUM_LIST_PAGES {
                return Err(McpHostError::InvalidProtocol);
            }
        }
        tools.sort_by(|left, right| {
            left.definition["name"]
                .as_str()
                .cmp(&right.definition["name"].as_str())
        });
        let discovery = McpServerDiscovery {
            protocol_version,
            server_info,
            tools,
        };
        discovery
            .validate()
            .map_err(|_| McpHostError::InvalidProtocol)?;
        Ok(discovery)
    }

    fn request(
        &mut self,
        id: u64,
        method: &str,
        params: &Value,
        cancellation: &dyn CancellationProbe,
        cancellable: bool,
    ) -> Result<Value, McpHostError> {
        self.write_message(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))?;
        self.wait_for_response(id, cancellation, cancellable)
    }

    fn notify(&mut self, method: &str, params: Option<Value>) -> Result<(), McpHostError> {
        let mut message = serde_json::Map::from_iter([
            ("jsonrpc".to_owned(), Value::String("2.0".to_owned())),
            ("method".to_owned(), Value::String(method.to_owned())),
        ]);
        if let Some(params) = params {
            message.insert("params".to_owned(), params);
        }
        self.write_message(&Value::Object(message))
    }

    fn write_message(&mut self, message: &Value) -> Result<(), McpHostError> {
        let mut bytes = serde_json::to_vec(message).map_err(|_| McpHostError::InvalidProtocol)?;
        if bytes.len() > MCP_MAXIMUM_MESSAGE_BYTES {
            return Err(McpHostError::OutputLimitExceeded);
        }
        bytes.push(b'\n');
        let input = self.input.as_mut().ok_or(McpHostError::ProcessFailed)?;
        input
            .write_all(&bytes)
            .and_then(|()| input.flush())
            .map_err(|_| McpHostError::ProcessFailed)
    }

    fn wait_for_response(
        &mut self,
        expected_id: u64,
        cancellation: &dyn CancellationProbe,
        cancellable: bool,
    ) -> Result<Value, McpHostError> {
        loop {
            if cancellation.is_cancelled() {
                if cancellable {
                    let _ = self.notify(
                        "notifications/cancelled",
                        Some(json!({"requestId": expected_id, "reason": "Mealy run cancelled"})),
                    );
                }
                return Err(McpHostError::Cancelled);
            }
            if self.started.elapsed() >= self.timeout {
                if cancellable {
                    let _ = self.notify(
                        "notifications/cancelled",
                        Some(json!({"requestId": expected_id, "reason": "Mealy deadline elapsed"})),
                    );
                }
                return Err(McpHostError::TimedOut);
            }
            if self.stderr_exceeded.load(Ordering::Acquire) {
                return Err(McpHostError::OutputLimitExceeded);
            }
            if self.stderr_failed.load(Ordering::Acquire) {
                return Err(McpHostError::ProcessFailed);
            }
            match self.output.recv_timeout(MCP_POLL_INTERVAL) {
                Ok(ReaderEvent::Line(bytes)) => {
                    self.messages = self.messages.saturating_add(1);
                    if self.messages > MCP_MAXIMUM_MESSAGES {
                        return Err(McpHostError::OutputLimitExceeded);
                    }
                    let message = serde_json::from_slice::<Value>(&bytes)
                        .map_err(|_| McpHostError::InvalidProtocol)?;
                    let object = message.as_object().ok_or(McpHostError::InvalidProtocol)?;
                    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
                        return Err(McpHostError::InvalidProtocol);
                    }
                    if let Some(id) = object.get("id") {
                        if object.get("method").is_some() {
                            self.answer_server_request(object, id)?;
                            continue;
                        }
                        if id.as_u64() != Some(expected_id)
                            || object.get("result").is_some() == object.get("error").is_some()
                        {
                            return Err(McpHostError::InvalidProtocol);
                        }
                        if let Some(result) = object.get("result") {
                            return Ok(result.clone());
                        }
                        return Err(remote_error(object.get("error"))?);
                    }
                    let method = object
                        .get("method")
                        .and_then(Value::as_str)
                        .ok_or(McpHostError::InvalidProtocol)?;
                    if method == "notifications/tools/list_changed" {
                        return Err(McpHostError::ToolsetDrift);
                    }
                    if !matches!(
                        method,
                        "notifications/message"
                            | "notifications/progress"
                            | "notifications/cancelled"
                    ) {
                        return Err(McpHostError::InvalidProtocol);
                    }
                }
                Ok(ReaderEvent::Limit) => return Err(McpHostError::OutputLimitExceeded),
                Ok(ReaderEvent::Malformed | ReaderEvent::Eof)
                | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(McpHostError::ProcessFailed);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if self
                        .child
                        .try_wait()
                        .map_err(|error| McpHostError::Io(format!("MCP wait failed: {error}")))?
                        .is_some()
                    {
                        return Err(McpHostError::ProcessFailed);
                    }
                }
            }
        }
    }

    fn answer_server_request(
        &mut self,
        object: &serde_json::Map<String, Value>,
        id: &Value,
    ) -> Result<(), McpHostError> {
        let method = object
            .get("method")
            .and_then(Value::as_str)
            .ok_or(McpHostError::InvalidProtocol)?;
        if method == "ping" {
            self.write_message(&json!({"jsonrpc": "2.0", "id": id, "result": {}}))
        } else {
            self.write_message(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": "Client capability not negotiated"}
            }))
        }
    }

    fn shutdown(&mut self) {
        self.input.take();
        let started = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if started.elapsed() < MCP_SHUTDOWN_GRACE => {
                    thread::sleep(MCP_POLL_INTERVAL);
                }
                Ok(None) | Err(_) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
        if let Some(handle) = self.output_thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.stderr_thread.take() {
            let _ = handle.join();
        }
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

impl Drop for McpSession {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn remote_error(value: Option<&Value>) -> Result<McpHostError, McpHostError> {
    let object = value
        .and_then(Value::as_object)
        .ok_or(McpHostError::InvalidProtocol)?;
    let code = object
        .get("code")
        .and_then(Value::as_i64)
        .ok_or(McpHostError::InvalidProtocol)?;
    let message = object
        .get("message")
        .and_then(Value::as_str)
        .filter(|message| message.len() <= 4_096 && !message.chars().any(char::is_control))
        .ok_or(McpHostError::InvalidProtocol)?;
    Ok(McpHostError::RemoteToolError(format!(
        "JSON-RPC {code}: {message}"
    )))
}

fn normalize_tool_result(
    result: &Value,
    server: &McpServerConfig,
    grant: &McpToolGrant,
) -> Result<Value, McpHostError> {
    let object = result.as_object().ok_or(McpHostError::InvalidProtocol)?;
    let content = object
        .get("content")
        .and_then(Value::as_array)
        .ok_or(McpHostError::InvalidProtocol)?;
    if content.len() > 128 || !content.iter().all(valid_content_item) {
        return Err(McpHostError::InvalidProtocol);
    }
    let is_error = match object.get("isError") {
        None => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(McpHostError::InvalidProtocol),
    };
    let structured = object.get("structuredContent").cloned();
    if structured.as_ref().is_some_and(|value| !value.is_object()) {
        return Err(McpHostError::InvalidProtocol);
    }
    if let Some(output_schema) = grant.definition().get("outputSchema") {
        let Some(structured) = structured.as_ref() else {
            return Err(McpHostError::InvalidProtocol);
        };
        if !is_error
            && jsonschema::validator_for(output_schema)
                .map_err(|_| McpHostError::InvalidProtocol)?
                .validate(structured)
                .is_err()
        {
            return Err(McpHostError::InvalidProtocol);
        }
    }
    let mut normalized = json!({
        "serverId": server.server_id(),
        "toolName": grant.remote_name(),
        "definitionDigest": grant.definition_digest(),
        "sourceLocator": format!("mcp://{}/{}", server.server_id(), grant.remote_name()),
        "isError": is_error,
        "content": content,
    });
    if let Some(structured) = structured {
        normalized["structuredContent"] = structured;
    }
    Ok(normalized)
}

fn valid_content_item(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let Some(kind) = object.get("type").and_then(Value::as_str) else {
        return false;
    };
    match kind {
        "text" => object.get("text").is_some_and(Value::is_string),
        "image" | "audio" => {
            object.get("data").is_some_and(Value::is_string)
                && object.get("mimeType").is_some_and(Value::is_string)
        }
        "resource_link" => {
            object.get("uri").is_some_and(Value::is_string)
                && object.get("name").is_some_and(Value::is_string)
        }
        "resource" => object.get("resource").is_some_and(Value::is_object),
        _ => false,
    }
}

enum ReaderEvent {
    Line(Vec<u8>),
    Limit,
    Malformed,
    Eof,
}

fn capture_protocol_lines(output: impl Read, sender: &mpsc::Sender<ReaderEvent>) {
    let mut reader = BufReader::new(output);
    let mut total = 0_usize;
    loop {
        match read_bounded_line(&mut reader, MCP_MAXIMUM_MESSAGE_BYTES) {
            Ok(Some(line)) => {
                total = total.saturating_add(line.len().saturating_add(1));
                if total > MCP_MAXIMUM_STDOUT_BYTES {
                    let _ = sender.send(ReaderEvent::Limit);
                    return;
                }
                if sender.send(ReaderEvent::Line(line)).is_err() {
                    return;
                }
            }
            Ok(None) => {
                let _ = sender.send(ReaderEvent::Eof);
                return;
            }
            Err(LineError::Limit) => {
                let _ = sender.send(ReaderEvent::Limit);
                return;
            }
            Err(LineError::Malformed) => {
                let _ = sender.send(ReaderEvent::Malformed);
                return;
            }
        }
    }
}

#[derive(Debug)]
enum LineError {
    Limit,
    Malformed,
}

fn read_bounded_line(
    reader: &mut impl BufRead,
    maximum: usize,
) -> Result<Option<Vec<u8>>, LineError> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(|_| LineError::Malformed)?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(LineError::Malformed)
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |position| position + 1);
        if line.len().saturating_add(consumed) > maximum.saturating_add(1) {
            return Err(LineError::Limit);
        }
        if let Some(position) = newline {
            line.extend_from_slice(&available[..position]);
            reader.consume(consumed);
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.is_empty() || line.len() > maximum {
                return Err(LineError::Malformed);
            }
            return Ok(Some(line));
        }
        line.extend_from_slice(available);
        reader.consume(consumed);
    }
}

fn exact_canonical_file(path: &Path) -> Result<PathBuf, McpHostError> {
    if !path.is_absolute() {
        return Err(McpHostError::InvalidConfiguration);
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| McpHostError::Io(format!("cannot inspect executable: {error}")))?;
    let canonical = fs::canonicalize(path)
        .map_err(|error| McpHostError::Io(format!("cannot canonicalize executable: {error}")))?;
    if canonical != path || metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(McpHostError::InvalidConfiguration);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(McpHostError::InvalidConfiguration);
        }
    }
    Ok(canonical)
}

fn digest_executable(path: &Path) -> Result<String, McpHostError> {
    let file = File::open(path)
        .map_err(|error| McpHostError::Io(format!("cannot open executable: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| McpHostError::Io(format!("cannot inspect executable: {error}")))?;
    if metadata.len() < 4 || metadata.len() > MCP_MAXIMUM_EXECUTABLE_BYTES {
        return Err(McpHostError::InvalidConfiguration);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(MCP_MAXIMUM_EXECUTABLE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| McpHostError::Io(format!("cannot hash executable: {error}")))?;
    if bytes.len() < 4 || &bytes[..4] != b"\x7fELF" {
        return Err(McpHostError::InvalidConfiguration);
    }
    Ok(sha256_digest(&bytes))
}

struct NeverCancelled;

impl CancellationProbe for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// Enters the no-shell MCP target launcher after Bubblewrap has created the isolated namespace.
///
/// Applications embedding this helper must dispatch it before normal CLI parsing whenever their
/// first argument is `--mcp-stdio-launcher`. The function never returns on success because it
/// replaces the launcher process with the fixed `/mcp/server` executable.
#[cfg(target_os = "linux")]
#[must_use]
pub fn mcp_stdio_launcher_main() -> std::process::ExitCode {
    use rustix::process::{Resource, Rlimit, setrlimit};
    use std::os::unix::process::CommandExt as _;

    if std::env::args().nth(1).as_deref() != Some(MCP_LAUNCHER_ARGUMENT) {
        return std::process::ExitCode::from(64);
    }
    let limits = [
        (Resource::Core, 0),
        (Resource::Fsize, 16 * 1024 * 1024),
        (Resource::Nofile, 64),
        (Resource::Nproc, 1),
        (Resource::As, 512 * 1024 * 1024),
        (Resource::Cpu, 65),
    ];
    for (resource, maximum) in limits {
        if setrlimit(
            resource,
            Rlimit {
                current: Some(maximum),
                maximum: Some(maximum),
            },
        )
        .is_err()
        {
            return std::process::ExitCode::from(70);
        }
    }
    let error = Command::new(MCP_SANDBOX_SERVER)
        .args(std::env::args_os().skip(2))
        .env_clear()
        .current_dir("/tmp")
        .exec();
    drop(error);
    std::process::ExitCode::from(70)
}

/// Reports unsupported launcher use on non-Linux systems without executing untrusted code.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn mcp_stdio_launcher_main() -> std::process::ExitCode {
    std::process::ExitCode::from(69)
}

/// Failure at the governed local stdio MCP process boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum McpHostError {
    /// Non-secret server configuration is malformed or non-canonical.
    #[error("MCP server configuration is invalid")]
    InvalidConfiguration,
    /// Host cannot enforce the requested isolation boundary.
    #[error("MCP stdio host is unsupported: {0}")]
    UnsupportedHost(String),
    /// Exact launcher or MCP executable bytes changed.
    #[error("MCP executable identity changed")]
    IdentityMismatch,
    /// Initialization, JSON-RPC, pagination, capability, schema, or result framing is invalid.
    #[error("MCP protocol response is invalid")]
    InvalidProtocol,
    /// Complete advertised tool-set evidence no longer matches owner review.
    #[error("MCP advertised tool set changed")]
    ToolsetDrift,
    /// Request exceeded its hard wall-clock limit.
    #[error("MCP request timed out")]
    TimedOut,
    /// Durable caller cancellation was observed and propagated.
    #[error("MCP request was cancelled")]
    Cancelled,
    /// Stdout, stderr, message count, or normalized result exceeded a hard bound.
    #[error("MCP process output exceeded its bound")]
    OutputLimitExceeded,
    /// Server returned a bounded JSON-RPC tool error.
    #[error("MCP server error: {0}")]
    RemoteToolError(String),
    /// Sandboxed process exited, closed a protocol pipe, or could not be terminated cleanly.
    #[error("MCP server process failed")]
    ProcessFailed,
    /// Trusted host-side process operation failed.
    #[error("MCP host I/O failed: {0}")]
    Io(String),
}

#[cfg(test)]
mod tests {
    use super::{LineError, read_bounded_line};
    use std::io::Cursor;

    #[test]
    fn bounded_line_reader_requires_complete_nonempty_frames() {
        let mut valid = Cursor::new(b"{\"jsonrpc\":\"2.0\"}\n".as_slice());
        assert_eq!(
            read_bounded_line(&mut valid, 64).expect("line"),
            Some(b"{\"jsonrpc\":\"2.0\"}".to_vec())
        );
        let mut missing_newline = Cursor::new(b"{}".as_slice());
        assert!(matches!(
            read_bounded_line(&mut missing_newline, 64),
            Err(LineError::Malformed)
        ));
        let mut oversized = Cursor::new(b"12345\n".as_slice());
        assert!(matches!(
            read_bounded_line(&mut oversized, 4),
            Err(LineError::Limit | LineError::Malformed)
        ));
    }
}
