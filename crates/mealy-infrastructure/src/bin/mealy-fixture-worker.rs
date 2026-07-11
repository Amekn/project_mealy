//! Trusted structured fixture worker used by the Linux one-shot sandbox proof.

use mealy_application::{
    EXECUTOR_PROTOCOL_VERSION, EXTENSION_RPC_VERSION, ExecutorFrame, ExecutorRequest,
    ExecutorTerminal, ExtensionRpcRequest, ExtensionRpcResponse, sha256_digest,
};
use serde_json::{Value, json};
use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Component, Path, PathBuf},
    process::ExitCode,
    str::FromStr,
    thread,
    time::Duration,
};

#[cfg(target_os = "linux")]
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

const MAXIMUM_REQUEST_BYTES: u64 = 64 * 1024;
const MAXIMUM_FIXTURE_CONTENT_BYTES: usize = 1024 * 1024;
const SANDBOX_WORKER_PATH: &str = "/runtime/mealy-fixture-worker";
const ENVIRONMENT_BOOTSTRAP_ARGUMENT: &str = "--bootstrap-empty-environment";
const PROTOCOL_WORKER_ARGUMENT: &str = "--protocol-worker";

/// Runs the one-shot worker entrypoint, including the empty-environment re-exec bootstrap.
#[must_use]
pub fn main() -> ExitCode {
    let mode = std::env::args_os().nth(1);
    if mode.as_deref() == Some(OsStr::new(ENVIRONMENT_BOOTSTRAP_ARGUMENT)) {
        return replace_with_empty_environment();
    }
    if mode.as_deref() != Some(OsStr::new(PROTOCOL_WORKER_ARGUMENT)) {
        let _ = writeln!(io::stderr().lock(), "fixture worker mode is invalid");
        return ExitCode::from(64);
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(
                io::stderr().lock(),
                "fixture worker rejected input: {error}"
            );
            ExitCode::from(64)
        }
    }
}

#[cfg(target_os = "linux")]
fn replace_with_empty_environment() -> ExitCode {
    use std::{os::unix::process::CommandExt, process::Command};

    let error = Command::new(SANDBOX_WORKER_PATH)
        .arg(PROTOCOL_WORKER_ARGUMENT)
        .env_clear()
        .exec();
    let _ = writeln!(
        io::stderr().lock(),
        "fixture worker environment bootstrap failed: {error}"
    );
    ExitCode::from(71)
}

#[cfg(not(target_os = "linux"))]
fn replace_with_empty_environment() -> ExitCode {
    let _ = writeln!(
        io::stderr().lock(),
        "fixture worker environment bootstrap requires Linux"
    );
    ExitCode::from(71)
}

fn run() -> Result<(), String> {
    let request = read_request()?;
    request.validate().map_err(|error| error.to_string())?;
    apply_resource_limits(&request)?;
    let mut stdout = io::stdout().lock();
    write_frame(
        &mut stdout,
        &ExecutorFrame::Started {
            protocol_version: EXECUTOR_PROTOCOL_VERSION.to_owned(),
            sequence: 0,
            effect_id: request.effect_id,
            attempt_id: request.attempt_id,
            fencing_token: request.fencing_token,
            capability_token_digest: request.capability_token_digest(),
            executable_identity_digest: request.executable_identity_digest.clone(),
            request_evidence_digest: request
                .evidence_digest()
                .map_err(|error| error.to_string())?,
        },
    )?;

    let operation = request
        .normalized_arguments
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| "operation must be a string".to_owned())?;
    match operation {
        "write_file" => write_file(&request, &mut stdout),
        "extension_rpc" => extension_rpc(&request, &mut stdout),
        "probe_isolation" => probe_isolation(&mut stdout),
        "probe_resource_limits" => probe_resource_limits(&mut stdout),
        "sleep" => sleep_then_succeed(&request, &mut stdout),
        "malformed_frame" => stdout
            .write_all(b"{this-is-not-json}\n")
            .and_then(|()| stdout.flush())
            .map_err(|error| error.to_string()),
        "oversized_frame" => oversized_frame(&request, &mut stdout),
        "crash" => std::process::exit(70),
        _ => terminal_failure(
            &mut stdout,
            "unsupported_operation",
            "fixture worker does not implement the requested operation",
        ),
    }
}

fn extension_rpc(request: &ExecutorRequest, stdout: &mut impl Write) -> Result<(), String> {
    let nested = request
        .normalized_arguments
        .get("request")
        .cloned()
        .ok_or_else(|| "extension request is absent".to_owned())?;
    let rpc = serde_json::from_value::<ExtensionRpcRequest>(nested)
        .map_err(|_| "extension request is malformed".to_owned())?;
    let input_digest = sha256_digest(
        &serde_json::to_vec(&rpc.input).map_err(|_| "extension input is invalid".to_owned())?,
    );
    if rpc.protocol_version != EXTENSION_RPC_VERSION || rpc.input_digest != input_digest {
        return terminal_failure(
            stdout,
            "invalid_extension_request",
            "extension RPC protocol or input digest is invalid",
        );
    }
    let forge_response = rpc.capability_id == "forge_response";
    let output = match rpc.capability_id.as_str() {
        "health" => json!({"status": "ok"}),
        "text_stats" => {
            let Some(text) = rpc.input.get("text").and_then(Value::as_str) else {
                return terminal_failure(
                    stdout,
                    "invalid_input",
                    "text_stats requires a text string",
                );
            };
            json!({
                "byteCount": text.len(),
                "wordCount": text.split_whitespace().count(),
                "sha256": sha256_digest(text.as_bytes()),
            })
        }
        "security_probe" => json!({
            "ambientEnvironmentCount": std::env::vars_os().count(),
            "hostSecretVisible": fs::read("/host-secret-canary").is_ok(),
            "outsideGrantWritable": OpenOptions::new()
                .create_new(true)
                .write(true)
                .open("/host-private-canary/outside-grant")
                .is_ok(),
            "daemonLoopbackReachable": TcpStream::connect_timeout(
                &SocketAddr::from_str("127.0.0.1:1").map_err(|error| error.to_string())?,
                Duration::from_millis(20),
            )
            .is_ok(),
        }),
        "forge_response" => json!({"status": "forged"}),
        "crash" => std::process::exit(70),
        _ => {
            return terminal_failure(
                stdout,
                "unknown_capability",
                "sample extension does not implement the requested capability",
            );
        }
    };
    let response = ExtensionRpcResponse {
        protocol_version: EXTENSION_RPC_VERSION.to_owned(),
        invocation_id: rpc.invocation_id,
        extension_id: rpc.extension_id,
        manifest_digest: rpc.manifest_digest,
        grant_digest: if forge_response {
            "f".repeat(64)
        } else {
            rpc.grant_digest
        },
        capability_id: rpc.capability_id,
        output_digest: sha256_digest(
            &serde_json::to_vec(&output).map_err(|_| "extension output is invalid".to_owned())?,
        ),
        output,
    };
    terminal_success(
        stdout,
        serde_json::to_value(response).map_err(|_| "extension response is invalid".to_owned())?,
    )
}

#[cfg(target_os = "linux")]
fn apply_resource_limits(request: &ExecutorRequest) -> Result<(), String> {
    let address_space = Rlimit {
        current: Some(request.maximum_memory_bytes),
        maximum: Some(request.maximum_memory_bytes),
    };
    setrlimit(Resource::As, address_space)
        .map_err(|error| format!("could not enforce worker memory limit: {error}"))?;
    let total_processes = u64::from(request.maximum_processes).saturating_add(1);
    let process_count = Rlimit {
        current: Some(total_processes),
        maximum: Some(total_processes),
    };
    setrlimit(Resource::Nproc, process_count)
        .map_err(|error| format!("could not enforce worker process limit: {error}"))
}

#[cfg(not(target_os = "linux"))]
fn apply_resource_limits(_request: &ExecutorRequest) -> Result<(), String> {
    Err("fixture worker resource enforcement is supported only on Linux".to_owned())
}

fn read_request() -> Result<ExecutorRequest, String> {
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(MAXIMUM_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAXIMUM_REQUEST_BYTES {
        return Err("request frame is empty or oversized".to_owned());
    }
    serde_json::from_slice(&bytes).map_err(|_| "request frame is malformed".to_owned())
}

fn write_file(request: &ExecutorRequest, stdout: &mut impl Write) -> Result<(), String> {
    let Some(root) = request.writable_roots.first() else {
        return terminal_failure(
            stdout,
            "workspace_not_writable",
            "request has no writable sandbox root",
        );
    };
    let relative = request
        .normalized_arguments
        .get("relativePath")
        .and_then(Value::as_str)
        .ok_or_else(|| "relativePath must be a string".to_owned())?;
    let content = request
        .normalized_arguments
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| "content must be a string".to_owned())?;
    if content.len() > MAXIMUM_FIXTURE_CONTENT_BYTES {
        return terminal_failure(
            stdout,
            "content_too_large",
            "fixture content exceeds its worker bound",
        );
    }
    let root_path = Path::new(&root.sandbox_path);
    let Ok(target) = secure_new_file_path(root_path, relative) else {
        return terminal_failure(
            stdout,
            "path_denied",
            "target path is non-canonical or crosses a symlink",
        );
    };
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let Ok(mut file) = options.open(&target) else {
        return terminal_failure(
            stdout,
            "path_denied",
            "target is not a new regular file beneath the writable root",
        );
    };
    file.write_all(content.as_bytes())
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    terminal_success(
        stdout,
        json!({
            "relativePath": relative,
            "bytesWritten": content.len(),
            "contentDigest": sha256_digest(content.as_bytes()),
        }),
    )
}

fn secure_new_file_path(root: &Path, relative: &str) -> Result<PathBuf, ()> {
    let path = Path::new(relative);
    if relative.is_empty()
        || relative.len() > 1_024
        || path.is_absolute()
        || relative.contains("//")
        || relative.ends_with('/')
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(());
    }
    let mut candidate = root.to_path_buf();
    let components = path.components().collect::<Vec<_>>();
    for component in &components[..components.len().saturating_sub(1)] {
        let Component::Normal(segment) = component else {
            return Err(());
        };
        candidate.push(segment);
        let metadata = fs::symlink_metadata(&candidate).map_err(|_| ())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(());
        }
    }
    candidate.push(
        components
            .last()
            .and_then(|component| match component {
                Component::Normal(segment) => Some(segment),
                _ => None,
            })
            .ok_or(())?,
    );
    if fs::symlink_metadata(&candidate).is_ok() {
        return Err(());
    }
    Ok(candidate)
}

fn probe_isolation(stdout: &mut impl Write) -> Result<(), String> {
    let environment_names = std::env::vars_os()
        .map(|(name, _)| name.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let ambient_path_readable = fs::File::open("/etc/passwd").is_ok();
    let destination = SocketAddr::from_str("1.1.1.1:53").map_err(|error| error.to_string())?;
    let network_denied =
        TcpStream::connect_timeout(&destination, Duration::from_millis(150)).is_err();
    terminal_success(
        stdout,
        json!({
            "environmentNames": environment_names,
            "ambientPathReadable": ambient_path_readable,
            "networkDenied": network_denied,
        }),
    )
}

#[cfg(target_os = "linux")]
fn probe_resource_limits(stdout: &mut impl Write) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let memory = getrlimit(Resource::As);
    let processes = getrlimit(Resource::Nproc);
    let process_spawn_denied = match Command::new("/runtime/mealy-fixture-worker")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            let _ = child.wait();
            false
        }
        Err(_) => true,
    };
    terminal_success(
        stdout,
        json!({
            "memoryCurrent": memory.current,
            "memoryMaximum": memory.maximum,
            "processCurrent": processes.current,
            "processMaximum": processes.maximum,
            "processSpawnDenied": process_spawn_denied,
        }),
    )
}

#[cfg(not(target_os = "linux"))]
fn probe_resource_limits(stdout: &mut impl Write) -> Result<(), String> {
    terminal_failure(
        stdout,
        "unsupported_host",
        "resource-limit probe is supported only on Linux",
    )
}

fn sleep_then_succeed(request: &ExecutorRequest, stdout: &mut impl Write) -> Result<(), String> {
    let duration_ms = request
        .normalized_arguments
        .get("durationMs")
        .and_then(Value::as_u64)
        .ok_or_else(|| "durationMs must be a nonnegative integer".to_owned())?
        .min(60_000);
    thread::sleep(Duration::from_millis(duration_ms));
    terminal_success(stdout, json!({"sleptMs": duration_ms}))
}

fn oversized_frame(request: &ExecutorRequest, stdout: &mut impl Write) -> Result<(), String> {
    let bytes = request
        .normalized_arguments
        .get("bytes")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(128 * 1024)
        .min(2 * 1024 * 1024);
    write_frame(
        stdout,
        &ExecutorFrame::Progress {
            sequence: 1,
            message: "x".repeat(bytes),
        },
    )
}

fn terminal_success(stdout: &mut impl Write, output: Value) -> Result<(), String> {
    let output_digest = sha256_digest(output.to_string().as_bytes());
    write_frame(
        stdout,
        &ExecutorFrame::Terminal {
            sequence: 1,
            outcome: ExecutorTerminal::Succeeded {
                output,
                output_digest,
            },
        },
    )
}

fn terminal_failure(
    stdout: &mut impl Write,
    error_class: &str,
    error_message: &str,
) -> Result<(), String> {
    write_frame(
        stdout,
        &ExecutorFrame::Terminal {
            sequence: 1,
            outcome: ExecutorTerminal::Failed {
                error_class: error_class.to_owned(),
                error_message: error_message.to_owned(),
                retryable: false,
            },
        },
    )
}

fn write_frame(stdout: &mut impl Write, frame: &ExecutorFrame) -> Result<(), String> {
    serde_json::to_writer(&mut *stdout, frame).map_err(|error| error.to_string())?;
    stdout
        .write_all(b"\n")
        .and_then(|()| stdout.flush())
        .map_err(|error| error.to_string())
}
