//! Trusted structured fixture worker used by the Linux one-shot sandbox proof.

use mealy_application::{
    EXECUTOR_PROTOCOL_VERSION, EXTENSION_RPC_VERSION, ExecutorFrame, ExecutorRequest,
    ExecutorTerminal, ExtensionRpcRequest, ExtensionRpcResponse,
    WORKSPACE_REPLACE_MAXIMUM_EDIT_TEXT_CHARACTERS, WORKSPACE_REPLACE_MAXIMUM_EDITS,
    WORKSPACE_REPLACE_MAXIMUM_EXPECTED_OCCURRENCES, is_sha256_digest,
    normalize_workspace_manage_path_arguments, sha256_digest,
};
use serde_json::{Value, json};
use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Component, Path},
    process::{Command, ExitCode, Stdio},
    str::FromStr,
    thread,
    time::Duration,
};

#[cfg(target_os = "linux")]
use rustix::fs::{
    AtFlags, Mode, OFlags, RenameFlags, ResolveFlags, fsync, mkdirat, open, openat2, renameat,
    renameat_with, unlinkat,
};
#[cfg(target_os = "linux")]
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

const MAXIMUM_REQUEST_BYTES: u64 = 64 * 1024;
const MAXIMUM_FIXTURE_CONTENT_BYTES: usize = 1024 * 1024;
const MAXIMUM_REPLACED_FILE_BYTES: u64 = 128 * 1024;
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
        "replace_file" => replace_file(&request, &mut stdout),
        "create_directory" | "move_file" | "remove_file" | "remove_empty_directory" => {
            manage_path(&request, &mut stdout)
        }
        "run_process" => run_process(&request, &mut stdout),
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
    let Ok(mut file) = secure_open_new_file(root_path, relative) else {
        return terminal_failure(
            stdout,
            "path_denied",
            "target path is non-canonical or crosses a symlink",
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

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines)]
fn replace_file(request: &ExecutorRequest, stdout: &mut impl Write) -> Result<(), String> {
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
    let expected_current_digest = request
        .normalized_arguments
        .get("expectedCurrentDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| "expectedCurrentDigest must be a string".to_owned())?;
    let direct_content = request
        .normalized_arguments
        .get("content")
        .and_then(Value::as_str);
    let replacements = request
        .normalized_arguments
        .get("replacements")
        .and_then(Value::as_array);
    if direct_content.is_some() == replacements.is_some() {
        return terminal_failure(
            stdout,
            "invalid_edit_shape",
            "replacement requires exactly one of content or replacements",
        );
    }
    if !is_sha256_digest(expected_current_digest) {
        return terminal_failure(
            stdout,
            "invalid_precondition",
            "expected current-content digest is malformed",
        );
    }
    let root_path = Path::new(&root.sandbox_path);
    let Ok(root) = secure_workspace_root(root_path) else {
        return terminal_failure(
            stdout,
            "path_denied",
            "workspace root is unavailable or redirected",
        );
    };
    if !valid_relative_file_path(relative) {
        return terminal_failure(stdout, "path_denied", "target path is non-canonical");
    }
    let content = if let Some(content) = direct_content {
        content.to_owned()
    } else {
        let replacements = replacements.expect("shape check requires replacement array");
        if replacements.is_empty() || replacements.len() > WORKSPACE_REPLACE_MAXIMUM_EDITS {
            return terminal_failure(
                stdout,
                "invalid_replacements",
                "exact-text replacement count is invalid",
            );
        }
        let current = match secure_existing_file_content(&root, relative) {
            Ok(content) => content,
            Err(ExistingFileError::PathDenied) => {
                return terminal_failure(
                    stdout,
                    "path_denied",
                    "target is absent, non-regular, oversized, or crosses a symlink",
                );
            }
            Err(ExistingFileError::ReadFailed) => {
                return terminal_failure(
                    stdout,
                    "target_read_failed",
                    "target content could not be read completely",
                );
            }
        };
        if sha256_digest(&current) != expected_current_digest {
            return terminal_failure(
                stdout,
                "precondition_mismatch",
                "target content changed after evidence was collected",
            );
        }
        let Ok(mut content) = String::from_utf8(current) else {
            return terminal_failure(
                stdout,
                "patch_target_not_utf8",
                "exact-text replacements require a UTF-8 target",
            );
        };
        for replacement in replacements {
            let Some(replacement) = replacement.as_object().filter(|value| value.len() == 3) else {
                return terminal_failure(
                    stdout,
                    "invalid_replacements",
                    "exact-text replacement shape is invalid",
                );
            };
            let Some(old_text) = replacement.get("oldText").and_then(Value::as_str) else {
                return terminal_failure(
                    stdout,
                    "invalid_replacements",
                    "exact-text replacement old text is invalid",
                );
            };
            let Some(new_text) = replacement.get("newText").and_then(Value::as_str) else {
                return terminal_failure(
                    stdout,
                    "invalid_replacements",
                    "exact-text replacement new text is invalid",
                );
            };
            let Some(expected_occurrences) = replacement
                .get("expectedOccurrences")
                .and_then(Value::as_u64)
                .filter(|value| {
                    (1..=WORKSPACE_REPLACE_MAXIMUM_EXPECTED_OCCURRENCES).contains(value)
                })
            else {
                return terminal_failure(
                    stdout,
                    "invalid_replacements",
                    "exact-text replacement occurrence bound is invalid",
                );
            };
            if old_text.is_empty()
                || old_text.chars().count() > WORKSPACE_REPLACE_MAXIMUM_EDIT_TEXT_CHARACTERS
                || new_text.chars().count() > WORKSPACE_REPLACE_MAXIMUM_EDIT_TEXT_CHARACTERS
            {
                return terminal_failure(
                    stdout,
                    "invalid_replacements",
                    "exact-text replacement text is invalid",
                );
            }
            let occurrences =
                u64::try_from(content.match_indices(old_text).count()).unwrap_or(u64::MAX);
            if occurrences != expected_occurrences {
                return terminal_failure(
                    stdout,
                    "patch_precondition_mismatch",
                    "exact old text occurrence count changed",
                );
            }
            content = content.replace(old_text, new_text);
            if content.len() > MAXIMUM_FIXTURE_CONTENT_BYTES
                || u64::try_from(content.len()).unwrap_or(u64::MAX) > MAXIMUM_REPLACED_FILE_BYTES
            {
                return terminal_failure(
                    stdout,
                    "content_too_large",
                    "patched content exceeds its worker bound",
                );
            }
        }
        content
    };
    if content.len() > MAXIMUM_FIXTURE_CONTENT_BYTES
        || u64::try_from(content.len()).unwrap_or(u64::MAX) > MAXIMUM_REPLACED_FILE_BYTES
    {
        return terminal_failure(
            stdout,
            "content_too_large",
            "replacement content exceeds its worker bound",
        );
    }
    let temporary = format!(
        ".mealy-replace-{}-{}.tmp",
        request.effect_id, request.attempt_id
    );
    let Ok(temporary_fd) = openat2(
        &root,
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from(0o600),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    ) else {
        return terminal_failure(
            stdout,
            "staging_unavailable",
            "exclusive replacement staging file could not be created",
        );
    };
    let mut temporary_file = fs::File::from(temporary_fd);
    if temporary_file
        .write_all(content.as_bytes())
        .and_then(|()| temporary_file.flush())
        .and_then(|()| temporary_file.sync_all())
        .is_err()
    {
        let _ = unlinkat(&root, temporary.as_str(), AtFlags::empty());
        return terminal_failure(
            stdout,
            "staging_write_failed",
            "replacement staging file could not be synchronized",
        );
    }
    drop(temporary_file);

    let current_digest = match secure_existing_file_digest(&root, relative) {
        Ok(digest) => digest,
        Err(ExistingFileError::PathDenied) => {
            let _ = unlinkat(&root, temporary.as_str(), AtFlags::empty());
            return terminal_failure(
                stdout,
                "path_denied",
                "target is absent, non-regular, oversized, or crosses a symlink",
            );
        }
        Err(ExistingFileError::ReadFailed) => {
            let _ = unlinkat(&root, temporary.as_str(), AtFlags::empty());
            return terminal_failure(
                stdout,
                "target_read_failed",
                "target content could not be read completely",
            );
        }
    };
    if current_digest != expected_current_digest {
        let _ = unlinkat(&root, temporary.as_str(), AtFlags::empty());
        return terminal_failure(
            stdout,
            "precondition_mismatch",
            "target content changed after evidence was collected",
        );
    }
    if renameat(&root, temporary.as_str(), &root, relative).is_err() {
        let _ = unlinkat(&root, temporary.as_str(), AtFlags::empty());
        return terminal_failure(
            stdout,
            "replace_failed",
            "atomic replacement could not be committed",
        );
    }
    fsync(&root).map_err(|_| "replacement directory synchronization failed".to_owned())?;
    terminal_success(
        stdout,
        json!({
            "relativePath": relative,
            "bytesWritten": content.len(),
            "contentDigest": sha256_digest(content.as_bytes()),
            "previousContentDigest": current_digest,
        }),
    )
}

#[cfg(not(target_os = "linux"))]
fn replace_file(_request: &ExecutorRequest, stdout: &mut impl Write) -> Result<(), String> {
    terminal_failure(
        stdout,
        "unsupported_platform",
        "secure existing-file replacement requires Linux",
    )
}

#[cfg(target_os = "linux")]
fn manage_path(request: &ExecutorRequest, stdout: &mut impl Write) -> Result<(), String> {
    let Some(mount) = request.writable_roots.first() else {
        return terminal_failure(
            stdout,
            "workspace_not_writable",
            "request has no writable sandbox root",
        );
    };
    let Ok(normalized) = normalize_workspace_manage_path_arguments(&request.normalized_arguments)
    else {
        return terminal_failure(
            stdout,
            "invalid_manage_shape",
            "path lifecycle arguments are not exact and canonical",
        );
    };
    if normalized != request.normalized_arguments {
        return terminal_failure(
            stdout,
            "noncanonical_manage_shape",
            "path lifecycle arguments differ from their canonical form",
        );
    }
    let Ok(root) = secure_workspace_root(Path::new(&mount.sandbox_path)) else {
        return terminal_failure(
            stdout,
            "path_denied",
            "workspace root is unavailable or redirected",
        );
    };
    let operation = normalized["operation"]
        .as_str()
        .ok_or_else(|| "normalized operation disappeared".to_owned())?;
    let result = match operation {
        "create_directory" => create_directory(&root, &normalized),
        "move_file" => move_file(&root, &normalized),
        "remove_file" => remove_file(&root, &normalized, request),
        "remove_empty_directory" => remove_empty_directory(&root, &normalized),
        _ => Err((
            "unsupported_operation",
            "path lifecycle operation is unsupported",
        )),
    };
    match result {
        Ok(output) => terminal_success(stdout, output),
        Err((code, message)) => terminal_failure(stdout, code, message),
    }
}

#[cfg(not(target_os = "linux"))]
fn manage_path(_request: &ExecutorRequest, stdout: &mut impl Write) -> Result<(), String> {
    terminal_failure(
        stdout,
        "unsupported_platform",
        "secure path lifecycle operations require Linux",
    )
}

#[cfg(target_os = "linux")]
type ManageFailure = (&'static str, &'static str);

#[cfg(target_os = "linux")]
fn create_directory(
    root: &impl std::os::fd::AsFd,
    arguments: &Value,
) -> Result<Value, ManageFailure> {
    let relative = arguments["relativePath"]
        .as_str()
        .ok_or(("invalid_path", "directory path is absent"))?;
    let (parent, name) = secure_parent_directory(root, relative)?;
    mkdirat(&parent, name.as_str(), Mode::from(0o700)).map_err(|_| {
        (
            "create_directory_failed",
            "directory already exists or could not be created safely",
        )
    })?;
    fsync(&parent).map_err(|_| {
        (
            "directory_sync_failed",
            "created directory parent could not be synchronized",
        )
    })?;
    Ok(json!({
        "operation": "create_directory",
        "relativePath": relative,
    }))
}

#[cfg(target_os = "linux")]
fn move_file(root: &impl std::os::fd::AsFd, arguments: &Value) -> Result<Value, ManageFailure> {
    let source = arguments["sourcePath"]
        .as_str()
        .ok_or(("invalid_path", "source path is absent"))?;
    let destination = arguments["destinationPath"]
        .as_str()
        .ok_or(("invalid_path", "destination path is absent"))?;
    let expected = arguments["expectedSourceDigest"]
        .as_str()
        .ok_or(("invalid_precondition", "source digest is absent"))?;
    let (source_parent, source_name) = secure_parent_directory(root, source)?;
    let (destination_parent, destination_name) = secure_parent_directory(root, destination)?;
    let current =
        secure_existing_file_digest(&source_parent, source_name.as_str()).map_err(|_| {
            (
                "source_denied",
                "source is absent, non-regular, oversized, unreadable, or redirected",
            )
        })?;
    if current != expected {
        return Err((
            "precondition_mismatch",
            "source content changed after evidence was collected",
        ));
    }
    renameat_with(
        &source_parent,
        source_name.as_str(),
        &destination_parent,
        destination_name.as_str(),
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| {
        (
            "move_failed",
            "source could not be moved or the destination already exists",
        )
    })?;
    sync_two_directories(&source_parent, &destination_parent)?;
    let moved = secure_existing_file_digest(&destination_parent, destination_name.as_str())
        .map_err(|_| {
            (
                "move_verification_failed",
                "moved destination is not the approved bounded regular file",
            )
        })?;
    if moved != expected {
        if renameat_with(
            &destination_parent,
            destination_name.as_str(),
            &source_parent,
            source_name.as_str(),
            RenameFlags::NOREPLACE,
        )
        .is_err()
        {
            return Err((
                "move_restore_failed",
                "moved bytes differed and could not be restored to the source path",
            ));
        }
        sync_two_directories(&source_parent, &destination_parent)?;
        return Err((
            "precondition_mismatch",
            "source entry changed during the approved move",
        ));
    }
    Ok(json!({
        "contentDigest": moved,
        "destinationPath": destination,
        "operation": "move_file",
        "sourcePath": source,
    }))
}

#[cfg(target_os = "linux")]
fn remove_file(
    root: &impl std::os::fd::AsFd,
    arguments: &Value,
    request: &ExecutorRequest,
) -> Result<Value, ManageFailure> {
    let relative = arguments["relativePath"]
        .as_str()
        .ok_or(("invalid_path", "file path is absent"))?;
    let expected = arguments["expectedCurrentDigest"]
        .as_str()
        .ok_or(("invalid_precondition", "current digest is absent"))?;
    let (parent, name) = secure_parent_directory(root, relative)?;
    let current = secure_existing_file_digest(&parent, name.as_str()).map_err(|_| {
        (
            "target_denied",
            "target is absent, non-regular, oversized, unreadable, or redirected",
        )
    })?;
    if current != expected {
        return Err((
            "precondition_mismatch",
            "target content changed after evidence was collected",
        ));
    }
    let quarantine = format!(
        ".mealy-remove-{}-{}.quarantine",
        request.effect_id, request.attempt_id
    );
    renameat_with(
        &parent,
        name.as_str(),
        root,
        quarantine.as_str(),
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| {
        (
            "quarantine_failed",
            "target could not be moved into exclusive deletion quarantine",
        )
    })?;
    fsync(&parent).map_err(|_| {
        (
            "directory_sync_failed",
            "target parent could not be synchronized after quarantine",
        )
    })?;
    fsync(root).map_err(|_| {
        (
            "directory_sync_failed",
            "workspace root could not be synchronized after quarantine",
        )
    })?;
    let quarantined = secure_existing_file_digest(root, quarantine.as_str()).map_err(|_| {
        (
            "quarantine_verification_failed",
            "quarantined target is not a bounded regular file",
        )
    })?;
    if quarantined != expected {
        if renameat_with(
            root,
            quarantine.as_str(),
            &parent,
            name.as_str(),
            RenameFlags::NOREPLACE,
        )
        .is_err()
        {
            return Err((
                "quarantine_restore_failed",
                "changed target was preserved in quarantine but could not be restored",
            ));
        }
        sync_two_directories(root, &parent)?;
        return Err((
            "precondition_mismatch",
            "target entry changed during the approved removal",
        ));
    }
    unlinkat(root, quarantine.as_str(), AtFlags::empty()).map_err(|_| {
        (
            "remove_failed",
            "approved quarantined file could not be removed",
        )
    })?;
    fsync(root).map_err(|_| {
        (
            "directory_sync_failed",
            "workspace root could not be synchronized after removal",
        )
    })?;
    Ok(json!({
        "contentDigest": quarantined,
        "operation": "remove_file",
        "relativePath": relative,
    }))
}

#[cfg(target_os = "linux")]
fn remove_empty_directory(
    root: &impl std::os::fd::AsFd,
    arguments: &Value,
) -> Result<Value, ManageFailure> {
    let relative = arguments["relativePath"]
        .as_str()
        .ok_or(("invalid_path", "directory path is absent"))?;
    let (parent, name) = secure_parent_directory(root, relative)?;
    unlinkat(&parent, name.as_str(), AtFlags::REMOVEDIR).map_err(|_| {
        (
            "remove_directory_failed",
            "target is absent, redirected, non-directory, or not empty",
        )
    })?;
    fsync(&parent).map_err(|_| {
        (
            "directory_sync_failed",
            "removed directory parent could not be synchronized",
        )
    })?;
    Ok(json!({
        "operation": "remove_empty_directory",
        "relativePath": relative,
    }))
}

#[cfg(target_os = "linux")]
fn secure_parent_directory(
    root: &impl std::os::fd::AsFd,
    relative: &str,
) -> Result<(std::os::fd::OwnedFd, String), ManageFailure> {
    if !valid_relative_file_path(relative) {
        return Err(("path_denied", "path is non-canonical"));
    }
    let (parent, name) = relative
        .rsplit_once('/')
        .map_or((".", relative), |(parent, name)| (parent, name));
    let parent = openat2(
        root,
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| {
        (
            "parent_denied",
            "parent is absent, non-directory, redirected, or crosses a mount",
        )
    })?;
    Ok((parent, name.to_owned()))
}

#[cfg(target_os = "linux")]
fn sync_two_directories(
    first: &impl std::os::fd::AsFd,
    second: &impl std::os::fd::AsFd,
) -> Result<(), ManageFailure> {
    fsync(first).and_then(|()| fsync(second)).map_err(|_| {
        (
            "directory_sync_failed",
            "workspace directories could not be synchronized",
        )
    })
}

#[cfg(target_os = "linux")]
enum ExistingFileError {
    PathDenied,
    ReadFailed,
}

#[cfg(target_os = "linux")]
fn secure_existing_file_digest(
    root: &impl std::os::fd::AsFd,
    relative: &str,
) -> Result<String, ExistingFileError> {
    secure_existing_file_content(root, relative).map(|content| sha256_digest(&content))
}

#[cfg(target_os = "linux")]
fn secure_existing_file_content(
    root: &impl std::os::fd::AsFd,
    relative: &str,
) -> Result<Vec<u8>, ExistingFileError> {
    let target = openat2(
        root,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| ExistingFileError::PathDenied)?;
    let file = fs::File::from(target);
    let metadata = file.metadata().map_err(|_| ExistingFileError::PathDenied)?;
    if !metadata.is_file() || metadata.len() > MAXIMUM_REPLACED_FILE_BYTES {
        return Err(ExistingFileError::PathDenied);
    }
    let mut bytes = Vec::new();
    file.take(MAXIMUM_REPLACED_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ExistingFileError::ReadFailed)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAXIMUM_REPLACED_FILE_BYTES {
        return Err(ExistingFileError::PathDenied);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn secure_workspace_root(root: &Path) -> Result<std::os::fd::OwnedFd, ()> {
    open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| ())
}

fn valid_relative_file_path(relative: &str) -> bool {
    let path = Path::new(relative);
    !relative.is_empty()
        && relative.len() <= 1_024
        && !path.is_absolute()
        && !relative.contains("//")
        && !relative.ends_with('/')
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

#[cfg(target_os = "linux")]
fn secure_open_new_file(root: &Path, relative: &str) -> Result<fs::File, ()> {
    if !valid_relative_file_path(relative) {
        return Err(());
    }
    let root = secure_workspace_root(root)?;
    let target = openat2(
        &root,
        relative,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from(0o600),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| ())?;
    Ok(fs::File::from(target))
}

#[cfg(not(target_os = "linux"))]
fn secure_open_new_file(_root: &Path, _relative: &str) -> Result<fs::File, ()> {
    Err(())
}

const MAXIMUM_PROCESS_STREAM_BYTES: usize = 16 * 1_024;

#[cfg(target_os = "linux")]
fn run_process(request: &ExecutorRequest, protocol_stdout: &mut impl Write) -> Result<(), String> {
    if !request.allow_process_spawn || request.maximum_processes == 0 {
        return terminal_failure(
            protocol_stdout,
            "process_not_authorized",
            "request does not authorize a child process",
        );
    }
    let root = request
        .writable_roots
        .first()
        .ok_or_else(|| "process request has no writable workspace".to_owned())?;
    let command_id = request
        .normalized_arguments
        .get("commandId")
        .and_then(Value::as_str)
        .filter(|value| canonical_runtime_id(value))
        .ok_or_else(|| "commandId is invalid".to_owned())?;
    let working_directory = request
        .normalized_arguments
        .get("workingDirectory")
        .and_then(Value::as_str)
        .filter(|value| canonical_relative_directory(value))
        .ok_or_else(|| "workingDirectory is invalid".to_owned())?;
    let arguments = request
        .normalized_arguments
        .get("arguments")
        .and_then(Value::as_array)
        .filter(|arguments| arguments.len() <= 32)
        .ok_or_else(|| "arguments are invalid".to_owned())?;
    let arguments = arguments
        .iter()
        .map(|argument| {
            argument
                .as_str()
                .filter(|value| {
                    value.len() <= 512
                        && !value.contains('\0')
                        && !value.chars().any(char::is_control)
                })
                .ok_or_else(|| "process argument is invalid".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if enter_workspace_directory(Path::new(&root.sandbox_path), working_directory).is_err() {
        return terminal_failure(
            protocol_stdout,
            "working_directory_denied",
            "working directory crossed the writable workspace boundary",
        );
    }
    let executable = format!("/commands/{command_id}");
    let child = Command::new(executable)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let Ok(mut child) = child else {
        return terminal_failure(
            protocol_stdout,
            "process_start_failed",
            "allowlisted process could not be started",
        );
    };
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| "process stdout pipe is absent".to_owned())?;
    let child_stderr = child
        .stderr
        .take()
        .ok_or_else(|| "process stderr pipe is absent".to_owned())?;
    let stdout_reader = thread::spawn(move || read_bounded_stream(child_stdout));
    let stderr_reader = thread::spawn(move || read_bounded_stream(child_stderr));
    let status = child
        .wait()
        .map_err(|_| "allowlisted process wait failed".to_owned())?;
    let (stdout_bytes, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| "process stdout reader failed".to_owned())??;
    let (stderr_bytes, stderr_truncated) = stderr_reader
        .join()
        .map_err(|_| "process stderr reader failed".to_owned())??;
    let stdout_utf8 = String::from_utf8(stdout_bytes.clone());
    let stderr_utf8 = String::from_utf8(stderr_bytes.clone());
    terminal_success(
        protocol_stdout,
        json!({
            "exitCode": status.code(),
            "stderr": stderr_utf8.as_deref().unwrap_or("[non-UTF-8 output omitted]"),
            "stderrDigest": sha256_digest(&stderr_bytes),
            "stderrTruncated": stderr_truncated,
            "stderrUtf8": stderr_utf8.is_ok(),
            "stdout": stdout_utf8.as_deref().unwrap_or("[non-UTF-8 output omitted]"),
            "stdoutDigest": sha256_digest(&stdout_bytes),
            "stdoutTruncated": stdout_truncated,
            "stdoutUtf8": stdout_utf8.is_ok(),
        }),
    )
}

#[cfg(not(target_os = "linux"))]
fn run_process(_request: &ExecutorRequest, stdout: &mut impl Write) -> Result<(), String> {
    terminal_failure(
        stdout,
        "unsupported_host",
        "direct process execution requires Linux",
    )
}

#[cfg(target_os = "linux")]
fn enter_workspace_directory(root: &Path, relative: &str) -> Result<(), String> {
    let root = open(
        root,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| "workspace root could not be opened".to_owned())?;
    let directory = openat2(
        &root,
        if relative.is_empty() { "." } else { relative },
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| "working directory crossed the workspace boundary".to_owned())?;
    rustix::process::fchdir(directory)
        .map_err(|_| "working directory could not be selected".to_owned())
}

fn read_bounded_stream(mut stream: impl Read) -> Result<(Vec<u8>, bool), String> {
    let mut bytes = Vec::new();
    stream
        .by_ref()
        .take(u64::try_from(MAXIMUM_PROCESS_STREAM_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "process output could not be read".to_owned())?;
    let truncated = bytes.len() > MAXIMUM_PROCESS_STREAM_BYTES;
    bytes.truncate(MAXIMUM_PROCESS_STREAM_BYTES);
    Ok((bytes, truncated))
}

fn canonical_runtime_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn canonical_relative_directory(value: &str) -> bool {
    value.len() <= 256
        && (value.is_empty()
            || value.split('/').all(|segment| {
                !segment.is_empty()
                    && segment != "."
                    && segment != ".."
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            }))
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
