//! Real-process conformance tests for the Linux one-shot sandbox adapter.

#![cfg(target_os = "linux")]

use mealy_application::{
    CancellationProbe, EXECUTOR_PROTOCOL_VERSION, ExecutorError, ExecutorMount, ExecutorRequest,
    ExecutorTerminal, SandboxExecutor, sha256_digest,
};
use mealy_domain::{AttemptId, EffectId, FencingToken, PolicyProfile};
use mealy_infrastructure::{LinuxBubblewrapConfig, LinuxBubblewrapExecutor, SandboxRuntimeBinding};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};
use tempfile::tempdir;

const BUBBLEWRAP_PATH: &str = "/usr/bin/bwrap";
static CAPABILITY_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static EXECUTOR: OnceLock<LinuxBubblewrapExecutor> = OnceLock::new();

struct NeverCancelled;

impl CancellationProbe for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct ImmediatelyCancelled;

impl CancellationProbe for ImmediatelyCancelled {
    fn is_cancelled(&self) -> bool {
        true
    }
}

fn executor() -> &'static LinuxBubblewrapExecutor {
    EXECUTOR.get_or_init(|| {
        LinuxBubblewrapExecutor::new(configuration()).expect("host should enforce Bubblewrap proof")
    })
}

fn configuration() -> LinuxBubblewrapConfig {
    let worker = worker_path();
    LinuxBubblewrapConfig::new(
        PathBuf::from(BUBBLEWRAP_PATH),
        worker.clone(),
        digest_file(&worker),
        runtime_bindings(&worker),
    )
}

fn worker_path() -> PathBuf {
    fs::canonicalize(env!("CARGO_BIN_EXE_mealy-fixture-worker"))
        .expect("fixture worker should have a canonical path")
}

fn digest_file(path: &Path) -> String {
    sha256_digest(&fs::read(path).expect("fixture worker should be readable"))
}

fn runtime_bindings(worker: &Path) -> Vec<SandboxRuntimeBinding> {
    let output = Command::new("ldd")
        .arg(worker)
        .output()
        .expect("ldd should inspect the fixture worker");
    assert!(output.status.success(), "ldd failed for fixture worker");
    let stdout = String::from_utf8(output.stdout).expect("ldd output should be UTF-8");
    let mut by_target = BTreeMap::new();
    for line in stdout.lines() {
        let candidate = line.split_once("=>").map_or_else(
            || line.split_whitespace().next(),
            |(_, right)| right.split_whitespace().next(),
        );
        let Some(candidate) = candidate.filter(|value| value.starts_with('/')) else {
            continue;
        };
        by_target.insert(
            PathBuf::from(candidate),
            SandboxRuntimeBinding {
                host_path: PathBuf::from(candidate),
                sandbox_path: PathBuf::from(candidate),
                identity_digest: None,
            },
        );
    }
    assert!(
        !by_target.is_empty(),
        "dynamic fixture worker should declare runtime files"
    );
    by_target.into_values().collect()
}

fn command_executor(command_id: &str, executable: &Path) -> LinuxBubblewrapExecutor {
    command_executor_with_commands(&[(command_id, executable)])
}

fn command_executor_with_commands(commands: &[(&str, &Path)]) -> LinuxBubblewrapExecutor {
    let worker = worker_path();
    let mut by_target = runtime_bindings(&worker)
        .into_iter()
        .map(|binding| (binding.sandbox_path.clone(), binding))
        .collect::<BTreeMap<_, _>>();
    for (command_id, executable) in commands {
        let executable = fs::canonicalize(executable).expect("canonical command executable");
        for binding in runtime_bindings(&executable) {
            by_target
                .entry(binding.sandbox_path.clone())
                .or_insert(binding);
        }
        by_target.insert(
            PathBuf::from(format!("/commands/{command_id}")),
            SandboxRuntimeBinding {
                host_path: executable.clone(),
                sandbox_path: PathBuf::from(format!("/commands/{command_id}")),
                identity_digest: Some(digest_file(&executable)),
            },
        );
    }
    LinuxBubblewrapExecutor::new(LinuxBubblewrapConfig::new(
        PathBuf::from(BUBBLEWRAP_PATH),
        worker.clone(),
        digest_file(&worker),
        by_target.into_values().collect(),
    ))
    .expect("host should enforce direct-process Bubblewrap proof")
}

fn request(arguments: Value, writable_root: Option<&Path>) -> ExecutorRequest {
    let capability = CAPABILITY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let writable_roots = writable_root.map_or_else(Vec::new, |root| {
        vec![ExecutorMount {
            host_path: root.to_string_lossy().into_owned(),
            sandbox_path: "/workspace".to_owned(),
        }]
    });
    ExecutorRequest {
        protocol_version: EXECUTOR_PROTOCOL_VERSION.to_owned(),
        effect_id: EffectId::new(),
        attempt_id: AttemptId::new(),
        fencing_token: FencingToken::new(1).expect("nonzero fence"),
        capability_token: format!("fixture-one-use-capability-token-{capability:020}"),
        executable_identity_digest: digest_file(&worker_path()),
        profile: if writable_roots.is_empty() {
            PolicyProfile::Observe
        } else {
            PolicyProfile::WorkspaceWrite
        },
        readable_roots: Vec::new(),
        writable_roots,
        network_destinations: Vec::new(),
        secret_handles: Vec::new(),
        allow_process_spawn: false,
        allowed_environment_variables: Vec::new(),
        idempotency_key: None,
        arguments_digest: sha256_digest(arguments.to_string().as_bytes()),
        normalized_arguments: arguments,
        maximum_duration_ms: 1_000,
        maximum_output_bytes: 512 * 1_024,
        maximum_memory_bytes: 256 * 1024 * 1024,
        maximum_processes: 0,
    }
}

fn process_request(
    command_id: &str,
    workspace: &Path,
    working_directory: &str,
    arguments: &[&str],
) -> ExecutorRequest {
    let mut request = request(
        json!({
            "arguments": arguments,
            "commandId": command_id,
            "operation": "run_process",
            "workingDirectory": working_directory,
            "workspaceId": "project",
        }),
        Some(workspace),
    );
    request.allow_process_spawn = true;
    request.maximum_duration_ms = 10_000;
    request.maximum_memory_bytes = 512 * 1024 * 1024;
    request.maximum_processes = 16;
    request
}

fn successful_output(terminal: ExecutorTerminal) -> Value {
    match terminal {
        ExecutorTerminal::Succeeded { output, .. } => output,
        ExecutorTerminal::Failed {
            error_class,
            error_message,
            ..
        } => panic!("worker failed unexpectedly: {error_class}: {error_message}"),
    }
}

fn assert_failure_class(terminal: &ExecutorTerminal, expected: &str) {
    assert!(
        matches!(terminal, ExecutorTerminal::Failed { error_class, .. } if error_class == expected),
        "expected failure class {expected}, got {terminal:?}"
    );
}

#[test]
fn writes_only_to_the_declared_workspace_root() {
    let workspace = tempdir().expect("workspace tempdir");
    let invocation = request(
        json!({
            "operation": "write_file",
            "relativePath": "result.txt",
            "content": "isolated write"
        }),
        Some(workspace.path()),
    );

    let result = executor()
        .execute(&invocation, &NeverCancelled)
        .expect("isolated write should succeed");
    let output = successful_output(result.terminal);
    assert_eq!(output["relativePath"], "result.txt");
    assert_eq!(output["bytesWritten"], 14);
    assert_eq!(
        fs::read_to_string(workspace.path().join("result.txt")).expect("written result"),
        "isolated write"
    );
}

#[test]
fn atomically_replaces_only_the_expected_existing_regular_file() {
    let workspace = tempdir().expect("workspace tempdir");
    let target = workspace.path().join("existing.txt");
    fs::write(&target, "old content").expect("seed existing file");
    let invocation = request(
        json!({
            "operation": "replace_file",
            "workspaceId": "project",
            "relativePath": "existing.txt",
            "expectedCurrentDigest": sha256_digest(b"old content"),
            "content": "new content"
        }),
        Some(workspace.path()),
    );
    let result = executor()
        .execute(&invocation, &NeverCancelled)
        .expect("exact replacement should succeed");
    let output = successful_output(result.terminal);
    assert_eq!(
        output["previousContentDigest"],
        sha256_digest(b"old content")
    );
    assert_eq!(output["contentDigest"], sha256_digest(b"new content"));
    assert_eq!(
        fs::read_to_string(&target).expect("replacement"),
        "new content"
    );
    assert!(
        fs::read_dir(workspace.path())
            .expect("workspace listing")
            .all(|entry| !entry
                .expect("workspace entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".mealy-replace-"))
    );

    let stale = request(
        json!({
            "operation": "replace_file",
            "workspaceId": "project",
            "relativePath": "existing.txt",
            "expectedCurrentDigest": sha256_digest(b"old content"),
            "content": "must not land"
        }),
        Some(workspace.path()),
    );
    let stale_result = executor()
        .execute(&stale, &NeverCancelled)
        .expect("stale precondition should be structured");
    assert!(matches!(
        stale_result.terminal,
        ExecutorTerminal::Failed { ref error_class, .. }
            if error_class == "precondition_mismatch"
    ));
    assert_eq!(
        fs::read_to_string(&target).expect("unchanged"),
        "new content"
    );

    let outside = tempdir().expect("outside tempdir");
    let outside_target = outside.path().join("outside.txt");
    fs::write(&outside_target, "outside").expect("outside file");
    std::os::unix::fs::symlink(&outside_target, workspace.path().join("redirect.txt"))
        .expect("target symlink");
    let redirected = request(
        json!({
            "operation": "replace_file",
            "workspaceId": "project",
            "relativePath": "redirect.txt",
            "expectedCurrentDigest": sha256_digest(b"outside"),
            "content": "must not escape"
        }),
        Some(workspace.path()),
    );
    let redirected_result = executor()
        .execute(&redirected, &NeverCancelled)
        .expect("symlink denial should be structured");
    assert!(matches!(
        redirected_result.terminal,
        ExecutorTerminal::Failed { ref error_class, .. } if error_class == "path_denied"
    ));
    assert_eq!(
        fs::read_to_string(outside_target).expect("outside unchanged"),
        "outside"
    );
}

#[test]
fn applies_only_approved_ordered_exact_text_replacements() {
    let workspace = tempdir().expect("workspace tempdir");
    let target = workspace.path().join("release.txt");
    let original = "version = 1\nstatus = draft\nversion = 1\n";
    fs::write(&target, original).expect("seed patch target");
    let invocation = request(
        json!({
            "operation": "replace_file",
            "workspaceId": "project",
            "relativePath": "release.txt",
            "expectedCurrentDigest": sha256_digest(original.as_bytes()),
            "replacements": [
                {
                    "oldText": "version = 1",
                    "newText": "version = 2",
                    "expectedOccurrences": 2
                },
                {
                    "oldText": "status = draft",
                    "newText": "status = ready",
                    "expectedOccurrences": 1
                }
            ]
        }),
        Some(workspace.path()),
    );
    let result = executor()
        .execute(&invocation, &NeverCancelled)
        .expect("exact patch should succeed");
    let output = successful_output(result.terminal);
    let expected = "version = 2\nstatus = ready\nversion = 2\n";
    assert_eq!(
        output["previousContentDigest"],
        sha256_digest(original.as_bytes())
    );
    assert_eq!(output["contentDigest"], sha256_digest(expected.as_bytes()));
    assert_eq!(
        fs::read_to_string(&target).expect("patched content"),
        expected
    );

    let changed_occurrences = request(
        json!({
            "operation": "replace_file",
            "workspaceId": "project",
            "relativePath": "release.txt",
            "expectedCurrentDigest": sha256_digest(expected.as_bytes()),
            "replacements": [{
                "oldText": "version = 2",
                "newText": "version = 3",
                "expectedOccurrences": 1
            }]
        }),
        Some(workspace.path()),
    );
    let failure = executor()
        .execute(&changed_occurrences, &NeverCancelled)
        .expect("occurrence mismatch should be structured");
    assert!(matches!(
        failure.terminal,
        ExecutorTerminal::Failed { ref error_class, .. }
            if error_class == "patch_precondition_mismatch"
    ));
    assert_eq!(
        fs::read_to_string(&target).expect("mismatch leaves target unchanged"),
        expected
    );
}

#[test]
fn creates_only_one_absent_directory_and_removes_only_one_empty_directory() {
    let workspace = tempdir().expect("workspace tempdir");
    fs::create_dir(workspace.path().join("archive")).expect("archive parent");
    let create = request(
        json!({
            "operation": "create_directory",
            "relativePath": "archive/2026",
            "workspaceId": "project"
        }),
        Some(workspace.path()),
    );
    let output = successful_output(
        executor()
            .execute(&create, &NeverCancelled)
            .expect("directory creation should be structured")
            .terminal,
    );
    assert_eq!(output["operation"], "create_directory");
    assert_eq!(output["relativePath"], "archive/2026");
    assert!(workspace.path().join("archive/2026").is_dir());

    let duplicate = request(
        json!({
            "operation": "create_directory",
            "relativePath": "archive/2026",
            "workspaceId": "project"
        }),
        Some(workspace.path()),
    );
    assert_failure_class(
        &executor()
            .execute(&duplicate, &NeverCancelled)
            .expect("duplicate denial should be structured")
            .terminal,
        "create_directory_failed",
    );

    let remove = request(
        json!({
            "operation": "remove_empty_directory",
            "relativePath": "archive/2026",
            "workspaceId": "project"
        }),
        Some(workspace.path()),
    );
    successful_output(
        executor()
            .execute(&remove, &NeverCancelled)
            .expect("empty-directory removal should succeed")
            .terminal,
    );
    assert!(!workspace.path().join("archive/2026").exists());

    fs::create_dir_all(workspace.path().join("archive/nonempty")).expect("nonempty directory");
    fs::write(workspace.path().join("archive/nonempty/keep.txt"), "keep").expect("nonempty marker");
    let nonempty = request(
        json!({
            "operation": "remove_empty_directory",
            "relativePath": "archive/nonempty",
            "workspaceId": "project"
        }),
        Some(workspace.path()),
    );
    assert_failure_class(
        &executor()
            .execute(&nonempty, &NeverCancelled)
            .expect("nonempty denial should be structured")
            .terminal,
        "remove_directory_failed",
    );
    assert_eq!(
        fs::read_to_string(workspace.path().join("archive/nonempty/keep.txt"))
            .expect("preserved marker"),
        "keep"
    );
}

#[test]
fn moves_only_a_digest_matched_regular_file_without_overwrite_or_symlink_crossing() {
    let workspace = tempdir().expect("workspace tempdir");
    fs::create_dir_all(workspace.path().join("drafts")).expect("drafts parent");
    fs::create_dir_all(workspace.path().join("archive")).expect("archive parent");
    fs::write(
        workspace.path().join("drafts/report.txt"),
        "approved report",
    )
    .expect("source file");
    let digest = sha256_digest(b"approved report");
    let move_request = request(
        json!({
            "destinationPath": "archive/report.txt",
            "expectedSourceDigest": digest,
            "operation": "move_file",
            "sourcePath": "drafts/report.txt",
            "workspaceId": "project"
        }),
        Some(workspace.path()),
    );
    let output = successful_output(
        executor()
            .execute(&move_request, &NeverCancelled)
            .expect("approved move should succeed")
            .terminal,
    );
    assert_eq!(output["contentDigest"], digest);
    assert!(!workspace.path().join("drafts/report.txt").exists());
    assert_eq!(
        fs::read_to_string(workspace.path().join("archive/report.txt")).expect("moved content"),
        "approved report"
    );

    fs::write(workspace.path().join("drafts/collision.txt"), "source").expect("collision source");
    fs::write(
        workspace.path().join("archive/collision.txt"),
        "destination",
    )
    .expect("collision destination");
    let collision = request(
        json!({
            "destinationPath": "archive/collision.txt",
            "expectedSourceDigest": sha256_digest(b"source"),
            "operation": "move_file",
            "sourcePath": "drafts/collision.txt",
            "workspaceId": "project"
        }),
        Some(workspace.path()),
    );
    assert_failure_class(
        &executor()
            .execute(&collision, &NeverCancelled)
            .expect("collision denial should be structured")
            .terminal,
        "move_failed",
    );
    assert_eq!(
        fs::read_to_string(workspace.path().join("drafts/collision.txt"))
            .expect("source preserved"),
        "source"
    );
    assert_eq!(
        fs::read_to_string(workspace.path().join("archive/collision.txt"))
            .expect("destination preserved"),
        "destination"
    );

    fs::write(workspace.path().join("drafts/stale.txt"), "changed").expect("stale source");
    let stale = request(
        json!({
            "destinationPath": "archive/stale.txt",
            "expectedSourceDigest": sha256_digest(b"old"),
            "operation": "move_file",
            "sourcePath": "drafts/stale.txt",
            "workspaceId": "project"
        }),
        Some(workspace.path()),
    );
    assert_failure_class(
        &executor()
            .execute(&stale, &NeverCancelled)
            .expect("stale denial should be structured")
            .terminal,
        "precondition_mismatch",
    );
    assert!(!workspace.path().join("archive/stale.txt").exists());
}

#[test]
fn move_rejects_a_symlink_source_without_touching_outside_bytes() {
    let workspace = tempdir().expect("workspace tempdir");
    fs::create_dir(workspace.path().join("drafts")).expect("drafts parent");
    fs::create_dir(workspace.path().join("archive")).expect("archive parent");
    let outside = tempdir().expect("outside tempdir");
    let outside_file = outside.path().join("outside.txt");
    fs::write(&outside_file, "outside").expect("outside content");
    std::os::unix::fs::symlink(&outside_file, workspace.path().join("drafts/redirect.txt"))
        .expect("source symlink");
    let redirected = request(
        json!({
            "destinationPath": "archive/redirect.txt",
            "expectedSourceDigest": sha256_digest(b"outside"),
            "operation": "move_file",
            "sourcePath": "drafts/redirect.txt",
            "workspaceId": "project"
        }),
        Some(workspace.path()),
    );
    assert_failure_class(
        &executor()
            .execute(&redirected, &NeverCancelled)
            .expect("symlink denial should be structured")
            .terminal,
        "source_denied",
    );
    assert_eq!(
        fs::read_to_string(outside_file).expect("outside unchanged"),
        "outside"
    );
    assert!(!workspace.path().join("archive/redirect.txt").exists());
}

#[test]
fn removes_only_a_digest_matched_bounded_regular_file_via_exclusive_quarantine() {
    let workspace = tempdir().expect("workspace tempdir");
    fs::create_dir(workspace.path().join("obsolete")).expect("obsolete parent");
    fs::write(
        workspace.path().join("obsolete/report.txt"),
        "remove exactly",
    )
    .expect("removal target");
    let digest = sha256_digest(b"remove exactly");
    let remove = request(
        json!({
            "expectedCurrentDigest": digest,
            "operation": "remove_file",
            "relativePath": "obsolete/report.txt",
            "workspaceId": "project"
        }),
        Some(workspace.path()),
    );
    let output = successful_output(
        executor()
            .execute(&remove, &NeverCancelled)
            .expect("approved removal should succeed")
            .terminal,
    );
    assert_eq!(output["contentDigest"], digest);
    assert!(!workspace.path().join("obsolete/report.txt").exists());
    assert!(
        fs::read_dir(workspace.path())
            .expect("workspace listing")
            .all(|entry| !entry
                .expect("workspace entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".mealy-remove-"))
    );

    fs::write(workspace.path().join("obsolete/stale.txt"), "changed").expect("stale target");
    let stale = request(
        json!({
            "expectedCurrentDigest": sha256_digest(b"old"),
            "operation": "remove_file",
            "relativePath": "obsolete/stale.txt",
            "workspaceId": "project"
        }),
        Some(workspace.path()),
    );
    assert_failure_class(
        &executor()
            .execute(&stale, &NeverCancelled)
            .expect("stale denial should be structured")
            .terminal,
        "precondition_mismatch",
    );
    assert_eq!(
        fs::read_to_string(workspace.path().join("obsolete/stale.txt"))
            .expect("stale target preserved"),
        "changed"
    );

    let outside = tempdir().expect("outside tempdir");
    let outside_file = outside.path().join("outside.txt");
    fs::write(&outside_file, "outside").expect("outside content");
    std::os::unix::fs::symlink(
        &outside_file,
        workspace.path().join("obsolete/redirect.txt"),
    )
    .expect("removal symlink");
    let redirected = request(
        json!({
            "expectedCurrentDigest": sha256_digest(b"outside"),
            "operation": "remove_file",
            "relativePath": "obsolete/redirect.txt",
            "workspaceId": "project"
        }),
        Some(workspace.path()),
    );
    assert_failure_class(
        &executor()
            .execute(&redirected, &NeverCancelled)
            .expect("symlink denial should be structured")
            .terminal,
        "target_denied",
    );
    assert_eq!(
        fs::read_to_string(outside_file).expect("outside unchanged"),
        "outside"
    );
}

#[test]
fn runs_only_the_digest_pinned_direct_executable_inside_the_workspace() {
    let workspace = tempdir().expect("process workspace");
    let executor = command_executor("mkdir", Path::new("/usr/bin/mkdir"));
    let invocation = process_request("mkdir", workspace.path(), "", &["created-by-command"]);
    let result = executor
        .execute(&invocation, &NeverCancelled)
        .expect("pinned direct command should succeed");
    let output = successful_output(result.terminal);
    assert_eq!(output["exitCode"], 0);
    assert_eq!(output["stdout"], "");
    assert_eq!(output["stderr"], "");
    assert_eq!(output["stdoutTruncated"], false);
    assert_eq!(output["stderrTruncated"], false);
    assert!(workspace.path().join("created-by-command").is_dir());

    let wrong_identity = process_request("unconfigured", workspace.path(), "", &["denied"]);
    assert!(matches!(
        executor.execute(&wrong_identity, &NeverCancelled),
        Err(ExecutorError::UnsupportedHost(message))
            if message.contains("direct-executable boundary")
    ));
    assert!(!workspace.path().join("denied").exists());
}

#[test]
fn mounts_only_the_command_identity_approved_for_this_attempt() {
    let workspace = tempdir().expect("process workspace");
    let executor = command_executor_with_commands(&[
        ("env", Path::new("/usr/bin/env")),
        ("mkdir", Path::new("/usr/bin/mkdir")),
    ]);
    let invocation = process_request(
        "env",
        workspace.path(),
        "",
        &["/commands/mkdir", "must-not-exist"],
    );
    let result = executor
        .execute(&invocation, &NeverCancelled)
        .expect("selected command should produce bounded terminal evidence");
    let output = successful_output(result.terminal);
    assert_ne!(output["exitCode"], 0);
    assert!(!workspace.path().join("must-not-exist").exists());
}

#[test]
fn unrelated_command_drift_does_not_widen_or_disable_selected_command() {
    let command_home = tempdir().expect("mutable command fixture");
    let unselected = command_home.path().join("mkdir");
    fs::copy("/usr/bin/mkdir", &unselected).expect("copy unselected command fixture");
    let executor = command_executor_with_commands(&[
        ("env", Path::new("/usr/bin/env")),
        ("mkdir", &unselected),
    ]);
    let mut bytes = fs::read(&unselected).expect("read copied command");
    let last = bytes.last_mut().expect("nonempty command");
    *last ^= 1;
    fs::write(&unselected, bytes).expect("mutate unselected command fixture");
    let workspace = tempdir().expect("process workspace");
    let invocation = process_request("env", workspace.path(), "", &[]);
    let result = executor
        .execute(&invocation, &NeverCancelled)
        .expect("unselected command is not part of this sandbox");
    let output = successful_output(result.terminal);
    assert_eq!(output["exitCode"], 0);
    assert_eq!(output["stdout"], "");
}

#[test]
fn rejects_command_digest_drift_before_process_dispatch() {
    let command_home = tempdir().expect("mutable command fixture");
    let command = command_home.path().join("mkdir");
    fs::copy("/usr/bin/mkdir", &command).expect("copy command fixture");
    let executor = command_executor("mkdir", &command);
    let mut bytes = fs::read(&command).expect("read copied command");
    let last = bytes.last_mut().expect("nonempty command");
    *last ^= 1;
    fs::write(&command, bytes).expect("mutate command fixture");
    let workspace = tempdir().expect("process workspace");
    let invocation = process_request("mkdir", workspace.path(), "", &["must-not-exist"]);
    assert_eq!(
        executor.execute(&invocation, &NeverCancelled),
        Err(ExecutorError::ExecutableIdentityMismatch)
    );
    assert!(!workspace.path().join("must-not-exist").exists());
}

#[test]
fn rejects_process_working_directory_symlink_crossing() {
    let workspace = tempdir().expect("process workspace");
    let outside = tempdir().expect("outside workspace");
    std::os::unix::fs::symlink(outside.path(), workspace.path().join("redirect"))
        .expect("working-directory symlink");
    let executor = command_executor("mkdir", Path::new("/usr/bin/mkdir"));
    let invocation = process_request("mkdir", workspace.path(), "redirect", &["must-not-exist"]);
    let result = executor
        .execute(&invocation, &NeverCancelled)
        .expect("path denial should be a structured terminal result");
    assert!(matches!(
        result.terminal,
        ExecutorTerminal::Failed { ref error_class, .. }
            if error_class == "working_directory_denied"
    ));
    assert!(!outside.path().join("must-not-exist").exists());
}

#[test]
fn clears_ambient_environment_filesystem_and_network_authority() {
    let invocation = request(json!({"operation": "probe_isolation"}), None);

    let result = executor()
        .execute(&invocation, &NeverCancelled)
        .expect("isolation probe should succeed");
    let output = successful_output(result.terminal);
    assert_eq!(output["environmentNames"], json!([]));
    assert_eq!(output["ambientPathReadable"], false);
    assert_eq!(output["networkDenied"], true);
}

#[test]
fn enforces_memory_and_child_process_limits_before_started_frame() {
    let invocation = request(json!({"operation": "probe_resource_limits"}), None);
    let result = executor()
        .execute(&invocation, &NeverCancelled)
        .expect("resource-limit probe should succeed");
    let output = successful_output(result.terminal);
    assert_eq!(output["memoryCurrent"], 256 * 1024 * 1024_u64);
    assert_eq!(output["memoryMaximum"], 256 * 1024 * 1024_u64);
    assert_eq!(output["processCurrent"], 1);
    assert_eq!(output["processMaximum"], 1);
    assert_eq!(output["processSpawnDenied"], true);
}

#[test]
fn denies_traversal_and_symlink_crossing() {
    let container = tempdir().expect("workspace container tempdir");
    let workspace = container.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace directory");
    let outside = tempdir().expect("outside tempdir");

    let traversal = request(
        json!({
            "operation": "write_file",
            "relativePath": "../escape.txt",
            "content": "denied"
        }),
        Some(&workspace),
    );
    let traversal_result = executor()
        .execute(&traversal, &NeverCancelled)
        .expect("denial should be a structured terminal result");
    assert!(matches!(
        traversal_result.terminal,
        ExecutorTerminal::Failed { ref error_class, .. } if error_class == "path_denied"
    ));
    assert!(!container.path().join("escape.txt").exists());

    std::os::unix::fs::symlink(outside.path(), workspace.join("link")).expect("fixture symlink");
    let symlink = request(
        json!({
            "operation": "write_file",
            "relativePath": "link/escape.txt",
            "content": "denied"
        }),
        Some(&workspace),
    );
    let symlink_result = executor()
        .execute(&symlink, &NeverCancelled)
        .expect("denial should be a structured terminal result");
    assert!(matches!(
        symlink_result.terminal,
        ExecutorTerminal::Failed { ref error_class, .. } if error_class == "path_denied"
    ));
    assert!(!outside.path().join("escape.txt").exists());
}

#[test]
fn rejects_malformed_and_oversized_frames_without_harming_parent() {
    let malformed = request(json!({"operation": "malformed_frame"}), None);
    assert_eq!(
        executor().execute(&malformed, &NeverCancelled),
        Err(ExecutorError::MalformedFrame)
    );

    let oversized = request(
        json!({"operation": "oversized_frame", "bytes": 128 * 1024}),
        None,
    );
    assert_eq!(
        executor().execute(&oversized, &NeverCancelled),
        Err(ExecutorError::OutputLimitExceeded)
    );

    let survivor = request(json!({"operation": "probe_isolation"}), None);
    executor()
        .execute(&survivor, &NeverCancelled)
        .expect("parent and adapter should survive invalid worker frames");
}

#[test]
fn kills_timeout_and_cancellation_and_survives_worker_crash() {
    let mut timeout = request(json!({"operation": "sleep", "durationMs": 1_000}), None);
    timeout.maximum_duration_ms = 25;
    assert_eq!(
        executor().execute(&timeout, &NeverCancelled),
        Err(ExecutorError::TimedOut)
    );

    let cancelled = request(json!({"operation": "sleep", "durationMs": 1_000}), None);
    assert_eq!(
        executor().execute(&cancelled, &ImmediatelyCancelled),
        Err(ExecutorError::Cancelled)
    );

    let crash = request(json!({"operation": "crash"}), None);
    assert_eq!(
        executor().execute(&crash, &NeverCancelled),
        Err(ExecutorError::WorkerCrashed(Some(70)))
    );

    let survivor = request(json!({"operation": "probe_isolation"}), None);
    executor()
        .execute(&survivor, &NeverCancelled)
        .expect("parent and adapter should survive bounded process failures");
}

#[test]
fn fails_closed_for_unsupported_authority_identity_and_replay() {
    let mut unsupported = request(json!({"operation": "probe_isolation"}), None);
    unsupported.profile = PolicyProfile::Networked;
    unsupported.network_destinations = vec!["example.invalid:443".to_owned()];
    assert_eq!(
        executor().execute(&unsupported, &NeverCancelled),
        Err(ExecutorError::UnsupportedProfile(PolicyProfile::Networked))
    );

    let mut environment = request(json!({"operation": "probe_isolation"}), None);
    environment.allowed_environment_variables = vec!["HOME".to_owned()];
    assert!(matches!(
        executor().execute(&environment, &NeverCancelled),
        Err(ExecutorError::UnsupportedHost(message))
            if message.contains("environment variables")
    ));

    let mut spawning = request(json!({"operation": "probe_isolation"}), None);
    spawning.allow_process_spawn = true;
    spawning.maximum_processes = 1;
    assert!(matches!(
        executor().execute(&spawning, &NeverCancelled),
        Err(ExecutorError::UnsupportedHost(message))
            if message.contains("process command identity")
    ));

    let mut wrong_identity = request(json!({"operation": "probe_isolation"}), None);
    wrong_identity.executable_identity_digest = sha256_digest(b"different worker");
    assert_eq!(
        executor().execute(&wrong_identity, &NeverCancelled),
        Err(ExecutorError::ExecutableIdentityMismatch)
    );

    let replay = request(json!({"operation": "probe_isolation"}), None);
    executor()
        .execute(&replay, &NeverCancelled)
        .expect("first use should succeed");
    assert_eq!(
        executor().execute(&replay, &NeverCancelled),
        Err(ExecutorError::CapabilityAlreadyUsed)
    );
}

#[test]
fn rejects_runtime_and_request_mount_overlap() {
    let host_root = tempdir().expect("host root tempdir");
    let runtime_parent = configuration().runtime_bindings[0]
        .sandbox_path
        .parent()
        .expect("runtime target should have a parent")
        .to_string_lossy()
        .into_owned();
    let mut invocation = request(json!({"operation": "probe_isolation"}), None);
    invocation.readable_roots.push(ExecutorMount {
        host_path: host_root.path().to_string_lossy().into_owned(),
        sandbox_path: runtime_parent,
    });
    assert!(matches!(
        executor().execute(&invocation, &NeverCancelled),
        Err(ExecutorError::UnsupportedHost(message))
            if message.contains("runtime boundary")
    ));
}
