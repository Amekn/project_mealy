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
            },
        );
    }
    assert!(
        !by_target.is_empty(),
        "dynamic fixture worker should declare runtime files"
    );
    by_target.into_values().collect()
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
        Err(ExecutorError::UnsupportedHost(message)) if message.contains("child processes")
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
