use mealy_application::{
    CancellationProbe, ExecutorError, ExecutorFrame, ExecutorRequest, ExecutorResult,
    SandboxExecutor, is_sha256_digest,
};
use mealy_domain::PolicyProfile;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const SANDBOX_WORKER_PATH: &str = "/runtime/mealy-fixture-worker";
const WORKER_ENVIRONMENT_BOOTSTRAP_ARGUMENT: &str = "--bootstrap-empty-environment";
const DEFAULT_MAXIMUM_FRAME_BYTES: u64 = 64 * 1024;
const DEFAULT_MAXIMUM_STDERR_BYTES: u64 = 64 * 1024;
const DEFAULT_MAXIMUM_FRAMES: usize = 64;
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(5);
const MAXIMUM_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_CONFIGURED_FRAME_BYTES: u64 = 8 * 1024 * 1024;
const MAXIMUM_CONFIGURED_STDERR_BYTES: u64 = 8 * 1024 * 1024;
const MAXIMUM_CONFIGURED_FRAMES: usize = 1_024;
const RESERVED_SANDBOX_ROOTS: [&str; 4] = ["/dev", "/proc", "/runtime", "/tmp"];
const SHA256_HEX: &[u8; 16] = b"0123456789abcdef";

/// One trusted dynamic-runtime file required to launch the bound worker executable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxRuntimeBinding {
    /// Host file containing a loader or shared library.
    pub host_path: PathBuf,
    /// Exact absolute path at which the dynamic loader expects that file in the sandbox.
    pub sandbox_path: PathBuf,
    /// Optional dispatch-time SHA-256 pin for executable-like runtime files.
    pub identity_digest: Option<String>,
}

/// Trusted construction parameters for the Linux Bubblewrap adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxBubblewrapConfig {
    /// Absolute path to the trusted Bubblewrap frontend.
    pub bubblewrap_path: PathBuf,
    /// Absolute path to the trusted one-shot worker.
    pub worker_path: PathBuf,
    /// SHA-256 of the exact authorized worker bytes.
    pub worker_identity_digest: String,
    /// Minimal loader/shared-library files needed by the worker.
    pub runtime_bindings: Vec<SandboxRuntimeBinding>,
    /// Hard bound for one NDJSON frame.
    pub maximum_frame_bytes: u64,
    /// Hard aggregate bound for captured stderr diagnostics.
    pub maximum_stderr_bytes: u64,
    /// Hard count of worker frames independent of byte size.
    pub maximum_frames: usize,
    /// Cancellation and deadline polling interval.
    pub poll_interval: Duration,
}

impl LinuxBubblewrapConfig {
    /// Creates a configuration with conservative protocol and diagnostic bounds.
    #[must_use]
    pub fn new(
        bubblewrap_path: impl Into<PathBuf>,
        worker_path: impl Into<PathBuf>,
        worker_identity_digest: impl Into<String>,
        runtime_bindings: Vec<SandboxRuntimeBinding>,
    ) -> Self {
        Self {
            bubblewrap_path: bubblewrap_path.into(),
            worker_path: worker_path.into(),
            worker_identity_digest: worker_identity_digest.into(),
            runtime_bindings,
            maximum_frame_bytes: DEFAULT_MAXIMUM_FRAME_BYTES,
            maximum_stderr_bytes: DEFAULT_MAXIMUM_STDERR_BYTES,
            maximum_frames: DEFAULT_MAXIMUM_FRAMES,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }
}

/// Linux one-shot worker adapter using Bubblewrap namespaces and explicit bind mounts.
#[derive(Debug)]
pub struct LinuxBubblewrapExecutor {
    config: ValidatedConfig,
    consumed_capabilities: Mutex<HashSet<String>>,
}

#[derive(Clone, Debug)]
struct ValidatedConfig {
    bubblewrap_path: PathBuf,
    worker_path: PathBuf,
    worker_identity_digest: String,
    runtime_bindings: Vec<SandboxRuntimeBinding>,
    maximum_frame_bytes: u64,
    maximum_stderr_bytes: u64,
    maximum_frames: usize,
    poll_interval: Duration,
}

impl LinuxBubblewrapExecutor {
    /// Validates trusted executable/runtime identity and probes the actual host sandbox boundary.
    ///
    /// `bubblewrap_path`, `worker_path`, and runtime sources are trusted-installation inputs. The
    /// worker is required to be a canonical, non-symlink file and its digest is checked during
    /// construction and immediately before dispatch. Preventing a privileged host administrator
    /// from replacing that file between those checks and `execve` remains an installation concern.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::UnsupportedHost`] when Linux user/mount namespaces or the supplied
    /// Bubblewrap/runtime configuration cannot launch the exact worker without host filesystem or
    /// environment inheritance.
    pub fn new(config: LinuxBubblewrapConfig) -> Result<Self, ExecutorError> {
        if !cfg!(target_os = "linux") {
            return Err(ExecutorError::UnsupportedHost(
                "Bubblewrap is available only on Linux".to_owned(),
            ));
        }
        let config = validate_config(config)?;
        let executor = Self {
            config,
            consumed_capabilities: Mutex::new(HashSet::new()),
        };
        executor.probe_host_capability()?;
        Ok(executor)
    }

    fn probe_host_capability(&self) -> Result<(), ExecutorError> {
        let mut command = self.base_command(None);
        command
            .arg("--")
            .arg(SANDBOX_WORKER_PATH)
            .arg(WORKER_ENVIRONMENT_BOOTSTRAP_ARGUMENT)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let output = command
            .output()
            .map_err(|error| unsupported(format!("could not launch Bubblewrap: {error}")))?;
        // An empty request is deliberately rejected by the trusted worker with EX_USAGE (64).
        if output.status.code() != Some(64) {
            return Err(unsupported(format!(
                "Bubblewrap probe failed: {}",
                bounded_diagnostic(&output.stderr)
            )));
        }
        Ok(())
    }

    fn preflight_request(&self, request: &ExecutorRequest) -> Result<(), ExecutorError> {
        request.validate().map_err(ExecutorError::InvalidRequest)?;
        if request.executable_identity_digest != self.config.worker_identity_digest
            || digest_file(&self.config.worker_path)? != self.config.worker_identity_digest
        {
            return Err(ExecutorError::ExecutableIdentityMismatch);
        }
        match request.profile {
            PolicyProfile::Observe if request.writable_roots.is_empty() => {}
            PolicyProfile::WorkspaceWrite if !request.writable_roots.is_empty() => {}
            PolicyProfile::Observe
            | PolicyProfile::WorkspaceWrite
            | PolicyProfile::Networked
            | PolicyProfile::ServiceOperator
            | PolicyProfile::FullTrust => {
                return Err(ExecutorError::UnsupportedProfile(request.profile));
            }
        }
        if !request.network_destinations.is_empty() {
            return Err(ExecutorError::UnsupportedProfile(request.profile));
        }
        if !request.secret_handles.is_empty() {
            return Err(unsupported(
                "this proof adapter has no scoped secret broker".to_owned(),
            ));
        }
        if !request.allowed_environment_variables.is_empty() {
            return Err(unsupported(
                "this proof adapter does not supply worker environment variables".to_owned(),
            ));
        }
        if request.allow_process_spawn {
            let command_id = request
                .normalized_arguments
                .get("commandId")
                .and_then(serde_json::Value::as_str)
                .filter(|value| canonical_runtime_id(value))
                .ok_or_else(|| unsupported("process command identity is invalid".to_owned()))?;
            let sandbox_path = PathBuf::from(format!("/commands/{command_id}"));
            let command_binding = self
                .config
                .runtime_bindings
                .iter()
                .find(|binding| {
                    binding.sandbox_path == sandbox_path && binding.identity_digest.is_some()
                })
                .ok_or_else(|| {
                    unsupported(
                        "process request exceeds the configured direct-executable boundary"
                            .to_owned(),
                    )
                })?;
            if command_binding
                .identity_digest
                .as_ref()
                .is_some_and(|digest| {
                    digest_file(&command_binding.host_path).as_ref() != Ok(digest)
                })
            {
                return Err(ExecutorError::ExecutableIdentityMismatch);
            }
            if request.profile != PolicyProfile::WorkspaceWrite
                || request.maximum_processes > 32
                || request
                    .normalized_arguments
                    .get("operation")
                    .and_then(serde_json::Value::as_str)
                    != Some("run_process")
            {
                return Err(unsupported(
                    "process request exceeds the configured direct-executable boundary".to_owned(),
                ));
            }
        }
        for mount in request.readable_roots.iter().chain(&request.writable_roots) {
            let host = Path::new(&mount.host_path);
            let canonical = canonical_directory(host)?;
            if canonical != host {
                return Err(unsupported(format!(
                    "mount root is not an exact canonical directory: {}",
                    host.display()
                )));
            }
            let sandbox = Path::new(&mount.sandbox_path);
            if self
                .config
                .runtime_bindings
                .iter()
                .any(|binding| sandbox_paths_overlap(sandbox, binding.sandbox_path.as_path()))
            {
                return Err(unsupported(
                    "request mount overlaps the trusted runtime boundary".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn consume_capability(&self, request: &ExecutorRequest) -> Result<(), ExecutorError> {
        let digest = request.capability_token_digest();
        let mut consumed = self
            .consumed_capabilities
            .lock()
            .map_err(|_| ExecutorError::Io("capability-token lock is poisoned".to_owned()))?;
        if !consumed.insert(digest) {
            return Err(ExecutorError::CapabilityAlreadyUsed);
        }
        Ok(())
    }

    fn base_command(&self, selected_command_id: Option<&str>) -> Command {
        let mut command = Command::new(&self.config.bubblewrap_path);
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
            "mealy-sandbox",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/runtime",
        ]);
        for directory in sandbox_parent_directories(&self.config.runtime_bindings, &[]) {
            command.arg("--dir").arg(directory);
        }
        command
            .arg("--ro-bind")
            .arg(&self.config.worker_path)
            .arg(SANDBOX_WORKER_PATH);
        for binding in &self.config.runtime_bindings {
            if command_binding_id(binding).is_some()
                && command_binding_id(binding) != selected_command_id
            {
                continue;
            }
            command
                .arg("--ro-bind")
                .arg(&binding.host_path)
                .arg(&binding.sandbox_path);
        }
        command
    }

    fn command_for_request(&self, request: &ExecutorRequest) -> Command {
        let selected_command_id = request.allow_process_spawn.then(|| {
            request
                .normalized_arguments
                .get("commandId")
                .and_then(serde_json::Value::as_str)
                .expect("preflight validates process command identity")
        });
        let mut command = self.base_command(selected_command_id);
        let mounts = request
            .readable_roots
            .iter()
            .chain(&request.writable_roots)
            .collect::<Vec<_>>();
        for directory in sandbox_parent_directories(&[], &mounts) {
            command.arg("--dir").arg(directory);
        }
        for mount in &request.readable_roots {
            command
                .arg("--ro-bind")
                .arg(&mount.host_path)
                .arg(&mount.sandbox_path);
        }
        for mount in &request.writable_roots {
            command
                .arg("--bind")
                .arg(&mount.host_path)
                .arg(&mount.sandbox_path);
        }
        let working_directory = request
            .writable_roots
            .first()
            .or_else(|| request.readable_roots.first())
            .map_or("/tmp", |mount| mount.sandbox_path.as_str());
        command
            .arg("--chdir")
            .arg(working_directory)
            .arg("--")
            .arg(SANDBOX_WORKER_PATH)
            .arg(WORKER_ENVIRONMENT_BOOTSTRAP_ARGUMENT)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

fn command_binding_id(binding: &SandboxRuntimeBinding) -> Option<&str> {
    binding.identity_digest.as_ref()?;
    let relative = binding.sandbox_path.strip_prefix("/commands").ok()?;
    let mut components = relative.components();
    let id = match components.next()? {
        std::path::Component::Normal(id) => id.to_str()?,
        _ => return None,
    };
    if components.next().is_none() && canonical_runtime_id(id) {
        Some(id)
    } else {
        None
    }
}

fn canonical_runtime_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

impl SandboxExecutor for LinuxBubblewrapExecutor {
    fn execute(
        &self,
        request: &ExecutorRequest,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ExecutorResult, ExecutorError> {
        self.preflight_request(request)?;
        self.consume_capability(request)?;
        let request_bytes = serde_json::to_vec(request)
            .map_err(|error| ExecutorError::Io(format!("request encoding failed: {error}")))?;
        let started = Instant::now();
        let mut child = self
            .command_for_request(request)
            .spawn()
            .map_err(|error| ExecutorError::Io(format!("worker spawn failed: {error}")))?;
        let Some(mut stdin) = child.stdin.take() else {
            terminate(&mut child);
            return Err(ExecutorError::Io("worker stdin pipe is missing".to_owned()));
        };
        if let Err(error) = stdin.write_all(&request_bytes) {
            terminate(&mut child);
            return Err(ExecutorError::Io(format!(
                "worker request write failed: {error}"
            )));
        }
        drop(stdin);

        let Some(stdout) = child.stdout.take() else {
            terminate(&mut child);
            return Err(ExecutorError::Io(
                "worker stdout pipe is missing".to_owned(),
            ));
        };
        let Some(stderr) = child.stderr.take() else {
            terminate(&mut child);
            return Err(ExecutorError::Io(
                "worker stderr pipe is missing".to_owned(),
            ));
        };
        let stdout_capture = capture_bounded(stdout, request.maximum_output_bytes);
        let stderr_capture = capture_bounded(stderr, self.config.maximum_stderr_bytes);
        let status = wait_for_worker(
            &mut child,
            cancellation,
            started,
            Duration::from_millis(request.maximum_duration_ms),
            self.config.poll_interval,
            &stdout_capture,
            &stderr_capture,
        );
        let status = match status {
            Ok(status) => status,
            Err(error) => {
                terminate(&mut child);
                let _ = stdout_capture.handle.join();
                let _ = stderr_capture.handle.join();
                return Err(error);
            }
        };
        let stdout = receive_capture(stdout_capture)?;
        let stderr = receive_capture(stderr_capture)?;
        if !status.success() {
            let _diagnostic = bounded_diagnostic(&stderr);
            return Err(ExecutorError::WorkerCrashed(status.code()));
        }
        let frames = parse_frames(
            &stdout,
            self.config.maximum_frame_bytes,
            self.config.maximum_frames,
        )?;
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        ExecutorResult::from_frames(request, frames, duration_ms).map_err(ExecutorError::Protocol)
    }
}

struct Capture {
    receiver: mpsc::Receiver<Result<Vec<u8>, String>>,
    handle: JoinHandle<()>,
    maximum: u64,
    exceeded: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
}

fn capture_bounded(mut source: impl Read + Send + 'static, maximum: u64) -> Capture {
    let (sender, receiver) = mpsc::sync_channel(1);
    let exceeded = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(AtomicBool::new(false));
    let reader_exceeded = Arc::clone(&exceeded);
    let reader_failed = Arc::clone(&failed);
    let handle = thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = source
            .by_ref()
            .take(maximum.saturating_add(1))
            .read_to_end(&mut bytes)
            .map(|_| {
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
                    reader_exceeded.store(true, Ordering::Release);
                }
                bytes
            })
            .map_err(|error| error.to_string());
        if result.is_err() {
            reader_failed.store(true, Ordering::Release);
        }
        let _ = sender.send(result);
    });
    Capture {
        receiver,
        handle,
        maximum,
        exceeded,
        failed,
    }
}

fn receive_capture(capture: Capture) -> Result<Vec<u8>, ExecutorError> {
    let result = capture
        .receiver
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| ExecutorError::Io("worker output reader did not finish".to_owned()))?;
    capture
        .handle
        .join()
        .map_err(|_| ExecutorError::Io("worker output reader panicked".to_owned()))?;
    let bytes =
        result.map_err(|error| ExecutorError::Io(format!("worker output read failed: {error}")))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > capture.maximum {
        return Err(ExecutorError::OutputLimitExceeded);
    }
    Ok(bytes)
}

fn wait_for_worker(
    child: &mut Child,
    cancellation: &dyn CancellationProbe,
    started: Instant,
    maximum_duration: Duration,
    poll_interval: Duration,
    stdout: &Capture,
    stderr: &Capture,
) -> Result<ExitStatus, ExecutorError> {
    loop {
        if cancellation.is_cancelled() {
            return Err(ExecutorError::Cancelled);
        }
        if stdout.exceeded.load(Ordering::Acquire) || stderr.exceeded.load(Ordering::Acquire) {
            return Err(ExecutorError::OutputLimitExceeded);
        }
        if stdout.failed.load(Ordering::Acquire) || stderr.failed.load(Ordering::Acquire) {
            return Err(ExecutorError::Io("worker output reader failed".to_owned()));
        }
        if started.elapsed() >= maximum_duration {
            return Err(ExecutorError::TimedOut);
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| ExecutorError::Io(format!("worker wait failed: {error}")))?
        {
            return Ok(status);
        }
        thread::sleep(poll_interval);
    }
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn parse_frames(
    stdout: &[u8],
    maximum_frame_bytes: u64,
    maximum_frames: usize,
) -> Result<Vec<ExecutorFrame>, ExecutorError> {
    let Some(payload) = stdout.strip_suffix(b"\n") else {
        return Err(ExecutorError::MalformedFrame);
    };
    if payload.is_empty() {
        return Err(ExecutorError::MalformedFrame);
    }
    let mut frames = Vec::new();
    for raw in payload.split(|byte| *byte == b'\n') {
        if raw.is_empty() {
            return Err(ExecutorError::MalformedFrame);
        }
        if u64::try_from(raw.len()).unwrap_or(u64::MAX) > maximum_frame_bytes
            || frames.len() >= maximum_frames
        {
            return Err(ExecutorError::OutputLimitExceeded);
        }
        let frame = serde_json::from_slice::<ExecutorFrame>(raw)
            .map_err(|_| ExecutorError::MalformedFrame)?;
        let canonical = serde_json::to_vec(&frame).map_err(|_| ExecutorError::MalformedFrame)?;
        if canonical != raw {
            return Err(ExecutorError::MalformedFrame);
        }
        frames.push(frame);
    }
    Ok(frames)
}

fn validate_config(config: LinuxBubblewrapConfig) -> Result<ValidatedConfig, ExecutorError> {
    if !is_sha256_digest(&config.worker_identity_digest)
        || config.maximum_frame_bytes == 0
        || config.maximum_frame_bytes > MAXIMUM_CONFIGURED_FRAME_BYTES
        || config.maximum_stderr_bytes == 0
        || config.maximum_stderr_bytes > MAXIMUM_CONFIGURED_STDERR_BYTES
        || config.maximum_frames == 0
        || config.maximum_frames > MAXIMUM_CONFIGURED_FRAMES
        || config.poll_interval.is_zero()
        || config.poll_interval > Duration::from_millis(100)
    {
        return Err(unsupported("sandbox configuration is invalid".to_owned()));
    }
    let bubblewrap_path = canonical_regular_file(&config.bubblewrap_path)?;
    if bubblewrap_path != config.bubblewrap_path {
        return Err(unsupported(
            "Bubblewrap path must be exact and canonical".to_owned(),
        ));
    }
    let worker_path = canonical_regular_file(&config.worker_path)?;
    if worker_path != config.worker_path {
        return Err(unsupported(
            "worker path must be exact and canonical".to_owned(),
        ));
    }
    if digest_file(&worker_path)? != config.worker_identity_digest {
        return Err(ExecutorError::ExecutableIdentityMismatch);
    }
    let mut runtime_bindings = Vec::with_capacity(config.runtime_bindings.len());
    let mut targets = HashSet::new();
    for binding in config.runtime_bindings {
        if !canonical_sandbox_path(&binding.sandbox_path)
            || reserved_sandbox_path(&binding.sandbox_path)
            || !targets.insert(binding.sandbox_path.clone())
            || targets.iter().any(|target| {
                target != &binding.sandbox_path
                    && sandbox_paths_overlap(target, &binding.sandbox_path)
            })
        {
            return Err(unsupported("runtime binding is invalid".to_owned()));
        }
        let host_path = canonical_regular_file(&binding.host_path)?;
        if binding.identity_digest.as_ref().is_some_and(|digest| {
            !is_sha256_digest(digest) || digest_file(&host_path).as_ref() != Ok(digest)
        }) {
            return Err(ExecutorError::ExecutableIdentityMismatch);
        }
        runtime_bindings.push(SandboxRuntimeBinding {
            host_path,
            sandbox_path: binding.sandbox_path,
            identity_digest: binding.identity_digest,
        });
    }
    runtime_bindings.sort_by(|left, right| left.sandbox_path.cmp(&right.sandbox_path));
    Ok(ValidatedConfig {
        bubblewrap_path,
        worker_path,
        worker_identity_digest: config.worker_identity_digest,
        runtime_bindings,
        maximum_frame_bytes: config.maximum_frame_bytes,
        maximum_stderr_bytes: config.maximum_stderr_bytes,
        maximum_frames: config.maximum_frames,
        poll_interval: config.poll_interval,
    })
}

fn canonical_regular_file(path: &Path) -> Result<PathBuf, ExecutorError> {
    if !path.is_absolute() {
        return Err(unsupported(format!(
            "trusted executable/runtime path is not absolute: {}",
            path.display()
        )));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| unsupported(format!("could not inspect {}: {error}", path.display())))?;
    let canonical = fs::canonicalize(path).map_err(|error| {
        unsupported(format!(
            "could not canonicalize {}: {error}",
            path.display()
        ))
    })?;
    let target = fs::metadata(&canonical).map_err(|error| {
        unsupported(format!(
            "could not inspect {}: {error}",
            canonical.display()
        ))
    })?;
    if (!metadata.is_file() && !metadata.file_type().is_symlink()) || !target.is_file() {
        return Err(unsupported(format!(
            "trusted runtime path is not a regular file: {}",
            path.display()
        )));
    }
    Ok(canonical)
}

fn canonical_directory(path: &Path) -> Result<PathBuf, ExecutorError> {
    if !path.is_absolute() {
        return Err(unsupported(format!(
            "mount root is not absolute: {}",
            path.display()
        )));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| unsupported(format!("could not inspect mount root: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(unsupported(
            "mount root is not a non-symlink directory".to_owned(),
        ));
    }
    fs::canonicalize(path)
        .map_err(|error| unsupported(format!("could not canonicalize mount root: {error}")))
}

fn digest_file(path: &Path) -> Result<String, ExecutorError> {
    let file = File::open(path)
        .map_err(|error| ExecutorError::Io(format!("could not read worker identity: {error}")))?;
    let mut reader = file.take(MAXIMUM_EXECUTABLE_BYTES.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| ExecutorError::Io(format!("worker identity read failed: {error}")))?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if total > MAXIMUM_EXECUTABLE_BYTES {
            return Err(unsupported("worker executable is oversized".to_owned()));
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(SHA256_HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(SHA256_HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}

fn canonical_sandbox_path(path: &Path) -> bool {
    path.to_str().is_some_and(|value| {
        value.len() >= 2
            && value.len() <= 4_096
            && value.starts_with('/')
            && !value.ends_with('/')
            && value
                .split('/')
                .skip(1)
                .all(|component| !component.is_empty() && component != "." && component != "..")
    })
}

fn reserved_sandbox_path(path: &Path) -> bool {
    RESERVED_SANDBOX_ROOTS.iter().any(|reserved| {
        path == Path::new(reserved)
            || path
                .strip_prefix(reserved)
                .is_ok_and(|suffix| !suffix.as_os_str().is_empty())
    })
}

fn sandbox_paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn sandbox_parent_directories(
    runtime: &[SandboxRuntimeBinding],
    mounts: &[&mealy_application::ExecutorMount],
) -> Vec<PathBuf> {
    let mut directories = HashSet::new();
    for target in runtime
        .iter()
        .map(|binding| binding.sandbox_path.as_path())
        .chain(mounts.iter().map(|mount| Path::new(&mount.sandbox_path)))
    {
        let mut parent = target.parent();
        while let Some(value) = parent {
            if value != Path::new("/") {
                directories.insert(value.to_path_buf());
            }
            parent = value.parent();
        }
    }
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by(|left, right| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| left.cmp(right))
    });
    directories
}

fn bounded_diagnostic(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(4_096)]).into_owned()
}

fn unsupported(message: String) -> ExecutorError {
    ExecutorError::UnsupportedHost(message)
}

#[cfg(test)]
mod tests {
    use super::parse_frames;
    use mealy_application::ExecutorError;

    #[test]
    fn frame_parser_rejects_non_json_and_noncanonical_json() {
        assert_eq!(
            parse_frames(b"not-json\n", 1_024, 4),
            Err(ExecutorError::MalformedFrame)
        );
        assert_eq!(
            parse_frames(
                b"{ \"frameType\": \"progress\", \"sequence\": 0, \"message\": \"x\" }\n",
                1_024,
                4
            ),
            Err(ExecutorError::MalformedFrame)
        );
        assert_eq!(
            parse_frames(
                b"{\"frameType\":\"progress\",\"sequence\":0,\"message\":\"x\"}",
                1_024,
                4
            ),
            Err(ExecutorError::MalformedFrame)
        );
        assert_eq!(
            parse_frames(
                b"{\"frameType\":\"progress\",\"sequence\":0,\"message\":\"x\"}\n\n",
                1_024,
                4
            ),
            Err(ExecutorError::MalformedFrame)
        );
    }
}
