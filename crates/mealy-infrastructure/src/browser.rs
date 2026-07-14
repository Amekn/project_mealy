use crate::{
    browser_bundle::{BrowserBundleInspection, inspect_browser_bundle},
    is_trusted_system_executable,
    web::resolve_pinned_web_destination,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use mealy_application::{
    BROWSER_CDP_PROTOCOL_VERSION, BrowserConfig, BrowserSnapshotRequest, CancellationProbe,
    ReadOnlyTool, ReadToolDescriptor, ReadToolError, ReadToolOutput, WebAccessConfig,
    browser_maximum_screenshot_bytes, browser_snapshot_descriptor, sha256_digest,
    validate_browser_snapshot_arguments,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use thiserror::Error;
use tungstenite::{Message, WebSocket};
use url::Url;

#[cfg(unix)]
use std::os::unix::{
    fs::PermissionsExt as _,
    net::{UnixListener, UnixStream},
};

const BROWSER_WORKER_ARGUMENT: &str = "--browser-worker";
const BROWSER_SANDBOX_WORKER: &str = "/runtime/mealy-browser-worker";
const BROWSER_SANDBOX_BUNDLE: &str = "/browser";
const BROWSER_SANDBOX_EXECUTABLE: &str = "/browser/chrome-headless-shell";
const BROWSER_SANDBOX_PROFILE: &str = "/profile";
const BROWSER_SANDBOX_DOWNLOADS: &str = "/profile/mealy-downloads";
const BROWSER_SANDBOX_PROXY: &str = "/run/mealy/browser-proxy.sock";
const BROWSER_CALL_TIMEOUT: Duration = Duration::from_secs(30);
const BROWSER_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const BROWSER_IO_TIMEOUT: Duration = Duration::from_millis(250);
const BROWSER_POLL_INTERVAL: Duration = Duration::from_millis(10);
const BROWSER_SHUTDOWN_GRACE: Duration = Duration::from_millis(500);
const BROWSER_MAXIMUM_WORKER_INPUT_BYTES: usize = 64 * 1024;
const BROWSER_MAXIMUM_WORKER_OUTPUT_BYTES: usize = 1024 * 1024;
const BROWSER_MAXIMUM_STDERR_BYTES: usize = 64 * 1024;
const BROWSER_MAXIMUM_PROXY_HEADER_BYTES: usize = 32 * 1024;
const BROWSER_MAXIMUM_CONCURRENT_PROXY_CONNECTIONS: usize = 32;
const BROWSER_MAXIMUM_PROXY_CONNECTIONS_PER_CALL: usize = 256;
const BROWSER_MAXIMUM_PROXY_BYTES: u64 = 16 * 1024 * 1024;
const BROWSER_MAXIMUM_CDP_MESSAGE_BYTES: usize = 1024 * 1024;
const BROWSER_MAXIMUM_CDP_MESSAGES: usize = 4096;
const BROWSER_MAXIMUM_CDP_COMMANDS: u64 = 4096;
const BROWSER_MAXIMUM_DOWNLOAD_BYTES: u64 = 512 * 1024;
const BROWSER_MAXIMUM_CONCURRENT_RELAY_CONNECTIONS: usize = 32;
const BROWSER_MAXIMUM_RELAY_CONNECTIONS_PER_CALL: usize = 256;

struct BrowserConnectionLease {
    active: Arc<AtomicUsize>,
}

impl Drop for BrowserConnectionLease {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn reserve_browser_connection(
    active: &Arc<AtomicUsize>,
    accepted: &mut usize,
    maximum_concurrent: usize,
    maximum_accepted: usize,
) -> Option<BrowserConnectionLease> {
    if *accepted >= maximum_accepted || active.fetch_add(1, Ordering::AcqRel) >= maximum_concurrent
    {
        if *accepted < maximum_accepted {
            active.fetch_sub(1, Ordering::AcqRel);
        }
        return None;
    }
    *accepted += 1;
    Some(BrowserConnectionLease {
        active: Arc::clone(active),
    })
}

fn reap_finished_threads(threads: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < threads.len() {
        if threads[index].is_finished() {
            let thread = threads.swap_remove(index);
            let _ = thread.join();
        } else {
            index += 1;
        }
    }
}

const BROWSER_READ_ONLY_BOOTSTRAP: &str = r"(() => {
  const denied = () => { throw new DOMException('Blocked by Mealy read-only browser policy', 'SecurityError'); };
  try { Object.defineProperty(globalThis, 'open', {value: denied, writable: false, configurable: false}); } catch (_) {}
  for (const name of ['WebSocket', 'EventSource']) {
    try { Object.defineProperty(globalThis, name, {value: class { constructor() { denied(); } }, writable: false, configurable: false}); } catch (_) {}
  }
  try { Object.defineProperty(navigator, 'sendBeacon', {value: () => false, writable: false, configurable: false}); } catch (_) {}
  try {
    const originalFetch = globalThis.fetch.bind(globalThis);
    Object.defineProperty(globalThis, 'fetch', {value: (input, init = {}) => {
      const method = String(init.method || (input && input.method) || 'GET').toUpperCase();
      return method === 'GET' || method === 'HEAD' ? originalFetch(input, init) : Promise.reject(new DOMException('Blocked by Mealy read-only browser policy', 'SecurityError'));
    }, writable: false, configurable: false});
  } catch (_) {}
  try {
    const originalOpen = XMLHttpRequest.prototype.open;
    Object.defineProperty(XMLHttpRequest.prototype, 'open', {value: function(method, ...rest) {
      const normalized = String(method || 'GET').toUpperCase();
      if (normalized !== 'GET' && normalized !== 'HEAD') denied();
      return originalOpen.call(this, normalized, ...rest);
    }, writable: false, configurable: false});
  } catch (_) {}
  try { Object.defineProperty(HTMLFormElement.prototype, 'submit', {value: denied, writable: false, configurable: false}); } catch (_) {}
  try { Object.defineProperty(HTMLFormElement.prototype, 'requestSubmit', {value: denied, writable: false, configurable: false}); } catch (_) {}
  try {
    document.addEventListener('submit', event => {
      event.preventDefault();
      event.stopImmediatePropagation();
    }, true);
  } catch (_) {}
  try {
    const Button = HTMLButtonElement;
    const nativeClick = HTMLElement.prototype.click;
    const type = Object.getOwnPropertyDescriptor(HTMLButtonElement.prototype, 'type').get;
    const form = Object.getOwnPropertyDescriptor(HTMLButtonElement.prototype, 'form').get;
    const disabled = Object.getOwnPropertyDescriptor(HTMLButtonElement.prototype, 'disabled').get;
    Object.defineProperty(globalThis, '__mealyActivateReadOnlyButton', {
      value: element => {
        try {
          if (!(element instanceof Button) || type.call(element) !== 'button' || form.call(element) !== null || disabled.call(element)) return false;
          nativeClick.call(element);
          return true;
        } catch (_) { return false; }
      },
      writable: false,
      configurable: false
    });
  } catch (_) {}
  try {
    const Input = HTMLInputElement;
    const Textarea = HTMLTextAreaElement;
    const inputType = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'type').get;
    const inputName = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'name').get;
    const inputForm = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'form').get;
    const inputDisabled = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'disabled').get;
    const inputReadOnly = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'readOnly').get;
    const inputValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    const textareaName = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'name').get;
    const textareaForm = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'form').get;
    const textareaDisabled = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'disabled').get;
    const textareaReadOnly = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'readOnly').get;
    const textareaValue = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
    const formAction = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, 'action').get;
    const formMethod = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, 'method').get;
    const formTarget = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, 'target').get;
    Object.defineProperty(globalThis, '__mealyFillReadOnlyTextControl', {
      value: (element, value) => {
        try {
          let kind;
          let type;
          let name;
          let form;
          if (element instanceof Input) {
            type = String(inputType.call(element)).toLowerCase();
            if (!['text', 'search', 'email', 'url', 'tel'].includes(type) || inputDisabled.call(element) || inputReadOnly.call(element)) return null;
            inputValue.call(element, String(value));
            kind = 'input';
            name = String(inputName.call(element));
            form = inputForm.call(element);
          } else if (element instanceof Textarea) {
            if (textareaDisabled.call(element) || textareaReadOnly.call(element)) return null;
            textareaValue.call(element, String(value));
            kind = 'textarea';
            type = 'textarea';
            name = String(textareaName.call(element));
            form = textareaForm.call(element);
          } else {
            return null;
          }
          return {
            kind,
            type,
            name,
            form: form === null ? null : {
              action: String(formAction.call(form)),
              method: String(formMethod.call(form)).toLowerCase(),
              target: String(formTarget.call(form))
            }
          };
        } catch (_) { return null; }
      },
      writable: false,
      configurable: false
    });
  } catch (_) {}
})();";

struct NeverCancelled;

impl CancellationProbe for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// Sandboxed, non-mutating identity evidence for one reviewed browser bundle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserRuntimeProbe {
    bundle_digest: String,
    executable_digest: String,
    product: String,
    protocol_version: String,
}

impl BrowserRuntimeProbe {
    /// Complete canonical bundle inventory digest.
    #[must_use]
    pub fn bundle_digest(&self) -> &str {
        &self.bundle_digest
    }

    /// Exact Chrome Headless Shell executable digest.
    #[must_use]
    pub fn executable_digest(&self) -> &str {
        &self.executable_digest
    }

    /// Exact product identity expected from CDP after translating the isolated version banner.
    #[must_use]
    pub fn product(&self) -> &str {
        &self.product
    }

    /// Stable CDP protocol revision required by the adapter.
    #[must_use]
    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }
}

/// Inspects and executes only `chrome-headless-shell --version` inside a no-network Bubblewrap
/// namespace, returning content and runtime identity without granting model authority.
///
/// # Errors
///
/// Fails closed for bundle drift, untrusted Bubblewrap, malformed version output, nonzero status,
/// stderr, timeout, or unsupported host.
pub fn probe_browser_bundle_product(
    bubblewrap_path: &Path,
    bundle_path: &Path,
    expected_bundle_digest: Option<&str>,
) -> Result<BrowserRuntimeProbe, BrowserHostError> {
    if !cfg!(target_os = "linux") {
        return Err(BrowserHostError::UnsupportedHost);
    }
    let bubblewrap_path = exact_canonical_file(bubblewrap_path)?;
    if !is_trusted_system_executable(&bubblewrap_path) {
        return Err(BrowserHostError::UnsupportedHost);
    }
    let inspection = inspect_browser_bundle(bundle_path, expected_bundle_digest)
        .map_err(|_| BrowserHostError::IdentityMismatch)?;
    let mut child = browser_probe_command(&bubblewrap_path, &inspection)
        .spawn()
        .map_err(|_| BrowserHostError::ProcessFailed)?;
    let stdout = child.stdout.take().ok_or(BrowserHostError::ProcessFailed)?;
    let stderr = child.stderr.take().ok_or(BrowserHostError::ProcessFailed)?;
    let stdout_thread = thread::spawn(move || read_bounded_stream(stdout, 256));
    let stderr_thread = thread::spawn(move || read_bounded_stream(stderr, 1024));
    let started = Instant::now();
    let status = loop {
        if started.elapsed() >= Duration::from_secs(5) {
            terminate_child(&mut child);
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(BrowserHostError::TimedOut);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(BROWSER_POLL_INTERVAL),
            Err(_) => {
                terminate_child(&mut child);
                return Err(BrowserHostError::ProcessFailed);
            }
        }
    };
    let stdout = stdout_thread
        .join()
        .map_err(|_| BrowserHostError::ProcessFailed)??;
    let stderr = stderr_thread
        .join()
        .map_err(|_| BrowserHostError::ProcessFailed)??;
    if !status.success() || !stderr.is_empty() {
        return Err(BrowserHostError::ProcessFailed);
    }
    let banner = std::str::from_utf8(&stdout)
        .map_err(|_| BrowserHostError::InvalidProtocol)?
        .strip_suffix('\n')
        .ok_or(BrowserHostError::InvalidProtocol)?;
    let version = banner
        .strip_prefix("Google Chrome for Testing ")
        .ok_or(BrowserHostError::InvalidProtocol)?;
    let product = format!("HeadlessChrome/{version}");
    BrowserConfig::new(
        false,
        format!("browser-runtimes/{}", inspection.bundle_digest()),
        inspection.bundle_digest().to_owned(),
        "chrome-headless-shell".to_owned(),
        inspection.executable_digest().to_owned(),
        product.clone(),
        BROWSER_CDP_PROTOCOL_VERSION.to_owned(),
    )
    .map_err(|_| BrowserHostError::InvalidProtocol)?;
    let reproduced = inspect_browser_bundle(inspection.root(), Some(inspection.bundle_digest()))
        .map_err(|_| BrowserHostError::IdentityMismatch)?;
    if reproduced.executable_digest() != inspection.executable_digest() {
        return Err(BrowserHostError::IdentityMismatch);
    }
    Ok(BrowserRuntimeProbe {
        bundle_digest: inspection.bundle_digest().to_owned(),
        executable_digest: inspection.executable_digest().to_owned(),
        product,
        protocol_version: BROWSER_CDP_PROTOCOL_VERSION.to_owned(),
    })
}

/// Starts a fresh fully isolated browser against a temporary exact loopback origin and verifies
/// CDP identity, navigation, proxying, rendering, and accessibility normalization end to end.
///
/// # Errors
///
/// Returns [`BrowserHostError`] if any installed identity or runtime boundary fails closed.
pub fn verify_browser_runtime_installation(
    home: &Path,
    bubblewrap_path: &Path,
    worker_path: &Path,
    config: &BrowserConfig,
) -> Result<(), BrowserHostError> {
    let origin = BrowserVerificationOrigin::start()?;
    let web = WebAccessConfig {
        enabled: true,
        allow_public_internet: false,
        allowed_domains: Vec::new(),
        allowed_origins: vec![format!("http://{}", origin.address)],
        search: None,
    };
    let tool = BrowserReadTool::load(
        home,
        bubblewrap_path,
        worker_path,
        config.with_enabled(true),
        web,
    )?;
    let request = validate_browser_snapshot_arguments(&json!({
        "url": format!("http://{}/", origin.address),
        "maximumTextBytes": 4096,
        "maximumElements": 8,
        "captureScreenshot": false
    }))
    .map_err(|_| BrowserHostError::InvalidConfiguration)?;
    let result = tool.run(request, &NeverCancelled)?;
    if result.get("title").and_then(Value::as_str) != Some("Mealy browser verification")
        || result
            .get("text")
            .and_then(Value::as_str)
            .is_none_or(|text| !text.contains("isolated rendered evidence"))
        || result.get("browserProduct").and_then(Value::as_str) != Some(config.product())
    {
        return Err(BrowserHostError::InvalidProtocol);
    }
    drop(origin);
    Ok(())
}

struct BrowserVerificationOrigin {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl BrowserVerificationOrigin {
    fn start() -> Result<Self, BrowserHostError> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(io_error)?;
        listener.set_nonblocking(true).map_err(io_error)?;
        let address = listener.local_addr().map_err(io_error)?;
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let active = Arc::new(AtomicUsize::new(0));
            let mut accepted = 0;
            let mut connections = Vec::new();
            while !server_stop.load(Ordering::Acquire) {
                reap_finished_threads(&mut connections);
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let Some(connection) = reserve_browser_connection(
                            &active,
                            &mut accepted,
                            BROWSER_MAXIMUM_CONCURRENT_PROXY_CONNECTIONS,
                            BROWSER_MAXIMUM_PROXY_CONNECTIONS_PER_CALL,
                        ) else {
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
                        };
                        connections.push(thread::spawn(move || {
                            let _connection = connection;
                            serve_browser_verification(&mut stream);
                        }));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(BROWSER_POLL_INTERVAL);
                    }
                    Err(_) => break,
                }
            }
            for connection in connections {
                let _ = connection.join();
            }
        });
        Ok(Self {
            address,
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for BrowserVerificationOrigin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_browser_verification(stream: &mut TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let mut request = [0_u8; 8192];
    let Ok(read) = stream.read(&mut request) else {
        return;
    };
    if !request[..read].starts_with(b"GET ") {
        return;
    }
    let body = "<!doctype html><title>Mealy browser verification</title><main>isolated rendered evidence</main>";
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn browser_probe_command(bubblewrap_path: &Path, inspection: &BrowserBundleInspection) -> Command {
    let mut command = Command::new(bubblewrap_path);
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
        "mealy-browser-probe",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
    ]);
    for (source, target) in browser_runtime_mounts() {
        command.arg("--ro-bind").arg(source).arg(target);
    }
    command
        .arg("--ro-bind")
        .arg(inspection.root())
        .arg(BROWSER_SANDBOX_BUNDLE)
        .arg("--chdir")
        .arg("/tmp")
        .arg("--")
        .arg(BROWSER_SANDBOX_EXECUTABLE)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// One startup-verified rendered-browser read tool. Every invocation uses a fresh browser process,
/// fresh profile, private network namespace, and scoped host proxy.
pub struct BrowserReadTool {
    descriptor: ReadToolDescriptor,
    config: BrowserConfig,
    web_config: Arc<WebAccessConfig>,
    bundle_path: PathBuf,
    bubblewrap_path: PathBuf,
    worker_path: PathBuf,
    worker_digest: String,
    calls_root: PathBuf,
    invocation_count: AtomicUsize,
}

impl std::fmt::Debug for BrowserReadTool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowserReadTool")
            .field("descriptor", &self.descriptor)
            .field("config", &self.config)
            .field("bundle_path", &self.bundle_path)
            .field("bubblewrap_path", &self.bubblewrap_path)
            .field("worker_path", &self.worker_path)
            .field("invocation_count", &self.invocation_count())
            .finish_non_exhaustive()
    }
}

impl BrowserReadTool {
    /// Loads one enabled content-pinned Chrome Headless Shell bundle.
    ///
    /// # Errors
    ///
    /// Fails closed when web authority is disabled, paths are redirected, bundle or worker bytes
    /// drift, Bubblewrap is not trusted, or descriptor evidence is invalid.
    pub fn load(
        home: &Path,
        bubblewrap_path: &Path,
        worker_path: &Path,
        config: BrowserConfig,
        web_config: WebAccessConfig,
    ) -> Result<Self, BrowserHostError> {
        if !cfg!(target_os = "linux") {
            return Err(BrowserHostError::UnsupportedHost);
        }
        config
            .validate()
            .map_err(|_| BrowserHostError::InvalidConfiguration)?;
        web_config
            .validate()
            .map_err(|_| BrowserHostError::InvalidConfiguration)?;
        if !config.enabled() || !web_config.enabled {
            return Err(BrowserHostError::InvalidConfiguration);
        }
        let home = exact_canonical_directory(home)?;
        let bundle_path = exact_canonical_directory(&home.join(config.bundle_path()))?;
        if !bundle_path.starts_with(&home) {
            return Err(BrowserHostError::InvalidConfiguration);
        }
        let inspection = inspect_browser_bundle(&bundle_path, Some(config.bundle_digest()))
            .map_err(|_| BrowserHostError::IdentityMismatch)?;
        if inspection.executable_digest() != config.executable_digest() {
            return Err(BrowserHostError::IdentityMismatch);
        }
        let bubblewrap_path = exact_canonical_file(bubblewrap_path)?;
        if !is_trusted_system_executable(&bubblewrap_path) {
            return Err(BrowserHostError::UnsupportedHost);
        }
        let worker_path = exact_canonical_file(worker_path)?;
        let worker_digest = digest_file(&worker_path)?;
        let calls_root = create_private_directory(&home.join("runtime/browser-calls"))?;
        let descriptor =
            browser_snapshot_descriptor().map_err(|_| BrowserHostError::InvalidConfiguration)?;
        descriptor
            .validate_evidence()
            .map_err(|_| BrowserHostError::InvalidConfiguration)?;
        Ok(Self {
            descriptor,
            config,
            web_config: Arc::new(web_config),
            bundle_path,
            bubblewrap_path,
            worker_path,
            worker_digest,
            calls_root,
            invocation_count: AtomicUsize::new(0),
        })
    }

    /// Number of calls that reached the process adapter in this daemon process.
    #[must_use]
    pub fn invocation_count(&self) -> usize {
        self.invocation_count.load(Ordering::SeqCst)
    }

    fn verify_identity(&self) -> Result<(), BrowserHostError> {
        if digest_file(&self.worker_path)? != self.worker_digest {
            return Err(BrowserHostError::IdentityMismatch);
        }
        let inspection =
            inspect_browser_bundle(&self.bundle_path, Some(self.config.bundle_digest()))
                .map_err(|_| BrowserHostError::IdentityMismatch)?;
        if inspection.executable_digest() != self.config.executable_digest() {
            return Err(BrowserHostError::IdentityMismatch);
        }
        Ok(())
    }

    fn run(
        &self,
        request: BrowserSnapshotRequest,
        cancellation: &dyn CancellationProbe,
    ) -> Result<Value, BrowserHostError> {
        self.verify_identity()?;
        let initial_url =
            Url::parse(request.url()).map_err(|_| BrowserHostError::InvalidConfiguration)?;
        resolve_pinned_web_destination(&initial_url, &self.web_config)
            .map_err(|_| BrowserHostError::DestinationDenied)?;
        if cancellation.is_cancelled() {
            return Err(BrowserHostError::Cancelled);
        }
        let call = BrowserCallDirectory::create(&self.calls_root)?;
        let proxy = BrowserProxy::start(
            call.proxy_path(),
            Arc::clone(&self.web_config),
            initial_url.origin().ascii_serialization(),
            cancellation,
        )?;
        let worker_request = BrowserWorkerRequest {
            request,
            expected_product: self.config.product().to_owned(),
            expected_protocol_version: self.config.protocol_version().to_owned(),
        };
        let input =
            serde_json::to_vec(&worker_request).map_err(|_| BrowserHostError::InvalidProtocol)?;
        if input.len() > BROWSER_MAXIMUM_WORKER_INPUT_BYTES {
            return Err(BrowserHostError::OutputLimitExceeded);
        }
        let mut child = self.spawn_worker(&call)?;
        child
            .stdin
            .take()
            .ok_or(BrowserHostError::ProcessFailed)?
            .write_all(&input)
            .map_err(|_| BrowserHostError::ProcessFailed)?;
        let stdout = child.stdout.take().ok_or(BrowserHostError::ProcessFailed)?;
        let stderr = child.stderr.take().ok_or(BrowserHostError::ProcessFailed)?;
        let stdout_thread =
            thread::spawn(move || read_bounded_stream(stdout, BROWSER_MAXIMUM_WORKER_OUTPUT_BYTES));
        let stderr_thread =
            thread::spawn(move || read_bounded_stream(stderr, BROWSER_MAXIMUM_STDERR_BYTES));
        let started = Instant::now();
        let status = loop {
            if cancellation.is_cancelled() {
                terminate_child(&mut child);
                drop(proxy);
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(BrowserHostError::Cancelled);
            }
            if started.elapsed() >= BROWSER_CALL_TIMEOUT {
                terminate_child(&mut child);
                drop(proxy);
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(BrowserHostError::TimedOut);
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => thread::sleep(BROWSER_POLL_INTERVAL),
                Err(_) => {
                    terminate_child(&mut child);
                    return Err(BrowserHostError::ProcessFailed);
                }
            }
        };
        drop(proxy);
        let output = stdout_thread
            .join()
            .map_err(|_| BrowserHostError::ProcessFailed)??;
        let stderr = stderr_thread
            .join()
            .map_err(|_| BrowserHostError::ProcessFailed)??;
        if !status.success() || !stderr.is_empty() {
            return Err(BrowserHostError::ProcessFailed);
        }
        let envelope = serde_json::from_slice::<BrowserWorkerResponse>(&output)
            .map_err(|_| BrowserHostError::InvalidProtocol)?;
        match (envelope.result, envelope.error, envelope.error_stage) {
            (Some(result), None, None) => Ok(result),
            (None, Some(error), Some(stage)) => Err(error.into_host_error(stage)),
            _ => Err(BrowserHostError::InvalidProtocol),
        }
    }

    fn spawn_worker(&self, call: &BrowserCallDirectory) -> Result<Child, BrowserHostError> {
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
            "mealy-browser",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/runtime",
            "--dir",
            "/run",
            "--dir",
            "/run/mealy",
        ]);
        for (source, target) in browser_runtime_mounts() {
            command.arg("--ro-bind").arg(source).arg(target);
        }
        command
            .arg("--ro-bind")
            .arg(&self.worker_path)
            .arg(BROWSER_SANDBOX_WORKER)
            .arg("--ro-bind")
            .arg(&self.bundle_path)
            .arg(BROWSER_SANDBOX_BUNDLE)
            .arg("--bind")
            .arg(call.profile_path())
            .arg(BROWSER_SANDBOX_PROFILE)
            .arg("--bind")
            .arg(call.proxy_path())
            .arg(BROWSER_SANDBOX_PROXY)
            .arg("--setenv")
            .arg("HOME")
            .arg(BROWSER_SANDBOX_PROFILE)
            .arg("--setenv")
            .arg("LANG")
            .arg("C.UTF-8")
            .arg("--chdir")
            .arg(BROWSER_SANDBOX_PROFILE)
            .arg("--")
            .arg(BROWSER_SANDBOX_WORKER)
            .arg(BROWSER_WORKER_ARGUMENT)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| BrowserHostError::ProcessFailed)
    }
}

impl ReadOnlyTool for BrowserReadTool {
    fn descriptor(&self) -> ReadToolDescriptor {
        self.descriptor.clone()
    }

    fn validate_arguments(&self, arguments: &Value) -> Result<(), ReadToolError> {
        validate_browser_snapshot_arguments(arguments).map(|_| ())
    }

    fn execute(
        &self,
        arguments: &Value,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ReadToolOutput, ReadToolError> {
        self.invocation_count.fetch_add(1, Ordering::SeqCst);
        let request = validate_browser_snapshot_arguments(arguments)?;
        let source_locator = request.url().to_owned();
        let result = self
            .run(request, cancellation)
            .map_err(|error| map_browser_read_error(&error))?;
        let output_validator =
            jsonschema::validator_for(&self.descriptor.output_schema).map_err(|_| {
                ReadToolError::Unavailable("browser output schema is invalid".to_owned())
            })?;
        if !output_validator.is_valid(&result) {
            return Err(ReadToolError::Unavailable(
                "isolated browser output failed schema validation".to_owned(),
            ));
        }
        let bytes = serde_json::to_vec(&result)
            .map_err(|_| ReadToolError::Unavailable("browser output encoding failed".to_owned()))?;
        let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if actual > self.descriptor.maximum_output_bytes {
            return Err(ReadToolError::OutputTooLarge {
                actual,
                maximum: self.descriptor.maximum_output_bytes,
            });
        }
        Ok(ReadToolOutput {
            media_type: "application/json".to_owned(),
            bytes,
            source_locator,
        })
    }
}

fn map_browser_read_error(error: &BrowserHostError) -> ReadToolError {
    match error {
        BrowserHostError::Cancelled => ReadToolError::Cancelled,
        BrowserHostError::OutputLimitExceeded => ReadToolError::OutputTooLarge {
            actual: 1024 * 1024 + 1,
            maximum: 1024 * 1024,
        },
        BrowserHostError::DestinationDenied => ReadToolError::InvalidArguments(
            "browser URL is outside configured web authority".to_owned(),
        ),
        BrowserHostError::TimedOut => {
            ReadToolError::Unavailable("browser call timed out".to_owned())
        }
        BrowserHostError::BrowserStartTimedOut => {
            ReadToolError::Unavailable("isolated browser startup timed out".to_owned())
        }
        BrowserHostError::CdpTimedOut => {
            ReadToolError::Unavailable("isolated browser CDP command timed out".to_owned())
        }
        BrowserHostError::PageLoadTimedOut => {
            ReadToolError::Unavailable("isolated browser page load timed out".to_owned())
        }
        BrowserHostError::IdentityMismatch => {
            ReadToolError::Unavailable("browser runtime identity changed".to_owned())
        }
        BrowserHostError::InvalidConfiguration | BrowserHostError::UnsupportedHost => {
            ReadToolError::Unavailable("isolated browser runtime is unavailable".to_owned())
        }
        BrowserHostError::InvalidProtocol => {
            ReadToolError::Unavailable("isolated browser protocol validation failed".to_owned())
        }
        BrowserHostError::InvalidProtocolAt(stage) => ReadToolError::Unavailable(format!(
            "isolated browser protocol validation failed at {stage}"
        )),
        BrowserHostError::InvalidDownloadProtocol => ReadToolError::Unavailable(
            "isolated browser download protocol validation failed".to_owned(),
        ),
        BrowserHostError::ProcessFailed => {
            ReadToolError::Unavailable("isolated browser process failed".to_owned())
        }
        BrowserHostError::Io(_) => {
            ReadToolError::Unavailable("isolated browser host I/O failed".to_owned())
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrowserWorkerRequest {
    request: BrowserSnapshotRequest,
    expected_product: String,
    expected_protocol_version: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrowserWorkerResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<BrowserWorkerFailure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_stage: Option<BrowserWorkerStage>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum BrowserWorkerStage {
    Request,
    Configuration,
    Initialization,
    InitialNavigation,
    InitialWait,
    LinkAccessibilityTree,
    LinkElementLookup,
    LinkDestination,
    LinkNavigation,
    LinkWait,
    ElementAccessibilityTree,
    ElementLookup,
    ElementLinkDestination,
    ElementLinkNavigation,
    ElementButtonResolution,
    ElementButtonInvocation,
    ElementWait,
    ElementFill,
    Download,
    DocumentIdentity,
    AccessibilityTree,
    AccessibilityNormalization,
    Screenshot,
    ResultEncoding,
}

impl BrowserWorkerStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Configuration => "configuration",
            Self::Initialization => "initialization",
            Self::InitialNavigation => "initial_navigation",
            Self::InitialWait => "initial_wait",
            Self::LinkAccessibilityTree => "link_accessibility_tree",
            Self::LinkElementLookup => "link_element_lookup",
            Self::LinkDestination => "link_destination",
            Self::LinkNavigation => "link_navigation",
            Self::LinkWait => "link_wait",
            Self::ElementAccessibilityTree => "element_accessibility_tree",
            Self::ElementLookup => "element_lookup",
            Self::ElementLinkDestination => "element_link_destination",
            Self::ElementLinkNavigation => "element_link_navigation",
            Self::ElementButtonResolution => "element_button_resolution",
            Self::ElementButtonInvocation => "element_button_invocation",
            Self::ElementWait => "element_wait",
            Self::ElementFill => "element_fill",
            Self::Download => "download",
            Self::DocumentIdentity => "document_identity",
            Self::AccessibilityTree => "accessibility_tree",
            Self::AccessibilityNormalization => "accessibility_normalization",
            Self::Screenshot => "screenshot",
            Self::ResultEncoding => "result_encoding",
        }
    }
}

#[derive(Debug)]
struct BrowserWorkerExecutionError {
    source: BrowserHostError,
    stage: BrowserWorkerStage,
}

fn worker_error(
    stage: BrowserWorkerStage,
    source: BrowserHostError,
) -> BrowserWorkerExecutionError {
    BrowserWorkerExecutionError { source, stage }
}

fn at_browser_stage<T>(
    stage: BrowserWorkerStage,
    result: Result<T, BrowserHostError>,
) -> Result<T, BrowserWorkerExecutionError> {
    result.map_err(|error| worker_error(stage, error))
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum BrowserWorkerFailure {
    InvalidConfiguration,
    UnsupportedHost,
    IdentityMismatch,
    DestinationDenied,
    InvalidProtocol,
    InvalidDownloadProtocol,
    TimedOut,
    BrowserStartTimedOut,
    CdpTimedOut,
    PageLoadTimedOut,
    Cancelled,
    OutputLimitExceeded,
    ProcessFailed,
    Io,
}

impl BrowserWorkerFailure {
    const fn from_host_error(error: &BrowserHostError) -> Self {
        match error {
            BrowserHostError::InvalidConfiguration => Self::InvalidConfiguration,
            BrowserHostError::UnsupportedHost => Self::UnsupportedHost,
            BrowserHostError::IdentityMismatch => Self::IdentityMismatch,
            BrowserHostError::DestinationDenied => Self::DestinationDenied,
            BrowserHostError::InvalidProtocol | BrowserHostError::InvalidProtocolAt(_) => {
                Self::InvalidProtocol
            }
            BrowserHostError::InvalidDownloadProtocol => Self::InvalidDownloadProtocol,
            BrowserHostError::TimedOut => Self::TimedOut,
            BrowserHostError::BrowserStartTimedOut => Self::BrowserStartTimedOut,
            BrowserHostError::CdpTimedOut => Self::CdpTimedOut,
            BrowserHostError::PageLoadTimedOut => Self::PageLoadTimedOut,
            BrowserHostError::Cancelled => Self::Cancelled,
            BrowserHostError::OutputLimitExceeded => Self::OutputLimitExceeded,
            BrowserHostError::ProcessFailed => Self::ProcessFailed,
            BrowserHostError::Io(_) => Self::Io,
        }
    }

    fn into_host_error(self, stage: BrowserWorkerStage) -> BrowserHostError {
        match self {
            Self::InvalidConfiguration => BrowserHostError::InvalidConfiguration,
            Self::UnsupportedHost => BrowserHostError::UnsupportedHost,
            Self::IdentityMismatch => BrowserHostError::IdentityMismatch,
            Self::DestinationDenied => BrowserHostError::DestinationDenied,
            Self::InvalidProtocol => BrowserHostError::InvalidProtocolAt(stage.as_str().to_owned()),
            Self::InvalidDownloadProtocol => BrowserHostError::InvalidDownloadProtocol,
            Self::TimedOut => BrowserHostError::TimedOut,
            Self::BrowserStartTimedOut => BrowserHostError::BrowserStartTimedOut,
            Self::CdpTimedOut => BrowserHostError::CdpTimedOut,
            Self::PageLoadTimedOut => BrowserHostError::PageLoadTimedOut,
            Self::Cancelled => BrowserHostError::Cancelled,
            Self::OutputLimitExceeded => BrowserHostError::OutputLimitExceeded,
            Self::ProcessFailed => BrowserHostError::ProcessFailed,
            Self::Io => BrowserHostError::Io("isolated worker I/O failed".to_owned()),
        }
    }
}

/// Failure at the isolated rendered-browser boundary.
#[derive(Debug, Error)]
pub enum BrowserHostError {
    /// Durable runtime configuration is malformed or inconsistent.
    #[error("browser runtime configuration is invalid")]
    InvalidConfiguration,
    /// The host cannot enforce the Linux namespace boundary.
    #[error("isolated browser runtime requires trusted Linux Bubblewrap")]
    UnsupportedHost,
    /// Browser bundle or trusted worker bytes changed.
    #[error("browser runtime identity changed")]
    IdentityMismatch,
    /// Destination falls outside owner-granted network authority.
    #[error("browser destination is outside configured authority")]
    DestinationDenied,
    /// Worker/CDP framing or normalized output is invalid.
    #[error("browser protocol response is invalid")]
    InvalidProtocol,
    /// Worker protocol validation failed at one fixed internal boundary stage.
    #[error("browser protocol response is invalid at {0}")]
    InvalidProtocolAt(String),
    /// Download-specific CDP framing or normalized evidence is invalid.
    #[error("browser download protocol response is invalid")]
    InvalidDownloadProtocol,
    /// Wall-clock deadline elapsed.
    #[error("browser call timed out")]
    TimedOut,
    /// Chrome did not publish its private CDP endpoint within the startup deadline.
    #[error("isolated browser startup timed out")]
    BrowserStartTimedOut,
    /// A bounded Chrome `DevTools` Protocol command did not complete.
    #[error("isolated browser CDP command timed out")]
    CdpTimedOut,
    /// The page did not emit its load event within the navigation deadline.
    #[error("isolated browser page load timed out")]
    PageLoadTimedOut,
    /// Durable cancellation was observed.
    #[error("browser call was cancelled")]
    Cancelled,
    /// Browser, proxy, protocol, or result exceeded a hard bound.
    #[error("browser output exceeded its bound")]
    OutputLimitExceeded,
    /// Isolated process failed without exposing its stderr to the model.
    #[error("isolated browser process failed")]
    ProcessFailed,
    /// Bounded local filesystem or socket operation failed.
    #[error("browser host I/O failed: {0}")]
    Io(String),
}

struct BrowserCallDirectory {
    root: PathBuf,
    profile: PathBuf,
    proxy: PathBuf,
}

impl BrowserCallDirectory {
    fn create(calls_root: &Path) -> Result<Self, BrowserHostError> {
        for _ in 0..16 {
            let mut random = [0_u8; 12];
            getrandom::fill(&mut random)
                .map_err(|_| BrowserHostError::Io("random source unavailable".to_owned()))?;
            let name = encode_hex(&random);
            let root = calls_root.join(name);
            match fs::create_dir(&root) {
                Ok(()) => {
                    #[cfg(unix)]
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                        .map_err(io_error)?;
                    let profile = root.join("profile");
                    fs::create_dir(&profile).map_err(io_error)?;
                    #[cfg(unix)]
                    fs::set_permissions(&profile, fs::Permissions::from_mode(0o700))
                        .map_err(io_error)?;
                    return Ok(Self {
                        proxy: root.join("proxy.sock"),
                        root,
                        profile,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        Err(BrowserHostError::Io(
            "could not allocate private browser call directory".to_owned(),
        ))
    }

    fn profile_path(&self) -> &Path {
        &self.profile
    }

    fn proxy_path(&self) -> &Path {
        &self.proxy
    }
}

impl Drop for BrowserCallDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct BrowserProxy {
    stop: Arc<AtomicBool>,
    socket_path: PathBuf,
    thread: Option<JoinHandle<()>>,
}

impl BrowserProxy {
    #[cfg(unix)]
    fn start(
        socket_path: &Path,
        config: Arc<WebAccessConfig>,
        allowed_origin: String,
        _cancellation: &dyn CancellationProbe,
    ) -> Result<Self, BrowserHostError> {
        let listener = UnixListener::bind(socket_path).map_err(io_error)?;
        listener.set_nonblocking(true).map_err(io_error)?;
        #[cfg(unix)]
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600)).map_err(io_error)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let bytes = Arc::new(AtomicU64::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let thread = thread::spawn(move || {
            let mut connections = Vec::new();
            let mut accepted = 0;
            while !thread_stop.load(Ordering::Acquire) {
                reap_finished_threads(&mut connections);
                match listener.accept() {
                    Ok((stream, _)) => {
                        let Some(connection) = reserve_browser_connection(
                            &active,
                            &mut accepted,
                            BROWSER_MAXIMUM_CONCURRENT_PROXY_CONNECTIONS,
                            BROWSER_MAXIMUM_PROXY_CONNECTIONS_PER_CALL,
                        ) else {
                            thread_stop.store(true, Ordering::Release);
                            let _ = stream.shutdown(Shutdown::Both);
                            break;
                        };
                        let connection_stop = Arc::clone(&thread_stop);
                        let connection_config = Arc::clone(&config);
                        let connection_origin = allowed_origin.clone();
                        let connection_bytes = Arc::clone(&bytes);
                        connections.push(thread::spawn(move || {
                            let _connection = connection;
                            let _ = handle_proxy_connection(
                                stream,
                                &connection_config,
                                &connection_origin,
                                &connection_stop,
                                &connection_bytes,
                            );
                        }));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(BROWSER_POLL_INTERVAL);
                    }
                    Err(_) => {
                        thread_stop.store(true, Ordering::Release);
                        break;
                    }
                }
            }
            for connection in connections {
                let _ = connection.join();
            }
        });
        Ok(Self {
            stop,
            socket_path: socket_path.to_owned(),
            thread: Some(thread),
        })
    }

    #[cfg(not(unix))]
    fn start(
        _socket_path: &Path,
        _config: Arc<WebAccessConfig>,
        _allowed_origin: String,
        _cancellation: &dyn CancellationProbe,
    ) -> Result<Self, BrowserHostError> {
        Err(BrowserHostError::UnsupportedHost)
    }
}

impl Drop for BrowserProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        #[cfg(unix)]
        {
            let _ = UnixStream::connect(&self.socket_path);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.socket_path);
    }
}

#[cfg(unix)]
fn handle_proxy_connection(
    mut client: UnixStream,
    config: &WebAccessConfig,
    allowed_origin: &str,
    stop: &Arc<AtomicBool>,
    transferred: &Arc<AtomicU64>,
) -> Result<(), BrowserHostError> {
    client
        .set_read_timeout(Some(BROWSER_IO_TIMEOUT))
        .map_err(io_error)?;
    client
        .set_write_timeout(Some(BROWSER_IO_TIMEOUT))
        .map_err(io_error)?;
    let header = read_proxy_header(&mut client, stop)?;
    let header_text = std::str::from_utf8(&header).map_err(|_| BrowserHostError::ProcessFailed)?;
    let mut lines = header_text[..header_text.len().saturating_sub(4)].split("\r\n");
    let request_line = lines.next().ok_or(BrowserHostError::ProcessFailed)?;
    let fields = request_line.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 3 || fields[2] != "HTTP/1.1" {
        write_proxy_error(&mut client, 400, "Bad Request");
        return Err(BrowserHostError::ProcessFailed);
    }
    let method = fields[0];
    let target = fields[1];
    let headers = parse_proxy_headers(lines)?;
    if headers.contains_key("proxy-authorization")
        || headers.contains_key("transfer-encoding")
        || headers
            .get("content-length")
            .is_some_and(|value| value != "0")
    {
        write_proxy_error(&mut client, 403, "Forbidden");
        return Err(BrowserHostError::DestinationDenied);
    }
    if method == "CONNECT" {
        let url = connect_target_url(target)?;
        let mut remote = connect_authorized(&url, config, allowed_origin)?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n")
            .map_err(io_error)?;
        relay_proxy_tunnel(&mut client, &mut remote, stop, transferred)
    } else if matches!(method, "GET" | "HEAD") {
        let url = Url::parse(target).map_err(|_| BrowserHostError::DestinationDenied)?;
        if !matches!(url.scheme(), "http" | "https") || url.scheme() != "http" {
            write_proxy_error(&mut client, 403, "Forbidden");
            return Err(BrowserHostError::DestinationDenied);
        }
        let mut remote = connect_authorized(&url, config, allowed_origin)?;
        let path = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };
        let origin_target = url
            .query()
            .map_or_else(|| path.to_owned(), |query| format!("{path}?{query}"));
        let authority = url
            .host_str()
            .map(|host| match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_owned(),
            })
            .ok_or(BrowserHostError::DestinationDenied)?;
        write!(
            remote,
            "{method} {origin_target} HTTP/1.1\r\nHost: {authority}\r\n"
        )
        .map_err(io_error)?;
        for (name, value) in headers {
            if !matches!(
                name.as_str(),
                "host"
                    | "connection"
                    | "proxy-connection"
                    | "proxy-authorization"
                    | "content-length"
                    | "transfer-encoding"
            ) {
                write!(remote, "{name}: {value}\r\n").map_err(io_error)?;
            }
        }
        remote
            .write_all(b"Connection: close\r\n\r\n")
            .map_err(io_error)?;
        copy_bounded(&mut remote, &mut client, stop, transferred)
    } else {
        write_proxy_error(&mut client, 405, "Method Not Allowed");
        Err(BrowserHostError::DestinationDenied)
    }
}

#[cfg(unix)]
fn read_proxy_header(
    stream: &mut UnixStream,
    stop: &AtomicBool,
) -> Result<Vec<u8>, BrowserHostError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 2048];
    loop {
        if stop.load(Ordering::Acquire) {
            return Err(BrowserHostError::Cancelled);
        }
        match stream.read(&mut buffer) {
            Ok(0) => return Err(BrowserHostError::ProcessFailed),
            Ok(read) => {
                bytes.extend_from_slice(&buffer[..read]);
                if bytes.len() > BROWSER_MAXIMUM_PROXY_HEADER_BYTES {
                    return Err(BrowserHostError::OutputLimitExceeded);
                }
                if bytes.ends_with(b"\r\n\r\n") {
                    return Ok(bytes);
                }
                if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                    return Err(BrowserHostError::ProcessFailed);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(io_error(error)),
        }
    }
}

fn parse_proxy_headers<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> Result<BTreeMap<String, String>, BrowserHostError> {
    let mut result = BTreeMap::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or(BrowserHostError::ProcessFailed)?;
        let name = name.to_ascii_lowercase();
        let value = value.trim().to_owned();
        if name.is_empty()
            || value.len() > 8192
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value.chars().any(char::is_control)
            || result.insert(name, value).is_some()
        {
            return Err(BrowserHostError::ProcessFailed);
        }
    }
    Ok(result)
}

fn connect_target_url(target: &str) -> Result<Url, BrowserHostError> {
    if target.is_empty()
        || target.len() > 512
        || target.contains('/')
        || target.contains('@')
        || target.chars().any(char::is_control)
    {
        return Err(BrowserHostError::DestinationDenied);
    }
    Url::parse(&format!("https://{target}/")).map_err(|_| BrowserHostError::DestinationDenied)
}

fn connect_authorized(
    url: &Url,
    config: &WebAccessConfig,
    allowed_origin: &str,
) -> Result<TcpStream, BrowserHostError> {
    if url.origin().ascii_serialization() != allowed_origin {
        return Err(BrowserHostError::DestinationDenied);
    }
    let addresses = resolve_pinned_web_destination(url, config)
        .map_err(|_| BrowserHostError::DestinationDenied)?;
    for address in addresses {
        if let Ok(stream) = TcpStream::connect_timeout(&address, BROWSER_CONNECT_TIMEOUT) {
            if stream.peer_addr().ok() != Some(address) {
                continue;
            }
            stream
                .set_read_timeout(Some(BROWSER_IO_TIMEOUT))
                .map_err(io_error)?;
            stream
                .set_write_timeout(Some(BROWSER_IO_TIMEOUT))
                .map_err(io_error)?;
            return Ok(stream);
        }
    }
    Err(BrowserHostError::ProcessFailed)
}

#[cfg(unix)]
fn relay_proxy_tunnel(
    client: &mut UnixStream,
    remote: &mut TcpStream,
    global_stop: &Arc<AtomicBool>,
    transferred: &Arc<AtomicU64>,
) -> Result<(), BrowserHostError> {
    let local_stop = Arc::new(AtomicBool::new(false));
    let mut client_reader = client.try_clone().map_err(io_error)?;
    let mut remote_writer = remote.try_clone().map_err(io_error)?;
    let outgoing_global = Arc::clone(global_stop);
    let outgoing_local = Arc::clone(&local_stop);
    let outgoing_bytes = Arc::clone(transferred);
    let outgoing = thread::spawn(move || {
        copy_bounded_with_local_stop(
            &mut client_reader,
            &mut remote_writer,
            &outgoing_global,
            &outgoing_local,
            &outgoing_bytes,
        )
    });
    let incoming =
        copy_bounded_with_local_stop(remote, client, global_stop, &local_stop, transferred);
    local_stop.store(true, Ordering::Release);
    let _ = client.shutdown(Shutdown::Both);
    let _ = remote.shutdown(Shutdown::Both);
    let outgoing = outgoing
        .join()
        .map_err(|_| BrowserHostError::ProcessFailed)?;
    match (incoming, outgoing) {
        (Err(error), _) | (_, Err(error)) => Err(error),
        _ => Ok(()),
    }
}

fn copy_bounded(
    source: &mut impl Read,
    destination: &mut impl Write,
    stop: &AtomicBool,
    transferred: &AtomicU64,
) -> Result<(), BrowserHostError> {
    let local = AtomicBool::new(false);
    copy_bounded_with_local_stop(source, destination, stop, &local, transferred)
}

fn copy_bounded_with_local_stop(
    source: &mut impl Read,
    destination: &mut impl Write,
    global_stop: &AtomicBool,
    local_stop: &AtomicBool,
    transferred: &AtomicU64,
) -> Result<(), BrowserHostError> {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        if global_stop.load(Ordering::Acquire) || local_stop.load(Ordering::Acquire) {
            return Ok(());
        }
        match source.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => {
                let total = transferred
                    .fetch_add(u64::try_from(read).unwrap_or(u64::MAX), Ordering::AcqRel)
                    .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
                if total > BROWSER_MAXIMUM_PROXY_BYTES {
                    global_stop.store(true, Ordering::Release);
                    return Err(BrowserHostError::OutputLimitExceeded);
                }
                destination.write_all(&buffer[..read]).map_err(io_error)?;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(io_error(error)),
        }
    }
}

#[cfg(unix)]
fn write_proxy_error(stream: &mut UnixStream, status: u16, reason: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
}

/// Enters the fixed browser worker after Bubblewrap created the namespace.
///
/// Applications embedding the browser adapter must dispatch this before normal CLI parsing when
/// their first argument is `--browser-worker`.
#[cfg(target_os = "linux")]
#[must_use]
pub fn browser_worker_main() -> std::process::ExitCode {
    use rustix::process::{Resource, Rlimit, setrlimit};

    if std::env::args().nth(1).as_deref() != Some(BROWSER_WORKER_ARGUMENT) {
        return std::process::ExitCode::from(64);
    }
    let limits = [
        (Resource::Core, 0),
        (Resource::Fsize, 64 * 1024 * 1024),
        (Resource::Nofile, 256),
        (Resource::Nproc, 256),
        (Resource::Cpu, 30),
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
    let response = (|| {
        let mut input = Vec::new();
        io::stdin()
            .take(u64::try_from(BROWSER_MAXIMUM_WORKER_INPUT_BYTES + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut input)
            .map_err(|_| {
                worker_error(BrowserWorkerStage::Request, BrowserHostError::ProcessFailed)
            })?;
        if input.is_empty() || input.len() > BROWSER_MAXIMUM_WORKER_INPUT_BYTES {
            return Err(worker_error(
                BrowserWorkerStage::Request,
                BrowserHostError::OutputLimitExceeded,
            ));
        }
        let request = serde_json::from_slice::<BrowserWorkerRequest>(&input).map_err(|_| {
            worker_error(
                BrowserWorkerStage::Request,
                BrowserHostError::InvalidProtocol,
            )
        })?;
        run_browser_worker(&request)
    })();
    let envelope = match response {
        Ok(result) => BrowserWorkerResponse {
            result: Some(result),
            error: None,
            error_stage: None,
        },
        Err(error) => BrowserWorkerResponse {
            result: None,
            error: Some(BrowserWorkerFailure::from_host_error(&error.source)),
            error_stage: Some(error.stage),
        },
    };
    let Ok(bytes) = serde_json::to_vec(&envelope) else {
        return std::process::ExitCode::from(70);
    };
    if bytes.len() > BROWSER_MAXIMUM_WORKER_OUTPUT_BYTES
        || io::stdout().write_all(&bytes).is_err()
        || io::stdout().flush().is_err()
    {
        return std::process::ExitCode::from(70);
    }
    std::process::ExitCode::SUCCESS
}

/// Reports unsupported worker use on non-Linux systems.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn browser_worker_main() -> std::process::ExitCode {
    std::process::ExitCode::from(69)
}

#[cfg(unix)]
fn run_browser_worker(
    request: &BrowserWorkerRequest,
) -> Result<Value, BrowserWorkerExecutionError> {
    if request.expected_protocol_version != BROWSER_CDP_PROTOCOL_VERSION
        || request.expected_product.is_empty()
        || request.expected_product.len() > 128
        || request.expected_product.chars().any(char::is_control)
    {
        return Err(worker_error(
            BrowserWorkerStage::Configuration,
            BrowserHostError::InvalidConfiguration,
        ));
    }
    let (relay, mut browser, mut cdp, session) = at_browser_stage(
        BrowserWorkerStage::Initialization,
        initialize_browser_session(request),
    )?;
    at_browser_stage(
        BrowserWorkerStage::InitialNavigation,
        navigate_and_wait(&mut cdp, &session, request.request.url()),
    )?;
    at_browser_stage(
        BrowserWorkerStage::InitialWait,
        cdp.pump_for(Duration::from_millis(request.request.wait_ms())),
    )?;
    let actions = perform_browser_actions(&mut cdp, &session, &request.request)?;
    let document = at_browser_stage(
        BrowserWorkerStage::DocumentIdentity,
        document_identity(&mut cdp, &session),
    )?;
    at_browser_stage(
        BrowserWorkerStage::DocumentIdentity,
        validate_document_origin(request.request.url(), &document.url),
    )?;
    let tree = at_browser_stage(
        BrowserWorkerStage::AccessibilityTree,
        accessibility_tree(&mut cdp, &session),
    )?;
    let normalized = at_browser_stage(
        BrowserWorkerStage::AccessibilityNormalization,
        normalize_accessibility_tree(
            &tree,
            request.request.maximum_text_bytes(),
            request.request.maximum_elements(),
        ),
    )?;
    let screenshot = if request.request.capture_screenshot() {
        Some(at_browser_stage(
            BrowserWorkerStage::Screenshot,
            capture_screenshot(&mut cdp, &session),
        )?)
    } else {
        None
    };
    let result = json!({
        "activatedElement": actions.activated_element,
        "browserProduct": request.expected_product.as_str(),
        "download": actions.download,
        "elements": normalized.elements,
        "filledElement": actions.filled_element,
        "finalUrl": document.url,
        "followedLink": actions.followed_link,
        "protocolVersion": request.expected_protocol_version.as_str(),
        "screenshot": screenshot,
        "sourceLocator": request.request.url(),
        "text": normalized.text,
        "title": document.title,
        "truncatedElements": normalized.truncated_elements,
        "truncatedText": normalized.truncated_text,
    });
    let encoded = serde_json::to_vec(&result).map_err(|_| {
        worker_error(
            BrowserWorkerStage::ResultEncoding,
            BrowserHostError::InvalidProtocol,
        )
    })?;
    if encoded.len() > BROWSER_MAXIMUM_WORKER_OUTPUT_BYTES {
        return Err(worker_error(
            BrowserWorkerStage::ResultEncoding,
            BrowserHostError::OutputLimitExceeded,
        ));
    }
    cdp.close_browser();
    browser.shutdown();
    drop(relay);
    Ok(result)
}

fn validate_document_origin(initial_url: &str, final_url: &str) -> Result<(), BrowserHostError> {
    let initial_origin = Url::parse(initial_url)
        .map_err(|_| BrowserHostError::InvalidConfiguration)?
        .origin()
        .ascii_serialization();
    let final_origin = Url::parse(final_url)
        .map_err(|_| BrowserHostError::InvalidProtocol)?
        .origin()
        .ascii_serialization();
    if final_origin != initial_origin {
        return Err(BrowserHostError::DestinationDenied);
    }
    Ok(())
}

struct BrowserActionResults {
    followed_link: Option<Value>,
    activated_element: Option<Value>,
    filled_element: Option<Value>,
    download: Option<Value>,
}

fn perform_browser_actions(
    cdp: &mut CdpClient,
    session: &str,
    request: &BrowserSnapshotRequest,
) -> Result<BrowserActionResults, BrowserWorkerExecutionError> {
    let followed_link = follow_requested_link(cdp, session, request)?;
    let activated_element = activate_requested_element(cdp, session, request)?;
    let filled_element = at_browser_stage(
        BrowserWorkerStage::ElementFill,
        fill_requested_element(cdp, session, request),
    )?;
    let download = at_browser_stage(
        BrowserWorkerStage::Download,
        download_requested_link(cdp, session, request).map_err(|error| match error {
            BrowserHostError::InvalidProtocol | BrowserHostError::InvalidProtocolAt(_) => {
                BrowserHostError::InvalidDownloadProtocol
            }
            other => other,
        }),
    )?;
    Ok(BrowserActionResults {
        followed_link,
        activated_element,
        filled_element,
        download,
    })
}

#[cfg(unix)]
fn initialize_browser_session(
    request: &BrowserWorkerRequest,
) -> Result<(LocalProxyRelay, BrowserChild, CdpClient, String), BrowserHostError> {
    let relay = LocalProxyRelay::start(Path::new(BROWSER_SANDBOX_PROXY))?;
    let browser = BrowserChild::spawn(relay.address())?;
    let (port, path) = wait_for_devtools_endpoint(Path::new(BROWSER_SANDBOX_PROFILE))?;
    let stream = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        BROWSER_CONNECT_TIMEOUT,
    )
    .map_err(|_| BrowserHostError::ProcessFailed)?;
    stream
        .set_read_timeout(Some(BROWSER_IO_TIMEOUT))
        .map_err(io_error)?;
    stream
        .set_write_timeout(Some(BROWSER_IO_TIMEOUT))
        .map_err(io_error)?;
    let websocket_url = format!("ws://127.0.0.1:{port}{path}");
    let (websocket, _) = tungstenite::client(websocket_url, stream)
        .map_err(|_| BrowserHostError::InvalidProtocol)?;
    let mut cdp = CdpClient::new(websocket);
    let version = cdp.command("Browser.getVersion", json!({}), None)?;
    if version.get("product").and_then(Value::as_str) != Some(request.expected_product.as_str())
        || version.get("protocolVersion").and_then(Value::as_str)
            != Some(request.expected_protocol_version.as_str())
    {
        return Err(BrowserHostError::IdentityMismatch);
    }
    let target = cdp.command(
        "Target.createTarget",
        json!({"url": "about:blank", "newWindow": false, "background": false}),
        None,
    )?;
    let target_id = target
        .get("targetId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or(BrowserHostError::InvalidProtocol)?;
    let attached = cdp.command(
        "Target.attachToTarget",
        json!({"targetId": target_id, "flatten": true}),
        None,
    )?;
    let session = attached
        .get("sessionId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or(BrowserHostError::InvalidProtocol)?
        .to_owned();
    cdp.command(
        "Browser.setDownloadBehavior",
        json!({"behavior": "deny", "eventsEnabled": false}),
        None,
    )?;
    for (method, params) in [
        ("Page.enable", json!({})),
        ("Runtime.enable", json!({})),
        ("DOM.enable", json!({})),
        ("Accessibility.enable", json!({})),
        ("Network.enable", json!({"maxTotalBufferSize": 1_048_576})),
        ("Network.setCacheDisabled", json!({"cacheDisabled": true})),
        (
            "Network.setBlockedURLs",
            json!({"urls": ["ws://*", "wss://*", "ftp://*", "file://*"]}),
        ),
        ("Page.setLifecycleEventsEnabled", json!({"enabled": true})),
        (
            "Page.addScriptToEvaluateOnNewDocument",
            json!({"source": BROWSER_READ_ONLY_BOOTSTRAP}),
        ),
        (
            "Emulation.setDeviceMetricsOverride",
            json!({
                "width": 1280,
                "height": 720,
                "deviceScaleFactor": 1,
                "mobile": false
            }),
        ),
        (
            "Fetch.enable",
            json!({
                "patterns": [{"urlPattern": "*", "requestStage": "Request"}],
                "handleAuthRequests": true
            }),
        ),
    ] {
        cdp.command(method, params, Some(&session))?;
    }
    Ok((relay, browser, cdp, session))
}

fn follow_requested_link(
    cdp: &mut CdpClient,
    session: &str,
    request: &BrowserSnapshotRequest,
) -> Result<Option<Value>, BrowserWorkerExecutionError> {
    let Some(target) = request.follow_link() else {
        return Ok(None);
    };
    let tree = at_browser_stage(
        BrowserWorkerStage::LinkAccessibilityTree,
        accessibility_tree(cdp, session),
    )?;
    let backend_node_id = at_browser_stage(
        BrowserWorkerStage::LinkElementLookup,
        exact_element_backend_node(&tree, "link", target.name(), target.occurrence()),
    )?;
    let destination = at_browser_stage(
        BrowserWorkerStage::LinkDestination,
        exact_link_destination(cdp, session, backend_node_id, request.url()),
    )?;
    at_browser_stage(
        BrowserWorkerStage::LinkNavigation,
        navigate_and_wait(cdp, session, destination.as_str()),
    )?;
    at_browser_stage(
        BrowserWorkerStage::LinkWait,
        cdp.pump_for(Duration::from_millis(request.wait_ms())),
    )?;
    Ok(Some(json!({
        "name": target.name(),
        "occurrence": target.occurrence(),
        "url": destination.as_str(),
    })))
}

fn activate_requested_element(
    cdp: &mut CdpClient,
    session: &str,
    request: &BrowserSnapshotRequest,
) -> Result<Option<Value>, BrowserWorkerExecutionError> {
    let Some(target) = request.activate_element() else {
        return Ok(None);
    };
    let tree = at_browser_stage(
        BrowserWorkerStage::ElementAccessibilityTree,
        accessibility_tree(cdp, session),
    )?;
    let backend_node_id = at_browser_stage(
        BrowserWorkerStage::ElementLookup,
        exact_element_backend_node(&tree, target.role(), target.name(), target.occurrence()),
    )?;
    if target.role() == "link" {
        let destination = at_browser_stage(
            BrowserWorkerStage::ElementLinkDestination,
            exact_link_destination(cdp, session, backend_node_id, request.url()),
        )?;
        at_browser_stage(
            BrowserWorkerStage::ElementLinkNavigation,
            navigate_and_wait(cdp, session, destination.as_str()),
        )?;
        at_browser_stage(
            BrowserWorkerStage::ElementWait,
            cdp.pump_for(Duration::from_millis(request.wait_ms())),
        )?;
    } else if target.role() == "button" {
        activate_form_free_button(cdp, session, backend_node_id)?;
        at_browser_stage(
            BrowserWorkerStage::ElementWait,
            cdp.pump_for(Duration::from_millis(request.wait_ms().max(250))),
        )?;
    } else {
        return Err(worker_error(
            BrowserWorkerStage::ElementLookup,
            BrowserHostError::InvalidConfiguration,
        ));
    }
    Ok(Some(json!({
        "name": target.name(),
        "occurrence": target.occurrence(),
        "role": target.role(),
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedBrowserFill {
    kind: String,
    r#type: String,
    name: String,
    form: Option<PreparedBrowserGetForm>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedBrowserGetForm {
    action: String,
    method: String,
    target: String,
}

fn fill_requested_element(
    cdp: &mut CdpClient,
    session: &str,
    request: &BrowserSnapshotRequest,
) -> Result<Option<Value>, BrowserHostError> {
    let Some(target) = request.fill_element() else {
        return Ok(None);
    };
    let tree = accessibility_tree(cdp, session)?;
    let backend_node_id =
        exact_element_backend_node(&tree, target.role(), target.name(), target.occurrence())?;
    let resolved = cdp.command(
        "DOM.resolveNode",
        json!({"backendNodeId": backend_node_id}),
        Some(session),
    )?;
    let object_id = resolved
        .get("object")
        .and_then(|object| object.get("objectId"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or(BrowserHostError::InvalidProtocol)?;
    let prepared = cdp.command(
        "Runtime.callFunctionOn",
        json!({
            "functionDeclaration": "function (value) { return globalThis.__mealyFillReadOnlyTextControl ? globalThis.__mealyFillReadOnlyTextControl(this, value) : null; }",
            "objectId": object_id,
            "arguments": [{"value": target.value()}],
            "returnByValue": true,
            "awaitPromise": false,
            "userGesture": false
        }),
        Some(session),
    )?;
    let prepared = prepared
        .get("result")
        .and_then(|result| result.get("value"))
        .cloned()
        .and_then(|value| serde_json::from_value::<PreparedBrowserFill>(value).ok())
        .filter(valid_prepared_browser_fill)
        .ok_or(BrowserHostError::DestinationDenied)?;
    let role_matches = match target.role() {
        "searchbox" => prepared.kind == "input" && prepared.r#type == "search",
        "textbox" => {
            prepared.kind == "textarea" || prepared.kind == "input" && prepared.r#type != "search"
        }
        _ => false,
    };
    if !role_matches {
        return Err(BrowserHostError::DestinationDenied);
    }
    let submitted_url = if target.submit_get_form() {
        let form = prepared
            .form
            .as_ref()
            .ok_or(BrowserHostError::DestinationDenied)?;
        let destination =
            exact_get_form_destination(request.url(), &prepared.name, target.value(), form)?;
        navigate_and_wait(cdp, session, destination.as_str())?;
        cdp.pump_for(Duration::from_millis(request.wait_ms()))?;
        Some(destination.to_string())
    } else {
        None
    };
    Ok(Some(json!({
        "name": target.name(),
        "occurrence": target.occurrence(),
        "role": target.role(),
        "submittedGetForm": target.submit_get_form(),
        "submittedUrl": submitted_url,
        "valueBytes": target.value().len(),
        "valueSha256Digest": sha256_digest(target.value().as_bytes()),
    })))
}

fn download_requested_link(
    cdp: &mut CdpClient,
    session: &str,
    request: &BrowserSnapshotRequest,
) -> Result<Option<Value>, BrowserHostError> {
    let Some(target) = request.download_link() else {
        return Ok(None);
    };
    let tree = accessibility_tree(cdp, session)?;
    let backend_node_id =
        exact_element_backend_node(&tree, "link", target.name(), target.occurrence())?;
    let destination = exact_link_destination(cdp, session, backend_node_id, request.url())?;
    fs::create_dir(BROWSER_SANDBOX_DOWNLOADS).map_err(io_error)?;
    cdp.command(
        "Browser.setDownloadBehavior",
        json!({
            "behavior": "allowAndName",
            "downloadPath": BROWSER_SANDBOX_DOWNLOADS,
            "eventsEnabled": true
        }),
        None,
    )?;
    cdp.download = None;
    let navigation = cdp.command(
        "Page.navigate",
        json!({"url": destination.as_str(), "transitionType": "typed"}),
        Some(session),
    )?;
    if navigation.get("errorText").is_some()
        && navigation.get("isDownload").and_then(Value::as_bool) != Some(true)
    {
        return Err(BrowserHostError::ProcessFailed);
    }
    let completed = cdp.wait_for_download(Duration::from_secs(10))?;
    if completed.url != destination.as_str() {
        return Err(BrowserHostError::DestinationDenied);
    }
    let path = Path::new(BROWSER_SANDBOX_DOWNLOADS).join(&completed.guid);
    let bytes = read_browser_download(&path)?;
    Ok(Some(json!({
        "dataBase64": BASE64_STANDARD.encode(&bytes),
        "mediaType": "application/octet-stream",
        "sha256Digest": sha256_digest(&bytes),
        "sizeBytes": bytes.len(),
        "url": destination.as_str(),
    })))
}

fn read_browser_download(path: &Path) -> Result<Vec<u8>, BrowserHostError> {
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags, open};
        open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| BrowserHostError::InvalidProtocol)?
    };
    #[cfg(not(unix))]
    let mut file = OpenOptions::new().read(true).open(path).map_err(io_error)?;
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file() || metadata.len() > BROWSER_MAXIMUM_DOWNLOAD_BYTES {
        return Err(BrowserHostError::OutputLimitExceeded);
    }
    let mut bytes = Vec::new();
    file.take(BROWSER_MAXIMUM_DOWNLOAD_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > BROWSER_MAXIMUM_DOWNLOAD_BYTES {
        return Err(BrowserHostError::OutputLimitExceeded);
    }
    Ok(bytes)
}

fn valid_prepared_browser_fill(fill: &PreparedBrowserFill) -> bool {
    matches!(fill.kind.as_str(), "input" | "textarea")
        && matches!(
            fill.r#type.as_str(),
            "text" | "search" | "email" | "url" | "tel" | "textarea"
        )
        && fill.name.len() <= 256
        && !fill.name.chars().any(char::is_control)
        && fill.form.as_ref().is_none_or(|form| {
            form.action.len() <= 4_096
                && form.method.len() <= 16
                && form.target.len() <= 256
                && !form.action.chars().any(char::is_control)
                && !form.method.chars().any(char::is_control)
                && !form.target.chars().any(char::is_control)
        })
}

fn exact_get_form_destination(
    initial_url: &str,
    control_name: &str,
    value: &str,
    form: &PreparedBrowserGetForm,
) -> Result<Url, BrowserHostError> {
    if control_name.is_empty()
        || form.method != "get"
        || !matches!(form.target.as_str(), "" | "_self")
    {
        return Err(BrowserHostError::DestinationDenied);
    }
    let initial = Url::parse(initial_url).map_err(|_| BrowserHostError::InvalidConfiguration)?;
    let mut destination =
        Url::parse(&form.action).map_err(|_| BrowserHostError::DestinationDenied)?;
    destination.set_fragment(None);
    if !matches!(destination.scheme(), "http" | "https")
        || !destination.username().is_empty()
        || destination.password().is_some()
        || destination.host_str().is_none()
        || destination.origin() != initial.origin()
    {
        return Err(BrowserHostError::DestinationDenied);
    }
    destination
        .query_pairs_mut()
        .append_pair(control_name, value);
    if destination.as_str().len() > 4_096 {
        return Err(BrowserHostError::DestinationDenied);
    }
    Ok(destination)
}

fn exact_link_destination(
    cdp: &mut CdpClient,
    session: &str,
    backend_node_id: u64,
    initial_url: &str,
) -> Result<Url, BrowserHostError> {
    let described = cdp.command(
        "DOM.describeNode",
        json!({"backendNodeId": backend_node_id, "depth": 0, "pierce": false}),
        Some(session),
    )?;
    let href = node_attribute(&described, "href").ok_or(BrowserHostError::InvalidProtocol)?;
    let document = document_identity(cdp, session)?;
    let base = Url::parse(&document.url).map_err(|_| BrowserHostError::InvalidProtocol)?;
    let mut destination = base
        .join(&href)
        .map_err(|_| BrowserHostError::InvalidProtocol)?;
    destination.set_fragment(None);
    if !matches!(destination.scheme(), "http" | "https")
        || !destination.username().is_empty()
        || destination.password().is_some()
        || destination.host_str().is_none()
    {
        return Err(BrowserHostError::DestinationDenied);
    }
    let initial_origin = Url::parse(initial_url)
        .map_err(|_| BrowserHostError::InvalidConfiguration)?
        .origin()
        .ascii_serialization();
    if destination.origin().ascii_serialization() != initial_origin {
        return Err(BrowserHostError::DestinationDenied);
    }
    Ok(destination)
}

fn activate_form_free_button(
    cdp: &mut CdpClient,
    session: &str,
    backend_node_id: u64,
) -> Result<(), BrowserWorkerExecutionError> {
    let resolved = at_browser_stage(
        BrowserWorkerStage::ElementButtonResolution,
        cdp.command(
            "DOM.resolveNode",
            json!({"backendNodeId": backend_node_id}),
            Some(session),
        ),
    )?;
    let object_id = resolved
        .get("object")
        .and_then(|object| object.get("objectId"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or_else(|| {
            worker_error(
                BrowserWorkerStage::ElementButtonResolution,
                BrowserHostError::InvalidProtocol,
            )
        })?;
    let activated = at_browser_stage(
        BrowserWorkerStage::ElementButtonInvocation,
        cdp.command(
            "Runtime.callFunctionOn",
            json!({
                "functionDeclaration": "function () { return globalThis.__mealyActivateReadOnlyButton ? globalThis.__mealyActivateReadOnlyButton(this) : false; }",
                "objectId": object_id,
                "returnByValue": true,
                "awaitPromise": false,
                "userGesture": false
            }),
            Some(session),
        ),
    )?;
    if activated
        .get("result")
        .and_then(|result| result.get("value"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(worker_error(
            BrowserWorkerStage::ElementButtonInvocation,
            BrowserHostError::DestinationDenied,
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn run_browser_worker(
    _request: &BrowserWorkerRequest,
) -> Result<Value, BrowserWorkerExecutionError> {
    Err(worker_error(
        BrowserWorkerStage::Configuration,
        BrowserHostError::UnsupportedHost,
    ))
}

#[cfg(unix)]
struct LocalProxyRelay {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

#[cfg(unix)]
impl LocalProxyRelay {
    fn start(proxy_path: &Path) -> Result<Self, BrowserHostError> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(io_error)?;
        let address = listener.local_addr().map_err(io_error)?;
        listener.set_nonblocking(true).map_err(io_error)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let proxy_path = proxy_path.to_owned();
        let active = Arc::new(AtomicUsize::new(0));
        let bytes = Arc::new(AtomicU64::new(0));
        let thread = thread::spawn(move || {
            let mut connections = Vec::new();
            let mut accepted = 0;
            while !thread_stop.load(Ordering::Acquire) {
                reap_finished_threads(&mut connections);
                match listener.accept() {
                    Ok((tcp, _)) => {
                        let Some(connection) = reserve_browser_connection(
                            &active,
                            &mut accepted,
                            BROWSER_MAXIMUM_CONCURRENT_RELAY_CONNECTIONS,
                            BROWSER_MAXIMUM_RELAY_CONNECTIONS_PER_CALL,
                        ) else {
                            thread_stop.store(true, Ordering::Release);
                            let _ = tcp.shutdown(Shutdown::Both);
                            break;
                        };
                        let Ok(unix) = UnixStream::connect(&proxy_path) else {
                            thread_stop.store(true, Ordering::Release);
                            break;
                        };
                        let connection_stop = Arc::clone(&thread_stop);
                        let connection_bytes = Arc::clone(&bytes);
                        connections.push(thread::spawn(move || {
                            let _connection = connection;
                            let _ =
                                relay_local_proxy(tcp, unix, &connection_stop, &connection_bytes);
                        }));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(BROWSER_POLL_INTERVAL);
                    }
                    Err(_) => {
                        thread_stop.store(true, Ordering::Release);
                        break;
                    }
                }
            }
            for connection in connections {
                let _ = connection.join();
            }
        });
        Ok(Self {
            address,
            stop,
            thread: Some(thread),
        })
    }

    const fn address(&self) -> SocketAddr {
        self.address
    }
}

#[cfg(unix)]
impl Drop for LocalProxyRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(unix)]
fn relay_local_proxy(
    mut tcp: TcpStream,
    mut unix: UnixStream,
    global_stop: &Arc<AtomicBool>,
    transferred: &Arc<AtomicU64>,
) -> Result<(), BrowserHostError> {
    tcp.set_read_timeout(Some(BROWSER_IO_TIMEOUT))
        .map_err(io_error)?;
    tcp.set_write_timeout(Some(BROWSER_IO_TIMEOUT))
        .map_err(io_error)?;
    unix.set_read_timeout(Some(BROWSER_IO_TIMEOUT))
        .map_err(io_error)?;
    unix.set_write_timeout(Some(BROWSER_IO_TIMEOUT))
        .map_err(io_error)?;
    let local_stop = Arc::new(AtomicBool::new(false));
    let mut tcp_reader = tcp.try_clone().map_err(io_error)?;
    let mut unix_writer = unix.try_clone().map_err(io_error)?;
    let outgoing_global = Arc::clone(global_stop);
    let outgoing_local = Arc::clone(&local_stop);
    let outgoing_bytes = Arc::clone(transferred);
    let outgoing = thread::spawn(move || {
        copy_bounded_with_local_stop(
            &mut tcp_reader,
            &mut unix_writer,
            &outgoing_global,
            &outgoing_local,
            &outgoing_bytes,
        )
    });
    let incoming =
        copy_bounded_with_local_stop(&mut unix, &mut tcp, global_stop, &local_stop, transferred);
    local_stop.store(true, Ordering::Release);
    let _ = tcp.shutdown(Shutdown::Both);
    let _ = unix.shutdown(Shutdown::Both);
    let outgoing = outgoing
        .join()
        .map_err(|_| BrowserHostError::ProcessFailed)?;
    match (incoming, outgoing) {
        (Err(error), _) | (_, Err(error)) => Err(error),
        _ => Ok(()),
    }
}

struct BrowserChild {
    child: Child,
}

impl BrowserChild {
    fn spawn(proxy_address: SocketAddr) -> Result<Self, BrowserHostError> {
        let proxy = format!("http://{proxy_address}");
        let child = Command::new(BROWSER_SANDBOX_EXECUTABLE)
            .env_clear()
            .env("HOME", BROWSER_SANDBOX_PROFILE)
            .env("LANG", "C.UTF-8")
            .args([
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-quic",
                "--headless",
                "--hide-scrollbars",
                "--window-size=1280,720",
                "--remote-debugging-port=0",
                "--remote-debugging-address=127.0.0.1",
                "--user-data-dir=/profile",
                "--proxy-bypass-list=<-loopback>",
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-default-apps",
                "--disable-domain-reliability",
                "--disable-extensions",
                "--disable-sync",
                "--metrics-recording-only",
                "--no-first-run",
                "--no-default-browser-check",
                "--safebrowsing-disable-auto-update",
                "--password-store=basic",
                "--use-mock-keychain",
                "--disable-client-side-phishing-detection",
                "--disable-features=ServiceWorker,WebTransport,Translate,OptimizationHints,MediaRouter,DialMediaRouteProvider,AutofillServerCommunication",
            ])
            .arg(format!("--proxy-server={proxy}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| BrowserHostError::ProcessFailed)?;
        Ok(Self { child })
    }

    fn shutdown(&mut self) {
        let started = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if started.elapsed() < BROWSER_SHUTDOWN_GRACE => {
                    thread::sleep(BROWSER_POLL_INTERVAL);
                }
                Ok(None) | Err(_) => {
                    terminate_child(&mut self.child);
                    return;
                }
            }
        }
    }
}

impl Drop for BrowserChild {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn wait_for_devtools_endpoint(profile: &Path) -> Result<(u16, String), BrowserHostError> {
    let path = profile.join("DevToolsActivePort");
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
        if let Ok(file) = File::open(&path) {
            let mut lines = BufReader::new(file).lines();
            let port = lines
                .next()
                .transpose()
                .map_err(io_error)?
                .and_then(|line| line.parse::<u16>().ok());
            let websocket_path = lines.next().transpose().map_err(io_error)?;
            if let (Some(port), Some(websocket_path)) = (port, websocket_path)
                && port != 0
                && websocket_path.starts_with("/devtools/browser/")
                && websocket_path.len() <= 512
                && !websocket_path.chars().any(char::is_control)
            {
                return Ok((port, websocket_path));
            }
        }
        thread::sleep(BROWSER_POLL_INTERVAL);
    }
    Err(BrowserHostError::BrowserStartTimedOut)
}

struct CdpClient {
    websocket: WebSocket<TcpStream>,
    next_id: u64,
    ignored_responses: BTreeSet<u64>,
    messages: usize,
    load_seen: bool,
    download: Option<CdpDownload>,
}

#[derive(Clone, Debug)]
struct CdpDownload {
    guid: String,
    url: String,
    state: CdpDownloadState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CdpDownloadState {
    InProgress,
    Completed,
    Cancelled,
}

impl CdpClient {
    fn new(websocket: WebSocket<TcpStream>) -> Self {
        Self {
            websocket,
            next_id: 1,
            ignored_responses: BTreeSet::new(),
            messages: 0,
            load_seen: false,
            download: None,
        }
    }

    fn command(
        &mut self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
    ) -> Result<Value, BrowserHostError> {
        let id = self.send_command(method, params, session_id)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if Instant::now() >= deadline {
                return Err(BrowserHostError::CdpTimedOut);
            }
            if let Some(result) = self.read_and_dispatch(Some(id))? {
                return Ok(result);
            }
        }
    }

    fn send_command(
        &mut self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
    ) -> Result<u64, BrowserHostError> {
        if self.next_id > BROWSER_MAXIMUM_CDP_COMMANDS
            || method.is_empty()
            || method.len() > 128
            || method.chars().any(char::is_control)
        {
            return Err(BrowserHostError::OutputLimitExceeded);
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let mut object = Map::from_iter([
            ("id".to_owned(), Value::from(id)),
            ("method".to_owned(), Value::String(method.to_owned())),
            ("params".to_owned(), params),
        ]);
        if let Some(session_id) = session_id {
            object.insert("sessionId".to_owned(), Value::String(session_id.to_owned()));
        }
        let text = serde_json::to_string(&Value::Object(object))
            .map_err(|_| BrowserHostError::InvalidProtocol)?;
        if text.len() > BROWSER_MAXIMUM_CDP_MESSAGE_BYTES {
            return Err(BrowserHostError::OutputLimitExceeded);
        }
        self.websocket
            .send(Message::Text(text.into()))
            .map_err(|_| BrowserHostError::ProcessFailed)?;
        Ok(id)
    }

    fn read_and_dispatch(
        &mut self,
        expected_id: Option<u64>,
    ) -> Result<Option<Value>, BrowserHostError> {
        let message = match self.websocket.read() {
            Ok(message) => message,
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(_) => return Err(BrowserHostError::ProcessFailed),
        };
        self.messages = self.messages.saturating_add(1);
        if self.messages > BROWSER_MAXIMUM_CDP_MESSAGES {
            return Err(BrowserHostError::OutputLimitExceeded);
        }
        let text = match message {
            Message::Text(text) => text,
            Message::Ping(bytes) => {
                self.websocket
                    .send(Message::Pong(bytes))
                    .map_err(|_| BrowserHostError::ProcessFailed)?;
                return Ok(None);
            }
            Message::Pong(_) => return Ok(None),
            Message::Close(_) => return Err(BrowserHostError::ProcessFailed),
            Message::Binary(_) | Message::Frame(_) => {
                return Err(BrowserHostError::InvalidProtocol);
            }
        };
        if text.len() > BROWSER_MAXIMUM_CDP_MESSAGE_BYTES {
            return Err(BrowserHostError::OutputLimitExceeded);
        }
        let message =
            serde_json::from_str::<Value>(&text).map_err(|_| BrowserHostError::InvalidProtocol)?;
        let object = message
            .as_object()
            .ok_or(BrowserHostError::InvalidProtocol)?;
        if let Some(id) = object.get("id").and_then(Value::as_u64) {
            if self.ignored_responses.remove(&id) {
                return Ok(None);
            }
            if Some(id) != expected_id
                || object.get("result").is_some() == object.get("error").is_some()
            {
                return Err(BrowserHostError::InvalidProtocol);
            }
            return object
                .get("result")
                .cloned()
                .map(Some)
                .ok_or(BrowserHostError::ProcessFailed);
        }
        let method = object
            .get("method")
            .and_then(Value::as_str)
            .filter(|method| method.len() <= 256 && !method.chars().any(char::is_control))
            .ok_or(BrowserHostError::InvalidProtocol)?;
        if method == "Page.loadEventFired" {
            self.load_seen = true;
        } else if method == "Browser.downloadWillBegin" {
            self.handle_download_will_begin(object)?;
        } else if method == "Browser.downloadProgress" {
            self.handle_download_progress(object)?;
        } else if method == "Fetch.requestPaused" {
            self.handle_paused_request(object)?;
        } else if method == "Fetch.authRequired" {
            self.handle_auth_required(object)?;
        } else if matches!(
            method,
            "Network.webSocketCreated"
                | "Network.webTransportCreated"
                | "Network.directTCPSocketCreated"
                | "Network.directUDPSocketCreated"
        ) {
            return Err(BrowserHostError::DestinationDenied);
        }
        Ok(None)
    }

    fn handle_paused_request(
        &mut self,
        event: &Map<String, Value>,
    ) -> Result<(), BrowserHostError> {
        let params = event
            .get("params")
            .and_then(Value::as_object)
            .ok_or(BrowserHostError::InvalidProtocol)?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .ok_or(BrowserHostError::InvalidProtocol)?;
        let method = params
            .get("request")
            .and_then(|request| request.get("method"))
            .and_then(Value::as_str)
            .filter(|value| value.len() <= 32 && !value.chars().any(char::is_control))
            .ok_or(BrowserHostError::InvalidProtocol)?;
        let session_id = event.get("sessionId").and_then(Value::as_str);
        let (command, params) = if matches!(method, "GET" | "HEAD") {
            ("Fetch.continueRequest", json!({"requestId": request_id}))
        } else {
            (
                "Fetch.failRequest",
                json!({"requestId": request_id, "errorReason": "BlockedByClient"}),
            )
        };
        let id = self.send_command(command, params, session_id)?;
        self.ignored_responses.insert(id);
        Ok(())
    }

    fn handle_auth_required(&mut self, event: &Map<String, Value>) -> Result<(), BrowserHostError> {
        let request_id = event
            .get("params")
            .and_then(|params| params.get("requestId"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .ok_or(BrowserHostError::InvalidProtocol)?;
        let session_id = event.get("sessionId").and_then(Value::as_str);
        let id = self.send_command(
            "Fetch.continueWithAuth",
            json!({
                "requestId": request_id,
                "authChallengeResponse": {"response": "CancelAuth"}
            }),
            session_id,
        )?;
        self.ignored_responses.insert(id);
        Ok(())
    }

    fn handle_download_will_begin(
        &mut self,
        event: &Map<String, Value>,
    ) -> Result<(), BrowserHostError> {
        let params = event
            .get("params")
            .and_then(Value::as_object)
            .ok_or(BrowserHostError::InvalidProtocol)?;
        let guid = params
            .get("guid")
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 128
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
            .ok_or(BrowserHostError::InvalidProtocol)?;
        let url = params
            .get("url")
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty() && value.len() <= 4_096 && !value.chars().any(char::is_control)
            })
            .ok_or(BrowserHostError::InvalidProtocol)?;
        if self.download.is_some() {
            return Err(BrowserHostError::InvalidProtocol);
        }
        self.download = Some(CdpDownload {
            guid: guid.to_owned(),
            url: url.to_owned(),
            state: CdpDownloadState::InProgress,
        });
        Ok(())
    }

    fn handle_download_progress(
        &mut self,
        event: &Map<String, Value>,
    ) -> Result<(), BrowserHostError> {
        let params = event
            .get("params")
            .and_then(Value::as_object)
            .ok_or(BrowserHostError::InvalidProtocol)?;
        let guid = params
            .get("guid")
            .and_then(Value::as_str)
            .ok_or(BrowserHostError::InvalidProtocol)?;
        let received = cdp_nonnegative_integer(params.get("receivedBytes"))?;
        let total = cdp_nonnegative_integer(params.get("totalBytes"))?;
        if received > BROWSER_MAXIMUM_DOWNLOAD_BYTES
            || total > BROWSER_MAXIMUM_DOWNLOAD_BYTES
            || total != 0 && received > total
        {
            return Err(BrowserHostError::OutputLimitExceeded);
        }
        let state = match params.get("state").and_then(Value::as_str) {
            Some("inProgress") => CdpDownloadState::InProgress,
            Some("completed") => CdpDownloadState::Completed,
            Some("canceled") => CdpDownloadState::Cancelled,
            _ => return Err(BrowserHostError::InvalidProtocol),
        };
        let download = self
            .download
            .as_mut()
            .filter(|download| download.guid == guid)
            .ok_or(BrowserHostError::InvalidProtocol)?;
        download.state = state;
        Ok(())
    }

    fn wait_for_load(&mut self, timeout: Duration) -> Result<(), BrowserHostError> {
        let deadline = Instant::now() + timeout;
        while !self.load_seen {
            if Instant::now() >= deadline {
                return Err(BrowserHostError::PageLoadTimedOut);
            }
            let _ = self.read_and_dispatch(None)?;
        }
        Ok(())
    }

    fn pump_for(&mut self, duration: Duration) -> Result<(), BrowserHostError> {
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            let _ = self.read_and_dispatch(None)?;
        }
        Ok(())
    }

    fn wait_for_download(&mut self, timeout: Duration) -> Result<CdpDownload, BrowserHostError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(download) = &self.download {
                match download.state {
                    CdpDownloadState::Completed => return Ok(download.clone()),
                    CdpDownloadState::Cancelled => {
                        return Err(BrowserHostError::DestinationDenied);
                    }
                    CdpDownloadState::InProgress => {}
                }
            }
            if Instant::now() >= deadline {
                return Err(BrowserHostError::PageLoadTimedOut);
            }
            let _ = self.read_and_dispatch(None)?;
        }
    }

    fn close_browser(&mut self) {
        if let Ok(id) = self.send_command("Browser.close", json!({}), None) {
            self.ignored_responses.insert(id);
        }
    }
}

fn cdp_nonnegative_integer(value: Option<&Value>) -> Result<u64, BrowserHostError> {
    const MAXIMUM_EXACT_JSON_INTEGER: u64 = 9_007_199_254_740_991;
    const MAXIMUM_EXACT_JSON_INTEGER_FLOAT: f64 = 9_007_199_254_740_991.0;

    let value = value.ok_or(BrowserHostError::InvalidProtocol)?;
    if let Some(integer) = value.as_u64() {
        return (integer <= MAXIMUM_EXACT_JSON_INTEGER)
            .then_some(integer)
            .ok_or(BrowserHostError::InvalidProtocol);
    }
    let number = value.as_f64().ok_or(BrowserHostError::InvalidProtocol)?;
    if !number.is_finite()
        || number < 0.0
        || number.fract() != 0.0
        || number > MAXIMUM_EXACT_JSON_INTEGER_FLOAT
    {
        return Err(BrowserHostError::InvalidProtocol);
    }
    format!("{number:.0}")
        .parse::<u64>()
        .map_err(|_| BrowserHostError::InvalidProtocol)
}

fn navigate_and_wait(
    cdp: &mut CdpClient,
    session: &str,
    url: &str,
) -> Result<(), BrowserHostError> {
    cdp.load_seen = false;
    let navigation = cdp.command(
        "Page.navigate",
        json!({"url": url, "transitionType": "typed"}),
        Some(session),
    )?;
    if navigation.get("errorText").is_some() {
        return Err(BrowserHostError::ProcessFailed);
    }
    cdp.wait_for_load(Duration::from_secs(10))
}

fn accessibility_tree(cdp: &mut CdpClient, session: &str) -> Result<Value, BrowserHostError> {
    let tree = cdp.command(
        "Accessibility.getFullAXTree",
        json!({"depth": -1}),
        Some(session),
    )?;
    if tree
        .get("nodes")
        .and_then(Value::as_array)
        .is_none_or(|nodes| nodes.len() > 100_000)
    {
        return Err(BrowserHostError::InvalidProtocol);
    }
    Ok(tree)
}

fn exact_element_backend_node(
    tree: &Value,
    role: &str,
    name: &str,
    occurrence: usize,
) -> Result<u64, BrowserHostError> {
    let mut observed = 0_usize;
    for node in tree
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or(BrowserHostError::InvalidProtocol)?
    {
        if node.get("ignored").and_then(Value::as_bool) == Some(true)
            || ax_value(node, "role") != Some(role)
            || normalize_untrusted_text(ax_value(node, "name").unwrap_or_default()) != name
        {
            continue;
        }
        observed = observed.saturating_add(1);
        if observed == occurrence {
            return node
                .get("backendDOMNodeId")
                .and_then(Value::as_u64)
                .ok_or(BrowserHostError::InvalidProtocol);
        }
    }
    Err(BrowserHostError::InvalidProtocol)
}

fn node_attribute(described: &Value, name: &str) -> Option<String> {
    let attributes = described.get("node")?.get("attributes")?.as_array()?;
    if attributes.len() % 2 != 0 || attributes.len() > 2048 {
        return None;
    }
    attributes.chunks_exact(2).find_map(|pair| {
        (pair[0].as_str() == Some(name))
            .then(|| pair[1].as_str().map(str::to_owned))
            .flatten()
    })
}

struct DocumentIdentity {
    url: String,
    title: String,
}

fn document_identity(
    cdp: &mut CdpClient,
    session: &str,
) -> Result<DocumentIdentity, BrowserHostError> {
    let evaluated = cdp.command(
        "Runtime.evaluate",
        json!({
            "expression": "(() => ({url: String(document.location.href), title: String(document.title || '')}))()",
            "returnByValue": true,
            "awaitPromise": false,
            "userGesture": false,
        }),
        Some(session),
    )?;
    let value = evaluated
        .get("result")
        .and_then(|result| result.get("value"))
        .and_then(Value::as_object)
        .ok_or(BrowserHostError::InvalidProtocol)?;
    let mut url = Url::parse(
        value
            .get("url")
            .and_then(Value::as_str)
            .filter(|url| url.len() <= 4096)
            .ok_or(BrowserHostError::InvalidProtocol)?,
    )
    .map_err(|_| BrowserHostError::InvalidProtocol)?;
    url.set_fragment(None);
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return Err(BrowserHostError::InvalidProtocol);
    }
    let title = value
        .get("title")
        .and_then(Value::as_str)
        .filter(|title| title.len() <= 65_536)
        .ok_or(BrowserHostError::InvalidProtocol)?;
    let mut title = normalize_untrusted_text(title);
    truncate_utf8_to_bytes(&mut title, 4096);
    Ok(DocumentIdentity {
        url: url.to_string(),
        title,
    })
}

struct NormalizedAccessibility {
    text: String,
    elements: Vec<Value>,
    truncated_text: bool,
    truncated_elements: bool,
}

fn normalize_accessibility_tree(
    tree: &Value,
    maximum_text_bytes: usize,
    maximum_elements: usize,
) -> Result<NormalizedAccessibility, BrowserHostError> {
    let nodes = tree
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or(BrowserHostError::InvalidProtocol)?;
    let mut text = String::new();
    let mut truncated_text = false;
    let mut elements = Vec::new();
    let mut truncated_elements = false;
    let mut occurrences = BTreeMap::<(String, String), usize>::new();
    for node in nodes {
        if node.get("ignored").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let role = ax_value(node, "role").unwrap_or_default();
        let name = normalize_untrusted_text(ax_value(node, "name").unwrap_or_default());
        if role == "StaticText" && !name.is_empty() {
            append_bounded_text(&mut text, &name, maximum_text_bytes, &mut truncated_text);
        }
        if interactive_role(role) && !name.is_empty() && name.len() <= 1024 {
            let key = (role.to_owned(), name.clone());
            let occurrence = occurrences.entry(key).or_insert(0);
            *occurrence = occurrence.saturating_add(1);
            if elements.len() < maximum_elements {
                elements.push(json!({
                    "name": name,
                    "occurrence": *occurrence,
                    "role": role,
                }));
            } else {
                truncated_elements = true;
            }
        }
    }
    Ok(NormalizedAccessibility {
        text,
        elements,
        truncated_text,
        truncated_elements,
    })
}

fn ax_value<'a>(node: &'a Value, field: &str) -> Option<&'a str> {
    node.get(field)?.get("value")?.as_str()
}

fn interactive_role(role: &str) -> bool {
    matches!(
        role,
        "link"
            | "button"
            | "textbox"
            | "searchbox"
            | "checkbox"
            | "radio"
            | "combobox"
            | "menuitem"
            | "tab"
            | "switch"
            | "slider"
            | "option"
    )
}

fn append_bounded_text(output: &mut String, value: &str, maximum: usize, truncated: &mut bool) {
    let normalized = normalize_untrusted_text(value);
    if normalized.is_empty() {
        return;
    }
    let separator = usize::from(!output.is_empty());
    let available = maximum.saturating_sub(output.len().saturating_add(separator));
    if available == 0 {
        *truncated = true;
        return;
    }
    if separator == 1 {
        output.push('\n');
    }
    if normalized.len() <= available {
        output.push_str(&normalized);
    } else {
        let boundary = normalized
            .char_indices()
            .map(|(index, _)| index)
            .take_while(|index| *index <= available)
            .last()
            .unwrap_or(0);
        output.push_str(&normalized[..boundary]);
        *truncated = true;
    }
}

fn normalize_untrusted_text(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut pending_space = false;
    for character in value.chars() {
        if character.is_control() || character.is_whitespace() {
            pending_space = !normalized.is_empty();
        } else {
            if pending_space {
                normalized.push(' ');
                pending_space = false;
            }
            normalized.push(character);
        }
    }
    normalized
}

fn truncate_utf8_to_bytes(value: &mut String, maximum: usize) -> bool {
    if value.len() <= maximum {
        return false;
    }
    let mut boundary = maximum;
    while !value.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    value.truncate(boundary);
    true
}

fn capture_screenshot(cdp: &mut CdpClient, session: &str) -> Result<Value, BrowserHostError> {
    let captured = cdp.command(
        "Page.captureScreenshot",
        json!({
            "format": "png",
            "fromSurface": true,
            "captureBeyondViewport": false,
            "optimizeForSpeed": true,
        }),
        Some(session),
    )?;
    let encoded = captured
        .get("data")
        .and_then(Value::as_str)
        .ok_or(BrowserHostError::InvalidProtocol)?;
    let maximum = browser_maximum_screenshot_bytes();
    if encoded.len() > usize::try_from(maximum.saturating_mul(2)).unwrap_or(usize::MAX) {
        return Err(BrowserHostError::OutputLimitExceeded);
    }
    let bytes = BASE64_STANDARD
        .decode(encoded)
        .map_err(|_| BrowserHostError::InvalidProtocol)?;
    if bytes.len() < 8
        || bytes[..8] != *b"\x89PNG\r\n\x1a\n"
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum
    {
        return Err(BrowserHostError::OutputLimitExceeded);
    }
    Ok(json!({
        "dataBase64": encoded,
        "mediaType": "image/png",
        "sha256Digest": sha256_digest(&bytes),
        "sizeBytes": bytes.len(),
    }))
}

fn browser_runtime_mounts() -> Vec<(PathBuf, PathBuf)> {
    [
        "/usr/lib",
        "/usr/lib64",
        "/lib",
        "/lib64",
        "/usr/share/fonts",
        "/etc/fonts",
        "/etc/ssl/certs",
        "/usr/share/ca-certificates",
    ]
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

fn exact_canonical_directory(path: &Path) -> Result<PathBuf, BrowserHostError> {
    let canonical = fs::canonicalize(path).map_err(io_error)?;
    let metadata = fs::symlink_metadata(&canonical).map_err(io_error)?;
    if !metadata.is_dir() {
        return Err(BrowserHostError::InvalidConfiguration);
    }
    Ok(canonical)
}

fn exact_canonical_file(path: &Path) -> Result<PathBuf, BrowserHostError> {
    let canonical = fs::canonicalize(path).map_err(io_error)?;
    let metadata = fs::symlink_metadata(&canonical).map_err(io_error)?;
    if !metadata.is_file() {
        return Err(BrowserHostError::InvalidConfiguration);
    }
    Ok(canonical)
}

fn create_private_directory(path: &Path) -> Result<PathBuf, BrowserHostError> {
    fs::create_dir_all(path).map_err(io_error)?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    let canonical = exact_canonical_directory(path)?;
    if path.is_absolute() && canonical != path {
        return Err(BrowserHostError::InvalidConfiguration);
    }
    Ok(canonical)
}

fn digest_file(path: &Path) -> Result<String, BrowserHostError> {
    let mut file = OpenOptions::new().read(true).open(path).map_err(io_error)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer).map_err(io_error)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(encode_hex(&hasher.finalize()))
}

fn read_bounded_stream(stream: impl Read, maximum: usize) -> Result<Vec<u8>, BrowserHostError> {
    let mut bytes = Vec::new();
    stream
        .take(u64::try_from(maximum.saturating_add(1)).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > maximum {
        return Err(BrowserHostError::OutputLimitExceeded);
    }
    Ok(bytes)
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn io_error(error: io::Error) -> BrowserHostError {
    let message = error.to_string();
    drop(error);
    BrowserHostError::Io(message)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{
        BROWSER_MAXIMUM_CONCURRENT_PROXY_CONNECTIONS, BROWSER_MAXIMUM_PROXY_CONNECTIONS_PER_CALL,
        BrowserProxy, BrowserVerificationOrigin, NeverCancelled, cdp_nonnegative_integer,
        normalize_accessibility_tree, normalize_untrusted_text, reap_finished_threads,
        reserve_browser_connection, truncate_utf8_to_bytes,
    };
    use mealy_application::WebAccessConfig;
    use serde_json::json;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    #[cfg(unix)]
    #[test]
    fn proxy_stops_after_bounded_sequential_connection_churn() {
        use std::{
            io::{Read, Write},
            net::Shutdown,
            os::unix::net::UnixStream,
        };

        let directory = tempfile::tempdir().expect("proxy directory");
        let socket = directory.path().join("proxy.sock");
        let proxy = BrowserProxy::start(
            &socket,
            Arc::new(WebAccessConfig {
                enabled: true,
                allow_public_internet: true,
                ..WebAccessConfig::default()
            }),
            "https://example.com".to_owned(),
            &NeverCancelled,
        )
        .expect("proxy");

        for _ in 0..BROWSER_MAXIMUM_PROXY_CONNECTIONS_PER_CALL {
            let mut connection = UnixStream::connect(&socket).expect("bounded connection");
            connection
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("read timeout");
            connection
                .write_all(b"invalid request\r\n\r\n")
                .expect("invalid request");
            connection
                .shutdown(Shutdown::Write)
                .expect("request shutdown");
            let mut response = Vec::new();
            connection
                .read_to_end(&mut response)
                .expect("bounded rejection");
            assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
        }

        let mut excess = UnixStream::connect(&socket).expect("excess connection");
        excess
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        excess
            .write_all(b"invalid request\r\n\r\n")
            .expect("excess request");
        excess.shutdown(Shutdown::Write).expect("request shutdown");
        let mut response = Vec::new();
        match excess.read_to_end(&mut response) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(error) => panic!("bounded close failed: {error}"),
        }
        assert!(response.is_empty());
        assert!(proxy.stop.load(Ordering::Acquire));
    }

    #[test]
    fn proxy_connection_budget_caps_concurrency_and_total_churn() {
        let active = Arc::new(AtomicUsize::new(0));
        let mut accepted = 0;
        let leases = (0..BROWSER_MAXIMUM_CONCURRENT_PROXY_CONNECTIONS)
            .map(|_| {
                reserve_browser_connection(
                    &active,
                    &mut accepted,
                    BROWSER_MAXIMUM_CONCURRENT_PROXY_CONNECTIONS,
                    BROWSER_MAXIMUM_PROXY_CONNECTIONS_PER_CALL,
                )
                .expect("connection below both ceilings")
            })
            .collect::<Vec<_>>();
        assert!(
            reserve_browser_connection(
                &active,
                &mut accepted,
                BROWSER_MAXIMUM_CONCURRENT_PROXY_CONNECTIONS,
                BROWSER_MAXIMUM_PROXY_CONNECTIONS_PER_CALL,
            )
            .is_none()
        );
        assert_eq!(accepted, BROWSER_MAXIMUM_CONCURRENT_PROXY_CONNECTIONS);
        drop(leases);

        while accepted < BROWSER_MAXIMUM_PROXY_CONNECTIONS_PER_CALL {
            drop(
                reserve_browser_connection(
                    &active,
                    &mut accepted,
                    BROWSER_MAXIMUM_CONCURRENT_PROXY_CONNECTIONS,
                    BROWSER_MAXIMUM_PROXY_CONNECTIONS_PER_CALL,
                )
                .expect("released connection remains below total ceiling"),
            );
        }
        assert!(
            reserve_browser_connection(
                &active,
                &mut accepted,
                BROWSER_MAXIMUM_CONCURRENT_PROXY_CONNECTIONS,
                BROWSER_MAXIMUM_PROXY_CONNECTIONS_PER_CALL,
            )
            .is_none()
        );
    }

    #[test]
    fn completed_proxy_threads_are_reaped_before_browser_shutdown() {
        let mut connections = (0..128).map(|_| thread::spawn(|| {})).collect::<Vec<_>>();
        for _ in 0..100 {
            reap_finished_threads(&mut connections);
            if connections.is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(connections.is_empty());
    }

    #[test]
    fn verification_origin_does_not_let_an_idle_connection_block_navigation() {
        use std::{
            io::{Read, Write},
            net::TcpStream,
        };

        let origin = BrowserVerificationOrigin::start().expect("verification origin");
        let idle = TcpStream::connect(origin.address).expect("idle speculative connection");
        thread::sleep(Duration::from_millis(50));

        let mut navigation = TcpStream::connect(origin.address).expect("navigation connection");
        navigation
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("navigation read timeout");
        navigation
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .expect("navigation request");
        let mut response = Vec::new();
        navigation
            .read_to_end(&mut response)
            .expect("navigation response before idle connection timeout");
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(
            response
                .windows(b"isolated rendered evidence".len())
                .any(|window| window == b"isolated rendered evidence")
        );
        drop(idle);
        drop(origin);
    }

    #[test]
    fn hostile_accessibility_strings_are_control_free_canonical_and_bounded() {
        assert_eq!(
            normalize_untrusted_text(" \0Hello\n\tworld\u{0085} "),
            "Hello world"
        );
        let normalized = normalize_accessibility_tree(
            &json!({
                "nodes": [
                    {"ignored": false, "role": {"value": "StaticText"}, "name": {"value": "A\0  B"}},
                    {"ignored": false, "role": {"value": "link"}, "name": {"value": "Read\n more"}},
                    {"ignored": false, "role": {"value": "link"}, "name": {"value": "Read  more"}}
                ]
            }),
            3,
            8,
        )
        .expect("normalize");
        assert_eq!(normalized.text, "A B");
        assert!(!normalized.text.chars().any(char::is_control));
        assert_eq!(normalized.elements[0]["name"], "Read more");
        assert_eq!(normalized.elements[0]["occurrence"], 1);
        assert_eq!(normalized.elements[1]["occurrence"], 2);
    }

    #[test]
    fn utf8_truncation_never_splits_a_scalar_value() {
        let mut value = "ab😀cd".to_owned();
        assert!(truncate_utf8_to_bytes(&mut value, 5));
        assert_eq!(value, "ab");
        assert!(!truncate_utf8_to_bytes(&mut value, 5));
    }

    #[test]
    fn cdp_byte_counts_accept_integral_json_numbers_and_reject_ambiguous_values() {
        for (value, expected) in [
            (json!(0), 0),
            (json!(37), 37),
            (json!(37.0), 37),
            (json!(1e3), 1_000),
        ] {
            assert_eq!(
                cdp_nonnegative_integer(Some(&value)).expect("integral CDP number"),
                expected
            );
        }
        for value in [
            json!(-1),
            json!(0.5),
            json!(9_007_199_254_740_992_u64),
            json!(9_007_199_254_740_992.0),
        ] {
            assert!(cdp_nonnegative_integer(Some(&value)).is_err());
        }
        assert!(cdp_nonnegative_integer(None).is_err());
    }
}
