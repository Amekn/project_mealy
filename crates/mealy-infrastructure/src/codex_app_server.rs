//! Bounded Codex app-server client for owner-local `ChatGPT` onboarding.

use crate::subscription_cli::{
    copy_owner_client_environment, inspect_subscription_cli_executable, terminate_process,
};
use mealy_application::SubscriptionCliClient;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeSet, VecDeque},
    io::{BufRead as _, BufReader, Read, Write as _},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError, Sender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use thiserror::Error;
use url::Url;

#[cfg(unix)]
use std::os::unix::process::CommandExt as _;

const APP_SERVER_INITIALIZATION_TIMEOUT: Duration = Duration::from_secs(15);
const APP_SERVER_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAXIMUM_LOGIN_WAIT: Duration = Duration::from_mins(5);
const MAXIMUM_JSON_LINE_BYTES: u64 = 1024 * 1024;
const MAXIMUM_TOTAL_STDOUT_BYTES: u64 = 8 * 1024 * 1024;
const MAXIMUM_STDERR_BYTES: u64 = 64 * 1024;
const MAXIMUM_MESSAGES: usize = 512;
const MAXIMUM_PENDING_NOTIFICATIONS: usize = 64;
const MAXIMUM_MODELS: usize = 500;
const MAXIMUM_MODEL_PAGES: usize = 10;
const MAXIMUM_CURSOR_BYTES: usize = 1_024;
const MAXIMUM_URL_BYTES: usize = 8 * 1024;
const MAXIMUM_USER_CODE_BYTES: usize = 128;

/// Fail-closed app-server startup, account, login, or model-catalog failure.
#[derive(Debug, Error)]
pub enum CodexAppServerError {
    /// The exact executable identity or a caller-supplied value was invalid.
    #[error("Codex app-server configuration is invalid")]
    InvalidConfiguration,
    /// The exact Codex executable could not be launched.
    #[error("Codex app-server process is unavailable")]
    ProcessUnavailable,
    /// The bounded JSONL exchange did not match the documented protocol.
    #[error("Codex app-server returned an invalid bounded response")]
    InvalidResponse,
    /// A bounded app-server request did not finish in time.
    #[error("Codex app-server request timed out")]
    Timeout,
    /// The managed `ChatGPT` login did not complete successfully.
    #[error("Codex ChatGPT login did not complete")]
    LoginFailed,
}

/// Coarse account state that deliberately omits email, tokens, and account identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodexAccountKind {
    /// No account is active for the selected built-in `OpenAI` provider.
    SignedOut,
    /// Codex owns an active managed `ChatGPT` session.
    Chatgpt,
    /// Another login mode (for example an API key) is active.
    Other,
}

/// Non-secret account state needed by Mealy onboarding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexAccountState {
    /// Coarse active authentication kind.
    pub kind: CodexAccountKind,
    /// Bounded `ChatGPT` plan label when the app-server supplies one.
    pub plan_type: Option<String>,
}

/// Managed `ChatGPT` login ceremony owned by Codex.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodexChatgptLoginFlow {
    /// Local callback and browser URL.
    Browser,
    /// Device verification URL and user code for remote/headless Linux.
    DeviceCode,
}

/// Non-secret, user-displayable challenge returned by the official app-server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodexChatgptLoginChallenge {
    /// Browser flow with one exact authorization URL.
    Browser {
        /// Opaque login identity used only for bounded completion matching.
        login_id: String,
        /// URL the owner opens to complete `ChatGPT` sign-in.
        auth_url: String,
    },
    /// Device-code flow suitable for a headless terminal.
    DeviceCode {
        /// Opaque login identity used only for bounded completion matching.
        login_id: String,
        /// URL the owner opens on any browser.
        verification_url: String,
        /// Short owner-entered verification code.
        user_code: String,
    },
}

impl CodexChatgptLoginChallenge {
    fn login_id(&self) -> &str {
        match self {
            Self::Browser { login_id, .. } | Self::DeviceCode { login_id, .. } => login_id,
        }
    }
}

/// Picker-visible model metadata from the account-scoped Codex catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexSubscriptionModel {
    /// Exact model ID accepted by Codex.
    pub model: String,
    /// Bounded user-facing name.
    pub display_name: String,
    /// Whether the current catalog recommends this model by default.
    pub is_default: bool,
}

enum ReaderEvent {
    Line(Vec<u8>),
    StdoutClosed,
    StdoutInvalid,
    StderrOverflow,
}

/// One exact-executable, bounded stdio app-server session.
pub struct CodexAppServerClient {
    child: Child,
    stdin: Option<ChildStdin>,
    events: Receiver<ReaderEvent>,
    readers: Vec<JoinHandle<()>>,
    pending_notifications: VecDeque<Value>,
    next_id: u64,
    message_count: usize,
    stdout_bytes: u64,
}

impl CodexAppServerClient {
    /// Starts and initializes one app-server process after rechecking its exact digest.
    ///
    /// # Errors
    ///
    /// Returns [`CodexAppServerError`] when the executable changed, process startup fails, or the
    /// initialization exchange is malformed or exceeds its bounds.
    pub fn start(
        executable_path: &Path,
        executable_sha256: &str,
    ) -> Result<Self, CodexAppServerError> {
        let (canonical, observed_sha256) = inspect_subscription_cli_executable(executable_path)
            .map_err(|_| CodexAppServerError::InvalidConfiguration)?;
        if canonical != executable_path || observed_sha256 != executable_sha256 {
            return Err(CodexAppServerError::InvalidConfiguration);
        }

        let mut command = Command::new(executable_path);
        command
            .args([
                "app-server",
                "--listen",
                "stdio://",
                "--strict-config",
                "--disable",
                "apps",
                "--disable",
                "remote_plugin",
                "--disable",
                "multi_agent",
                "--disable",
                "goals",
                "--disable",
                "hooks",
                "-c",
                "model_provider=\"openai\"",
                "-c",
                "web_search=\"disabled\"",
                "-c",
                "approval_policy=\"never\"",
            ])
            .current_dir("/")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        copy_owner_client_environment(&mut command, SubscriptionCliClient::OpenAiCodex);
        #[cfg(unix)]
        command.process_group(0);

        let mut child = command
            .spawn()
            .map_err(|_| CodexAppServerError::ProcessUnavailable)?;
        let stdin = child
            .stdin
            .take()
            .ok_or(CodexAppServerError::ProcessUnavailable)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(CodexAppServerError::ProcessUnavailable)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(CodexAppServerError::ProcessUnavailable)?;
        // The producer independently caps both message count and total bytes before sending, so
        // this queue remains bounded without allowing a full synchronous channel to deadlock
        // reader shutdown.
        let (sender, events) = mpsc::channel();
        let stdout_sender = sender.clone();
        let stdout_reader = thread::spawn(move || read_stdout(stdout, &stdout_sender));
        let stderr_reader = thread::spawn(move || read_stderr(stderr, &sender));
        let mut client = Self {
            child,
            stdin: Some(stdin),
            events,
            readers: vec![stdout_reader, stderr_reader],
            pending_notifications: VecDeque::new(),
            next_id: 1,
            message_count: 0,
            stdout_bytes: 0,
        };
        let result = client.request(
            "initialize",
            &json!({
                "clientInfo": {
                    "name": "mealy",
                    "title": "Mealy",
                    "version": env!("CARGO_PKG_VERSION"),
                },
            }),
            APP_SERVER_INITIALIZATION_TIMEOUT,
        )?;
        if !result.is_object() {
            return Err(CodexAppServerError::InvalidResponse);
        }
        client.notification("initialized", &json!({}))?;
        Ok(client)
    }

    /// Reads the active account without retaining email, IDs, or authentication material.
    ///
    /// # Errors
    ///
    /// Returns [`CodexAppServerError`] for a malformed or unavailable bounded response.
    pub fn account_state(&mut self) -> Result<CodexAccountState, CodexAppServerError> {
        let result = self.request(
            "account/read",
            &json!({ "refreshToken": false }),
            APP_SERVER_REQUEST_TIMEOUT,
        )?;
        let object = result
            .as_object()
            .ok_or(CodexAppServerError::InvalidResponse)?;
        if !object
            .get("requiresOpenaiAuth")
            .is_some_and(Value::is_boolean)
        {
            return Err(CodexAppServerError::InvalidResponse);
        }
        let Some(account) = object.get("account") else {
            return Err(CodexAppServerError::InvalidResponse);
        };
        if account.is_null() {
            return Ok(CodexAccountState {
                kind: CodexAccountKind::SignedOut,
                plan_type: None,
            });
        }
        let account = account
            .as_object()
            .ok_or(CodexAppServerError::InvalidResponse)?;
        let account_type = account
            .get("type")
            .and_then(Value::as_str)
            .filter(|value| valid_label(value, 64))
            .ok_or(CodexAppServerError::InvalidResponse)?;
        let plan_type = optional_label(account.get("planType"), 64)?;
        Ok(CodexAccountState {
            kind: if account_type == "chatgpt" {
                CodexAccountKind::Chatgpt
            } else {
                CodexAccountKind::Other
            },
            plan_type,
        })
    }

    /// Starts a managed `ChatGPT` browser or device-code login.
    ///
    /// # Errors
    ///
    /// Returns [`CodexAppServerError`] unless the official server returns one bounded HTTPS
    /// challenge with a valid opaque login identity.
    pub fn start_chatgpt_login(
        &mut self,
        flow: CodexChatgptLoginFlow,
    ) -> Result<CodexChatgptLoginChallenge, CodexAppServerError> {
        let params = match flow {
            CodexChatgptLoginFlow::Browser => json!({
                "type": "chatgpt",
                "useHostedLoginSuccessPage": true,
                "appBrand": "chatgpt",
            }),
            CodexChatgptLoginFlow::DeviceCode => json!({
                "type": "chatgptDeviceCode",
            }),
        };
        let result = self.request("account/login/start", &params, APP_SERVER_REQUEST_TIMEOUT)?;
        let object = result
            .as_object()
            .ok_or(CodexAppServerError::InvalidResponse)?;
        let login_id = required_label(object.get("loginId"), 128)?;
        match flow {
            CodexChatgptLoginFlow::Browser => {
                if object.get("type").and_then(Value::as_str) != Some("chatgpt") {
                    return Err(CodexAppServerError::InvalidResponse);
                }
                Ok(CodexChatgptLoginChallenge::Browser {
                    login_id,
                    auth_url: required_https_url(object.get("authUrl"))?,
                })
            }
            CodexChatgptLoginFlow::DeviceCode => {
                if object.get("type").and_then(Value::as_str) != Some("chatgptDeviceCode") {
                    return Err(CodexAppServerError::InvalidResponse);
                }
                let user_code = required_label(object.get("userCode"), MAXIMUM_USER_CODE_BYTES)?;
                Ok(CodexChatgptLoginChallenge::DeviceCode {
                    login_id,
                    verification_url: required_https_url(object.get("verificationUrl"))?,
                    user_code,
                })
            }
        }
    }

    /// Waits for the exact login challenge and re-reads the resulting account state.
    ///
    /// # Errors
    ///
    /// Returns [`CodexAppServerError`] on timeout, a negative completion, a mismatched login
    /// identity, or a final account that is not managed `ChatGPT` authentication.
    pub fn finish_chatgpt_login(
        &mut self,
        challenge: &CodexChatgptLoginChallenge,
    ) -> Result<CodexAccountState, CodexAppServerError> {
        let deadline = Instant::now() + MAXIMUM_LOGIN_WAIT;
        let notification =
            self.wait_for_notification("account/login/completed", deadline, |params| {
                params.get("loginId").and_then(Value::as_str) == Some(challenge.login_id())
            })?;
        let params = notification
            .get("params")
            .and_then(Value::as_object)
            .ok_or(CodexAppServerError::InvalidResponse)?;
        if params.get("success").and_then(Value::as_bool) != Some(true)
            || params.get("error").is_none_or(|error| !error.is_null())
        {
            return Err(CodexAppServerError::LoginFailed);
        }
        let account = self.account_state()?;
        if account.kind != CodexAccountKind::Chatgpt {
            return Err(CodexAppServerError::LoginFailed);
        }
        Ok(account)
    }

    /// Lists the current account-visible Codex catalog with bounded pagination.
    ///
    /// # Errors
    ///
    /// Returns [`CodexAppServerError`] for duplicate, malformed, oversized, or unbounded catalog
    /// data.
    pub fn list_models(
        &mut self,
        include_hidden: bool,
    ) -> Result<Vec<CodexSubscriptionModel>, CodexAppServerError> {
        let mut models = Vec::new();
        let mut ids = BTreeSet::new();
        let mut cursors = BTreeSet::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAXIMUM_MODEL_PAGES {
            let mut params = Map::new();
            params.insert("limit".to_owned(), Value::from(100));
            params.insert("includeHidden".to_owned(), Value::from(include_hidden));
            if let Some(cursor) = &cursor {
                params.insert("cursor".to_owned(), Value::from(cursor.clone()));
            }
            let result = self.request(
                "model/list",
                &Value::Object(params),
                APP_SERVER_REQUEST_TIMEOUT,
            )?;
            let page: ModelPage =
                serde_json::from_value(result).map_err(|_| CodexAppServerError::InvalidResponse)?;
            if page.data.len() > 100 {
                return Err(CodexAppServerError::InvalidResponse);
            }
            for item in page.data {
                if !valid_label(&item.id, 256)
                    || item.id != item.model
                    || !valid_label(&item.display_name, 256)
                    || (!include_hidden && item.hidden)
                    || !ids.insert(item.model.clone())
                    || models.len() >= MAXIMUM_MODELS
                {
                    return Err(CodexAppServerError::InvalidResponse);
                }
                models.push(CodexSubscriptionModel {
                    model: item.model,
                    display_name: item.display_name,
                    is_default: item.is_default,
                });
            }
            let Some(next) = page.next_cursor else {
                return (!models.is_empty())
                    .then_some(models)
                    .ok_or(CodexAppServerError::InvalidResponse);
            };
            if !valid_label(&next, MAXIMUM_CURSOR_BYTES) || !cursors.insert(next.clone()) {
                return Err(CodexAppServerError::InvalidResponse);
            }
            cursor = Some(next);
        }
        Err(CodexAppServerError::InvalidResponse)
    }

    fn request(
        &mut self,
        method: &str,
        params: &Value,
        timeout: Duration,
    ) -> Result<Value, CodexAppServerError> {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(CodexAppServerError::InvalidConfiguration)?;
        self.write_message(&json!({ "method": method, "id": id, "params": params }))?;
        let deadline = Instant::now() + timeout;
        loop {
            let message = self.read_message(deadline)?;
            if let Some(response_id) = message.get("id") {
                if response_id.as_u64() != Some(id)
                    || message.get("method").is_some()
                    || message.get("error").is_some()
                {
                    return Err(CodexAppServerError::InvalidResponse);
                }
                return message
                    .get("result")
                    .cloned()
                    .ok_or(CodexAppServerError::InvalidResponse);
            }
            if message.get("method").and_then(Value::as_str).is_none()
                || message.get("params").is_none()
                || self.pending_notifications.len() >= MAXIMUM_PENDING_NOTIFICATIONS
            {
                return Err(CodexAppServerError::InvalidResponse);
            }
            self.pending_notifications.push_back(message);
        }
    }

    fn notification(&mut self, method: &str, params: &Value) -> Result<(), CodexAppServerError> {
        self.write_message(&json!({ "method": method, "params": params }))
    }

    fn write_message(&mut self, message: &Value) -> Result<(), CodexAppServerError> {
        let mut encoded =
            serde_json::to_vec(message).map_err(|_| CodexAppServerError::InvalidConfiguration)?;
        if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > MAXIMUM_JSON_LINE_BYTES {
            return Err(CodexAppServerError::InvalidConfiguration);
        }
        encoded.push(b'\n');
        self.stdin
            .as_mut()
            .ok_or(CodexAppServerError::ProcessUnavailable)?
            .write_all(&encoded)
            .and_then(|()| self.stdin.as_mut().expect("stdin checked above").flush())
            .map_err(|_| CodexAppServerError::ProcessUnavailable)
    }

    fn read_message(&mut self, deadline: Instant) -> Result<Value, CodexAppServerError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(CodexAppServerError::Timeout)?;
        let event = self
            .events
            .recv_timeout(remaining)
            .map_err(|error| match error {
                RecvTimeoutError::Timeout => CodexAppServerError::Timeout,
                RecvTimeoutError::Disconnected => CodexAppServerError::ProcessUnavailable,
            })?;
        let ReaderEvent::Line(line) = event else {
            return Err(match event {
                ReaderEvent::StdoutClosed => CodexAppServerError::ProcessUnavailable,
                ReaderEvent::StdoutInvalid | ReaderEvent::StderrOverflow => {
                    CodexAppServerError::InvalidResponse
                }
                ReaderEvent::Line(_) => unreachable!(),
            });
        };
        self.message_count = self
            .message_count
            .checked_add(1)
            .filter(|count| *count <= MAXIMUM_MESSAGES)
            .ok_or(CodexAppServerError::InvalidResponse)?;
        self.stdout_bytes = self
            .stdout_bytes
            .checked_add(u64::try_from(line.len()).unwrap_or(u64::MAX))
            .filter(|bytes| *bytes <= MAXIMUM_TOTAL_STDOUT_BYTES)
            .ok_or(CodexAppServerError::InvalidResponse)?;
        serde_json::from_slice(&line).map_err(|_| CodexAppServerError::InvalidResponse)
    }

    fn wait_for_notification(
        &mut self,
        method: &str,
        deadline: Instant,
        matches: impl Fn(&Map<String, Value>) -> bool,
    ) -> Result<Value, CodexAppServerError> {
        loop {
            if let Some(index) = self.pending_notifications.iter().position(|message| {
                message.get("method").and_then(Value::as_str) == Some(method)
                    && message
                        .get("params")
                        .and_then(Value::as_object)
                        .is_some_and(&matches)
            }) {
                return self
                    .pending_notifications
                    .remove(index)
                    .ok_or(CodexAppServerError::InvalidResponse);
            }
            let message = self.read_message(deadline)?;
            if message.get("id").is_some() {
                return Err(CodexAppServerError::InvalidResponse);
            }
            let Some(notification_method) = message.get("method").and_then(Value::as_str) else {
                return Err(CodexAppServerError::InvalidResponse);
            };
            let Some(params) = message.get("params").and_then(Value::as_object) else {
                return Err(CodexAppServerError::InvalidResponse);
            };
            if notification_method == method && matches(params) {
                return Ok(message);
            }
            if self.pending_notifications.len() >= MAXIMUM_PENDING_NOTIFICATIONS {
                return Err(CodexAppServerError::InvalidResponse);
            }
            self.pending_notifications.push_back(message);
        }
    }
}

impl Drop for CodexAppServerClient {
    fn drop(&mut self) {
        self.stdin.take();
        terminate_process(&mut self.child);
        let _ = self.child.wait();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ModelPage {
    data: Vec<ModelEntry>,
    next_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ModelEntry {
    id: String,
    model: String,
    display_name: String,
    #[serde(default)]
    hidden: bool,
    #[serde(default)]
    is_default: bool,
}

fn read_stdout(stdout: impl Read, sender: &Sender<ReaderEvent>) {
    let mut reader = BufReader::new(stdout);
    let mut messages = 0_usize;
    let mut total = 0_u64;
    loop {
        let mut line = Vec::new();
        let read = reader
            .by_ref()
            .take(MAXIMUM_JSON_LINE_BYTES.saturating_add(1))
            .read_until(b'\n', &mut line);
        let Ok(read) = read else {
            let _ = sender.send(ReaderEvent::StdoutInvalid);
            return;
        };
        if read == 0 {
            let _ = sender.send(ReaderEvent::StdoutClosed);
            return;
        }
        if u64::try_from(line.len()).unwrap_or(u64::MAX) > MAXIMUM_JSON_LINE_BYTES
            || line.last() != Some(&b'\n')
        {
            let _ = sender.send(ReaderEvent::StdoutInvalid);
            return;
        }
        messages = messages.saturating_add(1);
        total = total.saturating_add(u64::try_from(line.len()).unwrap_or(u64::MAX));
        if messages > MAXIMUM_MESSAGES || total > MAXIMUM_TOTAL_STDOUT_BYTES {
            let _ = sender.send(ReaderEvent::StdoutInvalid);
            return;
        }
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() || sender.send(ReaderEvent::Line(line)).is_err() {
            return;
        }
    }
}

fn read_stderr(mut stderr: impl Read, sender: &Sender<ReaderEvent>) {
    let mut buffer = [0_u8; 8 * 1024];
    let mut total = 0_u64;
    loop {
        let Ok(read) = stderr.read(&mut buffer) else {
            let _ = sender.send(ReaderEvent::StderrOverflow);
            return;
        };
        if read == 0 {
            return;
        }
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if total > MAXIMUM_STDERR_BYTES {
            let _ = sender.send(ReaderEvent::StderrOverflow);
            return;
        }
    }
}

fn required_label(
    value: Option<&Value>,
    maximum_bytes: usize,
) -> Result<String, CodexAppServerError> {
    value
        .and_then(Value::as_str)
        .filter(|value| valid_label(value, maximum_bytes))
        .map(str::to_owned)
        .ok_or(CodexAppServerError::InvalidResponse)
}

fn optional_label(
    value: Option<&Value>,
    maximum_bytes: usize,
) -> Result<Option<String>, CodexAppServerError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => required_label(Some(value), maximum_bytes).map(Some),
    }
}

fn required_https_url(value: Option<&Value>) -> Result<String, CodexAppServerError> {
    let value = value
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= MAXIMUM_URL_BYTES
                && !value.chars().any(char::is_control)
        })
        .ok_or(CodexAppServerError::InvalidResponse)?;
    let url = Url::parse(value).map_err(|_| CodexAppServerError::InvalidResponse)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(CodexAppServerError::InvalidResponse);
    }
    Ok(value.to_owned())
}

fn valid_label(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::{
        CodexAccountKind, CodexAppServerClient, CodexAppServerError, CodexChatgptLoginChallenge,
        CodexChatgptLoginFlow, required_https_url,
    };
    use crate::subscription_cli::inspect_subscription_cli_executable;
    use serde_json::json;
    use std::{fs, path::Path};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    #[cfg(unix)]
    fn signed_in_account_and_catalog_are_bounded_and_account_scoped() {
        let directory = tempfile::tempdir().expect("temporary app-server fixture");
        let executable = fixture(
            directory.path(),
            r#"{"account":{"type":"chatgpt","email":"must-not-leave-adapter","planType":"plus"},"requiresOpenaiAuth":true}"#,
            false,
        );
        let (executable, digest) =
            inspect_subscription_cli_executable(&executable).expect("inspect fixture");
        let mut client =
            CodexAppServerClient::start(&executable, &digest).expect("start app-server fixture");
        let account = client.account_state().expect("account state");
        assert_eq!(account.kind, CodexAccountKind::Chatgpt);
        assert_eq!(account.plan_type.as_deref(), Some("plus"));
        let models = client.list_models(false).expect("model catalog");
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].model, "gpt-fixture-default");
        assert!(models[0].is_default);
        assert!(!format!("{account:?}").contains("must-not-leave-adapter"));
    }

    #[test]
    #[cfg(unix)]
    fn managed_device_login_is_challenge_bound_and_finishes_as_chatgpt() {
        let directory = tempfile::tempdir().expect("temporary app-server fixture");
        let executable = fixture(
            directory.path(),
            r#"{"account":null,"requiresOpenaiAuth":true}"#,
            true,
        );
        let (executable, digest) =
            inspect_subscription_cli_executable(&executable).expect("inspect fixture");
        let mut client =
            CodexAppServerClient::start(&executable, &digest).expect("start app-server fixture");
        assert_eq!(
            client.account_state().expect("signed-out account").kind,
            CodexAccountKind::SignedOut
        );
        let challenge = client
            .start_chatgpt_login(CodexChatgptLoginFlow::DeviceCode)
            .expect("start device login");
        assert_eq!(
            challenge,
            CodexChatgptLoginChallenge::DeviceCode {
                login_id: "fixture-login".to_owned(),
                verification_url: "https://auth.openai.com/codex/device".to_owned(),
                user_code: "ABCD-1234".to_owned(),
            }
        );
        let account = client
            .finish_chatgpt_login(&challenge)
            .expect("finish device login");
        assert_eq!(account.kind, CodexAccountKind::Chatgpt);
    }

    #[test]
    #[cfg(unix)]
    fn managed_browser_login_returns_only_the_owner_displayable_https_challenge() {
        let directory = tempfile::tempdir().expect("temporary app-server fixture");
        let executable = fixture(
            directory.path(),
            r#"{"account":null,"requiresOpenaiAuth":true}"#,
            true,
        );
        let (executable, digest) =
            inspect_subscription_cli_executable(&executable).expect("inspect fixture");
        let mut client =
            CodexAppServerClient::start(&executable, &digest).expect("start app-server fixture");
        assert_eq!(
            client.account_state().expect("signed-out account").kind,
            CodexAccountKind::SignedOut
        );
        let challenge = client
            .start_chatgpt_login(CodexChatgptLoginFlow::Browser)
            .expect("start browser login");
        assert_eq!(
            challenge,
            CodexChatgptLoginChallenge::Browser {
                login_id: "fixture-login".to_owned(),
                auth_url: "https://chatgpt.com/auth/fixture?state=bounded".to_owned(),
            }
        );
        assert_eq!(
            client
                .finish_chatgpt_login(&challenge)
                .expect("finish browser login")
                .kind,
            CodexAccountKind::Chatgpt
        );
    }

    #[test]
    fn owner_displayable_login_urls_reject_unsafe_shapes() {
        for value in [
            "http://auth.openai.com/codex",
            "https://owner:secret@auth.openai.com/codex",
            "https://auth.openai.com/codex#secret",
            "not a URL",
        ] {
            assert!(matches!(
                required_https_url(Some(&json!(value))),
                Err(CodexAppServerError::InvalidResponse)
            ));
        }
    }

    #[test]
    #[cfg(unix)]
    fn executable_digest_is_rechecked_immediately_before_start() {
        let directory = tempfile::tempdir().expect("temporary app-server fixture");
        let executable = fixture(
            directory.path(),
            r#"{"account":{"type":"chatgpt","planType":"plus"},"requiresOpenaiAuth":true}"#,
            false,
        );
        let (executable, digest) =
            inspect_subscription_cli_executable(&executable).expect("inspect fixture");
        fs::write(&executable, "#!/bin/sh\nexit 0\n").expect("replace inspected executable");
        assert!(matches!(
            CodexAppServerClient::start(&executable, &digest),
            Err(CodexAppServerError::InvalidConfiguration)
        ));
    }

    #[cfg(unix)]
    fn fixture(directory: &Path, initial_account: &str, login: bool) -> std::path::PathBuf {
        let executable = directory.join(if login {
            "codex-login-fixture"
        } else {
            "codex-account-fixture"
        });
        let post_login_account = if login {
            r#"{"account":{"type":"chatgpt","planType":"plus"},"requiresOpenaiAuth":true}"#
        } else {
            initial_account
        };
        let script = format!(
            r#"#!/bin/sh
test -z "${{OPENAI_API_KEY:-}}${{ANTHROPIC_API_KEY:-}}${{OPENROUTER_API_KEY:-}}${{LOCAL_API_KEY:-}}" || exit 90
test "${{1:-}}" = "app-server" || exit 91
account='{initial_account}'
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*) printf '%s\n' '{{"id":1,"result":{{"userAgent":"fixture","platformFamily":"linux","platformOs":"linux"}}}}' ;;
    *'"method":"initialized"'*) ;;
    *'"method":"account/read"'*)
      case "$line" in
        *'"id":2'*) printf '%s\n' "{{\"id\":2,\"result\":$account}}" ;;
        *'"id":4'*) printf '%s\n' '{{"id":4,"result":{post_login_account}}}' ;;
        *) exit 92 ;;
      esac
      ;;
    *'"method":"account/login/start"'*)
      case "$line" in
        *chatgptDeviceCode*) printf '%s\n' '{{"id":3,"result":{{"type":"chatgptDeviceCode","loginId":"fixture-login","verificationUrl":"https://auth.openai.com/codex/device","userCode":"ABCD-1234"}}}}' ;;
        *) printf '%s\n' '{{"id":3,"result":{{"type":"chatgpt","loginId":"fixture-login","authUrl":"https://chatgpt.com/auth/fixture?state=bounded"}}}}' ;;
      esac
      printf '%s\n' '{{"method":"account/login/completed","params":{{"loginId":"fixture-login","success":true,"error":null}}}}'
      account='{post_login_account}'
      ;;
    *'"method":"model/list"'*)
      printf '%s\n' '{{"id":3,"result":{{"data":[{{"id":"gpt-fixture-default","model":"gpt-fixture-default","displayName":"Fixture Default","hidden":false,"isDefault":true}},{{"id":"gpt-fixture-other","model":"gpt-fixture-other","displayName":"Fixture Other","hidden":false,"isDefault":false}}],"nextCursor":null}}}}'
      ;;
    *) exit 93 ;;
  esac
done
"#
        );
        fs::write(&executable, script).expect("write fixture");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("make fixture executable");
        executable
    }
}
