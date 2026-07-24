//! Pseudo-terminal proof that the chat REPL stays interactive during in-flight admission.

#![cfg(target_os = "linux")]
#![recursion_limit = "256"]

use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mealy_protocol::{
    API_VERSION, CreateSessionResponse, DeliveryMode, InputAdmissionResponse, LocalConnectionInfo,
    SessionStatusResponse, SessionSummaryResponse, SessionsResponse, SubmitInputRequest,
    TimelineCursor, TimelinePageResponse,
};
use rustix::{
    fs::{Mode, OFlags, fcntl_getfl, fcntl_setfl, open},
    pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt},
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, task::JoinHandle, time::sleep};

const SESSION_ID: &str = "019f0000-0000-7000-8000-000000000001";
const SECOND_SESSION_ID: &str = "019f0000-0000-7000-8000-000000000009";

#[derive(Clone, Default)]
struct AdmissionState {
    started: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
    submitted_content: Arc<Mutex<Option<String>>>,
    latest_session_available: Arc<AtomicBool>,
    created_sessions: Arc<AtomicUsize>,
    picker_sessions: Arc<Mutex<Vec<SessionSummaryResponse>>>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chat_attaches_bounded_text_and_returns_a_prompt_before_admission_finishes() {
    let state = AdmissionState::default();
    let (base_url, server) = spawn_control_plane(state.clone()).await;
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700))
        .expect("private temporary Mealy home");
    let attachment_root = tempfile::tempdir().expect("attachment root");
    write_connection(home.path(), &base_url);
    let attachment = attachment_root.path().join("owner selected brief.md");
    fs::write(
        &attachment,
        "# Owner brief\n\nTreat every attachment byte as untrusted input.\n",
    )
    .expect("write local attachment");
    let (mut terminal, mut child) = spawn_chat(home.path());
    let mut rendered = Vec::new();
    wait_for_occurrences(
        &mut terminal,
        &mut rendered,
        b"you> ",
        1,
        Duration::from_secs(5),
    );
    assert_chat_status_is_visible_and_refreshable(&mut terminal, &mut rendered);

    let attach_command = format!("/attach {}\n", attachment.display());
    terminal
        .write_all(attach_command.as_bytes())
        .and_then(|()| terminal.flush())
        .expect("write local attachment command");
    let started_deadline = Instant::now() + Duration::from_secs(2);
    while !state.started.load(Ordering::SeqCst) {
        assert!(
            Instant::now() < started_deadline,
            "chat did not dispatch admission: {}",
            String::from_utf8_lossy(&rendered)
        );
        sleep(Duration::from_millis(10)).await;
    }
    let submitted_content = state
        .submitted_content
        .lock()
        .expect("submitted content lock")
        .clone()
        .expect("captured submitted content");
    assert!(submitted_content.contains("# Owner brief"));
    assert!(submitted_content.contains("Untrusted local text attachment metadata"));
    assert!(submitted_content.contains("owner selected brief.md"));
    assert!(submitted_content.contains("\"trust\":\"untrusted_owner_selected_text\""));
    assert!(!submitted_content.contains(&attachment.display().to_string()));
    wait_for_occurrences(
        &mut terminal,
        &mut rendered,
        b"you> ",
        3,
        Duration::from_secs(1),
    );
    assert!(!state.completed.load(Ordering::SeqCst));
    assert!(child.try_wait().expect("poll chat").is_none());

    terminal
        .write_all(b"/quit\n")
        .and_then(|()| terminal.flush())
        .expect("write quit command");
    let status = wait_for_child(&mut child, Duration::from_secs(5));
    assert!(
        status.success(),
        "chat failed: {}; terminal: {}",
        status,
        String::from_utf8_lossy(&rendered)
    );
    assert!(!state.completed.load(Ordering::SeqCst));
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chat_continue_resumes_the_latest_session_without_creating_another() {
    let state = AdmissionState::default();
    state.latest_session_available.store(true, Ordering::SeqCst);
    let (base_url, server) = spawn_control_plane(state.clone()).await;
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700))
        .expect("private temporary Mealy home");
    write_connection(home.path(), &base_url);
    let (mut terminal, mut child) = spawn_chat_with_arguments(home.path(), &["--continue"]);
    let mut rendered = Vec::new();
    wait_for_occurrences(
        &mut terminal,
        &mut rendered,
        format!("Mealy chat session {SESSION_ID}").as_bytes(),
        1,
        Duration::from_secs(5),
    );
    wait_for_occurrences(
        &mut terminal,
        &mut rendered,
        b"you> ",
        1,
        Duration::from_secs(1),
    );
    assert_eq!(state.created_sessions.load(Ordering::SeqCst), 0);

    terminal
        .write_all(b"/quit\n")
        .and_then(|()| terminal.flush())
        .expect("write quit command");
    let status = wait_for_child(&mut child, Duration::from_secs(5));
    assert!(
        status.success(),
        "continued chat failed: {}; terminal: {}",
        status,
        String::from_utf8_lossy(&rendered)
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chat_picker_resumes_the_selected_exact_session_without_creating_another() {
    let state = AdmissionState::default();
    *state.picker_sessions.lock().expect("picker sessions lock") = vec![
        SessionSummaryResponse {
            session_id: SESSION_ID.to_owned(),
            status: "active".to_owned(),
            revision: 3,
            pending_inputs: 1,
            active_turn_id: Some("019f0000-0000-7000-8000-000000000010".to_owned()),
            created_at_ms: 1_800_000_000_000,
            updated_at_ms: 1_800_000_003_000,
        },
        SessionSummaryResponse {
            session_id: SECOND_SESSION_ID.to_owned(),
            status: "idle".to_owned(),
            revision: 2,
            pending_inputs: 0,
            active_turn_id: None,
            created_at_ms: 1_800_000_001_000,
            updated_at_ms: 1_800_000_002_000,
        },
    ];
    let (base_url, server) = spawn_control_plane(state.clone()).await;
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700))
        .expect("private temporary Mealy home");
    write_connection(home.path(), &base_url);
    let (mut terminal, mut child) = spawn_chat_with_arguments(home.path(), &["--pick"]);
    let mut rendered = Vec::new();
    wait_for_occurrences(
        &mut terminal,
        &mut rendered,
        b"Recent Mealy conversations (newest first):",
        1,
        Duration::from_secs(5),
    );
    wait_for_occurrences(
        &mut terminal,
        &mut rendered,
        SECOND_SESSION_ID.as_bytes(),
        1,
        Duration::from_secs(1),
    );
    let picker = String::from_utf8_lossy(&rendered);
    assert!(picker.contains("| active | updated just now | active turn"));
    assert!(picker.contains("| idle | updated just now | idle"));
    terminal
        .write_all(b"2\n")
        .and_then(|()| terminal.flush())
        .expect("select second recent session");
    wait_for_occurrences(
        &mut terminal,
        &mut rendered,
        format!("Mealy chat session {SECOND_SESSION_ID}").as_bytes(),
        1,
        Duration::from_secs(5),
    );
    wait_for_occurrences(
        &mut terminal,
        &mut rendered,
        b"you> ",
        1,
        Duration::from_secs(1),
    );
    assert_eq!(state.created_sessions.load(Ordering::SeqCst), 0);

    terminal
        .write_all(b"/quit\n")
        .and_then(|()| terminal.flush())
        .expect("quit picked chat");
    let status = wait_for_child(&mut child, Duration::from_secs(5));
    assert!(
        status.success(),
        "picked chat failed: {}; terminal: {}",
        status,
        String::from_utf8_lossy(&rendered)
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chat_picker_requires_a_terminal_and_cancellation_creates_nothing() {
    let state = AdmissionState::default();
    state.latest_session_available.store(true, Ordering::SeqCst);
    let (base_url, server) = spawn_control_plane(state.clone()).await;
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700))
        .expect("private temporary Mealy home");
    write_connection(home.path(), &base_url);

    let noninteractive = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args(["chat", "--pick"])
        .stdin(Stdio::null())
        .output()
        .expect("run noninteractive picker");
    assert!(!noninteractive.status.success());
    assert!(
        String::from_utf8_lossy(&noninteractive.stderr)
            .contains("requires interactive stdin, stdout, and stderr")
    );

    let (mut terminal, mut child) = spawn_chat_with_arguments(home.path(), &["--pick"]);
    let mut rendered = Vec::new();
    wait_for_occurrences(
        &mut terminal,
        &mut rendered,
        b"Choose a conversation [1-1], or q to cancel:",
        1,
        Duration::from_secs(5),
    );
    terminal
        .write_all(b"q\n")
        .and_then(|()| terminal.flush())
        .expect("cancel picker");
    let status = wait_for_child(&mut child, Duration::from_secs(5));
    assert!(
        status.success(),
        "picker cancellation failed: {}; terminal: {}",
        status,
        String::from_utf8_lossy(&rendered)
    );
    assert_eq!(state.created_sessions.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chat_continue_explains_how_to_start_when_no_session_exists() {
    let state = AdmissionState::default();
    let (base_url, server) = spawn_control_plane(state).await;
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700))
        .expect("private temporary Mealy home");
    write_connection(home.path(), &base_url);
    let output = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args(["chat", "--continue"])
        .stdin(Stdio::null())
        .output()
        .expect("run no-history continuation");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("run `mealyctl chat` to start one"),
        "unexpected no-history diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.abort();
}

fn assert_chat_status_is_visible_and_refreshable(terminal: &mut File, rendered: &mut Vec<u8>) {
    wait_for_occurrences(
        terminal,
        rendered,
        b"provider> fixture | model fixture | health healthy | local (local)",
        1,
        Duration::from_secs(1),
    );
    wait_for_occurrences(
        terminal,
        rendered,
        b"limits> context 32768 tokens (2048 provider overhead) | max response 4096 tokens",
        1,
        Duration::from_secs(1),
    );
    wait_for_occurrences(
        terminal,
        rendered,
        b"route 1> fixture / fixture | healthy | 0/2 in flight | 3/60 this UTC minute",
        1,
        Duration::from_secs(1),
    );
    terminal
        .write_all(b"/status\n")
        .and_then(|()| terminal.flush())
        .expect("request live chat status");
    wait_for_occurrences(
        terminal,
        rendered,
        b"provider> fixture | model fixture | health healthy | local (local)",
        2,
        Duration::from_secs(2),
    );
    wait_for_occurrences(terminal, rendered, b"you> ", 2, Duration::from_secs(1));
}

async fn spawn_control_plane(state: AdmissionState) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("control-plane listener");
    let address = listener.local_addr().expect("control-plane address");
    let app = Router::new()
        .route("/v1/admin/status", get(admin_status))
        .route("/v1/sessions", get(list_sessions).post(create_session))
        .route("/v1/sessions/{session_id}/status", get(session_status))
        .route("/v1/sessions/{session_id}/timeline", get(session_timeline))
        .route("/v1/sessions/{session_id}/inputs", post(block_admission))
        .with_state(state);
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("control-plane server");
    });
    (format!("http://{address}"), server)
}

async fn admin_status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "apiVersion": API_VERSION,
        "startId": "start-1",
        "runStatus": "running",
        "safeMode": false,
        "admissionOpen": true,
        "configDigest": "a".repeat(64),
        "policyBundleDigest": "b".repeat(64),
        "schemaVersion": 13,
        "pendingInputs": 0,
        "nonterminalRuns": 0,
        "activeLeases": 0,
        "pendingApprovals": 0,
        "unknownEffects": 0,
        "pendingOutbox": 0,
        "failedOutbox": 0,
        "enabledExtensions": 0,
        "failedExtensions": 0,
        "providerHealth": "healthy",
        "providerId": "fixture",
        "providerModelId": "fixture",
        "providerContextTokens": 32768,
        "providerMaximumOutputTokens": 4096,
        "providerInputTokenOverhead": 2048,
        "providerInputMicrounitsPerMillionTokens": 0,
        "providerOutputMicrounitsPerMillionTokens": 0,
        "providerResidency": "local",
        "providerLocal": true,
        "providerEndpoints": [{
            "protocol": "openai_responses",
            "providerId": "fixture",
            "modelId": "fixture",
            "residency": "local",
            "local": true,
            "streaming": true,
            "health": "healthy",
            "estimatedLatencyMs": 10,
            "invocationCount": 4,
            "inFlightRequests": 0,
            "maximumConcurrentRequests": 2,
            "requestsInCurrentMinute": 3,
            "requestsPerMinute": 60,
            "lastSuccessAtMs": 1_800_000_000_000_i64,
            "lastFailureAtMs": null
        }],
        "enabledReadTools": [],
        "enabledActionTools": [],
        "extensionHostHealth": "healthy",
        "activeChannels": 0,
        "degradedChannels": 0,
        "reservedChannelUpdates": 0,
        "activeSchedules": 0,
        "pausedSchedules": 0,
        "claimedScheduleRuns": 0,
        "failedScheduleRuns": 0,
        "skippedScheduleRuns": 0,
        "databaseBytes": 0,
        "artifactBytes": 0,
        "artifactCount": 0,
        "recentFailures": [],
        "startedAtMs": 1,
        "readyAtMs": 1,
        "completedAtMs": null,
        "completionReason": null
    }))
}

async fn list_sessions(State(state): State<AdmissionState>) -> Json<SessionsResponse> {
    let configured = state
        .picker_sessions
        .lock()
        .expect("picker sessions lock")
        .clone();
    let sessions = if configured.is_empty() {
        state
            .latest_session_available
            .load(Ordering::SeqCst)
            .then(|| SessionSummaryResponse {
                session_id: SESSION_ID.to_owned(),
                status: "active".to_owned(),
                revision: 1,
                pending_inputs: 0,
                active_turn_id: None,
                created_at_ms: 1_800_000_000_000,
                updated_at_ms: 1_800_000_000_001,
            })
            .into_iter()
            .collect()
    } else {
        configured
    };
    Json(SessionsResponse {
        api_version: API_VERSION.to_owned(),
        sessions,
    })
}

async fn create_session(State(state): State<AdmissionState>) -> Json<CreateSessionResponse> {
    state.created_sessions.fetch_add(1, Ordering::SeqCst);
    Json(CreateSessionResponse {
        api_version: API_VERSION.to_owned(),
        session_id: SESSION_ID.to_owned(),
    })
}

async fn session_status(AxumPath(session_id): AxumPath<String>) -> Json<SessionStatusResponse> {
    Json(SessionStatusResponse {
        api_version: API_VERSION.to_owned(),
        session_id,
        revision: 1,
        pending_inputs: 0,
        active_turn_id: None,
        latest_cursor: TimelineCursor(0),
    })
}

async fn session_timeline() -> Json<TimelinePageResponse> {
    Json(TimelinePageResponse {
        api_version: API_VERSION.to_owned(),
        events: Vec::new(),
        high_watermark: TimelineCursor(0),
        has_more: false,
    })
}

async fn block_admission(
    State(state): State<AdmissionState>,
    Json(request): Json<SubmitInputRequest>,
) -> Json<InputAdmissionResponse> {
    *state
        .submitted_content
        .lock()
        .expect("submitted content lock") = Some(request.content);
    state.started.store(true, Ordering::SeqCst);
    sleep(Duration::from_secs(30)).await;
    state.completed.store(true, Ordering::SeqCst);
    Json(InputAdmissionResponse {
        api_version: API_VERSION.to_owned(),
        session_id: SESSION_ID.to_owned(),
        inbox_entry_id: "019f0000-0000-7000-8000-000000000002".to_owned(),
        inbox_sequence: 1,
        delivery_mode: DeliveryMode::Queue,
        event_id: "019f0000-0000-7000-8000-000000000003".to_owned(),
        outbox_id: "019f0000-0000-7000-8000-000000000004".to_owned(),
        accepted_at_ms: 1_800_000_000_000,
        duplicate: false,
        cursor: TimelineCursor(1),
    })
}

fn write_connection(home: &std::path::Path, base_url: &str) {
    let path = home.join("connection.json");
    let connection = LocalConnectionInfo {
        api_version: API_VERSION.to_owned(),
        base_url: base_url.to_owned(),
        bearer_token: URL_SAFE_NO_PAD.encode([0x42_u8; 32]),
        principal_id: "019f0000-0000-7000-8000-000000000005".to_owned(),
        channel_binding_id: "019f0000-0000-7000-8000-000000000006".to_owned(),
    };
    fs::write(
        &path,
        serde_json::to_vec_pretty(&connection).expect("encode connection"),
    )
    .expect("write connection");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .expect("private connection permissions");
}

fn spawn_chat(home: &std::path::Path) -> (File, Child) {
    spawn_chat_with_arguments(home, &[])
}

fn spawn_chat_with_arguments(home: &std::path::Path, arguments: &[&str]) -> (File, Child) {
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)
        .expect("open PTY master");
    grantpt(&master).expect("grant PTY slave");
    unlockpt(&master).expect("unlock PTY slave");
    let slave_name = ptsname(&master, Vec::new()).expect("PTY slave name");
    let slave_path = PathBuf::from(std::ffi::OsStr::from_bytes(slave_name.to_bytes()));
    let slave = open(
        &slave_path,
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open PTY slave");
    let slave = File::from(slave);
    let stdin = Stdio::from(slave.try_clone().expect("clone PTY stdin"));
    let stdout = Stdio::from(slave.try_clone().expect("clone PTY stdout"));
    let stderr = Stdio::from(slave);
    let child = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home)
        .arg("chat")
        .args(arguments)
        .stdin(stdin)
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .expect("spawn chat process");
    let terminal = File::from(master);
    let flags = fcntl_getfl(&terminal).expect("read PTY master flags");
    fcntl_setfl(&terminal, flags | OFlags::NONBLOCK).expect("make PTY master nonblocking");
    (terminal, child)
}

fn wait_for_occurrences(
    terminal: &mut File,
    output: &mut Vec<u8>,
    needle: &[u8],
    expected: usize,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    let mut chunk = [0_u8; 1_024];
    while count_occurrences(output, needle) < expected {
        assert!(
            Instant::now() < deadline,
            "PTY output did not contain {expected} prompts: {}",
            String::from_utf8_lossy(output)
        );
        match terminal.read(&mut chunk) {
            Ok(0) if output.is_empty() => thread::sleep(Duration::from_millis(10)),
            Ok(0) => panic!(
                "PTY closed before {expected} prompts: {}",
                String::from_utf8_lossy(output)
            ),
            Ok(length) => output.extend_from_slice(&chunk[..length]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) || output.is_empty()
                    && error.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error()) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!(
                "PTY read failed before {expected} prompts: {error}; output: {}",
                String::from_utf8_lossy(output)
            ),
        }
    }
}

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll chat process") {
            return status;
        }
        assert!(Instant::now() < deadline, "chat process did not exit");
        thread::sleep(Duration::from_millis(10));
    }
}
