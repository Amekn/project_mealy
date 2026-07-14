//! Pseudo-terminal proof that the chat REPL stays interactive during in-flight admission.

#![cfg(target_os = "linux")]
#![recursion_limit = "256"]

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mealy_protocol::{
    API_VERSION, CreateSessionResponse, DeliveryMode, InputAdmissionResponse, LocalConnectionInfo,
    SubmitInputRequest, TimelineCursor,
};
use rustix::{
    fs::{Mode, OFlags, open},
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
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, task::JoinHandle, time::sleep};

const SESSION_ID: &str = "019f0000-0000-7000-8000-000000000001";

#[derive(Clone, Default)]
struct AdmissionState {
    started: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
    submitted_content: Arc<Mutex<Option<String>>>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chat_attaches_bounded_text_and_returns_a_prompt_before_admission_finishes() {
    let state = AdmissionState::default();
    let (base_url, server) = spawn_control_plane(state.clone()).await;
    let home = tempfile::tempdir().expect("temporary Mealy home");
    let attachment_root = tempfile::tempdir().expect("attachment root");
    write_connection(home.path(), &base_url);
    let attachment = attachment_root.path().join("owner selected brief.md");
    fs::write(
        &attachment,
        "# Owner brief\n\nTreat every attachment byte as untrusted input.\n",
    )
    .expect("write local attachment");
    let (mut terminal, mut child, output) = spawn_chat(home.path());
    let mut rendered = Vec::new();
    wait_for_occurrences(&output, &mut rendered, b"you> ", 1, Duration::from_secs(5));

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
    wait_for_occurrences(&output, &mut rendered, b"you> ", 2, Duration::from_secs(1));
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

async fn spawn_control_plane(state: AdmissionState) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("control-plane listener");
    let address = listener.local_addr().expect("control-plane address");
    let app = Router::new()
        .route("/v1/admin/status", get(admin_status))
        .route("/v1/sessions", post(create_session))
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
        "providerResidency": "local",
        "providerLocal": true,
        "providerEndpoints": [],
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

async fn create_session() -> Json<CreateSessionResponse> {
    Json(CreateSessionResponse {
        api_version: API_VERSION.to_owned(),
        session_id: SESSION_ID.to_owned(),
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

fn spawn_chat(home: &std::path::Path) -> (File, Child, mpsc::Receiver<Vec<u8>>) {
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
        .stdin(stdin)
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .expect("spawn chat process");
    let terminal = File::from(master);
    let mut reader = terminal.try_clone().expect("clone PTY reader");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut chunk = [0_u8; 1_024];
        let startup_deadline = Instant::now() + Duration::from_secs(5);
        let mut observed_output = false;
        loop {
            match reader.read(&mut chunk) {
                // A Linux PTY master can transiently report either EOF or an error before the
                // inherited slave becomes visible across spawn/exec. Keep the reader channel
                // alive for the same bounded interval in which the test expects its first
                // prompt. Once any real byte arrives, EOF and every error are terminal.
                Ok(0) | Err(_) if !observed_output && Instant::now() < startup_deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(0) | Err(_) => break,
                Ok(length) => {
                    observed_output = true;
                    if sender.send(chunk[..length].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    (terminal, child, receiver)
}

fn wait_for_occurrences(
    receiver: &mpsc::Receiver<Vec<u8>>,
    output: &mut Vec<u8>,
    needle: &[u8],
    expected: usize,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    while count_occurrences(output, needle) < expected {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "PTY output did not contain {expected} prompts: {}",
            String::from_utf8_lossy(output)
        );
        let chunk = receiver
            .recv_timeout(remaining)
            .expect("PTY output before deadline");
        output.extend_from_slice(&chunk);
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
