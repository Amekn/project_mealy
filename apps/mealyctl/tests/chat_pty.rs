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
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{Read, Write},
    net::TcpListener as StdTcpListener,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
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
async fn bare_mealyctl_enters_onboarding_or_a_new_chat_from_home_state() {
    let clean_home = tempfile::tempdir().expect("clean bare-command home");
    fs::set_permissions(clean_home.path(), fs::Permissions::from_mode(0o700))
        .expect("private clean home");
    let (mut clean_terminal, mut clean_child) = spawn_bare_mealyctl(clean_home.path());
    let mut clean_rendered = Vec::new();
    wait_for_occurrences(
        &mut clean_terminal,
        &mut clean_rendered,
        b"How should Mealy access a model?",
        1,
        Duration::from_secs(5),
    );
    assert!(!clean_home.path().join("config.json").exists());
    clean_terminal
        .write_all(b"q\n")
        .and_then(|()| clean_terminal.flush())
        .expect("cancel clean-home route prompt");
    let clean_status = wait_for_child(&mut clean_child, Duration::from_secs(5));
    assert!(!clean_status.success());
    assert!(!clean_home.path().join("config.json").exists());

    let noninteractive_home = tempfile::tempdir().expect("noninteractive bare-command home");
    let noninteractive = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(noninteractive_home.path())
        .stdin(Stdio::null())
        .output()
        .expect("run bare command without a terminal");
    assert!(!noninteractive.status.success());
    assert!(
        String::from_utf8_lossy(&noninteractive.stderr)
            .contains("without a subcommand requires interactive stdin, stdout, and stderr")
    );
    assert!(!noninteractive_home.path().join("config.json").exists());

    let state = AdmissionState::default();
    let (base_url, server) = spawn_control_plane(state.clone()).await;
    let configured_home = tempfile::tempdir().expect("configured bare-command home");
    fs::set_permissions(configured_home.path(), fs::Permissions::from_mode(0o700))
        .expect("private configured home");
    write_connection(configured_home.path(), &base_url);
    let config = configured_home.path().join("config.json");
    fs::write(&config, b"{}").expect("write configured-home marker");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600))
        .expect("private configured-home marker");
    let (mut terminal, mut child) = spawn_bare_mealyctl(configured_home.path());
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
    assert_eq!(state.created_sessions.load(Ordering::SeqCst), 1);
    terminal
        .write_all(b"/quit\n")
        .and_then(|()| terminal.flush())
        .expect("quit bare-command chat");
    let status = wait_for_child(&mut child, Duration::from_secs(5));
    assert!(
        status.success(),
        "bare configured command failed: {}; terminal: {}",
        status,
        String::from_utf8_lossy(&rendered)
    );
    server.abort();
}

#[test]
fn onboarding_hidden_prompt_brokers_openrouter_credential_without_echoing_it() {
    let home = tempfile::tempdir().expect("OpenRouter hidden-prompt home");
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700))
        .expect("private OpenRouter home");
    let probe = provider_probe_body("vendor/tool-model:free");
    let (base_url, requests, server) = serve_provider_onboarding(vec![
        ("application/json", strict_free_openrouter_catalog()),
        ("text/event-stream", probe),
    ]);
    let secret = "pty-openrouter-hidden-secret";
    let arguments = [
        "--route",
        "openrouter-free",
        "--base-url",
        &base_url,
        "--configure-only",
        "--approve",
    ];
    let (mut terminal, mut child) = spawn_mealyctl_pty_with_removed_environment(
        home.path(),
        Some("onboard"),
        &arguments,
        &["OPENROUTER_API_KEY"],
    );
    let mut rendered = Vec::new();
    wait_for_occurrences(
        &mut terminal,
        &mut rendered,
        b"OpenRouter free model API credential (input hidden): ",
        1,
        Duration::from_secs(5),
    );
    terminal
        .write_all(format!("{secret}\n").as_bytes())
        .and_then(|()| terminal.flush())
        .expect("enter hidden OpenRouter credential");
    wait_for_occurrences(
        &mut terminal,
        &mut rendered,
        b"Model number: ",
        1,
        Duration::from_secs(5),
    );
    terminal
        .write_all(b"1\n")
        .and_then(|()| terminal.flush())
        .expect("select discovered free model");
    let status = wait_for_child_and_collect(
        &mut terminal,
        &mut child,
        &mut rendered,
        Duration::from_secs(10),
    );
    assert!(
        status.success(),
        "OpenRouter hidden-prompt onboarding failed: {}; terminal: {}",
        status,
        String::from_utf8_lossy(&rendered)
    );
    assert!(
        !rendered
            .windows(secret.len())
            .any(|window| window == secret.as_bytes())
    );
    let visible = String::from_utf8_lossy(&rendered);
    assert!(visible.contains("Model number: 1\r\n"));
    assert!(visible.contains("credential source: hidden terminal prompt"));
    assert!(visible.contains("OPENROUTER_API_KEY was absent"));
    assert_brokered_onboarding(
        home.path(),
        "openrouter.responses",
        "vendor/tool-model:free",
        "openrouter-primary",
        secret,
    );
    let requests = requests
        .recv_timeout(Duration::from_secs(2))
        .expect("captured OpenRouter onboarding requests");
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /v1/models/user HTTP/1.1\r\n"));
    assert!(requests[1].starts_with("POST /v1/responses HTTP/1.1\r\n"));
    assert_bearer_headers(&requests, secret);
    server.join().expect("OpenRouter onboarding server");
}

#[test]
fn onboarding_hidden_prompt_brokers_custom_endpoint_credential_without_echoing_it() {
    let home = tempfile::tempdir().expect("custom hidden-prompt home");
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700))
        .expect("private custom home");
    let (base_url, requests, server) = serve_provider_onboarding(vec![(
        "text/event-stream",
        provider_probe_body("custom-tool-model"),
    )]);
    let secret = "pty-custom-hidden-secret";
    let arguments = [
        "--route",
        "custom",
        "--model",
        "custom-tool-model",
        "--context-tokens",
        "32768",
        "--input-microunits-per-million-tokens",
        "0",
        "--output-microunits-per-million-tokens",
        "0",
        "--configure-only",
        "--approve",
    ];
    let (mut terminal, mut child) = spawn_mealyctl_pty_with_removed_environment(
        home.path(),
        Some("onboard"),
        &arguments,
        &["CUSTOM_API_KEY"],
    );
    let mut rendered = Vec::new();
    wait_for_occurrences(
        &mut terminal,
        &mut rendered,
        b"OpenAI-compatible HTTPS API base URL: ",
        1,
        Duration::from_secs(5),
    );
    terminal
        .write_all(format!("{base_url}\n").as_bytes())
        .and_then(|()| terminal.flush())
        .expect("enter custom endpoint base URL");
    wait_for_occurrences(
        &mut terminal,
        &mut rendered,
        b"custom authenticated OpenAI-compatible endpoint API credential (input hidden): ",
        1,
        Duration::from_secs(5),
    );
    terminal
        .write_all(format!("{secret}\n").as_bytes())
        .and_then(|()| terminal.flush())
        .expect("enter hidden custom endpoint credential");
    let status = wait_for_child_and_collect(
        &mut terminal,
        &mut child,
        &mut rendered,
        Duration::from_secs(10),
    );
    assert!(
        status.success(),
        "custom hidden-prompt onboarding failed: {}; terminal: {}",
        status,
        String::from_utf8_lossy(&rendered)
    );
    assert!(
        !rendered
            .windows(secret.len())
            .any(|window| window == secret.as_bytes())
    );
    let visible = String::from_utf8_lossy(&rendered);
    assert!(visible.contains("credential source: hidden terminal prompt"));
    assert!(visible.contains("CUSTOM_API_KEY was absent"));
    assert_brokered_onboarding(
        home.path(),
        "custom.responses",
        "custom-tool-model",
        "custom-primary",
        secret,
    );
    let requests = requests
        .recv_timeout(Duration::from_secs(2))
        .expect("captured custom onboarding request");
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("POST /v1/responses HTTP/1.1\r\n"));
    assert_bearer_headers(&requests, secret);
    server.join().expect("custom onboarding server");
}

#[test]
fn onboarding_without_a_credential_or_terminal_fails_before_mutation() {
    let home = tempfile::tempdir().expect("nonterminal credential home");
    let output = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args([
            "onboard",
            "--route",
            "custom",
            "--base-url",
            "https://example.invalid/v1",
            "--model",
            "custom-model",
            "--context-tokens",
            "32768",
            "--input-microunits-per-million-tokens",
            "0",
            "--output-microunits-per-million-tokens",
            "0",
            "--configure-only",
            "--approve",
        ])
        .env_remove("CUSTOM_API_KEY")
        .stdin(Stdio::null())
        .output()
        .expect("run nonterminal credential onboarding");
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("provider credential CUSTOM_API_KEY is absent"));
    assert!(error.contains("rerun onboarding with terminal stdin and stderr"));
    assert!(!home.path().join("config.json").exists());
    assert!(!home.path().join("provider-secrets").exists());
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

fn strict_free_openrouter_catalog() -> String {
    json!({
        "data": [{
            "id": "vendor/tool-model:free",
            "name": "Tool Model Free",
            "created": 50,
            "context_length": 32768,
            "pricing": {
                "prompt": "0",
                "completion": "0",
                "request": "0",
                "image": "0",
                "web_search": "0",
                "internal_reasoning": "0",
                "input_cache_read": "0",
                "input_cache_write": "0"
            },
            "supported_parameters": ["max_tokens", "tools"],
            "architecture": {"output_modalities": ["text"]},
            "top_provider": {
                "context_length": 32768,
                "max_completion_tokens": 8192
            }
        }]
    })
    .to_string()
}

fn provider_probe_body(model: &str) -> String {
    let completed = json!({
        "id": "resp-hidden-prompt-onboarding",
        "object": "response",
        "model": model,
        "status": "completed",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "OK"}]
        }]
    });
    let event = json!({"type": "response.completed", "response": completed});
    format!("event: response.completed\ndata: {event}\n\ndata: [DONE]\n\n")
}

fn serve_provider_onboarding(
    responses: Vec<(&'static str, String)>,
) -> (String, mpsc::Receiver<Vec<String>>, thread::JoinHandle<()>) {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind provider onboarding fixture");
    let address = listener.local_addr().expect("provider fixture address");
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut captured = Vec::new();
        for (content_type, response_body) in responses {
            let (mut stream, _) = listener.accept().expect("accept provider request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("provider request timeout");
            let mut raw = Vec::new();
            let mut chunk = [0_u8; 4_096];
            let header_end = loop {
                let read = stream.read(&mut chunk).expect("read provider request");
                assert!(read != 0, "provider request ended before headers");
                raw.extend_from_slice(&chunk[..read]);
                if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                    break position + 4;
                }
            };
            let headers =
                String::from_utf8(raw[..header_end].to_vec()).expect("provider request headers");
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("content length"))
                    })
                })
                .unwrap_or_default();
            while raw.len().saturating_sub(header_end) < content_length {
                let read = stream.read(&mut chunk).expect("read provider request body");
                assert!(read != 0, "provider request ended before its body");
                raw.extend_from_slice(&chunk[..read]);
            }
            captured.push(headers);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                response_body.len()
            )
            .expect("write provider fixture response");
        }
        sender.send(captured).expect("publish captured requests");
    });
    (format!("http://{address}/v1"), receiver, handle)
}

fn assert_bearer_headers(requests: &[String], secret: &str) {
    assert!(requests.iter().all(|headers| {
        headers.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("authorization")
                    && value.trim() == format!("Bearer {secret}")
            })
        })
    }));
}

fn assert_brokered_onboarding(
    home: &std::path::Path,
    provider_id: &str,
    model: &str,
    secret_id: &str,
    secret: &str,
) {
    let config: Value = serde_json::from_slice(
        &fs::read(home.join("config.json")).expect("hidden-prompt provider configuration"),
    )
    .expect("hidden-prompt provider configuration JSON");
    assert_eq!(config["provider"]["providerId"], provider_id);
    assert_eq!(config["provider"]["model"], model);
    assert_eq!(config["provider"]["credential"]["secretId"], secret_id);
    assert!(!config.to_string().contains(secret));
    assert_eq!(
        fs::read(home.join(format!("provider-secrets/{secret_id}.key")))
            .expect("brokered hidden-prompt secret"),
        secret.as_bytes()
    );
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
    spawn_mealyctl_pty(home, Some("chat"), arguments)
}

fn spawn_bare_mealyctl(home: &std::path::Path) -> (File, Child) {
    spawn_mealyctl_pty(home, None, &[])
}

fn spawn_mealyctl_pty(
    home: &std::path::Path,
    subcommand: Option<&str>,
    arguments: &[&str],
) -> (File, Child) {
    spawn_mealyctl_pty_with_removed_environment(home, subcommand, arguments, &[])
}

fn spawn_mealyctl_pty_with_removed_environment(
    home: &std::path::Path,
    subcommand: Option<&str>,
    arguments: &[&str],
    removed_environment: &[&str],
) -> (File, Child) {
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
    let mut command = Command::new(env!("CARGO_BIN_EXE_mealyctl"));
    command.arg("--home").arg(home);
    if let Some(subcommand) = subcommand {
        command.arg(subcommand);
    }
    for variable in removed_environment {
        command.env_remove(variable);
    }
    let child = command
        .args(arguments)
        .stdin(stdin)
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .expect("spawn Mealy terminal process");
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

fn wait_for_child_and_collect(
    terminal: &mut File,
    child: &mut Child,
    output: &mut Vec<u8>,
    timeout: Duration,
) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        read_available_terminal_output(terminal, output);
        if let Some(status) = child.try_wait().expect("poll terminal process") {
            read_available_terminal_output(terminal, output);
            return status;
        }
        assert!(Instant::now() < deadline, "terminal process did not exit");
        thread::sleep(Duration::from_millis(10));
    }
}

fn read_available_terminal_output(terminal: &mut File, output: &mut Vec<u8>) {
    let mut chunk = [0_u8; 1_024];
    loop {
        match terminal.read(&mut chunk) {
            Ok(0) => return,
            Ok(length) => output.extend_from_slice(&chunk[..length]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) || error.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error()) =>
            {
                return;
            }
            Err(error) => panic!(
                "PTY read failed while collecting output: {error}; output: {}",
                String::from_utf8_lossy(output)
            ),
        }
    }
}
