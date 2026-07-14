//! Public-process proof for the temporary least-authority operations dashboard.

#![recursion_limit = "256"]

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mealy_protocol::API_VERSION;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead as _, BufReader},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tempfile::TempDir;
use tokio::{net::TcpListener, task::JoinHandle};

const DAEMON_TOKEN: &str = "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws";
const SESSION_ID: &str = "019f0000-0000-7000-8000-000000000010";
const TURN_ID: &str = "019f0000-0000-7000-8000-000000000011";
const TASK_ID: &str = "019f0000-0000-7000-8000-000000000012";
const OVERSIZED_TASK_USAGE_ID: &str = "019f0000-0000-7000-8000-000000000070";
const APPROVAL_ID: &str = "019f0000-0000-7000-8000-000000000013";
const EFFECT_ID: &str = "019f0000-0000-7000-8000-000000000014";
const ATTEMPT_ID: &str = "019f0000-0000-7000-8000-000000000015";
const RUN_ID: &str = "019f0000-0000-7000-8000-000000000016";
const SCHEDULE_ID: &str = "019f0000-0000-7000-8000-000000000017";
const SCHEDULE_RUN_ID: &str = "019f0000-0000-7000-8000-000000000018";
const SCHEDULE_INBOX_ID: &str = "019f0000-0000-7000-8000-000000000019";
const CREATED_SCHEDULE_ID: &str = "019f0000-0000-7000-8000-000000000080";
const MEMORY_ID: &str = "019f0000-0000-7000-8000-000000000040";
const SECOND_MEMORY_ID: &str = "019f0000-0000-7000-8000-000000000041";
const OVERSIZED_MEMORY_ID: &str = "019f0000-0000-7000-8000-000000000042";
const MEMORY_REVISION_ID: &str = "019f0000-0000-7000-8000-000000000043";
const MEMORY_CORRECTION_ID: &str = "019f0000-0000-7000-8000-000000000044";
const SECOND_MEMORY_REVISION_ID: &str = "019f0000-0000-7000-8000-000000000045";
const MEMORY_WORKSPACE: &str = "mealy://assistant/no-workspace";
const EXTENSION_ID: &str = "019f0000-0000-7000-8000-000000000060";
const EXTENSION_GRANT_ID: &str = "019f0000-0000-7000-8000-000000000061";
const SUBJECT_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DAY_MS: i64 = 86_400_000;

#[derive(Clone)]
struct MockState {
    requests: Arc<AtomicUsize>,
    commands: Arc<Mutex<Vec<(String, Value)>>>,
    memory: Arc<Mutex<Vec<Value>>>,
    extension: Arc<Mutex<Value>>,
    created_schedule: Arc<Mutex<Option<(Value, Value)>>>,
}

struct DashboardProcess(Child);

impl Drop for DashboardProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn dashboard_is_interactive_idempotent_origin_bound_and_never_exposes_daemon_bearer() {
    let (daemon_origin, requests, commands, daemon) = spawn_mock_daemon().await;
    let home = TempDir::new().expect("temporary Mealy home");
    let descriptor = json!({
        "apiVersion": API_VERSION,
        "baseUrl": daemon_origin,
        "bearerToken": DAEMON_TOKEN,
        "principalId": "019f0000-0000-7000-8000-000000000001",
        "channelBindingId": "019f0000-0000-7000-8000-000000000002"
    });
    let descriptor_path = home.path().join("connection.json");
    fs::write(
        &descriptor_path,
        serde_json::to_vec(&descriptor).expect("descriptor JSON"),
    )
    .expect("connection descriptor");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&descriptor_path, fs::Permissions::from_mode(0o600))
            .expect("private descriptor");
    }

    let mut child = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .arg("dashboard")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start dashboard");
    let mut output = BufReader::new(child.stdout.take().expect("dashboard stdout"));
    let mut line = String::new();
    output.read_line(&mut line).expect("dashboard URL");
    let dashboard_origin = line
        .trim()
        .strip_prefix("Mealy interactive dashboard: ")
        .and_then(|value| value.strip_suffix('/'))
        .expect("dashboard origin")
        .to_owned();
    let mut dashboard = DashboardProcess(child);
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("HTTP client");

    let root = client
        .get(format!("{dashboard_origin}/"))
        .send()
        .await
        .expect("dashboard HTML");
    assert_eq!(root.status(), StatusCode::OK);
    assert_eq!(
        root.headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let csp = root
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok())
        .expect("dashboard CSP")
        .to_owned();
    assert!(csp.contains("default-src 'none'"));
    assert!(csp.contains("frame-ancestors 'none'"));
    let html = root.text().await.expect("dashboard HTML body");
    assert!(html.contains("Mealy Operations"));
    assert!(html.contains("Temporary interactive console"));
    assert!(!html.contains(DAEMON_TOKEN));
    let dashboard_token = extract_dashboard_token(&html);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(&dashboard_token)
            .expect("dashboard token")
            .len(),
        32
    );

    let unauthorized = client
        .get(format!("{dashboard_origin}/api/snapshot"))
        .send()
        .await
        .expect("unauthorized snapshot");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    let rebound = client
        .get(format!("{dashboard_origin}/"))
        .header(header::HOST, "attacker.example")
        .send()
        .await
        .expect("rebound request");
    assert_eq!(rebound.status(), StatusCode::MISDIRECTED_REQUEST);

    let snapshot = client
        .get(format!("{dashboard_origin}/api/snapshot"))
        .header("x-mealy-dashboard", &dashboard_token)
        .send()
        .await
        .expect("authorized snapshot");
    assert_eq!(snapshot.status(), StatusCode::OK);
    let snapshot = snapshot.json::<Value>().await.expect("snapshot JSON");
    assert_eq!(snapshot["apiVersion"], API_VERSION);
    assert_eq!(snapshot["status"]["providerId"], "dashboard-fixture");
    assert_eq!(
        snapshot["usage"]["buckets"][0]["usedCostMicrounits"],
        321_000
    );
    assert_eq!(
        snapshot["approvals"]["approvals"][0]["approvalId"],
        APPROVAL_ID
    );
    assert!(!snapshot.to_string().contains(DAEMON_TOKEN));

    let task_usage_without_origin = client
        .post(format!("{dashboard_origin}/api/tasks/{TASK_ID}/usage"))
        .header("x-mealy-dashboard", &dashboard_token)
        .json(&json!({"apiVersion": API_VERSION}))
        .send()
        .await
        .expect("task usage origin denial");
    assert_eq!(task_usage_without_origin.status(), StatusCode::FORBIDDEN);
    let invalid_task_usage = client
        .post(format!("{dashboard_origin}/api/tasks/not-a-uuid/usage"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"apiVersion": API_VERSION}))
        .send()
        .await
        .expect("invalid task usage identifier denial");
    assert_eq!(invalid_task_usage.status(), StatusCode::BAD_REQUEST);
    let widened_task_usage = client
        .post(format!("{dashboard_origin}/api/tasks/{TASK_ID}/usage"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"apiVersion": API_VERSION, "currency": "USD"}))
        .send()
        .await
        .expect("widened task usage denial");
    assert_eq!(widened_task_usage.status(), StatusCode::BAD_REQUEST);
    let task_usage = client
        .post(format!("{dashboard_origin}/api/tasks/{TASK_ID}/usage"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"apiVersion": API_VERSION}))
        .send()
        .await
        .expect("task usage");
    assert_eq!(task_usage.status(), StatusCode::OK);
    let task_usage = task_usage.json::<Value>().await.expect("task usage JSON");
    assert_eq!(task_usage["taskId"], TASK_ID);
    assert_eq!(task_usage["usage"]["usedCostMicrounits"], 123_456);
    assert_eq!(task_usage["usage"]["reservedCostMicrounits"], 500);
    assert!(!task_usage.to_string().contains(DAEMON_TOKEN));
    let oversized_task_usage = client
        .post(format!(
            "{dashboard_origin}/api/tasks/{OVERSIZED_TASK_USAGE_ID}/usage"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"apiVersion": API_VERSION}))
        .send()
        .await
        .expect("oversized task usage denial");
    assert_eq!(
        oversized_task_usage.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(
        !oversized_task_usage
            .text()
            .await
            .expect("oversized task usage error")
            .contains(DAEMON_TOKEN)
    );

    let missing_origin = client
        .post(format!("{dashboard_origin}/api/sessions"))
        .header("x-mealy-dashboard", &dashboard_token)
        .json(&json!({"apiVersion": API_VERSION}))
        .send()
        .await
        .expect("origin-bound mutation");
    assert_eq!(missing_origin.status(), StatusCode::FORBIDDEN);
    assert_eq!(requests.load(Ordering::SeqCst), 14);

    let unknown_field = client
        .post(format!("{dashboard_origin}/api/sessions"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"apiVersion": API_VERSION, "daemonPath": "/v1/admin/drain"}))
        .send()
        .await
        .expect("unknown field denial");
    assert_eq!(unknown_field.status(), StatusCode::BAD_REQUEST);
    assert_eq!(requests.load(Ordering::SeqCst), 14);

    let created = client
        .post(format!("{dashboard_origin}/api/sessions"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"apiVersion": API_VERSION}))
        .send()
        .await
        .expect("create session");
    assert_eq!(created.status(), StatusCode::OK);
    assert_eq!(
        created.json::<Value>().await.expect("creation JSON")["sessionId"],
        SESSION_ID
    );

    let invalid_identifier = client
        .get(format!(
            "{dashboard_origin}/api/sessions/not-a-uuid/timeline?after=0&limit=200"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .send()
        .await
        .expect("invalid identifier denial");
    assert_eq!(invalid_identifier.status(), StatusCode::BAD_REQUEST);

    let timeline = client
        .get(format!(
            "{dashboard_origin}/api/sessions/{SESSION_ID}/timeline?after=0&limit=200"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .send()
        .await
        .expect("conversation timeline");
    assert_eq!(timeline.status(), StatusCode::OK);
    let timeline = timeline.json::<Value>().await.expect("timeline JSON");
    assert_eq!(timeline["status"]["sessionId"], SESSION_ID);
    assert_eq!(timeline["activeTaskId"], TASK_ID);
    assert_eq!(
        timeline["timeline"]["events"][0]["eventType"],
        "task.created"
    );

    let input_key = "dashboard-input-stable-1";
    let input = client
        .post(format!(
            "{dashboard_origin}/api/sessions/{SESSION_ID}/inputs"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "idempotencyKey": input_key,
            "deliveryMode": "queue",
            "content": "Produce the bounded release brief"
        }))
        .send()
        .await
        .expect("submit input");
    assert_eq!(input.status(), StatusCode::OK);
    assert_eq!(
        input.json::<Value>().await.expect("input JSON")["duplicate"],
        false
    );

    let approval_key = "dashboard-approval-stable-1";
    let approval = client
        .post(format!(
            "{dashboard_origin}/api/approvals/{APPROVAL_ID}/resolve"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "idempotencyKey": approval_key,
            "expectedSubjectDigest": SUBJECT_DIGEST,
            "decision": "approve"
        }))
        .send()
        .await
        .expect("resolve approval");
    assert_eq!(approval.status(), StatusCode::OK);
    assert_eq!(
        approval.json::<Value>().await.expect("approval JSON")["decision"],
        "approve"
    );

    let cancellation_key = "dashboard-cancel-stable-1";
    let cancellation = client
        .post(format!("{dashboard_origin}/api/tasks/{TASK_ID}/cancel"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "idempotencyKey": cancellation_key,
            "reason": "Cancelled from the temporary Mealy dashboard."
        }))
        .send()
        .await
        .expect("cancel task");
    assert_eq!(cancellation.status(), StatusCode::OK);
    assert_eq!(
        cancellation
            .json::<Value>()
            .await
            .expect("cancellation JSON")["taskId"],
        TASK_ID
    );

    let invalid_effect = client
        .get(format!("{dashboard_origin}/api/effects/not-a-uuid"))
        .header("x-mealy-dashboard", &dashboard_token)
        .send()
        .await
        .expect("invalid effect identifier denial");
    assert_eq!(invalid_effect.status(), StatusCode::BAD_REQUEST);
    assert_eq!(requests.load(Ordering::SeqCst), 20);

    let invalid_attempt = client
        .get(format!("{dashboard_origin}/api/effect-attempts/not-a-uuid"))
        .header("x-mealy-dashboard", &dashboard_token)
        .send()
        .await
        .expect("invalid attempt identifier denial");
    assert_eq!(invalid_attempt.status(), StatusCode::BAD_REQUEST);
    let cross_origin_effect = client
        .get(format!("{dashboard_origin}/api/effects/{EFFECT_ID}"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, "http://attacker.invalid")
        .send()
        .await
        .expect("cross-origin effect denial");
    assert_eq!(cross_origin_effect.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(requests.load(Ordering::SeqCst), 20);

    let effect = client
        .get(format!("{dashboard_origin}/api/effects/{EFFECT_ID}"))
        .header("x-mealy-dashboard", &dashboard_token)
        .send()
        .await
        .expect("effect detail");
    assert_eq!(effect.status(), StatusCode::OK);
    let effect = effect.json::<Value>().await.expect("effect detail JSON");
    assert_eq!(effect["effectId"], EFFECT_ID);
    assert_eq!(effect["status"], "outcome_unknown");
    assert_eq!(effect["revision"], 4);
    assert!(!effect.to_string().contains(DAEMON_TOKEN));

    let attempt = client
        .get(format!(
            "{dashboard_origin}/api/effect-attempts/{ATTEMPT_ID}"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .send()
        .await
        .expect("effect-attempt detail");
    assert_eq!(attempt.status(), StatusCode::OK);
    let attempt = attempt
        .json::<Value>()
        .await
        .expect("effect-attempt detail JSON");
    assert_eq!(attempt["attemptId"], ATTEMPT_ID);
    assert_eq!(attempt["effectId"], EFFECT_ID);
    assert_eq!(attempt["status"], "outcome_unknown");

    let reconcile_without_origin = client
        .post(format!(
            "{dashboard_origin}/api/effects/{EFFECT_ID}/attempts/{ATTEMPT_ID}/reconcile"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .json(&json!({
            "apiVersion": API_VERSION,
            "idempotencyKey": "dashboard-reconcile-stable-1",
            "expectedEffectRevision": 4,
            "outcome": "succeeded",
            "evidence": {"operatorObservation": "destination digest matched"}
        }))
        .send()
        .await
        .expect("reconciliation origin denial");
    assert_eq!(reconcile_without_origin.status(), StatusCode::FORBIDDEN);
    assert_eq!(requests.load(Ordering::SeqCst), 22);

    let empty_reconciliation = client
        .post(format!(
            "{dashboard_origin}/api/effects/{EFFECT_ID}/attempts/{ATTEMPT_ID}/reconcile"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "idempotencyKey": "dashboard-reconcile-empty",
            "expectedEffectRevision": 4,
            "outcome": "failed",
            "evidence": {}
        }))
        .send()
        .await
        .expect("empty reconciliation denial");
    assert_eq!(empty_reconciliation.status(), StatusCode::BAD_REQUEST);
    assert_eq!(requests.load(Ordering::SeqCst), 22);

    let widened_reconciliation = client
        .post(format!(
            "{dashboard_origin}/api/effects/{EFFECT_ID}/attempts/{ATTEMPT_ID}/reconcile"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "idempotencyKey": "dashboard-reconcile-widened",
            "expectedEffectRevision": 4,
            "outcome": "failed",
            "evidence": {"operatorObservation": "not dispatched"},
            "daemonPath": "/v1/admin/drain"
        }))
        .send()
        .await
        .expect("widened reconciliation denial");
    assert_eq!(widened_reconciliation.status(), StatusCode::BAD_REQUEST);
    assert_eq!(requests.load(Ordering::SeqCst), 22);

    let reconciliation_key = "dashboard-reconcile-stable-1";
    let reconciliation_evidence = json!({
        "operatorObservation": "approved source is absent and destination digest matched",
        "destinationDigest": "f".repeat(64)
    });
    let reconciliation = client
        .post(format!(
            "{dashboard_origin}/api/effects/{EFFECT_ID}/attempts/{ATTEMPT_ID}/reconcile"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "idempotencyKey": reconciliation_key,
            "expectedEffectRevision": 4,
            "outcome": "succeeded",
            "evidence": reconciliation_evidence
        }))
        .send()
        .await
        .expect("reconcile effect");
    assert_eq!(reconciliation.status(), StatusCode::OK);
    let reconciliation = reconciliation
        .json::<Value>()
        .await
        .expect("reconciliation receipt JSON");
    assert_eq!(reconciliation["effectId"], EFFECT_ID);
    assert_eq!(reconciliation["attemptId"], ATTEMPT_ID);
    assert_eq!(reconciliation["outcome"], "succeeded");
    assert_eq!(reconciliation["effectRevision"], 5);

    let invalid_schedule = client
        .get(format!("{dashboard_origin}/api/schedules/not-a-uuid"))
        .header("x-mealy-dashboard", &dashboard_token)
        .send()
        .await
        .expect("invalid schedule identifier denial");
    assert_eq!(invalid_schedule.status(), StatusCode::BAD_REQUEST);
    let invalid_run_limit = client
        .get(format!(
            "{dashboard_origin}/api/schedules/{SCHEDULE_ID}/runs?limit=101"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .send()
        .await
        .expect("invalid schedule run limit denial");
    assert_eq!(invalid_run_limit.status(), StatusCode::BAD_REQUEST);
    let cross_origin_schedule = client
        .get(format!("{dashboard_origin}/api/schedules/{SCHEDULE_ID}"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, "http://attacker.invalid")
        .send()
        .await
        .expect("cross-origin schedule denial");
    assert_eq!(cross_origin_schedule.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(requests.load(Ordering::SeqCst), 23);

    let schedule = client
        .get(format!("{dashboard_origin}/api/schedules/{SCHEDULE_ID}"))
        .header("x-mealy-dashboard", &dashboard_token)
        .send()
        .await
        .expect("schedule detail");
    assert_eq!(schedule.status(), StatusCode::OK);
    let schedule = schedule
        .json::<Value>()
        .await
        .expect("schedule detail JSON");
    assert_eq!(schedule["scheduleId"], SCHEDULE_ID);
    assert_eq!(schedule["status"], "active");
    assert_eq!(schedule["revision"], 7);

    let schedule_runs = client
        .get(format!(
            "{dashboard_origin}/api/schedules/{SCHEDULE_ID}/runs?limit=50"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .send()
        .await
        .expect("schedule run history");
    assert_eq!(schedule_runs.status(), StatusCode::OK);
    let schedule_runs = schedule_runs
        .json::<Value>()
        .await
        .expect("schedule run history JSON");
    assert_eq!(schedule_runs["scheduleId"], SCHEDULE_ID);
    assert_eq!(schedule_runs["runs"][0]["scheduleRunId"], SCHEDULE_RUN_ID);

    let schedule_without_origin = client
        .post(format!(
            "{dashboard_origin}/api/schedules/{SCHEDULE_ID}/pause"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .json(&json!({"apiVersion": API_VERSION, "expectedRevision": 7}))
        .send()
        .await
        .expect("schedule lifecycle origin denial");
    assert_eq!(schedule_without_origin.status(), StatusCode::FORBIDDEN);
    let widened_schedule = client
        .post(format!(
            "{dashboard_origin}/api/schedules/{SCHEDULE_ID}/pause"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "expectedRevision": 7,
            "operation": "cancel"
        }))
        .send()
        .await
        .expect("widened schedule lifecycle denial");
    assert_eq!(widened_schedule.status(), StatusCode::BAD_REQUEST);
    let overflowing_schedule = client
        .post(format!(
            "{dashboard_origin}/api/schedules/{SCHEDULE_ID}/pause"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "expectedRevision": u64::MAX
        }))
        .send()
        .await
        .expect("overflowing schedule revision denial");
    assert_eq!(overflowing_schedule.status(), StatusCode::BAD_REQUEST);
    assert_eq!(requests.load(Ordering::SeqCst), 25);

    let paused = client
        .post(format!(
            "{dashboard_origin}/api/schedules/{SCHEDULE_ID}/pause"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"apiVersion": API_VERSION, "expectedRevision": 7}))
        .send()
        .await
        .expect("pause schedule");
    assert_eq!(paused.status(), StatusCode::OK);
    let paused = paused.json::<Value>().await.expect("paused schedule JSON");
    assert_eq!(paused["status"], "paused");
    assert_eq!(paused["revision"], 8);

    let resumed = client
        .post(format!(
            "{dashboard_origin}/api/schedules/{SCHEDULE_ID}/resume"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"apiVersion": API_VERSION, "expectedRevision": 8}))
        .send()
        .await
        .expect("resume schedule");
    assert_eq!(resumed.status(), StatusCode::OK);
    let resumed = resumed
        .json::<Value>()
        .await
        .expect("resumed schedule JSON");
    assert_eq!(resumed["status"], "active");
    assert_eq!(resumed["revision"], 9);

    let cancelled_schedule = client
        .post(format!(
            "{dashboard_origin}/api/schedules/{SCHEDULE_ID}/cancel"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"apiVersion": API_VERSION, "expectedRevision": 9}))
        .send()
        .await
        .expect("cancel schedule");
    assert_eq!(cancelled_schedule.status(), StatusCode::OK);
    let cancelled_schedule = cancelled_schedule
        .json::<Value>()
        .await
        .expect("cancelled schedule JSON");
    assert_eq!(cancelled_schedule["status"], "cancelled");
    assert_eq!(cancelled_schedule["revision"], 10);

    let schedule_create_body = json!({
        "apiVersion": API_VERSION,
        "scheduleId": CREATED_SCHEDULE_ID,
        "sessionId": SESSION_ID,
        "name": "keyed dashboard creation",
        "prompt": "Review the durable keyed creation evidence.",
        "cronExpression": "0 9 * * *",
        "timezone": "Pacific/Auckland",
        "missedRunPolicy": "latest",
        "overlapPolicy": "skip_if_running",
        "misfireGraceMs": 60_000,
        "allowApprovalRequiredAction": false
    });
    let create_without_origin = client
        .post(format!("{dashboard_origin}/api/schedules"))
        .header("x-mealy-dashboard", &dashboard_token)
        .json(&schedule_create_body)
        .send()
        .await
        .expect("schedule creation origin denial");
    assert_eq!(create_without_origin.status(), StatusCode::FORBIDDEN);
    let mut widened_create = schedule_create_body.clone();
    widened_create["daemonPath"] = json!("/v1/admin/drain");
    let widened_create = client
        .post(format!("{dashboard_origin}/api/schedules"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&widened_create)
        .send()
        .await
        .expect("widened schedule creation denial");
    assert_eq!(widened_create.status(), StatusCode::BAD_REQUEST);
    let mut non_v7_create = schedule_create_body.clone();
    non_v7_create["scheduleId"] = json!("019f0000-0000-4000-8000-000000000080");
    let non_v7_create = client
        .post(format!("{dashboard_origin}/api/schedules"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&non_v7_create)
        .send()
        .await
        .expect("non-v7 schedule creation denial");
    assert_eq!(non_v7_create.status(), StatusCode::BAD_REQUEST);
    let mut unapproved_action_create = schedule_create_body.clone();
    unapproved_action_create["prompt"] = json!("/run perform a scheduled action");
    let unapproved_action_create = client
        .post(format!("{dashboard_origin}/api/schedules"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&unapproved_action_create)
        .send()
        .await
        .expect("unapproved action schedule denial");
    assert_eq!(unapproved_action_create.status(), StatusCode::BAD_REQUEST);

    let created_schedule = client
        .post(format!("{dashboard_origin}/api/schedules"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&schedule_create_body)
        .send()
        .await
        .expect("keyed schedule creation");
    assert_eq!(created_schedule.status(), StatusCode::OK);
    let created_schedule = created_schedule
        .json::<Value>()
        .await
        .expect("created schedule JSON");
    assert_eq!(created_schedule["scheduleId"], CREATED_SCHEDULE_ID);
    assert_eq!(created_schedule["revision"], 0);
    let duplicate_schedule = client
        .post(format!("{dashboard_origin}/api/schedules"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&schedule_create_body)
        .send()
        .await
        .expect("duplicate schedule creation");
    assert_eq!(duplicate_schedule.status(), StatusCode::OK);
    assert_eq!(
        duplicate_schedule
            .json::<Value>()
            .await
            .expect("duplicate schedule JSON"),
        created_schedule
    );
    let mut conflicting_create = schedule_create_body.clone();
    conflicting_create["name"] = json!("conflicting schedule definition");
    let conflicting_create = client
        .post(format!("{dashboard_origin}/api/schedules"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&conflicting_create)
        .send()
        .await
        .expect("conflicting schedule creation denial");
    assert_eq!(conflicting_create.status(), StatusCode::CONFLICT);

    let memory_without_origin = client
        .post(format!("{dashboard_origin}/api/memories/list"))
        .header("x-mealy-dashboard", &dashboard_token)
        .json(&json!({
            "apiVersion": API_VERSION,
            "workspaceIdentity": MEMORY_WORKSPACE,
            "includeDeleted": false
        }))
        .send()
        .await
        .expect("memory query origin denial");
    assert_eq!(memory_without_origin.status(), StatusCode::FORBIDDEN);
    let invalid_memory_workspace = client
        .post(format!("{dashboard_origin}/api/memories/list"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "workspaceIdentity": " padded-memory-workspace",
            "includeDeleted": false
        }))
        .send()
        .await
        .expect("invalid memory workspace denial");
    assert_eq!(invalid_memory_workspace.status(), StatusCode::BAD_REQUEST);
    let invalid_memory_id = client
        .post(format!("{dashboard_origin}/api/memories/not-a-uuid/detail"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "workspaceIdentity": MEMORY_WORKSPACE
        }))
        .send()
        .await
        .expect("invalid memory identifier denial");
    assert_eq!(invalid_memory_id.status(), StatusCode::BAD_REQUEST);
    let invalid_memory_search = client
        .post(format!("{dashboard_origin}/api/memories/search"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "workspaceIdentity": MEMORY_WORKSPACE,
            "query": "concise",
            "maximumSensitivity": "private",
            "limit": 101
        }))
        .send()
        .await
        .expect("invalid memory search denial");
    assert_eq!(invalid_memory_search.status(), StatusCode::BAD_REQUEST);
    let widened_memory_proposal = client
        .post(format!("{dashboard_origin}/api/memories"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "idempotencyKey": "widened-memory-proposal",
            "workspaceIdentity": MEMORY_WORKSPACE,
            "content": "Prefer concise operational summaries.",
            "category": "preference",
            "confidenceBasisPoints": 8000,
            "sensitivity": "private",
            "retention": "standard",
            "daemonPath": "/v1/admin/drain"
        }))
        .send()
        .await
        .expect("widened memory proposal denial");
    assert_eq!(widened_memory_proposal.status(), StatusCode::BAD_REQUEST);
    assert_eq!(requests.load(Ordering::SeqCst), 31);

    let empty_memories = client
        .post(format!("{dashboard_origin}/api/memories/list"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "workspaceIdentity": MEMORY_WORKSPACE,
            "includeDeleted": false
        }))
        .send()
        .await
        .expect("empty memory list");
    assert_eq!(empty_memories.status(), StatusCode::OK);
    assert_eq!(
        empty_memories
            .json::<Value>()
            .await
            .expect("empty memory JSON")["memories"],
        json!([])
    );

    let proposal_key = "dashboard-memory-proposal-stable-1";
    let proposal_body = json!({
        "apiVersion": API_VERSION,
        "idempotencyKey": proposal_key,
        "workspaceIdentity": MEMORY_WORKSPACE,
        "content": "Prefer concise operational summaries.",
        "category": "preference",
        "confidenceBasisPoints": 8000,
        "sensitivity": "private",
        "retention": "standard"
    });
    let proposed_memory = client
        .post(format!("{dashboard_origin}/api/memories"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&proposal_body)
        .send()
        .await
        .expect("propose memory");
    assert_eq!(proposed_memory.status(), StatusCode::OK);
    let proposed_memory = proposed_memory
        .json::<Value>()
        .await
        .expect("proposed memory JSON");
    assert_eq!(proposed_memory["memoryId"], MEMORY_ID);
    assert_eq!(proposed_memory["status"], "proposed");
    assert_eq!(proposed_memory["revision"], 0);
    assert_eq!(
        proposed_memory["revisions"][0]["revisionId"],
        MEMORY_REVISION_ID
    );
    let duplicate_proposal = client
        .post(format!("{dashboard_origin}/api/memories"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&proposal_body)
        .send()
        .await
        .expect("reconcile duplicate memory proposal");
    assert_eq!(duplicate_proposal.status(), StatusCode::OK);
    assert_eq!(
        duplicate_proposal
            .json::<Value>()
            .await
            .expect("duplicate proposal JSON")["memoryId"],
        MEMORY_ID
    );

    let memory_detail = client
        .post(format!(
            "{dashboard_origin}/api/memories/{MEMORY_ID}/detail"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "workspaceIdentity": MEMORY_WORKSPACE
        }))
        .send()
        .await
        .expect("memory detail");
    assert_eq!(memory_detail.status(), StatusCode::OK);
    assert_eq!(
        memory_detail
            .json::<Value>()
            .await
            .expect("memory detail JSON")["memoryId"],
        MEMORY_ID
    );

    let oversized_memory = client
        .post(format!(
            "{dashboard_origin}/api/memories/{OVERSIZED_MEMORY_ID}/detail"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "workspaceIdentity": MEMORY_WORKSPACE
        }))
        .send()
        .await
        .expect("oversized daemon response denial");
    assert_eq!(oversized_memory.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !oversized_memory
            .text()
            .await
            .expect("oversized response error")
            .contains(DAEMON_TOKEN)
    );

    let invalid_activation_revision = client
        .post(format!(
            "{dashboard_origin}/api/memories/{MEMORY_ID}/activate"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "workspaceIdentity": MEMORY_WORKSPACE,
            "expectedRevision": 0,
            "revisionId": "not-a-uuid"
        }))
        .send()
        .await
        .expect("invalid activation revision denial");
    assert_eq!(
        invalid_activation_revision.status(),
        StatusCode::BAD_REQUEST
    );
    let activated_memory = client
        .post(format!(
            "{dashboard_origin}/api/memories/{MEMORY_ID}/activate"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "workspaceIdentity": MEMORY_WORKSPACE,
            "expectedRevision": 0,
            "revisionId": MEMORY_REVISION_ID
        }))
        .send()
        .await
        .expect("activate memory");
    assert_eq!(activated_memory.status(), StatusCode::OK);
    let activated_memory = activated_memory
        .json::<Value>()
        .await
        .expect("activated memory JSON");
    assert_eq!(activated_memory["status"], "active");
    assert_eq!(activated_memory["revision"], 1);

    let memory_search = client
        .post(format!("{dashboard_origin}/api/memories/search"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "workspaceIdentity": MEMORY_WORKSPACE,
            "query": "concise",
            "maximumSensitivity": "private",
            "limit": 20
        }))
        .send()
        .await
        .expect("search memory");
    assert_eq!(memory_search.status(), StatusCode::OK);
    assert_eq!(
        memory_search
            .json::<Value>()
            .await
            .expect("memory search JSON")["hits"][0]["memory"]["memoryId"],
        MEMORY_ID
    );

    let pinned_memory = client
        .post(format!("{dashboard_origin}/api/memories/{MEMORY_ID}/pin"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "workspaceIdentity": MEMORY_WORKSPACE,
            "expectedRevision": 1,
            "pinned": true
        }))
        .send()
        .await
        .expect("pin memory");
    assert_eq!(pinned_memory.status(), StatusCode::OK);
    assert_eq!(
        pinned_memory
            .json::<Value>()
            .await
            .expect("pinned memory JSON")["retention"],
        "pinned"
    );
    let unpinned_memory = client
        .post(format!("{dashboard_origin}/api/memories/{MEMORY_ID}/pin"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "workspaceIdentity": MEMORY_WORKSPACE,
            "expectedRevision": 2,
            "pinned": false
        }))
        .send()
        .await
        .expect("unpin memory");
    assert_eq!(unpinned_memory.status(), StatusCode::OK);
    assert_eq!(
        unpinned_memory
            .json::<Value>()
            .await
            .expect("unpinned memory JSON")["revision"],
        3
    );

    let correction_key = "dashboard-memory-correction-stable-1";
    let correction_body = json!({
        "apiVersion": API_VERSION,
        "idempotencyKey": correction_key,
        "workspaceIdentity": MEMORY_WORKSPACE,
        "expectedRevision": 3,
        "content": "Prefer concise release summaries with explicit blockers.",
        "confidenceBasisPoints": 9000,
        "sensitivity": "private",
        "retention": "standard"
    });
    let corrected_memory = client
        .post(format!(
            "{dashboard_origin}/api/memories/{MEMORY_ID}/correct"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&correction_body)
        .send()
        .await
        .expect("correct memory");
    assert_eq!(corrected_memory.status(), StatusCode::OK);
    let corrected_memory = corrected_memory
        .json::<Value>()
        .await
        .expect("corrected memory JSON");
    assert_eq!(corrected_memory["revision"], 4);
    assert_eq!(
        corrected_memory["revisions"][1]["revisionId"],
        MEMORY_CORRECTION_ID
    );
    let duplicate_correction = client
        .post(format!(
            "{dashboard_origin}/api/memories/{MEMORY_ID}/correct"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&correction_body)
        .send()
        .await
        .expect("reconcile duplicate memory correction");
    assert_eq!(duplicate_correction.status(), StatusCode::OK);
    assert_eq!(
        duplicate_correction
            .json::<Value>()
            .await
            .expect("duplicate correction JSON")["revision"],
        4
    );

    let expired_memory = client
        .post(format!(
            "{dashboard_origin}/api/memories/{MEMORY_ID}/expire"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "workspaceIdentity": MEMORY_WORKSPACE,
            "expectedRevision": 4
        }))
        .send()
        .await
        .expect("expire memory");
    assert_eq!(expired_memory.status(), StatusCode::OK);
    assert_eq!(
        expired_memory
            .json::<Value>()
            .await
            .expect("expired memory JSON")["status"],
        "expired"
    );
    let deleted_memory = client
        .post(format!(
            "{dashboard_origin}/api/memories/{MEMORY_ID}/delete"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "workspaceIdentity": MEMORY_WORKSPACE,
            "expectedRevision": 5
        }))
        .send()
        .await
        .expect("delete memory");
    assert_eq!(deleted_memory.status(), StatusCode::OK);
    let deleted_memory = deleted_memory
        .json::<Value>()
        .await
        .expect("deleted memory JSON");
    assert_eq!(deleted_memory["status"], "deleted");
    assert!(
        deleted_memory["revisions"]
            .as_array()
            .expect("deleted revisions")
            .iter()
            .all(|revision| revision.get("content").is_none())
    );

    let second_proposal_body = json!({
        "apiVersion": API_VERSION,
        "idempotencyKey": "dashboard-memory-proposal-stable-2",
        "workspaceIdentity": MEMORY_WORKSPACE,
        "content": "This proposal should remain inactive.",
        "category": "fact",
        "confidenceBasisPoints": 7000,
        "sensitivity": "internal",
        "retention": "standard"
    });
    let second_proposal = client
        .post(format!("{dashboard_origin}/api/memories"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&second_proposal_body)
        .send()
        .await
        .expect("propose second memory");
    assert_eq!(second_proposal.status(), StatusCode::OK);
    assert_eq!(
        second_proposal
            .json::<Value>()
            .await
            .expect("second proposal JSON")["memoryId"],
        SECOND_MEMORY_ID
    );
    let rejected_memory = client
        .post(format!(
            "{dashboard_origin}/api/memories/{SECOND_MEMORY_ID}/reject"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "workspaceIdentity": MEMORY_WORKSPACE,
            "expectedRevision": 0
        }))
        .send()
        .await
        .expect("reject memory proposal");
    assert_eq!(rejected_memory.status(), StatusCode::OK);
    assert_eq!(
        rejected_memory
            .json::<Value>()
            .await
            .expect("rejected memory JSON")["status"],
        "rejected"
    );

    let memory_tombstones = client
        .post(format!("{dashboard_origin}/api/memories/list"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "workspaceIdentity": MEMORY_WORKSPACE,
            "includeDeleted": true
        }))
        .send()
        .await
        .expect("memory tombstone list");
    assert_eq!(memory_tombstones.status(), StatusCode::OK);
    assert_eq!(
        memory_tombstones
            .json::<Value>()
            .await
            .expect("memory tombstones JSON")["memories"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );

    let extension_without_origin = client
        .post(format!("{dashboard_origin}/api/extensions/list"))
        .header("x-mealy-dashboard", &dashboard_token)
        .json(&json!({"apiVersion": API_VERSION}))
        .send()
        .await
        .expect("extension inventory origin denial");
    assert_eq!(extension_without_origin.status(), StatusCode::FORBIDDEN);
    let widened_extension_read = client
        .post(format!("{dashboard_origin}/api/extensions/list"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"apiVersion": API_VERSION, "includePaths": true}))
        .send()
        .await
        .expect("widened extension read denial");
    assert_eq!(widened_extension_read.status(), StatusCode::BAD_REQUEST);
    let invalid_extension_id = client
        .post(format!(
            "{dashboard_origin}/api/extensions/not-a-uuid/detail"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"apiVersion": API_VERSION}))
        .send()
        .await
        .expect("invalid extension identifier denial");
    assert_eq!(invalid_extension_id.status(), StatusCode::BAD_REQUEST);

    let extension_inventory = client
        .post(format!("{dashboard_origin}/api/extensions/list"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"apiVersion": API_VERSION}))
        .send()
        .await
        .expect("extension inventory");
    assert_eq!(extension_inventory.status(), StatusCode::OK);
    assert_eq!(
        extension_inventory
            .json::<Value>()
            .await
            .expect("extension inventory JSON")["extensions"][0]["extensionId"],
        EXTENSION_ID
    );
    let extension_detail = client
        .post(format!(
            "{dashboard_origin}/api/extensions/{EXTENSION_ID}/detail"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"apiVersion": API_VERSION}))
        .send()
        .await
        .expect("extension detail");
    assert_eq!(extension_detail.status(), StatusCode::OK);
    assert_eq!(
        extension_detail
            .json::<Value>()
            .await
            .expect("extension detail JSON")["status"],
        "installed"
    );

    let extension_enable_body = json!({
        "apiVersion": API_VERSION,
        "expectedRevision": 0,
        "capabilityIds": ["health", "inspect"],
        "mounts": [{
            "name": "workspace",
            "access": "read_only",
            "hostPath": "/srv/mealy-dashboard-fixture",
            "sandboxPath": "/workspace"
        }],
        "networkDestinations": ["api.example:443"],
        "secretReferences": ["provider.primary"],
        "allowProcessSpawn": false
    });
    let widened_extension_enable = client
        .post(format!(
            "{dashboard_origin}/api/extensions/{EXTENSION_ID}/enable"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({
            "apiVersion": API_VERSION,
            "expectedRevision": 0,
            "capabilityIds": ["health"],
            "mounts": [],
            "networkDestinations": [],
            "secretReferences": [],
            "allowProcessSpawn": false,
            "installationRoot": "/attacker"
        }))
        .send()
        .await
        .expect("widened extension enable denial");
    assert_eq!(widened_extension_enable.status(), StatusCode::BAD_REQUEST);
    let mut invalid_extension_grant = extension_enable_body.clone();
    invalid_extension_grant["mounts"][0]["access"] = json!("read_write");
    let invalid_extension_grant = client
        .post(format!(
            "{dashboard_origin}/api/extensions/{EXTENSION_ID}/enable"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&invalid_extension_grant)
        .send()
        .await
        .expect("widened extension grant denial");
    assert_eq!(invalid_extension_grant.status(), StatusCode::BAD_REQUEST);

    let enabled_extension = client
        .post(format!(
            "{dashboard_origin}/api/extensions/{EXTENSION_ID}/enable"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&extension_enable_body)
        .send()
        .await
        .expect("enable extension");
    assert_eq!(enabled_extension.status(), StatusCode::OK);
    let enabled_extension = enabled_extension
        .json::<Value>()
        .await
        .expect("enabled extension JSON");
    assert_eq!(enabled_extension["status"], "enabled");
    assert_eq!(enabled_extension["revision"], 1);
    assert_eq!(
        enabled_extension["activeGrant"]["secretReferences"][0],
        "provider.primary"
    );
    let duplicate_enable = client
        .post(format!(
            "{dashboard_origin}/api/extensions/{EXTENSION_ID}/enable"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&extension_enable_body)
        .send()
        .await
        .expect("reconcile duplicate extension enable");
    assert_eq!(duplicate_enable.status(), StatusCode::OK);
    assert_eq!(
        duplicate_enable
            .json::<Value>()
            .await
            .expect("duplicate extension enable JSON")["revision"],
        1
    );

    let disabled_extension = client
        .post(format!(
            "{dashboard_origin}/api/extensions/{EXTENSION_ID}/disable"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"apiVersion": API_VERSION, "expectedRevision": 1}))
        .send()
        .await
        .expect("disable extension");
    assert_eq!(disabled_extension.status(), StatusCode::OK);
    assert_eq!(
        disabled_extension
            .json::<Value>()
            .await
            .expect("disabled extension JSON")["status"],
        "disabled"
    );
    let duplicate_disable = client
        .post(format!(
            "{dashboard_origin}/api/extensions/{EXTENSION_ID}/disable"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"apiVersion": API_VERSION, "expectedRevision": 1}))
        .send()
        .await
        .expect("reconcile duplicate extension disable");
    assert_eq!(duplicate_disable.status(), StatusCode::OK);

    let mut reenable_body = extension_enable_body.clone();
    reenable_body["expectedRevision"] = json!(2);
    let reenabled_extension = client
        .post(format!(
            "{dashboard_origin}/api/extensions/{EXTENSION_ID}/enable"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&reenable_body)
        .send()
        .await
        .expect("reenable extension");
    assert_eq!(reenabled_extension.status(), StatusCode::OK);
    assert_eq!(
        reenabled_extension
            .json::<Value>()
            .await
            .expect("reenabled extension JSON")["revision"],
        3
    );
    let revoked_extension = client
        .post(format!(
            "{dashboard_origin}/api/extensions/{EXTENSION_ID}/revoke"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"apiVersion": API_VERSION, "expectedRevision": 3}))
        .send()
        .await
        .expect("revoke extension");
    assert_eq!(revoked_extension.status(), StatusCode::OK);
    assert_eq!(
        revoked_extension
            .json::<Value>()
            .await
            .expect("revoked extension JSON")["status"],
        "revoked"
    );
    let duplicate_revoke = client
        .post(format!(
            "{dashboard_origin}/api/extensions/{EXTENSION_ID}/revoke"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"apiVersion": API_VERSION, "expectedRevision": 3}))
        .send()
        .await
        .expect("reconcile duplicate extension revoke");
    assert_eq!(duplicate_revoke.status(), StatusCode::OK);
    let mut revoked_enable_body = extension_enable_body.clone();
    revoked_enable_body["expectedRevision"] = json!(4);
    let revoked_enable = client
        .post(format!(
            "{dashboard_origin}/api/extensions/{EXTENSION_ID}/enable"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&revoked_enable_body)
        .send()
        .await
        .expect("revoked extension enable denial");
    assert_eq!(revoked_enable.status(), StatusCode::CONFLICT);

    let oversized = client
        .post(format!(
            "{dashboard_origin}/api/sessions/{SESSION_ID}/inputs"
        ))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .header(header::CONTENT_TYPE, "application/json")
        .body(format!(
            "{{\"apiVersion\":\"v1\",\"idempotencyKey\":\"oversized\",\"deliveryMode\":\"queue\",\"content\":\"{}\"}}",
            "x".repeat(70_000)
        ))
        .send()
        .await
        .expect("oversized body denial");
    assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);

    let arbitrary = client
        .post(format!("{dashboard_origin}/api/proxy"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({"path": "/v1/admin/drain"}))
        .send()
        .await
        .expect("arbitrary proxy denial");
    assert_eq!(arbitrary.status(), StatusCode::NOT_FOUND);

    let wrong_method = client
        .post(format!("{dashboard_origin}/api/snapshot"))
        .header("x-mealy-dashboard", &dashboard_token)
        .header(header::ORIGIN, &dashboard_origin)
        .json(&json!({}))
        .send()
        .await
        .expect("method denial");
    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        wrong_method
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );

    assert_eq!(requests.load(Ordering::SeqCst), 71);
    let commands = commands.lock().expect("recorded commands");
    assert_eq!(commands.len(), 22);
    assert_eq!(
        commands[0],
        (
            "create_session".to_owned(),
            json!({"apiVersion": API_VERSION})
        )
    );
    assert_eq!(commands[1].0, "submit_input");
    assert_eq!(commands[1].1["idempotencyKey"], input_key);
    assert_eq!(
        commands[1].1["content"],
        "Produce the bounded release brief"
    );
    assert_eq!(commands[2].0, "resolve_approval");
    assert_eq!(commands[2].1["idempotencyKey"], approval_key);
    assert_eq!(commands[2].1["expectedSubjectDigest"], SUBJECT_DIGEST);
    assert_eq!(commands[2].1["decision"], "approve");
    assert_eq!(commands[3].0, "cancel_task");
    assert_eq!(commands[3].1["idempotencyKey"], cancellation_key);
    assert_eq!(commands[4].0, "reconcile_effect");
    assert_eq!(commands[4].1["idempotencyKey"], reconciliation_key);
    assert_eq!(commands[4].1["expectedEffectRevision"], 4);
    assert_eq!(commands[4].1["outcome"], "succeeded");
    assert_eq!(
        commands[4].1["evidence"]["destinationDigest"],
        "f".repeat(64)
    );
    assert_eq!(
        commands[5],
        (
            "pause_schedule".to_owned(),
            json!({"apiVersion": API_VERSION, "expectedRevision": 7})
        )
    );
    assert_eq!(
        commands[6],
        (
            "resume_schedule".to_owned(),
            json!({"apiVersion": API_VERSION, "expectedRevision": 8})
        )
    );
    assert_eq!(
        commands[7],
        (
            "cancel_schedule".to_owned(),
            json!({"apiVersion": API_VERSION, "expectedRevision": 9})
        )
    );
    assert_eq!(commands[8].0, "create_schedule");
    assert_eq!(commands[8].1, schedule_create_body);
    assert_eq!(commands[9].0, "propose_memory");
    assert_eq!(commands[9].1["workspaceIdentity"], MEMORY_WORKSPACE);
    assert_eq!(commands[9].1["content"], proposal_body["content"]);
    assert!(commands[9].1.get("idempotencyKey").is_none());
    assert!(
        commands[9].1["sources"][0]["locator"]
            .as_str()
            .is_some_and(|value| value.starts_with("owner://mealyctl/dashboard/")
                && value.len() == "owner://mealyctl/dashboard/".len() + 64)
    );
    assert_eq!(commands[10].0, "activate_memory");
    assert_eq!(commands[10].1["revisionId"], MEMORY_REVISION_ID);
    assert_eq!(commands[10].1["authorization"], "owner_approval");
    assert_eq!(
        commands[11],
        (
            "pin_memory".to_owned(),
            json!({"apiVersion": API_VERSION, "expectedRevision": 1, "pinned": true})
        )
    );
    assert_eq!(
        commands[12],
        (
            "pin_memory".to_owned(),
            json!({"apiVersion": API_VERSION, "expectedRevision": 2, "pinned": false})
        )
    );
    assert_eq!(commands[13].0, "correct_memory");
    assert_eq!(commands[13].1["expectedRevision"], 3);
    assert_eq!(commands[13].1["content"], correction_body["content"]);
    assert_eq!(commands[13].1["authorization"], "owner_approval");
    assert!(commands[13].1.get("idempotencyKey").is_none());
    assert_eq!(
        commands[14],
        (
            "expire_memory".to_owned(),
            json!({"apiVersion": API_VERSION, "expectedRevision": 4})
        )
    );
    assert_eq!(
        commands[15],
        (
            "delete_memory".to_owned(),
            json!({"apiVersion": API_VERSION, "expectedRevision": 5})
        )
    );
    assert_eq!(commands[16].0, "propose_memory");
    assert_eq!(commands[16].1["content"], second_proposal_body["content"]);
    assert_eq!(
        commands[17],
        (
            "reject_memory".to_owned(),
            json!({"apiVersion": API_VERSION, "expectedRevision": 0})
        )
    );
    assert_eq!(commands[18].0, "enable_extension");
    assert_eq!(commands[18].1, extension_enable_body);
    assert_eq!(
        commands[19],
        (
            "disable_extension".to_owned(),
            json!({"apiVersion": API_VERSION, "expectedRevision": 1})
        )
    );
    assert_eq!(commands[20].0, "enable_extension");
    assert_eq!(commands[20].1["expectedRevision"], 2);
    assert_eq!(
        commands[20].1["capabilityIds"],
        json!(["health", "inspect"])
    );
    assert_eq!(
        commands[21],
        (
            "revoke_extension".to_owned(),
            json!({"apiVersion": API_VERSION, "expectedRevision": 3})
        )
    );
    assert!(
        !serde_json::to_string(&*commands)
            .expect("recorded command JSON")
            .contains(DAEMON_TOKEN)
    );
    drop(commands);

    dashboard.0.kill().expect("stop dashboard");
    dashboard.0.wait().expect("join dashboard");
    daemon.abort();
}

fn extract_dashboard_token(html: &str) -> String {
    const PREFIX: &str = "const DASHBOARD_TOKEN = \"";
    let remainder = html.split_once(PREFIX).expect("token prefix").1;
    remainder
        .split_once('"')
        .expect("token suffix")
        .0
        .to_owned()
}

async fn spawn_mock_daemon() -> (
    String,
    Arc<AtomicUsize>,
    Arc<Mutex<Vec<(String, Value)>>>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock daemon listener");
    let address = listener.local_addr().expect("mock daemon address");
    let requests = Arc::new(AtomicUsize::new(0));
    let commands = Arc::new(Mutex::new(Vec::new()));
    let state = MockState {
        requests: Arc::clone(&requests),
        commands: Arc::clone(&commands),
        memory: Arc::new(Mutex::new(Vec::new())),
        extension: Arc::new(Mutex::new(extension_value("installed", 0, None))),
        created_schedule: Arc::new(Mutex::new(None)),
    };
    let application = Router::new()
        .route("/v1/admin/status", get(status))
        .route("/v1/admin/doctor", get(doctor))
        .route("/v1/admin/usage", get(admin_usage))
        .route("/v1/sessions", get(sessions).post(create_session))
        .route("/v1/sessions/{session_id}/status", get(session_status))
        .route("/v1/sessions/{session_id}/timeline", get(timeline))
        .route("/v1/sessions/{session_id}/inputs", post(submit_input))
        .route("/v1/approvals", get(approvals))
        .route(
            "/v1/approvals/{approval_id}/resolve",
            post(resolve_approval),
        )
        .route("/v1/tasks/{task_id}/cancel", post(cancel_task))
        .route("/v1/tasks/{task_id}", get(task_detail))
        .route("/v1/effects/{effect_id}", get(effect_detail))
        .route(
            "/v1/effect-attempts/{attempt_id}",
            get(effect_attempt_detail),
        )
        .route(
            "/v1/effects/{effect_id}/attempts/{attempt_id}/reconcile",
            post(reconcile_effect),
        )
        .route("/v1/schedules", get(schedules).post(create_schedule))
        .route("/v1/schedules/{schedule_id}", get(schedule_detail))
        .route("/v1/schedules/{schedule_id}/runs", get(schedule_runs))
        .route("/v1/schedules/{schedule_id}/pause", post(pause_schedule))
        .route("/v1/schedules/{schedule_id}/resume", post(resume_schedule))
        .route("/v1/schedules/{schedule_id}/cancel", post(cancel_schedule))
        .route("/v1/memories", get(memories).post(propose_memory))
        .route("/v1/memories/search", get(search_memories))
        .route("/v1/memories/{memory_id}", get(memory_detail))
        .route("/v1/memories/{memory_id}/activate", post(activate_memory))
        .route("/v1/memories/{memory_id}/correct", post(correct_memory))
        .route("/v1/memories/{memory_id}/pin", post(pin_memory))
        .route("/v1/memories/{memory_id}/expire", post(expire_memory))
        .route("/v1/memories/{memory_id}/reject", post(reject_memory))
        .route("/v1/memories/{memory_id}/delete", post(delete_memory))
        .route("/v1/extensions", get(extensions))
        .route("/v1/extensions/{extension_id}", get(extension_detail))
        .route(
            "/v1/extensions/{extension_id}/enable",
            post(enable_extension),
        )
        .route(
            "/v1/extensions/{extension_id}/disable",
            post(disable_extension),
        )
        .route(
            "/v1/extensions/{extension_id}/revoke",
            post(revoke_extension),
        )
        .with_state(state);
    let server = tokio::spawn(async move {
        axum::serve(listener, application)
            .await
            .expect("mock daemon server");
    });
    (format!("http://{address}"), requests, commands, server)
}

async fn status(State(state): State<MockState>, headers: HeaderMap) -> Response {
    authenticated_json(
        &state,
        &headers,
        json!({
            "apiVersion": API_VERSION,
            "startId": "019f0000-0000-7000-8000-000000000003",
            "runStatus": "running",
            "safeMode": false,
            "admissionOpen": true,
            "configDigest": "a".repeat(64),
            "policyBundleDigest": "b".repeat(64),
            "schemaVersion": 15,
            "pendingInputs": 1,
            "nonterminalRuns": 1,
            "activeLeases": 1,
            "pendingApprovals": 1,
            "unknownEffects": 0,
            "pendingOutbox": 0,
            "failedOutbox": 0,
            "enabledExtensions": 0,
            "failedExtensions": 0,
            "providerHealth": "healthy",
            "providerId": "dashboard-fixture",
            "providerModelId": "fixture-model",
            "providerResidency": "local-test",
            "providerLocal": true,
            "providerEndpoints": [],
            "enabledReadTools": ["agent.delegate"],
            "enabledActionTools": ["workspace.create_file"],
            "extensionHostHealth": "healthy",
            "activeChannels": 0,
            "degradedChannels": 0,
            "reservedChannelUpdates": 0,
            "activeSchedules": 0,
            "pausedSchedules": 0,
            "claimedScheduleRuns": 0,
            "failedScheduleRuns": 0,
            "skippedScheduleRuns": 0,
            "databaseBytes": 4096,
            "artifactBytes": 0,
            "artifactCount": 0,
            "recentFailures": [],
            "startedAtMs": 1_800_000_000_000_i64,
            "readyAtMs": 1_800_000_000_001_i64,
            "completedAtMs": null,
            "completionReason": null
        }),
    )
}

async fn doctor(State(state): State<MockState>, headers: HeaderMap) -> Response {
    authenticated_json(
        &state,
        &headers,
        json!({
            "apiVersion": API_VERSION,
            "operatingSystem": "linux",
            "architecture": "x86_64",
            "controlPlaneReady": true,
            "sandboxAvailable": true,
            "sandboxProfiles": [],
            "checks": {"storage": "ok: fixture storage is healthy"}
        }),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MockAdminUsageQuery {
    from_ms: i64,
    to_ms: i64,
}

async fn admin_usage(
    State(state): State<MockState>,
    headers: HeaderMap,
    Query(query): Query<MockAdminUsageQuery>,
) -> Response {
    let bucket_start_ms = ((query.to_ms - 1) / DAY_MS) * DAY_MS;
    authenticated_json(
        &state,
        &headers,
        json!({
            "apiVersion": API_VERSION,
            "fromMs": query.from_ms,
            "toMs": query.to_ms,
            "buckets": [{
                "bucketStartMs": bucket_start_ms,
                "bucketEndMs": (bucket_start_ms + DAY_MS).min(query.to_ms),
                "completedRuns": 3,
                "succeededRuns": 2,
                "failedRuns": 1,
                "cancelledRuns": 0,
                "usedModelCalls": 7,
                "usedToolCalls": 4,
                "usedDelegatedRuns": 1,
                "usedRetries": 2,
                "usedInputTokens": 12_000,
                "usedOutputTokens": 3_000,
                "usedCostMicrounits": 321_000,
                "usedOutputBytes": 8_192
            }]
        }),
    )
}

async fn sessions(State(state): State<MockState>, headers: HeaderMap) -> Response {
    authenticated_json(
        &state,
        &headers,
        json!({
            "apiVersion": API_VERSION,
            "sessions": [{
                "sessionId": SESSION_ID,
                "status": "active",
                "revision": 3,
                "pendingInputs": 1,
                "activeTurnId": TURN_ID,
                "createdAtMs": 1_800_000_000_000_i64,
                "updatedAtMs": 1_800_000_000_010_i64
            }]
        }),
    )
}

async fn approvals(State(state): State<MockState>, headers: HeaderMap) -> Response {
    authenticated_json(
        &state,
        &headers,
        json!({
            "apiVersion": API_VERSION,
            "approvals": [{
                "apiVersion": API_VERSION,
                "approvalId": APPROVAL_ID,
                "effectId": EFFECT_ID,
                "subject": {
                    "effectId": EFFECT_ID,
                    "principalId": "019f0000-0000-7000-8000-000000000001",
                    "taskId": TASK_ID,
                    "toolId": "workspace.create_file",
                    "toolVersion": "1",
                    "canonicalArgumentsDigest": "b".repeat(64),
                    "capabilityScope": "workspace.write",
                    "targetResources": ["workspace://release.txt"],
                    "executableIdentityDigest": "c".repeat(64),
                    "policyVersion": "policy-v1",
                    "expiresAtMs": 1_900_000_000_000_i64
                },
                "subjectDigest": SUBJECT_DIGEST,
                "status": "pending",
                "decision": null,
                "requestedAtMs": 1_800_000_000_020_i64,
                "resolvedAtMs": null
            }]
        }),
    )
}

async fn schedules(State(state): State<MockState>, headers: HeaderMap) -> Response {
    let mut values = vec![schedule_value("active", 7)];
    if let Some((_, created)) = state
        .created_schedule
        .lock()
        .expect("created schedule fixture")
        .as_ref()
    {
        values.push(created.clone());
    }
    authenticated_json(
        &state,
        &headers,
        json!({"apiVersion": API_VERSION, "schedules": values}),
    )
}

async fn create_schedule(
    State(state): State<MockState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !authenticate(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut created = state
        .created_schedule
        .lock()
        .expect("created schedule fixture");
    if let Some((existing_body, response)) = created.as_ref() {
        if existing_body == &body {
            return Json(response.clone()).into_response();
        }
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "apiVersion": API_VERSION,
                "code": "schedule_conflict",
                "message": "schedule identity conflicts with canonical state",
                "retryable": false
            })),
        )
            .into_response();
    }
    state
        .commands
        .lock()
        .expect("command recorder")
        .push(("create_schedule".to_owned(), body.clone()));
    let response = schedule_value_from_create(&body);
    *created = Some((body, response.clone()));
    Json(response).into_response()
}

async fn schedule_detail(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(schedule_id): Path<String>,
) -> Response {
    let response = if schedule_id == SCHEDULE_ID {
        schedule_value("active", 7)
    } else {
        assert_eq!(schedule_id, CREATED_SCHEDULE_ID);
        state
            .created_schedule
            .lock()
            .expect("created schedule fixture")
            .as_ref()
            .expect("created schedule")
            .1
            .clone()
    };
    authenticated_json(&state, &headers, response)
}

async fn schedule_runs(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(schedule_id): Path<String>,
) -> Response {
    if schedule_id == CREATED_SCHEDULE_ID {
        return authenticated_json(
            &state,
            &headers,
            json!({"apiVersion": API_VERSION, "scheduleId": CREATED_SCHEDULE_ID, "runs": []}),
        );
    }
    assert_eq!(schedule_id, SCHEDULE_ID);
    authenticated_json(
        &state,
        &headers,
        json!({
            "apiVersion": API_VERSION,
            "scheduleId": SCHEDULE_ID,
            "runs": [{
                "scheduleRunId": SCHEDULE_RUN_ID,
                "scheduleId": SCHEDULE_ID,
                "scheduledForMs": 1_800_000_000_100_i64,
                "coalesced": false,
                "intent": "fire",
                "status": "admitted",
                "inboxEntryId": SCHEDULE_INBOX_ID,
                "reason": null,
                "createdAtMs": 1_800_000_000_101_i64,
                "completedAtMs": 1_800_000_000_102_i64
            }]
        }),
    )
}

async fn pause_schedule(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(schedule_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    assert_eq!(schedule_id, SCHEDULE_ID);
    authenticated_command(
        &state,
        &headers,
        "pause_schedule",
        body,
        schedule_value("paused", 8),
    )
}

async fn resume_schedule(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(schedule_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    assert_eq!(schedule_id, SCHEDULE_ID);
    authenticated_command(
        &state,
        &headers,
        "resume_schedule",
        body,
        schedule_value("active", 9),
    )
}

async fn cancel_schedule(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(schedule_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    assert_eq!(schedule_id, SCHEDULE_ID);
    authenticated_command(
        &state,
        &headers,
        "cancel_schedule",
        body,
        schedule_value("cancelled", 10),
    )
}

fn schedule_value(status: &str, revision: u64) -> Value {
    json!({
        "apiVersion": API_VERSION,
        "scheduleId": SCHEDULE_ID,
        "sessionId": SESSION_ID,
        "name": "dashboard evidence review",
        "prompt": "Review durable dashboard evidence.",
        "cronExpression": "0 9 * * *",
        "timezone": "Pacific/Auckland",
        "missedRunPolicy": "latest",
        "overlapPolicy": "skip_if_running",
        "misfireGraceMs": 60_000,
        "allowApprovalRequiredAction": false,
        "status": status,
        "nextDueAtMs": if status == "cancelled" { Value::Null } else { json!(1_900_000_000_000_i64) },
        "revision": revision,
        "createdAtMs": 1_800_000_000_000_i64,
        "updatedAtMs": 1_800_000_000_000_i64 + i64::try_from(revision).expect("revision fits")
    })
}

fn schedule_value_from_create(body: &Value) -> Value {
    json!({
        "apiVersion": API_VERSION,
        "scheduleId": body["scheduleId"].clone(),
        "sessionId": body["sessionId"].clone(),
        "name": body["name"].clone(),
        "prompt": body["prompt"].clone(),
        "cronExpression": body["cronExpression"].clone(),
        "timezone": body["timezone"].clone(),
        "missedRunPolicy": body["missedRunPolicy"].clone(),
        "overlapPolicy": body["overlapPolicy"].clone(),
        "misfireGraceMs": body["misfireGraceMs"].clone(),
        "allowApprovalRequiredAction": body["allowApprovalRequiredAction"].clone(),
        "status": "active",
        "nextDueAtMs": 1_900_000_000_000_i64,
        "revision": 0,
        "createdAtMs": 1_800_000_000_000_i64,
        "updatedAtMs": 1_800_000_000_000_i64
    })
}

async fn create_session(
    State(state): State<MockState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    authenticated_command(
        &state,
        &headers,
        "create_session",
        body,
        json!({"apiVersion": API_VERSION, "sessionId": SESSION_ID}),
    )
}

async fn session_status(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Response {
    assert_eq!(session_id, SESSION_ID);
    authenticated_json(
        &state,
        &headers,
        json!({
            "apiVersion": API_VERSION,
            "sessionId": SESSION_ID,
            "revision": 3,
            "pendingInputs": 1,
            "activeTurnId": TURN_ID,
            "latestCursor": 1
        }),
    )
}

async fn timeline(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Response {
    assert_eq!(session_id, SESSION_ID);
    authenticated_json(
        &state,
        &headers,
        json!({
            "apiVersion": API_VERSION,
            "events": [{
                "cursor": 1,
                "eventId": "019f0000-0000-7000-8000-000000000020",
                "aggregateKind": "task",
                "aggregateId": TASK_ID,
                "aggregateSequence": 0,
                "eventType": "task.created",
                "eventVersion": 1,
                "occurredAtMs": 1_800_000_000_030_i64,
                "correlationId": "019f0000-0000-7000-8000-000000000021",
                "causationId": null,
                "payload": {"turn_id": TURN_ID},
                "eventDigest": "d".repeat(64)
            }],
            "highWatermark": 1,
            "hasMore": false
        }),
    )
}

async fn submit_input(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    assert_eq!(session_id, SESSION_ID);
    authenticated_command(
        &state,
        &headers,
        "submit_input",
        body,
        json!({
            "apiVersion": API_VERSION,
            "sessionId": SESSION_ID,
            "inboxEntryId": "019f0000-0000-7000-8000-000000000022",
            "inboxSequence": 2,
            "deliveryMode": "queue",
            "eventId": "019f0000-0000-7000-8000-000000000023",
            "outboxId": "019f0000-0000-7000-8000-000000000024",
            "acceptedAtMs": 1_800_000_000_040_i64,
            "duplicate": false,
            "cursor": 2
        }),
    )
}

async fn resolve_approval(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(approval_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    assert_eq!(approval_id, APPROVAL_ID);
    authenticated_command(
        &state,
        &headers,
        "resolve_approval",
        body,
        json!({
            "apiVersion": API_VERSION,
            "approvalId": APPROVAL_ID,
            "effectId": EFFECT_ID,
            "status": "approved",
            "decision": "approve",
            "effectRevision": 2,
            "approvalEventId": "019f0000-0000-7000-8000-000000000025",
            "effectEventId": "019f0000-0000-7000-8000-000000000026",
            "cursor": 3,
            "duplicate": false
        }),
    )
}

async fn cancel_task(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    assert_eq!(task_id, TASK_ID);
    authenticated_command(
        &state,
        &headers,
        "cancel_task",
        body,
        json!({
            "apiVersion": API_VERSION,
            "taskId": TASK_ID,
            "status": "cancelling",
            "revision": 4,
            "eventId": "019f0000-0000-7000-8000-000000000027",
            "cursor": 4,
            "duplicate": false
        }),
    )
}

async fn task_detail(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
) -> Response {
    let cost = if task_id == OVERSIZED_TASK_USAGE_ID {
        9_007_199_254_740_992_u64
    } else {
        assert_eq!(task_id, TASK_ID);
        123_456
    };
    authenticated_json(&state, &headers, task_value(&task_id, cost))
}

fn task_value(task_id: &str, used_cost_microunits: u64) -> Value {
    json!({
        "apiVersion": API_VERSION,
        "taskId": task_id,
        "runId": RUN_ID,
        "status": "running",
        "revision": 3,
        "finalResponse": null,
        "finalDigest": null,
        "usage": {
            "usedModelCalls": 2,
            "reservedModelCalls": 1,
            "usedToolCalls": 1,
            "reservedToolCalls": 0,
            "usedDelegatedRuns": 0,
            "reservedDelegatedRuns": 0,
            "usedRetries": 1,
            "usedInputTokens": 120,
            "reservedInputTokens": 20,
            "usedOutputTokens": 30,
            "reservedOutputTokens": 10,
            "usedCostMicrounits": used_cost_microunits,
            "reservedCostMicrounits": 500,
            "usedOutputBytes": 512,
            "reservedOutputBytes": 128
        },
        "successCriteria": {
            "objective": "Produce the bounded release brief",
            "criteria": [{
                "criterionId": "brief_present",
                "requirement": "A bounded release brief is durably recorded"
            }],
            "noObjectiveCriteriaReason": null,
            "riskClass": "low",
            "policyVersion": "mealy.validation.phase4.v1",
            "criteriaDigest": "f".repeat(64)
        },
        "validation": null,
        "modelAttempts": 3,
        "toolCalls": 1
    })
}

async fn effect_detail(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(effect_id): Path<String>,
) -> Response {
    assert_eq!(effect_id, EFFECT_ID);
    authenticated_json(
        &state,
        &headers,
        json!({
            "apiVersion": API_VERSION,
            "effectId": EFFECT_ID,
            "taskId": TASK_ID,
            "runId": RUN_ID,
            "status": "outcome_unknown",
            "revision": 4,
            "toolId": "workspace.manage_path",
            "toolVersion": "1",
            "descriptorDigest": "a".repeat(64),
            "normalizedArguments": {
                "destinationPath": "archive/report.txt",
                "expectedSourceDigest": "e".repeat(64),
                "operation": "move_file",
                "sourcePath": "drafts/report.txt",
                "workspaceId": "project"
            },
            "argumentsDigest": "b".repeat(64),
            "capabilityScope": "write:workspace:manage",
            "targetResources": [
                "workspace://project/archive/report.txt",
                "workspace://project/drafts/report.txt"
            ],
            "executableIdentityDigest": "c".repeat(64),
            "policyDecision": "require_approval",
            "policyVersion": "mealy.workspace-manage.policy.v1",
            "policyExplanation": "workspace_manage_requires_approval",
            "policyObligations": {"profile": "workspace_write"},
            "idempotencyKey": null,
            "approval": null,
            "createdAtMs": 1_800_000_000_050_i64,
            "updatedAtMs": 1_800_000_000_060_i64
        }),
    )
}

async fn effect_attempt_detail(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(attempt_id): Path<String>,
) -> Response {
    assert_eq!(attempt_id, ATTEMPT_ID);
    authenticated_json(
        &state,
        &headers,
        json!({
            "apiVersion": API_VERSION,
            "attemptId": ATTEMPT_ID,
            "effectId": EFFECT_ID,
            "ordinal": 1,
            "status": "outcome_unknown",
            "idempotencyKey": null,
            "fencingToken": 7,
            "preparedAtMs": 1_800_000_000_051_i64,
            "startedAtMs": 1_800_000_000_052_i64,
            "completedAtMs": 1_800_000_000_060_i64,
            "errorClass": "worker_interrupted_after_dispatch",
            "outcomes": [{
                "sequence": 0,
                "outcome": "outcome_unknown",
                "evidence": {
                    "contractVersion": "mealy.effect-outcome-evidence.v1",
                    "details": {"reason": "worker interrupted after dispatch"}
                },
                "evidenceDigest": "d".repeat(64),
                "eventId": "019f0000-0000-7000-8000-000000000030",
                "recordedAtMs": 1_800_000_000_060_i64
            }]
        }),
    )
}

async fn reconcile_effect(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path((effect_id, attempt_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Response {
    assert_eq!(effect_id, EFFECT_ID);
    assert_eq!(attempt_id, ATTEMPT_ID);
    authenticated_command(
        &state,
        &headers,
        "reconcile_effect",
        body,
        json!({
            "apiVersion": API_VERSION,
            "effectId": EFFECT_ID,
            "attemptId": ATTEMPT_ID,
            "outcome": "succeeded",
            "effectRevision": 5,
            "eventId": "019f0000-0000-7000-8000-000000000031",
            "cursor": 5,
            "duplicate": false
        }),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MockMemoryNamespaceQuery {
    workspace_identity: String,
    include_deleted: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MockMemorySearchQuery {
    workspace_identity: String,
    query: String,
    maximum_sensitivity: String,
    limit: usize,
}

async fn memories(
    State(state): State<MockState>,
    headers: HeaderMap,
    Query(query): Query<MockMemoryNamespaceQuery>,
) -> Response {
    if !authenticate(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    assert_eq!(query.workspace_identity, MEMORY_WORKSPACE);
    let include_deleted = query.include_deleted.unwrap_or(false);
    let memories = state
        .memory
        .lock()
        .expect("memory fixture")
        .iter()
        .filter(|memory| include_deleted || memory["status"] != "deleted")
        .cloned()
        .collect::<Vec<_>>();
    Json(json!({"apiVersion": API_VERSION, "memories": memories})).into_response()
}

async fn search_memories(
    State(state): State<MockState>,
    headers: HeaderMap,
    Query(query): Query<MockMemorySearchQuery>,
) -> Response {
    if !authenticate(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    assert_eq!(query.workspace_identity, MEMORY_WORKSPACE);
    assert_eq!(query.query, "concise");
    assert_eq!(query.maximum_sensitivity, "private");
    assert_eq!(query.limit, 20);
    let hits = state
        .memory
        .lock()
        .expect("memory fixture")
        .iter()
        .filter(|memory| memory["status"] == "active")
        .map(|memory| json!({"memory": memory, "lexicalRank": -0.5}))
        .collect::<Vec<_>>();
    Json(json!({"apiVersion": API_VERSION, "hits": hits})).into_response()
}

async fn memory_detail(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(memory_id): Path<String>,
    Query(query): Query<MockMemoryNamespaceQuery>,
) -> Response {
    if !authenticate(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    assert_eq!(query.workspace_identity, MEMORY_WORKSPACE);
    assert!(query.include_deleted.is_none());
    if memory_id == OVERSIZED_MEMORY_ID {
        return Response::new(axum::body::Body::from(vec![b'x'; 8 * 1024 * 1024 + 1]));
    }
    state
        .memory
        .lock()
        .expect("memory fixture")
        .iter()
        .find(|memory| memory["memoryId"] == memory_id)
        .cloned()
        .map_or_else(memory_not_found, |memory| Json(memory).into_response())
}

async fn propose_memory(
    State(state): State<MockState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !record_dynamic_command(&state, &headers, "propose_memory", &body) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut memories = state.memory.lock().expect("memory fixture");
    let (memory_id, revision_id, created_at_ms) = if memories.is_empty() {
        (MEMORY_ID, MEMORY_REVISION_ID, 1_800_000_000_200_i64)
    } else {
        (
            SECOND_MEMORY_ID,
            SECOND_MEMORY_REVISION_ID,
            1_800_000_000_300_i64,
        )
    };
    let memory = memory_value_from_proposal(&body, memory_id, revision_id, created_at_ms);
    memories.push(memory.clone());
    Json(memory).into_response()
}

async fn activate_memory(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(memory_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    assert_eq!(memory_id, MEMORY_ID);
    if !record_dynamic_command(&state, &headers, "activate_memory", &body) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    assert_eq!(body["revisionId"], MEMORY_REVISION_ID);
    assert_eq!(body["authorization"], "owner_approval");
    update_memory(&state, &memory_id, |memory| {
        memory["status"] = json!("active");
        memory["revision"] = json!(1);
        memory["lastVerifiedAtMs"] = json!(1_800_000_000_201_i64);
        memory["revisions"][0]["status"] = json!("active");
        memory["revisions"][0]["lastVerifiedAtMs"] = json!(1_800_000_000_201_i64);
    })
}

async fn correct_memory(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(memory_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    assert_eq!(memory_id, MEMORY_ID);
    if !record_dynamic_command(&state, &headers, "correct_memory", &body) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    assert_eq!(body["authorization"], "owner_approval");
    update_memory(&state, &memory_id, |memory| {
        let expected = body["expectedRevision"]
            .as_u64()
            .expect("expected revision");
        memory["status"] = json!("active");
        memory["revision"] = json!(expected + 1);
        memory["confidenceBasisPoints"] = body["confidenceBasisPoints"].clone();
        memory["sensitivity"] = body["sensitivity"].clone();
        memory["retention"] = body["retention"].clone();
        memory["lastVerifiedAtMs"] = json!(1_800_000_000_210_i64);
        memory["revisions"][0]["status"] = json!("superseded");
        let revision = json!({
            "revisionId": MEMORY_CORRECTION_ID,
            "ordinal": 2,
            "status": "active",
            "content": body["content"].clone(),
            "contentDigest": body["sources"][0]["digest"].clone(),
            "confidenceBasisPoints": body["confidenceBasisPoints"].clone(),
            "sensitivity": body["sensitivity"].clone(),
            "retention": body["retention"].clone(),
            "supersedesRevisionId": MEMORY_REVISION_ID,
            "sources": body["sources"].clone(),
            "createdAtMs": 1_800_000_000_210_i64,
            "lastVerifiedAtMs": 1_800_000_000_210_i64
        });
        memory["revisions"]
            .as_array_mut()
            .expect("revision list")
            .push(revision);
    })
}

async fn pin_memory(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(memory_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    assert_eq!(memory_id, MEMORY_ID);
    if !record_dynamic_command(&state, &headers, "pin_memory", &body) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    update_memory(&state, &memory_id, |memory| {
        let expected = body["expectedRevision"]
            .as_u64()
            .expect("expected revision");
        let retention = if body["pinned"] == true {
            "pinned"
        } else {
            "standard"
        };
        memory["revision"] = json!(expected + 1);
        memory["retention"] = json!(retention);
    })
}

async fn expire_memory(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(memory_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    assert_eq!(memory_id, MEMORY_ID);
    if !record_dynamic_command(&state, &headers, "expire_memory", &body) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    update_memory_status(&state, &memory_id, &body, "expired")
}

async fn reject_memory(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(memory_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    assert_eq!(memory_id, SECOND_MEMORY_ID);
    if !record_dynamic_command(&state, &headers, "reject_memory", &body) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    update_memory_status(&state, &memory_id, &body, "rejected")
}

async fn delete_memory(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(memory_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    assert_eq!(memory_id, MEMORY_ID);
    if !record_dynamic_command(&state, &headers, "delete_memory", &body) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    update_memory(&state, &memory_id, |memory| {
        let expected = body["expectedRevision"]
            .as_u64()
            .expect("expected revision");
        memory["status"] = json!("deleted");
        memory["revision"] = json!(expected + 1);
        memory["lastVerifiedAtMs"] = json!(1_800_000_000_220_i64);
        let revisions = memory["revisions"].as_array_mut().expect("revision list");
        for revision in revisions.iter_mut() {
            revision["status"] = json!("deleted");
            revision
                .as_object_mut()
                .expect("revision object")
                .remove("content");
        }
        revisions.last_mut().expect("newest revision")["lastVerifiedAtMs"] =
            json!(1_800_000_000_220_i64);
    })
}

fn memory_value_from_proposal(
    body: &Value,
    memory_id: &str,
    revision_id: &str,
    created_at_ms: i64,
) -> Value {
    json!({
        "apiVersion": API_VERSION,
        "memoryId": memory_id,
        "principalId": "019f0000-0000-7000-8000-000000000001",
        "workspaceIdentity": body["workspaceIdentity"].clone(),
        "status": "proposed",
        "revision": 0,
        "category": body["category"].clone(),
        "confidenceBasisPoints": body["confidenceBasisPoints"].clone(),
        "sensitivity": body["sensitivity"].clone(),
        "retention": body["retention"].clone(),
        "createdAtMs": created_at_ms,
        "lastVerifiedAtMs": created_at_ms,
        "revisions": [{
            "revisionId": revision_id,
            "ordinal": 1,
            "status": "proposed",
            "content": body["content"].clone(),
            "contentDigest": body["sources"][0]["digest"].clone(),
            "confidenceBasisPoints": body["confidenceBasisPoints"].clone(),
            "sensitivity": body["sensitivity"].clone(),
            "retention": body["retention"].clone(),
            "supersedesRevisionId": null,
            "sources": body["sources"].clone(),
            "createdAtMs": created_at_ms,
            "lastVerifiedAtMs": created_at_ms
        }]
    })
}

fn update_memory(state: &MockState, memory_id: &str, update: impl FnOnce(&mut Value)) -> Response {
    let mut memories = state.memory.lock().expect("memory fixture");
    let Some(memory) = memories
        .iter_mut()
        .find(|memory| memory["memoryId"] == memory_id)
    else {
        return memory_not_found();
    };
    update(memory);
    Json(memory.clone()).into_response()
}

fn update_memory_status(
    state: &MockState,
    memory_id: &str,
    body: &Value,
    status: &str,
) -> Response {
    update_memory(state, memory_id, |memory| {
        let expected = body["expectedRevision"]
            .as_u64()
            .expect("expected revision");
        let updated_at_ms = memory["createdAtMs"]
            .as_i64()
            .expect("memory creation time")
            + 15;
        memory["status"] = json!(status);
        memory["revision"] = json!(expected + 1);
        memory["lastVerifiedAtMs"] = json!(updated_at_ms);
        let newest = memory["revisions"]
            .as_array_mut()
            .and_then(|revisions| revisions.last_mut())
            .expect("newest revision");
        newest["status"] = json!(status);
        newest["lastVerifiedAtMs"] = json!(updated_at_ms);
    })
}

async fn extensions(State(state): State<MockState>, headers: HeaderMap) -> Response {
    let extension = state.extension.lock().expect("extension fixture").clone();
    authenticated_json(
        &state,
        &headers,
        json!({"apiVersion": API_VERSION, "extensions": [extension]}),
    )
}

async fn extension_detail(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(extension_id): Path<String>,
) -> Response {
    assert_eq!(extension_id, EXTENSION_ID);
    let extension = state.extension.lock().expect("extension fixture").clone();
    authenticated_json(&state, &headers, extension)
}

async fn enable_extension(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(extension_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    assert_eq!(extension_id, EXTENSION_ID);
    if !record_dynamic_command(&state, &headers, "enable_extension", &body) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let expected_revision = body["expectedRevision"]
        .as_u64()
        .expect("extension expected revision");
    let grant = json!({
        "grantId": EXTENSION_GRANT_ID,
        "grantDigest": "d".repeat(64),
        "manifestDigest": "e".repeat(64),
        "capabilityIds": body["capabilityIds"].clone(),
        "mounts": body["mounts"].clone(),
        "networkDestinations": body["networkDestinations"].clone(),
        "secretReferences": body["secretReferences"].clone(),
        "allowProcessSpawn": body["allowProcessSpawn"].clone(),
        "policyVersion": "mealy.extension.policy.v1",
        "issuedAtMs": 1_800_000_000_100_i64 + i64::try_from(expected_revision).expect("revision fits")
    });
    let extension = extension_value("enabled", expected_revision + 1, Some(&grant));
    *state.extension.lock().expect("extension fixture") = extension.clone();
    Json(extension).into_response()
}

async fn disable_extension(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(extension_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    assert_eq!(extension_id, EXTENSION_ID);
    extension_lifecycle_command(&state, &headers, "disable_extension", &body, "disabled")
}

async fn revoke_extension(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(extension_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    assert_eq!(extension_id, EXTENSION_ID);
    extension_lifecycle_command(&state, &headers, "revoke_extension", &body, "revoked")
}

fn extension_lifecycle_command(
    state: &MockState,
    headers: &HeaderMap,
    operation: &str,
    body: &Value,
    status: &str,
) -> Response {
    if !record_dynamic_command(state, headers, operation, body) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let expected_revision = body["expectedRevision"]
        .as_u64()
        .expect("extension expected revision");
    let extension = extension_value(status, expected_revision + 1, None);
    *state.extension.lock().expect("extension fixture") = extension.clone();
    Json(extension).into_response()
}

fn extension_value(status: &str, revision: u64, active_grant: Option<&Value>) -> Value {
    json!({
        "apiVersion": API_VERSION,
        "extensionId": EXTENSION_ID,
        "principalId": "019f0000-0000-7000-8000-000000000001",
        "status": status,
        "revision": revision,
        "manifestDigest": "e".repeat(64),
        "version": "1.0.0",
        "name": "dev.mealy.dashboard-fixture",
        "publisher": "dev.mealy",
        "manifest": {
            "schemaVersion": 1,
            "extensionId": EXTENSION_ID,
            "name": "dev.mealy.dashboard-fixture",
            "publisher": "dev.mealy",
            "version": "1.0.0",
            "kinds": ["tool_service"],
            "compatibility": {"minimumHostApi": 1, "maximumHostApi": 1},
            "entryPoint": {"executable": "fixture", "executableDigest": "f".repeat(64), "runtimeFiles": []},
            "capabilities": [
                {
                    "capabilityId": "health",
                    "kind": "health",
                    "effectClass": "read_only",
                    "riskClass": "low",
                    "inputSchema": {"properties": {}, "required": [], "additionalProperties": false, "maximumSerializedBytes": 1024},
                    "outputSchema": {"properties": {}, "required": [], "additionalProperties": false, "maximumSerializedBytes": 1024},
                    "timeoutMs": 1000,
                    "maximumOutputBytes": 1024
                },
                {
                    "capabilityId": "inspect",
                    "kind": "tool",
                    "effectClass": "read_only",
                    "riskClass": "low",
                    "inputSchema": {"properties": {}, "required": [], "additionalProperties": false, "maximumSerializedBytes": 1024},
                    "outputSchema": {"properties": {}, "required": [], "additionalProperties": false, "maximumSerializedBytes": 1024},
                    "timeoutMs": 1000,
                    "maximumOutputBytes": 1024
                }
            ],
            "permissions": {
                "filesystem": [{"name": "workspace", "access": "read_only"}],
                "networkDestinations": ["api.example:443"],
                "secretReferences": ["provider.primary"],
                "allowProcessSpawn": true
            },
            "healthCheck": {"capabilityId": "health", "timeoutMs": 1000, "intervalMs": 5000},
            "migrations": [],
            "shutdown": {"mode": "terminate", "capabilityId": null, "gracePeriodMs": 1000}
        },
        "activeGrant": active_grant,
        "manifestHistory": [{
            "manifestDigest": "e".repeat(64),
            "version": "1.0.0",
            "installedAtMs": 1_800_000_000_000_i64
        }],
        "lastHealthyAtMs": if status == "enabled" { json!(1_800_000_000_100_i64 + i64::try_from(revision).expect("revision fits")) } else { Value::Null },
        "lastFailureAtMs": Value::Null
    })
}

fn record_dynamic_command(
    state: &MockState,
    headers: &HeaderMap,
    operation: &str,
    body: &Value,
) -> bool {
    if !authenticate(state, headers) {
        return false;
    }
    state
        .commands
        .lock()
        .expect("command recorder")
        .push((operation.to_owned(), body.clone()));
    true
}

fn memory_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "apiVersion": API_VERSION,
            "code": "memory_not_found",
            "message": "memory was not found",
            "retryable": false
        })),
    )
        .into_response()
}

fn authenticated_command(
    state: &MockState,
    headers: &HeaderMap,
    operation: &str,
    body: Value,
    response: Value,
) -> Response {
    if !authenticate(state, headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    state
        .commands
        .lock()
        .expect("command recorder")
        .push((operation.to_owned(), body));
    Json(response).into_response()
}

fn authenticated_json(state: &MockState, headers: &HeaderMap, value: Value) -> Response {
    if !authenticate(state, headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(value).into_response()
}

fn authenticate(state: &MockState, headers: &HeaderMap) -> bool {
    let expected = format!("Bearer {DAEMON_TOKEN}");
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        != Some(expected.as_str())
    {
        return false;
    }
    state.requests.fetch_add(1, Ordering::SeqCst);
    true
}
