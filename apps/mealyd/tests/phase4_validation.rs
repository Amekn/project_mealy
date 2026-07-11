//! Public-API proof for deterministic and fresh-context task validation.

#![cfg(target_os = "linux")]

use mealy_protocol::{
    API_VERSION, ApprovalDecisionCommand, ApprovalResolutionReceipt, CreateSessionRequest,
    CreateSessionResponse, DeliveryMode, InputAdmissionResponse, LocalConnectionInfo,
    PendingApprovalsResponse, ReadinessResponse, ResolveApprovalRequest, SubmitInputRequest,
    TaskReplayResponse, TaskResponse, TaskRiskClass, TaskStatus, TimelinePageResponse,
    ValidationMethodResponse, ValidationOutcomeResponse,
};
use reqwest::{Client, StatusCode};
use rusqlite::Connection;
use serde_json::json;
use std::{
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tempfile::TempDir;
use tokio::time::{Instant, sleep};

const READY_TIMEOUT: Duration = Duration::from_secs(15);
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(30);

struct Daemon {
    child: Child,
}

impl Daemon {
    fn spawn(home: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_mealyd"))
            .arg("--home")
            .arg(home)
            .arg("--promotion-delay-ms")
            .arg("0")
            .arg("--promotion-interval-ms")
            .arg("10")
            .arg("--outbox-delay-ms")
            .arg("0")
            .arg("--agent-delay-ms")
            .arg("0")
            .env("RUST_LOG", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("mealyd process should start");
        Self { child }
    }

    fn hard_kill(&mut self) {
        self.child.kill().expect("mealyd should accept a hard kill");
        let status = self.child.wait().expect("killed mealyd should be reaped");
        assert!(
            !status.success(),
            "hard-killed mealyd must not exit cleanly"
        );
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn public_tasks_expose_deterministic_and_fresh_validation_across_restart() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let home = TempDir::new().expect("temporary daemon home should be created");
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .expect("HTTP client should build");
    let mut daemon = Daemon::spawn(home.path());
    let connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;

    let read_admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase4-deterministic-read".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Read the fixture report and answer only from recorded evidence.".to_owned(),
        },
    )
    .await;
    let (read_task_id, read_run_id) = wait_for_task_and_run(
        &client,
        &connection,
        &session.session_id,
        read_admission.cursor.0,
    )
    .await;
    let read_task = wait_until_task_succeeds(&client, &connection, &read_task_id).await;
    assert_eq!(read_task.success_criteria.risk_class, TaskRiskClass::Low);
    assert_eq!(
        read_task
            .success_criteria
            .criteria
            .iter()
            .map(|criterion| criterion.criterion_id.as_str())
            .collect::<Vec<_>>(),
        vec!["tool_evidence", "response_grounding"]
    );
    let read_validation = read_task
        .validation
        .as_ref()
        .expect("low-risk read should retain deterministic validation evidence");
    assert_eq!(
        read_validation.method,
        ValidationMethodResponse::Deterministic
    );
    assert_eq!(read_validation.outcome, ValidationOutcomeResponse::Passed);
    assert_eq!(read_validation.producer_run_id, read_run_id);
    assert!(read_validation.validator_run_id.is_none());
    assert_all_findings_pass(&read_validation.evidence);

    let write_admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase4-fresh-write".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: format!(
                "fixture.write_file {}",
                json!({
                    "operation": "write_file",
                    "relativePath": "phase4-validated.txt",
                    "content": "validated exactly once",
                })
            ),
        },
    )
    .await;
    let (write_task_id, write_run_id) = wait_for_task_and_run(
        &client,
        &connection,
        &session.session_id,
        write_admission.cursor.0,
    )
    .await;
    let pending = wait_for_pending_approval(&client, &connection).await;
    let approval = pending
        .approvals
        .first()
        .expect("medium-risk write should request approval");
    let _: ApprovalResolutionReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/approvals/{}/resolve", approval.approval_id),
        &ResolveApprovalRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase4-approve-write".to_owned(),
            expected_subject_digest: approval.subject_digest.clone(),
            decision: ApprovalDecisionCommand::Approve,
        },
    )
    .await;
    let write_task = wait_until_task_succeeds(&client, &connection, &write_task_id).await;
    assert_eq!(
        write_task.success_criteria.risk_class,
        TaskRiskClass::Medium
    );
    let write_validation = write_task
        .validation
        .as_ref()
        .expect("medium-risk write must expose validation evidence");
    assert_eq!(
        write_validation.method,
        ValidationMethodResponse::FreshContextModel
    );
    assert_eq!(write_validation.outcome, ValidationOutcomeResponse::Passed);
    assert_eq!(write_validation.producer_run_id, write_run_id);
    let validator_run_id = write_validation
        .validator_run_id
        .as_deref()
        .expect("fresh-context validation should create a validator run");
    assert_all_findings_pass(&write_validation.evidence);
    assert_eq!(
        fs::read_to_string(home.path().join("fixture-workspace/phase4-validated.txt"))
            .expect("validated fixture output should exist"),
        "validated exactly once"
    );

    assert_validation_storage(
        home.path(),
        &read_task_id,
        &write_task_id,
        &write_run_id,
        validator_run_id,
        &write_validation.context_manifest_id,
    );
    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "validation.completed")
            .count(),
        2
    );
    let first_validation_id = read_validation.validation_id.clone();
    let second_validation_id = write_validation.validation_id.clone();

    daemon.hard_kill();
    fs::remove_file(home.path().join("connection.json"))
        .expect("stale endpoint descriptor should be removable");
    let _restarted = Daemon::spawn(home.path());
    let restarted_connection = wait_until_ready(&client, home.path()).await;
    let read_after: TaskResponse = authorized_get(
        &client,
        &restarted_connection,
        &format!("/v1/tasks/{read_task_id}"),
    )
    .await;
    let write_after: TaskResponse = authorized_get(
        &client,
        &restarted_connection,
        &format!("/v1/tasks/{write_task_id}"),
    )
    .await;
    assert_eq!(
        read_after.validation.map(|value| value.validation_id),
        Some(first_validation_id)
    );
    assert_eq!(
        write_after.validation.map(|value| value.validation_id),
        Some(second_validation_id)
    );
    let replay: TaskReplayResponse = authorized_get(
        &client,
        &restarted_connection,
        &format!("/v1/tasks/{write_task_id}/replay"),
    )
    .await;
    assert!(
        replay.evidence_complete,
        "replay evidence diverged: {replay:?}"
    );
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    assert_eq!(validation_count(home.path()), 2);
}

fn assert_all_findings_pass(evidence: &serde_json::Value) {
    let findings = evidence["findings"]
        .as_object()
        .expect("validation should expose structured findings");
    assert!(!findings.is_empty());
    assert!(
        findings.values().all(|value| value.as_bool() == Some(true)),
        "validation findings did not all pass: {findings:?}"
    );
    assert_eq!(evidence["producerHiddenContextUsed"], false);
}

fn assert_validation_storage(
    home: &Path,
    read_task_id: &str,
    write_task_id: &str,
    write_run_id: &str,
    validator_run_id: &str,
    context_manifest_id: &str,
) {
    let connection = open_database(home);
    let counts: (i64, i64) = connection
        .query_row(
            "SELECT \
                (SELECT COUNT(*) FROM validation_record WHERE task_id = ?1), \
                (SELECT COUNT(*) FROM validation_record WHERE task_id = ?2)",
            rusqlite::params![read_task_id, write_task_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("validation counts should be queryable");
    assert_eq!(counts, (1, 1));
    let manifest: (i64, i64, i64, i64, String) = connection
        .query_row(
            "SELECT producer_hidden_context_included, \
                    json_array_length(json_extract(capability_grant_json, '$.networkDestinations')), \
                    json_array_length(json_extract(capability_grant_json, '$.secretReferences')), \
                    json_array_length(json_extract(capability_grant_json, '$.effectClasses')), \
                    producer_run_id \
             FROM validation_context_manifest WHERE id = ?1",
            [context_manifest_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("fresh context manifest should be queryable");
    assert_eq!(manifest, (0, 0, 0, 1, write_run_id.to_owned()));
    let validator: (String, String, String, String, i64) = connection
        .query_row(
            "SELECT run.parent_run_id, run.agent_role, run.status, lineage.relation_kind, \
                    lineage.depth \
             FROM run JOIN run_lineage lineage ON lineage.run_id = run.id \
             WHERE run.id = ?1",
            [validator_run_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("validator lineage should be queryable");
    assert_eq!(
        validator,
        (
            write_run_id.to_owned(),
            "validator".to_owned(),
            "succeeded".to_owned(),
            "validation".to_owned(),
            1,
        )
    );
    let epochs: (i64, i64, i64, Option<String>) = connection
        .query_row(
            "SELECT COUNT(*), \
                    SUM(CASE WHEN retired_at_ms IS NOT NULL THEN 1 ELSE 0 END), \
                    SUM(CASE WHEN retired_at_ms IS NULL THEN 1 ELSE 0 END), \
                    MAX(CASE WHEN retired_at_ms IS NULL THEN baseline_version END) \
             FROM context_epoch WHERE session_id = (\
                SELECT turn.session_id FROM turn JOIN run ON run.id = turn.run_id \
                WHERE run.id = ?1\
             )",
            [write_run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("context epoch rotation should be queryable");
    assert_eq!(
        epochs,
        (2, 1, 1, Some("mealy.phase3.baseline.v1".to_owned()))
    );
}

fn validation_count(home: &Path) -> i64 {
    open_database(home)
        .query_row("SELECT COUNT(*) FROM validation_record", [], |row| {
            row.get(0)
        })
        .expect("validation count should be queryable")
}

fn open_database(home: &Path) -> Connection {
    let connection =
        Connection::open(home.join("mealy.sqlite3")).expect("durable Phase 4 database should open");
    connection
        .busy_timeout(Duration::from_secs(2))
        .expect("SQLite busy timeout should be configured");
    connection
}

async fn wait_until_ready(client: &Client, home: &Path) -> LocalConnectionInfo {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if let Ok(bytes) = fs::read(home.join("connection.json"))
            && let Ok(connection) = serde_json::from_slice::<LocalConnectionInfo>(&bytes)
            && let Ok(response) = client
                .get(format!("{}/health/ready", connection.base_url))
                .bearer_auth(&connection.bearer_token)
                .send()
                .await
            && response.status().is_success()
            && let Ok(readiness) = response.json::<ReadinessResponse>().await
            && readiness.ready
        {
            return connection;
        }
        assert!(Instant::now() < deadline, "mealyd did not become ready");
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_task_and_run(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
    after: u64,
) -> (String, String) {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let page: TimelinePageResponse = authorized_get(
            client,
            connection,
            &format!("/v1/sessions/{session_id}/timeline?after={after}&limit=100"),
        )
        .await;
        let task = page
            .events
            .iter()
            .find(|event| event.event_type == "task.created");
        let run = page
            .events
            .iter()
            .find(|event| event.event_type == "run.created");
        if let (Some(task), Some(run)) = (task, run) {
            return (task.aggregate_id.clone(), run.aggregate_id.clone());
        }
        assert!(Instant::now() < deadline, "input was not promoted");
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_pending_approval(
    client: &Client,
    connection: &LocalConnectionInfo,
) -> PendingApprovalsResponse {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let pending: PendingApprovalsResponse =
            authorized_get(client, connection, "/v1/approvals").await;
        if !pending.approvals.is_empty() {
            return pending;
        }
        assert!(Instant::now() < deadline, "approval was not requested");
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_until_task_succeeds(
    client: &Client,
    connection: &LocalConnectionInfo,
    task_id: &str,
) -> TaskResponse {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let task: TaskResponse =
            authorized_get(client, connection, &format!("/v1/tasks/{task_id}")).await;
        match task.status {
            TaskStatus::Succeeded => return task,
            TaskStatus::Failed | TaskStatus::Cancelled => {
                panic!("validation task reached an unexpected terminal state: {task:?}")
            }
            TaskStatus::Queued
            | TaskStatus::Running
            | TaskStatus::Waiting
            | TaskStatus::Paused
            | TaskStatus::Cancelling => {}
        }
        assert!(
            Instant::now() < deadline,
            "task did not reach validated success: {task:?}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn authorized_get<T: serde::de::DeserializeOwned>(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
) -> T {
    let response = client
        .get(format!("{}{path}", connection.base_url))
        .bearer_auth(&connection.bearer_token)
        .send()
        .await
        .expect("authorized GET should reach mealyd");
    assert_eq!(response.status(), StatusCode::OK);
    response
        .json()
        .await
        .expect("response should be valid JSON")
}

async fn authorized_post<T: serde::de::DeserializeOwned>(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
    body: &impl serde::Serialize,
) -> T {
    let response = client
        .post(format!("{}{path}", connection.base_url))
        .bearer_auth(&connection.bearer_token)
        .json(body)
        .send()
        .await
        .expect("authorized POST should reach mealyd");
    assert_eq!(response.status(), StatusCode::OK);
    response
        .json()
        .await
        .expect("response should be valid JSON")
}
