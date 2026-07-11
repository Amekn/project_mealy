//! Public-API crash-recovery scenario for a dispatched Phase 2 provider attempt.

use mealy_application::sha256_digest;
use mealy_protocol::{
    API_VERSION, CreateSessionRequest, CreateSessionResponse, DeliveryMode, InputAdmissionResponse,
    LocalConnectionInfo, ReadinessResponse, SubmitInputRequest, TaskReplayResponse, TaskResponse,
    TaskStatus, TimelineEvent, TimelinePageResponse,
};
use reqwest::{Client, StatusCode};
use rusqlite::Connection;
use std::{
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime},
};
use tempfile::TempDir;
use tokio::time::{Instant, sleep};

const READY_TIMEOUT: Duration = Duration::from_secs(10);
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(15);
const CRASH_PROVIDER_DELAY_MS: u64 = 60_000;

struct Daemon {
    child: Child,
}

impl Daemon {
    fn spawn(home: &Path, fake_provider_delay_ms: u64) -> Self {
        Self::spawn_with_boundary_delay(home, fake_provider_delay_ms, 0)
    }

    fn spawn_with_boundary_delay(
        home: &Path,
        fake_provider_delay_ms: u64,
        boundary_delay_ms: u64,
    ) -> Self {
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
            .arg("--fake-provider-delay-ms")
            .arg(fake_provider_delay_ms.to_string())
            .arg("--agent-boundary-delay-ms")
            .arg(boundary_delay_ms.to_string())
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

#[derive(Debug)]
struct CrashPoint {
    task_id: String,
    run_id: String,
    attempt_id: String,
    dispatched_cursor: u64,
}

#[derive(Debug)]
struct AbandonedLease {
    lease_id: String,
    owner_id: String,
    fencing_token: i64,
    expires_at_ms: i64,
}

#[derive(Debug)]
struct RecoveryFence {
    lease_id: String,
    fencing_token: i64,
}

#[derive(Debug)]
struct PreparedToolCrash {
    task_id: String,
    run_id: String,
    tool_call_id: String,
    prepared_cursor: u64,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dispatched_provider_attempt_is_recovered_immediately_under_a_new_fence() {
    let home = TempDir::new().expect("temporary daemon home should be created");
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("HTTP client should build");

    let mut first_daemon = Daemon::spawn(home.path(), CRASH_PROVIDER_DELAY_MS);
    let first_connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &first_connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-2-attempt-crash".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Recover a dispatched provider attempt without waiting for its lease TTL."
                .to_owned(),
        },
    )
    .await;
    assert!(!admission.duplicate);
    let crash = wait_for_dispatched_attempt(
        &client,
        &first_connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let abandoned = abandoned_lease(home.path(), &crash);
    let now_ms = epoch_milliseconds(SystemTime::now());
    assert!(
        abandoned.expires_at_ms - now_ms > 60_000,
        "the crash must occur while the original 90-second lease is still active"
    );

    first_daemon.hard_kill();
    drop(first_daemon);
    fs::remove_file(home.path().join("connection.json"))
        .expect("ephemeral endpoint descriptor can be recreated from durable identity");

    let restart_started = Instant::now();
    let _second_daemon = Daemon::spawn(home.path(), 0);
    let second_connection = wait_until_ready(&client, home.path()).await;
    assert!(
        restart_started.elapsed() < READY_TIMEOUT,
        "startup recovery must not wait for the abandoned lease TTL"
    );
    let task = wait_until_task_succeeds(&client, &second_connection, &crash.task_id).await;
    assert_recovered_task(&task, &crash);
    let recovery_fence = assert_recovery_state(home.path(), &crash, &abandoned);

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_recovery_timeline(&timeline.events, &crash, &abandoned, &recovery_fence);

    let replay: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{}/replay", crash.task_id),
    )
    .await;
    assert_eq!(replay.api_version, API_VERSION);
    assert_eq!(replay.task_id, crash.task_id);
    assert_eq!(replay.run_id, crash.run_id);
    assert_eq!(replay.mode, "recorded_only");
    assert!(replay.evidence_complete);
    assert_eq!(replay.model_attempts, 3);
    assert_eq!(replay.tool_calls, 1);
    assert_eq!(replay.live_provider_calls, 0);
    assert_eq!(replay.live_tool_calls, 0);
    assert_eq!(replay.final_response, task.final_response);
    assert_eq!(replay.final_digest, task.final_digest);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn undispatched_read_tool_is_retried_after_restart_without_phantom_usage() {
    let home = TempDir::new().expect("temporary daemon home should be created");
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("HTTP client should build");
    let mut first_daemon = Daemon::spawn_with_boundary_delay(home.path(), 0, 1_000);
    let first_connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &first_connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-2-prepared-tool-crash".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Recover an undispatched read tool without charging a phantom call."
                .to_owned(),
        },
    )
    .await;
    let crash = wait_for_prepared_tool(
        &client,
        &first_connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let abandoned = abandoned_tool_lease(home.path(), &crash);
    assert!(
        abandoned.expires_at_ms - epoch_milliseconds(SystemTime::now()) > 60_000,
        "the crash must occur while the original lease is still active"
    );
    first_daemon.hard_kill();
    drop(first_daemon);
    fs::remove_file(home.path().join("connection.json"))
        .expect("ephemeral endpoint descriptor can be recreated from durable identity");

    let _second_daemon = Daemon::spawn(home.path(), 0);
    let second_connection = wait_until_ready(&client, home.path()).await;
    let task = wait_until_task_succeeds(&client, &second_connection, &crash.task_id).await;
    assert_eq!(task.status, TaskStatus::Succeeded);
    assert_eq!(task.model_attempts, 2);
    assert_eq!(task.tool_calls, 2);
    assert_eq!(task.usage.used_model_calls, 2);
    assert_eq!(task.usage.used_tool_calls, 1);
    assert_eq!(task.usage.used_retries, 0);
    assert_eq!(task.usage.reserved_model_calls, 0);
    assert_eq!(task.usage.reserved_tool_calls, 0);

    let database = open_database(home.path());
    let (state, started_at, error_class): (String, Option<i64>, String) = database
        .query_row(
            "SELECT state, started_at_ms, error_class FROM tool_call WHERE tool_call_id = ?1",
            [crash.tool_call_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("abandoned prepared tool should remain as recovery evidence");
    assert_eq!(state, "interrupted");
    assert_eq!(started_at, None);
    assert_eq!(error_class, "daemon_restart");
    let successful_tools: i64 = database
        .query_row(
            "SELECT COUNT(*) FROM tool_call WHERE run_id = ?1 AND state = 'succeeded'",
            [crash.run_id.as_str()],
            |row| row.get(0),
        )
        .expect("successful retry should be queryable");
    assert_eq!(successful_tools, 1);

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    let recovered = timeline
        .events
        .iter()
        .find(|event| {
            event.event_type == "agent.boundary_recovered"
                && event.payload["classification"].as_str() == Some("retry_undispatched_read_tool")
        })
        .expect("timeline should expose the exact prepared-tool recovery classification");
    assert_eq!(
        recovered.payload["current_tool_call_id"].as_str(),
        Some(crash.tool_call_id.as_str())
    );
    assert!(recovered.cursor.0 > crash.prepared_cursor);

    let replay: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{}/replay", crash.task_id),
    )
    .await;
    assert!(replay.evidence_complete);
    assert_eq!(replay.model_attempts, 2);
    assert_eq!(replay.tool_calls, 2);
    assert_eq!(replay.live_provider_calls, 0);
    assert_eq!(replay.live_tool_calls, 0);
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

async fn wait_for_dispatched_attempt(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
    after: u64,
) -> CrashPoint {
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
        let dispatched = page
            .events
            .iter()
            .find(|event| event.event_type == "model.attempt.dispatched");
        if let (Some(task), Some(run), Some(dispatched)) = (task, run, dispatched) {
            assert_eq!(
                dispatched.payload["run_id"].as_str(),
                Some(run.aggregate_id.as_str())
            );
            return CrashPoint {
                task_id: task.aggregate_id.clone(),
                run_id: run.aggregate_id.clone(),
                attempt_id: dispatched.aggregate_id.clone(),
                dispatched_cursor: dispatched.cursor.0,
            };
        }
        assert!(
            Instant::now() < deadline,
            "provider attempt did not reach its durable dispatched boundary"
        );
        sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_prepared_tool(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
    after: u64,
) -> PreparedToolCrash {
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
        let prepared = page
            .events
            .iter()
            .find(|event| event.event_type == "tool.call.prepared");
        if let (Some(task), Some(run), Some(prepared)) = (task, run, prepared) {
            assert_eq!(
                prepared.payload["run_id"].as_str(),
                Some(run.aggregate_id.as_str())
            );
            return PreparedToolCrash {
                task_id: task.aggregate_id.clone(),
                run_id: run.aggregate_id.clone(),
                tool_call_id: prepared.aggregate_id.clone(),
                prepared_cursor: prepared.cursor.0,
            };
        }
        assert!(
            Instant::now() < deadline,
            "read tool did not reach its durable prepared boundary"
        );
        sleep(Duration::from_millis(10)).await;
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
                panic!("recovered task reached the wrong terminal state: {task:?}")
            }
            TaskStatus::Queued
            | TaskStatus::Running
            | TaskStatus::Waiting
            | TaskStatus::Paused
            | TaskStatus::Cancelling => {}
        }
        assert!(
            Instant::now() < deadline,
            "recovered task did not succeed: {task:?}"
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

fn open_database(home: &Path) -> Connection {
    let connection =
        Connection::open(home.join("mealy.sqlite3")).expect("durable database should open");
    connection
        .busy_timeout(Duration::from_secs(2))
        .expect("SQLite busy timeout should be configured");
    connection
}

fn abandoned_lease(home: &Path, crash: &CrashPoint) -> AbandonedLease {
    let (lease_id, owner_id, fencing_token, expires_at_ms, attempt_state, reservation_state): (
        String,
        String,
        i64,
        i64,
        String,
        String,
    ) = open_database(home)
        .query_row(
            "SELECT lease.lease_id, lease.owner_id, lease.fencing_token, lease.expires_at_ms, \
                    attempt.state, reservation.state \
             FROM model_attempt attempt \
             JOIN budget_reservation reservation \
               ON reservation.attempt_id = attempt.attempt_id \
             JOIN work_lease lease \
               ON lease.lease_id = attempt.prepared_lease_id \
              AND lease.run_id = attempt.run_id \
              AND lease.owner_id = attempt.prepared_owner_id \
              AND lease.fencing_token = attempt.prepared_fencing_token \
             WHERE attempt.attempt_id = ?1 AND attempt.run_id = ?2 \
               AND lease.state = 'active'",
            [crash.attempt_id.as_str(), crash.run_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .expect("dispatched attempt should retain an active lease and reservation");
    assert_eq!(attempt_state, "dispatching");
    assert_eq!(reservation_state, "active");
    AbandonedLease {
        lease_id,
        owner_id,
        fencing_token,
        expires_at_ms,
    }
}

fn abandoned_tool_lease(home: &Path, crash: &PreparedToolCrash) -> AbandonedLease {
    let (lease_id, owner_id, fencing_token, expires_at_ms, state, started_at_ms): (
        String,
        String,
        i64,
        i64,
        String,
        Option<i64>,
    ) = open_database(home)
        .query_row(
            "SELECT lease.lease_id, lease.owner_id, lease.fencing_token, lease.expires_at_ms, \
                    tool.state, tool.started_at_ms \
             FROM tool_call tool \
             JOIN work_lease lease \
               ON lease.lease_id = tool.prepared_lease_id AND lease.run_id = tool.run_id \
              AND lease.owner_id = tool.prepared_owner_id \
              AND lease.fencing_token = tool.prepared_fencing_token \
             WHERE tool.tool_call_id = ?1 AND tool.run_id = ?2 AND lease.state = 'active'",
            [crash.tool_call_id.as_str(), crash.run_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .expect("prepared tool should retain its active lease fence");
    assert_eq!(state, "prepared");
    assert_eq!(started_at_ms, None);
    AbandonedLease {
        lease_id,
        owner_id,
        fencing_token,
        expires_at_ms,
    }
}

fn assert_recovered_task(task: &TaskResponse, crash: &CrashPoint) {
    assert_eq!(task.api_version, API_VERSION);
    assert_eq!(task.task_id, crash.task_id);
    assert_eq!(task.run_id, crash.run_id);
    assert_eq!(task.status, TaskStatus::Succeeded);
    assert_eq!(task.model_attempts, 3);
    assert_eq!(task.tool_calls, 1);
    assert_eq!(task.usage.used_retries, 1);
    assert_eq!(task.usage.used_model_calls, 3);
    assert_eq!(task.usage.reserved_model_calls, 0);
    assert_eq!(task.usage.reserved_tool_calls, 0);
    assert_eq!(task.usage.reserved_input_tokens, 0);
    assert_eq!(task.usage.reserved_output_tokens, 0);
    assert_eq!(task.usage.reserved_cost_microunits, 0);
    assert_eq!(task.usage.reserved_output_bytes, 0);
    let response = task
        .final_response
        .as_deref()
        .expect("recovered task should publish a final response");
    let digest = task
        .final_digest
        .as_deref()
        .expect("recovered task should publish a final digest");
    assert_eq!(sha256_digest(response.as_bytes()), digest);
}

#[allow(clippy::too_many_lines)]
fn assert_recovery_state(
    home: &Path,
    crash: &CrashPoint,
    abandoned: &AbandonedLease,
) -> RecoveryFence {
    let database = open_database(home);
    let (lease_state, released_at_ms, expires_at_ms): (String, i64, i64) = database
        .query_row(
            "SELECT state, released_at_ms, expires_at_ms FROM work_lease WHERE lease_id = ?1",
            [abandoned.lease_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("abandoned lease should remain as recovery evidence");
    assert_eq!(lease_state, "expired");
    assert_eq!(expires_at_ms, abandoned.expires_at_ms);
    assert!(
        released_at_ms < expires_at_ms,
        "startup must invalidate the active lease before its original TTL"
    );

    let (attempt_state, error_class, retryable, reservation_state): (String, String, i64, String) =
        database
            .query_row(
                "SELECT attempt.state, attempt.error_class, attempt.retryable, reservation.state \
             FROM model_attempt attempt \
             JOIN budget_reservation reservation ON reservation.attempt_id = attempt.attempt_id \
             WHERE attempt.attempt_id = ?1",
                [crash.attempt_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("original provider attempt should retain recovery evidence");
    assert_eq!(attempt_state, "interrupted");
    assert_eq!(error_class, "provider_outcome_unknown_after_restart");
    assert_eq!(retryable, 1);
    assert_eq!(reservation_state, "charged_unknown");

    let (used_retries, used_model_calls, reserved_total): (i64, i64, i64) = database
        .query_row(
            "SELECT used_retries, used_model_calls, \
                    reserved_model_calls + reserved_tool_calls + reserved_input_tokens + \
                    reserved_output_tokens + reserved_cost_microunits + reserved_output_bytes \
             FROM run_budget_usage WHERE run_id = ?1",
            [crash.run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("recovered run budget should be queryable");
    assert_eq!(used_retries, 1);
    assert_eq!(used_model_calls, 3);
    assert_eq!(reserved_total, 0);

    let (attempts, completed_attempts, interrupted_attempts, tools, active_reservations): (
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = database
        .query_row(
            "SELECT \
                (SELECT COUNT(*) FROM model_attempt WHERE run_id = ?1), \
                (SELECT COUNT(*) FROM model_attempt WHERE run_id = ?1 AND state = 'completed'), \
                (SELECT COUNT(*) FROM model_attempt WHERE run_id = ?1 AND state = 'interrupted'), \
                (SELECT COUNT(*) FROM tool_call WHERE run_id = ?1 AND state = 'succeeded'), \
                (SELECT COUNT(*) FROM budget_reservation reservation \
                 JOIN model_attempt attempt ON attempt.attempt_id = reservation.attempt_id \
                 WHERE attempt.run_id = ?1 AND reservation.state = 'active')",
            [crash.run_id.as_str()],
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
        .expect("recovered execution evidence should be queryable");
    assert_eq!(
        (attempts, completed_attempts, interrupted_attempts),
        (3, 2, 1)
    );
    assert_eq!(tools, 1);
    assert_eq!(active_reservations, 0);
    let exact_lineage: i64 = database
        .query_row(
            "SELECT COUNT(*) FROM model_attempt WHERE run_id = ?1 AND (\
                 (ordinal = 2 AND retry_of_attempt_id = ?2) OR \
                 (ordinal <> 2 AND retry_of_attempt_id IS NULL))",
            [crash.run_id.as_str(), crash.attempt_id.as_str()],
            |row| row.get(0),
        )
        .expect("replacement attempt lineage should be queryable");
    assert_eq!(
        exact_lineage, 3,
        "the immediate post-crash attempt must name the interrupted attempt and no other attempt"
    );

    let (lease_id, fencing_token): (String, i64) = database
        .query_row(
            "SELECT lease_id, fencing_token FROM work_lease \
             WHERE run_id = ?1 AND lease_id <> ?2 ORDER BY acquired_at_ms DESC LIMIT 1",
            [crash.run_id.as_str(), abandoned.lease_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("recovered execution should claim a replacement lease");
    assert_ne!(lease_id, abandoned.lease_id);
    assert_eq!(fencing_token, abandoned.fencing_token + 2);
    let fenced_attempts: i64 = database
        .query_row(
            "SELECT COUNT(*) FROM model_attempt \
             WHERE run_id = ?1 AND attempt_id <> ?2 AND prepared_lease_id = ?3 \
               AND prepared_fencing_token = ?4 AND state = 'completed'",
            [
                crash.run_id.as_str(),
                crash.attempt_id.as_str(),
                lease_id.as_str(),
                &fencing_token.to_string(),
            ],
            |row| row.get(0),
        )
        .expect("replacement attempts should be bound to the replacement fence");
    assert_eq!(fenced_attempts, 2);
    RecoveryFence {
        lease_id,
        fencing_token,
    }
}

fn assert_recovery_timeline(
    events: &[TimelineEvent],
    crash: &CrashPoint,
    abandoned: &AbandonedLease,
    recovery: &RecoveryFence,
) {
    let abandoned_start = events
        .iter()
        .find(|event| {
            event.aggregate_kind == "run"
                && event.aggregate_id == crash.run_id
                && event.event_type == "run.started"
                && event.payload["lease_id"].as_str() == Some(abandoned.lease_id.as_str())
        })
        .expect("timeline should retain the abandoned lease claim");
    assert_eq!(
        abandoned_start.payload["owner_id"].as_str(),
        Some(abandoned.owner_id.as_str())
    );
    assert_eq!(
        abandoned_start.payload["fencing_token"].as_i64(),
        Some(abandoned.fencing_token)
    );
    assert!(abandoned_start.cursor.0 < crash.dispatched_cursor);

    let requeued = events
        .iter()
        .find(|event| {
            event.aggregate_kind == "run"
                && event.aggregate_id == crash.run_id
                && event.event_type == "run.requeued"
                && event.payload["agent_recovery"].as_str()
                    == Some("retry_provider_outcome_unknown")
        })
        .expect("timeline should expose provider-outcome-unknown recovery");
    assert!(requeued.cursor.0 > crash.dispatched_cursor);
    assert_eq!(requeued.payload["reason"].as_str(), Some("lease_expired"));
    assert_eq!(
        requeued.payload["invalidated_fencing_token"].as_i64(),
        Some(abandoned.fencing_token)
    );
    assert_eq!(
        requeued.payload["current_fencing_token"].as_i64(),
        Some(abandoned.fencing_token + 1)
    );
    assert!(requeued.occurred_at_ms < abandoned.expires_at_ms);

    let restarted = events
        .iter()
        .find(|event| {
            event.aggregate_kind == "run"
                && event.aggregate_id == crash.run_id
                && event.event_type == "run.started"
                && event.payload["lease_id"].as_str() == Some(recovery.lease_id.as_str())
        })
        .expect("requeued run should restart under the replacement lease");
    assert!(restarted.cursor > requeued.cursor);
    assert_eq!(
        restarted.payload["fencing_token"].as_i64(),
        Some(recovery.fencing_token)
    );
    let succeeded = events
        .iter()
        .find(|event| {
            event.aggregate_kind == "run"
                && event.aggregate_id == crash.run_id
                && event.event_type == "run.succeeded"
        })
        .expect("recovered run should durably succeed");
    assert!(succeeded.cursor > restarted.cursor);
}

fn epoch_milliseconds(time: SystemTime) -> i64 {
    i64::try_from(
        time.duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time should follow Unix epoch")
            .as_millis(),
    )
    .expect("epoch milliseconds should fit i64")
}
