//! Public-API process-boundary cancellation scenario for the Phase 2 agent loop.

use mealy_application::default_daemon_config_document;
use mealy_protocol::{
    API_VERSION, ApiErrorResponse, CancelTaskRequest, CreateSessionRequest, CreateSessionResponse,
    DeliveryMode, InputAdmissionResponse, LocalConnectionInfo, ReadinessResponse,
    SessionStatusResponse, SubmitInputRequest, TaskCancellationReceipt, TaskReplayResponse,
    TaskResponse, TaskStatus, TimelineEvent, TimelinePageResponse,
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

const READY_TIMEOUT: Duration = Duration::from_secs(10);
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(15);
const AGENT_DELAY_MS: u64 = 1_000;
const PROVIDER_TIMEOUT_TEST_MS: u64 = 1_000;

struct Daemon {
    child: Child,
}

impl Daemon {
    fn spawn(home: &Path) -> Self {
        Self::spawn_with_delays(home, AGENT_DELAY_MS, 0)
    }

    fn spawn_with_delays(home: &Path, agent_delay_ms: u64, provider_delay_ms: u64) -> Self {
        Self::spawn_with_boundary_delay(home, agent_delay_ms, provider_delay_ms, 0)
    }

    fn spawn_with_boundary_delay(
        home: &Path,
        agent_delay_ms: u64,
        provider_delay_ms: u64,
        boundary_delay_ms: u64,
    ) -> Self {
        Self::spawn_with_boundary_delay_and_estimate(
            home,
            agent_delay_ms,
            provider_delay_ms,
            1,
            boundary_delay_ms,
        )
    }

    fn spawn_with_boundary_delay_and_estimate(
        home: &Path,
        agent_delay_ms: u64,
        provider_delay_ms: u64,
        provider_estimated_latency_ms: u64,
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
            .arg(agent_delay_ms.to_string())
            .arg("--fake-provider-delay-ms")
            .arg(provider_delay_ms.to_string())
            .arg("--fake-provider-estimated-latency-ms")
            .arg(provider_estimated_latency_ms.to_string())
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

    #[cfg(target_os = "linux")]
    fn provider_threads(&self) -> Vec<String> {
        let task_dir = format!("/proc/{}/task", self.child.id());
        fs::read_dir(task_dir)
            .expect("daemon task directory should remain readable")
            .map(|entry| {
                fs::read_to_string(
                    entry
                        .expect("daemon task entry should be readable")
                        .path()
                        .join("comm"),
                )
                .expect("daemon thread name should be readable")
                .trim()
                .to_owned()
            })
            .filter(|name| name.starts_with("mealy-provider"))
            .collect()
    }

    fn hard_kill(&mut self) {
        self.child.kill().expect("daemon should accept a hard kill");
        self.child.wait().expect("hard-killed daemon should exit");
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
#[allow(clippy::struct_field_names)]
struct WorkIds {
    task_id: String,
    run_id: String,
    turn_id: String,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_is_idempotent_and_closes_every_durable_boundary() {
    let home = TempDir::new().expect("temporary daemon home should be created");
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("HTTP client should build");
    let _daemon = Daemon::spawn(home.path());
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
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-2-cancel-input".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "This task should be cancelled before provider dispatch.".to_owned(),
        },
    )
    .await;
    assert!(!admission.duplicate);
    let ids = wait_for_promoted_work(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;

    let cancellation = CancelTaskRequest {
        api_version: API_VERSION.to_owned(),
        idempotency_key: "phase-2-cancel-command".to_owned(),
        reason: "owner no longer needs this task".to_owned(),
    };
    let first: TaskCancellationReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/tasks/{}/cancel", ids.task_id),
        &cancellation,
    )
    .await;
    assert_eq!(first.api_version, API_VERSION);
    assert_eq!(first.task_id, ids.task_id);
    assert_eq!(first.status, TaskStatus::Cancelling);
    assert!(!first.duplicate);

    let cancelled = wait_until_cancelled(&client, &connection, &ids.task_id).await;
    assert_cancelled_task(&cancelled, &ids);
    assert_no_execution_residue(home.path(), &ids.run_id);

    let duplicate: TaskCancellationReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/tasks/{}/cancel", ids.task_id),
        &cancellation,
    )
    .await;
    assert_duplicate_receipt(&duplicate, &first);

    let conflicting = CancelTaskRequest {
        reason: "same delivery key with changed immutable reason".to_owned(),
        ..cancellation
    };
    let error = post_expect_error(
        &client,
        &connection,
        &format!("/v1/tasks/{}/cancel", ids.task_id),
        &conflicting,
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(error.api_version, API_VERSION);
    assert_eq!(error.code, "conflict");
    assert!(!error.retryable);

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_cancellation_timeline(&timeline.events, &ids, &first);

    let status: SessionStatusResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/status", session.session_id),
    )
    .await;
    assert_eq!(status.pending_inputs, 0);
    assert_eq!(status.active_turn_id, None);
    assert_durable_boundary(home.path(), &session.session_id, &ids);
    wait_until_outbox_delivered(home.path(), &ids).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_during_provider_dispatch_charges_only_dispatched_work() {
    let home = TempDir::new().expect("temporary daemon home should be created");
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("HTTP client should build");
    let daemon = Daemon::spawn_with_delays(home.path(), 0, 60_000);
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
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-2-cancel-dispatched-input".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Cancel this task after provider dispatch.".to_owned(),
        },
    )
    .await;
    let ids = wait_for_promoted_work(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    wait_for_timeline_event(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
        "model.attempt.dispatched",
    )
    .await;

    let _: TaskCancellationReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/tasks/{}/cancel", ids.task_id),
        &CancelTaskRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-2-cancel-dispatched-command".to_owned(),
            reason: "exercise the dispatched cancellation boundary".to_owned(),
        },
    )
    .await;
    let task = wait_until_cancelled(&client, &connection, &ids.task_id).await;
    assert_eq!(task.model_attempts, 1);
    assert_eq!(task.tool_calls, 0);
    assert_eq!(task.usage.used_model_calls, 1);
    assert_eq!(task.usage.reserved_model_calls, 0);
    assert_eq!(task.usage.used_tool_calls, 0);
    assert_eq!(task.usage.reserved_tool_calls, 0);
    assert!(task.usage.used_input_tokens > 0);
    assert!(task.usage.used_output_tokens > 0);
    assert!(task.usage.used_cost_microunits > 0);
    assert!(task.usage.used_output_bytes > 0);
    assert_no_execution_residue(home.path(), &ids.run_id);

    let (attempt_state, reservation_state, next_action): (String, String, String) =
        open_database(home.path())
            .query_row(
                "SELECT ma.state, br.state, ls.next_action FROM model_attempt ma \
                 JOIN budget_reservation br ON br.attempt_id = ma.attempt_id \
                 JOIN run_loop_state ls ON ls.run_id = ma.run_id \
                 WHERE ma.run_id = ?1",
                [ids.run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("dispatched cancellation evidence should be queryable");
    assert_eq!(attempt_state, "interrupted");
    assert_eq!(reservation_state, "charged_unknown");
    assert_eq!(next_action, "dispatch_model");

    #[cfg(target_os = "linux")]
    {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !daemon.provider_threads().is_empty() && Instant::now() < deadline {
            sleep(Duration::from_millis(10)).await;
        }
        assert!(
            daemon.provider_threads().is_empty(),
            "cooperative cancellation must stop the provider dispatch thread"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_after_prepare_releases_undispatched_reservation_without_charging() {
    let home = TempDir::new().expect("temporary daemon home should be created");
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("HTTP client should build");
    let _daemon = Daemon::spawn_with_boundary_delay(home.path(), 0, 0, 1_000);
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
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-2-cancel-prepared-input".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Cancel after durable preparation but before dispatch.".to_owned(),
        },
    )
    .await;
    let ids = wait_for_promoted_work(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    wait_for_timeline_event(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
        "model.attempt.prepared",
    )
    .await;

    let _: TaskCancellationReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/tasks/{}/cancel", ids.task_id),
        &CancelTaskRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-2-cancel-prepared-command".to_owned(),
            reason: "verify undispatched budget release".to_owned(),
        },
    )
    .await;
    let task = wait_until_cancelled(&client, &connection, &ids.task_id).await;
    assert_eq!(task.model_attempts, 1);
    assert_eq!(task.tool_calls, 0);
    assert_eq!(task.usage.used_model_calls, 0);
    assert_eq!(task.usage.reserved_model_calls, 0);
    assert_eq!(task.usage.used_tool_calls, 0);
    assert_eq!(task.usage.reserved_tool_calls, 0);
    assert_eq!(task.usage.used_input_tokens, 0);
    assert_eq!(task.usage.used_output_tokens, 0);
    assert_eq!(task.usage.used_cost_microunits, 0);
    assert_eq!(task.usage.used_output_bytes, 0);
    assert_no_execution_residue(home.path(), &ids.run_id);

    let (attempt_state, dispatched_at, reservation_state): (String, Option<i64>, String) =
        open_database(home.path())
            .query_row(
                "SELECT ma.state, ma.dispatched_at_ms, br.state FROM model_attempt ma \
                 JOIN budget_reservation br ON br.attempt_id = ma.attempt_id \
                 WHERE ma.run_id = ?1",
                [ids.run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("prepared cancellation evidence should be queryable");
    assert_eq!(attempt_state, "cancelled");
    assert_eq!(dispatched_at, None);
    assert_eq!(reservation_state, "released");
    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert!(
        timeline
            .events
            .iter()
            .all(|event| event.event_type != "model.attempt.dispatched"),
        "prepared cancellation must not fabricate a provider dispatch"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_timeout_is_terminal_bounded_and_stops_its_dispatch_thread() {
    let home = TempDir::new().expect("temporary daemon home should be created");
    write_provider_timeout_test_config(home.path());
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("HTTP client should build");
    let daemon = Daemon::spawn_with_delays(home.path(), 0, 60_000);
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
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-2-provider-timeout-input".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Exercise the bounded provider timeout.".to_owned(),
        },
    )
    .await;
    let ids = wait_for_promoted_work(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let task = wait_until_failed(&client, &connection, &ids.task_id).await;
    assert_eq!(task.model_attempts, 1);
    assert_eq!(task.tool_calls, 0);
    assert_eq!(task.usage.used_model_calls, 1);
    assert_eq!(task.usage.reserved_model_calls, 0);
    assert_eq!(task.usage.used_tool_calls, 0);
    assert_eq!(task.usage.reserved_tool_calls, 0);
    assert!(task.usage.used_input_tokens > 0);
    assert!(task.usage.used_output_tokens > 0);
    assert!(task.usage.used_cost_microunits > 0);
    assert!(task.usage.used_output_bytes > 0);
    assert_no_execution_residue(home.path(), &ids.run_id);

    let (attempt_state, reservation_state): (String, String) = open_database(home.path())
        .query_row(
            "SELECT ma.state, br.state FROM model_attempt ma \
             JOIN budget_reservation br ON br.attempt_id = ma.attempt_id \
             WHERE ma.run_id = ?1",
            [ids.run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("provider timeout evidence should be queryable");
    assert_eq!(attempt_state, "interrupted");
    assert_eq!(reservation_state, "charged_unknown");

    #[cfg(target_os = "linux")]
    {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !daemon.provider_threads().is_empty() && Instant::now() < deadline {
            sleep(Duration::from_millis(10)).await;
        }
        assert!(
            daemon.provider_threads().is_empty(),
            "the local timeout probe must stop the provider dispatch thread"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn elapsed_pre_dispatch_deadline_retries_without_phantom_usage() {
    let home = TempDir::new().expect("temporary daemon home should be created");
    write_provider_timeout_test_config(home.path());
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("HTTP client should build");
    let mut delayed_daemon = Daemon::spawn_with_boundary_delay(home.path(), 0, 0, 1_250);
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
            idempotency_key: "phase-2-expired-pre-dispatch-input".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Retry an undispatched provider attempt after scheduler contention."
                .to_owned(),
        },
    )
    .await;
    let ids = wait_for_promoted_work(
        &client,
        &first_connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let expired_attempt_id = wait_for_retired_pre_dispatch_attempt(
        home.path(),
        &ids.run_id,
        "provider_dispatch_deadline_elapsed",
    )
    .await;
    delayed_daemon.hard_kill();
    drop(delayed_daemon);
    fs::remove_file(home.path().join("connection.json"))
        .expect("ephemeral endpoint descriptor can be recreated after interruption");

    let _replacement_daemon = Daemon::spawn_with_delays(home.path(), 0, 0);
    let replacement_connection = wait_until_ready(&client, home.path()).await;
    assert_successful_undispatched_retry(&client, &replacement_connection, &ids).await;

    let database = open_database(home.path());
    let (state, dispatched_at_ms, deadline_at_ms, completed_at_ms, error_class, reservation): (
        String,
        Option<i64>,
        i64,
        i64,
        String,
        String,
    ) = database
        .query_row(
            "SELECT ma.state, ma.dispatched_at_ms, ma.deadline_at_ms, ma.completed_at_ms, \
                    ma.error_class, br.state \
             FROM model_attempt ma \
             JOIN budget_reservation br ON br.attempt_id = ma.attempt_id \
             WHERE ma.attempt_id = ?1 AND ma.run_id = ?2",
            [expired_attempt_id.as_str(), ids.run_id.as_str()],
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
        .expect("expired preparation evidence should remain queryable");
    assert_eq!(state, "interrupted");
    assert_eq!(dispatched_at_ms, None);
    assert!(completed_at_ms >= deadline_at_ms);
    assert_eq!(error_class, "provider_dispatch_deadline_elapsed");
    assert_eq!(reservation, "released");

    assert_complete_undispatched_retry_replay(&client, &replacement_connection, &ids).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn insufficient_pre_dispatch_execution_window_retries_without_phantom_usage() {
    let home = TempDir::new().expect("temporary daemon home should be created");
    write_provider_timeout_test_config(home.path());
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("HTTP client should build");
    let mut delayed_daemon =
        Daemon::spawn_with_boundary_delay_and_estimate(home.path(), 0, 250, 250, 800);
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
            idempotency_key: "phase-2-short-pre-dispatch-window-input".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Retry before dispatch when contention consumed the provider window."
                .to_owned(),
        },
    )
    .await;
    let ids = wait_for_promoted_work(
        &client,
        &first_connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let retired_attempt_id = wait_for_retired_pre_dispatch_attempt(
        home.path(),
        &ids.run_id,
        "provider_dispatch_window_exhausted",
    )
    .await;
    delayed_daemon.hard_kill();
    drop(delayed_daemon);
    fs::remove_file(home.path().join("connection.json"))
        .expect("ephemeral endpoint descriptor can be recreated after interruption");

    let _replacement_daemon = Daemon::spawn_with_delays(home.path(), 0, 0);
    let replacement_connection = wait_until_ready(&client, home.path()).await;
    assert_successful_undispatched_retry(&client, &replacement_connection, &ids).await;

    let database = open_database(home.path());
    let (state, dispatched_at_ms, deadline_at_ms, completed_at_ms, error_class, reservation): (
        String,
        Option<i64>,
        i64,
        i64,
        String,
        String,
    ) = database
        .query_row(
            "SELECT ma.state, ma.dispatched_at_ms, ma.deadline_at_ms, ma.completed_at_ms, \
                    ma.error_class, br.state \
             FROM model_attempt ma \
             JOIN budget_reservation br ON br.attempt_id = ma.attempt_id \
             WHERE ma.attempt_id = ?1 AND ma.run_id = ?2",
            [retired_attempt_id.as_str(), ids.run_id.as_str()],
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
        .expect("short dispatch-window evidence should remain queryable");
    assert_eq!(state, "interrupted");
    assert_eq!(dispatched_at_ms, None);
    assert!(completed_at_ms < deadline_at_ms);
    assert!(deadline_at_ms - completed_at_ms < 250);
    assert_eq!(error_class, "provider_dispatch_window_exhausted");
    assert_eq!(reservation, "released");

    assert_complete_undispatched_retry_replay(&client, &replacement_connection, &ids).await;
}

async fn assert_successful_undispatched_retry(
    client: &Client,
    connection: &LocalConnectionInfo,
    ids: &WorkIds,
) {
    let task = wait_until_succeeded(client, connection, &ids.task_id).await;
    assert_eq!(task.status, TaskStatus::Succeeded);
    assert_eq!(task.model_attempts, 3);
    assert_eq!(task.tool_calls, 1);
    assert_eq!(task.usage.used_model_calls, 2);
    assert_eq!(task.usage.used_retries, 0);
    assert_eq!(task.usage.used_tool_calls, 1);
    assert_eq!(task.usage.reserved_model_calls, 0);
    assert_eq!(task.usage.reserved_tool_calls, 0);
}

async fn assert_complete_undispatched_retry_replay(
    client: &Client,
    connection: &LocalConnectionInfo,
    ids: &WorkIds,
) {
    let replay: TaskReplayResponse = authorized_get(
        client,
        connection,
        &format!("/v1/tasks/{}/replay", ids.task_id),
    )
    .await;
    assert!(replay.evidence_complete);
    assert_eq!(replay.model_attempts, 3);
    assert_eq!(replay.tool_calls, 1);
    assert_eq!(replay.live_provider_calls, 0);
    assert_eq!(replay.live_tool_calls, 0);
}

fn assert_duplicate_receipt(
    duplicate: &TaskCancellationReceipt,
    original: &TaskCancellationReceipt,
) {
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.api_version, original.api_version);
    assert_eq!(duplicate.task_id, original.task_id);
    assert_eq!(duplicate.status, original.status);
    assert_eq!(duplicate.revision, original.revision);
    assert_eq!(duplicate.event_id, original.event_id);
    assert_eq!(duplicate.cursor, original.cursor);
}

fn assert_cancelled_task(task: &TaskResponse, ids: &WorkIds) {
    assert_eq!(task.api_version, API_VERSION);
    assert_eq!(task.task_id, ids.task_id);
    assert_eq!(task.run_id, ids.run_id);
    assert_eq!(task.status, TaskStatus::Cancelled);
    assert_eq!(task.final_response, None);
    assert_eq!(task.final_digest, None);
    assert_eq!(task.model_attempts, 0);
    assert_eq!(task.tool_calls, 0);
    assert_eq!(task.usage.used_model_calls, 0);
    assert_eq!(task.usage.reserved_model_calls, 0);
    assert_eq!(task.usage.used_tool_calls, 0);
    assert_eq!(task.usage.reserved_tool_calls, 0);
    assert_eq!(task.usage.reserved_input_tokens, 0);
    assert_eq!(task.usage.reserved_output_tokens, 0);
    assert_eq!(task.usage.reserved_cost_microunits, 0);
    assert_eq!(task.usage.reserved_output_bytes, 0);
}

fn write_provider_timeout_test_config(home: &Path) {
    let mut config = default_daemon_config_document();
    config["agentLoopLimits"]["providerTimeoutMs"] = json!(PROVIDER_TIMEOUT_TEST_MS);
    fs::write(
        home.join("config.json"),
        serde_json::to_vec_pretty(&config).expect("encode timeout-test config"),
    )
    .expect("write timeout-test config");
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

async fn wait_for_promoted_work(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
    after: u64,
) -> WorkIds {
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
            let turn_id = task.payload["turn_id"]
                .as_str()
                .expect("task creation should identify its turn")
                .to_owned();
            assert_eq!(
                run.payload["task_id"].as_str(),
                Some(task.aggregate_id.as_str())
            );
            return WorkIds {
                task_id: task.aggregate_id.clone(),
                run_id: run.aggregate_id.clone(),
                turn_id,
            };
        }
        assert!(
            Instant::now() < deadline,
            "input was not promoted before the delayed agent worker"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_timeline_event(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
    after: u64,
    event_type: &str,
) {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let page: TimelinePageResponse = authorized_get(
            client,
            connection,
            &format!("/v1/sessions/{session_id}/timeline?after={after}&limit=100"),
        )
        .await;
        if page
            .events
            .iter()
            .any(|event| event.event_type == event_type)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timeline did not expose {event_type}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_until_cancelled(
    client: &Client,
    connection: &LocalConnectionInfo,
    task_id: &str,
) -> TaskResponse {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let task: TaskResponse =
            authorized_get(client, connection, &format!("/v1/tasks/{task_id}")).await;
        match task.status {
            TaskStatus::Cancelled => return task,
            TaskStatus::Succeeded | TaskStatus::Failed => {
                panic!("cancelled task reached the wrong terminal state: {task:?}")
            }
            TaskStatus::Queued
            | TaskStatus::Running
            | TaskStatus::Waiting
            | TaskStatus::Paused
            | TaskStatus::Cancelling => {}
        }
        assert!(
            Instant::now() < deadline,
            "task did not reach its durable cancellation boundary: {task:?}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_until_failed(
    client: &Client,
    connection: &LocalConnectionInfo,
    task_id: &str,
) -> TaskResponse {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let task: TaskResponse =
            authorized_get(client, connection, &format!("/v1/tasks/{task_id}")).await;
        match task.status {
            TaskStatus::Failed => return task,
            TaskStatus::Succeeded | TaskStatus::Cancelled => {
                panic!("timed-out task reached the wrong terminal state: {task:?}")
            }
            TaskStatus::Queued
            | TaskStatus::Running
            | TaskStatus::Waiting
            | TaskStatus::Paused
            | TaskStatus::Cancelling => {}
        }
        assert!(
            Instant::now() < deadline,
            "provider timeout did not reach a terminal failure: {task:?}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_until_succeeded(
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
                panic!("retried task reached the wrong terminal state: {task:?}")
            }
            TaskStatus::Queued
            | TaskStatus::Running
            | TaskStatus::Waiting
            | TaskStatus::Paused
            | TaskStatus::Cancelling => {}
        }
        assert!(
            Instant::now() < deadline,
            "retried task did not succeed: {task:?}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_retired_pre_dispatch_attempt(
    home: &Path,
    run_id: &str,
    error_class: &str,
) -> String {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let candidate = open_database(home)
            .query_row(
                "SELECT attempt_id FROM model_attempt \
                 WHERE run_id = ?1 AND state = 'interrupted' \
                   AND dispatched_at_ms IS NULL \
                   AND error_class = ?2 \
                 ORDER BY ordinal LIMIT 1",
                [run_id, error_class],
                |row| row.get::<_, String>(0),
            )
            .ok();
        if let Some(attempt_id) = candidate {
            return attempt_id;
        }
        assert!(
            Instant::now() < deadline,
            "prepared provider attempt did not retire before unsafe dispatch: {:?}",
            open_database(home)
                .prepare(
                    "SELECT state, dispatched_at_ms, deadline_at_ms - prepared_at_ms, \
                            deadline_at_ms - COALESCE(dispatched_at_ms, completed_at_ms), \
                            error_class \
                     FROM model_attempt WHERE run_id = ?1 ORDER BY ordinal"
                )
                .and_then(|mut statement| {
                    statement
                        .query_map([run_id], |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, Option<i64>>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, Option<i64>>(3)?,
                                row.get::<_, Option<String>>(4)?,
                            ))
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap_or_default()
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

async fn post_expect_error(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
    body: &impl serde::Serialize,
    expected: StatusCode,
) -> ApiErrorResponse {
    let response = client
        .post(format!("{}{path}", connection.base_url))
        .bearer_auth(&connection.bearer_token)
        .json(body)
        .send()
        .await
        .expect("authorized conflicting POST should reach mealyd");
    assert_eq!(response.status(), expected);
    response
        .json()
        .await
        .expect("error response should be valid JSON")
}

fn open_database(home: &Path) -> Connection {
    let connection =
        Connection::open(home.join("mealy.sqlite3")).expect("durable database should open");
    connection
        .busy_timeout(Duration::from_secs(2))
        .expect("SQLite busy timeout should be configured");
    connection
}

fn assert_no_execution_residue(home: &Path, run_id: &str) {
    let (active_reservations, final_messages, reserved_usage): (i64, i64, i64) =
        open_database(home)
            .query_row(
                "SELECT \
                    (SELECT COUNT(*) FROM budget_reservation br \
                     JOIN model_attempt ma ON ma.attempt_id = br.attempt_id \
                     WHERE ma.run_id = ?1 AND br.state = 'active'), \
                    (SELECT COUNT(*) FROM message \
                     WHERE run_id = ?1 AND role = 'assistant'), \
                    (SELECT COALESCE(SUM(\
                        reserved_model_calls + reserved_tool_calls + reserved_input_tokens + \
                        reserved_output_tokens + reserved_cost_microunits + reserved_output_bytes\
                     ), 0) FROM run_budget_usage WHERE run_id = ?1)",
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("cancellation residue should be queryable");
    assert_eq!(active_reservations, 0);
    assert_eq!(final_messages, 0);
    assert_eq!(reserved_usage, 0);
}

fn assert_cancellation_timeline(
    events: &[TimelineEvent],
    ids: &WorkIds,
    receipt: &TaskCancellationReceipt,
) {
    assert_eq!(
        events
            .iter()
            .filter(|event| event.event_type == "task.cancellation_requested")
            .count(),
        1,
        "an exact duplicate must not append another cancellation fact"
    );
    let requested = events
        .iter()
        .find(|event| event.event_type == "task.cancellation_requested")
        .expect("timeline should expose the cancellation command");
    assert_eq!(requested.event_id, receipt.event_id);
    assert_eq!(requested.cursor, receipt.cursor);
    assert_eq!(requested.aggregate_kind, "task");
    assert_eq!(requested.aggregate_id, ids.task_id);
    assert_eq!(
        requested.payload["run_id"].as_str(),
        Some(ids.run_id.as_str())
    );

    let expected = [
        ("run", ids.run_id.as_str(), "run.cancelled"),
        ("task", ids.task_id.as_str(), "task.cancelled"),
        ("turn", ids.turn_id.as_str(), "turn.cancelled"),
        ("session", "", "turn.cancelled"),
    ];
    let mut prior = receipt.cursor;
    for (kind, aggregate_id, event_type) in expected {
        let event = events
            .iter()
            .find(|event| {
                event.aggregate_kind == kind
                    && (aggregate_id.is_empty() || event.aggregate_id == aggregate_id)
                    && event.event_type == event_type
            })
            .unwrap_or_else(|| panic!("missing {kind} cancellation boundary"));
        assert!(
            event.cursor > prior,
            "cancellation boundaries must be ordered"
        );
        prior = event.cursor;
    }
    assert_eq!(
        events
            .iter()
            .filter(|event| event.event_type == "message.assistant.final")
            .count(),
        0
    );
}

fn assert_durable_boundary(home: &Path, session_id: &str, ids: &WorkIds) {
    let (task_status, run_status, turn_status, active_turn): (
        String,
        String,
        String,
        Option<String>,
    ) = open_database(home)
        .query_row(
            "SELECT task.status, run.status, turn.status, session.active_turn_id \
             FROM run \
             JOIN task ON task.id = run.task_id \
             JOIN turn ON turn.run_id = run.id AND turn.task_id = task.id \
             JOIN session ON session.id = turn.session_id \
             WHERE run.id = ?1 AND session.id = ?2",
            [ids.run_id.as_str(), session_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("durable cancellation boundary should be queryable");
    assert_eq!(task_status, "cancelled");
    assert_eq!(run_status, "cancelled");
    assert_eq!(turn_status, "cancelled");
    assert_eq!(active_turn, None);
}

async fn wait_until_outbox_delivered(home: &Path, ids: &WorkIds) {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let result = open_database(home).query_row(
            "SELECT \
                COALESCE(SUM(CASE WHEN state IN ('pending', 'delivering') THEN 1 ELSE 0 END), 0), \
                COALESCE(SUM(CASE WHEN state = 'delivered' THEN 1 ELSE 0 END), 0), \
                COALESCE(SUM(CASE WHEN state = 'failed' THEN 1 ELSE 0 END), 0), \
                COALESCE(SUM(CASE WHEN topic = 'session.turn_completed' \
                    AND state = 'delivered' \
                    AND json_extract(payload_json, '$.run_id') = ?1 \
                    AND json_extract(payload_json, '$.status') = 'cancelled' \
                    THEN 1 ELSE 0 END), 0) \
             FROM outbox",
            [ids.run_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        );
        if let Ok((0, delivered, 0, 1)) = result
            && delivered >= 2
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "cancelled turn completion was not delivered through the durable outbox"
        );
        sleep(Duration::from_millis(20)).await;
    }
}
