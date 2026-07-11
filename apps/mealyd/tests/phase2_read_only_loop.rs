//! Public-API process-boundary scenario for the Phase 2 read-only agent-loop exit gate.

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
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tempfile::TempDir;
use tokio::time::{Instant, sleep};

const READY_TIMEOUT: Duration = Duration::from_secs(10);
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(15);

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

#[derive(Debug)]
struct ArtifactEvidence {
    artifact_id: String,
    digest: String,
    size_bytes: u64,
    relative_path: PathBuf,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn public_api_completes_read_only_loop_and_replays_without_live_calls() {
    let home = TempDir::new().expect("temporary daemon home should be created");
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("HTTP client should build");

    let mut first_daemon = Daemon::spawn(home.path());
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
            idempotency_key: "phase-2-read-only-loop".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Read the Phase 2 fixture report and answer from its evidence.".to_owned(),
        },
    )
    .await;
    assert!(!admission.duplicate);

    let (task_id, run_id) = wait_for_task_and_run(
        &client,
        &first_connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let task = wait_until_task_succeeds(&client, &first_connection, &task_id).await;
    let (expected_final_response, expected_final_digest) =
        assert_successful_task(&task, &task_id, &run_id);
    let timeline = completed_timeline(&client, &first_connection, &session.session_id).await;

    let artifact = artifact_evidence(home.path(), &run_id);
    assert!(
        artifact.size_bytes > 1024,
        "fixture output should cross the configured inline boundary"
    );
    assert!(task.usage.used_output_bytes > artifact.size_bytes);
    assert!(expected_final_response.contains(&artifact.artifact_id));
    assert!(expected_final_response.contains(&artifact.digest));
    assert!(
        expected_final_response.contains(&format!("({} bytes)", artifact.size_bytes)),
        "final response should cite the recorded artifact size"
    );
    verify_artifact_file(home.path(), &artifact);
    assert_artifact_event(&timeline.events, &artifact);

    let counts_before_replay = durable_execution_counts(home.path(), &run_id);
    assert_eq!(counts_before_replay, (2, 1));

    first_daemon.hard_kill();
    drop(first_daemon);
    fs::remove_file(home.path().join("connection.json"))
        .expect("ephemeral endpoint descriptor can be recreated from durable identity");

    let _second_daemon = Daemon::spawn(home.path());
    let second_connection = wait_until_ready(&client, home.path()).await;
    let second_admission: InputAdmissionResponse = authorized_post(
        &client,
        &second_connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-2-second-turn".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Run a second turn in the same context epoch.".to_owned(),
        },
    )
    .await;
    let (second_task_id, _) = wait_for_task_and_run(
        &client,
        &second_connection,
        &session.session_id,
        second_admission.cursor.0,
    )
    .await;
    let second_task = wait_until_task_succeeds(&client, &second_connection, &second_task_id).await;
    assert_eq!(second_task.status, TaskStatus::Succeeded);
    let replay: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert_recorded_replay(
        &replay,
        &task_id,
        &run_id,
        &expected_final_response,
        &expected_final_digest,
    );
    assert_eq!(
        durable_execution_counts(home.path(), &run_id),
        counts_before_replay,
        "recorded replay must not create provider attempts or tool calls"
    );
    verify_artifact_file(home.path(), &artifact);

    let original_response_digest =
        replace_final_response_digest(home.path(), &run_id, &"0".repeat(64));
    let corrupt_database: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(
        !corrupt_database.evidence_complete,
        "recorded replay must fail closed when normalized result evidence is corrupt"
    );
    replace_final_response_digest(home.path(), &run_id, &original_response_digest);
    let restored: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(restored.evidence_complete);

    let original_used_model_calls = replace_used_model_calls(home.path(), &run_id, 0);
    let corrupt_budget: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(
        !corrupt_budget.evidence_complete,
        "recorded replay must reconcile structured usage with attempt evidence"
    );
    replace_used_model_calls(home.path(), &run_id, original_used_model_calls);

    let original_run_status = replace_run_status(home.path(), &run_id, "failed");
    let corrupt_terminal_graph: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(
        !corrupt_terminal_graph.evidence_complete,
        "recorded replay must reject a mismatched task/run terminal graph"
    );
    replace_run_status(home.path(), &run_id, &original_run_status);

    let original_model_completion = violate_final_model_deadline(home.path(), &run_id);
    let late_model: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(
        !late_model.evidence_complete,
        "recorded replay must recheck provider attempt deadlines"
    );
    restore_final_model_completion(home.path(), &run_id, original_model_completion);

    let original_tool_completion = violate_tool_timeout(home.path(), &run_id);
    let late_tool: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(
        !late_tool.evidence_complete,
        "recorded replay must recheck read-tool timeouts"
    );
    restore_tool_completion(home.path(), &run_id, original_tool_completion);

    let original_policy = replace_tool_policy(home.path(), &run_id, "forged.policy.v1");
    let forged_policy: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(
        !forged_policy.evidence_complete,
        "recorded replay must bind the tool authorization to its policy evidence"
    );
    replace_tool_policy(home.path(), &run_id, &original_policy);

    let (checkpoint_event_id, checkpoint_payload) = forge_checkpoint_payload(home.path(), &run_id);
    let forged_checkpoint: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(
        !forged_checkpoint.evidence_complete,
        "recorded replay must require the exact canonical checkpoint event payload"
    );
    restore_journal_payload(home.path(), &checkpoint_event_id, &checkpoint_payload);
    let fully_restored: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(fully_restored.evidence_complete);

    let (model_event_id, model_event_payload) = forge_model_completion_event(home.path(), &run_id);
    let forged_model_event: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(
        !forged_model_event.evidence_complete,
        "recorded replay must bind completed model state to its exact journal payload"
    );
    restore_journal_payload(home.path(), &model_event_id, &model_event_payload);

    let terminal_timeline = remove_terminal_timeline_entry(home.path(), &run_id);
    let missing_terminal_timeline: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(
        !missing_terminal_timeline.evidence_complete,
        "recorded replay must require every journal authority event in the global timeline"
    );
    restore_timeline_entry(home.path(), &terminal_timeline);

    for (earlier, later) in [
        ("context.epoch.created", "context.manifest.created"),
        ("model.attempt.prepared", "model.attempt.completed"),
        ("artifact.committed", "tool.call.succeeded"),
        ("message.assistant.final", "run.succeeded"),
    ] {
        swap_first_event_cursors(home.path(), earlier, later);
        let reordered: TaskReplayResponse = authorized_get(
            &client,
            &second_connection,
            &format!("/v1/tasks/{task_id}/replay"),
        )
        .await;
        assert!(
            !reordered.evidence_complete,
            "recorded replay must reject reordered {earlier} and {later} evidence"
        );
        swap_first_event_cursors(home.path(), later, earlier);
    }

    let original_dispatch = invert_final_model_dispatch_order(home.path(), &run_id);
    let inverted_dispatch: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(
        !inverted_dispatch.evidence_complete,
        "recorded replay must reject completion before recorded dispatch"
    );
    restore_final_model_dispatch(home.path(), &run_id, original_dispatch);

    let original_producer = replace_artifact_producer(home.path(), &artifact.artifact_id, "forged");
    let forged_producer: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(
        !forged_producer.evidence_complete,
        "recorded replay must bind artifacts to the trusted built-in producer"
    );
    replace_artifact_producer(home.path(), &artifact.artifact_id, &original_producer);

    let original_model_error = replace_final_model_error(home.path(), &run_id, Some("forged"));
    let forged_success_error: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(
        !forged_success_error.evidence_complete,
        "successful model evidence cannot also carry an error classification"
    );
    replace_final_model_error(home.path(), &run_id, original_model_error.as_deref());

    let original_tool_error = replace_successful_tool_error(home.path(), &run_id, Some("forged"));
    let forged_tool_success_error: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(
        !forged_tool_success_error.evidence_complete,
        "successful tool evidence cannot also carry an error classification"
    );
    replace_successful_tool_error(home.path(), &run_id, original_tool_error.as_deref());

    let original_descriptor = forge_tool_capability(home.path(), &run_id);
    let forged_capability: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(
        !forged_capability.evidence_complete,
        "recorded replay must bind the descriptor to its granted fixture capability"
    );
    restore_tool_descriptor(home.path(), &run_id, &original_descriptor);

    let restored_after_coauthority_checks: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(restored_after_coauthority_checks.evidence_complete);

    fs::remove_file(home.path().join("artifacts").join(&artifact.relative_path))
        .expect("test should be able to remove the recorded evidence blob");
    let incomplete: TaskReplayResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(
        !incomplete.evidence_complete,
        "recorded replay must fail closed when referenced artifact bytes are missing"
    );
    assert_eq!(incomplete.live_provider_calls, 0);
    assert_eq!(incomplete.live_tool_calls, 0);
    assert_eq!(
        durable_execution_counts(home.path(), &run_id),
        counts_before_replay,
        "evidence verification must remain side-effect free"
    );
}

fn assert_successful_task(task: &TaskResponse, task_id: &str, run_id: &str) -> (String, String) {
    assert_eq!(task.api_version, API_VERSION);
    assert_eq!(task.task_id, task_id);
    assert_eq!(task.run_id, run_id);
    assert_eq!(task.status, TaskStatus::Succeeded);
    assert_eq!(task.model_attempts, 2);
    assert_eq!(task.tool_calls, 1);
    assert_eq!(task.usage.used_model_calls, 2);
    assert_eq!(task.usage.reserved_model_calls, 0);
    assert_eq!(task.usage.used_tool_calls, 1);
    assert_eq!(task.usage.reserved_tool_calls, 0);
    assert_eq!(task.usage.used_retries, 0);
    assert!(task.usage.used_input_tokens > 0);
    assert!(task.usage.used_output_tokens > 0);
    assert_eq!(task.usage.used_cost_microunits, 2);
    assert_eq!(task.usage.reserved_input_tokens, 0);
    assert_eq!(task.usage.reserved_output_tokens, 0);
    assert_eq!(task.usage.reserved_cost_microunits, 0);
    assert_eq!(task.usage.reserved_output_bytes, 0);

    let response = task
        .final_response
        .clone()
        .expect("successful task should expose its committed final response");
    let digest = task
        .final_digest
        .clone()
        .expect("successful task should expose its committed final digest");
    assert_eq!(sha256_digest(response.as_bytes()), digest);
    assert!(response.starts_with("Fixture read completed with durable evidence:"));
    (response, digest)
}

async fn completed_timeline(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
) -> TimelinePageResponse {
    let timeline: TimelinePageResponse = authorized_get(
        client,
        connection,
        &format!("/v1/sessions/{session_id}/timeline?limit=1000"),
    )
    .await;
    assert!(!timeline.has_more);
    assert!(
        timeline
            .events
            .windows(2)
            .all(|pair| pair[0].cursor < pair[1].cursor),
        "durable event cursors must be strictly increasing"
    );
    assert_eq!(count_events(&timeline.events, "model.attempt.prepared"), 2);
    assert_eq!(
        count_events(&timeline.events, "model.attempt.dispatched"),
        2
    );
    assert_eq!(count_events(&timeline.events, "model.attempt.completed"), 2);
    assert_eq!(count_events(&timeline.events, "tool.call.prepared"), 1);
    assert_eq!(count_events(&timeline.events, "tool.call.started"), 1);
    assert_eq!(count_events(&timeline.events, "artifact.committed"), 1);
    assert_eq!(count_events(&timeline.events, "tool.call.succeeded"), 1);
    assert_eq!(count_events(&timeline.events, "message.assistant.final"), 1);
    assert_eq!(count_events(&timeline.events, "run.succeeded"), 1);
    assert_eq!(count_events(&timeline.events, "task.succeeded"), 1);
    assert_event_subsequence(
        &timeline.events,
        &[
            "model.attempt.prepared",
            "model.attempt.dispatched",
            "model.attempt.completed",
            "tool.call.prepared",
            "tool.call.started",
            "artifact.committed",
            "tool.call.succeeded",
            "model.attempt.prepared",
            "model.attempt.dispatched",
            "model.attempt.completed",
            "message.assistant.final",
            "run.succeeded",
            "task.succeeded",
        ],
    );
    timeline
}

fn assert_recorded_replay(
    replay: &TaskReplayResponse,
    task_id: &str,
    run_id: &str,
    expected_response: &str,
    expected_digest: &str,
) {
    assert_eq!(replay.api_version, API_VERSION);
    assert_eq!(replay.task_id, task_id);
    assert_eq!(replay.run_id, run_id);
    assert_eq!(replay.mode, "recorded_only");
    assert!(replay.evidence_complete);
    assert_eq!(replay.final_response.as_deref(), Some(expected_response));
    assert_eq!(replay.final_digest.as_deref(), Some(expected_digest));
    assert_eq!(replay.model_attempts, 2);
    assert_eq!(replay.tool_calls, 1);
    assert_eq!(replay.live_provider_calls, 0);
    assert_eq!(replay.live_tool_calls, 0);
    assert_eq!(
        replay
            .final_response
            .as_deref()
            .map(|content| sha256_digest(content.as_bytes())),
        replay.final_digest
    );
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
            assert_eq!(
                run.payload["task_id"].as_str(),
                Some(task.aggregate_id.as_str())
            );
            return (task.aggregate_id.clone(), run.aggregate_id.clone());
        }
        assert!(
            Instant::now() < deadline,
            "input was not promoted into a task and run"
        );
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
                panic!("agent task reached an unexpected terminal state: {task:?}")
            }
            TaskStatus::Queued
            | TaskStatus::Running
            | TaskStatus::Waiting
            | TaskStatus::Paused
            | TaskStatus::Cancelling => {}
        }
        assert!(
            Instant::now() < deadline,
            "Phase 2 agent task did not succeed: {task:?}"
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
        Connection::open(home.join("mealy.sqlite3")).expect("durable Phase 2 database should open");
    connection
        .busy_timeout(Duration::from_secs(2))
        .expect("SQLite busy timeout should be configured");
    connection
}

fn durable_execution_counts(home: &Path, run_id: &str) -> (i64, i64) {
    open_database(home)
        .query_row(
            "SELECT \
                (SELECT COUNT(*) FROM model_attempt WHERE run_id = ?1), \
                (SELECT COUNT(*) FROM tool_call WHERE run_id = ?1)",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("durable provider/tool evidence counts should be queryable")
}

fn replace_final_response_digest(home: &Path, run_id: &str, replacement: &str) -> String {
    let connection = open_database(home);
    let original = connection
        .query_row(
            "SELECT response_digest FROM model_attempt \
             WHERE run_id = ?1 AND state = 'completed' AND response_kind = 'final'",
            [run_id],
            |row| row.get::<_, String>(0),
        )
        .expect("final model response digest should be queryable");
    let changed = connection
        .execute(
            "UPDATE model_attempt SET response_digest = ?1 \
             WHERE run_id = ?2 AND state = 'completed' AND response_kind = 'final'",
            [replacement, run_id],
        )
        .expect("test should be able to corrupt or restore terminal response evidence");
    assert_eq!(changed, 1);
    original
}

fn replace_used_model_calls(home: &Path, run_id: &str, replacement: i64) -> i64 {
    let connection = open_database(home);
    let original = connection
        .query_row(
            "SELECT used_model_calls FROM run_budget_usage WHERE run_id = ?1",
            [run_id],
            |row| row.get::<_, i64>(0),
        )
        .expect("used model calls should be queryable");
    let changed = connection
        .execute(
            "UPDATE run_budget_usage SET used_model_calls = ?1 WHERE run_id = ?2",
            rusqlite::params![replacement, run_id],
        )
        .expect("test should be able to corrupt or restore usage evidence");
    assert_eq!(changed, 1);
    original
}

fn replace_run_status(home: &Path, run_id: &str, replacement: &str) -> String {
    let connection = open_database(home);
    let original = connection
        .query_row("SELECT status FROM run WHERE id = ?1", [run_id], |row| {
            row.get::<_, String>(0)
        })
        .expect("run status should be queryable");
    let changed = connection
        .execute(
            "UPDATE run SET status = ?1 WHERE id = ?2",
            [replacement, run_id],
        )
        .expect("test should be able to corrupt or restore terminal graph evidence");
    assert_eq!(changed, 1);
    original
}

fn violate_final_model_deadline(home: &Path, run_id: &str) -> i64 {
    let connection = open_database(home);
    let (original, deadline): (i64, i64) = connection
        .query_row(
            "SELECT completed_at_ms, deadline_at_ms FROM model_attempt \
             WHERE run_id = ?1 AND state = 'completed' AND response_kind = 'final'",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("final model deadline should be queryable");
    connection
        .execute(
            "UPDATE model_attempt SET completed_at_ms = ?1 \
             WHERE run_id = ?2 AND state = 'completed' AND response_kind = 'final'",
            rusqlite::params![deadline + 1, run_id],
        )
        .expect("test should be able to violate terminal model deadline evidence");
    original
}

fn restore_final_model_completion(home: &Path, run_id: &str, completed_at_ms: i64) {
    let changed = open_database(home)
        .execute(
            "UPDATE model_attempt SET completed_at_ms = ?1 \
             WHERE run_id = ?2 AND state = 'completed' AND response_kind = 'final'",
            rusqlite::params![completed_at_ms, run_id],
        )
        .expect("test should restore model completion evidence");
    assert_eq!(changed, 1);
}

fn violate_tool_timeout(home: &Path, run_id: &str) -> i64 {
    let connection = open_database(home);
    let (original, started_at, timeout_ms): (i64, i64, i64) = connection
        .query_row(
            "SELECT completed_at_ms, started_at_ms, timeout_ms FROM tool_call \
             WHERE run_id = ?1 AND state = 'succeeded'",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("successful tool timeout should be queryable");
    connection
        .execute(
            "UPDATE tool_call SET completed_at_ms = ?1 \
             WHERE run_id = ?2 AND state = 'succeeded'",
            rusqlite::params![started_at + timeout_ms + 1, run_id],
        )
        .expect("test should be able to violate tool timeout evidence");
    original
}

fn restore_tool_completion(home: &Path, run_id: &str, completed_at_ms: i64) {
    let changed = open_database(home)
        .execute(
            "UPDATE tool_call SET completed_at_ms = ?1 \
             WHERE run_id = ?2 AND state = 'succeeded'",
            rusqlite::params![completed_at_ms, run_id],
        )
        .expect("test should restore tool completion evidence");
    assert_eq!(changed, 1);
}

fn replace_tool_policy(home: &Path, run_id: &str, replacement: &str) -> String {
    let connection = open_database(home);
    let original = connection
        .query_row(
            "SELECT policy_version FROM tool_call WHERE run_id = ?1 AND state = 'succeeded'",
            [run_id],
            |row| row.get::<_, String>(0),
        )
        .expect("tool policy should be queryable");
    let changed = connection
        .execute(
            "UPDATE tool_call SET policy_version = ?1 \
             WHERE run_id = ?2 AND state = 'succeeded'",
            [replacement, run_id],
        )
        .expect("test should be able to corrupt or restore tool policy evidence");
    assert_eq!(changed, 1);
    original
}

fn forge_checkpoint_payload(home: &Path, run_id: &str) -> (String, String) {
    let connection = open_database(home);
    let (event_id, payload): (String, String) = connection
        .query_row(
            "SELECT event.event_id, event.payload_json FROM loop_checkpoint checkpoint \
             JOIN journal_event event ON event.event_id = checkpoint.event_id \
             WHERE checkpoint.run_id = ?1 ORDER BY checkpoint.sequence DESC LIMIT 1",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("checkpoint payload should be queryable");
    let forged = serde_json::from_str::<serde_json::Value>(&payload)
        .expect("stored checkpoint payload should be JSON");
    let mut forged = forged
        .as_object()
        .expect("checkpoint payload should be an object")
        .clone();
    forged.insert("unexpected".to_owned(), serde_json::json!("forged"));
    let changed = connection
        .execute(
            "UPDATE journal_event SET payload_json = ?1 WHERE event_id = ?2",
            [
                serde_json::Value::Object(forged).to_string(),
                event_id.clone(),
            ],
        )
        .expect("test should be able to corrupt checkpoint event evidence");
    assert_eq!(changed, 1);
    (event_id, payload)
}

fn forge_model_completion_event(home: &Path, run_id: &str) -> (String, String) {
    let connection = open_database(home);
    let evidence = connection
        .query_row(
            "SELECT event.event_id, event.payload_json FROM journal_event event \
             JOIN model_attempt attempt ON attempt.attempt_id = event.aggregate_id \
             WHERE attempt.run_id = ?1 AND attempt.response_kind = 'final' \
               AND event.aggregate_kind = 'model_attempt' \
               AND event.event_type = 'model.attempt.completed'",
            [run_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .expect("completed model event should be queryable");
    let changed = connection
        .execute(
            "UPDATE journal_event SET payload_json = '{}' WHERE event_id = ?1",
            [evidence.0.as_str()],
        )
        .expect("test should be able to corrupt completed model event evidence");
    assert_eq!(changed, 1);
    evidence
}

fn remove_terminal_timeline_entry(home: &Path, run_id: &str) -> (i64, String) {
    let connection = open_database(home);
    let entry = connection
        .query_row(
            "SELECT timeline.cursor, timeline.event_id FROM timeline_event timeline \
             JOIN journal_event event ON event.event_id = timeline.event_id \
             JOIN message ON message.id = event.aggregate_id \
             WHERE message.run_id = ?1 AND event.aggregate_kind = 'message' \
               AND event.event_type = 'message.assistant.final'",
            [run_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .expect("terminal message timeline entry should be queryable");
    let changed = connection
        .execute("DELETE FROM timeline_event WHERE event_id = ?1", [&entry.1])
        .expect("test should be able to remove a terminal timeline link");
    assert_eq!(changed, 1);
    entry
}

fn restore_timeline_entry(home: &Path, entry: &(i64, String)) {
    let changed = open_database(home)
        .execute(
            "INSERT INTO timeline_event(cursor, event_id) VALUES (?1, ?2)",
            rusqlite::params![entry.0, entry.1],
        )
        .expect("test should restore the exact terminal timeline link");
    assert_eq!(changed, 1);
}

fn swap_first_event_cursors(home: &Path, left_type: &str, right_type: &str) {
    let mut connection = open_database(home);
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .expect("timeline cursor swap transaction should begin");
    let select = |event_type: &str| {
        transaction
            .query_row(
                "SELECT timeline.event_id, timeline.cursor FROM timeline_event timeline \
                 JOIN journal_event event ON event.event_id = timeline.event_id \
                 WHERE event.event_type = ?1 ORDER BY timeline.cursor LIMIT 1",
                [event_type],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .expect("causal timeline event should be queryable")
    };
    let left = select(left_type);
    let right = select(right_type);
    let temporary: i64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(cursor), 0) + 1 FROM timeline_event",
            [],
            |row| row.get(0),
        )
        .expect("temporary timeline cursor should be queryable");
    for (cursor, event_id) in [
        (temporary, left.0.as_str()),
        (left.1, right.0.as_str()),
        (right.1, left.0.as_str()),
    ] {
        let changed = transaction
            .execute(
                "UPDATE timeline_event SET cursor = ?1 WHERE event_id = ?2",
                rusqlite::params![cursor, event_id],
            )
            .expect("test should be able to swap causal timeline cursors");
        assert_eq!(changed, 1);
    }
    transaction
        .commit()
        .expect("timeline cursor swap should commit atomically");
}

fn invert_final_model_dispatch_order(home: &Path, run_id: &str) -> i64 {
    let connection = open_database(home);
    let (dispatched_at_ms, completed_at_ms): (i64, i64) = connection
        .query_row(
            "SELECT dispatched_at_ms, completed_at_ms FROM model_attempt \
             WHERE run_id = ?1 AND state = 'completed' AND response_kind = 'final'",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("final model ordering evidence should be queryable");
    let changed = connection
        .execute(
            "UPDATE model_attempt SET dispatched_at_ms = ?1 \
             WHERE run_id = ?2 AND state = 'completed' AND response_kind = 'final'",
            rusqlite::params![completed_at_ms + 1, run_id],
        )
        .expect("test should be able to invert dispatch/completion ordering");
    assert_eq!(changed, 1);
    dispatched_at_ms
}

fn restore_final_model_dispatch(home: &Path, run_id: &str, dispatched_at_ms: i64) {
    let changed = open_database(home)
        .execute(
            "UPDATE model_attempt SET dispatched_at_ms = ?1 \
             WHERE run_id = ?2 AND state = 'completed' AND response_kind = 'final'",
            rusqlite::params![dispatched_at_ms, run_id],
        )
        .expect("test should restore final model dispatch evidence");
    assert_eq!(changed, 1);
}

fn replace_artifact_producer(home: &Path, artifact_id: &str, replacement: &str) -> String {
    let connection = open_database(home);
    let original = connection
        .query_row(
            "SELECT producer_kind FROM artifact WHERE id = ?1",
            [artifact_id],
            |row| row.get::<_, String>(0),
        )
        .expect("artifact producer should be queryable");
    let changed = connection
        .execute(
            "UPDATE artifact SET producer_kind = ?1 WHERE id = ?2",
            [replacement, artifact_id],
        )
        .expect("test should be able to corrupt or restore artifact producer evidence");
    assert_eq!(changed, 1);
    original
}

fn replace_final_model_error(
    home: &Path,
    run_id: &str,
    replacement: Option<&str>,
) -> Option<String> {
    let connection = open_database(home);
    let original = connection
        .query_row(
            "SELECT error_class FROM model_attempt \
             WHERE run_id = ?1 AND state = 'completed' AND response_kind = 'final'",
            [run_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .expect("successful model error classification should be queryable");
    let changed = connection
        .execute(
            "UPDATE model_attempt SET error_class = ?1 \
             WHERE run_id = ?2 AND state = 'completed' AND response_kind = 'final'",
            rusqlite::params![replacement, run_id],
        )
        .expect("test should be able to corrupt or restore successful model evidence");
    assert_eq!(changed, 1);
    original
}

fn replace_successful_tool_error(
    home: &Path,
    run_id: &str,
    replacement: Option<&str>,
) -> Option<String> {
    let connection = open_database(home);
    let original = connection
        .query_row(
            "SELECT error_class FROM tool_call WHERE run_id = ?1 AND state = 'succeeded'",
            [run_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .expect("successful tool error classification should be queryable");
    let changed = connection
        .execute(
            "UPDATE tool_call SET error_class = ?1 WHERE run_id = ?2 AND state = 'succeeded'",
            rusqlite::params![replacement, run_id],
        )
        .expect("test should be able to corrupt or restore successful tool evidence");
    assert_eq!(changed, 1);
    original
}

fn forge_tool_capability(home: &Path, run_id: &str) -> (String, String) {
    let connection = open_database(home);
    let (descriptor_json, descriptor_digest): (String, String) = connection
        .query_row(
            "SELECT descriptor_json, descriptor_digest FROM tool_call \
             WHERE run_id = ?1 AND state = 'succeeded'",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("successful tool descriptor should be queryable");
    let mut descriptor = serde_json::from_str::<serde_json::Value>(&descriptor_json)
        .expect("tool descriptor should be canonical JSON");
    descriptor["requiredCapability"] = serde_json::json!("forged:capability");
    let forged_json = descriptor.to_string();
    let forged_digest = sha256_digest(forged_json.as_bytes());
    let changed = connection
        .execute(
            "UPDATE tool_call SET descriptor_json = ?1, descriptor_digest = ?2 \
             WHERE run_id = ?3 AND state = 'succeeded'",
            rusqlite::params![forged_json, forged_digest, run_id],
        )
        .expect("test should be able to forge self-consistent descriptor evidence");
    assert_eq!(changed, 1);
    (descriptor_json, descriptor_digest)
}

fn restore_tool_descriptor(home: &Path, run_id: &str, descriptor: &(String, String)) {
    let changed = open_database(home)
        .execute(
            "UPDATE tool_call SET descriptor_json = ?1, descriptor_digest = ?2 \
             WHERE run_id = ?3 AND state = 'succeeded'",
            rusqlite::params![descriptor.0, descriptor.1, run_id],
        )
        .expect("test should restore the canonical tool descriptor evidence");
    assert_eq!(changed, 1);
}

fn restore_journal_payload(home: &Path, event_id: &str, payload: &str) {
    let changed = open_database(home)
        .execute(
            "UPDATE journal_event SET payload_json = ?1 WHERE event_id = ?2",
            [payload, event_id],
        )
        .expect("test should restore checkpoint event evidence");
    assert_eq!(changed, 1);
}

fn artifact_evidence(home: &Path, run_id: &str) -> ArtifactEvidence {
    let (artifact_id, output_digest, output_size, algorithm, blob_digest, blob_size, relative_path) =
        open_database(home)
            .query_row(
                "SELECT tc.output_artifact_id, tc.output_digest, tc.output_size_bytes, \
                        a.blob_algorithm, a.blob_digest, b.size_bytes, b.relative_path \
                 FROM tool_call tc \
                 JOIN artifact a ON a.id = tc.output_artifact_id \
                 JOIN artifact_blob b \
                   ON b.algorithm = a.blob_algorithm AND b.digest = a.blob_digest \
                 WHERE tc.run_id = ?1 AND tc.state = 'succeeded'",
                [run_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .expect("successful oversized read tool should reference one durable artifact");
    assert_eq!(algorithm, "sha256");
    assert_eq!(output_digest, blob_digest);
    assert_eq!(output_size, blob_size);
    assert_eq!(relative_path, format!("sha256/{blob_digest}"));
    ArtifactEvidence {
        artifact_id,
        digest: blob_digest,
        size_bytes: u64::try_from(blob_size).expect("artifact size should be nonnegative"),
        relative_path: PathBuf::from(relative_path),
    }
}

fn verify_artifact_file(home: &Path, artifact: &ArtifactEvidence) {
    let path = home.join("artifacts").join(&artifact.relative_path);
    let bytes = fs::read(&path).expect("committed artifact blob should exist");
    assert_eq!(
        u64::try_from(bytes.len()).expect("artifact length should fit u64"),
        artifact.size_bytes
    );
    assert_eq!(
        fs::metadata(&path)
            .expect("artifact metadata should be readable")
            .len(),
        artifact.size_bytes
    );
    assert_eq!(sha256_digest(&bytes), artifact.digest);
}

fn assert_artifact_event(events: &[TimelineEvent], artifact: &ArtifactEvidence) {
    let event = events
        .iter()
        .find(|event| event.event_type == "artifact.committed")
        .expect("timeline should contain the committed artifact event");
    assert_eq!(event.aggregate_id, artifact.artifact_id);
    assert_eq!(event.payload["algorithm"].as_str(), Some("sha256"));
    assert_eq!(
        event.payload["digest"].as_str(),
        Some(artifact.digest.as_str())
    );
    assert_eq!(
        event.payload["size_bytes"].as_u64(),
        Some(artifact.size_bytes)
    );
}

fn assert_event_subsequence(events: &[TimelineEvent], expected: &[&str]) {
    let mut next = 0;
    for event in events {
        if expected
            .get(next)
            .is_some_and(|name| *name == event.event_type)
        {
            next += 1;
        }
    }
    assert_eq!(
        next,
        expected.len(),
        "required ordered evidence was absent; observed {:?}",
        events
            .iter()
            .map(|event| event.event_type.as_str())
            .collect::<Vec<_>>()
    );
}

fn count_events(events: &[TimelineEvent], event_type: &str) -> usize {
    events
        .iter()
        .filter(|event| event.event_type == event_type)
        .count()
}
