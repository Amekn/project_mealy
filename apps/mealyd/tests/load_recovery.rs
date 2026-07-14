//! Public-process burst/restart proof for concurrent durable personal-agent work.

use mealy_protocol::{
    API_VERSION, AdminMetricsResponse, AdminStatusResponse, CreateSessionRequest,
    CreateSessionResponse, DeliveryMode, DrainDaemonRequest, DrainDaemonResponse,
    InputAdmissionResponse, LocalConnectionInfo, ReadinessResponse, SubmitInputRequest,
    TaskReplayResponse, TaskResponse, TaskStatus, TimelinePageResponse,
};
use reqwest::{Client, StatusCode};
use serde_json::json;
use std::{
    fs,
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    time::Duration,
};
use tempfile::TempDir;
use tokio::time::{Instant, sleep};

const SESSION_COUNT: usize = 24;
const READY_TIMEOUT: Duration = Duration::from_secs(15);
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);

struct Daemon {
    child: Child,
}

impl Daemon {
    fn spawn(home: &Path, provider_delay_ms: u64) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_mealyd"))
            .arg("--home")
            .arg(home)
            .arg("--promotion-delay-ms")
            .arg("0")
            .arg("--promotion-interval-ms")
            .arg("5")
            .arg("--agent-delay-ms")
            .arg("0")
            .arg("--fake-provider-delay-ms")
            .arg(provider_delay_ms.to_string())
            .arg("--outbox-delay-ms")
            .arg("0")
            .env("RUST_LOG", "warn")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("mealyd process should start");
        Self { child }
    }

    fn hard_kill(&mut self) {
        self.child.kill().expect("kill mealyd");
        assert!(!self.child.wait().expect("reap mealyd").success());
    }

    async fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().expect("poll mealyd") {
                return status;
            }
            assert!(Instant::now() < deadline, "mealyd did not terminate");
            sleep(Duration::from_millis(20)).await;
        }
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

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[allow(clippy::too_many_lines)]
async fn burst_of_tasks_recovers_after_hard_kill_without_loss_or_redispatch_on_replay() {
    let home = TempDir::new().expect("temporary daemon home");
    write_concurrent_fixture_config(home.path());
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("HTTP client");
    let mut daemon = Daemon::spawn(home.path(), 3_000);
    let connection = wait_until_ready(&client, home.path()).await;

    let mut admitted = Vec::with_capacity(SESSION_COUNT);
    for sequence in 0..SESSION_COUNT {
        let session: CreateSessionResponse = authorized_post(
            &client,
            &connection,
            "/v1/sessions",
            &CreateSessionRequest {
                api_version: API_VERSION.to_owned(),
            },
        )
        .await;
        let request = SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: format!("load-recovery-{sequence}"),
            delivery_mode: DeliveryMode::Queue,
            content: format!("Read the deterministic fixture for recovery task {sequence}."),
        };
        let admission: InputAdmissionResponse = authorized_post(
            &client,
            &connection,
            &format!("/v1/sessions/{}/inputs", session.session_id),
            &request,
        )
        .await;
        if sequence < 4 {
            let duplicate: InputAdmissionResponse = authorized_post(
                &client,
                &connection,
                &format!("/v1/sessions/{}/inputs", session.session_id),
                &request,
            )
            .await;
            assert!(duplicate.duplicate);
            assert_eq!(duplicate.inbox_entry_id, admission.inbox_entry_id);
        }
        admitted.push((session.session_id, admission.cursor.0));
    }

    let mut task_ids = Vec::with_capacity(SESSION_COUNT);
    for (session_id, cursor) in &admitted {
        task_ids.push(wait_for_task_id(&client, &connection, session_id, *cursor).await);
    }
    wait_for_active_leases(&client, &connection, 8).await;
    daemon.hard_kill();
    fs::remove_file(home.path().join("connection.json")).expect("remove stale descriptor");
    assert_eq!(sqlite_integrity(home.path()), "ok");

    let mut restarted = Daemon::spawn(home.path(), 0);
    let recovered_connection = wait_until_ready(&client, home.path()).await;
    let completion_deadline = Instant::now() + RECOVERY_TIMEOUT;
    let mut recovered_provider_attempts = 0_usize;
    for task_id in &task_ids {
        let task =
            wait_until_terminal(&client, &recovered_connection, task_id, completion_deadline).await;
        let failure_diagnostics = (task.status != TaskStatus::Succeeded)
            .then(|| load_failure_diagnostics(home.path(), task_id, &task.run_id));
        assert_eq!(
            task.status,
            TaskStatus::Succeeded,
            "recovered task: {task:?}; diagnostics: {failure_diagnostics:?}"
        );
        assert!(matches!(task.model_attempts, 2 | 3), "task: {task:?}");
        assert_eq!(task.tool_calls, 1);
        if task.model_attempts == 3 {
            recovered_provider_attempts += 1;
        }
        let replay: TaskReplayResponse = authorized_get(
            &client,
            &recovered_connection,
            &format!("/v1/tasks/{task_id}/replay"),
        )
        .await;
        assert!(replay.evidence_complete, "recovered replay: {replay:?}");
        assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    }
    assert!(
        recovered_provider_attempts >= 8,
        "expected the killed concurrent provider attempts to be recovered"
    );

    let status: AdminStatusResponse =
        authorized_get(&client, &recovered_connection, "/v1/admin/status").await;
    assert_eq!(status.pending_inputs, 0);
    assert_eq!(status.nonterminal_runs, 0);
    assert_eq!(status.active_leases, 0);
    assert_eq!(status.pending_approvals, 0);
    assert_eq!(status.unknown_effects, 0);
    assert_eq!(status.failed_outbox, 0);
    let metrics: AdminMetricsResponse =
        authorized_get(&client, &recovered_connection, "/v1/admin/metrics").await;
    for gauge in [
        "pending_inputs",
        "nonterminal_runs",
        "active_leases",
        "unknown_effects",
    ] {
        assert_eq!(metrics.gauges.get(gauge), Some(&0), "gauge {gauge}");
    }
    assert_eq!(sqlite_integrity(home.path()), "ok");

    let _: DrainDaemonResponse = authorized_post(
        &client,
        &recovered_connection,
        "/v1/admin/drain",
        &DrainDaemonRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    assert!(restarted.wait().await.success());
}

fn write_concurrent_fixture_config(home: &Path) {
    fs::create_dir_all(home).expect("create daemon home");
    let config = json!({
        "formatVersion": 1,
        "drainDeadlineMs": 10_000,
        "maximumPendingInputsPerSession": 64,
        "agentLoopLimits": {
            "maximumModelCalls": 8,
            "maximumToolCalls": 2,
            "maximumRetries": 3,
            "maximumDelegatedRuns": 2,
            "maximumInputTokens": 32_768,
            "maximumOutputTokens": 4_096,
            "maximumCostMicrounits": 1_000_000,
            "maximumOutputBytes": 4_194_304,
            "maximumWallTimeMs": 60_000,
            "providerTimeoutMs": 10_000,
            "toolTimeoutMs": 5_000,
            "inlineOutputBytes": 1_024,
            "maximumArtifactBytes": 4_194_304
        },
        "concurrencyLimits": {
            "daemonAgentRuns": 8,
            "principalAgentRuns": 8,
            "sessionAgentRuns": 1,
            "providerRequests": 8,
            "providerRequestsPerMinute": 600,
            "extensionInvocations": 8,
            "agentRoleRuns": 8,
            "resourceClassInvocations": 8
        },
        "provider": {"kind": "builtin_fixture"},
        "artifactGcMinimumAgeHours": 24,
        "forensicBackupOnOpenFailure": true,
        "retentionPolicy": {
            "dataClassMinimumAgeHours": {
                "canonical_audit": 87_600,
                "temporary_artifact": 24,
                "unreferenced_artifact": 24
            },
            "sensitivityMinimumAgeHours": {
                "internal": 720,
                "private": 8_760,
                "public": 24,
                "restricted": 87_600
            },
            "protectedPrincipalIds": [],
            "protectedTaskIds": [],
            "protectedChannelBindingIds": [],
            "legalHoldLabels": []
        }
    });
    fs::write(
        home.join("config.json"),
        serde_json::to_vec_pretty(&config).expect("encode config"),
    )
    .expect("write config");
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
            && response
                .json::<ReadinessResponse>()
                .await
                .is_ok_and(|readiness| readiness.ready)
        {
            return connection;
        }
        assert!(Instant::now() < deadline, "mealyd did not become ready");
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_task_id(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
    after: u64,
) -> String {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        let page: TimelinePageResponse = authorized_get(
            client,
            connection,
            &format!("/v1/sessions/{session_id}/timeline?after={after}&limit=100"),
        )
        .await;
        if let Some(task) = page
            .events
            .iter()
            .find(|event| event.event_type == "task.created")
        {
            return task.aggregate_id.clone();
        }
        assert!(Instant::now() < deadline, "input was not promoted");
        sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_active_leases(client: &Client, connection: &LocalConnectionInfo, expected: u64) {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        let status: AdminStatusResponse =
            authorized_get(client, connection, "/v1/admin/status").await;
        if status.active_leases >= expected {
            return;
        }
        assert!(Instant::now() < deadline, "concurrent leases did not start");
        sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_until_terminal(
    client: &Client,
    connection: &LocalConnectionInfo,
    task_id: &str,
    deadline: Instant,
) -> TaskResponse {
    loop {
        let task: TaskResponse =
            authorized_get(client, connection, &format!("/v1/tasks/{task_id}")).await;
        if matches!(
            task.status,
            TaskStatus::Succeeded | TaskStatus::Failed | TaskStatus::Cancelled
        ) {
            return task;
        }
        assert!(Instant::now() < deadline, "task did not recover: {task:?}");
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
        .expect("authorized GET");
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.expect("valid response JSON")
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
        .expect("authorized POST");
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.expect("valid response JSON")
}

fn sqlite_integrity(home: &Path) -> String {
    rusqlite::Connection::open(home.join("mealy.sqlite3"))
        .expect("open database")
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("integrity check")
}

fn load_failure_diagnostics(home: &Path, task_id: &str, run_id: &str) -> String {
    let connection =
        rusqlite::Connection::open(home.join("mealy.sqlite3")).expect("diagnostic database");
    let mut events = connection
        .prepare(
            "SELECT aggregate_kind, event_type, payload_json FROM journal_event \
             WHERE aggregate_id IN (?1, ?2) ORDER BY occurred_at_ms, event_id",
        )
        .expect("diagnostic event query");
    let events = events
        .query_map(rusqlite::params![task_id, run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .expect("diagnostic events")
        .collect::<Result<Vec<_>, _>>()
        .expect("diagnostic event rows");
    let mut attempts = connection
        .prepare(
            "SELECT state, error_class, error_message, prepared_at_ms, dispatched_at_ms, \
                    completed_at_ms FROM model_attempt WHERE run_id = ?1 ORDER BY ordinal",
        )
        .expect("diagnostic attempt query");
    let attempts = attempts
        .query_map([run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<i64>>(5)?,
            ))
        })
        .expect("diagnostic attempts")
        .collect::<Result<Vec<_>, _>>()
        .expect("diagnostic attempt rows");
    format!("events={events:?}; attempts={attempts:?}")
}
