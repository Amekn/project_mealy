//! Public-process proofs for safe mode, operational maintenance, drain, and forensic recovery.

#[cfg(target_os = "linux")]
use mealy_protocol::SandboxProfileStatusResponse;
use mealy_protocol::{
    API_VERSION, AdminStatusResponse, BackupResponse, BackupVerificationResponse,
    ControlTaskRequest, CreateBackupRequest, CreateExportRequest, CreateScheduleRequest,
    CreateSessionRequest, CreateSessionResponse, DeliveryMode, DoctorResponse, DrainDaemonRequest,
    DrainDaemonResponse, ExportKindRequest, ExportResponse, InputAdmissionResponse,
    LocalConnectionInfo, MissedRunPolicyCommand, ReadinessResponse, ScheduleLifecycleRequest,
    ScheduleOverlapPolicyCommand, ScheduleResponse, ScheduleRunsResponse, ScheduleStatusResponse,
    SchedulesResponse, SubmitInputRequest, TaskControlReceipt, TaskResponse, TaskStatus,
};
use reqwest::{Client, Response, StatusCode};
use std::{
    fs,
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    time::Duration,
};
use tempfile::TempDir;
use tokio::time::{Instant, sleep};

const READY_TIMEOUT: Duration = Duration::from_secs(15);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(8);

struct Daemon {
    child: Child,
}

impl Daemon {
    fn spawn(home: &Path, arguments: &[&str]) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_mealyd"))
            .arg("--home")
            .arg(home)
            .args(arguments)
            .env("RUST_LOG", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("mealyd process should start");
        Self { child }
    }

    #[cfg(target_os = "linux")]
    fn spawn_without_ambient_path(home: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_mealyd"))
            .arg("--home")
            .arg(home)
            .env_clear()
            .env("PATH", "/nonexistent")
            .env("RUST_LOG", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("mealyd process should start without ambient PATH");
        Self { child }
    }

    async fn wait(&mut self) -> ExitStatus {
        wait_for_process(&mut self.child).await
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

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dynamic_runtime_discovery_does_not_resolve_helpers_from_ambient_path() {
    let home = TempDir::new().expect("temporary daemon home");
    let client = http_client();
    let mut daemon = Daemon::spawn_without_ambient_path(home.path());
    let connection = wait_until_ready(&client, home.path()).await;

    let doctor: DoctorResponse = authorized_get(&client, &connection, "/v1/admin/doctor").await;
    assert!(doctor.control_plane_ready);
    assert!(doctor.sandbox_available);
    let workspace_write = doctor
        .sandbox_profiles
        .iter()
        .find(|profile| profile.profile == "workspace_write")
        .expect("workspace-write profile");
    assert_eq!(
        workspace_write.status,
        SandboxProfileStatusResponse::Enforceable
    );

    let _: DrainDaemonResponse = authorized_post(
        &client,
        &connection,
        "/v1/admin/drain",
        &DrainDaemonRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    assert_eq!(daemon.wait().await.code(), Some(0));
    assert_eq!(latest_daemon_status(home.path()), "clean");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn safe_mode_supports_diagnostics_backup_export_and_clean_drain() {
    let home = TempDir::new().expect("temporary daemon home");
    let client = http_client();
    let mut daemon = Daemon::spawn(
        home.path(),
        &[
            "--safe-mode",
            "--drain-deadline-ms",
            "2000",
            "--promotion-delay-ms",
            "60000",
            "--agent-delay-ms",
            "60000",
        ],
    );
    let connection = wait_until_ready(&client, home.path()).await;

    let status: AdminStatusResponse =
        authorized_get(&client, &connection, "/v1/admin/status").await;
    assert!(status.safe_mode);
    assert!(status.admission_open);
    assert_eq!(status.schema_version, 15);
    assert_eq!(status.provider_health, "healthy");
    let doctor: DoctorResponse = authorized_get(&client, &connection, "/v1/admin/doctor").await;
    assert!(doctor.control_plane_ready);
    assert_eq!(doctor.sandbox_profiles.len(), 5);
    assert!(doctor.checks["provider_routing"].contains("excluded the lower-trust provider"));

    let rejected = authorized_post_response(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);

    let backup: BackupResponse = authorized_post(
        &client,
        &connection,
        "/v1/admin/backups",
        &CreateBackupRequest {
            api_version: API_VERSION.to_owned(),
            name: "safe-mode-backup".to_owned(),
            include_secrets: true,
            secret_passphrase: Some("phase seven encrypted backup passphrase".to_owned()),
        },
    )
    .await;
    assert_eq!(backup.schema_version, 15);
    assert!(backup.secrets_included);
    assert!(Path::new(&backup.path).join("manifest.json").is_file());

    let verification: BackupVerificationResponse = authorized_post(
        &client,
        &connection,
        "/v1/admin/backup-verifications",
        &mealy_protocol::VerifyBackupRequest {
            api_version: API_VERSION.to_owned(),
            name: "safe-mode-backup".to_owned(),
            secret_passphrase: Some("phase seven encrypted backup passphrase".to_owned()),
        },
    )
    .await;
    assert_eq!(verification.manifest_digest, backup.manifest_digest);
    assert_eq!(verification.schema_version, 15);
    assert!(verification.identity_verified);

    let export: ExportResponse = authorized_post(
        &client,
        &connection,
        "/v1/admin/exports",
        &CreateExportRequest {
            api_version: API_VERSION.to_owned(),
            name: "safe-mode-audit".to_owned(),
            kind: ExportKindRequest::Audit,
            selector: None,
        },
    )
    .await;
    assert!(Path::new(&export.path).is_file());
    assert_eq!(export.kind, ExportKindRequest::Audit);

    let complete: ExportResponse = authorized_post(
        &client,
        &connection,
        "/v1/admin/exports",
        &CreateExportRequest {
            api_version: API_VERSION.to_owned(),
            name: "safe-mode-complete".to_owned(),
            kind: ExportKindRequest::Complete,
            selector: None,
        },
    )
    .await;
    assert!(Path::new(&complete.path).join("manifest.json").is_file());
    assert!(Path::new(&complete.path).join("state.sqlite3").is_file());
    assert_eq!(complete.kind, ExportKindRequest::Complete);

    let drain: DrainDaemonResponse = authorized_post(
        &client,
        &connection,
        "/v1/admin/drain",
        &DrainDaemonRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    assert!(drain.newly_requested);
    assert_eq!(daemon.wait().await.code(), Some(0));
    assert!(!home.path().join("connection.json").exists());
    assert_eq!(latest_daemon_status(home.path()), "clean");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn corrupt_database_open_preserves_original_and_sidecars_before_failure() {
    let home = TempDir::new().expect("temporary daemon home");
    let client = http_client();
    let mut initial = Daemon::spawn(home.path(), &["--safe-mode"]);
    let connection = wait_until_ready(&client, home.path()).await;
    let _: DrainDaemonResponse = authorized_post(
        &client,
        &connection,
        "/v1/admin/drain",
        &DrainDaemonRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    assert!(initial.wait().await.success());

    let database = home.path().join("mealy.sqlite3");
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{suffix}", database.display()));
    }
    let corrupt = b"REC-014 original corrupt database evidence";
    fs::write(&database, corrupt).expect("replace database with corrupt fixture");
    let mut restart = Command::new(env!("CARGO_BIN_EXE_mealyd"))
        .arg("--home")
        .arg(home.path())
        .arg("--safe-mode")
        .env("RUST_LOG", "error")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("corrupt restart should launch far enough to inspect storage");
    assert!(!wait_for_process(&mut restart).await.success());
    assert_eq!(fs::read(&database).expect("original remains"), corrupt);

    let forensic_root = home.path().join("forensics");
    let directories = fs::read_dir(&forensic_root)
        .expect("forensic root")
        .map(|entry| entry.expect("forensic entry").path())
        .collect::<Vec<_>>();
    assert_eq!(directories.len(), 1);
    assert_eq!(
        fs::read(directories[0].join("mealy.sqlite3")).expect("preserved database"),
        corrupt
    );
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(directories[0].join("manifest.json")).expect("forensic manifest"),
    )
    .expect("valid forensic manifest");
    assert_eq!(manifest["formatVersion"], 1);
    assert!(
        manifest["openFailure"]
            .as_str()
            .is_some_and(|text| !text.is_empty())
    );
    assert!(!home.path().join("connection.json").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn recurring_schedule_api_is_revision_fenced_auditable_and_operationally_visible() {
    let home = TempDir::new().expect("temporary daemon home");
    let client = http_client();
    let mut daemon = Daemon::spawn(
        home.path(),
        &["--promotion-delay-ms", "60000", "--agent-delay-ms", "60000"],
    );
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

    let rejected = authorized_post_response(
        &client,
        &connection,
        "/v1/schedules",
        &CreateScheduleRequest {
            api_version: API_VERSION.to_owned(),
            schedule_id: mealy_domain::ScheduleId::new().to_string(),
            session_id: session.session_id.clone(),
            name: "unapproved action".to_owned(),
            prompt: "/run perform an action".to_owned(),
            cron_expression: "0 0 1 1 *".to_owned(),
            timezone: "Pacific/Auckland".to_owned(),
            missed_run_policy: MissedRunPolicyCommand::Latest,
            overlap_policy: ScheduleOverlapPolicyCommand::SkipIfRunning,
            misfire_grace_ms: 60_000,
            allow_approval_required_action: false,
        },
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);

    let create_request = CreateScheduleRequest {
        api_version: API_VERSION.to_owned(),
        schedule_id: mealy_domain::ScheduleId::new().to_string(),
        session_id: session.session_id,
        name: "annual recovery review".to_owned(),
        prompt: "Review durable recovery evidence.".to_owned(),
        cron_expression: "0 0 1 1 *".to_owned(),
        timezone: "Pacific/Auckland".to_owned(),
        missed_run_policy: MissedRunPolicyCommand::Latest,
        overlap_policy: ScheduleOverlapPolicyCommand::SkipIfRunning,
        misfire_grace_ms: 60_000,
        allow_approval_required_action: false,
    };
    let created: ScheduleResponse =
        authorized_post(&client, &connection, "/v1/schedules", &create_request).await;
    assert_eq!(created.status, ScheduleStatusResponse::Active);
    assert_eq!(created.revision, 0);
    assert!(created.next_due_at_ms.is_some());
    let duplicate: ScheduleResponse =
        authorized_post(&client, &connection, "/v1/schedules", &create_request).await;
    assert_eq!(duplicate, created);
    let mut conflicting_request = create_request.clone();
    conflicting_request.name = "conflicting schedule identity reuse".to_owned();
    let conflict =
        authorized_post_response(&client, &connection, "/v1/schedules", &conflicting_request).await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);

    let listed: SchedulesResponse = authorized_get(&client, &connection, "/v1/schedules").await;
    assert_eq!(listed.schedules, vec![created.clone()]);
    let status: AdminStatusResponse =
        authorized_get(&client, &connection, "/v1/admin/status").await;
    assert_eq!(status.active_schedules, 1);
    assert_eq!(status.paused_schedules, 0);
    assert_eq!(status.claimed_schedule_runs, 0);

    let paused: ScheduleResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/schedules/{}/pause", created.schedule_id),
        &ScheduleLifecycleRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: created.revision,
        },
    )
    .await;
    assert_eq!(paused.status, ScheduleStatusResponse::Paused);
    assert_eq!(paused.revision, 1);
    let stale = authorized_post_response(
        &client,
        &connection,
        &format!("/v1/schedules/{}/resume", created.schedule_id),
        &ScheduleLifecycleRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: created.revision,
        },
    )
    .await;
    assert_eq!(stale.status(), StatusCode::CONFLICT);

    let resumed: ScheduleResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/schedules/{}/resume", created.schedule_id),
        &ScheduleLifecycleRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: paused.revision,
        },
    )
    .await;
    assert_eq!(resumed.status, ScheduleStatusResponse::Active);
    assert_eq!(resumed.revision, 2);
    let cancelled: ScheduleResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/schedules/{}/cancel", created.schedule_id),
        &ScheduleLifecycleRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: resumed.revision,
        },
    )
    .await;
    assert_eq!(cancelled.status, ScheduleStatusResponse::Cancelled);
    assert_eq!(cancelled.revision, 3);
    assert!(cancelled.next_due_at_ms.is_none());
    let runs: ScheduleRunsResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/schedules/{}/runs?limit=10", created.schedule_id),
    )
    .await;
    assert!(runs.runs.is_empty());

    let _: DrainDaemonResponse = authorized_post(
        &client,
        &connection,
        "/v1/admin/drain",
        &DrainDaemonRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    assert!(daemon.wait().await.success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_drain_records_forced_termination_durably() {
    let home = TempDir::new().expect("temporary daemon home");
    let client = http_client();
    let mut daemon = Daemon::spawn(
        home.path(),
        &[
            "--drain-deadline-ms",
            "100",
            "--promotion-delay-ms",
            "0",
            "--promotion-interval-ms",
            "5",
            "--agent-delay-ms",
            "0",
            "--fake-provider-delay-ms",
            "5000",
            "--outbox-delay-ms",
            "60000",
        ],
    );
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
    let _: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase7-forced-drain".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "hold the provider boundary open".to_owned(),
        },
    )
    .await;
    wait_for_prepared_model_attempt(home.path()).await;
    let task_id = current_task_id(home.path());
    let running: TaskResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}")).await;
    assert_eq!(running.status, TaskStatus::Running);
    let paused: TaskControlReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/tasks/{task_id}/pause"),
        &ControlTaskRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: running.revision,
        },
    )
    .await;
    assert_eq!(paused.status, TaskStatus::Paused);
    let stale_pause = authorized_post_response(
        &client,
        &connection,
        &format!("/v1/tasks/{task_id}/pause"),
        &ControlTaskRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: running.revision,
        },
    )
    .await;
    assert_eq!(stale_pause.status(), StatusCode::CONFLICT);
    let resumed: TaskControlReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/tasks/{task_id}/resume"),
        &ControlTaskRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: paused.revision,
        },
    )
    .await;
    assert_eq!(resumed.status, TaskStatus::Queued);

    let _: DrainDaemonResponse = authorized_post(
        &client,
        &connection,
        "/v1/admin/drain",
        &DrainDaemonRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    assert_eq!(daemon.wait().await.code(), Some(2));
    assert_eq!(latest_daemon_status(home.path()), "forced");
    assert!(!home.path().join("forced-shutdown.json").exists());
    assert!(!home.path().join("connection.json").exists());
}

fn http_client() -> Client {
    Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("HTTP client")
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

async fn authorized_get<T: serde::de::DeserializeOwned>(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
) -> T {
    client
        .get(format!("{}{path}", connection.base_url))
        .bearer_auth(&connection.bearer_token)
        .send()
        .await
        .expect("authorized GET")
        .error_for_status()
        .expect("successful GET")
        .json()
        .await
        .expect("GET response JSON")
}

async fn authorized_post<T: serde::de::DeserializeOwned>(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
    body: &impl serde::Serialize,
) -> T {
    authorized_post_response(client, connection, path, body)
        .await
        .error_for_status()
        .expect("successful POST")
        .json()
        .await
        .expect("POST response JSON")
}

async fn authorized_post_response(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
    body: &impl serde::Serialize,
) -> Response {
    client
        .post(format!("{}{path}", connection.base_url))
        .bearer_auth(&connection.bearer_token)
        .json(body)
        .send()
        .await
        .expect("authorized POST")
}

async fn wait_for_process(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().expect("poll daemon") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not terminate in time"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_prepared_model_attempt(home: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let prepared = rusqlite::Connection::open(home.join("mealy.sqlite3"))
            .and_then(|connection| {
                connection.query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM model_attempt WHERE state IN ('prepared', 'dispatching')
                     )",
                    [],
                    |row| row.get::<_, bool>(0),
                )
            })
            .unwrap_or(false);
        if prepared {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "provider attempt was not prepared"
        );
        sleep(Duration::from_millis(10)).await;
    }
}

fn latest_daemon_status(home: &Path) -> String {
    rusqlite::Connection::open(home.join("mealy.sqlite3"))
        .expect("open daemon database")
        .query_row(
            "SELECT status FROM daemon_run_record ORDER BY started_at_ms DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("latest daemon status")
}

fn current_task_id(home: &Path) -> String {
    rusqlite::Connection::open(home.join("mealy.sqlite3"))
        .expect("open daemon database")
        .query_row(
            "SELECT id FROM task ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("current task ID")
}
