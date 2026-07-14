//! Opt-in public-process soak, restart, replay, and resource-measurement harness.

use mealy_application::sha256_digest;
use mealy_protocol::{
    API_VERSION, AdminMetricsResponse, AdminStatusResponse, CreateSessionRequest,
    CreateSessionResponse, DeliveryMode, DrainDaemonRequest, DrainDaemonResponse,
    InputAdmissionResponse, LocalConnectionInfo, ReadinessResponse, SubmitInputRequest,
    TaskReplayResponse, TaskResponse, TaskStatus, TimelinePageResponse,
};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, SystemTime},
};
use tempfile::TempDir;
use tokio::time::{Instant, sleep};

const READY_TIMEOUT: Duration = Duration::from_secs(20);
const ROUND_TIMEOUT: Duration = Duration::from_secs(90);

struct SoakConfiguration {
    duration: Duration,
    sessions: usize,
    restart_every_rounds: u64,
    provider_delay_ms: u64,
    round_interval: Duration,
    report_path: Option<PathBuf>,
    revision: String,
    daemon_path: PathBuf,
    daemon_sha256: String,
    harness_mode: &'static str,
    home_path: Option<PathBuf>,
    home_filesystem: String,
}

impl SoakConfiguration {
    fn from_environment() -> Self {
        let (daemon_path, harness_mode) = env::var_os("MEALY_SOAK_MEALYD").map_or_else(
            || {
                (
                    PathBuf::from(env!("CARGO_BIN_EXE_mealyd")),
                    "cargo_integration_binary",
                )
            },
            |path| (PathBuf::from(path), "external_release_binary"),
        );
        let daemon_path = daemon_path
            .canonicalize()
            .expect("soak daemon path must resolve to a real file");
        let daemon_metadata = fs::metadata(&daemon_path).expect("read soak daemon metadata");
        assert!(daemon_metadata.is_file(), "soak daemon must be a real file");
        let daemon_bytes = fs::read(&daemon_path).expect("read soak daemon bytes");
        let version = Command::new(&daemon_path)
            .arg("--version")
            .output()
            .expect("query soak daemon version");
        assert!(version.status.success(), "soak daemon version query failed");
        assert_eq!(
            String::from_utf8(version.stdout)
                .expect("soak daemon version must be UTF-8")
                .trim(),
            format!("mealyd {}", env!("CARGO_PKG_VERSION")),
            "soak daemon version does not match the harness"
        );
        Self {
            duration: Duration::from_secs(environment_u64(
                "MEALY_SOAK_DURATION_SECONDS",
                300,
                1,
                7 * 24 * 60 * 60,
            )),
            sessions: usize::try_from(environment_u64("MEALY_SOAK_SESSIONS", 8, 1, 64))
                .expect("soak session count"),
            restart_every_rounds: environment_u64("MEALY_SOAK_RESTART_EVERY_ROUNDS", 10, 1, 10_000),
            provider_delay_ms: environment_u64("MEALY_SOAK_PROVIDER_DELAY_MS", 250, 100, 10_000),
            round_interval: Duration::from_millis(environment_u64(
                "MEALY_SOAK_ROUND_INTERVAL_MS",
                0,
                0,
                60_000,
            )),
            report_path: env::var_os("MEALY_SOAK_REPORT").map(PathBuf::from),
            revision: env::var("MEALY_SOAK_REVISION")
                .ok()
                .filter(|value| !value.is_empty() && value.len() <= 128)
                .unwrap_or_else(|| "unknown".to_owned()),
            daemon_path,
            daemon_sha256: sha256_digest(&daemon_bytes),
            harness_mode,
            home_path: env::var_os("MEALY_SOAK_HOME").map(PathBuf::from),
            home_filesystem: env::var("MEALY_SOAK_FILESYSTEM")
                .ok()
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= 64
                        && value.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                        })
                })
                .unwrap_or_else(|| "unreported".to_owned()),
        }
    }
}

enum SoakHome {
    Temporary(TempDir),
    Retained(PathBuf),
}

impl SoakHome {
    fn create(configuration: &SoakConfiguration) -> Self {
        if let Some(path) = &configuration.home_path {
            let path = path
                .canonicalize()
                .expect("retained soak home must already exist");
            let metadata = fs::symlink_metadata(&path).expect("read retained soak home metadata");
            assert!(metadata.is_dir(), "retained soak home must be a directory");
            assert!(
                fs::read_dir(&path)
                    .expect("read retained soak home")
                    .next()
                    .is_none(),
                "retained soak home must start empty"
            );
            Self::Retained(path)
        } else {
            Self::Temporary(TempDir::new().expect("temporary soak home"))
        }
    }

    fn path(&self) -> &Path {
        match self {
            Self::Temporary(home) => home.path(),
            Self::Retained(home) => home,
        }
    }

    const fn mode(&self) -> &'static str {
        match self {
            Self::Temporary(_) => "temporary",
            Self::Retained(_) => "retained",
        }
    }
}

struct Daemon {
    child: Child,
}

impl Daemon {
    fn spawn(daemon_path: &Path, home: &Path, provider_delay_ms: u64) -> Self {
        let child = Command::new(daemon_path)
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
            .env("RUST_LOG", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("mealyd process should start");
        Self { child }
    }

    fn process_id(&self) -> u32 {
        self.child.id()
    }

    fn hard_kill(&mut self) {
        self.child.kill().expect("kill mealyd");
        assert!(!self.child.wait().expect("reap mealyd").success());
    }

    async fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(15);
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
#[ignore = "manual bounded/long soak; run through scripts/run-soak.sh"]
#[allow(clippy::too_many_lines)]
async fn bounded_soak_restarts_and_reports_durable_measurements() {
    let configuration = SoakConfiguration::from_environment();
    let started_at_ms = unix_milliseconds(SystemTime::now());
    let started = Instant::now();
    let home = SoakHome::create(&configuration);
    write_soak_config(home.path(), configuration.sessions);
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("HTTP client");
    let mut daemon = Daemon::spawn(
        &configuration.daemon_path,
        home.path(),
        configuration.provider_delay_ms,
    );
    let mut connection = wait_until_ready(&client, home.path()).await;
    let mut peak_rss_kib = resident_set_kib(daemon.process_id()).unwrap_or(0);

    let mut session_ids = Vec::with_capacity(configuration.sessions);
    for _ in 0..configuration.sessions {
        let session: CreateSessionResponse = authorized_post(
            &client,
            &connection,
            "/v1/sessions",
            &CreateSessionRequest {
                api_version: API_VERSION.to_owned(),
            },
        )
        .await;
        session_ids.push(session.session_id);
    }

    let mut round = 0_u64;
    let mut completed_turns = 0_u64;
    let mut hard_restarts = 0_u64;
    let mut duplicate_admissions = 0_u64;
    let mut interrupted_provider_turns = 0_u64;
    let mut retried_read_tool_turns = 0_u64;
    let mut resumed_undispatched_model_turns = 0_u64;
    let mut resumed_undispatched_read_tool_turns = 0_u64;
    let mut latencies_ms = Vec::new();
    while started.elapsed() < configuration.duration || round == 0 {
        round = round.checked_add(1).expect("soak round overflow");
        let restart_this_round = round.is_multiple_of(configuration.restart_every_rounds);
        let mut tasks = Vec::with_capacity(configuration.sessions);
        for (session_index, session_id) in session_ids.iter().enumerate() {
            let submitted = Instant::now();
            let request = SubmitInputRequest {
                api_version: API_VERSION.to_owned(),
                idempotency_key: format!("soak-{round}-{session_index}"),
                delivery_mode: DeliveryMode::Queue,
                content: format!(
                    "Read the deterministic fixture for soak round {round}, session {session_index}."
                ),
            };
            let admission: InputAdmissionResponse = authorized_post(
                &client,
                &connection,
                &format!("/v1/sessions/{session_id}/inputs"),
                &request,
            )
            .await;
            if (round == 1 && session_index == 0)
                || (round + u64::try_from(session_index).expect("session index")).is_multiple_of(17)
            {
                let duplicate: InputAdmissionResponse = authorized_post(
                    &client,
                    &connection,
                    &format!("/v1/sessions/{session_id}/inputs"),
                    &request,
                )
                .await;
                assert!(duplicate.duplicate);
                assert_eq!(duplicate.inbox_entry_id, admission.inbox_entry_id);
                duplicate_admissions = duplicate_admissions
                    .checked_add(1)
                    .expect("duplicate count overflow");
            }
            let task_id =
                wait_for_task_id(&client, &connection, session_id, admission.cursor.0).await;
            tasks.push((session_id.clone(), admission.cursor.0, task_id, submitted));
        }

        if restart_this_round {
            wait_for_dispatched_attempt(&client, &connection, &tasks).await;
            peak_rss_kib = peak_rss_kib.max(resident_set_kib(daemon.process_id()).unwrap_or(0));
            daemon.hard_kill();
            let _ = fs::remove_file(home.path().join("connection.json"));
            assert_eq!(sqlite_integrity(home.path()), "ok");
            daemon = Daemon::spawn(
                &configuration.daemon_path,
                home.path(),
                configuration.provider_delay_ms,
            );
            connection = wait_until_ready(&client, home.path()).await;
            hard_restarts = hard_restarts
                .checked_add(1)
                .expect("restart count overflow");
        }

        let deadline = Instant::now() + ROUND_TIMEOUT;
        for (session_id, cursor, task_id, submitted) in tasks {
            let task = wait_until_terminal(&client, &connection, &task_id, deadline).await;
            if task.status != TaskStatus::Succeeded {
                let timeline: TimelinePageResponse = authorized_get(
                    &client,
                    &connection,
                    &format!("/v1/sessions/{session_id}/timeline?after={cursor}&limit=100"),
                )
                .await;
                let replay: TaskReplayResponse =
                    authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay"))
                        .await;
                write_failure_report(
                    &configuration,
                    round,
                    &session_id,
                    cursor,
                    &task,
                    &timeline,
                    &replay,
                );
                panic!("soak task did not succeed: {task:?}");
            }
            if restart_this_round {
                match (
                    task.model_attempts,
                    task.tool_calls,
                    task.usage.used_retries,
                ) {
                    (3, 1, 1) => {
                        interrupted_provider_turns = interrupted_provider_turns
                            .checked_add(1)
                            .expect("interrupted count overflow");
                    }
                    (2, 2, 1) => {
                        retried_read_tool_turns = retried_read_tool_turns
                            .checked_add(1)
                            .expect("read-tool retry count overflow");
                    }
                    (2, 2, 0) => {
                        resumed_undispatched_read_tool_turns = resumed_undispatched_read_tool_turns
                            .checked_add(1)
                            .expect("undispatched read-tool resume count overflow");
                    }
                    (3, 1, 0) => {
                        resumed_undispatched_model_turns = resumed_undispatched_model_turns
                            .checked_add(1)
                            .expect("undispatched model resume count overflow");
                    }
                    (2, 1, 0) => {}
                    _ => panic!("unexpected restart recovery lineage: {task:?}"),
                }
            } else {
                assert_eq!(task.model_attempts, 2, "ordinary task: {task:?}");
                assert_eq!(task.tool_calls, 1, "ordinary task: {task:?}");
                assert_eq!(task.usage.used_retries, 0, "ordinary task: {task:?}");
            }
            let replay: TaskReplayResponse =
                authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
            assert!(replay.evidence_complete, "soak replay: {replay:?}");
            assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
            latencies_ms.push(u64::try_from(submitted.elapsed().as_millis()).unwrap_or(u64::MAX));
            completed_turns = completed_turns
                .checked_add(1)
                .expect("completed turn count overflow");
        }
        peak_rss_kib = peak_rss_kib.max(resident_set_kib(daemon.process_id()).unwrap_or(0));
        if !configuration.round_interval.is_zero() && started.elapsed() < configuration.duration {
            sleep(configuration.round_interval).await;
        }
    }

    assert!(
        hard_restarts > 0,
        "soak must cross at least one hard restart"
    );
    assert!(
        interrupted_provider_turns.saturating_add(retried_read_tool_turns) >= hard_restarts,
        "every hard restart must recover at least one dispatched provider or pure read-tool boundary"
    );
    let status: AdminStatusResponse =
        authorized_get(&client, &connection, "/v1/admin/status").await;
    assert_eq!(status.pending_inputs, 0);
    assert_eq!(status.nonterminal_runs, 0);
    assert_eq!(status.active_leases, 0);
    assert_eq!(status.pending_approvals, 0);
    assert_eq!(status.unknown_effects, 0);
    assert_eq!(status.failed_outbox, 0);
    let metrics: AdminMetricsResponse =
        authorized_get(&client, &connection, "/v1/admin/metrics").await;
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
        &connection,
        "/v1/admin/drain",
        &DrainDaemonRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    assert!(daemon.wait().await.success());
    assert_eq!(sqlite_integrity(home.path()), "ok");

    latencies_ms.sort_unstable();
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let finished_at_ms = unix_milliseconds(SystemTime::now());
    let database_bytes = file_bytes_with_sidecars(home.path().join("mealy.sqlite3").as_path());
    let sqlite_storage = sqlite_storage_profile(home.path());
    let artifact_bytes = directory_bytes(&home.path().join("artifacts"));
    let completed_turns_per_minute = completed_turns
        .saturating_mul(60_000)
        .checked_div(duration_ms.max(1))
        .unwrap_or(0);
    let database_bytes_per_completed_turn = database_bytes
        .checked_div(completed_turns.max(1))
        .unwrap_or(0);
    let report = json!({
        "schemaVersion": "mealy.soak-report.v2",
        "revision": configuration.revision,
        "sourceState": if configuration.revision.ends_with("-dirty") {
            "dirty_worktree"
        } else if configuration.revision == "unknown" {
            "unknown"
        } else {
            "clean_revision"
        },
        "mealyVersion": env!("CARGO_PKG_VERSION"),
        "harnessMode": configuration.harness_mode,
        "daemonBinarySha256": configuration.daemon_sha256,
        "homeStorage": {
            "mode": home.mode(),
            "filesystem": configuration.home_filesystem,
        },
        "buildProfile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "target": {
            "os": env::consts::OS,
            "architecture": env::consts::ARCH,
            "logicalCpus": std::thread::available_parallelism().map_or(0, usize::from),
            "cpuModel": linux_value("/proc/cpuinfo", "model name").unwrap_or_else(|| "unknown".to_owned()),
            "hostMemoryKiB": linux_numeric_value("/proc/meminfo", "MemTotal").unwrap_or(0),
        },
        "startedAtUnixMs": started_at_ms,
        "finishedAtUnixMs": finished_at_ms,
        "requestedDurationSeconds": configuration.duration.as_secs(),
        "observedDurationMs": duration_ms,
        "sessions": configuration.sessions,
        "rounds": round,
        "completedTurns": completed_turns,
        "completedTurnsPerMinute": completed_turns_per_minute,
        "hardRestarts": hard_restarts,
        "interruptedProviderTurns": interrupted_provider_turns,
        "retriedReadToolTurns": retried_read_tool_turns,
        "resumedUndispatchedModelTurns": resumed_undispatched_model_turns,
        "resumedUndispatchedReadToolTurns": resumed_undispatched_read_tool_turns,
        "duplicateAdmissions": duplicate_admissions,
        "providerDelayMs": configuration.provider_delay_ms,
        "roundIntervalMs": u64::try_from(configuration.round_interval.as_millis()).unwrap_or(u64::MAX),
        "latencyMs": latency_summary(&latencies_ms),
        "peakResidentSetKiB": peak_rss_kib,
        "databaseBytesIncludingSidecars": database_bytes,
        "databaseBytesPerCompletedTurn": database_bytes_per_completed_turn,
        "sqliteStorage": sqlite_storage,
        "artifactBytes": artifact_bytes,
        "sqliteIntegrity": "ok",
        "residual": {
            "pendingInputs": status.pending_inputs,
            "nonterminalRuns": status.nonterminal_runs,
            "activeLeases": status.active_leases,
            "pendingApprovals": status.pending_approvals,
            "unknownEffects": status.unknown_effects,
            "failedOutbox": status.failed_outbox,
        },
    });
    let encoded = serde_json::to_vec_pretty(&report).expect("encode soak report");
    println!("{}", String::from_utf8_lossy(&encoded));
    if let Some(path) = configuration.report_path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create soak report directory");
        }
        fs::write(path, encoded).expect("write soak report");
    }
}

fn write_failure_report(
    configuration: &SoakConfiguration,
    round: u64,
    session_id: &str,
    cursor: u64,
    task: &TaskResponse,
    timeline: &TimelinePageResponse,
    replay: &TaskReplayResponse,
) {
    let report = json!({
        "schemaVersion": "mealy.soak-failure.v1",
        "revision": configuration.revision,
        "harnessMode": configuration.harness_mode,
        "daemonBinarySha256": configuration.daemon_sha256,
        "homeStorage": {
            "mode": if configuration.home_path.is_some() { "retained" } else { "temporary" },
            "filesystem": configuration.home_filesystem,
        },
        "round": round,
        "sessionId": session_id,
        "admissionCursor": cursor,
        "task": task,
        "timeline": timeline,
        "replay": replay,
    });
    let encoded = serde_json::to_vec_pretty(&report).expect("encode soak failure report");
    eprintln!("{}", String::from_utf8_lossy(&encoded));
    if let Some(path) = &configuration.report_path {
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("soak-report.json");
        let failure_path = path.with_file_name(format!("{file_name}.failure.json"));
        if let Some(parent) = failure_path.parent() {
            fs::create_dir_all(parent).expect("create soak failure report directory");
        }
        fs::write(failure_path, encoded).expect("write soak failure report");
    }
}

fn environment_u64(name: &str, default: u64, minimum: u64, maximum: u64) -> u64 {
    let value = env::var(name).map_or(default, |raw| {
        raw.parse::<u64>()
            .unwrap_or_else(|_| panic!("{name} must be an unsigned integer"))
    });
    assert!(
        (minimum..=maximum).contains(&value),
        "{name} must be between {minimum} and {maximum}"
    );
    value
}

fn unix_milliseconds(time: SystemTime) -> i64 {
    i64::try_from(
        time.duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time")
            .as_millis(),
    )
    .expect("Unix millisecond timestamp")
}

fn latency_summary(sorted: &[u64]) -> Value {
    assert!(!sorted.is_empty(), "soak produced no latency samples");
    let sum = sorted.iter().fold(0_u128, |total, value| {
        total.saturating_add(u128::from(*value))
    });
    json!({
        "minimum": sorted[0],
        "mean": u64::try_from(sum / u128::try_from(sorted.len()).expect("sample count"))
            .unwrap_or(u64::MAX),
        "p50": percentile(sorted, 50),
        "p95": percentile(sorted, 95),
        "p99": percentile(sorted, 99),
        "maximum": sorted[sorted.len() - 1],
    })
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    let rank = sorted
        .len()
        .saturating_mul(percentile)
        .div_ceil(100)
        .max(1)
        .saturating_sub(1)
        .min(sorted.len().saturating_sub(1));
    sorted[rank]
}

fn resident_set_kib(process_id: u32) -> Option<u64> {
    let status = fs::read_to_string(format!("/proc/{process_id}/status")).ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("VmRSS:")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

fn linux_value(path: &str, key: &str) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    content.lines().find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        (candidate.trim() == key)
            .then(|| value.trim())
            .filter(|value| !value.is_empty() && value.len() <= 256)
            .map(str::to_owned)
    })
}

fn linux_numeric_value(path: &str, key: &str) -> Option<u64> {
    linux_value(path, key)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn file_bytes_with_sidecars(path: &Path) -> u64 {
    ["", "-wal", "-shm"].iter().fold(0_u64, |total, suffix| {
        let candidate = if suffix.is_empty() {
            path.to_path_buf()
        } else {
            let mut value = path.as_os_str().to_owned();
            value.push(suffix);
            PathBuf::from(value)
        };
        total.saturating_add(
            fs::metadata(candidate)
                .ok()
                .filter(std::fs::Metadata::is_file)
                .map_or(0, |metadata| metadata.len()),
        )
    })
}

fn directory_bytes(path: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    entries.flatten().fold(0_u64, |total, entry| {
        let path = entry.path();
        let bytes = entry.metadata().ok().map_or(0, |metadata| {
            if metadata.is_dir() {
                directory_bytes(&path)
            } else if metadata.is_file() {
                metadata.len()
            } else {
                0
            }
        });
        total.saturating_add(bytes)
    })
}

fn write_soak_config(home: &Path, sessions: usize) {
    fs::create_dir_all(home).expect("create daemon home");
    let concurrency = u64::try_from(sessions).expect("session count");
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
            "maximumWallTimeMs": 120_000,
            "providerTimeoutMs": 10_000,
            "toolTimeoutMs": 5_000,
            "inlineOutputBytes": 1_024,
            "maximumArtifactBytes": 4_194_304
        },
        "concurrencyLimits": {
            "daemonAgentRuns": concurrency,
            "principalAgentRuns": concurrency,
            "sessionAgentRuns": 1,
            "providerRequests": concurrency,
            "providerRequestsPerMinute": 10_000,
            "extensionInvocations": concurrency,
            "agentRoleRuns": concurrency,
            "resourceClassInvocations": concurrency
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

async fn wait_for_dispatched_attempt(
    client: &Client,
    connection: &LocalConnectionInfo,
    tasks: &[(String, u64, String, Instant)],
) {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        for (session_id, cursor, _, _) in tasks {
            let page: TimelinePageResponse = authorized_get(
                client,
                connection,
                &format!("/v1/sessions/{session_id}/timeline?after={cursor}&limit=100"),
            )
            .await;
            if page
                .events
                .iter()
                .any(|event| event.event_type == "model.attempt.dispatched")
            {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "a soak provider attempt did not dispatch before restart"
        );
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
        assert!(Instant::now() < deadline, "soak task did not terminate");
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

fn sqlite_storage_profile(home: &Path) -> Value {
    let database = home.join("mealy.sqlite3");
    let connection = rusqlite::Connection::open(&database).expect("open database storage profile");
    let page_size_bytes = pragma_i64(&connection, "PRAGMA page_size");
    let page_count = pragma_i64(&connection, "PRAGMA page_count");
    let free_pages = pragma_i64(&connection, "PRAGMA freelist_count");
    let mut statement = connection
        .prepare(
            "SELECT stat.name, COALESCE(schema.type, 'internal'), \
                    SUM(stat.pgsize), SUM(stat.payload), SUM(stat.unused), COUNT(*) \
             FROM dbstat stat \
             LEFT JOIN sqlite_schema schema ON schema.name = stat.name \
             GROUP BY stat.name, schema.type \
             ORDER BY SUM(stat.pgsize) DESC, stat.name \
             LIMIT 64",
        )
        .expect("prepare SQLite object storage profile");
    let objects = statement
        .query_map([], |row| {
            Ok(json!({
                "name": row.get::<_, String>(0)?,
                "kind": row.get::<_, String>(1)?,
                "bytes": row.get::<_, i64>(2)?,
                "payloadBytes": row.get::<_, i64>(3)?,
                "unusedBytes": row.get::<_, i64>(4)?,
                "pages": row.get::<_, i64>(5)?,
            }))
        })
        .expect("query SQLite object storage profile")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect SQLite object storage profile");
    let context_items = connection
        .query_row(
            "SELECT COUNT(*), \
                    COALESCE(SUM(disposition = 'included'), 0), \
                    COALESCE(SUM(disposition <> 'included'), 0), \
                    COALESCE(SUM(content_text IS NOT NULL), 0), \
                    COALESCE(SUM(length(CAST(content_text AS BLOB))), 0), \
                    COALESCE(MAX(length(CAST(content_text AS BLOB))), 0), \
                    COALESCE(SUM(content_artifact_id IS NOT NULL), 0) \
             FROM context_manifest_item",
            [],
            |row| {
                Ok(json!({
                    "rows": row.get::<_, i64>(0)?,
                    "includedRows": row.get::<_, i64>(1)?,
                    "withheldRows": row.get::<_, i64>(2)?,
                    "inlineContentRows": row.get::<_, i64>(3)?,
                    "inlineContentBytes": row.get::<_, i64>(4)?,
                    "maximumInlineContentBytes": row.get::<_, i64>(5)?,
                    "artifactContentRows": row.get::<_, i64>(6)?,
                }))
            },
        )
        .expect("query context manifest item storage profile");
    let mut source_type_counts = serde_json::Map::new();
    let mut source_statement = connection
        .prepare(
            "SELECT source_type, COUNT(*) FROM context_manifest_item \
             GROUP BY source_type ORDER BY source_type",
        )
        .expect("prepare context source type profile");
    for row in source_statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .expect("query context source type profile")
    {
        let (source_type, count) = row.expect("read context source type profile");
        source_type_counts.insert(source_type, json!(count));
    }
    json!({
        "databaseFileBytes": file_bytes(&database),
        "walFileBytes": file_bytes(&database.with_extension("sqlite3-wal")),
        "sharedMemoryFileBytes": file_bytes(&database.with_extension("sqlite3-shm")),
        "pageSizeBytes": page_size_bytes,
        "pageCount": page_count,
        "freePages": free_pages,
        "freeBytes": free_pages.saturating_mul(page_size_bytes),
        "contextManifestItems": context_items,
        "contextManifestSourceRows": source_type_counts,
        "largestObjects": objects,
    })
}

fn pragma_i64(connection: &rusqlite::Connection, statement: &str) -> i64 {
    connection
        .query_row(statement, [], |row| row.get(0))
        .expect("read SQLite storage pragma")
}

fn file_bytes(path: &Path) -> u64 {
    fs::metadata(path).map_or(0, |metadata| metadata.len())
}
