//! Public-API process-boundary recovery scenario for the Phase 1 exit gate.

use eventsource_stream::Eventsource;
use futures_util::StreamExt;
use mealy_protocol::{
    API_VERSION, CreateSessionRequest, CreateSessionResponse, DeliveryMode, InputAdmissionResponse,
    LocalConnectionInfo, ReadinessResponse, SessionStatusResponse, SubmitInputRequest,
    TimelineEvent, TimelinePageResponse,
};
use reqwest::{Client, StatusCode, header};
use std::{
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tempfile::TempDir;
use tokio::time::{Instant, sleep, timeout};

const READY_TIMEOUT: Duration = Duration::from_secs(10);

struct Daemon {
    child: Child,
}

impl Daemon {
    fn spawn(home: &Path, promotion_delay_ms: u64) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_mealyd"))
            .arg("--home")
            .arg(home)
            .arg("--promotion-delay-ms")
            .arg(promotion_delay_ms.to_string())
            .arg("--promotion-interval-ms")
            .arg("10")
            .arg("--outbox-delay-ms")
            .arg(promotion_delay_ms.to_string())
            .arg("--agent-delay-ms")
            .arg("60000")
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
async fn acknowledged_input_is_promoted_exactly_once_after_hard_restart() {
    let home = TempDir::new().expect("temporary daemon home should be created");
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("HTTP client should build");

    let mut first_daemon = Daemon::spawn(home.path(), 60_000);
    let first_connection = wait_until_ready(&client, home.path()).await;

    let created: CreateSessionResponse = authorized_post(
        &client,
        &first_connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    let command = SubmitInputRequest {
        api_version: API_VERSION.to_owned(),
        idempotency_key: "phase-1-crash-window".to_owned(),
        delivery_mode: DeliveryMode::Queue,
        content: "survive acknowledgement-to-promotion crash".to_owned(),
    };
    let accepted: InputAdmissionResponse = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/sessions/{}/inputs", created.session_id),
        &command,
    )
    .await;
    assert!(!accepted.duplicate);

    let before_crash = session_status(&client, &first_connection, &created.session_id).await;
    assert_eq!(before_crash.pending_inputs, 1);
    assert_eq!(before_crash.active_turn_id, None);
    assert_eq!(
        outbox_count(home.path(), "pending"),
        1,
        "crash window must include an undelivered durable acknowledgement"
    );

    first_daemon.hard_kill();
    drop(first_daemon);
    fs::remove_file(home.path().join("connection.json"))
        .expect("ephemeral endpoint descriptor can be recreated from durable identity");

    let _second_daemon = Daemon::spawn(home.path(), 0);
    let second_connection = wait_until_ready(&client, home.path()).await;
    let after_restart = wait_until_promoted(&client, &second_connection, &created.session_id).await;
    assert_eq!(after_restart.pending_inputs, 0);
    assert!(after_restart.active_turn_id.is_some());

    let duplicate: InputAdmissionResponse = authorized_post(
        &client,
        &second_connection,
        &format!("/v1/sessions/{}/inputs", created.session_id),
        &command,
    )
    .await;
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.inbox_entry_id, accepted.inbox_entry_id);
    assert_eq!(duplicate.inbox_sequence, accepted.inbox_sequence);
    assert_eq!(duplicate.event_id, accepted.event_id);
    assert_eq!(duplicate.outbox_id, accepted.outbox_id);
    assert_eq!(duplicate.accepted_at_ms, accepted.accepted_at_ms);
    assert_eq!(duplicate.cursor, accepted.cursor);

    let page: TimelinePageResponse = authorized_get(
        &client,
        &second_connection,
        &format!("/v1/sessions/{}/timeline?limit=100", created.session_id),
    )
    .await;
    assert_eq!(count_events(&page.events, "input.accepted"), 1);
    assert_eq!(count_events(&page.events, "input.promoted"), 1);
    assert_eq!(count_events(&page.events, "task.created"), 1);
    assert_eq!(count_events(&page.events, "run.created"), 1);
    assert!(
        page.events
            .windows(2)
            .all(|events| events[0].cursor < events[1].cursor),
        "timeline cursors must remain strictly increasing"
    );

    let resumed = sse_events_after(
        &client,
        &second_connection,
        &created.session_id,
        accepted.cursor.0,
        3,
    )
    .await;
    assert_eq!(
        resumed
            .iter()
            .map(|event| event.event_type.as_str())
            .collect::<Vec<_>>(),
        vec!["input.promoted", "task.created", "run.created"]
    );
    assert!(
        resumed
            .iter()
            .all(|event| event.cursor.0 > accepted.cursor.0)
    );
    wait_until_outbox_drained(home.path()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn durable_database_without_identity_fails_closed() {
    let home = TempDir::new().expect("temporary daemon home should be created");
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("HTTP client should build");
    let mut first = Daemon::spawn(home.path(), 60_000);
    wait_until_ready(&client, home.path()).await;
    first.hard_kill();
    drop(first);
    fs::remove_file(home.path().join("connection.json")).expect("remove endpoint descriptor");
    fs::remove_file(home.path().join("identity.json")).expect("remove durable identity");

    let mut restart = Command::new(env!("CARGO_BIN_EXE_mealyd"))
        .arg("--home")
        .arg(home.path())
        .env("RUST_LOG", "error")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("restart process should start far enough to validate identity");
    let status = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(status) = restart.try_wait().expect("poll failed restart") {
                return status;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("missing identity should fail promptly");
    assert!(!status.success());
    assert!(!home.path().join("identity.json").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_home_directory_has_exactly_one_live_daemon() {
    let home = TempDir::new().expect("temporary daemon home should be created");
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("HTTP client should build");
    let _first = Daemon::spawn(home.path(), 60_000);
    let connection = wait_until_ready(&client, home.path()).await;
    let descriptor_before =
        fs::read(home.path().join("connection.json")).expect("connection descriptor should exist");

    let mut second = Command::new(env!("CARGO_BIN_EXE_mealyd"))
        .arg("--home")
        .arg(home.path())
        .env("RUST_LOG", "error")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("second daemon process should start far enough to reject the lock");
    let status = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(status) = second.try_wait().expect("poll second daemon") {
                return status;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("second daemon should fail promptly");
    assert!(!status.success());
    assert_eq!(
        fs::read(home.path().join("connection.json"))
            .expect("first daemon descriptor should remain"),
        descriptor_before
    );
    let readiness: ReadinessResponse = authorized_get(&client, &connection, "/health/ready").await;
    assert!(readiness.ready);
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

async fn wait_until_promoted(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
) -> SessionStatusResponse {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        let status = session_status(client, connection, session_id).await;
        if status.pending_inputs == 0 && status.active_turn_id.is_some() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "acknowledged input was not promoted after restart"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_until_outbox_drained(home: &Path) {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        let counts =
            rusqlite::Connection::open(home.join("mealy.sqlite3")).and_then(|connection| {
                connection.query_row(
                    "SELECT \
                        SUM(CASE WHEN state IN ('pending', 'delivering') THEN 1 ELSE 0 END), \
                        SUM(CASE WHEN state = 'delivered' THEN 1 ELSE 0 END), \
                        SUM(CASE WHEN state = 'failed' THEN 1 ELSE 0 END) \
                     FROM outbox",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
            });
        if let Ok((0, delivered, 0)) = counts
            && delivered >= 2
        {
            return;
        }
        assert!(Instant::now() < deadline, "durable outbox did not drain");
        sleep(Duration::from_millis(20)).await;
    }
}

fn outbox_count(home: &Path, state: &str) -> i64 {
    rusqlite::Connection::open(home.join("mealy.sqlite3"))
        .and_then(|connection| {
            connection.query_row(
                "SELECT COUNT(*) FROM outbox WHERE state = ?1",
                [state],
                |row| row.get(0),
            )
        })
        .expect("query durable outbox state")
}

async fn session_status(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
) -> SessionStatusResponse {
    authorized_get(
        client,
        connection,
        &format!("/v1/sessions/{session_id}/status"),
    )
    .await
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

async fn sse_events_after(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
    after: u64,
    expected: usize,
) -> Vec<TimelineEvent> {
    let response = client
        .get(format!(
            "{}/v1/sessions/{session_id}/events",
            connection.base_url
        ))
        .bearer_auth(&connection.bearer_token)
        .header(header::ACCEPT, "text/event-stream")
        .header("Last-Event-ID", after.to_string())
        .send()
        .await
        .expect("SSE request should reach mealyd");
    assert_eq!(response.status(), StatusCode::OK);

    let mut stream = response.bytes_stream().eventsource();
    let mut observed = Vec::with_capacity(expected);
    while observed.len() < expected {
        let item = timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("resumed SSE should produce a durable event")
            .expect("SSE stream should remain open")
            .expect("SSE frame should be valid");
        assert_ne!(item.event, "error", "SSE returned an error: {}", item.data);
        let event: TimelineEvent =
            serde_json::from_str(&item.data).expect("SSE data should be a timeline event");
        assert_eq!(item.id, event.cursor.0.to_string());
        observed.push(event);
    }
    observed
}

fn count_events(events: &[TimelineEvent], event_type: &str) -> usize {
    events
        .iter()
        .filter(|event| event.event_type == event_type)
        .count()
}
