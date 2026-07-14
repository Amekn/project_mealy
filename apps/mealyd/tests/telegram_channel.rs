//! Public-process proof for Telegram setup, allowlists, polling recovery, delivery, and revocation.

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Response as AxumResponse},
    routing::any,
};
use mealy_protocol::{
    API_VERSION, CreateScheduleRequest, CreateTelegramChannelRequest, DrainDaemonRequest,
    DrainDaemonResponse, LocalConnectionInfo, MissedRunPolicyCommand, ReadinessResponse,
    RevokeTelegramChannelRequest, ScheduleOverlapPolicyCommand, ScheduleResponse,
    ScheduleRunStatusResponse, ScheduleRunsResponse, SessionSearchResponse,
    TelegramChannelResponse, TelegramChannelStatusResponse, TelegramChannelsResponse,
};
use reqwest::Client;
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    net::TcpListener,
    task::JoinHandle,
    time::{Instant, sleep},
};

const BOT_TOKEN: &str = "123456:abcdefghijklmnopqrstuvwxyz_ABCDEFGH";
const READY_TIMEOUT: Duration = Duration::from_secs(15);
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(20);

struct Daemon {
    child: Child,
}

impl Daemon {
    fn spawn(home: &Path, telegram_api_base_url: &str) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_mealyd"))
            .arg("--home")
            .arg(home)
            .arg("--telegram-api-base-url")
            .arg(telegram_api_base_url)
            .arg("--promotion-delay-ms")
            .arg("0")
            .arg("--promotion-interval-ms")
            .arg("10")
            .arg("--agent-delay-ms")
            .arg("0")
            .arg("--outbox-delay-ms")
            .arg("0")
            .arg("--schedule-clock-offset-ms")
            .arg("60000")
            .env("RUST_LOG", "error")
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
        let deadline = Instant::now() + Duration::from_secs(8);
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

#[derive(Clone, Default)]
struct BotApiState(Arc<BotApiInner>);

#[derive(Default)]
struct BotApiInner {
    updates: Mutex<Vec<Value>>,
    requested_offsets: Mutex<Vec<i64>>,
    sent_messages: Mutex<Vec<String>>,
    send_failures_remaining: AtomicUsize,
    get_me_calls: AtomicUsize,
}

impl BotApiState {
    fn fail_first_send() -> Self {
        let state = Self::default();
        state.0.send_failures_remaining.store(1, Ordering::SeqCst);
        state
    }

    fn push_update(&self, update: Value) {
        self.0.updates.lock().expect("updates lock").push(update);
    }

    fn sent_messages(&self) -> Vec<String> {
        self.0.sent_messages.lock().expect("messages lock").clone()
    }

    fn requested_offsets(&self) -> Vec<i64> {
        self.0
            .requested_offsets
            .lock()
            .expect("offsets lock")
            .clone()
    }
}

async fn bot_api_handler(
    State(state): State<BotApiState>,
    AxumPath(path): AxumPath<String>,
    body: Bytes,
) -> AxumResponse {
    if path == format!("file/bot{BOT_TOKEN}/documents/report.txt") {
        return (
            [(axum::http::header::CONTENT_TYPE, "text/plain")],
            "bounded attachment evidence\n",
        )
            .into_response();
    }
    let expected_prefix = format!("bot{BOT_TOKEN}/");
    let Some(method) = path.strip_prefix(&expected_prefix) else {
        return (StatusCode::UNAUTHORIZED, Json(json!({"ok": false}))).into_response();
    };
    match method {
        "getMe" => {
            state.0.get_me_calls.fetch_add(1, Ordering::SeqCst);
            Json(json!({
                "ok": true,
                "result": {
                    "id": 9001,
                    "is_bot": true,
                    "username": "mealy_process_test_bot"
                }
            }))
            .into_response()
        }
        "getUpdates" => {
            let request: Value = serde_json::from_slice(&body).expect("getUpdates request JSON");
            let offset = request["offset"].as_i64().expect("getUpdates offset");
            state
                .0
                .requested_offsets
                .lock()
                .expect("offset lock")
                .push(offset);
            let updates = state
                .0
                .updates
                .lock()
                .expect("updates lock")
                .iter()
                .filter(|update| update["update_id"].as_i64().is_some_and(|id| id >= offset))
                .cloned()
                .collect::<Vec<_>>();
            Json(json!({"ok": true, "result": updates})).into_response()
        }
        "sendMessage" => {
            let request: Value = serde_json::from_slice(&body).expect("sendMessage request JSON");
            assert_eq!(request["chat_id"], 8001);
            let text = request["text"]
                .as_str()
                .expect("sendMessage text")
                .to_owned();
            if state
                .0
                .send_failures_remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"ok": false, "description": "retry fixture"})),
                )
                    .into_response();
            }
            state
                .0
                .sent_messages
                .lock()
                .expect("messages lock")
                .push(text);
            Json(json!({
                "ok": true,
                "result": {"message_id": 1, "chat": {"id": 8001}, "text": "sent"}
            }))
            .into_response()
        }
        "getFile" => {
            let request: Value = serde_json::from_slice(&body).expect("getFile request JSON");
            assert_eq!(request["file_id"], "document-file-1");
            Json(json!({
                "ok": true,
                "result": {
                    "file_id": "document-file-1",
                    "file_unique_id": "document-unique-1",
                    "file_size": 28,
                    "file_path": "documents/report.txt"
                }
            }))
            .into_response()
        }
        _ => (StatusCode::NOT_FOUND, Json(json!({"ok": false}))).into_response(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn telegram_channel_is_allowlisted_restart_safe_retrying_and_revocable() {
    let bot_state = BotApiState::fail_first_send();
    let (bot_api_url, bot_server) = spawn_bot_api(bot_state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("HTTP client");
    let mut daemon = Daemon::spawn(home.path(), &bot_api_url);
    let connection = wait_until_ready(&client, home.path()).await;
    let created: TelegramChannelResponse = authorized_post(
        &client,
        &connection,
        "/v1/channels/telegram",
        &CreateTelegramChannelRequest {
            api_version: API_VERSION.to_owned(),
            bot_token: BOT_TOKEN.to_owned(),
            telegram_user_id: 7001,
            telegram_chat_id: 8001,
            initial_next_update_id: 100,
        },
    )
    .await;
    assert_eq!(created.status, TelegramChannelStatusResponse::Active);
    assert_eq!(created.bot_user_id, 9001);
    assert_eq!(created.bot_username, "mealy_process_test_bot");
    assert_eq!(created.next_update_id, 100);
    assert_eq!(bot_state.0.get_me_calls.load(Ordering::SeqCst), 1);
    assert!(!database_contains(home.path(), BOT_TOKEN.as_bytes()));
    assert!(
        home.path()
            .join("provider-secrets")
            .join(format!("telegram.{}.key", created.binding_id))
            .is_file()
    );

    let listed: TelegramChannelsResponse =
        authorized_get(&client, &connection, "/v1/channels/telegram").await;
    assert_eq!(listed.channels, vec![created.clone()]);
    bot_state.push_update(telegram_message(101, 7001, 8001, "hello from Telegram"));
    let advanced = wait_for_cursor(&client, &connection, &created.binding_id, 102).await;
    assert_eq!(advanced.next_update_id, 102);
    wait_for_sent_message(&bot_state, "Mealy accepted your message.").await;
    wait_for_sent_prefix(&bot_state, "Mealy (succeeded):").await;
    assert_eq!(session_inbox_count(home.path(), &created.session_id), 1);
    let local_search: SessionSearchResponse = authorized_get(
        &client,
        &connection,
        "/v1/sessions/search?query=hello%20from%20Telegram&limit=20",
    )
    .await;
    assert!(
        local_search.hits.is_empty(),
        "local transcript search crossed into a Telegram binding"
    );

    daemon.hard_kill();
    fs::remove_file(home.path().join("connection.json")).expect("remove stale descriptor");
    let mut restarted_daemon = Daemon::spawn(home.path(), &bot_api_url);
    let restarted = wait_until_ready(&client, home.path()).await;
    sleep(Duration::from_millis(750)).await;
    assert_eq!(session_inbox_count(home.path(), &created.session_id), 1);
    assert!(
        bot_state
            .requested_offsets()
            .iter()
            .any(|offset| *offset >= 102)
    );

    bot_state.push_update(telegram_message(102, 7999, 8001, "unauthorized sender"));
    bot_state.push_update(telegram_message(
        103,
        7001,
        8001,
        "/interrupt replace the task",
    ));
    let advanced = wait_for_cursor(&client, &restarted, &created.binding_id, 104).await;
    assert_eq!(advanced.next_update_id, 104);
    assert_eq!(session_inbox_count(home.path(), &created.session_id), 2);
    assert_eq!(
        ignored_update_reason(home.path(), &created.binding_id, 102),
        "sender_not_allowed"
    );

    bot_state.push_update(telegram_document(104, 7001, 8001));
    let advanced = wait_for_cursor(&client, &restarted, &created.binding_id, 105).await;
    assert_eq!(advanced.next_update_id, 105);
    assert_eq!(session_inbox_count(home.path(), &created.session_id), 3);
    assert!(
        newest_inbox_content(home.path(), &created.session_id)
            .contains("bounded attachment evidence")
    );

    let schedule: ScheduleResponse = authorized_post(
        &client,
        &restarted,
        "/v1/schedules",
        &CreateScheduleRequest {
            api_version: API_VERSION.to_owned(),
            schedule_id: mealy_domain::ScheduleId::new().to_string(),
            session_id: created.session_id.clone(),
            name: "Telegram schedule proof".to_owned(),
            prompt: "Run the remote scheduled proof.".to_owned(),
            cron_expression: "* * * * *".to_owned(),
            timezone: "Pacific/Auckland".to_owned(),
            missed_run_policy: MissedRunPolicyCommand::Latest,
            overlap_policy: ScheduleOverlapPolicyCommand::Queue,
            misfire_grace_ms: 60_000,
            allow_approval_required_action: false,
        },
    )
    .await;
    wait_for_schedule_admission(&client, &restarted, &schedule.schedule_id).await;
    assert_eq!(session_inbox_count(home.path(), &created.session_id), 4);

    let revoked: TelegramChannelResponse = authorized_post(
        &client,
        &restarted,
        &format!("/v1/channels/telegram/{}/revoke", created.binding_id),
        &RevokeTelegramChannelRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: 0,
        },
    )
    .await;
    assert_eq!(revoked.status, TelegramChannelStatusResponse::Revoked);
    assert_eq!(revoked.revision, 1);
    assert!(
        !home
            .path()
            .join("provider-secrets")
            .join(format!("telegram.{}.key", created.binding_id))
            .exists()
    );
    bot_state.push_update(telegram_message(105, 7001, 8001, "after revocation"));
    sleep(Duration::from_millis(750)).await;
    assert_eq!(session_inbox_count(home.path(), &created.session_id), 4);

    let _: DrainDaemonResponse = authorized_post(
        &client,
        &restarted,
        "/v1/admin/drain",
        &DrainDaemonRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    assert!(restarted_daemon.wait().await.success());
    bot_server.abort();
}

fn telegram_message(update_id: i64, user_id: i64, chat_id: i64, text: &str) -> Value {
    json!({
        "update_id": update_id,
        "message": {
            "message_id": update_id,
            "from": {"id": user_id, "is_bot": false, "first_name": "Owner"},
            "chat": {"id": chat_id, "type": "private"},
            "date": 1_800_000_000,
            "text": text,
        }
    })
}

fn telegram_document(update_id: i64, user_id: i64, chat_id: i64) -> Value {
    json!({
        "update_id": update_id,
        "message": {
            "message_id": update_id,
            "from": {"id": user_id, "is_bot": false, "first_name": "Owner"},
            "chat": {"id": chat_id, "type": "private"},
            "date": 1_800_000_000,
            "caption": "Summarize this attachment.",
            "document": {
                "file_id": "document-file-1",
                "file_unique_id": "document-unique-1",
                "file_name": "report.txt",
                "mime_type": "text/plain",
                "file_size": 28
            }
        }
    })
}

async fn spawn_bot_api(state: BotApiState) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Bot API listener");
    let address = listener.local_addr().expect("Bot API address");
    let app = Router::new()
        .route("/{*path}", any(bot_api_handler))
        .with_state(state);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("Bot API server");
    });
    (format!("http://{address}"), handle)
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

async fn wait_for_cursor(
    client: &Client,
    connection: &LocalConnectionInfo,
    binding_id: &str,
    expected: i64,
) -> TelegramChannelResponse {
    let deadline = Instant::now() + CHANNEL_TIMEOUT;
    loop {
        let channel: TelegramChannelResponse = authorized_get(
            client,
            connection,
            &format!("/v1/channels/telegram/{binding_id}"),
        )
        .await;
        if channel.next_update_id >= expected {
            return channel;
        }
        assert!(Instant::now() < deadline, "Telegram cursor did not advance");
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_schedule_admission(
    client: &Client,
    connection: &LocalConnectionInfo,
    schedule_id: &str,
) {
    let deadline = Instant::now() + CHANNEL_TIMEOUT;
    loop {
        let runs: ScheduleRunsResponse = authorized_get(
            client,
            connection,
            &format!("/v1/schedules/{schedule_id}/runs?limit=10"),
        )
        .await;
        if runs
            .runs
            .iter()
            .any(|run| run.status == ScheduleRunStatusResponse::Admitted)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "remote schedule was not admitted"
        );
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_sent_message(state: &BotApiState, expected: &str) {
    let deadline = Instant::now() + CHANNEL_TIMEOUT;
    loop {
        if state
            .sent_messages()
            .iter()
            .any(|message| message == expected)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Telegram message was not delivered"
        );
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_sent_prefix(state: &BotApiState, expected: &str) {
    let deadline = Instant::now() + CHANNEL_TIMEOUT;
    loop {
        if state
            .sent_messages()
            .iter()
            .any(|message| message.starts_with(expected))
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Telegram final was not delivered"
        );
        sleep(Duration::from_millis(25)).await;
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
    client
        .post(format!("{}{path}", connection.base_url))
        .bearer_auth(&connection.bearer_token)
        .json(body)
        .send()
        .await
        .expect("authorized POST")
        .error_for_status()
        .expect("successful POST")
        .json()
        .await
        .expect("POST response JSON")
}

fn session_inbox_count(home: &Path, session_id: &str) -> i64 {
    rusqlite::Connection::open(home.join("mealy.sqlite3"))
        .expect("open database")
        .query_row(
            "SELECT COUNT(*) FROM session_inbox WHERE session_id = ?1",
            [session_id],
            |row| row.get(0),
        )
        .expect("session inbox count")
}

fn ignored_update_reason(home: &Path, binding_id: &str, update_id: i64) -> String {
    rusqlite::Connection::open(home.join("mealy.sqlite3"))
        .expect("open database")
        .query_row(
            "SELECT ignore_reason FROM telegram_update_receipt \
             WHERE binding_id = ?1 AND update_id = ?2",
            rusqlite::params![binding_id, update_id],
            |row| row.get(0),
        )
        .expect("ignored update reason")
}

fn newest_inbox_content(home: &Path, session_id: &str) -> String {
    rusqlite::Connection::open(home.join("mealy.sqlite3"))
        .expect("open database")
        .query_row(
            "SELECT content FROM session_inbox WHERE session_id = ?1 \
             ORDER BY sequence DESC LIMIT 1",
            [session_id],
            |row| row.get(0),
        )
        .expect("newest inbox content")
}

fn database_contains(home: &Path, needle: &[u8]) -> bool {
    fs::read(home.join("mealy.sqlite3"))
        .expect("read database")
        .windows(needle.len())
        .any(|window| window == needle)
}
