//! Public-process proof for Discord DM setup, allowlists, restart recovery, rate limits, delivery,
//! mention suppression, nonce deduplication, and revocation.

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response as AxumResponse},
    routing::get,
};
use mealy_protocol::{
    API_VERSION, CreateDiscordChannelRequest, DiscordChannelResponse, DiscordChannelStatusResponse,
    DiscordChannelsResponse, DrainDaemonRequest, DrainDaemonResponse, LocalConnectionInfo,
    ReadinessResponse, RevokeDiscordChannelRequest, SessionSearchResponse,
};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    net::TcpListener,
    task::JoinHandle,
    time::{Instant, sleep},
};

const BOT_TOKEN: &str = "discord.process.test_token-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const BOT_USER_ID: &str = "9001";
const HUMAN_USER_ID: &str = "7001";
const DM_CHANNEL_ID: &str = "8001";
const READY_TIMEOUT: Duration = Duration::from_secs(15);
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(25);

struct Daemon {
    child: Child,
}

impl Daemon {
    fn spawn(home: &Path, discord_api_base_url: &str) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_mealyd"))
            .arg("--home")
            .arg(home)
            .arg("--discord-api-base-url")
            .arg(discord_api_base_url)
            .arg("--promotion-delay-ms")
            .arg("0")
            .arg("--promotion-interval-ms")
            .arg("10")
            .arg("--agent-delay-ms")
            .arg("0")
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

#[derive(Clone)]
struct DiscordApiState(Arc<DiscordApiInner>);

struct DiscordApiInner {
    messages: Mutex<Vec<Value>>,
    poll_cursors: Mutex<Vec<Option<String>>>,
    sent_requests: Mutex<Vec<Value>>,
    sent_contents: Mutex<Vec<String>>,
    nonce_messages: Mutex<BTreeMap<String, Value>>,
    next_message_id: AtomicU64,
    send_rate_limits_remaining: AtomicUsize,
    current_user_calls: AtomicUsize,
}

impl Default for DiscordApiState {
    fn default() -> Self {
        Self(Arc::new(DiscordApiInner {
            messages: Mutex::new(Vec::new()),
            poll_cursors: Mutex::new(Vec::new()),
            sent_requests: Mutex::new(Vec::new()),
            sent_contents: Mutex::new(Vec::new()),
            nonce_messages: Mutex::new(BTreeMap::new()),
            next_message_id: AtomicU64::new(10_000),
            send_rate_limits_remaining: AtomicUsize::new(1),
            current_user_calls: AtomicUsize::new(0),
        }))
    }
}

impl DiscordApiState {
    fn push_human_message(&self, user_id: &str, content: &str, attachments: &[Value]) -> String {
        let id = self
            .0
            .next_message_id
            .fetch_add(1, Ordering::SeqCst)
            .to_string();
        self.0.messages.lock().expect("messages lock").push(json!({
            "id": id,
            "channel_id": DM_CHANNEL_ID,
            "author": {"id": user_id, "username": "owner", "bot": false},
            "content": content,
            "type": 0,
            "attachments": attachments,
            "timestamp": "2026-07-13T00:00:00.000000+00:00",
            "tts": false,
            "mention_everyone": false,
            "mentions": [],
            "mention_roles": [],
            "embeds": [],
            "pinned": false
        }));
        id
    }

    fn sent_contents(&self) -> Vec<String> {
        self.0
            .sent_contents
            .lock()
            .expect("sent contents lock")
            .clone()
    }
}

#[derive(Deserialize)]
struct MessageQuery {
    after: Option<String>,
    before: Option<String>,
    limit: Option<usize>,
}

async fn current_user(State(state): State<DiscordApiState>, headers: HeaderMap) -> AxumResponse {
    assert_discord_headers(&headers);
    state.0.current_user_calls.fetch_add(1, Ordering::SeqCst);
    Json(json!({
        "id": BOT_USER_ID,
        "username": "mealy_process_test_bot",
        "discriminator": "0",
        "bot": true
    }))
    .into_response()
}

async fn channel(
    State(_state): State<DiscordApiState>,
    AxumPath(channel_id): AxumPath<String>,
    headers: HeaderMap,
) -> AxumResponse {
    assert_discord_headers(&headers);
    assert_eq!(channel_id, DM_CHANNEL_ID);
    Json(json!({
        "id": DM_CHANNEL_ID,
        "type": 1,
        "last_message_id": null,
        "recipients": [{
            "id": HUMAN_USER_ID,
            "username": "owner",
            "discriminator": "0",
            "bot": false
        }]
    }))
    .into_response()
}

async fn get_messages(
    State(state): State<DiscordApiState>,
    AxumPath(channel_id): AxumPath<String>,
    Query(query): Query<MessageQuery>,
    headers: HeaderMap,
) -> AxumResponse {
    assert_discord_headers(&headers);
    assert_eq!(channel_id, DM_CHANNEL_ID);
    assert!(query.limit.is_some_and(|limit| (1..=100).contains(&limit)));
    state
        .0
        .poll_cursors
        .lock()
        .expect("cursor lock")
        .push(query.after.clone());
    let after = query
        .after
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok());
    let before = query
        .before
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok());
    assert!(after.is_none() || before.is_none());
    let mut messages = state
        .0
        .messages
        .lock()
        .expect("messages lock")
        .iter()
        .filter(|message| {
            let id = message["id"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok());
            after.is_none_or(|after| id.is_some_and(|id| id > after))
                && before.is_none_or(|before| id.is_some_and(|id| id < before))
        })
        .cloned()
        .collect::<Vec<_>>();
    messages.sort_by_key(|message| {
        std::cmp::Reverse(
            message["id"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0),
        )
    });
    messages.truncate(query.limit.unwrap_or(50));
    (
        [
            ("x-ratelimit-remaining", "1"),
            ("x-ratelimit-reset-after", "0.05"),
        ],
        Json(messages),
    )
        .into_response()
}

async fn create_message(
    State(state): State<DiscordApiState>,
    AxumPath(channel_id): AxumPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> AxumResponse {
    assert_discord_headers(&headers);
    assert_eq!(channel_id, DM_CHANNEL_ID);
    let request: Value = serde_json::from_slice(&body).expect("Create Message request JSON");
    let content = request["content"]
        .as_str()
        .expect("Discord message content")
        .to_owned();
    let nonce = request["nonce"]
        .as_str()
        .expect("Discord message nonce")
        .to_owned();
    assert!(!content.is_empty() && content.chars().count() <= 2_000);
    assert_eq!(nonce.len(), 25);
    assert_eq!(request["enforce_nonce"], true);
    assert_eq!(request["tts"], false);
    assert_eq!(request["flags"], 4);
    assert_eq!(request["allowed_mentions"]["parse"], json!([]));
    state
        .0
        .sent_requests
        .lock()
        .expect("sent request lock")
        .push(request);
    if state
        .0
        .send_rate_limits_remaining
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
            remaining.checked_sub(1)
        })
        .is_ok()
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "0.05")],
            Json(json!({
                "message": "You are being rate limited.",
                "retry_after": 0.05,
                "global": false
            })),
        )
            .into_response();
    }
    if let Some(existing) = state
        .0
        .nonce_messages
        .lock()
        .expect("nonce lock")
        .get(&nonce)
        .cloned()
    {
        return Json(existing).into_response();
    }
    let id = state
        .0
        .next_message_id
        .fetch_add(1, Ordering::SeqCst)
        .to_string();
    let message = json!({
        "id": id,
        "channel_id": DM_CHANNEL_ID,
        "author": {"id": BOT_USER_ID, "username": "mealy_process_test_bot", "bot": true},
        "content": content,
        "nonce": nonce,
        "type": 0,
        "attachments": [],
        "timestamp": "2026-07-13T00:00:00.000000+00:00",
        "tts": false,
        "mention_everyone": false,
        "mentions": [],
        "mention_roles": [],
        "embeds": [],
        "pinned": false
    });
    state
        .0
        .nonce_messages
        .lock()
        .expect("nonce lock")
        .insert(nonce, message.clone());
    state
        .0
        .sent_contents
        .lock()
        .expect("sent contents lock")
        .push(content);
    state
        .0
        .messages
        .lock()
        .expect("messages lock")
        .push(message.clone());
    Json(message).into_response()
}

fn assert_discord_headers(headers: &HeaderMap) {
    assert_eq!(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        Some(format!("Bot {BOT_TOKEN}").as_str())
    );
    assert!(
        headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("DiscordBot ("))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn discord_dm_is_allowlisted_restart_safe_rate_limited_and_revocable() {
    let discord_state = DiscordApiState::default();
    let (discord_api_url, discord_server) = spawn_discord_api(discord_state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("HTTP client");
    let mut daemon = Daemon::spawn(home.path(), &discord_api_url);
    let connection = wait_until_ready(&client, home.path()).await;
    let created: DiscordChannelResponse = authorized_post(
        &client,
        &connection,
        "/v1/channels/discord",
        &CreateDiscordChannelRequest {
            api_version: API_VERSION.to_owned(),
            bot_token: BOT_TOKEN.to_owned(),
            discord_user_id: HUMAN_USER_ID.to_owned(),
            discord_channel_id: DM_CHANNEL_ID.to_owned(),
        },
    )
    .await;
    assert_eq!(created.status, DiscordChannelStatusResponse::Active);
    assert_eq!(created.bot_user_id, BOT_USER_ID);
    assert_eq!(created.bot_username, "mealy_process_test_bot");
    assert_eq!(created.after_message_id.as_deref(), Some("1"));
    assert_eq!(discord_state.0.current_user_calls.load(Ordering::SeqCst), 1);
    assert!(!database_contains(home.path(), BOT_TOKEN.as_bytes()));
    let credential_path = home
        .path()
        .join("provider-secrets")
        .join(format!("discord.{}.key", created.binding_id));
    assert!(credential_path.is_file());

    let listed: DiscordChannelsResponse =
        authorized_get(&client, &connection, "/v1/channels/discord").await;
    assert_eq!(listed.channels, vec![created.clone()]);
    let first_id =
        discord_state.push_human_message(HUMAN_USER_ID, "hello from Discord @everyone", &[]);
    wait_for_cursor(&client, &connection, &created.binding_id, &first_id).await;
    wait_for_sent_message(&discord_state, "Mealy accepted your message.").await;
    wait_for_sent_prefix(&discord_state, "Mealy (succeeded):").await;
    assert_eq!(session_inbox_count(home.path(), &created.session_id), 1);
    let local_search: SessionSearchResponse = authorized_get(
        &client,
        &connection,
        "/v1/sessions/search?query=hello%20from%20Discord&limit=20",
    )
    .await;
    assert!(
        local_search.hits.is_empty(),
        "local transcript search crossed into a Discord binding"
    );
    let requests = discord_state
        .0
        .sent_requests
        .lock()
        .expect("sent request lock")
        .clone();
    assert!(
        requests.len() >= 3,
        "rate-limited outbox request was not retried"
    );
    let mut nonce_counts = BTreeMap::<String, usize>::new();
    for request in &requests {
        *nonce_counts
            .entry(request["nonce"].as_str().expect("request nonce").to_owned())
            .or_default() += 1;
    }
    assert!(
        nonce_counts.values().any(|count| *count >= 2),
        "rate-limited delivery did not reuse its deterministic nonce"
    );
    assert_eq!(requests[0]["allowed_mentions"]["parse"], json!([]));

    daemon.hard_kill();
    fs::remove_file(home.path().join("connection.json")).expect("remove stale descriptor");
    let mut restarted_daemon = Daemon::spawn(home.path(), &discord_api_url);
    let restarted = wait_until_ready(&client, home.path()).await;
    sleep(Duration::from_millis(1_500)).await;
    assert_eq!(session_inbox_count(home.path(), &created.session_id), 1);
    assert!(
        discord_state
            .0
            .poll_cursors
            .lock()
            .expect("cursor lock")
            .iter()
            .any(Option::is_some)
    );

    let attacker_id = discord_state.push_human_message("7999", "unauthorized sender", &[]);
    for _ in 0..104 {
        let _ = discord_state.push_human_message("7999", "backlog attacker", &[]);
    }
    let valid_id =
        discord_state.push_human_message(HUMAN_USER_ID, "/interrupt replace the task", &[]);
    wait_for_cursor(&client, &restarted, &created.binding_id, &valid_id).await;
    assert_eq!(session_inbox_count(home.path(), &created.session_id), 2);
    assert_eq!(
        ignored_message_reason(home.path(), &created.binding_id, &attacker_id),
        "sender_not_allowed"
    );

    let attachment_id = discord_state.push_human_message(
        HUMAN_USER_ID,
        "review attachment",
        &[json!({"id": "1", "filename": "secret.txt"})],
    );
    wait_for_cursor(&client, &restarted, &created.binding_id, &attachment_id).await;
    assert_eq!(
        ignored_message_reason(home.path(), &created.binding_id, &attachment_id),
        "unsupported_attachment"
    );
    assert_eq!(session_inbox_count(home.path(), &created.session_id), 2);

    let revoked: DiscordChannelResponse = authorized_post(
        &client,
        &restarted,
        &format!("/v1/channels/discord/{}/revoke", created.binding_id),
        &RevokeDiscordChannelRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: 0,
        },
    )
    .await;
    assert_eq!(revoked.status, DiscordChannelStatusResponse::Revoked);
    assert_eq!(revoked.revision, 1);
    assert!(!credential_path.exists());
    let _after_revocation =
        discord_state.push_human_message(HUMAN_USER_ID, "after revocation", &[]);
    sleep(Duration::from_millis(1_500)).await;
    assert_eq!(session_inbox_count(home.path(), &created.session_id), 2);

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
    discord_server.abort();
}

async fn spawn_discord_api(state: DiscordApiState) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Discord API listener");
    let address = listener.local_addr().expect("Discord API address");
    let app = Router::new()
        .route("/users/@me", get(current_user))
        .route("/channels/{channel_id}", get(channel))
        .route(
            "/channels/{channel_id}/messages",
            get(get_messages).post(create_message),
        )
        .with_state(state);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("Discord API server");
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
    expected: &str,
) -> DiscordChannelResponse {
    let expected = expected.parse::<u64>().expect("expected snowflake");
    let deadline = Instant::now() + CHANNEL_TIMEOUT;
    loop {
        let channel: DiscordChannelResponse = authorized_get(
            client,
            connection,
            &format!("/v1/channels/discord/{binding_id}"),
        )
        .await;
        if channel
            .after_message_id
            .as_deref()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|cursor| cursor >= expected)
        {
            return channel;
        }
        assert!(Instant::now() < deadline, "Discord cursor did not advance");
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_sent_message(state: &DiscordApiState, expected: &str) {
    let deadline = Instant::now() + CHANNEL_TIMEOUT;
    loop {
        if state
            .sent_contents()
            .iter()
            .any(|message| message == expected)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Discord message was not delivered"
        );
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_sent_prefix(state: &DiscordApiState, expected: &str) {
    let deadline = Instant::now() + CHANNEL_TIMEOUT;
    loop {
        if state
            .sent_contents()
            .iter()
            .any(|message| message.starts_with(expected))
        {
            return;
        }
        assert!(Instant::now() < deadline, "Discord final was not delivered");
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

fn ignored_message_reason(home: &Path, binding_id: &str, message_id: &str) -> String {
    rusqlite::Connection::open(home.join("mealy.sqlite3"))
        .expect("open database")
        .query_row(
            "SELECT ignore_reason FROM discord_message_receipt \
             WHERE binding_id = ?1 AND message_id = ?2",
            rusqlite::params![binding_id, message_id],
            |row| row.get(0),
        )
        .expect("ignored Discord message reason")
}

fn database_contains(home: &Path, needle: &[u8]) -> bool {
    fs::read(home.join("mealy.sqlite3"))
        .expect("read database")
        .windows(needle.len())
        .any(|window| window == needle)
}
