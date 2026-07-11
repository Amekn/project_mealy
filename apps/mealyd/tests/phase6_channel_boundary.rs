//! Public-API proof for signed ingress, replay defense, revocation, and durable callback delivery.

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mealy_application::{sign_webhook, verify_webhook_signature};
use mealy_domain::ChannelBindingId;
use mealy_protocol::{
    API_VERSION, CreateWebhookChannelRequest, CreateWebhookChannelResponse, DeliveryMode,
    InputAdmissionResponse, LocalConnectionInfo, ReadinessResponse, RevokeWebhookChannelRequest,
    SignedWebhookInputRequest, WebhookChannelResponse, WebhookChannelStatusResponse,
};
use reqwest::{Client, Response, StatusCode as ClientStatusCode};
use std::{
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};
use tempfile::TempDir;
use tokio::{
    net::TcpListener,
    task::JoinHandle,
    time::{Instant, sleep},
};

const READY_TIMEOUT: Duration = Duration::from_secs(15);
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(15);

struct Daemon {
    child: Child,
}

impl Daemon {
    fn spawn(home: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_mealyd"))
            .arg("--home")
            .arg(home)
            .arg("--promotion-delay-ms")
            .arg("60000")
            .arg("--agent-delay-ms")
            .arg("60000")
            .arg("--outbox-delay-ms")
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
        assert!(!status.success());
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
struct CallbackState(Arc<CallbackInner>);

struct CallbackInner {
    authority: Mutex<Option<(ChannelBindingId, [u8; 32])>>,
    attempts: Mutex<Vec<CallbackAttempt>>,
    accepting: AtomicBool,
}

#[derive(Clone, Debug)]
struct CallbackAttempt {
    delivery_id: String,
    topic: String,
    signature_valid: bool,
    accepted: bool,
}

impl CallbackState {
    fn new() -> Self {
        Self(Arc::new(CallbackInner {
            authority: Mutex::new(None),
            attempts: Mutex::new(Vec::new()),
            accepting: AtomicBool::new(false),
        }))
    }

    fn configure(&self, binding_id: ChannelBindingId, secret: [u8; 32]) {
        *self.0.authority.lock().expect("callback authority lock") = Some((binding_id, secret));
    }

    fn attempts(&self) -> Vec<CallbackAttempt> {
        self.0
            .attempts
            .lock()
            .expect("callback attempts lock")
            .clone()
    }
}

async fn callback_handler(
    State(state): State<CallbackState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let field = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let delivery_id = field("x-mealy-delivery-id").unwrap_or_default();
    let topic = field("x-mealy-topic").unwrap_or_default();
    let timestamp = field("x-mealy-timestamp").and_then(|value| value.parse::<i64>().ok());
    let nonce = field("x-mealy-nonce");
    let signature = field("x-mealy-signature");
    let authority = *state.0.authority.lock().expect("callback authority lock");
    let signature_valid = authority
        .zip(timestamp)
        .zip(nonce.as_deref())
        .zip(signature.as_deref())
        .is_some_and(|((((binding_id, secret), timestamp), nonce), signature)| {
            verify_webhook_signature(&secret, binding_id, timestamp, nonce, &body, signature)
                .is_ok()
        });
    let accepted = signature_valid && state.0.accepting.load(Ordering::SeqCst);
    state
        .0
        .attempts
        .lock()
        .expect("callback attempts lock")
        .push(CallbackAttempt {
            delivery_id,
            topic,
            signature_valid,
            accepted,
        });
    if !signature_valid {
        StatusCode::BAD_REQUEST
    } else if accepted {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn signed_channel_deduplicates_replay_survives_restart_delivers_and_revokes() {
    let callback_state = CallbackState::new();
    let (callback_url, callback_server) = spawn_callback(callback_state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("HTTP client");
    let mut daemon = Daemon::spawn(home.path());
    let connection = wait_until_ready(&client, home.path()).await;
    let created: CreateWebhookChannelResponse = authorized_post(
        &client,
        &connection,
        "/v1/channels/webhooks",
        &CreateWebhookChannelRequest {
            api_version: API_VERSION.to_owned(),
            external_subject: "platform-user-7".to_owned(),
            callback_url,
        },
    )
    .await;
    assert_eq!(created.channel.status, WebhookChannelStatusResponse::Active);
    assert_eq!(created.channel.revision, 0);
    let binding_id = ChannelBindingId::from_str(&created.channel.binding_id).expect("binding ID");
    let secret = URL_SAFE_NO_PAD
        .decode(&created.signing_secret)
        .expect("base64 signing secret");
    let secret = <[u8; 32]>::try_from(secret).expect("32-byte signing secret");
    callback_state.configure(binding_id, secret);
    assert_eq!(created.signature_algorithm, "hmac-sha256");
    assert!(!database_contains(
        home.path(),
        created.signing_secret.as_bytes()
    ));

    let request = SignedWebhookInputRequest {
        api_version: API_VERSION.to_owned(),
        delivery_id: "platform-delivery-1".to_owned(),
        subject: "platform-user-7".to_owned(),
        content: "hello from the signed channel".to_owned(),
        delivery_mode: DeliveryMode::Queue,
    };
    let body = serde_json::to_vec(&request).expect("signed body");
    let timestamp = now_ms();
    let signature =
        sign_webhook(&secret, binding_id, timestamp, "nonce-1", &body).expect("inbound signature");
    let accepted = signed_post(
        &client,
        &connection,
        binding_id,
        timestamp,
        "nonce-1",
        &signature,
        body.clone(),
    )
    .await;
    assert_eq!(accepted.status(), ClientStatusCode::OK);
    let accepted = accepted
        .json::<InputAdmissionResponse>()
        .await
        .expect("admission receipt");
    assert!(!accepted.duplicate);
    assert_eq!(accepted.session_id, created.channel.session_id);

    let duplicate = signed_post(
        &client,
        &connection,
        binding_id,
        timestamp,
        "nonce-1",
        &signature,
        body,
    )
    .await;
    assert_eq!(duplicate.status(), ClientStatusCode::OK);
    let duplicate = duplicate
        .json::<InputAdmissionResponse>()
        .await
        .expect("duplicate receipt");
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.inbox_entry_id, accepted.inbox_entry_id);
    assert_eq!(duplicate.outbox_id, accepted.outbox_id);

    let replay_request = SignedWebhookInputRequest {
        delivery_id: "platform-delivery-2".to_owned(),
        content: "nonce replay".to_owned(),
        ..request.clone()
    };
    let replay_body = serde_json::to_vec(&replay_request).expect("replay body");
    let replay_signature = sign_webhook(&secret, binding_id, timestamp, "nonce-1", &replay_body)
        .expect("replay signature");
    assert_eq!(
        signed_post(
            &client,
            &connection,
            binding_id,
            timestamp,
            "nonce-1",
            &replay_signature,
            replay_body,
        )
        .await
        .status(),
        ClientStatusCode::CONFLICT
    );

    let forged_body = serde_json::to_vec(&SignedWebhookInputRequest {
        delivery_id: "platform-delivery-forged".to_owned(),
        ..request.clone()
    })
    .expect("forged body");
    assert_eq!(
        signed_post(
            &client,
            &connection,
            binding_id,
            timestamp,
            "nonce-forged",
            &"f".repeat(64),
            forged_body,
        )
        .await
        .status(),
        ClientStatusCode::FORBIDDEN
    );

    let stale_timestamp = timestamp - 600_000;
    let stale_body = serde_json::to_vec(&SignedWebhookInputRequest {
        delivery_id: "platform-delivery-stale".to_owned(),
        ..request.clone()
    })
    .expect("stale body");
    let stale_signature = sign_webhook(
        &secret,
        binding_id,
        stale_timestamp,
        "nonce-stale",
        &stale_body,
    )
    .expect("stale signature");
    assert_eq!(
        signed_post(
            &client,
            &connection,
            binding_id,
            stale_timestamp,
            "nonce-stale",
            &stale_signature,
            stale_body,
        )
        .await
        .status(),
        ClientStatusCode::FORBIDDEN
    );

    let wrong_subject_body = serde_json::to_vec(&SignedWebhookInputRequest {
        delivery_id: "platform-delivery-wrong-subject".to_owned(),
        subject: "platform-user-8".to_owned(),
        ..request.clone()
    })
    .expect("wrong-subject body");
    let wrong_subject_signature = sign_webhook(
        &secret,
        binding_id,
        timestamp,
        "nonce-wrong-subject",
        &wrong_subject_body,
    )
    .expect("wrong-subject signature");
    assert_eq!(
        signed_post(
            &client,
            &connection,
            binding_id,
            timestamp,
            "nonce-wrong-subject",
            &wrong_subject_signature,
            wrong_subject_body,
        )
        .await
        .status(),
        ClientStatusCode::FORBIDDEN
    );

    wait_for_callback_attempts(&callback_state, 1).await;
    daemon.hard_kill();
    fs::remove_file(home.path().join("connection.json"))
        .expect("stale endpoint descriptor should be removable");
    callback_state.0.accepting.store(true, Ordering::SeqCst);
    let _restarted_daemon = Daemon::spawn(home.path());
    let restarted = wait_until_ready(&client, home.path()).await;
    wait_for_successful_callback(&callback_state).await;
    let attempts = callback_state.attempts();
    assert!(attempts.len() >= 2, "{attempts:?}");
    assert!(attempts.iter().all(|attempt| attempt.signature_valid));
    assert!(
        attempts
            .iter()
            .all(|attempt| attempt.topic == "session.input_acknowledgement")
    );
    assert!(
        attempts
            .iter()
            .all(|attempt| attempt.delivery_id == accepted.outbox_id)
    );

    let revoked: WebhookChannelResponse = authorized_post(
        &client,
        &restarted,
        &format!("/v1/channels/webhooks/{binding_id}/revoke"),
        &RevokeWebhookChannelRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: 0,
        },
    )
    .await;
    assert_eq!(revoked.status, WebhookChannelStatusResponse::Revoked);
    assert_eq!(revoked.revision, 1);
    assert!(
        !home
            .path()
            .join("channel-secrets")
            .join(format!("{binding_id}.key"))
            .exists()
    );

    let after_revoke_body = serde_json::to_vec(&SignedWebhookInputRequest {
        delivery_id: "platform-delivery-after-revoke".to_owned(),
        ..request
    })
    .expect("post-revocation body");
    let after_revoke_timestamp = now_ms();
    let after_revoke_signature = sign_webhook(
        &secret,
        binding_id,
        after_revoke_timestamp,
        "nonce-after-revoke",
        &after_revoke_body,
    )
    .expect("post-revocation signature");
    assert_eq!(
        signed_post(
            &client,
            &restarted,
            binding_id,
            after_revoke_timestamp,
            "nonce-after-revoke",
            &after_revoke_signature,
            after_revoke_body,
        )
        .await
        .status(),
        ClientStatusCode::FORBIDDEN
    );
    callback_server.abort();
}

async fn spawn_callback(state: CallbackState) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("callback listener");
    let address = listener.local_addr().expect("callback address");
    let app = Router::new()
        .route("/callback", post(callback_handler))
        .with_state(state);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("callback server");
    });
    (format!("http://{address}/callback"), handle)
}

async fn signed_post(
    client: &Client,
    connection: &LocalConnectionInfo,
    binding_id: ChannelBindingId,
    timestamp_ms: i64,
    nonce: &str,
    signature: &str,
    body: Vec<u8>,
) -> Response {
    client
        .post(format!(
            "{}/v1/channels/webhooks/{binding_id}/deliveries",
            connection.base_url
        ))
        .header("content-type", "application/json")
        .header("x-mealy-timestamp", timestamp_ms.to_string())
        .header("x-mealy-nonce", nonce)
        .header("x-mealy-signature", signature)
        .body(body)
        .send()
        .await
        .expect("signed webhook POST")
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

async fn wait_for_callback_attempts(state: &CallbackState, count: usize) {
    let deadline = Instant::now() + DELIVERY_TIMEOUT;
    loop {
        if state.attempts().len() >= count {
            return;
        }
        assert!(Instant::now() < deadline, "callback was not attempted");
        sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_successful_callback(state: &CallbackState) {
    let deadline = Instant::now() + DELIVERY_TIMEOUT;
    loop {
        if state.attempts().iter().any(|attempt| attempt.accepted) {
            return;
        }
        assert!(Instant::now() < deadline, "durable callback did not resume");
        sleep(Duration::from_millis(20)).await;
    }
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
    let status = response.status();
    let bytes = response.bytes().await.expect("response body");
    assert_eq!(
        status,
        ClientStatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).expect("versioned JSON response")
}

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("current time")
            .as_millis(),
    )
    .expect("current epoch milliseconds")
}

fn database_contains(home: &Path, needle: &[u8]) -> bool {
    fs::read(home.join("mealy.sqlite3"))
        .expect("read database")
        .windows(needle.len())
        .any(|window| window == needle)
}
