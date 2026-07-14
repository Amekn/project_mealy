//! Public-API and real-process proof for the digest-pinned extension boundary.

#![cfg(target_os = "linux")]

use mealy_application::sha256_digest;
use mealy_domain::{
    EXTENSION_MANIFEST_SCHEMA_VERSION, EffectClass, ExtensionCapabilityKind,
    ExtensionCapabilityManifest, ExtensionCompatibility, ExtensionEntryPoint, ExtensionFieldSchema,
    ExtensionHealthCheck, ExtensionId, ExtensionKind, ExtensionManifest, ExtensionObjectSchema,
    ExtensionPermissions, ExtensionRuntimeFile, ExtensionScalarType, ExtensionShutdownBehavior,
    ExtensionShutdownMode, RiskClass,
};
use mealy_protocol::{
    API_VERSION, EnableExtensionRequest, ExtensionFilesystemAccessCommand,
    ExtensionInvocationResponse, ExtensionInvocationStatusResponse, ExtensionLifecycleRequest,
    ExtensionMountGrantCommand, ExtensionResponse, ExtensionStatusResponse,
    InstallExtensionRequest, InvokeExtensionRequest, LocalConnectionInfo, ReadinessResponse,
    StageExtensionManifestRequest,
};
use reqwest::{Client, StatusCode};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tempfile::TempDir;
use tokio::time::{Instant, sleep};

const READY_TIMEOUT: Duration = Duration::from_secs(15);

struct Daemon {
    child: Child,
}

impl Daemon {
    fn spawn(home: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_mealyd"))
            .arg("--home")
            .arg(home)
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn extension_lifecycle_is_isolated_durable_upgradeable_and_terminally_revocable() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        eprintln!("skipping extension process proof because Bubblewrap is unavailable");
        return;
    }
    let home = TempDir::new().expect("temporary daemon home");
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("HTTP client");
    let mut daemon = Daemon::spawn(home.path());
    let connection = wait_until_ready(&client, home.path()).await;
    let worker = sample_extension_path();
    let extension_id = ExtensionId::new();
    let manifest_v1 = sample_manifest(extension_id, "1.0.0", &worker);
    let manifest_json_v1 = serde_json::to_string(&manifest_v1).expect("manifest JSON");
    let manifest_digest_v1 = sha256_digest(manifest_json_v1.as_bytes());
    let package_root = worker
        .parent()
        .expect("sample extension parent")
        .to_string_lossy()
        .into_owned();

    let installed: ExtensionResponse = authorized_post(
        &client,
        &connection,
        "/v1/extensions",
        &InstallExtensionRequest {
            api_version: API_VERSION.to_owned(),
            manifest_json: manifest_json_v1,
            manifest_digest: manifest_digest_v1.clone(),
            installation_root: package_root.clone(),
        },
    )
    .await;
    assert_eq!(installed.status, ExtensionStatusResponse::Installed);
    assert_eq!(installed.revision, 0);
    assert_eq!(installed.manifest_digest, manifest_digest_v1);
    assert!(installed.active_grant.is_none());
    let public_projection = serde_json::to_string(&installed).expect("public extension JSON");
    assert!(
        !public_projection.contains(&package_root),
        "package root must not cross the public projection"
    );

    let mut private_mount = enable_request(0);
    private_mount.mounts.push(ExtensionMountGrantCommand {
        name: "private-state".to_owned(),
        access: ExtensionFilesystemAccessCommand::ReadOnly,
        host_path: home.path().display().to_string(),
        sandbox_path: "/documents".to_owned(),
    });
    assert_eq!(
        post_status(
            &client,
            &connection,
            &format!("/v1/extensions/{extension_id}/enable"),
            &private_mount,
        )
        .await,
        StatusCode::BAD_REQUEST
    );

    let enabled: ExtensionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/extensions/{extension_id}/enable"),
        &enable_request(0),
    )
    .await;
    assert_eq!(enabled.status, ExtensionStatusResponse::Enabled);
    assert_eq!(enabled.revision, 1);
    assert!(enabled.last_healthy_at_ms.is_some());
    let first_grant = enabled
        .active_grant
        .as_ref()
        .expect("enabled extension grant")
        .grant_id
        .clone();

    let stats = invoke(
        &client,
        &connection,
        extension_id,
        "text_stats",
        serde_json::json!({"text": "one two three"}),
    )
    .await;
    assert_eq!(stats.status, ExtensionInvocationStatusResponse::Succeeded);
    assert_eq!(
        stats
            .output
            .as_ref()
            .and_then(|value| value["wordCount"].as_i64()),
        Some(3)
    );

    let security = invoke(
        &client,
        &connection,
        extension_id,
        "security_probe",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        security.status,
        ExtensionInvocationStatusResponse::Succeeded
    );
    let security_output = security.output.expect("security probe output");
    assert_eq!(security_output["ambientEnvironmentCount"], 0);
    assert_eq!(security_output["hostSecretVisible"], false);
    assert_eq!(security_output["outsideGrantWritable"], false);
    assert_eq!(security_output["daemonLoopbackReachable"], false);

    let forged = invoke(
        &client,
        &connection,
        extension_id,
        "forge_response",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(forged.status, ExtensionInvocationStatusResponse::Failed);
    assert_eq!(forged.error_class.as_deref(), Some("invalid_response"));
    assert!(forged.output.is_none());

    let crashed = invoke(
        &client,
        &connection,
        extension_id,
        "crash",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(crashed.status, ExtensionInvocationStatusResponse::Failed);
    assert_eq!(crashed.error_class.as_deref(), Some("process_failure"));
    assert_ready(&client, &connection).await;
    assert_eq!(
        invoke(
            &client,
            &connection,
            extension_id,
            "text_stats",
            serde_json::json!({"text": "daemon survived"}),
        )
        .await
        .status,
        ExtensionInvocationStatusResponse::Succeeded
    );

    let disabled: ExtensionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/extensions/{extension_id}/disable"),
        &ExtensionLifecycleRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: 1,
        },
    )
    .await;
    assert_eq!(disabled.status, ExtensionStatusResponse::Disabled);
    assert!(disabled.active_grant.is_none());
    assert_eq!(
        post_status(
            &client,
            &connection,
            &format!("/v1/extensions/{extension_id}/invoke"),
            &InvokeExtensionRequest {
                api_version: API_VERSION.to_owned(),
                capability_id: "health".to_owned(),
                input: serde_json::json!({}),
            },
        )
        .await,
        StatusCode::CONFLICT
    );

    let reenabled: ExtensionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/extensions/{extension_id}/enable"),
        &enable_request(2),
    )
    .await;
    assert_ne!(
        reenabled
            .active_grant
            .as_ref()
            .expect("fresh grant")
            .grant_id,
        first_grant
    );

    let manifest_v2 = sample_manifest(extension_id, "1.1.0", &worker);
    let manifest_json_v2 = serde_json::to_string(&manifest_v2).expect("upgrade manifest JSON");
    let manifest_digest_v2 = sha256_digest(manifest_json_v2.as_bytes());
    let staged: ExtensionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/extensions/{extension_id}/stage"),
        &StageExtensionManifestRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: 3,
            manifest_json: manifest_json_v2,
            manifest_digest: manifest_digest_v2.clone(),
            installation_root: package_root,
        },
    )
    .await;
    assert_eq!(staged.status, ExtensionStatusResponse::Installed);
    assert_eq!(staged.revision, 4);
    assert_eq!(staged.manifest_history.len(), 2);
    assert!(staged.active_grant.is_none());
    let upgraded: ExtensionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/extensions/{extension_id}/enable"),
        &enable_request(4),
    )
    .await;
    assert_eq!(upgraded.manifest_digest, manifest_digest_v2);
    assert_eq!(upgraded.version, "1.1.0");

    let revoked: ExtensionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/extensions/{extension_id}/revoke"),
        &ExtensionLifecycleRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: 5,
        },
    )
    .await;
    assert_eq!(revoked.status, ExtensionStatusResponse::Revoked);
    assert!(revoked.active_grant.is_none());
    assert_eq!(
        post_status(
            &client,
            &connection,
            &format!("/v1/extensions/{extension_id}/enable"),
            &enable_request(6),
        )
        .await,
        StatusCode::CONFLICT
    );

    daemon.hard_kill();
    fs::remove_file(home.path().join("connection.json"))
        .expect("stale endpoint descriptor should be removable");
    let _restarted = Daemon::spawn(home.path());
    let restarted = wait_until_ready(&client, home.path()).await;
    let persisted: ExtensionResponse = authorized_get(
        &client,
        &restarted,
        &format!("/v1/extensions/{extension_id}"),
    )
    .await;
    assert_eq!(persisted.status, ExtensionStatusResponse::Revoked);
    assert_eq!(persisted.revision, 6);
    assert_eq!(persisted.manifest_history.len(), 2);
}

fn enable_request(expected_revision: u64) -> EnableExtensionRequest {
    EnableExtensionRequest {
        api_version: API_VERSION.to_owned(),
        expected_revision,
        capability_ids: vec![
            "health".to_owned(),
            "text_stats".to_owned(),
            "security_probe".to_owned(),
            "forge_response".to_owned(),
            "crash".to_owned(),
        ],
        mounts: Vec::new(),
        network_destinations: Vec::new(),
        secret_references: Vec::new(),
        allow_process_spawn: false,
    }
}

async fn invoke(
    client: &Client,
    connection: &LocalConnectionInfo,
    extension_id: ExtensionId,
    capability_id: &str,
    input: serde_json::Value,
) -> ExtensionInvocationResponse {
    authorized_post(
        client,
        connection,
        &format!("/v1/extensions/{extension_id}/invoke"),
        &InvokeExtensionRequest {
            api_version: API_VERSION.to_owned(),
            capability_id: capability_id.to_owned(),
            input,
        },
    )
    .await
}

fn sample_manifest(extension_id: ExtensionId, version: &str, worker: &Path) -> ExtensionManifest {
    ExtensionManifest {
        schema_version: EXTENSION_MANIFEST_SCHEMA_VERSION,
        extension_id,
        name: "dev.mealy.sample-text".to_owned(),
        publisher: "dev.mealy".to_owned(),
        version: version.to_owned(),
        kinds: BTreeSet::from([ExtensionKind::ToolService]),
        compatibility: ExtensionCompatibility {
            minimum_host_api: 1,
            maximum_host_api: 1,
        },
        entry_point: ExtensionEntryPoint {
            executable: worker
                .file_name()
                .expect("sample extension filename")
                .to_string_lossy()
                .into_owned(),
            executable_digest: digest_file(worker),
            runtime_files: runtime_files(worker),
        },
        capabilities: vec![
            capability(
                "health",
                ExtensionCapabilityKind::Health,
                empty_schema(),
                status_schema(),
            ),
            capability(
                "text_stats",
                ExtensionCapabilityKind::Tool,
                text_schema(),
                text_stats_schema(),
            ),
            capability(
                "security_probe",
                ExtensionCapabilityKind::Tool,
                empty_schema(),
                security_schema(),
            ),
            capability(
                "forge_response",
                ExtensionCapabilityKind::Tool,
                empty_schema(),
                status_schema(),
            ),
            capability(
                "crash",
                ExtensionCapabilityKind::Tool,
                empty_schema(),
                status_schema(),
            ),
        ],
        permissions: ExtensionPermissions::default(),
        health_check: ExtensionHealthCheck {
            capability_id: "health".to_owned(),
            timeout_ms: 1_000,
            interval_ms: 5_000,
        },
        migrations: Vec::new(),
        shutdown: ExtensionShutdownBehavior {
            mode: ExtensionShutdownMode::Terminate,
            capability_id: None,
            grace_period_ms: 1_000,
        },
    }
}

fn capability(
    capability_id: &str,
    kind: ExtensionCapabilityKind,
    input_schema: ExtensionObjectSchema,
    output_schema: ExtensionObjectSchema,
) -> ExtensionCapabilityManifest {
    ExtensionCapabilityManifest {
        capability_id: capability_id.to_owned(),
        kind,
        effect_class: EffectClass::ReadOnly,
        risk_class: RiskClass::Low,
        input_schema,
        output_schema,
        timeout_ms: 1_000,
        maximum_output_bytes: 16 * 1_024,
    }
}

fn empty_schema() -> ExtensionObjectSchema {
    schema(BTreeMap::new(), [], 2)
}

fn status_schema() -> ExtensionObjectSchema {
    schema(
        BTreeMap::from([("status".to_owned(), string_field(32))]),
        ["status"],
        64,
    )
}

fn text_schema() -> ExtensionObjectSchema {
    schema(
        BTreeMap::from([("text".to_owned(), string_field(8_192))]),
        ["text"],
        8_256,
    )
}

fn text_stats_schema() -> ExtensionObjectSchema {
    schema(
        BTreeMap::from([
            ("byteCount".to_owned(), integer_field()),
            ("sha256".to_owned(), string_field(64)),
            ("wordCount".to_owned(), integer_field()),
        ]),
        ["byteCount", "sha256", "wordCount"],
        256,
    )
}

fn security_schema() -> ExtensionObjectSchema {
    schema(
        BTreeMap::from([
            ("ambientEnvironmentCount".to_owned(), integer_field()),
            ("daemonLoopbackReachable".to_owned(), boolean_field()),
            ("hostSecretVisible".to_owned(), boolean_field()),
            ("outsideGrantWritable".to_owned(), boolean_field()),
        ]),
        [
            "ambientEnvironmentCount",
            "daemonLoopbackReachable",
            "hostSecretVisible",
            "outsideGrantWritable",
        ],
        256,
    )
}

fn schema<const N: usize>(
    properties: BTreeMap<String, ExtensionFieldSchema>,
    required: [&str; N],
    maximum_serialized_bytes: u64,
) -> ExtensionObjectSchema {
    ExtensionObjectSchema {
        properties,
        required: required.into_iter().map(str::to_owned).collect(),
        additional_properties: false,
        maximum_serialized_bytes,
    }
}

fn string_field(maximum: u64) -> ExtensionFieldSchema {
    ExtensionFieldSchema {
        value_type: ExtensionScalarType::String,
        maximum_length: Some(maximum),
        minimum_integer: None,
        maximum_integer: None,
    }
}

fn integer_field() -> ExtensionFieldSchema {
    ExtensionFieldSchema {
        value_type: ExtensionScalarType::Integer,
        maximum_length: None,
        minimum_integer: Some(0),
        maximum_integer: Some(i64::MAX),
    }
}

fn boolean_field() -> ExtensionFieldSchema {
    ExtensionFieldSchema {
        value_type: ExtensionScalarType::Boolean,
        maximum_length: None,
        minimum_integer: None,
        maximum_integer: None,
    }
}

fn sample_extension_path() -> PathBuf {
    fs::canonicalize(env!("CARGO_BIN_EXE_mealy-sample-extension"))
        .expect("sample extension canonical path")
}

fn digest_file(path: &Path) -> String {
    sha256_digest(&fs::read(path).expect("read digest-pinned extension file"))
}

fn runtime_files(worker: &Path) -> Vec<ExtensionRuntimeFile> {
    let output = Command::new("ldd")
        .arg(worker)
        .output()
        .expect("inspect sample extension runtime");
    assert!(output.status.success(), "ldd must inspect sample extension");
    let stdout = String::from_utf8(output.stdout).expect("ldd UTF-8 output");
    let mut files = BTreeMap::new();
    for line in stdout.lines() {
        let candidate = line.split_once("=>").map_or_else(
            || line.split_whitespace().next(),
            |(_, right)| right.split_whitespace().next(),
        );
        let Some(candidate) = candidate.filter(|value| value.starts_with('/')) else {
            continue;
        };
        files.insert(
            candidate.to_owned(),
            ExtensionRuntimeFile {
                host_path: candidate.to_owned(),
                sandbox_path: candidate.to_owned(),
                digest: digest_file(Path::new(candidate)),
            },
        );
    }
    assert!(!files.is_empty(), "sample extension requires runtime files");
    files.into_values().collect()
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

async fn assert_ready(client: &Client, connection: &LocalConnectionInfo) {
    let response = client
        .get(format!("{}/health/ready", connection.base_url))
        .bearer_auth(&connection.bearer_token)
        .send()
        .await
        .expect("readiness request");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .json::<ReadinessResponse>()
            .await
            .expect("readiness JSON")
            .ready
    );
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
    response.json().await.expect("versioned JSON response")
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
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).expect("versioned JSON response")
}

async fn post_status(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
    body: &impl serde::Serialize,
) -> StatusCode {
    client
        .post(format!("{}{path}", connection.base_url))
        .bearer_auth(&connection.bearer_token)
        .json(body)
        .send()
        .await
        .expect("authorized POST")
        .status()
}
