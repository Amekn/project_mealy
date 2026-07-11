//! Real-process conformance proof for the digest-pinned extension host boundary.

#![cfg(target_os = "linux")]

use mealy_application::{
    CancellationProbe, EXTENSION_POLICY_VERSION, EXTENSION_RPC_VERSION, ExtensionDispatchRequest,
    ExtensionGrant, ExtensionHost, ExtensionHostError, ExtensionRpcRequest, extension_grant_digest,
    inspect_extension_manifest, sha256_digest,
};
use mealy_domain::{
    ChannelBindingId, EXTENSION_MANIFEST_SCHEMA_VERSION, EffectClass, ExtensionCapabilityKind,
    ExtensionCapabilityManifest, ExtensionCompatibility, ExtensionEntryPoint, ExtensionFieldSchema,
    ExtensionGrantId, ExtensionHealthCheck, ExtensionId, ExtensionInvocationId, ExtensionKind,
    ExtensionManifest, ExtensionObjectSchema, ExtensionPermissions, ExtensionRuntimeFile,
    ExtensionScalarType, ExtensionShutdownBehavior, ExtensionShutdownMode, PrincipalId, RiskClass,
};
use mealy_infrastructure::{LinuxBubblewrapExtensionHost, inspect_extension_package};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

const BUBBLEWRAP_PATH: &str = "/usr/bin/bwrap";
static INVOCATION_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct NeverCancelled;

impl CancellationProbe for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[test]
fn supervised_extension_is_schema_bound_isolated_and_survives_worker_failure() {
    let fixture = Fixture::new();
    let host = LinuxBubblewrapExtensionHost::new(BUBBLEWRAP_PATH, fixture.package.clone())
        .expect("construct isolated extension host");

    let health = host
        .invoke(&fixture.dispatch("health", json!({})), &NeverCancelled)
        .expect("health response");
    assert_eq!(health.output, json!({"status": "ok"}));

    let stats = host
        .invoke(
            &fixture.dispatch("text_stats", json!({"text": "one two three"})),
            &NeverCancelled,
        )
        .expect("text stats response");
    assert_eq!(stats.output["byteCount"], 13);
    assert_eq!(stats.output["wordCount"], 3);
    assert_eq!(stats.output["sha256"], sha256_digest(b"one two three"));

    let security = host
        .invoke(
            &fixture.dispatch("security_probe", json!({})),
            &NeverCancelled,
        )
        .expect("security probe response");
    assert_eq!(security.output["ambientEnvironmentCount"], 0);
    assert_eq!(security.output["hostSecretVisible"], false);
    assert_eq!(security.output["outsideGrantWritable"], false);
    assert_eq!(security.output["daemonLoopbackReachable"], false);

    assert_eq!(
        host.invoke(
            &fixture.dispatch("forge_response", json!({})),
            &NeverCancelled,
        ),
        Err(ExtensionHostError::InvalidResponse)
    );
    assert!(matches!(
        host.invoke(&fixture.dispatch("crash", json!({})), &NeverCancelled),
        Err(ExtensionHostError::ProcessFailure(_))
    ));
    assert_eq!(
        host.invoke(&fixture.dispatch("health", json!({})), &NeverCancelled)
            .expect("daemon-side host survives extension crash")
            .output,
        json!({"status": "ok"})
    );
}

#[test]
fn package_inspection_fails_closed_on_executable_or_runtime_digest_drift() {
    let worker = worker_path();
    let mut manifest = sample_manifest(&worker);
    manifest.entry_point.executable_digest = "f".repeat(64);
    let bytes = serde_json::to_vec(&manifest).expect("manifest JSON");
    let inspection = inspect_extension_manifest(&bytes, &sha256_digest(&bytes))
        .expect("data-only manifest remains structurally valid");
    assert_eq!(
        inspect_extension_package(inspection, worker.parent().expect("worker parent")),
        Err(ExtensionHostError::IdentityMismatch)
    );

    let mut manifest = sample_manifest(&worker);
    manifest.entry_point.runtime_files[0].digest = "e".repeat(64);
    let bytes = serde_json::to_vec(&manifest).expect("manifest JSON");
    let inspection =
        inspect_extension_manifest(&bytes, &sha256_digest(&bytes)).expect("runtime pin manifest");
    assert_eq!(
        inspect_extension_package(inspection, worker.parent().expect("worker parent")),
        Err(ExtensionHostError::IdentityMismatch)
    );
}

struct Fixture {
    ownership: mealy_application::OwnershipContext,
    manifest: ExtensionManifest,
    manifest_digest: String,
    grant: ExtensionGrant,
    package: mealy_infrastructure::InstalledExtensionPackage,
}

impl Fixture {
    fn new() -> Self {
        let worker = worker_path();
        let manifest = sample_manifest(&worker);
        let bytes = serde_json::to_vec(&manifest).expect("manifest JSON");
        let manifest_digest = sha256_digest(&bytes);
        let inspection = inspect_extension_manifest(&bytes, &manifest_digest).expect("manifest");
        let package =
            inspect_extension_package(inspection, worker.parent().expect("fixture worker parent"))
                .expect("inspect package without executing it");
        let principal_id = PrincipalId::new();
        let ownership =
            mealy_application::OwnershipContext::new(principal_id, ChannelBindingId::new());
        let grant = ExtensionGrant {
            grant_id: ExtensionGrantId::new(),
            extension_id: manifest.extension_id,
            manifest_digest: manifest_digest.clone(),
            capability_ids: manifest
                .capabilities
                .iter()
                .map(|capability| capability.capability_id.clone())
                .collect(),
            mounts: Vec::new(),
            network_destinations: BTreeSet::new(),
            secret_references: BTreeSet::new(),
            allow_process_spawn: false,
            policy_version: EXTENSION_POLICY_VERSION.to_owned(),
            issued_by_principal_id: principal_id,
            issued_at_ms: 1,
        };
        grant
            .validate(&manifest, ownership)
            .expect("least-authority grant");
        Self {
            ownership,
            manifest,
            manifest_digest,
            grant,
            package,
        }
    }

    fn dispatch(&self, capability_id: &str, input: Value) -> ExtensionDispatchRequest {
        let sequence = INVOCATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let request = ExtensionRpcRequest {
            protocol_version: EXTENSION_RPC_VERSION.to_owned(),
            invocation_id: ExtensionInvocationId::new(),
            extension_id: self.manifest.extension_id,
            manifest_digest: self.manifest_digest.clone(),
            grant_digest: extension_grant_digest(&self.grant).expect("grant digest"),
            capability_id: capability_id.to_owned(),
            input_digest: sha256_digest(
                &serde_json::to_vec(&input).expect("canonical extension input"),
            ),
            input,
        };
        ExtensionDispatchRequest {
            ownership: self.ownership,
            manifest: self.manifest.clone(),
            manifest_digest: self.manifest_digest.clone(),
            grant: self.grant.clone(),
            rpc_request: request,
            capability_token: format!("extension-test-capability-{sequence:020}-one-use-boundary"),
        }
    }
}

fn sample_manifest(worker: &Path) -> ExtensionManifest {
    let executable = worker
        .file_name()
        .expect("worker filename")
        .to_string_lossy()
        .into_owned();
    ExtensionManifest {
        schema_version: EXTENSION_MANIFEST_SCHEMA_VERSION,
        extension_id: ExtensionId::new(),
        name: "dev.mealy.sample-text".to_owned(),
        publisher: "dev.mealy".to_owned(),
        version: "1.0.0".to_owned(),
        kinds: BTreeSet::from([ExtensionKind::ToolService]),
        compatibility: ExtensionCompatibility {
            minimum_host_api: 1,
            maximum_host_api: 1,
        },
        entry_point: ExtensionEntryPoint {
            executable,
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
    ExtensionObjectSchema {
        properties: BTreeMap::new(),
        required: BTreeSet::new(),
        additional_properties: false,
        maximum_serialized_bytes: 2,
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

fn schema(
    properties: BTreeMap<String, ExtensionFieldSchema>,
    required: impl IntoIterator<Item = &'static str>,
    maximum_serialized_bytes: u64,
) -> ExtensionObjectSchema {
    ExtensionObjectSchema {
        properties,
        required: required.into_iter().map(str::to_owned).collect(),
        additional_properties: false,
        maximum_serialized_bytes,
    }
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

fn worker_path() -> PathBuf {
    fs::canonicalize(env!("CARGO_BIN_EXE_mealy-fixture-worker"))
        .expect("fixture worker canonical path")
}

fn digest_file(path: &Path) -> String {
    sha256_digest(&fs::read(path).expect("read digest-pinned file"))
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
