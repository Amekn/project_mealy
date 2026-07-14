//! Process-boundary proofs for governed, schema-pinned local MCP stdio tools.

use mealy_application::{
    CancellationProbe, McpServerConfig, McpToolGrant, ReadOnlyTool, ReadToolError, sha256_digest,
};
use mealy_infrastructure::{McpHostError, discover_mcp_stdio_server, load_mcp_read_tools};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{Duration, Instant},
};

const BUBBLEWRAP: &str = "/usr/bin/bwrap";

struct NeverCancelled;

impl CancellationProbe for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct DeadlineCancellation {
    started: Instant,
    after: Duration,
    observed: OnceLock<Instant>,
}

impl CancellationProbe for DeadlineCancellation {
    fn is_cancelled(&self) -> bool {
        let cancelled = self.started.elapsed() >= self.after;
        if cancelled {
            self.observed.get_or_init(Instant::now);
        }
        cancelled
    }
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mealy-mcp-fixture-server"))
}

fn launcher() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mealy-mcp-launcher"))
}

fn sandbox_available() -> bool {
    cfg!(target_os = "linux") && Path::new(BUBBLEWRAP).is_file()
}

fn fixture_digest() -> String {
    sha256_digest(&fs::read(fixture()).expect("fixture bytes"))
}

fn discovery(mode: &str) -> mealy_application::McpServerDiscovery {
    discover_mcp_stdio_server(
        BUBBLEWRAP,
        launcher(),
        "fixture",
        fixture(),
        &fixture_digest(),
        &[mode.to_owned()],
    )
    .expect("fixture discovery")
}

fn install_fixture(home: &Path, mode: &str, selected_tools: &[&str]) -> McpServerConfig {
    let discovered = discovery("good");
    let digest = fixture_digest();
    let relative = format!("mcp-servers/{digest}/server");
    let installed = home.join(&relative);
    fs::create_dir_all(installed.parent().expect("installed parent")).expect("server directory");
    fs::copy(fixture(), &installed).expect("install fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o700)).expect("permissions");
    }
    let grants = selected_tools
        .iter()
        .map(|name| {
            let tool = discovered.tool(name).expect("selected tool");
            McpToolGrant::new(tool.definition.clone(), 5_000, 128 * 1024).expect("tool grant")
        })
        .collect();
    McpServerConfig::new(
        "fixture".to_owned(),
        relative,
        digest,
        vec![mode.to_owned()],
        discovered.toolset_digest().expect("toolset digest"),
        true,
        grants,
    )
    .expect("server config")
}

#[test]
fn stdio_discovery_paginates_and_calls_through_empty_least_authority_boundary() {
    if !sandbox_available() {
        return;
    }
    let discovered = discovery("good");
    assert_eq!(discovered.tools.len(), 3);
    assert!(discovered.tool("add").is_some());
    assert!(discovered.tool("inspect_boundary").is_some());
    assert!(discovered.tool("sleep").is_some());

    let home = tempfile::tempdir().expect("home");
    let config = install_fixture(home.path(), "good", &["add", "inspect_boundary"]);
    let tools = load_mcp_read_tools(home.path(), Path::new(BUBBLEWRAP), &launcher(), &[config])
        .expect("runtime tools");
    assert_eq!(tools.len(), 2);
    let add = tools
        .iter()
        .find(|tool| tool.descriptor().tool_id == "mcp.fixture.add")
        .expect("add tool");
    let added = add
        .execute(&json!({"left": 20, "right": 22}), &NeverCancelled)
        .expect("add call");
    let added: Value = serde_json::from_slice(&added.bytes).expect("add JSON");
    assert_eq!(added["structuredContent"]["sum"], 42);

    let boundary = tools
        .iter()
        .find(|tool| tool.descriptor().tool_id == "mcp.fixture.inspect_boundary")
        .expect("boundary tool")
        .execute(&json!({}), &NeverCancelled)
        .expect("boundary call");
    let boundary: Value = serde_json::from_slice(&boundary.bytes).expect("boundary JSON");
    assert_eq!(boundary["structuredContent"]["environmentCount"], 0);
    assert_eq!(boundary["structuredContent"]["passwdReadable"], false);
    assert_eq!(boundary["structuredContent"]["spawnSucceeded"], false);
}

#[test]
fn malformed_extra_stdout_stderr_flood_and_version_mismatch_fail_closed() {
    if !sandbox_available() {
        return;
    }
    for (mode, expected) in [
        ("malformed", McpHostError::InvalidProtocol),
        ("extra-stdout", McpHostError::InvalidProtocol),
        ("stderr-flood", McpHostError::OutputLimitExceeded),
        ("wrong-version", McpHostError::InvalidProtocol),
    ] {
        let error = discover_mcp_stdio_server(
            BUBBLEWRAP,
            launcher(),
            "fixture",
            fixture(),
            &fixture_digest(),
            &[mode.to_owned()],
        )
        .expect_err("hostile fixture must fail");
        assert_eq!(error, expected, "mode {mode}");
    }
}

#[test]
fn complete_toolset_drift_and_executable_tampering_remove_authority() {
    if !sandbox_available() {
        return;
    }
    let home = tempfile::tempdir().expect("home");
    let drift = install_fixture(home.path(), "drift", &["add"]);
    assert_eq!(
        load_mcp_read_tools(home.path(), Path::new(BUBBLEWRAP), &launcher(), &[drift])
            .expect_err("drift must fail"),
        McpHostError::ToolsetDrift
    );

    let valid = install_fixture(home.path(), "good", &["add"]);
    fs::OpenOptions::new()
        .append(true)
        .open(home.path().join(valid.executable_path()))
        .expect("open installed fixture")
        .write_all(b"tamper")
        .expect("tamper fixture");
    assert_eq!(
        load_mcp_read_tools(home.path(), Path::new(BUBBLEWRAP), &launcher(), &[valid])
            .expect_err("identity mismatch must fail"),
        McpHostError::IdentityMismatch
    );
}

#[test]
fn durable_cancellation_stops_an_in_flight_mcp_call() {
    if !sandbox_available() {
        return;
    }
    let home = tempfile::tempdir().expect("home");
    let config = install_fixture(home.path(), "good", &["sleep"]);
    let tools = load_mcp_read_tools(home.path(), Path::new(BUBBLEWRAP), &launcher(), &[config])
        .expect("runtime tools");
    let cancellation = DeadlineCancellation {
        started: Instant::now(),
        after: Duration::from_millis(50),
        observed: OnceLock::new(),
    };
    let started = Instant::now();
    let error = tools[0]
        .execute(&json!({"milliseconds": 5_000}), &cancellation)
        .expect_err("call must cancel");
    assert_eq!(error, ReadToolError::Cancelled);
    let observed = cancellation.observed.get().expect("cancellation observed");
    assert!(observed.elapsed() < Duration::from_secs(2));
    assert!(started.elapsed() < Duration::from_secs(10));
}
