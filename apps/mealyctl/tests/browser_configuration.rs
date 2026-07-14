//! Opt-in process proof for stopped-home browser configuration lifecycle.

use mealy_application::{AgentLoopLimits, ProviderConfig};
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command, time::Instant};
use tempfile::TempDir;

fn initialize_home(home: &Path) {
    fs::create_dir_all(home.join("config-history")).expect("configuration history");
    let config = json!({
        "formatVersion": 1,
        "drainDeadlineMs": 10_000,
        "maximumPendingInputsPerSession": 1_024,
        "agentLoopLimits": AgentLoopLimits::default(),
        "concurrencyLimits": {
            "daemonAgentRuns": 1,
            "principalAgentRuns": 1,
            "sessionAgentRuns": 1,
            "providerRequests": 1,
            "providerRequestsPerMinute": 600,
            "extensionInvocations": 1,
            "agentRoleRuns": 1,
            "resourceClassInvocations": 1
        },
        "provider": ProviderConfig::default(),
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
        serde_json::to_vec_pretty(&config).expect("config JSON"),
    )
    .expect("config file");
}

fn run(home: &Path, arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home)
        .args(arguments)
        .output()
        .expect("run mealyctl")
}

fn run_success(home: &Path, arguments: &[&str]) -> Value {
    let started = Instant::now();
    let output = run(home, arguments);
    assert!(
        output.status.success(),
        "mealyctl {arguments:?} failed with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!(
        "mealyctl {arguments:?} completed in {:?}",
        started.elapsed()
    );
    serde_json::from_slice(&output.stdout).expect("mealyctl JSON")
}

#[test]
#[ignore = "set MEALY_BROWSER_BUNDLE to a reviewed Chrome Headless Shell bundle"]
fn inspect_add_disable_enable_revoke_is_approved_verified_and_rollback_safe() {
    let bundle = std::env::var("MEALY_BROWSER_BUNDLE").expect("browser bundle path");
    let home = TempDir::new().expect("temporary home");
    initialize_home(home.path());

    let inspected = run_success(home.path(), &["config", "browser-inspect", &bundle]);
    assert_eq!(inspected["protocolVersion"], "1.3");
    assert_eq!(inspected["product"], "HeadlessChrome/150.0.7871.124");
    assert!(
        !run(home.path(), &["config", "browser-add", &bundle])
            .status
            .success()
    );
    assert!(!home.path().join("browser-runtimes").exists());

    run_success(
        home.path(),
        &[
            "config",
            "web-enable",
            "--allow-origin",
            "http://127.0.0.1:1",
            "--approve",
        ],
    );
    let added = run_success(
        home.path(),
        &["config", "browser-add", &bundle, "--approve"],
    );
    assert_eq!(added["operation"], "installed_and_enabled");
    assert_eq!(added["browser"]["bundleDigest"], inspected["bundleDigest"]);
    let listed = run_success(home.path(), &["config", "browser-list"]);
    assert_eq!(listed["browser"]["enabled"], true);
    assert!(
        !run(home.path(), &["config", "web-disable", "--approve"])
            .status
            .success()
    );

    let disabled = run_success(home.path(), &["config", "browser-disable", "--approve"]);
    assert_eq!(disabled["browser"]["enabled"], false);
    run_success(home.path(), &["config", "web-disable", "--approve"]);
    assert!(
        !run(home.path(), &["config", "browser-enable", "--approve"])
            .status
            .success()
    );
    run_success(
        home.path(),
        &[
            "config",
            "web-enable",
            "--allow-origin",
            "http://127.0.0.1:1",
            "--approve",
        ],
    );
    let enabled = run_success(home.path(), &["config", "browser-enable", "--approve"]);
    assert_eq!(enabled["browser"]["enabled"], true);
    let revoked = run_success(home.path(), &["config", "browser-revoke", "--approve"]);
    assert!(revoked["browser"].is_null());
    assert!(revoked["runtimeRetainedForRollback"].as_bool() == Some(true));
    assert!(home.path().join("browser-runtimes").is_dir());
    assert!(
        fs::read_dir(home.path().join("config-history"))
            .expect("history")
            .count()
            >= 6
    );
}
