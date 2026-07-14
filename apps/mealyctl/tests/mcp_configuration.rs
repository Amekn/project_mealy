//! Process-boundary proof for stopped-daemon MCP configuration lifecycle controls.

use mealy_application::{
    MCP_PROTOCOL_VERSION, McpServerConfig, McpServerDiscovery, McpToolGrant, McpToolInspection,
};
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};

#[test]
fn configured_mcp_authority_is_listable_disableable_and_revocable_with_explicit_approval() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::create_dir(home.path().join("config-history")).expect("configuration history");
    let server = fixture_config();
    let mut config = default_config();
    config["mcpServers"] = serde_json::to_value([server]).expect("MCP config");
    fs::write(
        home.path().join("config.json"),
        serde_json::to_vec_pretty(&config).expect("config bytes"),
    )
    .expect("write config");

    let listed = command(home.path(), &["mcp-list"]);
    assert!(
        listed.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let response: Value = serde_json::from_slice(&listed.stdout).expect("list response");
    assert_eq!(response["servers"][0]["serverId"], "fixture");
    assert_eq!(response["servers"][0]["enabled"], true);
    assert_eq!(
        response["servers"][0]["tools"][0]["definition"]["name"],
        "add"
    );

    let before = fs::read(home.path().join("config.json")).expect("config before denial");
    let denied = command(home.path(), &["mcp-disable", "fixture"]);
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("requires --approve"));
    assert_eq!(
        fs::read(home.path().join("config.json")).expect("config after denial"),
        before
    );

    let disabled = command(home.path(), &["mcp-disable", "fixture", "--approve"]);
    assert!(
        disabled.status.success(),
        "disable failed: {}",
        String::from_utf8_lossy(&disabled.stderr)
    );
    let response: Value = serde_json::from_slice(&disabled.stdout).expect("disable response");
    assert_eq!(response["operation"], "disabled");
    assert_eq!(response["enabled"], false);
    assert_eq!(response["restartRequired"], true);
    assert_eq!(read_config(home.path())["mcpServers"][0]["enabled"], false);

    let revoked = command(home.path(), &["mcp-revoke", "fixture", "--approve"]);
    assert!(
        revoked.status.success(),
        "revoke failed: {}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    let response: Value = serde_json::from_slice(&revoked.stdout).expect("revoke response");
    assert_eq!(response["operation"], "revoked");
    assert_eq!(response["executableRetainedForRollback"], true);
    assert!(read_config(home.path()).get("mcpServers").is_none());
    assert!(
        fs::read_dir(home.path().join("config-history"))
            .expect("history")
            .count()
            >= 2
    );
}

#[test]
fn mcp_add_parses_but_cannot_execute_or_mutate_without_approval() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::write(
        home.path().join("config.json"),
        serde_json::to_vec_pretty(&default_config()).expect("config bytes"),
    )
    .expect("write config");
    let before = fs::read(home.path().join("config.json")).expect("config before");
    let output = command(
        home.path(),
        &[
            "mcp-add",
            "fixture",
            "/definitely/not/executable",
            "--allow-tool",
            "add",
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires --approve"));
    assert_eq!(
        fs::read(home.path().join("config.json")).expect("config after"),
        before
    );
    assert!(!home.path().join("mcp-servers").exists());
}

fn fixture_config() -> McpServerConfig {
    let definition = json!({
        "name": "add",
        "description": "Adds two integers",
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "left": {"type": "integer"},
                "right": {"type": "integer"}
            },
            "required": ["left", "right"]
        }
    });
    let grant = McpToolGrant::new(definition, 5_000, 64 * 1024).expect("grant");
    let discovery = McpServerDiscovery {
        protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
        server_info: json!({"name": "fixture", "version": "1"}),
        tools: vec![McpToolInspection {
            definition: grant.definition().clone(),
            definition_digest: grant.definition_digest().to_owned(),
        }],
    };
    let executable_digest = "a".repeat(64);
    McpServerConfig::new(
        "fixture".to_owned(),
        format!("mcp-servers/{executable_digest}/server"),
        executable_digest,
        Vec::new(),
        discovery.toolset_digest().expect("toolset digest"),
        true,
        vec![grant],
    )
    .expect("server")
}

fn command(home: &Path, arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home)
        .arg("config")
        .args(arguments)
        .output()
        .expect("run mealyctl config command")
}

fn read_config(home: &Path) -> Value {
    serde_json::from_slice(&fs::read(home.join("config.json")).expect("read config"))
        .expect("config JSON")
}

fn default_config() -> Value {
    json!({
        "formatVersion": 1,
        "drainDeadlineMs": 10_000,
        "maximumPendingInputsPerSession": 1_024,
        "agentLoopLimits": {
            "maximumModelCalls": 4,
            "maximumToolCalls": 2,
            "maximumRetries": 1,
            "maximumDelegatedRuns": 2,
            "maximumInputTokens": 32_768,
            "maximumOutputTokens": 4_096,
            "maximumCostMicrounits": 1_000_000,
            "maximumOutputBytes": 4_194_304,
            "maximumWallTimeMs": 120_000,
            "providerTimeoutMs": 5_000,
            "toolTimeoutMs": 5_000,
            "inlineOutputBytes": 1_024,
            "maximumArtifactBytes": 4_194_304
        },
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
    })
}
