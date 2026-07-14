//! Process-boundary proof for data-only skill inspection, inert installation, and activation.

use mealy_application::sha256_digest;
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};

#[test]
#[allow(clippy::too_many_lines)]
fn skill_lifecycle_is_digest_pinned_inert_on_install_and_revision_fenced() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::write(
        home.path().join("config.json"),
        serde_json::to_vec_pretty(&default_config()).expect("encode config"),
    )
    .expect("write config");
    let source_v1 = tempfile::tempdir().expect("skill v1 source");
    let digest_v1 = write_package(source_v1.path(), "1.0.0", "Check every cited claim.");

    let inspected = skill_command(
        home.path(),
        &[
            "inspect",
            "--manifest",
            source_v1
                .path()
                .join("manifest.json")
                .to_str()
                .expect("manifest path"),
            "--package-root",
            source_v1.path().to_str().expect("package path"),
            "--digest",
            &digest_v1,
        ],
    );
    assert!(
        inspected.status.success(),
        "skill inspection failed: {}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let response: Value = serde_json::from_slice(&inspected.stdout).expect("inspection response");
    assert_eq!(response["operation"], "inspected");
    assert_eq!(response["installed"], false);
    assert_eq!(response["manifestDigest"], digest_v1);
    assert_eq!(
        response["toolAuthority"],
        "references_only_no_authority_granted"
    );
    assert!(!home.path().join("skills").exists());

    let unapproved = install_command(home.path(), source_v1.path(), &digest_v1, false);
    assert!(!unapproved.status.success());
    assert!(!home.path().join("skills").exists());
    assert!(default_config() == read_config(home.path()));

    let installed = install_command(home.path(), source_v1.path(), &digest_v1, true);
    assert!(
        installed.status.success(),
        "skill installation failed: {}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let response: Value = serde_json::from_slice(&installed.stdout).expect("install response");
    assert_eq!(response["operation"], "installed_disabled");
    assert_eq!(response["enabled"], false);
    assert_eq!(response["restartRequired"], true);
    let installed_root = home.path().join("skills").join(&digest_v1);
    assert_eq!(
        fs::read(installed_root.join("instructions/review.md")).expect("installed instruction"),
        b"Check every cited claim."
    );
    let config = read_config(home.path());
    assert_eq!(config["skills"][0]["skillId"], "mealy.fixture.review");
    assert_eq!(config["skills"][0]["enabled"], false);
    assert_eq!(
        config["skills"][0]["packagePath"],
        format!("skills/{digest_v1}")
    );

    fs::remove_dir_all(source_v1.path()).expect("remove original source package");
    let listed = skill_command(home.path(), &["list"]);
    assert!(listed.status.success());
    let response: Value = serde_json::from_slice(&listed.stdout).expect("list response");
    assert_eq!(response["skills"][0]["manifestDigest"], digest_v1);

    let wrong_revision = skill_command(
        home.path(),
        &[
            "enable",
            "mealy.fixture.review",
            "--expected-manifest-digest",
            &"f".repeat(64),
            "--approve",
        ],
    );
    assert!(!wrong_revision.status.success());
    assert_eq!(read_config(home.path())["skills"][0]["enabled"], false);

    let enabled = skill_command(
        home.path(),
        &[
            "enable",
            "mealy.fixture.review",
            "--expected-manifest-digest",
            &digest_v1,
            "--approve",
        ],
    );
    assert!(
        enabled.status.success(),
        "skill enable failed: {}",
        String::from_utf8_lossy(&enabled.stderr)
    );
    assert_eq!(read_config(home.path())["skills"][0]["enabled"], true);

    let source_v2 = tempfile::tempdir().expect("skill v2 source");
    let digest_v2 = write_package(source_v2.path(), "2.0.0", "Check claims and quote digests.");
    let updated = skill_command(
        home.path(),
        &[
            "update",
            "mealy.fixture.review",
            "--expected-manifest-digest",
            &digest_v1,
            "--manifest",
            source_v2
                .path()
                .join("manifest.json")
                .to_str()
                .expect("manifest path"),
            "--package-root",
            source_v2.path().to_str().expect("package path"),
            "--digest",
            &digest_v2,
            "--approve",
        ],
    );
    assert!(
        updated.status.success(),
        "skill update failed: {}",
        String::from_utf8_lossy(&updated.stderr)
    );
    let response: Value = serde_json::from_slice(&updated.stdout).expect("update response");
    assert_eq!(response["operation"], "updated_disabled");
    assert_eq!(response["enabled"], false);
    assert!(
        installed_root.exists(),
        "old immutable revision must remain"
    );
    assert!(home.path().join("skills").join(&digest_v2).exists());
    let config = read_config(home.path());
    assert_eq!(config["skills"][0]["manifestDigest"], digest_v2);
    assert_eq!(config["skills"][0]["version"], "2.0.0");
    assert_eq!(config["skills"][0]["enabled"], false);

    fs::write(
        home.path()
            .join("skills")
            .join(&digest_v2)
            .join("instructions/review.md"),
        b"tampered",
    )
    .expect("tamper installed instruction");
    let tampered = skill_command(home.path(), &["status", "mealy.fixture.review"]);
    assert!(!tampered.status.success());
    assert!(!String::from_utf8_lossy(&tampered.stderr).contains("Check claims"));
}

fn install_command(
    home: &Path,
    package_root: &Path,
    digest: &str,
    approve: bool,
) -> std::process::Output {
    let manifest = package_root.join("manifest.json");
    let mut arguments = vec![
        "install",
        "--manifest",
        manifest.to_str().expect("manifest path"),
        "--package-root",
        package_root.to_str().expect("package path"),
        "--digest",
        digest,
    ];
    if approve {
        arguments.push("--approve");
    }
    skill_command(home, &arguments)
}

fn skill_command(home: &Path, arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home)
        .arg("skill")
        .args(arguments)
        .output()
        .expect("run mealyctl skill command")
}

fn write_package(root: &Path, version: &str, instruction: &str) -> String {
    fs::create_dir_all(root.join("instructions")).expect("instruction directory");
    fs::create_dir_all(root.join("resources")).expect("resource directory");
    let resource = br#"{"minimumEvidence":2}"#;
    fs::write(root.join("instructions/review.md"), instruction).expect("instruction");
    fs::write(root.join("resources/rubric.json"), resource).expect("resource");
    let manifest = json!({
        "contractVersion": "mealy.skill.v1",
        "skillId": "mealy.fixture.review",
        "version": version,
        "instructions": [{
            "relativePath": "instructions/review.md",
            "mediaType": "text/markdown",
            "contentDigest": sha256_digest(instruction.as_bytes()),
            "sizeBytes": instruction.len()
        }],
        "resources": [{
            "relativePath": "resources/rubric.json",
            "mediaType": "application/json",
            "contentDigest": sha256_digest(resource),
            "sizeBytes": resource.len()
        }],
        "requiredTools": [{
            "toolId": "workspace.read",
            "version": "1",
            "inputSchemaDigest": "a".repeat(64)
        }]
    });
    let body = serde_json::to_vec_pretty(&manifest).expect("manifest bytes");
    fs::write(root.join("manifest.json"), &body).expect("manifest");
    sha256_digest(&body)
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
