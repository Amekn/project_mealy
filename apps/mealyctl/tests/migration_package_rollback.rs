//! Public-process proof for package-managed cross-schema rollback.

#![cfg(target_os = "linux")]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mealy_application::OwnershipContext;
use mealy_domain::{ChannelBindingId, PrincipalId};
use mealy_infrastructure::{
    FileProviderSecretStore, SqliteStore, create_pre_migration_backup,
    inspect_existing_schema_version,
};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::SystemTime,
};

#[test]
#[allow(clippy::too_many_lines)]
fn package_manager_compensates_denial_then_activates_matching_binary_and_home() {
    let root = tempfile::tempdir().expect("migration package root");
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let home = root.path().join("home");
    fs::create_dir(&home).expect("home");
    fs::write(
        home.join("config.json"),
        br#"{"formatVersion":1,"drainDeadlineMs":10000,"providerFallbacks":[],"artifactGcMinimumAgeHours":24,"forensicBackupOnOpenFailure":true}"#,
    )
    .expect("configuration");
    let principal_id = PrincipalId::new();
    let channel_binding_id = ChannelBindingId::new();
    let database = home.join("mealy.sqlite3");
    let mut store = SqliteStore::open(&database, 1).expect("current store");
    store
        .register_local_identity(OwnershipContext::new(principal_id, channel_binding_id), 1)
        .expect("identity registry");
    drop(store);
    fs::write(
        home.join("identity.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "formatVersion": 1,
            "bearerToken": URL_SAFE_NO_PAD.encode([0x63_u8; 32]),
            "principalId": principal_id,
            "channelBindingId": channel_binding_id,
        }))
        .expect("identity JSON"),
    )
    .expect("identity file");
    FileProviderSecretStore::new(home.join("provider-secrets"))
        .expect("provider broker")
        .put("openai-primary", "package-rollback-provider-secret")
        .expect("provider secret");

    downgrade_fixture_to_v13(&database);
    let migration = create_pre_migration_backup(&home, &database, 13, 16, SystemTime::now())
        .expect("migration backup");
    let migration_name = migration
        .path
        .file_name()
        .and_then(|value| value.to_str())
        .expect("migration backup name");

    let target = match std::env::consts::ARCH {
        "x86_64" => "linux-x86_64-gnu",
        "aarch64" => "linux-aarch64-gnu",
        architecture => panic!("unsupported packaging test architecture: {architecture}"),
    };
    let sbom = prepare_sbom(root.path(), &repository, target);
    let old_package = build_package(root.path(), &repository, &sbom, target, 13, "old");
    let new_package = build_package(root.path(), &repository, &sbom, target, 16, "new");
    let prefix = root.path().join("prefix");
    run_success(
        Command::new(repository.join("packaging/install.sh"))
            .env("MEALY_TEST_REAL_MEALYCTL", env!("CARGO_BIN_EXE_mealyctl"))
            .arg("install")
            .arg("--archive")
            .arg(old_package.join(format!("mealy-v0.1.0-{target}.tar.gz")))
            .arg("--checksums")
            .arg(old_package.join("SHA256SUMS"))
            .arg("--prefix")
            .arg(&prefix)
            .arg("--home")
            .arg(&home),
        "install schema-13 package",
    );

    drop(SqliteStore::open(&database, 2).expect("migrate active home to schema 16"));
    run_success(
        Command::new(repository.join("packaging/install.sh"))
            .env("MEALY_TEST_REAL_MEALYCTL", env!("CARGO_BIN_EXE_mealyctl"))
            .arg("install")
            .arg("--archive")
            .arg(new_package.join(format!("mealy-v0.1.0-{target}.tar.gz")))
            .arg("--checksums")
            .arg(new_package.join("SHA256SUMS"))
            .arg("--prefix")
            .arg(&prefix)
            .arg("--home")
            .arg(&home),
        "install schema-16 package",
    );
    fs::write(
        home.join("newer-only.txt"),
        b"preserve migrated package home",
    )
    .expect("newer sentinel");

    let manager = prefix.join("share/mealy-manager.sh");
    let denied = rollback_command(&manager, &prefix, &home, migration_name, &"0".repeat(64));
    assert!(!denied.status.success());
    assert_eq!(package_schema(&prefix), 16);
    assert_eq!(
        inspect_existing_schema_version(&database).expect("schema after compensated denial"),
        Some(16)
    );
    assert!(home.join("newer-only.txt").is_file());

    let activated = rollback_command(
        &manager,
        &prefix,
        &home,
        migration_name,
        &migration.manifest_digest,
    );
    assert!(
        activated.status.success(),
        "package rollback failed: {}",
        String::from_utf8_lossy(&activated.stderr)
    );
    assert!(String::from_utf8_lossy(&activated.stdout).contains("\"fromSchemaVersion\": 13"));
    assert_eq!(package_schema(&prefix), 13);
    assert_eq!(
        inspect_existing_schema_version(&database).expect("activated schema"),
        Some(13)
    );
    assert_eq!(
        fs::read(home.join("provider-secrets/openai-primary.key"))
            .expect("activated provider secret"),
        b"package-rollback-provider-secret"
    );
    let evidence: serde_json::Value = serde_json::from_slice(
        &fs::read(home.join("migration-rollback-activation.json")).expect("activation evidence"),
    )
    .expect("activation evidence JSON");
    let preserved = Path::new(
        evidence
            .get("preservedHome")
            .and_then(serde_json::Value::as_str)
            .expect("preserved home path"),
    );
    assert!(preserved.join("newer-only.txt").is_file());
    assert_eq!(
        inspect_existing_schema_version(&preserved.join("mealy.sqlite3"))
            .expect("preserved migrated schema"),
        Some(16)
    );
}

fn downgrade_fixture_to_v13(database: &Path) {
    let connection = rusqlite::Connection::open(database).expect("downgrade fixture");
    connection
        .execute_batch(
            "DROP INDEX run_terminal_completion_idx;
             DROP TRIGGER model_attempt_manifest_token_total_insert;
             DROP TABLE context_manifest_bundle_memory_citation;
             DROP TABLE context_manifest_bundle_compaction;
             DROP TABLE context_manifest_bundle_artifact;
             DROP TABLE context_manifest_bundle;
             DROP TABLE discord_message_receipt;
             DROP TABLE discord_channel_health;
             DROP TABLE discord_channel_cursor;
             DROP TABLE discord_channel_binding;
             DELETE FROM schema_version WHERE version IN (14, 15, 16);
             PRAGMA wal_checkpoint(TRUNCATE);",
        )
        .expect("simulate schema 13");
}

fn prepare_sbom(root: &Path, repository: &Path, target: &str) -> PathBuf {
    let raw = root.join("raw-sbom.json");
    let normalized = root.join("mealy.cdx.json");
    fs::write(
        &raw,
        br#"{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:00000000-0000-4000-8000-000000000000","version":1,"metadata":{"timestamp":"2099-01-01T00:00:00Z","component":{"name":"temporary"}},"components":[{"type":"application","name":"mealyd","version":"0.1.0"},{"type":"application","name":"mealyctl","version":"0.1.0"}]}"#,
    )
    .expect("raw SBOM");
    run_success(
        Command::new(repository.join("packaging/normalize-sbom.sh"))
            .arg(&raw)
            .arg(&normalized)
            .arg("0.1.0")
            .arg(target)
            .arg("0123456789abcdef0123456789abcdef01234567")
            .arg("1700000000"),
        "normalize SBOM",
    );
    normalized
}

fn build_package(
    root: &Path,
    repository: &Path,
    sbom: &Path,
    target: &str,
    schema: u64,
    label: &str,
) -> PathBuf {
    let binaries = root.join(format!("binaries-{label}"));
    let output = root.join(format!("package-{label}"));
    let third_party_licenses = root.join(format!("third-party-licenses-{label}.html"));
    fs::create_dir(&binaries).expect("binary directory");
    fs::write(
        &third_party_licenses,
        format!(
            "<h1>Mealy third-party licenses</h1>\n<pre>\n{}</pre>\n",
            "Deterministic third-party license fixture text.\n".repeat(64)
        ),
    )
    .expect("third-party license fixture");
    fs::write(
        binaries.join("mealyctl"),
        "#!/usr/bin/env bash\nexec \"${MEALY_TEST_REAL_MEALYCTL:?}\" \"$@\"\n",
    )
    .expect("fixture mealyctl launcher");
    fs::write(
        binaries.join("mealyd"),
        format!(
            "#!/usr/bin/env bash\nif [[ ${{1-}} == --version ]]; then printf 'mealyd 0.1.0\\n'; elif [[ ${{1-}} == --print-supported-schema-version ]]; then printf '{schema}\\n'; else printf 'mealyd-{label}\\n'; fi\n"
        ),
    )
    .expect("fixture mealyd");
    for binary in ["mealyd", "mealyctl"] {
        let path = binaries.join(binary);
        let mut permissions = fs::metadata(&path).expect("binary metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("binary permissions");
    }
    run_success(
        Command::new(repository.join("packaging/build-release.sh"))
            .env("MEALY_TEST_REAL_MEALYCTL", env!("CARGO_BIN_EXE_mealyctl"))
            .arg("0.1.0")
            .arg(target)
            .arg(&binaries)
            .arg(sbom)
            .arg(&third_party_licenses)
            .arg(&output)
            .arg("0123456789abcdef0123456789abcdef01234567")
            .arg("1700000000")
            .arg(schema.to_string()),
        "build package",
    );
    output
}

fn rollback_command(
    manager: &Path,
    prefix: &Path,
    home: &Path,
    migration_name: &str,
    digest: &str,
) -> Output {
    Command::new(manager)
        .env("MEALY_TEST_REAL_MEALYCTL", env!("CARGO_BIN_EXE_mealyctl"))
        .arg("rollback-migration")
        .arg("--migration-backup")
        .arg(migration_name)
        .arg("--expected-manifest-digest")
        .arg(digest)
        .arg("--approve")
        .arg("--prefix")
        .arg(prefix)
        .arg("--home")
        .arg(home)
        .output()
        .expect("run package-managed migration rollback")
}

fn package_schema(prefix: &Path) -> u64 {
    let output = Command::new(prefix.join("bin/mealyd"))
        .arg("--print-supported-schema-version")
        .output()
        .expect("query packaged schema");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("schema UTF-8")
        .trim()
        .parse()
        .expect("numeric package schema")
}

fn run_success(command: &mut Command, context: &str) {
    let output = command.output().expect(context);
    assert!(
        output.status.success(),
        "{context} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
