use crate::{FileArtifactBlobStore, SqliteStore, StoreError};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use mealy_application::is_sha256_digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const BACKUP_FORMAT_VERSION: u32 = 1;
const BUFFER_BYTES: usize = 64 * 1024;
const MAXIMUM_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAXIMUM_SECRET_ARCHIVE_BYTES: usize = 4 * 1024 * 1024;
const SECRET_KDF_MEMORY_KIB: u32 = 64 * 1024;
const SECRET_KDF_ITERATIONS: u32 = 3;
const SECRET_KDF_PARALLELISM: u32 = 1;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// One immutable file in a complete Mealy backup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackupFileEntry {
    /// Slash-separated path relative to the backup root.
    pub relative_path: String,
    /// Exact byte count.
    pub size_bytes: u64,
    /// Lowercase SHA-256 digest of the file bytes.
    pub sha256_digest: String,
}

/// Canonical manifest for an immutable complete backup directory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackupManifest {
    /// Backup contract revision.
    pub format_version: u32,
    /// UTC creation time in epoch milliseconds.
    pub created_at_ms: i64,
    /// `SQLite` schema revision captured by the online backup.
    pub schema_version: u64,
    /// Whether explicitly requested authenticated-encrypted secret material is present.
    pub secrets_included: bool,
    /// Explicit secret-bearing components omitted from this archive.
    pub excluded_secret_components: Vec<String>,
    /// Files covered by exact size and digest evidence.
    pub files: Vec<BackupFileEntry>,
}

/// Result of atomically publishing one complete backup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupReport {
    /// Final immutable backup directory.
    pub path: PathBuf,
    /// Digest of the canonical manifest bytes.
    pub manifest_digest: String,
    /// Number of manifest-covered files.
    pub file_count: u64,
    /// Aggregate manifest-covered bytes.
    pub total_bytes: u64,
    /// `SQLite` schema revision.
    pub schema_version: u64,
    /// Canonical artifact blobs captured.
    pub artifact_count: u64,
    /// Secret material inclusion state.
    pub secrets_included: bool,
}

/// Result of restoring a backup into an isolated temporary home and verifying it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupVerificationReport {
    /// Verified immutable source directory.
    pub path: PathBuf,
    /// Digest of the verified manifest bytes.
    pub manifest_digest: String,
    /// UTC verification time in epoch milliseconds.
    pub verified_at_ms: i64,
    /// Verified `SQLite` schema revision.
    pub schema_version: u64,
    /// Number of verified files.
    pub file_count: u64,
    /// Aggregate verified bytes.
    pub total_bytes: u64,
    /// Canonical artifact blobs cross-checked against `SQLite` metadata.
    pub artifact_count: u64,
    /// Secret material inclusion state.
    pub secrets_included: bool,
    /// Whether decrypted identity is active in the restored canonical registry.
    pub identity_verified: bool,
}

/// Evidence that a failed database and all existing sidecars were preserved for forensics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForensicBackupReport {
    /// Timestamped private forensic directory.
    pub path: PathBuf,
    /// Number of original files preserved.
    pub file_count: u64,
    /// Aggregate preserved bytes.
    pub total_bytes: u64,
    /// Digest of the forensic manifest.
    pub manifest_digest: String,
}

/// Result of publishing one immutable, scoped, owner-requested export bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportReport {
    /// Final private JSON bundle path.
    pub path: PathBuf,
    /// SHA-256 digest of the exact bundle bytes.
    pub digest: String,
    /// Exact bundle byte count.
    pub size_bytes: u64,
}

/// Durable pre-migration snapshot evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationBackupReport {
    /// Private immutable snapshot directory.
    pub path: PathBuf,
    /// Source schema revision.
    pub from_schema_version: u64,
    /// Binary target schema revision.
    pub to_schema_version: u64,
    /// Digest of the migration-backup manifest.
    pub manifest_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ForensicManifest<'a> {
    format_version: u32,
    preserved_at_ms: i64,
    open_failure: &'a str,
    files: &'a [BackupFileEntry],
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EncryptedSecretEnvelope {
    format_version: u32,
    kdf: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    cipher: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SecretArchive {
    format_version: u32,
    files: Vec<SecretFile>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SecretFile {
    relative_path: String,
    content: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MigrationBackupManifest<'a> {
    format_version: u32,
    created_at_ms: i64,
    from_schema_version: u64,
    to_schema_version: u64,
    files: &'a [BackupFileEntry],
    rollback: &'static str,
}

/// Creates a consistent complete backup below `HOME/backups/NAME`.
///
/// The online `SQLite` snapshot, validated non-secret configuration, canonical journal/state,
/// extension manifests, memories, and every referenced artifact are covered by one digest
/// manifest. Bearer credentials and brokered channel keys are excluded by default and may only be
/// included through an Argon2id-derived, XChaCha20-Poly1305 authenticated-encryption envelope.
///
/// # Errors
///
/// Returns [`MaintenanceError`] for invalid names, an existing immutable destination, unavailable
/// canonical state, unsafe files, integrity mismatches, or publication failures.
pub fn create_backup(
    home: &Path,
    store: &SqliteStore,
    artifacts: &FileArtifactBlobStore,
    name: &str,
    secret_passphrase: Option<&str>,
    now: SystemTime,
) -> Result<BackupReport, MaintenanceError> {
    create_complete_archive(
        home,
        store,
        artifacts,
        "backups",
        name,
        secret_passphrase,
        now,
    )
}

/// Creates a secret-free complete portable archive below `HOME/exports/NAME`.
///
/// Unlike scoped JSON exports, this captures the online canonical database, configuration, and
/// every referenced artifact. Credentials remain excluded; use encrypted backup when disaster
/// recovery of secrets is required.
///
/// # Errors
///
/// Returns [`MaintenanceError`] for invalid names, an existing destination, unavailable canonical
/// state, unsafe files, integrity mismatches, or publication failures.
pub fn create_complete_export(
    home: &Path,
    store: &SqliteStore,
    artifacts: &FileArtifactBlobStore,
    name: &str,
    now: SystemTime,
) -> Result<BackupReport, MaintenanceError> {
    create_complete_archive(home, store, artifacts, "exports", name, None, now)
}

fn create_complete_archive(
    home: &Path,
    store: &SqliteStore,
    artifacts: &FileArtifactBlobStore,
    collection: &str,
    name: &str,
    secret_passphrase: Option<&str>,
    now: SystemTime,
) -> Result<BackupReport, MaintenanceError> {
    validate_name(name)?;
    store.verify_storage_integrity()?;
    let archives = home.join(collection);
    create_private_directory(&archives)?;
    let target = archives.join(name);
    ensure_absent(&target)?;
    let temporary = archives.join(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    ensure_absent(&temporary)?;
    create_private_directory(&temporary)?;
    let mut cleanup = CleanupDirectory::new(temporary.clone());

    let database_path = temporary.join("state.sqlite3");
    store.online_backup(&database_path)?;
    set_private_file_permissions(&database_path)?;
    let mut files = vec![inspect_file(&temporary, &database_path)?];

    let config_source = home.join("config.json");
    if !config_source.exists() {
        return Err(MaintenanceError::MissingComponent("config.json".to_owned()));
    }
    let config_target = temporary.join("config.json");
    copy_private_file(&config_source, &config_target)?;
    validate_config_snapshot(&config_target)?;
    files.push(inspect_file(&temporary, &config_target)?);

    let records = store.artifact_blob_records()?;
    for record in &records {
        let source = artifacts.root().join(&record.relative_path);
        let target_file = temporary.join("artifacts").join(&record.relative_path);
        let parent = target_file
            .parent()
            .ok_or_else(|| MaintenanceError::UnsafePath(record.relative_path.clone()))?;
        create_private_directory(parent)?;
        copy_private_file(&source, &target_file)?;
        let entry = inspect_file(&temporary, &target_file)?;
        if entry.sha256_digest != record.digest || entry.size_bytes != record.size_bytes {
            return Err(MaintenanceError::Integrity(format!(
                "artifact {} differs from canonical metadata",
                record.digest
            )));
        }
        files.push(entry);
    }
    if let Some(passphrase) = secret_passphrase {
        let encrypted = encrypt_secret_archive(home, name, passphrase)?;
        let secret_path = temporary.join("secrets.enc");
        write_private_file(&secret_path, &encrypted)?;
        files.push(inspect_file(&temporary, &secret_path)?);
    }
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    ensure_unique_entries(&files)?;
    let schema_version = store.schema_version()?;
    let manifest = BackupManifest {
        format_version: BACKUP_FORMAT_VERSION,
        created_at_ms: epoch_milliseconds(now)?,
        schema_version,
        secrets_included: secret_passphrase.is_some(),
        excluded_secret_components: if secret_passphrase.is_some() {
            vec!["connection.json".to_owned()]
        } else {
            vec![
                "identity.json".to_owned(),
                "connection.json".to_owned(),
                "channel-secrets/".to_owned(),
            ]
        },
        files,
    };
    let manifest_body = serde_json::to_vec_pretty(&manifest)?;
    let manifest_digest = sha256_bytes(&manifest_body);
    write_private_file(&temporary.join("manifest.json"), &manifest_body)?;
    sync_directory_tree(&temporary)?;
    fs::rename(&temporary, &target)?;
    sync_directory(&archives)?;
    cleanup.disarm();

    let (file_count, total_bytes) = aggregate_entries(&manifest.files)?;
    Ok(BackupReport {
        path: target,
        manifest_digest,
        file_count,
        total_bytes,
        schema_version,
        artifact_count: u64::try_from(records.len()).map_err(|_| MaintenanceError::Overflow)?,
        secrets_included: manifest.secrets_included,
    })
}

/// Verifies a complete backup by copying it into a new isolated home and opening that copy.
///
/// Source files and the manifest are checked before the restored `SQLite` database is opened. Full
/// `SQLite` integrity, foreign keys, schema readiness, configuration shape, and every canonical
/// artifact's digest/size/path are then checked against the fresh restored copy. No active home is
/// replaced by this operation.
///
/// # Errors
///
/// Returns [`MaintenanceError`] if the manifest, files, database, configuration, or artifact graph
/// fails closed.
#[allow(clippy::too_many_lines)]
pub fn verify_backup(
    home: &Path,
    name: &str,
    secret_passphrase: Option<&str>,
    now: SystemTime,
) -> Result<BackupVerificationReport, MaintenanceError> {
    validate_name(name)?;
    let source = home.join("backups").join(name);
    validate_real_directory(&source)?;
    let manifest_path = source.join("manifest.json");
    let manifest_body = read_bounded_file(&manifest_path, MAXIMUM_MANIFEST_BYTES)?;
    let manifest_digest = sha256_bytes(&manifest_body);
    let manifest: BackupManifest = serde_json::from_slice(&manifest_body)?;
    validate_manifest(&manifest)?;

    let verification_root = home.join("restore-verifications");
    create_private_directory(&verification_root)?;
    let restored = verification_root.join(format!(
        ".verify-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    ensure_absent(&restored)?;
    create_private_directory(&restored)?;
    let cleanup = CleanupDirectory::new(restored.clone());

    for entry in &manifest.files {
        let relative = validate_relative_path(&entry.relative_path)?;
        let source_file = source.join(relative);
        let observed = inspect_file(&source, &source_file)?;
        if &observed != entry {
            return Err(MaintenanceError::Integrity(format!(
                "backup file {} does not match its manifest",
                entry.relative_path
            )));
        }
        let target_file = restored.join(relative);
        let parent = target_file
            .parent()
            .ok_or_else(|| MaintenanceError::UnsafePath(entry.relative_path.clone()))?;
        create_private_directory(parent)?;
        copy_private_file(&source_file, &target_file)?;
        if inspect_file(&restored, &target_file)? != *entry {
            return Err(MaintenanceError::Integrity(format!(
                "restored file {} changed during copy",
                entry.relative_path
            )));
        }
    }

    let identity = if manifest.secrets_included {
        let passphrase = secret_passphrase.ok_or(MaintenanceError::PassphraseRequired)?;
        Some(restore_encrypted_secrets(
            &restored,
            name,
            passphrase,
            &restored.join("secrets.enc"),
        )?)
    } else {
        if secret_passphrase.is_some() {
            return Err(MaintenanceError::UnexpectedPassphrase);
        }
        None
    };

    validate_config_snapshot(&restored.join("config.json"))?;
    let database_path = restored.join("state.sqlite3");
    let restored_store = SqliteStore::open(&database_path, epoch_milliseconds(now)?)?;
    restored_store.verify_storage_integrity()?;
    let schema_version = restored_store.schema_version()?;
    if schema_version != manifest.schema_version {
        return Err(MaintenanceError::Integrity(format!(
            "restored schema {schema_version} differs from manifest schema {}",
            manifest.schema_version
        )));
    }
    let artifact_records = restored_store.artifact_blob_records()?;
    for record in &artifact_records {
        let path = restored.join("artifacts").join(&record.relative_path);
        let entry = inspect_file(&restored, &path)?;
        if entry.sha256_digest != record.digest || entry.size_bytes != record.size_bytes {
            return Err(MaintenanceError::Integrity(format!(
                "restored artifact {} differs from canonical metadata",
                record.digest
            )));
        }
    }
    let identity_verified = if let Some((principal_id, channel_binding_id)) = identity {
        if !restored_store.identity_is_active(&principal_id, &channel_binding_id)? {
            return Err(MaintenanceError::Integrity(
                "decrypted owner identity is not active in restored canonical state".to_owned(),
            ));
        }
        true
    } else {
        false
    };
    drop(restored_store);
    drop(cleanup);

    let (file_count, total_bytes) = aggregate_entries(&manifest.files)?;
    Ok(BackupVerificationReport {
        path: source,
        manifest_digest,
        verified_at_ms: epoch_milliseconds(now)?,
        schema_version,
        file_count,
        total_bytes,
        artifact_count: u64::try_from(artifact_records.len())
            .map_err(|_| MaintenanceError::Overflow)?,
        secrets_included: manifest.secrets_included,
        identity_verified,
    })
}

/// Copies the original database and every existing WAL/SHM sidecar to timestamped forensics.
///
/// This function never deletes, truncates, rebuilds, or replaces the failed source. Callers invoke
/// it before offering any repair or restore path and continue returning the original open failure.
///
/// # Errors
///
/// Returns [`MaintenanceError`] if no source exists or preservation cannot be durably published.
pub fn preserve_forensic_database(
    home: &Path,
    database_path: &Path,
    open_failure: &str,
    now: SystemTime,
) -> Result<ForensicBackupReport, MaintenanceError> {
    let preserved_at_ms = epoch_milliseconds(now)?;
    let forensic_root = home.join("forensics");
    create_private_directory(&forensic_root)?;
    let target = forensic_root.join(format!(
        "corrupt-{preserved_at_ms}-{}",
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    ensure_absent(&target)?;
    create_private_directory(&target)?;
    let mut cleanup = CleanupDirectory::new(target.clone());
    let mut entries = Vec::new();
    for (suffix, name) in [
        ("", "mealy.sqlite3"),
        ("-wal", "mealy.sqlite3-wal"),
        ("-shm", "mealy.sqlite3-shm"),
    ] {
        let source = PathBuf::from(format!("{}{suffix}", database_path.display()));
        match fs::symlink_metadata(&source) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                let destination = target.join(name);
                copy_private_file(&source, &destination)?;
                entries.push(inspect_file(&target, &destination)?);
            }
            Ok(_) => return Err(MaintenanceError::UnsafePath(source.display().to_string())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(MaintenanceError::Io(error)),
        }
    }
    if entries.is_empty() {
        return Err(MaintenanceError::MissingComponent(
            database_path.display().to_string(),
        ));
    }
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let manifest = ForensicManifest {
        format_version: 1,
        preserved_at_ms,
        open_failure,
        files: &entries,
    };
    let body = serde_json::to_vec_pretty(&manifest)?;
    let manifest_digest = sha256_bytes(&body);
    write_private_file(&target.join("manifest.json"), &body)?;
    sync_directory_tree(&target)?;
    sync_directory(&forensic_root)?;
    cleanup.disarm();
    let (file_count, total_bytes) = aggregate_entries(&entries)?;
    Ok(ForensicBackupReport {
        path: target,
        file_count,
        total_bytes,
        manifest_digest,
    })
}

/// Inspects an existing database schema without enabling WAL or applying migrations.
///
/// # Errors
///
/// Returns [`MaintenanceError`] when the path is unsafe, corrupt, or cannot be read-only opened.
pub fn inspect_existing_schema_version(
    database_path: &Path,
) -> Result<Option<u64>, MaintenanceError> {
    let metadata = match fs::symlink_metadata(database_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(MaintenanceError::Io(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(MaintenanceError::UnsafePath(
            database_path.display().to_string(),
        ));
    }
    let connection = rusqlite::Connection::open_with_flags(
        database_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(StoreError::from)?;
    let exists = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'schema_version'
             )",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(StoreError::from)?;
    if !exists {
        return Ok(Some(0));
    }
    let version = connection
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(StoreError::from)?;
    u64::try_from(version)
        .map(Some)
        .map_err(|_| MaintenanceError::InvalidMigrationVersion)
}

/// Publishes a consistent immutable database/config snapshot before a forward migration.
///
/// Artifacts are content-addressed and untouched by schema migration; the snapshot retains their
/// canonical references. Downgrade uses the recorded older binary plus this database copy, never
/// an older binary against the migrated active database.
///
/// # Errors
///
/// Returns [`MaintenanceError`] for invalid versions, source integrity, or publication failure.
pub fn create_pre_migration_backup(
    home: &Path,
    database_path: &Path,
    from_schema_version: u64,
    to_schema_version: u64,
    now: SystemTime,
) -> Result<MigrationBackupReport, MaintenanceError> {
    if from_schema_version == 0 || from_schema_version >= to_schema_version {
        return Err(MaintenanceError::InvalidMigrationVersion);
    }
    let created_at_ms = epoch_milliseconds(now)?;
    let root = home.join("migration-backups");
    create_private_directory(&root)?;
    let name = format!(
        "v{from_schema_version}-to-v{to_schema_version}-{created_at_ms}-{}",
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let target = root.join(&name);
    ensure_absent(&target)?;
    let temporary = root.join(format!(".{name}.tmp"));
    ensure_absent(&temporary)?;
    create_private_directory(&temporary)?;
    let mut cleanup = CleanupDirectory::new(temporary.clone());
    let source = rusqlite::Connection::open_with_flags(
        database_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(StoreError::from)?;
    let database_target = temporary.join("state.sqlite3");
    source
        .backup("main", &database_target, None)
        .map_err(StoreError::from)?;
    set_private_file_permissions(&database_target)?;
    let mut files = vec![inspect_file(&temporary, &database_target)?];
    let config_source = home.join("config.json");
    let config_target = temporary.join("config.json");
    copy_private_file(&config_source, &config_target)?;
    validate_config_snapshot(&config_target)?;
    files.push(inspect_file(&temporary, &config_target)?);
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let manifest = MigrationBackupManifest {
        format_version: 1,
        created_at_ms,
        from_schema_version,
        to_schema_version,
        files: &files,
        rollback: "stop mealyd; restore state.sqlite3 with the matching older binary; artifacts remain unchanged",
    };
    let body = serde_json::to_vec_pretty(&manifest)?;
    let manifest_digest = sha256_bytes(&body);
    write_private_file(&temporary.join("manifest.json"), &body)?;
    sync_directory_tree(&temporary)?;
    fs::rename(&temporary, &target)?;
    sync_directory(&root)?;
    cleanup.disarm();
    Ok(MigrationBackupReport {
        path: target,
        from_schema_version,
        to_schema_version,
        manifest_digest,
    })
}

/// Atomically publishes a bounded JSON export below `HOME/exports/NAME.json`.
///
/// The caller constructs an owner-authorized, schema-versioned scope envelope. This function
/// enforces a portable immutable name, private storage, an exact digest, and durable publication.
///
/// # Errors
///
/// Returns [`MaintenanceError`] for unsafe names, an existing immutable bundle, encoding, I/O,
/// or size overflow.
pub fn publish_export(
    home: &Path,
    name: &str,
    bundle: &serde_json::Value,
) -> Result<ExportReport, MaintenanceError> {
    validate_name(name)?;
    let exports = home.join("exports");
    create_private_directory(&exports)?;
    let target = exports.join(format!("{name}.json"));
    ensure_absent(&target)?;
    let body = serde_json::to_vec_pretty(bundle)?;
    let digest = sha256_bytes(&body);
    let size_bytes = u64::try_from(body.len()).map_err(|_| MaintenanceError::Overflow)?;
    let temporary = exports.join(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    ensure_absent(&temporary)?;
    write_private_file(&temporary, &body)?;
    fs::rename(&temporary, &target)?;
    sync_directory(&exports)?;
    Ok(ExportReport {
        path: target,
        digest,
        size_bytes,
    })
}

fn encrypt_secret_archive(
    home: &Path,
    backup_name: &str,
    passphrase: &str,
) -> Result<Vec<u8>, MaintenanceError> {
    validate_passphrase(passphrase)?;
    let identity = read_bounded_file(&home.join("identity.json"), 256 * 1024)?;
    validate_identity_json(&identity)?;
    let mut files = vec![SecretFile {
        relative_path: "identity.json".to_owned(),
        content: URL_SAFE_NO_PAD.encode(identity),
    }];
    let channel_root = home.join("channel-secrets");
    match fs::symlink_metadata(&channel_root) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            for entry in fs::read_dir(&channel_root)? {
                let entry = entry?;
                let metadata = fs::symlink_metadata(entry.path())?;
                let name = entry
                    .file_name()
                    .to_str()
                    .ok_or(MaintenanceError::InvalidSecretArchive)?
                    .to_owned();
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.len() != 32
                    || !valid_channel_secret_name(&name)
                {
                    return Err(MaintenanceError::InvalidSecretArchive);
                }
                files.push(SecretFile {
                    relative_path: format!("channel-secrets/{name}"),
                    content: URL_SAFE_NO_PAD.encode(fs::read(entry.path())?),
                });
            }
        }
        Ok(_) => return Err(MaintenanceError::InvalidSecretArchive),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(MaintenanceError::Io(error)),
    }
    if files.len() > 1_001 {
        return Err(MaintenanceError::InvalidSecretArchive);
    }
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let plaintext = Zeroizing::new(serde_json::to_vec(&SecretArchive {
        format_version: 1,
        files,
    })?);
    if plaintext.len() > MAXIMUM_SECRET_ARCHIVE_BYTES {
        return Err(MaintenanceError::InvalidSecretArchive);
    }
    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut salt).map_err(|_| MaintenanceError::RandomUnavailable)?;
    getrandom::fill(&mut nonce).map_err(|_| MaintenanceError::RandomUnavailable)?;
    let key = derive_secret_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let aad = secret_archive_aad(backup_name);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| MaintenanceError::CryptographicFailure)?;
    serde_json::to_vec_pretty(&EncryptedSecretEnvelope {
        format_version: 1,
        kdf: "argon2id".to_owned(),
        memory_kib: SECRET_KDF_MEMORY_KIB,
        iterations: SECRET_KDF_ITERATIONS,
        parallelism: SECRET_KDF_PARALLELISM,
        cipher: "xchacha20poly1305".to_owned(),
        salt: URL_SAFE_NO_PAD.encode(salt),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
    .map_err(MaintenanceError::from)
}

fn restore_encrypted_secrets(
    restored: &Path,
    backup_name: &str,
    passphrase: &str,
    encrypted_path: &Path,
) -> Result<(String, String), MaintenanceError> {
    validate_passphrase(passphrase)?;
    let body = read_bounded_file(
        encrypted_path,
        u64::try_from(MAXIMUM_SECRET_ARCHIVE_BYTES * 2).map_err(|_| MaintenanceError::Overflow)?,
    )?;
    let envelope: EncryptedSecretEnvelope = serde_json::from_slice(&body)?;
    if envelope.format_version != 1
        || envelope.kdf != "argon2id"
        || envelope.memory_kib != SECRET_KDF_MEMORY_KIB
        || envelope.iterations != SECRET_KDF_ITERATIONS
        || envelope.parallelism != SECRET_KDF_PARALLELISM
        || envelope.cipher != "xchacha20poly1305"
    {
        return Err(MaintenanceError::InvalidSecretArchive);
    }
    let salt = URL_SAFE_NO_PAD
        .decode(envelope.salt)
        .map_err(|_| MaintenanceError::InvalidSecretArchive)?;
    let nonce = URL_SAFE_NO_PAD
        .decode(envelope.nonce)
        .map_err(|_| MaintenanceError::InvalidSecretArchive)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(envelope.ciphertext)
        .map_err(|_| MaintenanceError::InvalidSecretArchive)?;
    let salt = <[u8; 16]>::try_from(salt).map_err(|_| MaintenanceError::InvalidSecretArchive)?;
    let nonce = <[u8; 24]>::try_from(nonce).map_err(|_| MaintenanceError::InvalidSecretArchive)?;
    if ciphertext.len() > MAXIMUM_SECRET_ARCHIVE_BYTES + 32 {
        return Err(MaintenanceError::InvalidSecretArchive);
    }
    let key = derive_secret_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let aad = secret_archive_aad(backup_name);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| MaintenanceError::CryptographicFailure)?,
    );
    if plaintext.len() > MAXIMUM_SECRET_ARCHIVE_BYTES {
        return Err(MaintenanceError::InvalidSecretArchive);
    }
    let archive: SecretArchive = serde_json::from_slice(&plaintext)?;
    if archive.format_version != 1 || archive.files.is_empty() || archive.files.len() > 1_001 {
        return Err(MaintenanceError::InvalidSecretArchive);
    }
    let mut paths = BTreeSet::new();
    let mut identity = None;
    for file in archive.files {
        if !paths.insert(file.relative_path.clone()) {
            return Err(MaintenanceError::InvalidSecretArchive);
        }
        let content = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(file.content)
                .map_err(|_| MaintenanceError::InvalidSecretArchive)?,
        );
        let valid_path = file.relative_path == "identity.json"
            || file
                .relative_path
                .strip_prefix("channel-secrets/")
                .is_some_and(valid_channel_secret_name);
        if !valid_path
            || (file.relative_path.starts_with("channel-secrets/") && content.len() != 32)
        {
            return Err(MaintenanceError::InvalidSecretArchive);
        }
        if file.relative_path == "identity.json" {
            identity = Some(validate_identity_json(&content)?);
        }
        let relative = validate_relative_path(&file.relative_path)?;
        let destination = restored.join(relative);
        let parent = destination
            .parent()
            .ok_or(MaintenanceError::InvalidSecretArchive)?;
        create_private_directory(parent)?;
        write_private_file(&destination, &content)?;
    }
    identity.ok_or(MaintenanceError::InvalidSecretArchive)
}

fn validate_identity_json(body: &[u8]) -> Result<(String, String), MaintenanceError> {
    let value: serde_json::Value = serde_json::from_slice(body)?;
    let object = value
        .as_object()
        .ok_or(MaintenanceError::InvalidSecretArchive)?;
    if object.len() != 4
        || object
            .get("formatVersion")
            .and_then(serde_json::Value::as_u64)
            != Some(1)
    {
        return Err(MaintenanceError::InvalidSecretArchive);
    }
    let token = object
        .get("bearerToken")
        .and_then(serde_json::Value::as_str)
        .ok_or(MaintenanceError::InvalidSecretArchive)?;
    if URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| MaintenanceError::InvalidSecretArchive)?
        .len()
        != 32
    {
        return Err(MaintenanceError::InvalidSecretArchive);
    }
    let principal_id = object
        .get("principalId")
        .and_then(serde_json::Value::as_str)
        .filter(|value| valid_uuid_text(value))
        .ok_or(MaintenanceError::InvalidSecretArchive)?;
    let channel_binding_id = object
        .get("channelBindingId")
        .and_then(serde_json::Value::as_str)
        .filter(|value| valid_uuid_text(value))
        .ok_or(MaintenanceError::InvalidSecretArchive)?;
    Ok((principal_id.to_owned(), channel_binding_id.to_owned()))
}

fn derive_secret_key(
    passphrase: &str,
    salt: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, MaintenanceError> {
    let parameters = Params::new(
        SECRET_KDF_MEMORY_KIB,
        SECRET_KDF_ITERATIONS,
        SECRET_KDF_PARALLELISM,
        Some(32),
    )
    .map_err(|_| MaintenanceError::CryptographicFailure)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
    let mut key = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|_| MaintenanceError::CryptographicFailure)?;
    Ok(key)
}

fn validate_passphrase(passphrase: &str) -> Result<(), MaintenanceError> {
    if (12..=1_024).contains(&passphrase.len()) {
        Ok(())
    } else {
        Err(MaintenanceError::InvalidPassphrase)
    }
}

fn secret_archive_aad(backup_name: &str) -> String {
    format!("mealy.backup.secrets.v1:{backup_name}")
}

fn valid_channel_secret_name(value: &str) -> bool {
    value.len() == 40
        && value.as_bytes().get(36..) == Some(b".key")
        && valid_uuid_text(&value[..36])
}

fn valid_uuid_text(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}

fn validate_manifest(manifest: &BackupManifest) -> Result<(), MaintenanceError> {
    if manifest.format_version != BACKUP_FORMAT_VERSION
        || manifest.created_at_ms < 0
        || manifest.schema_version == 0
        || manifest.files.is_empty()
    {
        return Err(MaintenanceError::InvalidManifest);
    }
    let excluded = manifest
        .excluded_secret_components
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_excluded = if manifest.secrets_included {
        BTreeSet::from(["connection.json"])
    } else {
        BTreeSet::from(["channel-secrets/", "connection.json", "identity.json"])
    };
    if excluded != expected_excluded {
        return Err(MaintenanceError::InvalidManifest);
    }
    ensure_unique_entries(&manifest.files)?;
    for entry in &manifest.files {
        validate_relative_path(&entry.relative_path)?;
        if !is_sha256_digest(&entry.sha256_digest) {
            return Err(MaintenanceError::InvalidManifest);
        }
    }
    let paths = manifest
        .files
        .iter()
        .map(|entry| entry.relative_path.as_str())
        .collect::<BTreeSet<_>>();
    if !paths.contains("state.sqlite3") || !paths.contains("config.json") {
        return Err(MaintenanceError::InvalidManifest);
    }
    if manifest.secrets_included != paths.contains("secrets.enc") {
        return Err(MaintenanceError::InvalidManifest);
    }
    Ok(())
}

fn validate_config_snapshot(path: &Path) -> Result<(), MaintenanceError> {
    let body = read_bounded_file(path, MAXIMUM_MANIFEST_BYTES)?;
    let value: serde_json::Value = serde_json::from_slice(&body)?;
    let object = value
        .as_object()
        .ok_or(MaintenanceError::InvalidConfiguration)?;
    if object
        .get("formatVersion")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
        || object.len() < 4
        || object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "formatVersion"
                    | "drainDeadlineMs"
                    | "maximumPendingInputsPerSession"
                    | "agentLoopLimits"
                    | "concurrencyLimits"
                    | "artifactGcMinimumAgeHours"
                    | "forensicBackupOnOpenFailure"
                    | "retentionPolicy"
            )
        })
    {
        return Err(MaintenanceError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), MaintenanceError> {
    if name.is_empty()
        || name.len() > 96
        || name.starts_with('.')
        || name.ends_with('.')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(MaintenanceError::InvalidName);
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<&Path, MaintenanceError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('\\')
        || path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_)) || component.as_os_str().to_str().is_none()
        })
    {
        return Err(MaintenanceError::UnsafePath(value.to_owned()));
    }
    Ok(path)
}

fn inspect_file(root: &Path, path: &Path) -> Result<BackupFileEntry, MaintenanceError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| MaintenanceError::UnsafePath(path.display().to_string()))?;
    let relative_path = relative
        .to_str()
        .ok_or_else(|| MaintenanceError::UnsafePath(path.display().to_string()))?
        .replace(std::path::MAIN_SEPARATOR, "/");
    validate_relative_path(&relative_path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(MaintenanceError::UnsafePath(path.display().to_string()));
    }
    let (sha256_digest, size_bytes) = hash_file(path)?;
    if size_bytes != metadata.len() {
        return Err(MaintenanceError::Integrity(format!(
            "file {} changed while it was inspected",
            path.display()
        )));
    }
    Ok(BackupFileEntry {
        relative_path,
        size_bytes,
        sha256_digest,
    })
}

fn hash_file(path: &Path) -> Result<(String, u64), MaintenanceError> {
    let mut file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(MaintenanceError::UnsafePath(path.display().to_string()));
    }
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; BUFFER_BYTES].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total = total
            .checked_add(u64::try_from(read).map_err(|_| MaintenanceError::Overflow)?)
            .ok_or(MaintenanceError::Overflow)?;
    }
    Ok((lowercase_hex(&hasher.finalize()), total))
}

fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, MaintenanceError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(MaintenanceError::UnsafePath(path.display().to_string()));
    }
    Ok(fs::read(path)?)
}

fn copy_private_file(source: &Path, destination: &Path) -> Result<(), MaintenanceError> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(MaintenanceError::UnsafePath(source.display().to_string()));
    }
    let mut input = File::open(source)?;
    if !input.metadata()?.is_file() {
        return Err(MaintenanceError::UnsafePath(source.display().to_string()));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut output = options.open(destination)?;
    io::copy(&mut input, &mut output)?;
    output.flush()?;
    output.sync_all()?;
    set_private_file_permissions(destination)
}

fn write_private_file(path: &Path, body: &[u8]) -> Result<(), MaintenanceError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(body)?;
    file.flush()?;
    file.sync_all()?;
    set_private_file_permissions(path)
}

fn create_private_directory(path: &Path) -> Result<(), MaintenanceError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(MaintenanceError::UnsafePath(path.display().to_string()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(path)?,
        Err(error) => return Err(MaintenanceError::Io(error)),
    }
    validate_real_directory(path)?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn validate_real_directory(path: &Path) -> Result<(), MaintenanceError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(MaintenanceError::UnsafePath(path.display().to_string()));
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), MaintenanceError> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), MaintenanceError> {
    Ok(())
}

fn sync_directory_tree(root: &Path) -> Result<(), MaintenanceError> {
    let mut directories = vec![root.to_owned()];
    let mut index = 0;
    while index < directories.len() {
        let directory = directories[index].clone();
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.is_dir() {
                directories.push(entry.path());
            } else if !metadata.is_file() {
                return Err(MaintenanceError::UnsafePath(
                    entry.path().display().to_string(),
                ));
            }
        }
        index += 1;
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        sync_directory(&directory)?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), MaintenanceError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), MaintenanceError> {
    Ok(())
}

fn ensure_absent(path: &Path) -> Result<(), MaintenanceError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(MaintenanceError::AlreadyExists(path.to_owned())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(MaintenanceError::Io(error)),
    }
}

fn ensure_unique_entries(entries: &[BackupFileEntry]) -> Result<(), MaintenanceError> {
    let unique = entries
        .iter()
        .map(|entry| entry.relative_path.as_str())
        .collect::<BTreeSet<_>>();
    if unique.len() == entries.len() {
        Ok(())
    } else {
        Err(MaintenanceError::InvalidManifest)
    }
}

fn aggregate_entries(entries: &[BackupFileEntry]) -> Result<(u64, u64), MaintenanceError> {
    let count = u64::try_from(entries.len()).map_err(|_| MaintenanceError::Overflow)?;
    let bytes = entries.iter().try_fold(0_u64, |total, entry| {
        total
            .checked_add(entry.size_bytes)
            .ok_or(MaintenanceError::Overflow)
    })?;
    Ok((count, bytes))
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, MaintenanceError> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| MaintenanceError::InvalidTime)?;
    i64::try_from(duration.as_millis()).map_err(|_| MaintenanceError::InvalidTime)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    lowercase_hex(&Sha256::digest(bytes))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 0x0f)]),
            ]
        })
        .collect()
}

struct CleanupDirectory {
    path: PathBuf,
    armed: bool,
}

impl CleanupDirectory {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CleanupDirectory {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// Backup, verification, forensic preservation, or retention failure.
#[derive(Debug, Error)]
pub enum MaintenanceError {
    /// Filesystem operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// `SQLite` storage operation failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// JSON manifest or configuration encoding failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Backup label was not one safe path component.
    #[error(
        "backup name must be 1-96 portable alphanumeric, dot, underscore, or hyphen characters"
    )]
    InvalidName,
    /// Immutable backup destination already exists.
    #[error("immutable maintenance destination already exists: {0}")]
    AlreadyExists(PathBuf),
    /// Required canonical component is absent.
    #[error("required maintenance component is missing: {0}")]
    MissingComponent(String),
    /// Path is absolute, escaping, symbolic, or otherwise unsafe.
    #[error("unsafe maintenance path: {0}")]
    UnsafePath(String),
    /// Manifest shape or evidence is invalid.
    #[error("backup manifest is invalid")]
    InvalidManifest,
    /// Configuration snapshot is not a supported non-secret schema.
    #[error("backup configuration snapshot is invalid")]
    InvalidConfiguration,
    /// Secret inclusion or verification requires a sufficiently strong passphrase.
    #[error("secret-backup passphrase must contain 12 through 1024 bytes")]
    InvalidPassphrase,
    /// Encrypted secret backup requires the original passphrase.
    #[error("encrypted backup verification requires a passphrase")]
    PassphraseRequired,
    /// A passphrase was supplied for a backup which deliberately contains no secrets.
    #[error("backup contains no encrypted secrets; passphrase was unexpected")]
    UnexpectedPassphrase,
    /// Decrypted secret archive paths, sizes, or identity shape failed closed.
    #[error("encrypted secret archive is invalid")]
    InvalidSecretArchive,
    /// Authenticated encryption or password-based key derivation failed.
    #[error("encrypted secret archive authentication failed")]
    CryptographicFailure,
    /// Operating-system randomness was unavailable.
    #[error("operating-system randomness is unavailable")]
    RandomUnavailable,
    /// Exact digest, size, or relational verification failed.
    #[error("backup integrity failure: {0}")]
    Integrity(String),
    /// Aggregate count or size overflowed.
    #[error("maintenance count or size overflowed")]
    Overflow,
    /// Clock value cannot be represented by the durable contract.
    #[error("maintenance clock is outside the supported epoch range")]
    InvalidTime,
    /// Schema version cannot be represented or is not a forward migration.
    #[error("pre-migration backup schema versions are invalid")]
    InvalidMigrationVersion,
}

#[cfg(test)]
mod tests {
    use super::{
        MaintenanceError, create_backup, create_pre_migration_backup,
        inspect_existing_schema_version, preserve_forensic_database, verify_backup,
    };
    use crate::{FileArtifactBlobStore, FileChannelSecretStore, SqliteStore};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use mealy_application::{ArtifactBlobStore, OwnershipContext, sha256_digest};
    use mealy_domain::{ChannelBindingId, PrincipalId};
    use rusqlite::params;
    use std::{fs, time::SystemTime};

    #[test]
    fn complete_backup_restores_into_isolated_home_and_detects_tampering() {
        let home = tempfile::tempdir().expect("home");
        fs::write(
            home.path().join("config.json"),
            br#"{"formatVersion":1,"drainDeadlineMs":10000,"artifactGcMinimumAgeHours":24,"forensicBackupOnOpenFailure":true}"#,
        )
        .expect("config");
        let database = home.path().join("mealy.sqlite3");
        let store = SqliteStore::open(&database, 1).expect("store");
        let artifacts =
            FileArtifactBlobStore::new(home.path().join("artifacts"), 1024).expect("artifacts");
        let content = b"backup artifact";
        let blob = artifacts.commit(content).expect("blob");
        rusqlite::Connection::open(&database)
            .expect("metadata connection")
            .execute(
                "INSERT INTO artifact_blob(algorithm, digest, size_bytes, relative_path, committed_at_ms) \
                 VALUES ('sha256', ?1, ?2, ?3, 1)",
                params![
                    blob.digest,
                    i64::try_from(blob.size_bytes).expect("size"),
                    blob.relative_path
                ],
            )
            .expect("metadata");

        let report = create_backup(
            home.path(),
            &store,
            &artifacts,
            "daily-1",
            None,
            SystemTime::now(),
        )
        .expect("backup");
        assert_eq!(report.artifact_count, 1);
        let verified =
            verify_backup(home.path(), "daily-1", None, SystemTime::now()).expect("verify");
        assert_eq!(verified.artifact_count, 1);
        assert_eq!(verified.schema_version, 11);
        assert!(!verified.identity_verified);

        fs::write(
            report.path.join("artifacts").join(&blob.relative_path),
            b"tampered",
        )
        .expect("tamper");
        assert!(matches!(
            verify_backup(home.path(), "daily-1", None, SystemTime::now()),
            Err(MaintenanceError::Integrity(_))
        ));
    }

    #[test]
    fn secret_backup_is_explicit_authenticated_encrypted_and_identity_ready() {
        let home = tempfile::tempdir().expect("home");
        fs::write(
            home.path().join("config.json"),
            br#"{"formatVersion":1,"drainDeadlineMs":10000,"artifactGcMinimumAgeHours":24,"forensicBackupOnOpenFailure":true}"#,
        )
        .expect("config");
        let database = home.path().join("mealy.sqlite3");
        let mut store = SqliteStore::open(&database, 1).expect("store");
        let principal_id = PrincipalId::new();
        let channel_binding_id = ChannelBindingId::new();
        store
            .register_local_identity(OwnershipContext::new(principal_id, channel_binding_id), 1)
            .expect("register identity");
        let token = [0x5a_u8; 32];
        fs::write(
            home.path().join("identity.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "formatVersion": 1,
                "bearerToken": URL_SAFE_NO_PAD.encode(token),
                "principalId": principal_id,
                "channelBindingId": channel_binding_id,
            }))
            .expect("identity JSON"),
        )
        .expect("identity");
        let channel_secrets =
            FileChannelSecretStore::new(home.path().join("channel-secrets")).expect("broker");
        let webhook_binding = ChannelBindingId::new();
        let webhook_key = [0xa5_u8; 32];
        channel_secrets
            .put(webhook_binding, &webhook_key)
            .expect("channel key");
        let artifacts =
            FileArtifactBlobStore::new(home.path().join("artifacts"), 1024).expect("artifacts");
        let passphrase = "correct horse battery staple";
        let report = create_backup(
            home.path(),
            &store,
            &artifacts,
            "encrypted-1",
            Some(passphrase),
            SystemTime::now(),
        )
        .expect("encrypted backup");
        assert!(report.secrets_included);
        let encrypted = fs::read(report.path.join("secrets.enc")).expect("encrypted archive");
        assert!(!encrypted.windows(token.len()).any(|window| window == token));
        assert!(
            !encrypted
                .windows(webhook_key.len())
                .any(|window| window == webhook_key)
        );
        assert!(matches!(
            verify_backup(
                home.path(),
                "encrypted-1",
                Some("wrong passphrase value"),
                SystemTime::now()
            ),
            Err(MaintenanceError::CryptographicFailure)
        ));
        let verified = verify_backup(
            home.path(),
            "encrypted-1",
            Some(passphrase),
            SystemTime::now(),
        )
        .expect("verify encrypted backup");
        assert!(verified.secrets_included);
        assert!(verified.identity_verified);
    }

    #[test]
    fn corrupt_source_and_sidecars_are_copied_without_modifying_originals() {
        let home = tempfile::tempdir().expect("home");
        let database = home.path().join("mealy.sqlite3");
        fs::write(&database, b"not sqlite").expect("database");
        fs::write(home.path().join("mealy.sqlite3-wal"), b"wal evidence").expect("wal");
        let before = fs::read(&database).expect("before");
        let report = preserve_forensic_database(
            home.path(),
            &database,
            "file is not a database",
            SystemTime::now(),
        )
        .expect("preserve");
        assert_eq!(report.file_count, 2);
        assert_eq!(fs::read(&database).expect("after"), before);
        assert_eq!(
            sha256_digest(&fs::read(report.path.join("mealy.sqlite3")).expect("preserved")),
            sha256_digest(&before)
        );
    }

    #[test]
    fn forward_migration_snapshot_preserves_exact_prior_schema() {
        let home = tempfile::tempdir().expect("home");
        fs::write(
            home.path().join("config.json"),
            br#"{"formatVersion":1,"drainDeadlineMs":10000,"artifactGcMinimumAgeHours":24,"forensicBackupOnOpenFailure":true}"#,
        )
        .expect("config");
        let database = home.path().join("mealy.sqlite3");
        drop(SqliteStore::open(&database, 1).expect("current store"));
        let connection = rusqlite::Connection::open(&database).expect("downgrade fixture");
        connection
            .execute_batch(
                "DROP TABLE daemon_run_record;
                 DELETE FROM schema_version WHERE version = 11;
                 PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .expect("simulate exact v10 snapshot");
        drop(connection);
        assert_eq!(
            inspect_existing_schema_version(&database).expect("inspect"),
            Some(10)
        );
        let report = create_pre_migration_backup(home.path(), &database, 10, 11, SystemTime::now())
            .expect("migration backup");
        let snapshot = rusqlite::Connection::open(report.path.join("state.sqlite3"))
            .expect("open migration snapshot");
        let version: i64 = snapshot
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .expect("snapshot version");
        assert_eq!(version, 10);
        assert!(report.path.join("manifest.json").is_file());
    }
}
