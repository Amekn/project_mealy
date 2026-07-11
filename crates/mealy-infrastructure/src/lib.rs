//! Concrete infrastructure adapters for Mealy.

mod artifact;
mod channel_secret;
mod extension_host;
mod fixture;
mod maintenance;
mod sandbox;
mod sqlite;
mod system;

pub use artifact::{ArtifactGarbageCollectionReport, ArtifactStorageUsage, FileArtifactBlobStore};
pub use channel_secret::{ChannelSecretStoreError, FileChannelSecretStore};
pub use extension_host::{
    InstalledExtensionPackage, LinuxBubblewrapExtensionHost, inspect_extension_package,
};
pub use fixture::{FixtureReadTool, FixtureResource, FixtureToolConfigurationError};
pub use maintenance::{
    BackupManifest, BackupReport, BackupVerificationReport, ExportReport, ForensicBackupReport,
    MaintenanceError, MigrationBackupReport, create_backup, create_complete_export,
    create_pre_migration_backup, inspect_existing_schema_version, preserve_forensic_database,
    publish_export, verify_backup,
};
pub use sandbox::{LinuxBubblewrapConfig, LinuxBubblewrapExecutor, SandboxRuntimeBinding};
pub use sqlite::{
    ArtifactBlobRecord, JournalRecord, LATEST_SCHEMA_VERSION, OutboxRecord, SqliteStore,
    StoreError, TaskMutation, TaskSnapshot,
};
pub use system::{SystemClock, SystemIdGenerator};
