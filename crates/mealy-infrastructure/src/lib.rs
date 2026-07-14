//! Concrete infrastructure adapters for Mealy.

mod artifact;
mod browser;
mod browser_bundle;
mod channel_secret;
mod extension_host;
mod fixture;
mod maintenance;
mod mcp;
mod provider_secret;
mod sandbox;
mod skill_package;
mod sqlite;
mod system;
mod trusted_executable;
mod web;
mod workspace;

pub use artifact::{ArtifactGarbageCollectionReport, ArtifactStorageUsage, FileArtifactBlobStore};
pub use browser::{
    BrowserHostError, BrowserReadTool, BrowserRuntimeProbe, browser_worker_main,
    probe_browser_bundle_product, verify_browser_runtime_installation,
};
pub use browser_bundle::{
    BrowserBundleEntry, BrowserBundleError, BrowserBundleInspection, inspect_browser_bundle,
    publish_browser_bundle,
};
pub use channel_secret::{ChannelSecretStoreError, FileChannelSecretStore};
pub use extension_host::{
    InstalledExtensionPackage, LinuxBubblewrapExtensionHost, inspect_extension_package,
};
pub use fixture::{FixtureReadTool, FixtureResource, FixtureToolConfigurationError};
pub use maintenance::{
    BackupActivationReport, BackupManifest, BackupReport, BackupVerificationReport, ExportReport,
    ForensicBackupReport, MaintenanceError, MigrationBackupActivationReport, MigrationBackupReport,
    activate_backup, activate_migration_backup, create_backup, create_complete_export,
    create_pre_migration_backup, inspect_existing_schema_version, preserve_forensic_database,
    publish_export, verify_backup,
};
pub use mcp::{
    McpHostError, McpReadTool, discover_mcp_stdio_server, load_mcp_read_tools,
    mcp_stdio_launcher_main,
};
pub use provider_secret::{FileProviderSecretStore, ProviderSecretStoreError};
pub use sandbox::{LinuxBubblewrapConfig, LinuxBubblewrapExecutor, SandboxRuntimeBinding};
pub use skill_package::{
    InspectedSkillAsset, InspectedSkillPackage, MAXIMUM_ACTIVE_SKILL_INSTRUCTION_BYTES,
    MAXIMUM_ACTIVE_SKILL_RESOURCE_BYTES, SkillPackageError, SkillResourceReadTool,
    inspect_skill_package, publish_skill_package,
};
pub use sqlite::{
    ArtifactBlobRecord, JournalRecord, LATEST_SCHEMA_VERSION, OutboxRecord, SqliteStore,
    StoreError, TaskMutation, TaskSnapshot,
};
pub use system::{SystemClock, SystemIdGenerator};
pub use trusted_executable::is_trusted_system_executable;
pub use web::{WebReadTool, WebToolConfigurationError};
pub use workspace::{WorkspaceGrant, WorkspaceReadTool, WorkspaceToolConfigurationError};
