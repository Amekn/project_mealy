use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use mealy_application::{
    CancellationProbe, ReadOnlyTool, ReadToolDescriptor, ReadToolError, ReadToolOutput,
    sha256_digest,
};
use mealy_domain::{SkillAsset, SkillManifest, SkillManifestError};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

const MANIFEST_FILE_NAME: &str = "manifest.json";
const MAXIMUM_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAXIMUM_PACKAGE_ENTRIES: usize = 512;
static INSTALL_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Maximum combined instruction bytes that may be active in one daemon context profile.
pub const MAXIMUM_ACTIVE_SKILL_INSTRUCTION_BYTES: u64 = 256 * 1024;
/// Maximum passive-resource bytes retained for all enabled skills in one daemon.
pub const MAXIMUM_ACTIVE_SKILL_RESOURCE_BYTES: u64 = 32 * 1024 * 1024;
const MAXIMUM_SKILL_RESOURCE_READ_BYTES: usize = 64 * 1024;
const DEFAULT_SKILL_RESOURCE_READ_BYTES: usize = 32 * 1024;
const MAXIMUM_SKILL_RESOURCE_OUTPUT_BYTES: u64 = 128 * 1024;
// This in-memory adapter shares the normal run ceiling. A one-second descriptor proved too short
// under concurrent restart/load contention even when the run itself allowed five seconds.
const SKILL_RESOURCE_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Exact verified bytes for one declared passive skill asset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedSkillAsset {
    declaration: SkillAsset,
    bytes: Vec<u8>,
}

impl InspectedSkillAsset {
    /// Returns the immutable manifest declaration for these bytes.
    #[must_use]
    pub const fn declaration(&self) -> &SkillAsset {
        &self.declaration
    }

    /// Returns the exact bytes matching the declared digest and size.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Fully inspected data-only skill package, retained in memory to close source time-of-check races.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedSkillPackage {
    manifest: SkillManifest,
    manifest_bytes: Vec<u8>,
    manifest_digest: String,
    assets: BTreeMap<String, InspectedSkillAsset>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeSkillResource {
    version: String,
    media_type: String,
    content_digest: String,
    bytes: Vec<u8>,
}

/// Bounded in-memory read adapter for passive resources from enabled, verified skill packages.
pub struct SkillResourceReadTool {
    descriptor: ReadToolDescriptor,
    resources: BTreeMap<(String, String), RuntimeSkillResource>,
}

impl std::fmt::Debug for SkillResourceReadTool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SkillResourceReadTool")
            .field("resource_count", &self.resources.len())
            .finish_non_exhaustive()
    }
}

impl SkillResourceReadTool {
    /// Builds the resource adapter from enabled packages already verified in the same startup.
    ///
    /// # Errors
    ///
    /// Returns [`SkillPackageError`] for duplicate identities, absent asset bytes, aggregate
    /// resource overflow, or invalid canonical descriptor evidence.
    pub fn from_packages(
        packages: &[InspectedSkillPackage],
    ) -> Result<Option<Self>, SkillPackageError> {
        let mut resources = BTreeMap::new();
        let mut total_bytes = 0_u64;
        for package in packages {
            for declaration in &package.manifest.resources {
                total_bytes = total_bytes
                    .checked_add(declaration.size_bytes)
                    .ok_or(SkillPackageError::InvalidPackage)?;
                if total_bytes > MAXIMUM_ACTIVE_SKILL_RESOURCE_BYTES {
                    return Err(SkillPackageError::InvalidPackage);
                }
                let asset = package
                    .assets
                    .get(&declaration.relative_path)
                    .ok_or(SkillPackageError::InvalidPackage)?;
                let key = (
                    package.manifest.skill_id.clone(),
                    declaration.relative_path.clone(),
                );
                if resources
                    .insert(
                        key,
                        RuntimeSkillResource {
                            version: package.manifest.version.clone(),
                            media_type: declaration.media_type.clone(),
                            content_digest: declaration.content_digest.clone(),
                            bytes: asset.bytes.clone(),
                        },
                    )
                    .is_some()
                {
                    return Err(SkillPackageError::InvalidPackage);
                }
            }
        }
        if resources.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Self {
                descriptor: skill_resource_descriptor()?,
                resources,
            }))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SkillResourceReadArguments {
    skill_id: String,
    path: String,
    #[serde(default)]
    offset_bytes: usize,
    #[serde(default = "default_skill_resource_read_bytes")]
    maximum_bytes: usize,
}

impl ReadOnlyTool for SkillResourceReadTool {
    fn descriptor(&self) -> ReadToolDescriptor {
        self.descriptor.clone()
    }

    fn validate_arguments(&self, arguments: &serde_json::Value) -> Result<(), ReadToolError> {
        parse_skill_resource_arguments(arguments).map(|_| ())
    }

    fn execute(
        &self,
        arguments: &serde_json::Value,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ReadToolOutput, ReadToolError> {
        let arguments = parse_skill_resource_arguments(arguments)?;
        if cancellation.is_cancelled() {
            return Err(ReadToolError::Cancelled);
        }
        let resource = self
            .resources
            .get(&(arguments.skill_id.clone(), arguments.path.clone()))
            .ok_or(ReadToolError::NotFound)?;
        if arguments.offset_bytes > resource.bytes.len() {
            return Err(ReadToolError::InvalidArguments(
                "offsetBytes exceeds the resource size".to_owned(),
            ));
        }
        let end = arguments
            .offset_bytes
            .saturating_add(arguments.maximum_bytes)
            .min(resource.bytes.len());
        let chunk = &resource.bytes[arguments.offset_bytes..end];
        let (content_encoding, content) = match std::str::from_utf8(chunk) {
            Ok(text) => ("utf-8", text.to_owned()),
            Err(_) => ("base64", BASE64_STANDARD.encode(chunk)),
        };
        let source_locator = skill_resource_locator(&arguments.skill_id, &arguments.path);
        let bytes = serde_json::to_vec(&serde_json::json!({
            "skillId": arguments.skill_id,
            "version": resource.version,
            "path": arguments.path,
            "mediaType": resource.media_type,
            "contentDigest": resource.content_digest,
            "offsetBytes": arguments.offset_bytes,
            "returnedBytes": chunk.len(),
            "totalBytes": resource.bytes.len(),
            "truncated": end < resource.bytes.len(),
            "contentEncoding": content_encoding,
            "content": content,
            "sourceLocator": source_locator,
        }))
        .map_err(|_| ReadToolError::Unavailable("skill resource encoding failed".to_owned()))?;
        let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if actual > self.descriptor.maximum_output_bytes {
            return Err(ReadToolError::OutputTooLarge {
                actual,
                maximum: self.descriptor.maximum_output_bytes,
            });
        }
        Ok(ReadToolOutput {
            media_type: "application/json".to_owned(),
            bytes,
            source_locator,
        })
    }
}

impl InspectedSkillPackage {
    /// Returns the validated data-only manifest.
    #[must_use]
    pub const fn manifest(&self) -> &SkillManifest {
        &self.manifest
    }

    /// Returns the digest of the exact manifest bytes.
    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// Returns every declared asset in stable path order.
    #[must_use]
    pub const fn assets(&self) -> &BTreeMap<String, InspectedSkillAsset> {
        &self.assets
    }

    /// Returns the sum of all declared asset sizes.
    #[must_use]
    pub fn total_asset_bytes(&self) -> u64 {
        self.assets.values().fold(0_u64, |total, asset| {
            total.saturating_add(asset.declaration.size_bytes)
        })
    }
}

/// Safe package-inspection or immutable-publication failure.
#[derive(Debug, Error)]
pub enum SkillPackageError {
    /// Filesystem access failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Manifest JSON did not match the strict contract.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Manifest fields violated the data-only contract.
    #[error(transparent)]
    Manifest(#[from] SkillManifestError),
    /// Manifest location, inventory, file type, or declared asset evidence was unsafe.
    #[error("skill package structure or asset evidence is invalid")]
    InvalidPackage,
    /// The exact manifest bytes did not match the owner-supplied digest.
    #[error("skill package manifest digest does not match the expected digest")]
    ManifestDigestMismatch,
    /// An existing immutable installation differs from the inspected source package.
    #[error("skill package installation digest already exists with different bytes")]
    InstallationConflict,
}

/// Inspects one exact `manifest.json` and all declared assets without executing package content.
///
/// The package root must be a canonical real directory. Its complete file inventory must contain
/// only `manifest.json` and the manifest-declared instruction/resource paths; symlinks and other
/// file types are rejected. All bytes are retained in the returned value so publication cannot
/// race a later source change.
///
/// # Errors
///
/// Returns [`SkillPackageError`] for malformed manifests, unsafe paths/file types, undeclared or
/// absent files, digest/size mismatches, non-UTF-8 instructions, and I/O failures.
pub fn inspect_skill_package(
    manifest_path: &Path,
    package_root: &Path,
    expected_manifest_digest: Option<&str>,
) -> Result<InspectedSkillPackage, SkillPackageError> {
    let supplied_root_metadata = fs::symlink_metadata(package_root)?;
    if !supplied_root_metadata.is_dir() || supplied_root_metadata.file_type().is_symlink() {
        return Err(SkillPackageError::InvalidPackage);
    }
    let root = fs::canonicalize(package_root)?;
    let root_metadata = fs::symlink_metadata(&root)?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(SkillPackageError::InvalidPackage);
    }
    let expected_manifest_path = root.join(MANIFEST_FILE_NAME);
    let canonical_manifest = fs::canonicalize(manifest_path)?;
    if canonical_manifest != expected_manifest_path {
        return Err(SkillPackageError::InvalidPackage);
    }
    let manifest_metadata = fs::symlink_metadata(&canonical_manifest)?;
    if !manifest_metadata.is_file()
        || manifest_metadata.file_type().is_symlink()
        || manifest_metadata.len() > MAXIMUM_MANIFEST_BYTES
    {
        return Err(SkillPackageError::InvalidPackage);
    }
    let manifest_bytes = read_bounded_regular_file(
        &canonical_manifest,
        MAXIMUM_MANIFEST_BYTES,
        Some(manifest_metadata.len()),
    )?;
    let manifest_digest = sha256_digest(&manifest_bytes);
    if expected_manifest_digest.is_some_and(|expected| expected != manifest_digest) {
        return Err(SkillPackageError::ManifestDigestMismatch);
    }
    let manifest = serde_json::from_slice::<SkillManifest>(&manifest_bytes)?;
    manifest.validate()?;

    let declared = manifest
        .instructions
        .iter()
        .chain(&manifest.resources)
        .map(|asset| asset.relative_path.clone())
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    let mut scanned_entries = 0_usize;
    collect_package_files(&root, &root, &mut actual, &mut scanned_entries)?;
    let mut expected = declared.clone();
    expected.insert(MANIFEST_FILE_NAME.to_owned());
    if actual != expected {
        return Err(SkillPackageError::InvalidPackage);
    }

    let instruction_paths = manifest
        .instructions
        .iter()
        .map(|asset| asset.relative_path.as_str())
        .collect::<BTreeSet<_>>();
    let mut assets = BTreeMap::new();
    for declaration in manifest.instructions.iter().chain(&manifest.resources) {
        let path = root.join(&declaration.relative_path);
        let canonical = fs::canonicalize(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        if canonical != path
            || !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != declaration.size_bytes
        {
            return Err(SkillPackageError::InvalidPackage);
        }
        let bytes =
            read_bounded_regular_file(&path, declaration.size_bytes, Some(declaration.size_bytes))?;
        let invalid_instruction = instruction_paths
            .contains(declaration.relative_path.as_str())
            .then(|| std::str::from_utf8(&bytes))
            .is_some_and(|result| {
                result.is_err()
                    || result.is_ok_and(|text| {
                        text.chars().any(|character| {
                            character.is_control() && !matches!(character, '\n' | '\r' | '\t')
                        })
                    })
            });
        if u64::try_from(bytes.len()).ok() != Some(declaration.size_bytes)
            || sha256_digest(&bytes) != declaration.content_digest
            || invalid_instruction
        {
            return Err(SkillPackageError::InvalidPackage);
        }
        assets.insert(
            declaration.relative_path.clone(),
            InspectedSkillAsset {
                declaration: declaration.clone(),
                bytes,
            },
        );
    }
    Ok(InspectedSkillPackage {
        manifest,
        manifest_bytes,
        manifest_digest,
        assets,
    })
}

/// Publishes an inspected package below `installation_root/MANIFEST_DIGEST` without rewriting an
/// existing immutable digest directory.
///
/// # Errors
///
/// Returns [`SkillPackageError`] when directories/files cannot be created privately or an existing
/// digest directory does not reproduce the exact inspected package.
pub fn publish_skill_package(
    package: &InspectedSkillPackage,
    installation_root: &Path,
) -> Result<PathBuf, SkillPackageError> {
    create_private_directory(installation_root)?;
    let destination = installation_root.join(package.manifest_digest());
    if destination.exists() {
        let installed = inspect_skill_package(
            &destination.join(MANIFEST_FILE_NAME),
            &destination,
            Some(package.manifest_digest()),
        )?;
        if installed == *package {
            return Ok(destination);
        }
        return Err(SkillPackageError::InstallationConflict);
    }
    let temporary = installation_root.join(format!(
        ".{}.tmp-{}-{}",
        package.manifest_digest(),
        std::process::id(),
        INSTALL_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    if temporary.exists() {
        return Err(SkillPackageError::InstallationConflict);
    }
    create_private_directory(&temporary)?;
    let publication: Result<(), SkillPackageError> = (|| {
        write_private_file(&temporary.join(MANIFEST_FILE_NAME), &package.manifest_bytes)?;
        for (relative_path, asset) in &package.assets {
            let target = temporary.join(relative_path);
            let parent = target.parent().ok_or(SkillPackageError::InvalidPackage)?;
            create_private_directory(parent)?;
            write_private_file(&target, &asset.bytes)?;
        }
        sync_tree(&temporary)?;
        fs::rename(&temporary, &destination)?;
        File::open(installation_root)?.sync_all()?;
        Ok(())
    })();
    if publication.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    publication?;
    Ok(destination)
}

fn collect_package_files(
    root: &Path,
    directory: &Path,
    output: &mut BTreeSet<String>,
    scanned_entries: &mut usize,
) -> Result<(), SkillPackageError> {
    for entry in fs::read_dir(directory)? {
        *scanned_entries = scanned_entries.saturating_add(1);
        if *scanned_entries > MAXIMUM_PACKAGE_ENTRIES {
            return Err(SkillPackageError::InvalidPackage);
        }
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(SkillPackageError::InvalidPackage);
        }
        if metadata.is_dir() {
            collect_package_files(root, &path, output, scanned_entries)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| SkillPackageError::InvalidPackage)?;
            if !relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
            {
                return Err(SkillPackageError::InvalidPackage);
            }
            let relative = relative
                .to_str()
                .ok_or(SkillPackageError::InvalidPackage)?
                .replace(std::path::MAIN_SEPARATOR, "/");
            output.insert(relative);
        } else {
            return Err(SkillPackageError::InvalidPackage);
        }
    }
    Ok(())
}

fn default_skill_resource_read_bytes() -> usize {
    DEFAULT_SKILL_RESOURCE_READ_BYTES
}

fn parse_skill_resource_arguments(
    arguments: &serde_json::Value,
) -> Result<SkillResourceReadArguments, ReadToolError> {
    let arguments = serde_json::from_value::<SkillResourceReadArguments>(arguments.clone())
        .map_err(|_| {
            ReadToolError::InvalidArguments(
                "arguments do not match the skill resource schema".to_owned(),
            )
        })?;
    if !valid_skill_identifier(&arguments.skill_id)
        || !safe_skill_relative_path(&arguments.path)
        || arguments.offset_bytes
            > usize::try_from(MAXIMUM_ACTIVE_SKILL_RESOURCE_BYTES).unwrap_or(usize::MAX)
        || !(1..=MAXIMUM_SKILL_RESOURCE_READ_BYTES).contains(&arguments.maximum_bytes)
    {
        return Err(ReadToolError::InvalidArguments(
            "skillId, path, offsetBytes, or maximumBytes is invalid".to_owned(),
        ));
    }
    Ok(arguments)
}

pub(crate) fn validate_skill_resource_tool_arguments(
    arguments: &serde_json::Value,
) -> Result<String, ReadToolError> {
    let arguments = parse_skill_resource_arguments(arguments)?;
    Ok(skill_resource_locator(&arguments.skill_id, &arguments.path))
}

fn skill_resource_locator(skill_id: &str, path: &str) -> String {
    format!("skill://{skill_id}/{path}")
}

fn valid_skill_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

fn safe_skill_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.contains("//")
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
        && !value.chars().any(char::is_control)
}

fn skill_resource_descriptor() -> Result<ReadToolDescriptor, SkillPackageError> {
    let input_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "skillId": {
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]*$"
            },
            "path": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256
            },
            "offsetBytes": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAXIMUM_ACTIVE_SKILL_RESOURCE_BYTES
            },
            "maximumBytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAXIMUM_SKILL_RESOURCE_READ_BYTES
            }
        },
        "required": ["skillId", "path"],
        "additionalProperties": false
    });
    let output_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "skillId": {"type": "string"},
            "version": {"type": "string"},
            "path": {"type": "string"},
            "mediaType": {"type": "string"},
            "contentDigest": {"type": "string"},
            "offsetBytes": {"type": "integer"},
            "returnedBytes": {"type": "integer"},
            "totalBytes": {"type": "integer"},
            "truncated": {"type": "boolean"},
            "contentEncoding": {"type": "string", "enum": ["utf-8", "base64"]},
            "content": {"type": "string"},
            "sourceLocator": {"type": "string"}
        },
        "required": [
            "skillId", "version", "path", "mediaType", "contentDigest", "offsetBytes",
            "returnedBytes", "totalBytes", "truncated", "contentEncoding", "content",
            "sourceLocator"
        ],
        "additionalProperties": false
    });
    let schema_digest = sha256_digest(input_schema.to_string().as_bytes());
    let mut descriptor = ReadToolDescriptor {
        tool_id: "skill.read_resource".to_owned(),
        version: "1".to_owned(),
        input_schema,
        output_schema,
        descriptor_digest: String::new(),
        schema_digest,
        effect_class: "read_only".to_owned(),
        risk_class: "low".to_owned(),
        required_capability: "skill:resource-read".to_owned(),
        timeout: SKILL_RESOURCE_READ_TIMEOUT,
        maximum_output_bytes: MAXIMUM_SKILL_RESOURCE_OUTPUT_BYTES,
        conflict_key_template: "skill-resource:{skillId}:{path}".to_owned(),
        recovery: "retry".to_owned(),
    };
    descriptor.descriptor_digest = descriptor
        .computed_descriptor_digest()
        .map_err(|_| SkillPackageError::InvalidPackage)?;
    descriptor
        .validate_evidence()
        .map_err(|_| SkillPackageError::InvalidPackage)?;
    Ok(descriptor)
}

fn create_private_directory(path: &Path) -> Result<(), SkillPackageError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(SkillPackageError::InvalidPackage);
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn read_bounded_regular_file(
    path: &Path,
    maximum_bytes: u64,
    exact_bytes: Option<u64>,
) -> Result<Vec<u8>, SkillPackageError> {
    #[cfg(unix)]
    let mut file = {
        use rustix::fs::{Mode, OFlags, open};
        open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| SkillPackageError::Io(error.into()))?
    };
    #[cfg(not(unix))]
    let mut file = OpenOptions::new().read(true).open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() > maximum_bytes
        || exact_bytes.is_some_and(|exact| metadata.len() != exact)
    {
        return Err(SkillPackageError::InvalidPackage);
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum_bytes
        || exact_bytes.is_some_and(|exact| u64::try_from(bytes.len()).ok() != Some(exact))
    {
        return Err(SkillPackageError::InvalidPackage);
    }
    Ok(bytes)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), SkillPackageError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sync_tree(directory: &Path) -> Result<(), SkillPackageError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_tree(&entry.path())?;
        }
    }
    File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        SKILL_RESOURCE_READ_TIMEOUT, SkillResourceReadTool, inspect_skill_package,
        publish_skill_package,
    };
    use mealy_application::{CancellationProbe, ReadOnlyTool, sha256_digest};
    use serde_json::json;
    use std::fs;

    struct NotCancelled;

    impl CancellationProbe for NotCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    fn package(root: &std::path::Path) -> String {
        fs::create_dir_all(root.join("instructions")).expect("instruction directory");
        fs::create_dir_all(root.join("resources")).expect("resource directory");
        let instruction = b"Review the evidence carefully.";
        let resource = br#"{"minimumScore":4}"#;
        fs::write(root.join("instructions/review.md"), instruction).expect("instruction");
        fs::write(root.join("resources/rubric.json"), resource).expect("resource");
        let manifest = json!({
            "contractVersion": "mealy.skill.v1",
            "skillId": "mealy.fixture.review",
            "version": "1.0.0",
            "instructions": [{
                "relativePath": "instructions/review.md",
                "mediaType": "text/markdown",
                "contentDigest": sha256_digest(instruction),
                "sizeBytes": instruction.len()
            }],
            "resources": [{
                "relativePath": "resources/rubric.json",
                "mediaType": "application/json",
                "contentDigest": sha256_digest(resource),
                "sizeBytes": resource.len()
            }],
            "requiredTools": []
        });
        let body = serde_json::to_vec_pretty(&manifest).expect("manifest bytes");
        fs::write(root.join("manifest.json"), &body).expect("manifest");
        sha256_digest(&body)
    }

    #[test]
    fn inspection_and_publication_are_exact_data_only_and_idempotent() {
        let source = tempfile::tempdir().expect("source");
        let digest = package(source.path());
        let inspected = inspect_skill_package(
            &source.path().join("manifest.json"),
            source.path(),
            Some(&digest),
        )
        .expect("inspect package");
        assert_eq!(inspected.manifest().skill_id, "mealy.fixture.review");
        assert_eq!(inspected.assets().len(), 2);

        let installation = tempfile::tempdir().expect("installation");
        let published =
            publish_skill_package(&inspected, installation.path()).expect("publish package");
        assert_eq!(published, installation.path().join(&digest));
        assert_eq!(
            publish_skill_package(&inspected, installation.path()).expect("repeat publication"),
            published
        );
        inspect_skill_package(&published.join("manifest.json"), &published, Some(&digest))
            .expect("inspect installed package");
    }

    #[test]
    fn inspection_rejects_undeclared_files_and_changed_assets() {
        let source = tempfile::tempdir().expect("source");
        let digest = package(source.path());
        fs::write(source.path().join("run.sh"), b"#!/bin/sh").expect("undeclared executable");
        assert!(
            inspect_skill_package(
                &source.path().join("manifest.json"),
                source.path(),
                Some(&digest)
            )
            .is_err()
        );
        fs::remove_file(source.path().join("run.sh")).expect("remove executable");
        fs::write(source.path().join("instructions/review.md"), b"changed").expect("tamper asset");
        assert!(
            inspect_skill_package(
                &source.path().join("manifest.json"),
                source.path(),
                Some(&digest)
            )
            .is_err()
        );
    }

    #[test]
    fn enabled_resource_tool_returns_bounded_cited_content_without_external_authority() {
        let source = tempfile::tempdir().expect("source");
        let digest = package(source.path());
        let inspected = inspect_skill_package(
            &source.path().join("manifest.json"),
            source.path(),
            Some(&digest),
        )
        .expect("inspect package");
        let tool = SkillResourceReadTool::from_packages(&[inspected])
            .expect("resource tool")
            .expect("resource present");
        let descriptor = tool.descriptor();
        descriptor.validate_evidence().expect("descriptor evidence");
        assert_eq!(descriptor.tool_id, "skill.read_resource");
        assert_eq!(descriptor.required_capability, "skill:resource-read");
        assert_eq!(descriptor.timeout, SKILL_RESOURCE_READ_TIMEOUT);
        let output = tool
            .execute(
                &json!({
                    "skillId": "mealy.fixture.review",
                    "path": "resources/rubric.json",
                    "maximumBytes": 4
                }),
                &NotCancelled,
            )
            .expect("read resource");
        assert_eq!(output.media_type, "application/json");
        assert_eq!(
            output.source_locator,
            "skill://mealy.fixture.review/resources/rubric.json"
        );
        let body: serde_json::Value =
            serde_json::from_slice(&output.bytes).expect("resource output JSON");
        assert_eq!(body["contentEncoding"], "utf-8");
        assert_eq!(body["content"], "{\"mi");
        assert_eq!(body["truncated"], true);
        assert_eq!(body["sourceLocator"], output.source_locator);
        assert!(
            tool.validate_arguments(&json!({
                "skillId": "mealy.fixture.review",
                "path": "resources/rubric.json",
                "unexpected": true
            }))
            .is_err()
        );
    }
}
