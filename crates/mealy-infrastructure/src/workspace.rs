use mealy_application::{
    CancellationProbe, ReadOnlyTool, ReadToolDescriptor, ReadToolError, ReadToolOutput,
    sha256_digest,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use thiserror::Error;

#[cfg(target_os = "linux")]
use rustix::fs::{Dir, FileType, Mode, OFlags, ResolveFlags, fstat, open, openat2};
#[cfg(target_os = "linux")]
use std::io::{Read, Seek, SeekFrom};

const MAXIMUM_WORKSPACES: usize = 16;
const MAXIMUM_LOGICAL_PATH_BYTES: usize = 2_048;
const MAXIMUM_TOOL_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAXIMUM_READ_BYTES: usize = 128 * 1024;
const DEFAULT_READ_BYTES: usize = 32 * 1024;
const MAXIMUM_LIST_ENTRIES: usize = 512;
const MAXIMUM_LIST_SCANNED_ENTRIES: usize = 4_096;
const DEFAULT_LIST_ENTRIES: usize = 100;
const MAXIMUM_SEARCH_RESULTS: usize = 100;
const DEFAULT_SEARCH_RESULTS: usize = 25;
const MAXIMUM_SEARCH_FILES: usize = 10_000;
const MAXIMUM_SEARCH_DIRECTORIES: usize = 10_000;
const MAXIMUM_SEARCH_ENTRIES: usize = 100_000;
const MAXIMUM_SEARCH_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_SEARCH_FILE_BYTES: usize = 1024 * 1024;

/// One owner-approved host directory mapped to a stable logical workspace identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceGrant {
    /// Stable model-visible identity.
    pub workspace_id: String,
    /// Absolute host path retained only inside the trusted adapter.
    pub root: PathBuf,
}

/// Invalid or unenforceable workspace tool configuration.
#[derive(Debug, Error)]
pub enum WorkspaceToolConfigurationError {
    /// Identity, path, count, or duplicate constraints failed.
    #[error("workspace grant configuration is invalid")]
    Invalid,
    /// The current platform cannot enforce beneath-root path resolution.
    #[error("workspace tools require Linux openat2 enforcement")]
    UnsupportedPlatform,
    /// A configured root is absent, redirected, or cannot be opened safely.
    #[error("workspace root cannot be opened with required path protections")]
    Unavailable,
    /// A canonical descriptor could not be constructed.
    #[error("workspace tool descriptor is invalid")]
    InvalidDescriptor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkspaceOperation {
    List,
    Stat,
    Read,
    Search,
}

impl WorkspaceOperation {
    const fn tool_id(self) -> &'static str {
        match self {
            Self::List => "workspace.list",
            Self::Stat => "workspace.stat",
            Self::Read => "workspace.read",
            Self::Search => "workspace.search",
        }
    }

    fn from_tool_id(value: &str) -> Option<Self> {
        match value {
            "workspace.list" => Some(Self::List),
            "workspace.stat" => Some(Self::Stat),
            "workspace.read" => Some(Self::Read),
            "workspace.search" => Some(Self::Search),
            _ => None,
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct WorkspaceRoot {
    directory: std::fs::File,
}

/// One of the four bounded read-only workspace operations.
#[derive(Debug)]
pub struct WorkspaceReadTool {
    operation: WorkspaceOperation,
    descriptor: ReadToolDescriptor,
    #[cfg(target_os = "linux")]
    roots: Arc<BTreeMap<String, WorkspaceRoot>>,
    invocation_count: AtomicUsize,
}

impl WorkspaceReadTool {
    /// Builds list/stat/read/search tools over an exact set of approved roots.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceToolConfigurationError`] when roots are invalid, redirected, duplicated,
    /// unsupported, or cannot pass an `openat2` enforcement probe.
    pub fn suite(
        grants: impl IntoIterator<Item = WorkspaceGrant>,
    ) -> Result<Vec<Self>, WorkspaceToolConfigurationError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = grants.into_iter().count();
            return Err(WorkspaceToolConfigurationError::UnsupportedPlatform);
        }
        #[cfg(target_os = "linux")]
        {
            let roots = Arc::new(open_roots(grants)?);
            [
                WorkspaceOperation::List,
                WorkspaceOperation::Stat,
                WorkspaceOperation::Read,
                WorkspaceOperation::Search,
            ]
            .into_iter()
            .map(|operation| {
                Ok(Self {
                    operation,
                    descriptor: workspace_descriptor(operation)?,
                    roots: Arc::clone(&roots),
                    invocation_count: AtomicUsize::new(0),
                })
            })
            .collect()
        }
    }

    /// Number of invocations reaching this adapter in the current process.
    #[must_use]
    pub fn invocation_count(&self) -> usize {
        self.invocation_count.load(Ordering::SeqCst)
    }

    /// Logical workspace identities enforced by this adapter, never host paths.
    #[must_use]
    pub fn workspace_ids(&self) -> Vec<String> {
        #[cfg(target_os = "linux")]
        {
            self.roots.keys().cloned().collect()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Vec::new()
        }
    }
}

impl ReadOnlyTool for WorkspaceReadTool {
    fn descriptor(&self) -> ReadToolDescriptor {
        self.descriptor.clone()
    }

    fn validate_arguments(&self, arguments: &Value) -> Result<(), ReadToolError> {
        validate_operation_arguments(self.operation, arguments)
    }

    fn execute(
        &self,
        arguments: &Value,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ReadToolOutput, ReadToolError> {
        self.invocation_count.fetch_add(1, Ordering::SeqCst);
        self.validate_arguments(arguments)?;
        if cancellation.is_cancelled() {
            return Err(ReadToolError::Cancelled);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = arguments;
            Err(ReadToolError::Unavailable(
                "workspace path enforcement is unavailable".to_owned(),
            ))
        }
        #[cfg(target_os = "linux")]
        {
            let common = parse_common(arguments)?;
            let root = self
                .roots
                .get(common.workspace_id)
                .ok_or(ReadToolError::NotFound)?;
            let value = match self.operation {
                WorkspaceOperation::List => execute_list(root, common, arguments, cancellation)?,
                WorkspaceOperation::Stat => execute_stat(root, common)?,
                WorkspaceOperation::Read => execute_read(root, common, arguments, cancellation)?,
                WorkspaceOperation::Search => {
                    execute_search(root, common, arguments, cancellation)?
                }
            };
            let bytes = serde_json::to_vec(&value).map_err(|_| {
                ReadToolError::Unavailable("workspace output encoding failed".to_owned())
            })?;
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
                source_locator: workspace_locator(common.workspace_id, common.path),
            })
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ListArguments {
    workspace_id: String,
    #[serde(default)]
    path: String,
    #[serde(default = "default_list_entries")]
    maximum_entries: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatArguments {
    workspace_id: String,
    path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadArguments {
    workspace_id: String,
    path: String,
    #[serde(default)]
    offset_bytes: u64,
    #[serde(default = "default_read_bytes")]
    maximum_bytes: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SearchArguments {
    workspace_id: String,
    query: String,
    #[serde(default)]
    path: String,
    #[serde(default = "default_search_results")]
    maximum_results: usize,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct CommonArguments<'a> {
    workspace_id: &'a str,
    path: &'a str,
}

fn default_list_entries() -> usize {
    DEFAULT_LIST_ENTRIES
}

fn default_read_bytes() -> usize {
    DEFAULT_READ_BYTES
}

fn default_search_results() -> usize {
    DEFAULT_SEARCH_RESULTS
}

fn validate_operation_arguments(
    operation: WorkspaceOperation,
    arguments: &Value,
) -> Result<(), ReadToolError> {
    match operation {
        WorkspaceOperation::List => {
            let parsed: ListArguments = parse_arguments(arguments)?;
            validate_workspace_id(&parsed.workspace_id)?;
            validate_logical_path(&parsed.path, true)?;
            if !(1..=MAXIMUM_LIST_ENTRIES).contains(&parsed.maximum_entries) {
                return invalid_arguments("maximumEntries is outside its bound");
            }
        }
        WorkspaceOperation::Stat => {
            let parsed: StatArguments = parse_arguments(arguments)?;
            validate_workspace_id(&parsed.workspace_id)?;
            validate_logical_path(&parsed.path, false)?;
        }
        WorkspaceOperation::Read => {
            let parsed: ReadArguments = parse_arguments(arguments)?;
            validate_workspace_id(&parsed.workspace_id)?;
            validate_logical_path(&parsed.path, false)?;
            if !(1..=MAXIMUM_READ_BYTES).contains(&parsed.maximum_bytes) {
                return invalid_arguments("maximumBytes is outside its bound");
            }
        }
        WorkspaceOperation::Search => {
            let parsed: SearchArguments = parse_arguments(arguments)?;
            validate_workspace_id(&parsed.workspace_id)?;
            validate_logical_path(&parsed.path, true)?;
            if parsed.query.is_empty()
                || parsed.query.len() > 256
                || parsed.query.chars().any(char::is_control)
                || !(1..=MAXIMUM_SEARCH_RESULTS).contains(&parsed.maximum_results)
            {
                return invalid_arguments("query or maximumResults is invalid");
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_workspace_tool_arguments(
    tool_id: &str,
    arguments: &Value,
) -> Result<String, ReadToolError> {
    let operation = WorkspaceOperation::from_tool_id(tool_id)
        .ok_or_else(|| ReadToolError::InvalidArguments("unknown workspace tool".to_owned()))?;
    validate_operation_arguments(operation, arguments)?;
    let object = arguments
        .as_object()
        .ok_or_else(|| ReadToolError::InvalidArguments("expected object".to_owned()))?;
    let workspace_id = object
        .get("workspaceId")
        .and_then(Value::as_str)
        .ok_or_else(|| ReadToolError::InvalidArguments("workspaceId is absent".to_owned()))?;
    let path = object.get("path").and_then(Value::as_str).unwrap_or("");
    Ok(workspace_locator(workspace_id, path))
}

fn parse_arguments<T: for<'de> Deserialize<'de>>(arguments: &Value) -> Result<T, ReadToolError> {
    serde_json::from_value(arguments.clone())
        .map_err(|_| ReadToolError::InvalidArguments("arguments do not match schema".to_owned()))
}

fn validate_workspace_id(value: &str) -> Result<(), ReadToolError> {
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('.')
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b'-'))
    {
        return invalid_arguments("workspaceId is invalid");
    }
    Ok(())
}

fn validate_logical_path(value: &str, allow_empty: bool) -> Result<(), ReadToolError> {
    if (!allow_empty && value.is_empty())
        || value.len() > MAXIMUM_LOGICAL_PATH_BYTES
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || Path::new(value).is_absolute()
        || Path::new(value)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return invalid_arguments("path must be a normalized relative workspace path");
    }
    Ok(())
}

fn invalid_arguments<T>(message: &str) -> Result<T, ReadToolError> {
    Err(ReadToolError::InvalidArguments(message.to_owned()))
}

#[cfg(target_os = "linux")]
fn open_roots(
    grants: impl IntoIterator<Item = WorkspaceGrant>,
) -> Result<BTreeMap<String, WorkspaceRoot>, WorkspaceToolConfigurationError> {
    let grants = grants.into_iter().collect::<Vec<_>>();
    if grants.is_empty() || grants.len() > MAXIMUM_WORKSPACES {
        return Err(WorkspaceToolConfigurationError::Invalid);
    }
    let mut roots = BTreeMap::new();
    for grant in grants {
        validate_workspace_id(&grant.workspace_id)
            .map_err(|_| WorkspaceToolConfigurationError::Invalid)?;
        if !grant.root.is_absolute()
            || grant.root.to_str().is_none_or(|value| value.len() > 4_096)
            || std::fs::symlink_metadata(&grant.root)
                .map_err(|_| WorkspaceToolConfigurationError::Unavailable)?
                .file_type()
                .is_symlink()
            || std::fs::canonicalize(&grant.root)
                .map_err(|_| WorkspaceToolConfigurationError::Unavailable)?
                != grant.root
        {
            return Err(WorkspaceToolConfigurationError::Unavailable);
        }
        let directory = open(
            &grant.root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(std::fs::File::from)
        .map_err(|_| WorkspaceToolConfigurationError::Unavailable)?;
        openat2(
            &directory,
            ".",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            resolve_flags(),
        )
        .map_err(|_| WorkspaceToolConfigurationError::Unavailable)?;
        if roots
            .insert(grant.workspace_id, WorkspaceRoot { directory })
            .is_some()
        {
            return Err(WorkspaceToolConfigurationError::Invalid);
        }
    }
    Ok(roots)
}

#[cfg(target_os = "linux")]
const fn resolve_flags() -> ResolveFlags {
    ResolveFlags::BENEATH
        .union(ResolveFlags::NO_SYMLINKS)
        .union(ResolveFlags::NO_MAGICLINKS)
        .union(ResolveFlags::NO_XDEV)
}

#[cfg(target_os = "linux")]
fn parse_common(arguments: &Value) -> Result<CommonArguments<'_>, ReadToolError> {
    let object = arguments
        .as_object()
        .ok_or_else(|| ReadToolError::InvalidArguments("expected object".to_owned()))?;
    Ok(CommonArguments {
        workspace_id: object
            .get("workspaceId")
            .and_then(Value::as_str)
            .ok_or_else(|| ReadToolError::InvalidArguments("workspaceId is absent".to_owned()))?,
        path: object.get("path").and_then(Value::as_str).unwrap_or(""),
    })
}

#[cfg(target_os = "linux")]
fn open_workspace_path(
    root: &WorkspaceRoot,
    path: &str,
    flags: OFlags,
) -> Result<rustix::fd::OwnedFd, ReadToolError> {
    openat2(
        &root.directory,
        if path.is_empty() { "." } else { path },
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        resolve_flags(),
    )
    .map_err(map_open_error)
}

#[cfg(target_os = "linux")]
fn map_open_error(error: rustix::io::Errno) -> ReadToolError {
    if error == rustix::io::Errno::NOENT || error == rustix::io::Errno::NOTDIR {
        ReadToolError::NotFound
    } else if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::XDEV {
        ReadToolError::InvalidArguments("path crossed the workspace boundary".to_owned())
    } else {
        ReadToolError::Unavailable("workspace path could not be opened safely".to_owned())
    }
}

#[cfg(target_os = "linux")]
fn execute_list(
    root: &WorkspaceRoot,
    common: CommonArguments<'_>,
    arguments: &Value,
    cancellation: &dyn CancellationProbe,
) -> Result<Value, ReadToolError> {
    let parsed: ListArguments = parse_arguments(arguments)?;
    let fd = open_workspace_path(root, common.path, OFlags::RDONLY | OFlags::DIRECTORY)?;
    let mut entries = Vec::new();
    let mut scanned_entries = 0_usize;
    let mut omitted_non_utf8 = 0_u64;
    let mut truncated = false;
    for entry in Dir::new(fd).map_err(|_| {
        ReadToolError::Unavailable("workspace directory could not be read".to_owned())
    })? {
        if cancellation.is_cancelled() {
            return Err(ReadToolError::Cancelled);
        }
        let entry = entry.map_err(|_| {
            ReadToolError::Unavailable("workspace directory entry failed".to_owned())
        })?;
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        if scanned_entries >= MAXIMUM_LIST_SCANNED_ENTRIES {
            truncated = true;
            break;
        }
        scanned_entries = scanned_entries.saturating_add(1);
        let Ok(name) = std::str::from_utf8(bytes) else {
            omitted_non_utf8 = omitted_non_utf8.saturating_add(1);
            continue;
        };
        if entries.len() >= parsed.maximum_entries {
            truncated = true;
            break;
        }
        entries.push(json!({
            "name": name,
            "type": file_type_name(entry.file_type()),
        }));
    }
    entries.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    Ok(json!({
        "workspaceId": common.workspace_id,
        "path": common.path,
        "sourceLocator": workspace_locator(common.workspace_id, common.path),
        "entries": entries,
        "truncated": truncated,
        "scannedEntries": scanned_entries,
        "omittedNonUtf8": omitted_non_utf8,
    }))
}

#[cfg(target_os = "linux")]
fn execute_stat(root: &WorkspaceRoot, common: CommonArguments<'_>) -> Result<Value, ReadToolError> {
    let fd = open_workspace_path(root, common.path, OFlags::PATH)?;
    let stat = fstat(&fd).map_err(|_| {
        ReadToolError::Unavailable("workspace metadata could not be read".to_owned())
    })?;
    Ok(json!({
        "workspaceId": common.workspace_id,
        "path": common.path,
        "sourceLocator": workspace_locator(common.workspace_id, common.path),
        "type": file_type_name(FileType::from_raw_mode(stat.st_mode)),
        "sizeBytes": stat.st_size,
        "readOnly": true,
    }))
}

#[cfg(target_os = "linux")]
fn execute_read(
    root: &WorkspaceRoot,
    common: CommonArguments<'_>,
    arguments: &Value,
    cancellation: &dyn CancellationProbe,
) -> Result<Value, ReadToolError> {
    let parsed: ReadArguments = parse_arguments(arguments)?;
    let fd = open_workspace_path(root, common.path, OFlags::RDONLY)?;
    let mut file = std::fs::File::from(fd);
    let metadata = file.metadata().map_err(|_| {
        ReadToolError::Unavailable("workspace file metadata is unavailable".to_owned())
    })?;
    if !metadata.is_file() {
        return invalid_arguments("workspace.read requires a regular file");
    }
    file.seek(SeekFrom::Start(parsed.offset_bytes))
        .map_err(|_| ReadToolError::Unavailable("workspace offset failed".to_owned()))?;
    let mut bytes = Vec::new();
    file.take(
        u64::try_from(parsed.maximum_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1),
    )
    .read_to_end(&mut bytes)
    .map_err(|_| ReadToolError::Unavailable("workspace read failed".to_owned()))?;
    if cancellation.is_cancelled() {
        return Err(ReadToolError::Cancelled);
    }
    let truncated = bytes.len() > parsed.maximum_bytes;
    bytes.truncate(parsed.maximum_bytes);
    let content = std::str::from_utf8(&bytes).map_err(|_| {
        ReadToolError::InvalidArguments("workspace.read accepts UTF-8 text files only".to_owned())
    })?;
    Ok(json!({
        "workspaceId": common.workspace_id,
        "path": common.path,
        "sourceLocator": workspace_locator(common.workspace_id, common.path),
        "offsetBytes": parsed.offset_bytes,
        "returnedBytes": bytes.len(),
        "fileSizeBytes": metadata.len(),
        "truncated": truncated,
        "contentSha256": sha256_digest(&bytes),
        "content": content,
    }))
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines)]
fn execute_search(
    root: &WorkspaceRoot,
    common: CommonArguments<'_>,
    arguments: &Value,
    cancellation: &dyn CancellationProbe,
) -> Result<Value, ReadToolError> {
    let parsed: SearchArguments = parse_arguments(arguments)?;
    open_workspace_path(root, common.path, OFlags::RDONLY | OFlags::DIRECTORY)?;
    let mut pending = VecDeque::from([common.path.to_owned()]);
    let mut matches = Vec::new();
    let mut scanned_files = 0_usize;
    let mut scanned_directories = 0_usize;
    let mut scanned_entries = 0_usize;
    let mut scanned_bytes = 0_usize;
    let mut truncated = false;
    while let Some(directory) = pending.pop_front() {
        if cancellation.is_cancelled() {
            return Err(ReadToolError::Cancelled);
        }
        if scanned_directories >= MAXIMUM_SEARCH_DIRECTORIES {
            truncated = true;
            break;
        }
        scanned_directories = scanned_directories.saturating_add(1);
        let fd = open_workspace_path(root, &directory, OFlags::RDONLY | OFlags::DIRECTORY)?;
        let mut children = Vec::new();
        for entry in Dir::new(fd).map_err(|_| {
            ReadToolError::Unavailable("workspace search directory failed".to_owned())
        })? {
            let entry = entry.map_err(|_| {
                ReadToolError::Unavailable("workspace search entry failed".to_owned())
            })?;
            let bytes = entry.file_name().to_bytes();
            if matches!(bytes, b"." | b"..") {
                continue;
            }
            if cancellation.is_cancelled() {
                return Err(ReadToolError::Cancelled);
            }
            if scanned_entries >= MAXIMUM_SEARCH_ENTRIES {
                truncated = true;
                break;
            }
            scanned_entries = scanned_entries.saturating_add(1);
            if let Ok(name) = std::str::from_utf8(bytes) {
                children.push((name.to_owned(), entry.file_type()));
            }
        }
        if truncated {
            break;
        }
        children.sort_by(|left, right| left.0.cmp(&right.0));
        for (name, file_type) in children {
            let child = if directory.is_empty() {
                name
            } else {
                format!("{directory}/{name}")
            };
            if file_type.is_dir() {
                pending.push_back(child);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            if scanned_files >= MAXIMUM_SEARCH_FILES || scanned_bytes >= MAXIMUM_SEARCH_BYTES {
                truncated = true;
                break;
            }
            scanned_files += 1;
            let fd = open_workspace_path(root, &child, OFlags::RDONLY)?;
            let mut file = std::fs::File::from(fd);
            let file_size = file
                .metadata()
                .map_err(|_| {
                    ReadToolError::Unavailable("workspace search file metadata failed".to_owned())
                })?
                .len();
            let maximum_bytes =
                MAXIMUM_SEARCH_FILE_BYTES.min(MAXIMUM_SEARCH_BYTES.saturating_sub(scanned_bytes));
            let mut bytes = Vec::new();
            file.by_ref()
                .take(u64::try_from(maximum_bytes).unwrap_or(u64::MAX))
                .read_to_end(&mut bytes)
                .map_err(|_| {
                    ReadToolError::Unavailable("workspace search read failed".to_owned())
                })?;
            scanned_bytes = scanned_bytes.saturating_add(bytes.len());
            if file_size > u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
                truncated = true;
            }
            let Ok(text) = std::str::from_utf8(&bytes) else {
                if truncated {
                    break;
                }
                continue;
            };
            for (line_index, line) in text.lines().enumerate() {
                if line.contains(&parsed.query) {
                    matches.push(json!({
                        "path": child.clone(),
                        "line": line_index.saturating_add(1),
                        "sourceLocator": format!(
                            "{}#L{}",
                            workspace_locator(common.workspace_id, &child),
                            line_index.saturating_add(1)
                        ),
                        "snippet": line.chars().take(512).collect::<String>(),
                    }));
                    if matches.len() >= parsed.maximum_results {
                        truncated = true;
                        break;
                    }
                }
            }
            if matches.len() >= parsed.maximum_results {
                break;
            }
        }
        if truncated {
            break;
        }
    }
    Ok(json!({
        "workspaceId": common.workspace_id,
        "path": common.path,
        "sourceLocator": workspace_locator(common.workspace_id, common.path),
        "query": parsed.query,
        "matches": matches,
        "scannedDirectories": scanned_directories,
        "scannedEntries": scanned_entries,
        "scannedFiles": scanned_files,
        "scannedBytes": scanned_bytes,
        "truncated": truncated,
    }))
}

#[cfg(target_os = "linux")]
fn file_type_name(file_type: FileType) -> &'static str {
    if file_type.is_file() {
        "file"
    } else if file_type.is_dir() {
        "directory"
    } else if file_type.is_symlink() {
        "symlink"
    } else {
        "other"
    }
}

fn workspace_locator(workspace_id: &str, path: &str) -> String {
    if path.is_empty() {
        format!("workspace://{workspace_id}/")
    } else {
        format!("workspace://{workspace_id}/{path}")
    }
}

fn workspace_descriptor(
    operation: WorkspaceOperation,
) -> Result<ReadToolDescriptor, WorkspaceToolConfigurationError> {
    let input_schema = match operation {
        WorkspaceOperation::List => json!({
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string", "minLength": 1, "maxLength": 128},
                "path": {"type": "string", "maxLength": MAXIMUM_LOGICAL_PATH_BYTES},
                "maximumEntries": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_LIST_ENTRIES}
            },
            "required": ["workspaceId"],
            "additionalProperties": false
        }),
        WorkspaceOperation::Stat => json!({
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string", "minLength": 1, "maxLength": 128},
                "path": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_LOGICAL_PATH_BYTES}
            },
            "required": ["workspaceId", "path"],
            "additionalProperties": false
        }),
        WorkspaceOperation::Read => json!({
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string", "minLength": 1, "maxLength": 128},
                "path": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_LOGICAL_PATH_BYTES},
                "offsetBytes": {"type": "integer", "minimum": 0},
                "maximumBytes": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_READ_BYTES}
            },
            "required": ["workspaceId", "path"],
            "additionalProperties": false
        }),
        WorkspaceOperation::Search => json!({
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string", "minLength": 1, "maxLength": 128},
                "query": {"type": "string", "minLength": 1, "maxLength": 256},
                "path": {"type": "string", "maxLength": MAXIMUM_LOGICAL_PATH_BYTES},
                "maximumResults": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_SEARCH_RESULTS}
            },
            "required": ["workspaceId", "query"],
            "additionalProperties": false
        }),
    };
    let output_schema = json!({"type": "object"});
    let mut descriptor = ReadToolDescriptor {
        tool_id: operation.tool_id().to_owned(),
        version: "1".to_owned(),
        schema_digest: sha256_digest(input_schema.to_string().as_bytes()),
        input_schema,
        output_schema,
        descriptor_digest: String::new(),
        effect_class: "read_only".to_owned(),
        risk_class: "low".to_owned(),
        required_capability: "workspace:read".to_owned(),
        timeout: Duration::from_secs(10),
        maximum_output_bytes: MAXIMUM_TOOL_OUTPUT_BYTES,
        conflict_key_template: format!("{}:{{workspaceId}}:{{path}}", operation.tool_id()),
        recovery: "retry".to_owned(),
    };
    descriptor.descriptor_digest = descriptor
        .computed_descriptor_digest()
        .map_err(|_| WorkspaceToolConfigurationError::InvalidDescriptor)?;
    descriptor
        .validate_evidence()
        .map_err(|_| WorkspaceToolConfigurationError::InvalidDescriptor)?;
    Ok(descriptor)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{WorkspaceGrant, WorkspaceReadTool};
    use mealy_application::{CancellationProbe, ReadOnlyTool, ReadToolError};
    use serde_json::json;
    use std::{fs, os::unix::fs::symlink};

    struct NeverCancelled;

    impl CancellationProbe for NeverCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    fn tools(root: &std::path::Path) -> Vec<WorkspaceReadTool> {
        WorkspaceReadTool::suite([WorkspaceGrant {
            workspace_id: "project".to_owned(),
            root: root.to_path_buf(),
        }])
        .expect("workspace tools")
    }

    #[test]
    fn list_stat_read_and_search_are_bounded_and_logical() {
        let root = tempfile::tempdir().expect("workspace");
        fs::create_dir(root.path().join("src")).expect("source directory");
        fs::write(
            root.path().join("src/main.rs"),
            "fn main() { /* needle */ }\n",
        )
        .expect("source file");
        let tools = tools(root.path());
        let list = tools
            .iter()
            .find(|tool| tool.descriptor().tool_id == "workspace.list")
            .expect("list tool")
            .execute(
                &json!({"workspaceId": "project", "path": "src"}),
                &NeverCancelled,
            )
            .expect("list");
        assert_eq!(list.source_locator, "workspace://project/src");
        assert!(
            String::from_utf8(list.bytes)
                .expect("JSON")
                .contains("main.rs")
        );

        let read = tools
            .iter()
            .find(|tool| tool.descriptor().tool_id == "workspace.read")
            .expect("read tool")
            .execute(
                &json!({"workspaceId": "project", "path": "src/main.rs"}),
                &NeverCancelled,
            )
            .expect("read");
        assert!(
            serde_json::from_slice::<serde_json::Value>(&read.bytes).expect("JSON")["content"]
                .as_str()
                .is_some_and(|content| content.contains("needle"))
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&read.bytes).expect("JSON")["sourceLocator"],
            "workspace://project/src/main.rs"
        );

        let search = tools
            .iter()
            .find(|tool| tool.descriptor().tool_id == "workspace.search")
            .expect("search tool")
            .execute(
                &json!({"workspaceId": "project", "query": "needle"}),
                &NeverCancelled,
            )
            .expect("search");
        assert!(
            serde_json::from_slice::<serde_json::Value>(&search.bytes).expect("JSON")["matches"][0]
                ["sourceLocator"]
                .as_str()
                .is_some_and(|locator| locator == "workspace://project/src/main.rs#L1")
        );
    }

    #[test]
    fn traversal_and_symlink_escape_fail_closed() {
        let root = tempfile::tempdir().expect("workspace");
        let outside = tempfile::tempdir().expect("outside");
        fs::write(outside.path().join("secret.txt"), "secret").expect("outside secret");
        symlink(outside.path(), root.path().join("escape")).expect("symlink");
        let tools = tools(root.path());
        let read = tools
            .iter()
            .find(|tool| tool.descriptor().tool_id == "workspace.read")
            .expect("read tool");
        assert!(matches!(
            read.execute(
                &json!({"workspaceId": "project", "path": "../secret.txt"}),
                &NeverCancelled,
            ),
            Err(ReadToolError::InvalidArguments(_))
        ));
        assert!(matches!(
            read.execute(
                &json!({"workspaceId": "project", "path": "escape/secret.txt"}),
                &NeverCancelled,
            ),
            Err(ReadToolError::InvalidArguments(_))
        ));
    }
}
