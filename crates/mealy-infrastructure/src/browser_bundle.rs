use mealy_application::{
    BROWSER_MAXIMUM_BUNDLE_BYTES, BROWSER_MAXIMUM_BUNDLE_FILE_BYTES, BROWSER_MAXIMUM_BUNDLE_FILES,
    is_sha256_digest, sha256_digest,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeSet, VecDeque},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

const BROWSER_EXECUTABLE_RELATIVE_PATH: &str = "chrome-headless-shell";
const HASH_BUFFER_BYTES: usize = 64 * 1024;

/// One exact regular file in a reviewed Chrome Headless Shell bundle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserBundleEntry {
    relative_path: String,
    size_bytes: u64,
    sha256_digest: String,
    executable: bool,
}

impl BrowserBundleEntry {
    /// Slash-separated path relative to the bundle root.
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// Exact byte count.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Exact lowercase SHA-256 digest.
    #[must_use]
    pub fn sha256_digest(&self) -> &str {
        &self.sha256_digest
    }

    /// Whether owner execute bits are required on the installed copy.
    #[must_use]
    pub const fn executable(&self) -> bool {
        self.executable
    }
}

/// Complete canonical no-symlink Chrome Headless Shell bundle evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserBundleInspection {
    root: PathBuf,
    bundle_digest: String,
    executable_digest: String,
    total_bytes: u64,
    entries: Vec<BrowserBundleEntry>,
}

impl BrowserBundleInspection {
    /// Exact canonical inspected source root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Digest over the complete canonical ordered inventory.
    #[must_use]
    pub fn bundle_digest(&self) -> &str {
        &self.bundle_digest
    }

    /// Digest of `chrome-headless-shell` itself.
    #[must_use]
    pub fn executable_digest(&self) -> &str {
        &self.executable_digest
    }

    /// Aggregate regular-file bytes.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Complete entries in canonical relative-path order.
    #[must_use]
    pub fn entries(&self) -> &[BrowserBundleEntry] {
        &self.entries
    }
}

/// Inspects a Chrome Headless Shell bundle without executing any bundle code.
///
/// # Errors
///
/// Returns [`BrowserBundleError`] for a redirected root, symlink/special file, unsafe inventory,
/// missing/invalid executable, size overflow, or expected-digest mismatch.
pub fn inspect_browser_bundle(
    root: &Path,
    expected_digest: Option<&str>,
) -> Result<BrowserBundleInspection, BrowserBundleError> {
    let root = exact_canonical_directory(root)?;
    if expected_digest.is_some_and(|digest| !is_sha256_digest(digest)) {
        return Err(BrowserBundleError::InvalidDigest);
    }
    let mut directories = VecDeque::from([root.clone()]);
    let mut entries = Vec::new();
    let mut seen_paths = BTreeSet::new();
    let mut total_bytes = 0_u64;
    while let Some(directory) = directories.pop_front() {
        let mut children = fs::read_dir(&directory)?.collect::<io::Result<Vec<_>>>()?;
        children.sort_by_key(fs::DirEntry::file_name);
        for child in children {
            let path = child.path();
            let metadata = fs::symlink_metadata(&path)?;
            let relative_path = canonical_relative_path(&root, &path)?;
            if metadata.file_type().is_symlink() {
                return Err(BrowserBundleError::UnsafeEntry(relative_path));
            }
            if metadata.is_dir() {
                directories.push_back(path);
                continue;
            }
            if !metadata.is_file()
                || metadata.len() == 0
                || metadata.len() > BROWSER_MAXIMUM_BUNDLE_FILE_BYTES
                || entries.len() >= BROWSER_MAXIMUM_BUNDLE_FILES
                || !seen_paths.insert(relative_path.clone())
            {
                return Err(BrowserBundleError::UnsafeEntry(relative_path));
            }
            total_bytes = total_bytes
                .checked_add(metadata.len())
                .ok_or(BrowserBundleError::TooLarge)?;
            if total_bytes > BROWSER_MAXIMUM_BUNDLE_BYTES {
                return Err(BrowserBundleError::TooLarge);
            }
            let (digest, observed_size) = hash_file(&path)?;
            if observed_size != metadata.len() {
                return Err(BrowserBundleError::ChangedDuringInspection);
            }
            #[cfg(unix)]
            let executable = metadata.permissions().mode() & 0o111 != 0;
            #[cfg(not(unix))]
            let executable = relative_path == BROWSER_EXECUTABLE_RELATIVE_PATH;
            entries.push(BrowserBundleEntry {
                relative_path,
                size_bytes: observed_size,
                sha256_digest: digest,
                executable,
            });
        }
    }
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    if entries.is_empty() {
        return Err(BrowserBundleError::InvalidExecutable);
    }
    let executable = entries
        .iter()
        .find(|entry| entry.relative_path == BROWSER_EXECUTABLE_RELATIVE_PATH)
        .filter(|entry| entry.executable)
        .ok_or(BrowserBundleError::InvalidExecutable)?;
    let mut header = [0_u8; 4];
    File::open(root.join(BROWSER_EXECUTABLE_RELATIVE_PATH))?.read_exact(&mut header)?;
    if header != *b"\x7fELF" {
        return Err(BrowserBundleError::InvalidExecutable);
    }
    let bundle_digest = sha256_digest(
        json!({
            "contractVersion": "mealy.browser-bundle.v1",
            "entries": entries,
        })
        .to_string()
        .as_bytes(),
    );
    if expected_digest.is_some_and(|expected| expected != bundle_digest) {
        return Err(BrowserBundleError::InvalidDigest);
    }
    Ok(BrowserBundleInspection {
        root,
        bundle_digest,
        executable_digest: executable.sha256_digest.clone(),
        total_bytes,
        entries,
    })
}

/// Publishes exact inspected bundle bytes to owner-private content-addressed storage.
///
/// Existing identical publication is accepted idempotently. A changed or redirected destination
/// fails without replacement.
///
/// # Errors
///
/// Returns [`BrowserBundleError`] for unsafe destination state, source drift, or copy failure.
pub fn publish_browser_bundle(
    inspection: &BrowserBundleInspection,
    browser_runtimes_root: &Path,
) -> Result<PathBuf, BrowserBundleError> {
    let root = create_exact_private_directory(browser_runtimes_root)?;
    let destination = root.join(inspection.bundle_digest());
    match fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(BrowserBundleError::UnsafeDestination);
        }
        Ok(_) => {
            inspect_browser_bundle(&destination, Some(inspection.bundle_digest()))?;
            return Ok(destination);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(BrowserBundleError::Io(error)),
    }
    let temporary = root.join(format!(
        ".{}.tmp-{}",
        inspection.bundle_digest(),
        std::process::id()
    ));
    if fs::symlink_metadata(&temporary).is_ok() {
        return Err(BrowserBundleError::UnsafeDestination);
    }
    create_exact_private_directory(&temporary)?;
    let result = (|| {
        for entry in inspection.entries() {
            let source = inspection.root().join(entry.relative_path());
            let destination_file = temporary.join(entry.relative_path());
            let parent = destination_file
                .parent()
                .ok_or(BrowserBundleError::UnsafeDestination)?;
            create_exact_private_directory(parent)?;
            copy_exact_file(&source, &destination_file, entry.executable())?;
            let (digest, size) = hash_file(&destination_file)?;
            if digest != entry.sha256_digest() || size != entry.size_bytes() {
                return Err(BrowserBundleError::ChangedDuringInspection);
            }
        }
        let reproduced = inspect_browser_bundle(&temporary, Some(inspection.bundle_digest()))?;
        if reproduced.entries != inspection.entries {
            return Err(BrowserBundleError::ChangedDuringInspection);
        }
        sync_directory_tree(&temporary)?;
        fs::rename(&temporary, &destination)?;
        File::open(&root)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result?;
    Ok(destination)
}

fn exact_canonical_directory(path: &Path) -> Result<PathBuf, BrowserBundleError> {
    if !path.is_absolute() {
        return Err(BrowserBundleError::UnsafeRoot);
    }
    let metadata = fs::symlink_metadata(path)?;
    let canonical = fs::canonicalize(path)?;
    if canonical != path || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BrowserBundleError::UnsafeRoot);
    }
    Ok(canonical)
}

fn create_exact_private_directory(path: &Path) -> Result<PathBuf, BrowserBundleError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(BrowserBundleError::UnsafeDestination);
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(path)?,
        Err(error) => return Err(BrowserBundleError::Io(error)),
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    let canonical = fs::canonicalize(path)?;
    if canonical != path {
        return Err(BrowserBundleError::UnsafeDestination);
    }
    Ok(canonical)
}

fn canonical_relative_path(root: &Path, path: &Path) -> Result<String, BrowserBundleError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| BrowserBundleError::UnsafeRoot)?;
    if relative.components().any(|component| {
        !matches!(component, Component::Normal(_))
            || component
                .as_os_str()
                .to_str()
                .is_none_or(|value| value.is_empty() || value.chars().any(char::is_control))
    }) {
        return Err(BrowserBundleError::UnsafeEntry(
            relative.display().to_string(),
        ));
    }
    relative
        .to_str()
        .map(|value| value.replace(std::path::MAIN_SEPARATOR, "/"))
        .ok_or_else(|| BrowserBundleError::UnsafeEntry(relative.display().to_string()))
}

fn hash_file(path: &Path) -> Result<(String, u64), BrowserBundleError> {
    use sha2::{Digest as _, Sha256};

    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        total = total
            .checked_add(u64::try_from(read).map_err(|_| BrowserBundleError::TooLarge)?)
            .ok_or(BrowserBundleError::TooLarge)?;
    }
    let bytes = digest.finalize();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok((encoded, total))
}

fn copy_exact_file(
    source: &Path,
    destination: &Path,
    executable: bool,
) -> Result<(), BrowserBundleError> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BrowserBundleError::UnsafeEntry(
            source.display().to_string(),
        ));
    }
    let mut input = File::open(source)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(if executable { 0o700 } else { 0o600 });
    let mut output = options.open(destination)?;
    io::copy(&mut input, &mut output)?;
    output.flush()?;
    output.sync_all()?;
    #[cfg(unix)]
    fs::set_permissions(
        destination,
        fs::Permissions::from_mode(if executable { 0o700 } else { 0o600 }),
    )?;
    Ok(())
}

fn sync_directory_tree(root: &Path) -> Result<(), BrowserBundleError> {
    let mut directories = Vec::from([root.to_owned()]);
    let mut index = 0;
    while index < directories.len() {
        for entry in fs::read_dir(&directories[index])? {
            let path = entry?.path();
            if fs::symlink_metadata(&path)?.is_dir() {
                directories.push(path);
            }
        }
        index += 1;
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}

/// Browser bundle inspection/publication failure.
#[derive(Debug, Error)]
pub enum BrowserBundleError {
    /// Bundle root is not an exact canonical real directory.
    #[error("browser bundle root is unsafe")]
    UnsafeRoot,
    /// Bundle contains a symlink, special, malformed, duplicate, or oversized entry.
    #[error("browser bundle entry is unsafe: {0}")]
    UnsafeEntry(String),
    /// Chrome Headless Shell executable is missing, non-ELF, or non-executable.
    #[error("browser bundle executable is invalid")]
    InvalidExecutable,
    /// Aggregate inventory exceeds its hard byte or item bound.
    #[error("browser bundle exceeds its hard bound")]
    TooLarge,
    /// Expected or computed content identity is malformed or differs.
    #[error("browser bundle digest is invalid or changed")]
    InvalidDigest,
    /// Source bytes changed during inspection or publication.
    #[error("browser bundle changed during inspection")]
    ChangedDuringInspection,
    /// Destination is redirected, occupied by a non-directory, or non-canonical.
    #[error("browser bundle destination is unsafe")]
    UnsafeDestination,
    /// Host filesystem operation failed.
    #[error("browser bundle I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::{inspect_browser_bundle, publish_browser_bundle};
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    #[test]
    fn bundle_inventory_is_complete_content_addressed_and_reproducible() {
        let source = tempfile::tempdir().expect("source");
        let executable = source.path().join("chrome-headless-shell");
        fs::write(&executable, b"\x7fELFbrowser-fixture").expect("executable");
        fs::create_dir(source.path().join("locales")).expect("locales");
        fs::write(source.path().join("locales/en-US.pak"), b"locale").expect("asset");
        #[cfg(unix)]
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("mode");
        let inspection = inspect_browser_bundle(source.path(), None).expect("inspect");
        assert_eq!(inspection.entries().len(), 2);
        let installed = tempfile::tempdir().expect("installed");
        let destination = publish_browser_bundle(&inspection, installed.path()).expect("publish");
        assert_eq!(
            inspect_browser_bundle(&destination, Some(inspection.bundle_digest()))
                .expect("reinspect")
                .entries(),
            inspection.entries()
        );
        assert_eq!(
            publish_browser_bundle(&inspection, installed.path()).expect("idempotent"),
            destination
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_or_changed_inventory_fails_closed() {
        let source = tempfile::tempdir().expect("source");
        let executable = source.path().join("chrome-headless-shell");
        fs::write(&executable, b"\x7fELFbrowser-fixture").expect("executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("mode");
        symlink(&executable, source.path().join("redirect")).expect("symlink");
        assert!(inspect_browser_bundle(source.path(), None).is_err());
        fs::remove_file(source.path().join("redirect")).expect("remove symlink");
        let inspected = inspect_browser_bundle(source.path(), None).expect("inspect");
        fs::write(&executable, b"\x7fELFchanged-fixture").expect("change");
        assert!(inspect_browser_bundle(source.path(), Some(inspected.bundle_digest())).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn redirected_or_noncanonical_bundle_root_fails_closed() {
        let parent = tempfile::tempdir().expect("parent");
        let source = parent.path().join("source");
        fs::create_dir(&source).expect("source directory");
        let executable = source.join("chrome-headless-shell");
        fs::write(&executable, b"\x7fELFbrowser-fixture").expect("executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("mode");
        let redirected = parent.path().join("redirected");
        symlink(&source, &redirected).expect("root symlink");
        assert!(inspect_browser_bundle(&redirected, None).is_err());
        assert!(inspect_browser_bundle(&source.join("..").join("source"), None).is_err());
    }
}
