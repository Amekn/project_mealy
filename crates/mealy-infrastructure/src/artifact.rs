use mealy_application::{
    ArtifactBlobStore, ArtifactBlobStoreError, CommittedArtifactBlob, SHA256_ALGORITHM,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const IO_BUFFER_BYTES: usize = 16 * 1024;
const TEMP_FILE_ATTEMPTS: u8 = 16;
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Private filesystem-backed content-addressed artifact blob store.
///
/// Content is hashed while it is streamed to a private temporary file under the SHA-256
/// directory. A successful commit flushes and syncs that file before atomically renaming it to
/// its digest. Metadata and ownership links remain the responsibility of a separate database
/// transaction through application use cases.
#[derive(Debug)]
pub struct FileArtifactBlobStore {
    root: PathBuf,
    algorithm_root: PathBuf,
    maximum_blob_bytes: u64,
    commit_lock: Mutex<()>,
}

/// Aggregate private artifact-store usage for owner operational health.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactStorageUsage {
    /// Committed content-addressed blobs.
    pub blob_count: u64,
    /// Bytes occupied by committed blobs.
    pub total_bytes: u64,
    /// Incomplete temporary files awaiting age-based garbage collection.
    pub temporary_file_count: u64,
}

/// Physical erasure summary for aged files which have no canonical reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactGarbageCollectionReport {
    /// Unreferenced committed blobs removed.
    pub removed_blob_count: u64,
    /// Bytes removed from unreferenced committed blobs.
    pub removed_blob_bytes: u64,
    /// Incomplete temporary files removed.
    pub removed_temporary_file_count: u64,
    /// Young unreferenced or temporary files retained for a future pass.
    pub retained_young_file_count: u64,
    /// Canonically referenced blobs retained regardless of age.
    pub retained_referenced_blob_count: u64,
}

impl FileArtifactBlobStore {
    /// Opens or creates a private artifact root with a configured per-blob size limit.
    ///
    /// On Unix, the root and algorithm directory are restricted to mode `0700`; committed files
    /// are mode `0600`.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactBlobStoreError::Io`] when a directory cannot be created, validated, or
    /// restricted to private access.
    pub fn new(
        root: impl Into<PathBuf>,
        maximum_blob_bytes: u64,
    ) -> Result<Self, ArtifactBlobStoreError> {
        let root = root.into();
        create_private_directory(&root)?;
        let algorithm_root = root.join(SHA256_ALGORITHM);
        create_private_directory(&algorithm_root)?;

        Ok(Self {
            root,
            algorithm_root,
            maximum_blob_bytes,
            commit_lock: Mutex::new(()),
        })
    }

    /// Returns the configured artifact root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the maximum number of bytes accepted for one blob.
    #[must_use]
    pub const fn maximum_blob_bytes(&self) -> u64 {
        self.maximum_blob_bytes
    }

    /// Scans bounded file metadata for operational storage gauges without reading blob content.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactBlobStoreError`] for unsafe file types, malformed committed names, or I/O.
    pub fn storage_usage(&self) -> Result<ArtifactStorageUsage, ArtifactBlobStoreError> {
        let mut usage = ArtifactStorageUsage {
            blob_count: 0,
            total_bytes: 0,
            temporary_file_count: 0,
        };
        for entry in fs::read_dir(&self.algorithm_root)
            .map_err(|source| storage_io("scan artifact storage usage", source))?
        {
            let entry =
                entry.map_err(|source| storage_io("read artifact directory entry", source))?;
            let metadata = entry
                .metadata()
                .map_err(|source| storage_io("inspect artifact directory entry", source))?;
            if !metadata.is_file() {
                return Err(storage_io(
                    "inspect artifact storage usage",
                    io::Error::other("artifact directory contains a non-regular entry"),
                ));
            }
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                storage_io(
                    "inspect artifact storage usage",
                    io::Error::other("artifact filename is not UTF-8"),
                )
            })?;
            if name.starts_with(".tmp-") {
                usage.temporary_file_count =
                    usage.temporary_file_count.checked_add(1).ok_or_else(|| {
                        storage_io(
                            "count temporary artifacts",
                            io::Error::other("counter overflow"),
                        )
                    })?;
                continue;
            }
            if name.len() != 64
                || name
                    .bytes()
                    .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
            {
                return Err(storage_io(
                    "inspect artifact storage usage",
                    io::Error::other("artifact filename is not a canonical SHA-256 digest"),
                ));
            }
            usage.blob_count = usage.blob_count.checked_add(1).ok_or_else(|| {
                storage_io("count artifact blobs", io::Error::other("counter overflow"))
            })?;
            usage.total_bytes = usage
                .total_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| {
                    storage_io(
                        "sum artifact bytes",
                        io::Error::other("byte counter overflow"),
                    )
                })?;
        }
        Ok(usage)
    }

    /// Physically erases only aged temporary files and aged blobs absent from canonical metadata.
    ///
    /// A caller obtains `referenced_digests` from the same locked canonical store used for the
    /// operation. Any referenced blob is retained regardless of age. Young orphan files remain
    /// available for crash reconciliation and a later collection pass.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactBlobStoreError`] for malformed digests, unsafe file types, invalid clock
    /// values, or filesystem failures. Collection stops at the first error.
    pub fn garbage_collect(
        &self,
        referenced_digests: &BTreeSet<String>,
        minimum_age: Duration,
        now: SystemTime,
    ) -> Result<ArtifactGarbageCollectionReport, ArtifactBlobStoreError> {
        if minimum_age.is_zero()
            || referenced_digests.iter().any(|digest| {
                digest.len() != 64
                    || digest
                        .bytes()
                        .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
            })
        {
            return Err(storage_io(
                "validate artifact garbage collection policy",
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "minimum age and referenced digests must be valid",
                ),
            ));
        }
        let mut report = ArtifactGarbageCollectionReport {
            removed_blob_count: 0,
            removed_blob_bytes: 0,
            removed_temporary_file_count: 0,
            retained_young_file_count: 0,
            retained_referenced_blob_count: 0,
        };
        let mut removed_any = false;
        for entry in fs::read_dir(&self.algorithm_root)
            .map_err(|source| storage_io("scan artifact garbage collection", source))?
        {
            let entry =
                entry.map_err(|source| storage_io("read artifact directory entry", source))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|source| storage_io("inspect artifact garbage candidate", source))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(storage_io(
                    "inspect artifact garbage candidate",
                    io::Error::other("artifact directory contains an unsafe file type"),
                ));
            }
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                storage_io(
                    "inspect artifact garbage candidate",
                    io::Error::other("artifact filename is not UTF-8"),
                )
            })?;
            let temporary = name.starts_with(".tmp-");
            if !temporary
                && (name.len() != 64
                    || name
                        .bytes()
                        .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte)))
            {
                return Err(storage_io(
                    "inspect artifact garbage candidate",
                    io::Error::other("artifact filename is not a canonical SHA-256 digest"),
                ));
            }
            if !temporary && referenced_digests.contains(name) {
                report.retained_referenced_blob_count = report
                    .retained_referenced_blob_count
                    .checked_add(1)
                    .ok_or_else(|| gc_overflow("count retained artifact blobs"))?;
                continue;
            }
            let modified = metadata
                .modified()
                .map_err(|source| storage_io("read artifact modification time", source))?;
            let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
            if age < minimum_age {
                report.retained_young_file_count = report
                    .retained_young_file_count
                    .checked_add(1)
                    .ok_or_else(|| gc_overflow("count retained young artifacts"))?;
                continue;
            }
            fs::remove_file(entry.path())
                .map_err(|source| storage_io("remove aged unreferenced artifact", source))?;
            removed_any = true;
            if temporary {
                report.removed_temporary_file_count = report
                    .removed_temporary_file_count
                    .checked_add(1)
                    .ok_or_else(|| gc_overflow("count removed temporary artifacts"))?;
            } else {
                report.removed_blob_count = report
                    .removed_blob_count
                    .checked_add(1)
                    .ok_or_else(|| gc_overflow("count removed artifact blobs"))?;
                report.removed_blob_bytes =
                    report
                        .removed_blob_bytes
                        .checked_add(metadata.len())
                        .ok_or_else(|| gc_overflow("sum removed artifact bytes"))?;
            }
        }
        if removed_any {
            sync_directory(&self.algorithm_root)?;
        }
        Ok(report)
    }

    fn create_temporary_file(&self) -> Result<(TemporaryFile, File), ArtifactBlobStoreError> {
        for _ in 0..TEMP_FILE_ATTEMPTS {
            let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = format!(".tmp-{}-{sequence}", std::process::id());
            let path = self.algorithm_root.join(name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);

            match options.open(&path) {
                Ok(file) => return Ok((TemporaryFile::new(path), file)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => return Err(storage_io("create a private temporary file", source)),
            }
        }

        Err(storage_io(
            "allocate a unique private temporary file",
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "temporary artifact name attempts exhausted",
            ),
        ))
    }

    fn target_path(&self, blob: &CommittedArtifactBlob) -> PathBuf {
        self.algorithm_root.join(&blob.digest)
    }

    fn verify_existing_target(
        &self,
        blob: &CommittedArtifactBlob,
    ) -> Result<bool, ArtifactBlobStoreError> {
        match fs::symlink_metadata(self.target_path(blob)) {
            Ok(_) => {
                self.read(blob)?;
                set_private_file_permissions(&self.target_path(blob))?;
                File::options()
                    .write(true)
                    .open(self.target_path(blob))
                    .and_then(|file| file.set_modified(SystemTime::now()))
                    .map_err(|source| {
                        storage_io("refresh a deduplicated artifact retention age", source)
                    })?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(storage_io("inspect an existing artifact blob", source)),
        }
    }
}

impl ArtifactBlobStore for FileArtifactBlobStore {
    fn commit_reader(
        &self,
        source: &mut dyn Read,
    ) -> Result<CommittedArtifactBlob, ArtifactBlobStoreError> {
        let (mut temporary, mut file) = self.create_temporary_file()?;
        let mut hasher = Sha256::new();
        let mut size_bytes = 0_u64;
        let mut buffer = [0_u8; IO_BUFFER_BYTES];

        loop {
            let capacity = next_read_capacity(self.maximum_blob_bytes, size_bytes, buffer.len());
            let read_bytes = source
                .read(&mut buffer[..capacity])
                .map_err(|source| storage_io("read artifact source content", source))?;
            if read_bytes == 0 {
                break;
            }

            let chunk_bytes = u64::try_from(read_bytes).map_err(|_| {
                size_limit_error(
                    self.maximum_blob_bytes,
                    self.maximum_blob_bytes.saturating_add(1),
                )
            })?;
            let observed_bytes = size_bytes
                .checked_add(chunk_bytes)
                .ok_or_else(|| size_limit_error(self.maximum_blob_bytes, u64::MAX))?;
            if observed_bytes > self.maximum_blob_bytes {
                return Err(size_limit_error(self.maximum_blob_bytes, observed_bytes));
            }

            hasher.update(&buffer[..read_bytes]);
            file.write_all(&buffer[..read_bytes])
                .map_err(|source| storage_io("write private artifact content", source))?;
            size_bytes = observed_bytes;
        }

        file.flush()
            .map_err(|source| storage_io("flush private artifact content", source))?;
        file.sync_all()
            .map_err(|source| storage_io("sync private artifact content", source))?;
        drop(file);

        let digest = lowercase_hex(&hasher.finalize());
        let blob = CommittedArtifactBlob::new_sha256(digest, size_bytes)?;
        let target = self.target_path(&blob);
        let commit_guard = self.commit_lock.lock().map_err(|_| {
            storage_io(
                "lock artifact publication",
                io::Error::other("artifact publication lock is poisoned"),
            )
        })?;

        if self.verify_existing_target(&blob)? {
            fs::remove_file(temporary.path())
                .map_err(|source| storage_io("remove a duplicate temporary artifact", source))?;
            temporary.disarm();
            drop(commit_guard);
            return Ok(blob);
        }

        fs::rename(temporary.path(), &target)
            .map_err(|source| storage_io("atomically publish an artifact blob", source))?;
        temporary.disarm();
        set_private_file_permissions(&target)?;
        sync_directory(&self.algorithm_root)?;
        drop(commit_guard);
        Ok(blob)
    }

    fn read(&self, blob: &CommittedArtifactBlob) -> Result<Vec<u8>, ArtifactBlobStoreError> {
        blob.validate()?;
        if blob.size_bytes > self.maximum_blob_bytes {
            return Err(size_limit_error(self.maximum_blob_bytes, blob.size_bytes));
        }

        let path = self.target_path(blob);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(not_found(blob));
            }
            Err(source) => return Err(storage_io("inspect an artifact blob", source)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(unsafe_file_type(blob));
        }

        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(not_found(blob));
            }
            Err(source) => return Err(storage_io("open an artifact blob", source)),
        };
        if !file
            .metadata()
            .map_err(|source| storage_io("inspect an open artifact blob", source))?
            .is_file()
        {
            return Err(unsafe_file_type(blob));
        }

        let mut content = Vec::new();
        let mut hasher = Sha256::new();
        let mut size_bytes = 0_u64;
        let mut buffer = [0_u8; IO_BUFFER_BYTES];
        loop {
            let capacity = next_read_capacity(self.maximum_blob_bytes, size_bytes, buffer.len());
            let read_bytes = file
                .read(&mut buffer[..capacity])
                .map_err(|source| storage_io("read an artifact blob", source))?;
            if read_bytes == 0 {
                break;
            }

            let chunk_bytes = u64::try_from(read_bytes).map_err(|_| {
                size_limit_error(
                    self.maximum_blob_bytes,
                    self.maximum_blob_bytes.saturating_add(1),
                )
            })?;
            let observed_bytes = size_bytes
                .checked_add(chunk_bytes)
                .ok_or_else(|| size_limit_error(self.maximum_blob_bytes, u64::MAX))?;
            if observed_bytes > self.maximum_blob_bytes {
                return Err(size_limit_error(self.maximum_blob_bytes, observed_bytes));
            }

            hasher.update(&buffer[..read_bytes]);
            content.extend_from_slice(&buffer[..read_bytes]);
            size_bytes = observed_bytes;
        }

        let actual_digest = lowercase_hex(&hasher.finalize());
        if actual_digest != blob.digest || size_bytes != blob.size_bytes {
            return Err(ArtifactBlobStoreError::IntegrityMismatch {
                expected_digest: blob.digest.clone(),
                actual_digest,
                expected_size_bytes: blob.size_bytes,
                actual_size_bytes: size_bytes,
            });
        }

        Ok(content)
    }
}

#[derive(Debug)]
struct TemporaryFile {
    path: PathBuf,
    armed: bool,
}

impl TemporaryFile {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn next_read_capacity(maximum_bytes: u64, current_bytes: u64, buffer_bytes: usize) -> usize {
    let remaining_plus_one = maximum_bytes
        .saturating_sub(current_bytes)
        .saturating_add(1);
    usize::try_from(remaining_plus_one)
        .unwrap_or(buffer_bytes)
        .min(buffer_bytes)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(LOWER_HEX[usize::from(byte >> 4)]),
                char::from(LOWER_HEX[usize::from(byte & 0x0f)]),
            ]
        })
        .collect()
}

fn size_limit_error(maximum_bytes: u64, observed_bytes: u64) -> ArtifactBlobStoreError {
    ArtifactBlobStoreError::SizeLimitExceeded {
        maximum_bytes,
        observed_bytes,
    }
}

fn not_found(blob: &CommittedArtifactBlob) -> ArtifactBlobStoreError {
    ArtifactBlobStoreError::NotFound {
        algorithm: blob.algorithm.clone(),
        digest: blob.digest.clone(),
    }
}

fn unsafe_file_type(blob: &CommittedArtifactBlob) -> ArtifactBlobStoreError {
    ArtifactBlobStoreError::UnsafeFileType {
        algorithm: blob.algorithm.clone(),
        digest: blob.digest.clone(),
    }
}

fn storage_io(operation: &'static str, source: io::Error) -> ArtifactBlobStoreError {
    ArtifactBlobStoreError::Io { operation, source }
}

fn gc_overflow(operation: &'static str) -> ArtifactBlobStoreError {
    storage_io(
        operation,
        io::Error::other("artifact garbage collection counter overflow"),
    )
}

fn create_private_directory(path: &Path) -> Result<(), ArtifactBlobStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(storage_io(
                "validate a private artifact directory",
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "artifact directory is not a real directory",
                ),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|source| storage_io("create a private artifact directory", source))?;
        }
        Err(source) => {
            return Err(storage_io("inspect a private artifact directory", source));
        }
    }

    let metadata = fs::symlink_metadata(path)
        .map_err(|source| storage_io("validate a private artifact directory", source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(storage_io(
            "validate a private artifact directory",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "artifact directory is not a real directory",
            ),
        ));
    }
    set_private_directory_permissions(path)
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), ArtifactBlobStoreError> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| storage_io("restrict an artifact directory", source))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), ArtifactBlobStoreError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), ArtifactBlobStoreError> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|source| storage_io("restrict an artifact blob", source))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), ArtifactBlobStoreError> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ArtifactBlobStoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| storage_io("sync the artifact directory", source))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), ArtifactBlobStoreError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::FileArtifactBlobStore;
    use mealy_application::{
        ArtifactBlobStore, ArtifactBlobStoreError, CommittedArtifactBlob, sha256_digest,
    };
    use std::{
        collections::BTreeSet,
        fs,
        io::{self, Read},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, SystemTime},
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn commit_is_content_addressed_private_deduplicated_and_verified() {
        let directory = TestDirectory::new();
        let store = FileArtifactBlobStore::new(directory.path(), 1024).expect("open store");
        let content = b"durable artifact";

        let first = store.commit(content).expect("commit artifact");
        let second = store.commit(content).expect("deduplicate artifact");

        assert_eq!(first, second);
        assert_eq!(first.algorithm, "sha256");
        assert_eq!(first.digest, sha256_digest(content));
        assert_eq!(first.size_bytes, 16);
        assert_eq!(first.relative_path, format!("sha256/{}", first.digest));
        assert_eq!(store.read(&first).expect("verified read"), content);

        let algorithm_root = directory.path().join("sha256");
        let entries = fs::read_dir(&algorithm_root)
            .expect("read algorithm directory")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect entries");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_name().to_string_lossy(), first.digest);

        #[cfg(unix)]
        {
            let root_mode = fs::metadata(directory.path())
                .expect("root metadata")
                .permissions()
                .mode()
                & 0o777;
            let algorithm_mode = fs::metadata(&algorithm_root)
                .expect("algorithm metadata")
                .permissions()
                .mode()
                & 0o777;
            let file_mode = entries[0]
                .metadata()
                .expect("artifact metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(root_mode, 0o700);
            assert_eq!(algorithm_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }
    }

    #[test]
    fn garbage_collection_never_removes_referenced_content_and_ages_orphans() {
        let directory = TestDirectory::new();
        let store = FileArtifactBlobStore::new(directory.path(), 1024).expect("open store");
        let referenced = store.commit(b"referenced").expect("referenced blob");
        let orphan = store.commit(b"orphan").expect("orphan blob");
        let report = store
            .garbage_collect(
                &BTreeSet::from([referenced.digest.clone()]),
                Duration::from_hours(1),
                SystemTime::now() + Duration::from_hours(2),
            )
            .expect("collect aged orphan");
        assert_eq!(report.removed_blob_count, 1);
        assert_eq!(report.removed_blob_bytes, orphan.size_bytes);
        assert_eq!(report.retained_referenced_blob_count, 1);
        assert_eq!(
            store.read(&referenced).expect("referenced content"),
            b"referenced"
        );
        assert!(matches!(
            store.read(&orphan),
            Err(ArtifactBlobStoreError::NotFound { .. })
        ));
    }

    #[test]
    fn oversized_and_failed_sources_leave_no_partial_files() {
        let directory = TestDirectory::new();
        let store = FileArtifactBlobStore::new(directory.path(), 3).expect("open store");

        assert!(matches!(
            store.commit(b"four"),
            Err(ArtifactBlobStoreError::SizeLimitExceeded {
                maximum_bytes: 3,
                ..
            })
        ));

        let mut broken = BrokenReader { first_read: true };
        assert!(matches!(
            store.commit_reader(&mut broken),
            Err(ArtifactBlobStoreError::Io { .. })
        ));

        assert_eq!(
            fs::read_dir(directory.path().join("sha256"))
                .expect("read algorithm directory")
                .count(),
            0
        );
    }

    #[test]
    fn read_detects_tampering_and_rejects_redirected_descriptors() {
        let directory = TestDirectory::new();
        let store = FileArtifactBlobStore::new(directory.path(), 1024).expect("open store");
        let blob = store.commit(b"original").expect("commit artifact");
        fs::write(directory.path().join(&blob.relative_path), b"tampered")
            .expect("tamper artifact");

        assert!(matches!(
            store.read(&blob),
            Err(ArtifactBlobStoreError::IntegrityMismatch { .. })
        ));

        let redirected = CommittedArtifactBlob {
            relative_path: "../outside".to_owned(),
            ..blob
        };
        assert!(matches!(
            store.read(&redirected),
            Err(ArtifactBlobStoreError::InvalidDescriptor { .. })
        ));
    }

    struct BrokenReader {
        first_read: bool,
    }

    impl Read for BrokenReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.first_read {
                self.first_read = false;
                buffer[0] = b'x';
                Ok(1)
            } else {
                Err(io::Error::other("injected source failure"))
            }
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "mealy-artifact-store-{}-{sequence}",
                std::process::id()
            )))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
