use mealy_application::WEBHOOK_SIGNING_SECRET_BYTES;
use mealy_domain::ChannelBindingId;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;

/// Owner-only filesystem broker for signed webhook channel keys.
pub struct FileChannelSecretStore {
    root: PathBuf,
}

impl FileChannelSecretStore {
    /// Creates or opens a private channel-secret directory.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelSecretStoreError`] when the directory cannot be created or hardened.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, ChannelSecretStoreError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(io_error)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
        }
        let metadata = fs::symlink_metadata(&root).map_err(io_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ChannelSecretStoreError::UnsafeStorage);
        }
        Ok(Self { root })
    }

    /// Commits a new exact 32-byte secret without replacing an existing different key.
    ///
    /// Repeating the same binding and key is idempotent, which permits safe command recovery.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelSecretStoreError`] for malformed keys, conflicts, unsafe files, or I/O.
    pub fn put(
        &self,
        binding_id: ChannelBindingId,
        secret: &[u8],
    ) -> Result<(), ChannelSecretStoreError> {
        if secret.len() != WEBHOOK_SIGNING_SECRET_BYTES {
            return Err(ChannelSecretStoreError::InvalidSecret);
        }
        let path = self.path(binding_id);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                let result = file
                    .write_all(secret)
                    .and_then(|()| file.flush())
                    .and_then(|()| file.sync_all());
                if let Err(error) = result {
                    let _ = fs::remove_file(&path);
                    return Err(io_error(error));
                }
                sync_directory(&self.root).map_err(io_error)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if self.read(binding_id)? == secret {
                    Ok(())
                } else {
                    Err(ChannelSecretStoreError::Conflict)
                }
            }
            Err(error) => Err(io_error(error)),
        }
    }

    /// Resolves one brokered key after validating type, permissions, and exact size.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelSecretStoreError`] when absent, unsafe, malformed, or unreadable.
    pub fn read(
        &self,
        binding_id: ChannelBindingId,
    ) -> Result<[u8; WEBHOOK_SIGNING_SECRET_BYTES], ChannelSecretStoreError> {
        let path = self.path(binding_id);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ChannelSecretStoreError::NotFound);
            }
            Err(error) => return Err(io_error(error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ChannelSecretStoreError::UnsafeStorage);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(ChannelSecretStoreError::UnsafeStorage);
            }
        }
        if metadata.len() != u64::try_from(WEBHOOK_SIGNING_SECRET_BYTES).unwrap_or(u64::MAX) {
            return Err(ChannelSecretStoreError::InvalidSecret);
        }
        let mut file = File::open(path).map_err(io_error)?;
        let mut secret = [0_u8; WEBHOOK_SIGNING_SECRET_BYTES];
        file.read_exact(&mut secret).map_err(io_error)?;
        let mut trailing = [0_u8; 1];
        if file.read(&mut trailing).map_err(io_error)? != 0 {
            return Err(ChannelSecretStoreError::InvalidSecret);
        }
        Ok(secret)
    }

    /// Permanently removes one brokered key; absence is idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelSecretStoreError`] for unsafe file types or I/O failure.
    pub fn remove(&self, binding_id: ChannelBindingId) -> Result<(), ChannelSecretStoreError> {
        let path = self.path(binding_id);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(io_error(error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ChannelSecretStoreError::UnsafeStorage);
        }
        fs::remove_file(path).map_err(io_error)?;
        sync_directory(&self.root).map_err(io_error)
    }

    fn path(&self, binding_id: ChannelBindingId) -> PathBuf {
        self.root.join(format!("{binding_id}.key"))
    }
}

/// Failure in owner-only channel credential storage.
#[derive(Debug, Error)]
pub enum ChannelSecretStoreError {
    /// Key is not exactly 32 bytes.
    #[error("channel signing secret is invalid")]
    InvalidSecret,
    /// Binding already has a different key.
    #[error("channel signing secret conflicts with existing broker state")]
    Conflict,
    /// Binding has no brokered key.
    #[error("channel signing secret was not found")]
    NotFound,
    /// Directory, symlink, type, or permissions fail closed.
    #[error("channel signing secret storage is unsafe")]
    UnsafeStorage,
    /// Filesystem operation failed.
    #[error("channel signing secret storage is unavailable")]
    Io {
        /// Underlying OS error retained for trusted diagnostics.
        #[source]
        source: std::io::Error,
    },
}

fn io_error(source: std::io::Error) -> ChannelSecretStoreError {
    ChannelSecretStoreError::Io { source }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ChannelSecretStoreError, FileChannelSecretStore};
    use mealy_domain::ChannelBindingId;
    use tempfile::TempDir;

    #[test]
    fn broker_is_exact_idempotent_conflict_safe_and_revocable() {
        let root = TempDir::new().expect("secret root");
        let store = FileChannelSecretStore::new(root.path().join("channels")).expect("broker");
        let binding = ChannelBindingId::new();
        let secret = [7_u8; 32];
        store.put(binding, &secret).expect("new secret");
        store.put(binding, &secret).expect("idempotent secret");
        assert_eq!(store.read(binding).expect("read secret"), secret);
        assert!(matches!(
            store.put(binding, &[8_u8; 32]),
            Err(ChannelSecretStoreError::Conflict)
        ));
        store.remove(binding).expect("remove secret");
        store.remove(binding).expect("idempotent removal");
        assert!(matches!(
            store.read(binding),
            Err(ChannelSecretStoreError::NotFound)
        ));
    }
}
