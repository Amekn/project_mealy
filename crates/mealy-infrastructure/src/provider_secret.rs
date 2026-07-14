use mealy_application::{MAXIMUM_PROVIDER_CREDENTIAL_BYTES, valid_provider_secret_id};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;
use zeroize::Zeroizing;

/// Owner-private filesystem broker for model-provider credentials.
pub struct FileProviderSecretStore {
    root: PathBuf,
}

impl FileProviderSecretStore {
    /// Creates or opens a hardened provider-secret directory.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderSecretStoreError`] when the directory cannot be created or is unsafe.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, ProviderSecretStoreError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(io_error)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
        }
        let metadata = fs::symlink_metadata(&root).map_err(io_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ProviderSecretStoreError::UnsafeStorage);
        }
        Ok(Self { root })
    }

    /// Commits a new credential without replacing different material under the same identity.
    ///
    /// Repeating the exact secret is idempotent. Rotation uses a new secret identity and an atomic
    /// configuration activation, avoiding a replace window on platforms without rename-overwrite.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderSecretStoreError`] for malformed identities/credentials, conflicts,
    /// unsafe files, or I/O failures.
    pub fn put(&self, secret_id: &str, secret: &str) -> Result<(), ProviderSecretStoreError> {
        validate_secret(secret_id, secret)?;
        let path = self.path(secret_id);
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
                    .write_all(secret.as_bytes())
                    .and_then(|()| file.flush())
                    .and_then(|()| file.sync_all());
                if let Err(error) = result {
                    let _ = fs::remove_file(&path);
                    return Err(io_error(error));
                }
                sync_directory(&self.root).map_err(io_error)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = self.read(secret_id)?;
                if existing.as_str() == secret {
                    Ok(())
                } else {
                    Err(ProviderSecretStoreError::Conflict)
                }
            }
            Err(error) => Err(io_error(error)),
        }
    }

    /// Resolves one credential after validating its file type, permissions, size, and text shape.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderSecretStoreError`] when absent, unsafe, malformed, or unreadable.
    pub fn read(&self, secret_id: &str) -> Result<Zeroizing<String>, ProviderSecretStoreError> {
        if !valid_provider_secret_id(secret_id) {
            return Err(ProviderSecretStoreError::InvalidSecretId);
        }
        let path = self.path(secret_id);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ProviderSecretStoreError::NotFound);
            }
            Err(error) => return Err(io_error(error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ProviderSecretStoreError::UnsafeStorage);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(ProviderSecretStoreError::UnsafeStorage);
            }
        }
        if metadata.len() == 0
            || metadata.len() > u64::try_from(MAXIMUM_PROVIDER_CREDENTIAL_BYTES).unwrap_or(u64::MAX)
        {
            return Err(ProviderSecretStoreError::InvalidSecret);
        }
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len()).map_err(|_| ProviderSecretStoreError::InvalidSecret)?,
        );
        File::open(path)
            .map_err(io_error)?
            .take(
                u64::try_from(MAXIMUM_PROVIDER_CREDENTIAL_BYTES)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            )
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        let secret = Zeroizing::new(
            String::from_utf8(bytes).map_err(|_| ProviderSecretStoreError::InvalidSecret)?,
        );
        validate_secret(secret_id, &secret)?;
        Ok(secret)
    }

    /// Permanently removes one brokered credential; absence is idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderSecretStoreError`] for invalid identities, unsafe files, or I/O failure.
    pub fn remove(&self, secret_id: &str) -> Result<(), ProviderSecretStoreError> {
        if !valid_provider_secret_id(secret_id) {
            return Err(ProviderSecretStoreError::InvalidSecretId);
        }
        let path = self.path(secret_id);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(io_error(error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ProviderSecretStoreError::UnsafeStorage);
        }
        fs::remove_file(path).map_err(io_error)?;
        sync_directory(&self.root).map_err(io_error)
    }

    fn path(&self, secret_id: &str) -> PathBuf {
        self.root.join(format!("{secret_id}.key"))
    }
}

/// Failure in owner-private provider credential storage.
#[derive(Debug, Error)]
pub enum ProviderSecretStoreError {
    /// Secret identity cannot be mapped to one portable broker entry.
    #[error("provider secret identity is invalid")]
    InvalidSecretId,
    /// Credential bytes are empty, oversized, non-UTF-8, or contain control characters.
    #[error("provider credential is invalid")]
    InvalidSecret,
    /// Identity already holds different credential material.
    #[error(
        "provider credential conflicts with existing broker state; rotate with a new secret identity"
    )]
    Conflict,
    /// Identity has no brokered credential.
    #[error("provider credential was not found")]
    NotFound,
    /// Directory, symlink, type, or permissions fail closed.
    #[error("provider credential storage is unsafe")]
    UnsafeStorage,
    /// Filesystem operation failed.
    #[error("provider credential storage is unavailable")]
    Io {
        /// Underlying OS error retained for trusted diagnostics.
        #[source]
        source: std::io::Error,
    },
}

fn validate_secret(secret_id: &str, secret: &str) -> Result<(), ProviderSecretStoreError> {
    if !valid_provider_secret_id(secret_id) {
        return Err(ProviderSecretStoreError::InvalidSecretId);
    }
    if secret.is_empty()
        || secret.len() > MAXIMUM_PROVIDER_CREDENTIAL_BYTES
        || secret.chars().any(char::is_control)
    {
        return Err(ProviderSecretStoreError::InvalidSecret);
    }
    Ok(())
}

fn io_error(source: std::io::Error) -> ProviderSecretStoreError {
    ProviderSecretStoreError::Io { source }
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
    use super::{FileProviderSecretStore, ProviderSecretStoreError};

    #[test]
    fn broker_is_private_exact_conflict_safe_and_revocable() {
        let root = tempfile::tempdir().expect("secret root");
        let store = FileProviderSecretStore::new(root.path().join("providers")).expect("broker");
        store
            .put("openai-primary", "unit-test-secret")
            .expect("new secret");
        store
            .put("openai-primary", "unit-test-secret")
            .expect("idempotent secret");
        assert_eq!(
            store.read("openai-primary").expect("read secret").as_str(),
            "unit-test-secret"
        );
        assert!(matches!(
            store.put("openai-primary", "different-secret"),
            Err(ProviderSecretStoreError::Conflict)
        ));
        assert!(matches!(
            store.put("../escape", "secret"),
            Err(ProviderSecretStoreError::InvalidSecretId)
        ));
        store.remove("openai-primary").expect("remove secret");
        store.remove("openai-primary").expect("idempotent removal");
        assert!(matches!(
            store.read("openai-primary"),
            Err(ProviderSecretStoreError::NotFound)
        ));
    }
}
