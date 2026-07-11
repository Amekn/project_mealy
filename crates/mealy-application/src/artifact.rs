use crate::{OwnershipContext, SHA256_ALGORITHM, is_sha256_digest};
use mealy_domain::{ArtifactId, TaskId};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};
use std::time::SystemTime;
use thiserror::Error;

/// A content-addressed blob that has been durably published by an artifact adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommittedArtifactBlob {
    /// Digest algorithm used by the content-addressed store.
    pub algorithm: String,
    /// Canonical lowercase hexadecimal digest of the plaintext logical content.
    pub digest: String,
    /// Verified content size in bytes.
    pub size_bytes: u64,
    /// Portable path relative to the configured artifact root.
    pub relative_path: String,
}

impl CommittedArtifactBlob {
    /// Builds and validates a descriptor for SHA-256-addressed content.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactBlobStoreError::InvalidDescriptor`] when `digest` is not canonical
    /// lowercase SHA-256 hexadecimal text.
    pub fn new_sha256(
        digest: impl Into<String>,
        size_bytes: u64,
    ) -> Result<Self, ArtifactBlobStoreError> {
        let digest = digest.into();
        if !is_sha256_digest(&digest) {
            return Err(ArtifactBlobStoreError::InvalidDescriptor {
                reason: "digest is not canonical lowercase SHA-256 hexadecimal text".to_owned(),
            });
        }

        Ok(Self {
            relative_path: format!("{SHA256_ALGORITHM}/{digest}"),
            algorithm: SHA256_ALGORITHM.to_owned(),
            digest,
            size_bytes,
        })
    }

    /// Validates the digest and relative-path invariants of a persisted descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactBlobStoreError::InvalidDescriptor`] when any invariant is violated.
    pub fn validate(&self) -> Result<(), ArtifactBlobStoreError> {
        if self.algorithm != SHA256_ALGORITHM {
            return Err(ArtifactBlobStoreError::InvalidDescriptor {
                reason: "unsupported artifact digest algorithm".to_owned(),
            });
        }
        if !is_sha256_digest(&self.digest) {
            return Err(ArtifactBlobStoreError::InvalidDescriptor {
                reason: "digest is not canonical lowercase SHA-256 hexadecimal text".to_owned(),
            });
        }
        if self.relative_path != format!("{SHA256_ALGORITHM}/{}", self.digest) {
            return Err(ArtifactBlobStoreError::InvalidDescriptor {
                reason: "relative path does not match the content address".to_owned(),
            });
        }
        Ok(())
    }
}

/// Owner-authorized artifact metadata safe to project without a filesystem storage path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactMetadata {
    /// Stable logical artifact identity.
    pub artifact_id: ArtifactId,
    /// Digest algorithm used by the immutable blob.
    pub algorithm: String,
    /// Canonical digest of the plaintext logical content.
    pub digest: String,
    /// Exact verified blob size.
    pub size_bytes: u64,
    /// Declared media type.
    pub media_type: String,
    /// Stable origin category.
    pub origin_kind: String,
    /// Origin identity within its category.
    pub origin_id: String,
    /// Stable producer category.
    pub producer_kind: String,
    /// Producer identity within its category.
    pub producer_id: String,
    /// Sensitivity classification.
    pub sensitivity: String,
    /// Retention-policy classification.
    pub retention_class: String,
    /// Exact bounded access-policy JSON committed with the artifact.
    pub access_policy_json: String,
    /// Digest of the exact access-policy JSON bytes.
    pub access_policy_digest: String,
    /// Time at which the logical artifact metadata was committed.
    pub created_at: SystemTime,
}

/// Owner-authorized content locator for a trusted storage backend.
///
/// This type deliberately does not implement serialization. Presentation adapters should expose
/// [`ArtifactMetadata`] and stream content through a trusted backend instead of returning the
/// blob's private relative path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactContentDescriptor {
    metadata: ArtifactMetadata,
    committed_blob: CommittedArtifactBlob,
}

impl ArtifactContentDescriptor {
    /// Joins public artifact metadata to its private committed blob descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactEvidenceStoreError::InvariantViolation`] when algorithm, digest, size,
    /// or the committed content-addressed path is inconsistent.
    pub fn new(
        metadata: ArtifactMetadata,
        committed_blob: CommittedArtifactBlob,
    ) -> Result<Self, ArtifactEvidenceStoreError> {
        committed_blob
            .validate()
            .map_err(|error| ArtifactEvidenceStoreError::InvariantViolation(error.to_string()))?;
        if metadata.algorithm != committed_blob.algorithm
            || metadata.digest != committed_blob.digest
            || metadata.size_bytes != committed_blob.size_bytes
        {
            return Err(ArtifactEvidenceStoreError::InvariantViolation(
                "artifact metadata does not match its committed blob".to_owned(),
            ));
        }
        Ok(Self {
            metadata,
            committed_blob,
        })
    }

    /// Returns the path-free artifact metadata projection.
    #[must_use]
    pub const fn metadata(&self) -> &ArtifactMetadata {
        &self.metadata
    }

    /// Returns the private blob descriptor for a trusted content backend.
    #[must_use]
    pub const fn committed_blob(&self) -> &CommittedArtifactBlob {
        &self.committed_blob
    }

    /// Separates the path-free metadata and trusted blob descriptor.
    #[must_use]
    pub fn into_parts(self) -> (ArtifactMetadata, CommittedArtifactBlob) {
        (self.metadata, self.committed_blob)
    }
}

/// Failure from an owner-authorized artifact evidence projection.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ArtifactEvidenceStoreError {
    /// Artifact does not exist or is deliberately hidden from the supplied owner and channel.
    #[error("artifact evidence was not found")]
    NotFound,
    /// Persistence could not complete the projection.
    #[error("artifact evidence store is unavailable: {0}")]
    Unavailable(String),
    /// Stored artifact metadata or its content descriptor violates an invariant.
    #[error("artifact evidence invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port for owner-authorized artifact metadata and trusted content lookup.
pub trait ArtifactEvidenceStore {
    /// Returns path-free artifact metadata for an authenticated owner and channel binding.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactEvidenceStoreError`] when evidence is absent, unauthorized, unavailable,
    /// or inconsistent.
    fn artifact_metadata(
        &self,
        ownership: OwnershipContext,
        artifact_id: ArtifactId,
    ) -> Result<ArtifactMetadata, ArtifactEvidenceStoreError>;

    /// Returns an authorized private blob descriptor for a trusted content backend.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactEvidenceStoreError`] when evidence is absent, unauthorized, unavailable,
    /// or inconsistent.
    fn artifact_content_descriptor(
        &self,
        ownership: OwnershipContext,
        artifact_id: ArtifactId,
    ) -> Result<ArtifactContentDescriptor, ArtifactEvidenceStoreError>;

    /// Returns all artifact descriptors linked to one authorized task in stable creation order.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactEvidenceStoreError`] when the task is absent, unauthorized, unavailable,
    /// or any linked artifact evidence is inconsistent.
    fn task_artifact_content_descriptors(
        &self,
        ownership: OwnershipContext,
        task_id: TaskId,
    ) -> Result<Vec<ArtifactContentDescriptor>, ArtifactEvidenceStoreError>;
}

/// Classified failure from a content-addressed artifact blob adapter.
#[derive(Debug, Error)]
pub enum ArtifactBlobStoreError {
    /// A source or persisted blob exceeded the adapter's configured safety limit.
    #[error(
        "artifact blob exceeded the {maximum_bytes}-byte limit after observing {observed_bytes} bytes"
    )]
    SizeLimitExceeded {
        /// Configured maximum blob size.
        maximum_bytes: u64,
        /// Bytes observed before the operation stopped.
        observed_bytes: u64,
    },
    /// A caller supplied a malformed or non-canonical committed descriptor.
    #[error("invalid committed artifact blob descriptor: {reason}")]
    InvalidDescriptor {
        /// Safe validation detail.
        reason: String,
    },
    /// No committed blob exists for the requested content address.
    #[error("artifact blob not found: {algorithm}:{digest}")]
    NotFound {
        /// Requested digest algorithm.
        algorithm: String,
        /// Requested canonical digest.
        digest: String,
    },
    /// Stored content no longer matches its committed descriptor.
    #[error("artifact blob failed integrity verification for sha256:{expected_digest}")]
    IntegrityMismatch {
        /// Digest from the committed descriptor.
        expected_digest: String,
        /// Digest computed from bytes read from storage.
        actual_digest: String,
        /// Size from the committed descriptor.
        expected_size_bytes: u64,
        /// Size computed while reading storage.
        actual_size_bytes: u64,
    },
    /// A committed path resolved to something other than a regular file.
    #[error("artifact blob is not a regular file: {algorithm}:{digest}")]
    UnsafeFileType {
        /// Requested digest algorithm.
        algorithm: String,
        /// Requested canonical digest.
        digest: String,
    },
    /// The storage backend failed while performing an operation.
    #[error("artifact blob storage operation failed while attempting to {operation}")]
    Io {
        /// Stable operation description without a private filesystem path.
        operation: &'static str,
        /// Adapter-specific I/O cause.
        #[source]
        source: std::io::Error,
    },
}

/// Port for durable immutable content-addressed blob storage.
pub trait ArtifactBlobStore: Send + Sync + 'static {
    /// Streams one blob into durable content-addressed storage.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactBlobStoreError`] when the source is too large, I/O fails, or an existing
    /// blob at the resulting address fails verification.
    fn commit_reader(
        &self,
        source: &mut dyn Read,
    ) -> Result<CommittedArtifactBlob, ArtifactBlobStoreError>;

    /// Convenience wrapper for committing an in-memory byte slice.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::commit_reader`].
    fn commit(&self, content: &[u8]) -> Result<CommittedArtifactBlob, ArtifactBlobStoreError> {
        let mut source = Cursor::new(content);
        self.commit_reader(&mut source)
    }

    /// Reads a committed blob after verifying its size and digest.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactBlobStoreError`] when the descriptor is invalid, the blob is absent or
    /// oversized, storage I/O fails, or the persisted content fails integrity verification.
    fn read(&self, blob: &CommittedArtifactBlob) -> Result<Vec<u8>, ArtifactBlobStoreError>;
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactBlobStoreError, ArtifactContentDescriptor, ArtifactEvidenceStoreError,
        ArtifactMetadata, CommittedArtifactBlob,
    };
    use mealy_domain::ArtifactId;
    use std::time::SystemTime;

    #[test]
    fn committed_descriptor_rejects_non_canonical_or_redirected_paths() {
        assert!(matches!(
            CommittedArtifactBlob::new_sha256("not-a-digest", 1),
            Err(ArtifactBlobStoreError::InvalidDescriptor { .. })
        ));

        let mut descriptor = CommittedArtifactBlob::new_sha256(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            3,
        )
        .expect("valid descriptor");
        descriptor.relative_path = "../private-file".to_owned();
        assert!(matches!(
            descriptor.validate(),
            Err(ArtifactBlobStoreError::InvalidDescriptor { .. })
        ));
    }

    #[test]
    fn content_descriptor_rejects_metadata_for_a_different_blob() {
        let metadata = ArtifactMetadata {
            artifact_id: ArtifactId::new(),
            algorithm: "sha256".to_owned(),
            digest: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_owned(),
            size_bytes: 3,
            media_type: "text/plain".to_owned(),
            origin_kind: "tool_call".to_owned(),
            origin_id: "tool-1".to_owned(),
            producer_kind: "builtin".to_owned(),
            producer_id: "read_text".to_owned(),
            sensitivity: "private".to_owned(),
            retention_class: "task_history".to_owned(),
            access_policy_json: "{}".to_owned(),
            access_policy_digest:
                "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a".to_owned(),
            created_at: SystemTime::UNIX_EPOCH,
        };
        let other_blob = CommittedArtifactBlob::new_sha256(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            5,
        )
        .expect("valid other blob");

        assert!(matches!(
            ArtifactContentDescriptor::new(metadata, other_blob),
            Err(ArtifactEvidenceStoreError::InvariantViolation(_))
        ));
    }
}
