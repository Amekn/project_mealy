use super::SqliteStore;
use mealy_application::{
    ArtifactContentDescriptor, ArtifactEvidenceStore, ArtifactEvidenceStoreError, ArtifactMetadata,
    CommittedArtifactBlob, OwnershipContext, sha256_digest,
};
use mealy_domain::{ArtifactId, TaskId};
use rusqlite::{OptionalExtension, params};
use std::time::{Duration, SystemTime};

impl ArtifactEvidenceStore for SqliteStore {
    fn artifact_metadata(
        &self,
        ownership: OwnershipContext,
        artifact_id: ArtifactId,
    ) -> Result<ArtifactMetadata, ArtifactEvidenceStoreError> {
        load_authorized_artifact(&self.connection, ownership, artifact_id)
            .map(|descriptor| descriptor.metadata().clone())
    }

    fn artifact_content_descriptor(
        &self,
        ownership: OwnershipContext,
        artifact_id: ArtifactId,
    ) -> Result<ArtifactContentDescriptor, ArtifactEvidenceStoreError> {
        load_authorized_artifact(&self.connection, ownership, artifact_id)
    }

    fn task_artifact_content_descriptors(
        &self,
        ownership: OwnershipContext,
        task_id: TaskId,
    ) -> Result<Vec<ArtifactContentDescriptor>, ArtifactEvidenceStoreError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT DISTINCT a.id \
                 FROM artifact a \
                 JOIN turn t ON t.session_id = a.session_id AND t.task_id = ?1 \
                 JOIN session s ON s.id = t.session_id AND s.principal_id = a.principal_id \
                 WHERE s.principal_id = ?2 AND s.channel_binding_id = ?3 \
                   AND ((a.origin_kind = 'tool_call' AND a.origin_id IN \
                            (SELECT tool_call_id FROM tool_call WHERE run_id = t.run_id)) \
                     OR (a.origin_kind = 'model_attempt' AND a.origin_id IN \
                            (SELECT attempt_id FROM model_attempt WHERE run_id = t.run_id))) \
                 ORDER BY a.created_at_ms, a.id",
            )
            .map_err(|error| map_sqlite_error(&error))?;
        let artifact_ids = statement
            .query_map(
                params![
                    task_id.to_string(),
                    ownership.principal_id().to_string(),
                    ownership.channel_binding_id().to_string(),
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| map_sqlite_error(&error))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| map_sqlite_error(&error))?;
        if artifact_ids.is_empty() {
            let authorized_task = self
                .connection
                .query_row(
                    "SELECT EXISTS(\
                        SELECT 1 FROM turn t JOIN session s ON s.id = t.session_id \
                        WHERE t.task_id = ?1 AND s.principal_id = ?2 \
                          AND s.channel_binding_id = ?3\
                    )",
                    params![
                        task_id.to_string(),
                        ownership.principal_id().to_string(),
                        ownership.channel_binding_id().to_string(),
                    ],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|error| map_sqlite_error(&error))?;
            if !authorized_task {
                return Err(ArtifactEvidenceStoreError::NotFound);
            }
        }
        artifact_ids
            .into_iter()
            .map(|value| {
                let artifact_id = value
                    .parse::<ArtifactId>()
                    .map_err(|_| invariant("stored artifact ID is invalid"))?;
                load_authorized_artifact(&self.connection, ownership, artifact_id)
            })
            .collect()
    }
}

fn load_authorized_artifact(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
    artifact_id: ArtifactId,
) -> Result<ArtifactContentDescriptor, ArtifactEvidenceStoreError> {
    let row = connection
        .query_row(
            "SELECT a.blob_algorithm, a.blob_digest, blob.size_bytes, blob.relative_path, \
                    blob.committed_at_ms, a.media_type, a.origin_kind, a.origin_id, \
                    a.producer_kind, a.producer_id, a.sensitivity, a.retention_class, \
                    a.access_policy_json, a.access_policy_digest, a.created_at_ms, \
                    a.principal_id, a.session_id \
             FROM artifact a \
             JOIN artifact_blob blob \
               ON blob.algorithm = a.blob_algorithm AND blob.digest = a.blob_digest \
             JOIN session owner_session \
               ON owner_session.id = a.session_id \
              AND owner_session.principal_id = a.principal_id \
             WHERE a.id = ?1 AND a.principal_id = ?2 \
               AND owner_session.principal_id = ?2 \
               AND owner_session.channel_binding_id = ?3",
            params![
                artifact_id.to_string(),
                ownership.principal_id().to_string(),
                ownership.channel_binding_id().to_string(),
            ],
            |result| {
                Ok(AuthorizedArtifactRow {
                    algorithm: result.get(0)?,
                    digest: result.get(1)?,
                    size_bytes: result.get(2)?,
                    relative_path: result.get(3)?,
                    committed_at_ms: result.get(4)?,
                    media_type: result.get(5)?,
                    origin_kind: result.get(6)?,
                    origin_id: result.get(7)?,
                    producer_kind: result.get(8)?,
                    producer_id: result.get(9)?,
                    sensitivity: result.get(10)?,
                    retention_class: result.get(11)?,
                    access_policy_json: result.get(12)?,
                    access_policy_digest: result.get(13)?,
                    created_at_ms: result.get(14)?,
                    principal_id: result.get(15)?,
                    session_id: result.get(16)?,
                })
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?
        .ok_or(ArtifactEvidenceStoreError::NotFound)?;
    row.into_descriptor(artifact_id)
}

struct AuthorizedArtifactRow {
    algorithm: String,
    digest: String,
    size_bytes: i64,
    relative_path: String,
    committed_at_ms: i64,
    media_type: String,
    origin_kind: String,
    origin_id: String,
    producer_kind: String,
    producer_id: String,
    sensitivity: String,
    retention_class: String,
    access_policy_json: String,
    access_policy_digest: String,
    created_at_ms: i64,
    principal_id: String,
    session_id: String,
}

impl AuthorizedArtifactRow {
    fn into_descriptor(
        self,
        artifact_id: ArtifactId,
    ) -> Result<ArtifactContentDescriptor, ArtifactEvidenceStoreError> {
        let size_bytes = u64::try_from(self.size_bytes)
            .map_err(|_| invariant("stored artifact size is negative"))?;
        if self.committed_at_ms < 0 || self.created_at_ms < self.committed_at_ms {
            return Err(invariant(
                "artifact metadata predates its committed content blob",
            ));
        }
        let expected_access_policy = serde_json::json!({
            "principalId": self.principal_id,
            "sessionId": self.session_id,
        })
        .to_string();
        if self.access_policy_json != expected_access_policy
            || sha256_digest(self.access_policy_json.as_bytes()) != self.access_policy_digest
        {
            return Err(invariant("stored artifact access-policy digest mismatch"));
        }

        let committed_blob = CommittedArtifactBlob {
            algorithm: self.algorithm.clone(),
            digest: self.digest.clone(),
            size_bytes,
            relative_path: self.relative_path,
        };
        let metadata = ArtifactMetadata {
            artifact_id,
            algorithm: self.algorithm,
            digest: self.digest,
            size_bytes,
            media_type: self.media_type,
            origin_kind: self.origin_kind,
            origin_id: self.origin_id,
            producer_kind: self.producer_kind,
            producer_id: self.producer_id,
            sensitivity: self.sensitivity,
            retention_class: self.retention_class,
            access_policy_json: self.access_policy_json,
            access_policy_digest: self.access_policy_digest,
            created_at: timestamp_from_milliseconds(self.created_at_ms)?,
        };
        ArtifactContentDescriptor::new(metadata, committed_blob)
    }
}

fn timestamp_from_milliseconds(value: i64) -> Result<SystemTime, ArtifactEvidenceStoreError> {
    let milliseconds =
        u64::try_from(value).map_err(|_| invariant("stored artifact timestamp is negative"))?;
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_millis(milliseconds))
        .ok_or_else(|| invariant("stored artifact timestamp is out of range"))
}

fn map_sqlite_error(error: &rusqlite::Error) -> ArtifactEvidenceStoreError {
    ArtifactEvidenceStoreError::Unavailable(error.to_string())
}

fn invariant(message: impl Into<String>) -> ArtifactEvidenceStoreError {
    ArtifactEvidenceStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::SqliteStore;
    use mealy_application::{
        ArtifactEvidenceStore, ArtifactEvidenceStoreError, OwnershipContext, sha256_digest,
    };
    use mealy_domain::{ArtifactId, ChannelBindingId, PrincipalId, SessionId};
    use rusqlite::params;
    use serde_json::json;

    const CREATED_AT_MS: i64 = 20;
    const CONTENT: &[u8] = b"durable evidence";

    #[test]
    fn authorized_owner_receives_path_free_metadata_and_trusted_descriptor() {
        let fixture = Fixture::new();

        let metadata = fixture
            .store
            .artifact_metadata(fixture.ownership, fixture.artifact_id)
            .expect("authorized metadata");
        assert_eq!(metadata.artifact_id, fixture.artifact_id);
        assert_eq!(metadata.digest, fixture.digest);
        assert_eq!(metadata.size_bytes, CONTENT.len() as u64);
        assert_eq!(metadata.media_type, "text/plain");
        assert_eq!(metadata.access_policy_json, fixture.access_policy_json);
        assert_eq!(
            serde_json::to_value(&metadata)
                .expect("serialize metadata")
                .get("relativePath"),
            None
        );

        let descriptor = fixture
            .store
            .artifact_content_descriptor(fixture.ownership, fixture.artifact_id)
            .expect("authorized content descriptor");
        assert_eq!(descriptor.metadata(), &metadata);
        assert_eq!(descriptor.committed_blob().digest, metadata.digest);
        assert_eq!(descriptor.committed_blob().size_bytes, metadata.size_bytes);
        assert_eq!(
            descriptor.committed_blob().relative_path,
            format!("sha256/{}", metadata.digest)
        );
    }

    #[test]
    fn wrong_principal_or_channel_cannot_enumerate_artifact_evidence() {
        let fixture = Fixture::new();
        let wrong_principal =
            OwnershipContext::new(PrincipalId::new(), fixture.ownership.channel_binding_id());
        let wrong_channel =
            OwnershipContext::new(fixture.ownership.principal_id(), ChannelBindingId::new());

        for ownership in [wrong_principal, wrong_channel] {
            assert_eq!(
                fixture
                    .store
                    .artifact_metadata(ownership, fixture.artifact_id),
                Err(ArtifactEvidenceStoreError::NotFound)
            );
            assert_eq!(
                fixture
                    .store
                    .artifact_content_descriptor(ownership, fixture.artifact_id),
                Err(ArtifactEvidenceStoreError::NotFound)
            );
        }
    }

    #[test]
    fn artifact_owner_and_access_policy_are_immutable() {
        let fixture = Fixture::new();
        assert!(
            fixture
                .store
                .connection
                .execute(
                    "UPDATE artifact SET access_policy_json = '{}' WHERE id = ?1",
                    [fixture.artifact_id.to_string()],
                )
                .is_err()
        );
    }

    #[test]
    fn projection_rejects_inconsistent_digests_and_blob_metadata() {
        let fixture = Fixture::new();
        fixture
            .store
            .connection
            .execute_batch("DROP TRIGGER artifact_ownership_immutable;")
            .expect("simulate corruption below the normal immutability boundary");
        fixture
            .store
            .connection
            .execute(
                "UPDATE artifact SET access_policy_digest = ?1 WHERE id = ?2",
                params!["0".repeat(64), fixture.artifact_id.to_string()],
            )
            .expect("corrupt policy digest");
        assert!(matches!(
            fixture
                .store
                .artifact_metadata(fixture.ownership, fixture.artifact_id),
            Err(ArtifactEvidenceStoreError::InvariantViolation(message))
                if message.contains("access-policy digest")
        ));

        let forged_policy = json!({
            "principalId": PrincipalId::new(),
            "sessionId": SessionId::new(),
        })
        .to_string();
        fixture
            .store
            .connection
            .execute(
                "UPDATE artifact SET access_policy_json = ?1, access_policy_digest = ?2 \
                 WHERE id = ?3",
                params![
                    forged_policy,
                    sha256_digest(forged_policy.as_bytes()),
                    fixture.artifact_id.to_string(),
                ],
            )
            .expect("forge self-consistent but unauthorized policy evidence");
        assert!(matches!(
            fixture
                .store
                .artifact_metadata(fixture.ownership, fixture.artifact_id),
            Err(ArtifactEvidenceStoreError::InvariantViolation(message))
                if message.contains("access-policy digest")
        ));

        fixture
            .store
            .connection
            .pragma_update(None, "ignore_check_constraints", true)
            .expect("disable checks for corruption fixture");
        fixture
            .store
            .connection
            .execute(
                "UPDATE artifact SET access_policy_json = ?1, access_policy_digest = ?2 \
                 WHERE id = ?3;",
                params![
                    fixture.access_policy_json.as_str(),
                    sha256_digest(fixture.access_policy_json.as_bytes()),
                    fixture.artifact_id.to_string()
                ],
            )
            .expect("restore policy digest");
        fixture
            .store
            .connection
            .execute(
                "UPDATE artifact_blob SET relative_path = 'sha256/redirected' \
                 WHERE algorithm = 'sha256' AND digest = ?1",
                [fixture.digest],
            )
            .expect("corrupt blob metadata");
        assert!(matches!(
            fixture
                .store
                .artifact_content_descriptor(fixture.ownership, fixture.artifact_id),
            Err(ArtifactEvidenceStoreError::InvariantViolation(_))
        ));
    }

    struct Fixture {
        store: SqliteStore,
        ownership: OwnershipContext,
        artifact_id: ArtifactId,
        digest: String,
        access_policy_json: String,
    }

    impl Fixture {
        fn new() -> Self {
            let store = SqliteStore::open_in_memory(0).expect("open store");
            let principal_id = PrincipalId::new();
            let channel_binding_id = ChannelBindingId::new();
            let session_id = SessionId::new();
            let artifact_id = ArtifactId::new();
            let digest = sha256_digest(CONTENT);
            let access_policy_json = json!({
                "principalId": principal_id,
                "sessionId": session_id,
            })
            .to_string();
            let access_policy_digest = sha256_digest(access_policy_json.as_bytes());
            store
                .connection
                .execute(
                    "INSERT INTO session(\
                        id, principal_id, channel_binding_id, created_at_ms, updated_at_ms\
                     ) VALUES (?1, ?2, ?3, 0, 0)",
                    params![
                        session_id.to_string(),
                        principal_id.to_string(),
                        channel_binding_id.to_string(),
                    ],
                )
                .expect("seed owner session");
            store
                .connection
                .execute(
                    "INSERT INTO artifact_blob(\
                        algorithm, digest, size_bytes, relative_path, committed_at_ms\
                     ) VALUES ('sha256', ?1, ?2, ?3, 10)",
                    params![
                        digest,
                        i64::try_from(CONTENT.len()).expect("content size fits SQLite"),
                        format!("sha256/{digest}"),
                    ],
                )
                .expect("seed artifact blob");
            store
                .connection
                .execute(
                    "INSERT INTO artifact(\
                        id, blob_algorithm, blob_digest, principal_id, session_id, media_type, \
                        origin_kind, origin_id, producer_kind, producer_id, sensitivity, \
                        retention_class, access_policy_json, access_policy_digest, created_at_ms\
                     ) VALUES (?1, 'sha256', ?2, ?3, ?4, 'text/plain', 'tool_call', 'tool-1', \
                               'builtin', 'read_text', 'private', 'task_history', ?5, ?6, ?7)",
                    params![
                        artifact_id.to_string(),
                        digest,
                        principal_id.to_string(),
                        session_id.to_string(),
                        access_policy_json,
                        access_policy_digest,
                        CREATED_AT_MS,
                    ],
                )
                .expect("seed artifact metadata");
            Self {
                store,
                ownership: OwnershipContext::new(principal_id, channel_binding_id),
                artifact_id,
                digest,
                access_policy_json,
            }
        }
    }
}
