use super::SqliteStore;
use mealy_application::{
    BeginDaemonRunCommit, CompleteDaemonRunCommit, DaemonRunStatus, OperationalFailure,
    OperationalSnapshot, OperationalStore, OperationalStoreError, OwnershipContext,
    is_sha256_digest,
};
use mealy_domain::{CorrelationId, SessionId};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use std::{collections::BTreeSet, path::Path, str::FromStr, time::SystemTime};

/// One content-addressed blob referenced by canonical artifact metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactBlobRecord {
    /// Lowercase SHA-256 digest used as the storage identity.
    pub digest: String,
    /// Exact committed byte count.
    pub size_bytes: u64,
    /// Canonical path relative to the artifact root.
    pub relative_path: String,
}

impl SqliteStore {
    /// Returns aggregate bytes for the main database and existing WAL/SHM sidecars.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalStoreError`] when the database path or file metadata is unavailable.
    pub fn database_storage_bytes(&self) -> Result<u64, OperationalStoreError> {
        let path = self
            .connection
            .query_row("PRAGMA database_list", [], |row| row.get::<_, String>(2))
            .map_err(map_sqlite_error)?;
        if path.is_empty() {
            return Ok(0);
        }
        let mut total = 0_u64;
        for suffix in ["", "-wal", "-shm"] {
            let candidate = format!("{path}{suffix}");
            match std::fs::metadata(candidate) {
                Ok(metadata) if metadata.is_file() => {
                    total = total
                        .checked_add(metadata.len())
                        .ok_or_else(|| invariant("database storage bytes overflowed"))?;
                }
                Ok(_) => return Err(invariant("database storage path is not a regular file")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(OperationalStoreError::Unavailable(error.to_string())),
            }
        }
        Ok(total)
    }

    /// Creates a consistent online copy through `SQLite`'s backup API.
    ///
    /// The caller must publish the destination atomically only after all accompanying backup
    /// components and their manifest have been synced.
    ///
    /// # Errors
    ///
    /// Returns [`super::StoreError`] when the source is not ready or `SQLite` cannot complete the
    /// snapshot.
    pub fn online_backup(&self, destination: &Path) -> Result<(), super::StoreError> {
        self.readiness_check()?;
        self.connection.backup("main", destination, None)?;
        let backup = rusqlite::Connection::open(destination)?;
        backup.pragma_update(None, "foreign_keys", "ON")?;
        verify_connection_integrity(&backup)?;
        Ok(())
    }

    /// Returns the current schema version recorded by canonical migration history.
    ///
    /// # Errors
    ///
    /// Returns [`super::StoreError`] when migration history cannot be read.
    pub fn schema_version(&self) -> Result<u64, super::StoreError> {
        let version = self.connection.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        u64::try_from(version).map_err(|_| super::StoreError::InvalidSchemaVersion(version))
    }

    /// Performs full `SQLite` and foreign-key integrity checks.
    ///
    /// # Errors
    ///
    /// Returns [`super::StoreError::NotReady`] for any reported corruption or relational breach.
    pub fn verify_storage_integrity(&self) -> Result<(), super::StoreError> {
        self.readiness_check()?;
        verify_connection_integrity(&self.connection)
    }

    /// Loads the canonical content blobs that a backup or garbage collector must preserve.
    ///
    /// # Errors
    ///
    /// Returns [`super::StoreError`] for malformed or unavailable artifact metadata.
    pub fn artifact_blob_records(&self) -> Result<Vec<ArtifactBlobRecord>, super::StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT digest, size_bytes, relative_path FROM artifact_blob \
             WHERE algorithm = 'sha256' ORDER BY digest",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .map(|row| {
                let (digest, size_bytes, relative_path) = row?;
                if !is_sha256_digest(&digest)
                    || relative_path != format!("sha256/{digest}")
                    || size_bytes < 0
                {
                    return Err(super::StoreError::NotReady(
                        "canonical artifact blob metadata is malformed".to_owned(),
                    ));
                }
                Ok(ArtifactBlobRecord {
                    digest,
                    size_bytes: u64::try_from(size_bytes).map_err(|_| {
                        super::StoreError::NotReady(
                            "canonical artifact size is negative".to_owned(),
                        )
                    })?,
                    relative_path,
                })
            })
            .collect()
    }

    /// Returns canonical blob digests which physical garbage collection must never remove.
    ///
    /// # Errors
    ///
    /// Returns [`super::StoreError`] when artifact metadata is unavailable or malformed.
    pub fn referenced_artifact_digests(&self) -> Result<BTreeSet<String>, super::StoreError> {
        self.artifact_blob_records()
            .map(|records| records.into_iter().map(|record| record.digest).collect())
    }

    /// Lists every session visible to an exact authenticated owner/channel for audit export.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalStoreError`] when authorization, parsing, or the bounded export limit
    /// fails closed.
    pub fn operational_session_ids(
        &self,
        ownership: OwnershipContext,
    ) -> Result<Vec<SessionId>, OperationalStoreError> {
        const MAXIMUM_EXPORT_SESSIONS: usize = 10_000;
        authorize_owner(&self.connection, ownership)?;
        let sql_limit = i64::try_from(MAXIMUM_EXPORT_SESSIONS + 1)
            .map_err(|_| invariant("audit export session limit exceeds SQLite"))?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT id FROM session WHERE principal_id = ?1 AND channel_binding_id = ?2 \
                 ORDER BY created_at_ms, id LIMIT ?3",
            )
            .map_err(map_sqlite_error)?;
        let values = statement
            .query_map(
                params![
                    ownership.principal_id().to_string(),
                    ownership.channel_binding_id().to_string(),
                    sql_limit,
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(map_sqlite_error)?
            .map(|row| {
                SessionId::from_str(&row.map_err(map_sqlite_error)?)
                    .map_err(|_| invariant("stored session ID is invalid"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if values.len() > MAXIMUM_EXPORT_SESSIONS {
            Err(invalid_contract(
                "audit export exceeds the bounded session limit",
            ))
        } else {
            Ok(values)
        }
    }

    /// Checks whether decrypted restore identity maps to one active local registry binding.
    ///
    /// # Errors
    ///
    /// Returns [`super::StoreError`] when the registry cannot be inspected.
    pub fn identity_is_active(
        &self,
        principal_id: &str,
        channel_binding_id: &str,
    ) -> Result<bool, super::StoreError> {
        self.connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM principal_registry principal
                    JOIN channel_binding_registry binding
                      ON binding.principal_id = principal.principal_id
                    WHERE principal.principal_id = ?1 AND principal.status = 'active'
                      AND binding.binding_id = ?2 AND binding.status = 'active'
                 )",
                params![principal_id, channel_binding_id],
                |row| row.get(0),
            )
            .map_err(super::StoreError::from)
    }
}

fn verify_connection_integrity(connection: &rusqlite::Connection) -> Result<(), super::StoreError> {
    let integrity =
        connection.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))?;
    if integrity != "ok" {
        return Err(super::StoreError::NotReady(format!(
            "SQLite integrity check failed: {integrity}"
        )));
    }
    let violations =
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get::<_, i64>(0)
        })?;
    if violations != 0 {
        return Err(super::StoreError::NotReady(format!(
            "SQLite foreign-key check reported {violations} violation(s)"
        )));
    }
    Ok(())
}

impl OperationalStore for SqliteStore {
    fn begin_daemon_run(
        &mut self,
        commit: BeginDaemonRunCommit,
    ) -> Result<(), OperationalStoreError> {
        if !is_sha256_digest(&commit.config_digest)
            || !is_sha256_digest(&commit.policy_bundle_digest)
            || commit.recovery_counts.len() > 64
            || commit
                .recovery_counts
                .keys()
                .any(|key| !valid_field(key, 128))
        {
            return Err(invalid_contract("daemon start evidence is invalid"));
        }
        let started_at_ms = epoch_milliseconds(commit.started_at)?;
        let ready_at_ms = epoch_milliseconds(commit.ready_at)?;
        if ready_at_ms < started_at_ms {
            return Err(invalid_contract("daemon readiness precedes startup"));
        }
        let recovery_counts_json = serde_json::to_string(&commit.recovery_counts)
            .map_err(|error| invalid_contract(error.to_string()))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let principal_active = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM principal_registry \
                 WHERE principal_id = ?1 AND status = 'active')",
                [commit.principal_id.to_string()],
                |row| row.get::<_, bool>(0),
            )
            .map_err(map_sqlite_error)?;
        if !principal_active {
            return Err(OperationalStoreError::NotFound);
        }
        transaction
            .execute(
                "UPDATE daemon_run_record SET status = 'unclean', \
                    completed_at_ms = MAX(ready_at_ms, ?1), \
                    completion_reason = 'next daemon start observed missing shutdown evidence' \
                 WHERE status = 'running'",
                [started_at_ms],
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO daemon_run_record(\
                    start_id, principal_id, config_digest, policy_bundle_digest, safe_mode, \
                    recovery_counts_json, status, started_at_ms, ready_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'running', ?7, ?8)",
                params![
                    commit.start_id.to_string(),
                    commit.principal_id.to_string(),
                    commit.config_digest,
                    commit.policy_bundle_digest,
                    commit.safe_mode,
                    recovery_counts_json,
                    started_at_ms,
                    ready_at_ms,
                ],
            )
            .map_err(map_sqlite_error)?;
        transaction.commit().map_err(map_sqlite_error)
    }

    fn complete_daemon_run(
        &mut self,
        commit: CompleteDaemonRunCommit,
    ) -> Result<(), OperationalStoreError> {
        if !matches!(
            commit.status,
            DaemonRunStatus::Clean | DaemonRunStatus::Forced
        ) || !valid_field(&commit.reason, 4_096)
        {
            return Err(invalid_contract("daemon shutdown evidence is invalid"));
        }
        let completed_at_ms = epoch_milliseconds(commit.completed_at)?;
        let status = match commit.status {
            DaemonRunStatus::Clean => "clean",
            DaemonRunStatus::Forced => "forced",
            DaemonRunStatus::Running | DaemonRunStatus::Unclean => unreachable!(),
        };
        let changed = self
            .connection
            .execute(
                "UPDATE daemon_run_record SET status = ?1, completed_at_ms = ?2, \
                    completion_reason = ?3 \
                 WHERE start_id = ?4 AND status = 'running' AND ready_at_ms <= ?2",
                params![
                    status,
                    completed_at_ms,
                    commit.reason,
                    commit.start_id.to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(OperationalStoreError::Conflict)
        }
    }

    #[allow(clippy::too_many_lines)]
    fn operational_snapshot(
        &self,
        ownership: OwnershipContext,
    ) -> Result<OperationalSnapshot, OperationalStoreError> {
        authorize_owner(&self.connection, ownership)?;
        let run = self
            .connection
            .query_row(
                "SELECT start_id, principal_id, status, safe_mode, config_digest, \
                        policy_bundle_digest, started_at_ms, ready_at_ms, completed_at_ms, \
                        completion_reason \
                 FROM daemon_run_record ORDER BY started_at_ms DESC, start_id DESC LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, bool>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                        row.get::<_, Option<String>>(9)?,
                    ))
                },
            )
            .optional()
            .map_err(map_sqlite_error)?
            .ok_or(OperationalStoreError::NotFound)?;
        if run.1 != ownership.principal_id().to_string()
            || !is_sha256_digest(&run.4)
            || !is_sha256_digest(&run.5)
        {
            return Err(invariant("daemon run ownership or digests are invalid"));
        }
        let schema_version = count_query(
            &self.connection,
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        )?;
        let pending_inputs = count_query(
            &self.connection,
            "SELECT COUNT(*) FROM session_inbox WHERE state = 'pending'",
        )?;
        let nonterminal_runs = count_query(
            &self.connection,
            "SELECT COUNT(*) FROM run WHERE status IN ('queued', 'running', 'waiting')",
        )?;
        let active_leases = count_query(
            &self.connection,
            "SELECT COUNT(*) FROM work_lease WHERE state = 'active'",
        )?;
        let pending_approvals = count_query(
            &self.connection,
            "SELECT COUNT(*) FROM approval_request WHERE status = 'pending'",
        )?;
        let unknown_effects = count_query(
            &self.connection,
            "SELECT COUNT(*) FROM effect WHERE status = 'outcome_unknown'",
        )?;
        let pending_outbox = count_query(
            &self.connection,
            "SELECT COUNT(*) FROM outbox WHERE state IN ('pending', 'delivering')",
        )?;
        let failed_outbox = count_query(
            &self.connection,
            "SELECT COUNT(*) FROM outbox WHERE state = 'failed'",
        )?;
        let enabled_extensions = count_query(
            &self.connection,
            "SELECT COUNT(*) FROM extension_installation WHERE status = 'enabled'",
        )?;
        let failed_extensions = count_query(
            &self.connection,
            "SELECT COUNT(*) FROM extension_installation WHERE status = 'failed'",
        )?;
        let active_channels = count_query(
            &self.connection,
            "SELECT COUNT(*) FROM webhook_channel_binding WHERE status = 'active'",
        )?;
        let recent_failures = load_recent_failures(&self.connection, ownership)?;
        Ok(OperationalSnapshot {
            start_id: CorrelationId::from_str(&run.0)
                .map_err(|_| invariant("daemon start ID is invalid"))?,
            run_status: parse_status(&run.2)?,
            safe_mode: run.3,
            config_digest: run.4,
            policy_bundle_digest: run.5,
            schema_version,
            pending_inputs,
            nonterminal_runs,
            active_leases,
            pending_approvals,
            unknown_effects,
            pending_outbox,
            failed_outbox,
            enabled_extensions,
            failed_extensions,
            active_channels,
            recent_failures,
            started_at_ms: run.6,
            ready_at_ms: run.7,
            completed_at_ms: run.8,
            completion_reason: run.9,
        })
    }

    fn checkpoint_for_shutdown(&mut self) -> Result<(), OperationalStoreError> {
        let (busy, _log_frames, _checkpointed_frames) = self
            .connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(map_sqlite_error)?;
        if busy == 0 {
            Ok(())
        } else {
            Err(OperationalStoreError::Conflict)
        }
    }
}

fn load_recent_failures(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
) -> Result<Vec<OperationalFailure>, OperationalStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT timeline.cursor, journal.event_type, journal.aggregate_kind, \
                    journal.aggregate_id, journal.correlation_id, journal.occurred_at_ms \
             FROM journal_event journal \
             JOIN timeline_event timeline ON timeline.event_id = journal.event_id \
             WHERE journal.actor_principal_id = ?1 \
               AND (journal.event_type LIKE '%failed%' \
                    OR journal.event_type LIKE '%unknown%' \
                    OR journal.event_type LIKE '%denied%' \
                    OR journal.event_type LIKE '%abandoned%') \
             ORDER BY timeline.cursor DESC LIMIT 10",
        )
        .map_err(map_sqlite_error)?;
    statement
        .query_map([ownership.principal_id().to_string()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(map_sqlite_error)?
        .map(|row| {
            let row = row.map_err(map_sqlite_error)?;
            Ok(OperationalFailure {
                cursor: u64::try_from(row.0)
                    .map_err(|_| invariant("failure cursor is negative"))?,
                event_type: row.1,
                aggregate_kind: row.2,
                aggregate_id: row.3,
                correlation_id: row.4,
                occurred_at_ms: row.5,
            })
        })
        .collect()
}

fn authorize_owner(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
) -> Result<(), OperationalStoreError> {
    let authorized = connection
        .query_row(
            "SELECT EXISTS(\
                SELECT 1 FROM principal_registry principal \
                JOIN channel_binding_registry binding \
                  ON binding.principal_id = principal.principal_id \
                WHERE principal.principal_id = ?1 AND principal.status = 'active' \
                  AND binding.binding_id = ?2 AND binding.status = 'active'\
             )",
            params![
                ownership.principal_id().to_string(),
                ownership.channel_binding_id().to_string(),
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(map_sqlite_error)?;
    if authorized {
        Ok(())
    } else {
        Err(OperationalStoreError::NotFound)
    }
}

fn count_query(connection: &rusqlite::Connection, sql: &str) -> Result<u64, OperationalStoreError> {
    let count = connection
        .query_row(sql, [], |row| row.get::<_, i64>(0))
        .map_err(map_sqlite_error)?;
    u64::try_from(count).map_err(|_| invariant("operational count is negative"))
}

fn parse_status(value: &str) -> Result<DaemonRunStatus, OperationalStoreError> {
    match value {
        "running" => Ok(DaemonRunStatus::Running),
        "clean" => Ok(DaemonRunStatus::Clean),
        "forced" => Ok(DaemonRunStatus::Forced),
        "unclean" => Ok(DaemonRunStatus::Unclean),
        _ => Err(invariant("daemon run status is invalid")),
    }
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, OperationalStoreError> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invariant("operational clock is before the Unix epoch"))?;
    i64::try_from(duration.as_millis()).map_err(|_| invariant("operational time exceeds SQLite"))
}

fn valid_field(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[allow(clippy::needless_pass_by_value)]
fn map_sqlite_error(error: rusqlite::Error) -> OperationalStoreError {
    OperationalStoreError::Unavailable(error.to_string())
}

fn invalid_contract(message: impl Into<String>) -> OperationalStoreError {
    OperationalStoreError::InvalidContract(message.into())
}

fn invariant(message: impl Into<String>) -> OperationalStoreError {
    OperationalStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::OperationalStore;
    use mealy_application::{
        BeginDaemonRunCommit, CompleteDaemonRunCommit, DaemonRunStatus, OperationalStoreError,
        OwnershipContext,
    };
    use mealy_domain::{ChannelBindingId, CorrelationId, PrincipalId};
    use std::{
        collections::BTreeMap,
        time::{Duration, SystemTime},
    };

    #[test]
    fn daemon_lifetimes_mark_unclean_predecessors_and_checkpoint_terminal_state() {
        let mut store = super::SqliteStore::open_in_memory(1).expect("store");
        let principal_id = PrincipalId::new();
        let ownership = OwnershipContext::new(principal_id, ChannelBindingId::new());
        store
            .register_local_identity(ownership, 1)
            .expect("register owner");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let first = CorrelationId::new();
        store
            .begin_daemon_run(BeginDaemonRunCommit {
                start_id: first,
                principal_id,
                config_digest: "a".repeat(64),
                policy_bundle_digest: "b".repeat(64),
                safe_mode: false,
                recovery_counts: BTreeMap::new(),
                started_at: now,
                ready_at: now,
            })
            .expect("first start");
        let second = CorrelationId::new();
        store
            .begin_daemon_run(BeginDaemonRunCommit {
                start_id: second,
                principal_id,
                config_digest: "c".repeat(64),
                policy_bundle_digest: "d".repeat(64),
                safe_mode: true,
                recovery_counts: BTreeMap::from([("pending_outbox".to_owned(), 1)]),
                started_at: now + Duration::from_secs(1),
                ready_at: now + Duration::from_secs(2),
            })
            .expect("second start marks first unclean");
        let first_status: String = store
            .connection
            .query_row(
                "SELECT status FROM daemon_run_record WHERE start_id = ?1",
                [first.to_string()],
                |row| row.get(0),
            )
            .expect("first status");
        assert_eq!(first_status, "unclean");
        let snapshot = store
            .operational_snapshot(ownership)
            .expect("operational snapshot");
        assert_eq!(snapshot.start_id, second);
        assert!(snapshot.safe_mode);
        assert_eq!(snapshot.schema_version, 11);
        store
            .complete_daemon_run(CompleteDaemonRunCommit {
                start_id: second,
                status: DaemonRunStatus::Clean,
                reason: "bounded drain completed".to_owned(),
                completed_at: now + Duration::from_secs(3),
            })
            .expect("clean shutdown");
        assert_eq!(
            store.complete_daemon_run(CompleteDaemonRunCommit {
                start_id: second,
                status: DaemonRunStatus::Forced,
                reason: "duplicate".to_owned(),
                completed_at: now + Duration::from_secs(4),
            }),
            Err(OperationalStoreError::Conflict)
        );
        store.checkpoint_for_shutdown().expect("checkpoint");
    }
}
