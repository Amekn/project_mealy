use super::SqliteStore;
use mealy_application::{
    BeginDaemonRunCommit, CompleteDaemonRunCommit, CompletedUsageBucket, CompletedUsageReport,
    DaemonRunStatus, OperationalFailure, OperationalSnapshot, OperationalStore,
    OperationalStoreError, OwnershipContext, ProviderEndpointHistory, is_sha256_digest,
};
use mealy_domain::{CorrelationId, SessionId};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use std::{collections::BTreeSet, path::Path, str::FromStr, time::SystemTime};

const USAGE_DAY_MS: i64 = 86_400_000;
const MAXIMUM_USAGE_REPORT_DAYS: i64 = 31;
const MAXIMUM_USAGE_REPORT_BUCKETS: usize = 32;

struct StoredCompletedUsageBucket {
    bucket_start_ms: i64,
    completed_runs: i64,
    succeeded_runs: i64,
    failed_runs: i64,
    cancelled_runs: i64,
    used_model_calls: i64,
    used_tool_calls: i64,
    used_delegated_runs: i64,
    used_retries: i64,
    used_input_tokens: i64,
    used_output_tokens: i64,
    used_cost_microunits: i64,
    used_output_bytes: i64,
    reserved_usage: i64,
}

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
            "SELECT (SELECT COUNT(*) FROM webhook_channel_binding WHERE status = 'active') \
                  + (SELECT COUNT(*) FROM telegram_channel_binding WHERE status = 'active') \
                  + (SELECT COUNT(*) FROM discord_channel_binding WHERE status = 'active')",
        )?;
        let degraded_channels = count_query(
            &self.connection,
            "SELECT (SELECT COUNT(*) FROM telegram_channel_binding binding \
                     JOIN telegram_channel_health health \
                       ON health.binding_id = binding.binding_id \
                     WHERE binding.status = 'active' AND health.consecutive_failures > 0) \
                  + (SELECT COUNT(*) FROM discord_channel_binding binding \
                     JOIN discord_channel_health health \
                       ON health.binding_id = binding.binding_id \
                     WHERE binding.status = 'active' AND health.consecutive_failures > 0)",
        )?;
        let reserved_channel_updates = count_query(
            &self.connection,
            "SELECT (SELECT COUNT(*) FROM telegram_update_receipt WHERE state = 'reserved') \
                  + (SELECT COUNT(*) FROM discord_message_receipt WHERE state = 'reserved')",
        )?;
        let active_schedules = count_query(
            &self.connection,
            "SELECT COUNT(*) FROM agent_schedule WHERE status = 'active'",
        )?;
        let paused_schedules = count_query(
            &self.connection,
            "SELECT COUNT(*) FROM agent_schedule WHERE status = 'paused'",
        )?;
        let claimed_schedule_runs = count_query(
            &self.connection,
            "SELECT COUNT(*) FROM agent_schedule_run WHERE status = 'claimed'",
        )?;
        let failed_schedule_runs = count_query(
            &self.connection,
            "SELECT COUNT(*) FROM agent_schedule_run WHERE status = 'failed'",
        )?;
        let skipped_schedule_runs = count_query(
            &self.connection,
            "SELECT COUNT(*) FROM agent_schedule_run WHERE status = 'skipped'",
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
            degraded_channels,
            reserved_channel_updates,
            active_schedules,
            paused_schedules,
            claimed_schedule_runs,
            failed_schedule_runs,
            skipped_schedule_runs,
            recent_failures,
            started_at_ms: run.6,
            ready_at_ms: run.7,
            completed_at_ms: run.8,
            completion_reason: run.9,
        })
    }

    fn provider_endpoint_history(
        &self,
        ownership: OwnershipContext,
        endpoints: &[(String, String)],
    ) -> Result<Vec<ProviderEndpointHistory>, OperationalStoreError> {
        authorize_owner(&self.connection, ownership)?;
        if endpoints.is_empty()
            || endpoints.len() > 16
            || endpoints.iter().any(|(provider_id, model_id)| {
                !valid_field(provider_id, 128) || !valid_field(model_id, 128)
            })
            || endpoints.iter().collect::<BTreeSet<_>>().len() != endpoints.len()
        {
            return Err(invalid_contract(
                "provider endpoint history query is invalid",
            ));
        }
        let mut history = Vec::with_capacity(endpoints.len());
        for (provider_id, model_id) in endpoints {
            let row = self
                .connection
                .query_row(
                    "SELECT \
                        COALESCE(SUM(CASE WHEN dispatched_at_ms IS NOT NULL THEN 1 ELSE 0 END), 0), \
                        MAX(CASE WHEN state = 'completed' THEN completed_at_ms END), \
                        MAX(CASE WHEN state = 'failed' AND dispatched_at_ms IS NOT NULL \
                            THEN completed_at_ms END) \
                     FROM model_attempt WHERE provider_id = ?1 AND model_id = ?2",
                    params![provider_id, model_id],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Option<i64>>(1)?,
                            row.get::<_, Option<i64>>(2)?,
                        ))
                    },
                )
                .map_err(map_sqlite_error)?;
            if row.1.is_some_and(|value| value < 0) || row.2.is_some_and(|value| value < 0) {
                return Err(invariant("provider endpoint history time is negative"));
            }
            history.push(ProviderEndpointHistory {
                provider_id: provider_id.clone(),
                model_id: model_id.clone(),
                invocation_count: u64::try_from(row.0)
                    .map_err(|_| invariant("provider endpoint invocation count is negative"))?,
                last_success_at_ms: row.1,
                last_failure_at_ms: row.2,
            });
        }
        Ok(history)
    }

    #[allow(clippy::too_many_lines)]
    fn completed_usage_report(
        &self,
        ownership: OwnershipContext,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<CompletedUsageReport, OperationalStoreError> {
        authorize_owner(&self.connection, ownership)?;
        let duration_ms = to_ms
            .checked_sub(from_ms)
            .ok_or_else(|| invalid_contract("usage report range overflows"))?;
        if from_ms < 0 || duration_ms <= 0 || duration_ms > MAXIMUM_USAGE_REPORT_DAYS * USAGE_DAY_MS
        {
            return Err(invalid_contract(
                "usage report range must be positive and no longer than 31 days",
            ));
        }

        let mut statement = self
            .connection
            .prepare(
                "SELECT (run.completed_at_ms / ?1) * ?1 AS bucket_start_ms, \
                        COUNT(*), \
                        SUM(CASE WHEN run.status = 'succeeded' THEN 1 ELSE 0 END), \
                        SUM(CASE WHEN run.status = 'failed' THEN 1 ELSE 0 END), \
                        SUM(CASE WHEN run.status = 'cancelled' THEN 1 ELSE 0 END), \
                        SUM(usage.used_model_calls), SUM(usage.used_tool_calls), \
                        SUM(usage.used_delegated_runs), SUM(usage.used_retries), \
                        SUM(usage.used_input_tokens), SUM(usage.used_output_tokens), \
                        SUM(usage.used_cost_microunits), SUM(usage.used_output_bytes), \
                        SUM(usage.reserved_model_calls + usage.reserved_tool_calls \
                            + usage.reserved_delegated_runs + usage.reserved_input_tokens \
                            + usage.reserved_output_tokens + usage.reserved_cost_microunits \
                            + usage.reserved_output_bytes) \
                 FROM run INDEXED BY run_terminal_completion_idx \
                 JOIN run_lineage lineage ON lineage.run_id = run.id \
                 JOIN turn ON turn.run_id = lineage.root_run_id \
                 JOIN session ON session.id = turn.session_id \
                 JOIN run_budget_usage usage ON usage.run_id = run.id \
                 WHERE session.principal_id = ?2 AND session.channel_binding_id = ?3 \
                   AND run.completed_at_ms >= ?4 AND run.completed_at_ms < ?5 \
                   AND run.status IN ('succeeded', 'failed', 'cancelled') \
                 GROUP BY bucket_start_ms ORDER BY bucket_start_ms",
            )
            .map_err(map_sqlite_error)?;
        let stored = statement
            .query_map(
                params![
                    USAGE_DAY_MS,
                    ownership.principal_id().to_string(),
                    ownership.channel_binding_id().to_string(),
                    from_ms,
                    to_ms,
                ],
                |row| {
                    Ok(StoredCompletedUsageBucket {
                        bucket_start_ms: row.get(0)?,
                        completed_runs: row.get(1)?,
                        succeeded_runs: row.get(2)?,
                        failed_runs: row.get(3)?,
                        cancelled_runs: row.get(4)?,
                        used_model_calls: row.get(5)?,
                        used_tool_calls: row.get(6)?,
                        used_delegated_runs: row.get(7)?,
                        used_retries: row.get(8)?,
                        used_input_tokens: row.get(9)?,
                        used_output_tokens: row.get(10)?,
                        used_cost_microunits: row.get(11)?,
                        used_output_bytes: row.get(12)?,
                        reserved_usage: row.get(13)?,
                    })
                },
            )
            .map_err(map_sqlite_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_sqlite_error)?;
        if stored.len() > MAXIMUM_USAGE_REPORT_BUCKETS {
            return Err(invariant("usage report exceeds its bounded bucket count"));
        }

        let mut buckets = Vec::with_capacity(stored.len());
        for row in stored {
            if row.bucket_start_ms < 0 || row.bucket_start_ms % USAGE_DAY_MS != 0 {
                return Err(invariant("usage report bucket is not a UTC day"));
            }
            let bucket_end_ms = row
                .bucket_start_ms
                .checked_add(USAGE_DAY_MS)
                .ok_or_else(|| invariant("usage report bucket end overflows"))?
                .min(to_ms);
            if bucket_end_ms <= from_ms || row.reserved_usage != 0 {
                return Err(invariant(
                    "terminal usage report contains an invalid bucket or active reservation",
                ));
            }
            let completed_runs = nonnegative_usage(row.completed_runs, "completed run count")?;
            let succeeded_runs = nonnegative_usage(row.succeeded_runs, "succeeded run count")?;
            let failed_runs = nonnegative_usage(row.failed_runs, "failed run count")?;
            let cancelled_runs = nonnegative_usage(row.cancelled_runs, "cancelled run count")?;
            if succeeded_runs
                .checked_add(failed_runs)
                .and_then(|value| value.checked_add(cancelled_runs))
                != Some(completed_runs)
            {
                return Err(invariant("terminal usage status counts do not balance"));
            }
            buckets.push(CompletedUsageBucket {
                bucket_start_ms: row.bucket_start_ms,
                bucket_end_ms,
                completed_runs,
                succeeded_runs,
                failed_runs,
                cancelled_runs,
                used_model_calls: nonnegative_usage(row.used_model_calls, "model call usage")?,
                used_tool_calls: nonnegative_usage(row.used_tool_calls, "tool call usage")?,
                used_delegated_runs: nonnegative_usage(
                    row.used_delegated_runs,
                    "delegated run usage",
                )?,
                used_retries: nonnegative_usage(row.used_retries, "retry usage")?,
                used_input_tokens: nonnegative_usage(row.used_input_tokens, "input token usage")?,
                used_output_tokens: nonnegative_usage(
                    row.used_output_tokens,
                    "output token usage",
                )?,
                used_cost_microunits: nonnegative_usage(row.used_cost_microunits, "cost usage")?,
                used_output_bytes: nonnegative_usage(row.used_output_bytes, "output byte usage")?,
            });
        }
        Ok(CompletedUsageReport {
            from_ms,
            to_ms,
            buckets,
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

fn nonnegative_usage(value: i64, field: &str) -> Result<u64, OperationalStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("usage report {field} is negative")))
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
    use rusqlite::params;
    use std::{
        collections::BTreeMap,
        time::{Duration, SystemTime},
    };

    const DAY_MS: i64 = 86_400_000;

    #[derive(Clone, Copy)]
    struct UsageSeed {
        model_calls: i64,
        tool_calls: i64,
        delegated_runs: i64,
        retries: i64,
        input_tokens: i64,
        output_tokens: i64,
        cost_microunits: i64,
        output_bytes: i64,
    }

    #[allow(clippy::too_many_lines)]
    fn seed_terminal_usage_graph(
        store: &super::SqliteStore,
        ownership: OwnershipContext,
        suffix: &str,
        status: &str,
        completed_at_ms: i64,
        usage: UsageSeed,
        parent: Option<(&str, &str, &str)>,
    ) {
        let session_id = format!("session-{suffix}");
        let inbox_id = format!("inbox-{suffix}");
        let task_id = format!("task-{suffix}");
        let run_id = format!("run-{suffix}");
        let turn_id = format!("turn-{suffix}");
        let task_status = if status == "succeeded" {
            "succeeded"
        } else if status == "failed" {
            "failed"
        } else {
            "cancelled"
        };
        store
            .connection
            .execute(
                "INSERT INTO task(id, status, revision, validation_required, parent_task_id) \
                 VALUES (?1, ?2, 1, 0, ?3)",
                params![task_id, task_status, parent.map(|value| value.1)],
            )
            .expect("seed task");
        store
            .connection
            .execute(
                "INSERT INTO run(\
                    id, task_id, parent_run_id, status, revision, agent_role, \
                    capability_ceiling_json, budget_json, correlation_id, created_at_ms, \
                    updated_at_ms, completed_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, 1, 'assistant', '{}', '{}', ?5, ?6, ?7, ?7)",
                params![
                    run_id,
                    task_id,
                    parent.map(|value| value.2),
                    status,
                    format!("correlation-{suffix}"),
                    completed_at_ms - 100,
                    completed_at_ms,
                ],
            )
            .expect("seed run");
        let root_run_id = if let Some((root_run_id, _, parent_run_id)) = parent {
            let delegation_id = format!("delegation-{suffix}");
            store
                .connection
                .execute(
                    "INSERT INTO delegation(\
                        id, parent_run_id, child_task_id, child_run_id, ordinal, \
                        parent_fencing_token, work_order_json, work_order_digest, \
                        success_criteria_json, success_criteria_digest, context_package_json, \
                        context_package_digest, requested_capabilities_json, \
                        effective_capabilities_json, effective_capabilities_digest, budget_json, \
                        budget_digest, state, result_json, result_digest, result_fencing_token, \
                        created_at_ms, completed_at_ms\
                     ) VALUES (?1, ?2, ?3, ?4, 1, 1, '{}', ?5, '{}', ?5, '{}', ?5, '{}', \
                        '{}', ?5, '{}', ?5, ?6, '{}', ?5, 1, ?7, ?8)",
                    params![
                        delegation_id,
                        parent_run_id,
                        task_id,
                        run_id,
                        "a".repeat(64),
                        status,
                        completed_at_ms - 100,
                        completed_at_ms,
                    ],
                )
                .expect("seed delegation");
            store
                .connection
                .execute(
                    "INSERT INTO run_lineage(\
                        run_id, root_run_id, parent_run_id, depth, relation_kind, relation_id\
                     ) VALUES (?1, ?2, ?3, 1, 'delegation', ?4)",
                    params![run_id, root_run_id, parent_run_id, delegation_id,],
                )
                .expect("seed child lineage");
            root_run_id.to_owned()
        } else {
            store
                .connection
                .execute(
                    "INSERT INTO run_lineage(\
                        run_id, root_run_id, parent_run_id, depth, relation_kind, relation_id\
                     ) VALUES (?1, ?1, NULL, 0, 'root', NULL)",
                    [&run_id],
                )
                .expect("seed root lineage");
            store
                .connection
                .execute(
                    "INSERT INTO session(\
                        id, principal_id, channel_binding_id, created_at_ms, updated_at_ms\
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        session_id,
                        ownership.principal_id().to_string(),
                        ownership.channel_binding_id().to_string(),
                        completed_at_ms - 200,
                        completed_at_ms,
                    ],
                )
                .expect("seed session");
            store
                .connection
                .execute(
                    "INSERT INTO session_inbox(\
                        inbox_entry_id, session_id, sequence, dedupe_key, delivery_mode, state, \
                        content, admission_event_id, acknowledgement_outbox_id, correlation_id, \
                        accepted_at_ms, promoted_at_ms, promoted_turn_id\
                     ) VALUES (?1, ?2, 1, ?3, 'queue', 'promoted', 'usage test', ?4, ?5, ?6, \
                        ?7, ?8, ?9)",
                    params![
                        inbox_id,
                        session_id,
                        format!("dedupe-{suffix}"),
                        format!("admission-{suffix}"),
                        format!("ack-{suffix}"),
                        format!("correlation-{suffix}"),
                        completed_at_ms - 200,
                        completed_at_ms - 100,
                        turn_id,
                    ],
                )
                .expect("seed inbox");
            store
                .connection
                .execute(
                    "INSERT INTO turn(\
                        id, session_id, inbox_entry_id, task_id, run_id, status, revision, \
                        correlation_id, created_at_ms, completed_at_ms\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8, ?9)",
                    params![
                        turn_id,
                        session_id,
                        inbox_id,
                        task_id,
                        run_id,
                        if status == "succeeded" {
                            "completed"
                        } else if status == "failed" {
                            "failed"
                        } else {
                            "cancelled"
                        },
                        format!("correlation-{suffix}"),
                        completed_at_ms - 100,
                        completed_at_ms,
                    ],
                )
                .expect("seed turn");
            run_id.clone()
        };
        assert!(!root_run_id.is_empty());
        store
            .connection
            .execute(
                "INSERT INTO run_budget_usage(\
                    run_id, maximum_model_calls, maximum_tool_calls, maximum_retries, \
                    maximum_input_tokens, maximum_output_tokens, maximum_cost_microunits, \
                    maximum_output_bytes, maximum_wall_time_ms, used_model_calls, \
                    used_tool_calls, used_retries, used_input_tokens, used_output_tokens, \
                    used_cost_microunits, used_output_bytes, started_at_ms, deadline_at_ms, \
                    maximum_delegated_runs, used_delegated_runs\
                 ) VALUES (?1, 100, 100, 100, 100000, 100000, 1000000, 1000000, 10000, \
                    ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 100, ?11)",
                params![
                    run_id,
                    usage.model_calls,
                    usage.tool_calls,
                    usage.retries,
                    usage.input_tokens,
                    usage.output_tokens,
                    usage.cost_microunits,
                    usage.output_bytes,
                    completed_at_ms - 100,
                    completed_at_ms + 9_900,
                    usage.delegated_runs,
                ],
            )
            .expect("seed usage");
    }

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
        assert_eq!(
            snapshot.schema_version,
            u64::try_from(crate::LATEST_SCHEMA_VERSION).expect("nonnegative schema version")
        );
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

    #[test]
    #[allow(clippy::too_many_lines)]
    fn completed_usage_is_owner_scoped_bounded_and_includes_child_runs() {
        let mut store = super::SqliteStore::open_in_memory(1).expect("store");
        let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
        store
            .register_local_identity(ownership, 1)
            .expect("register owner");
        seed_terminal_usage_graph(
            &store,
            ownership,
            "day-one-root",
            "succeeded",
            DAY_MS + 200,
            UsageSeed {
                model_calls: 2,
                tool_calls: 1,
                delegated_runs: 1,
                retries: 0,
                input_tokens: 10,
                output_tokens: 5,
                cost_microunits: 100,
                output_bytes: 50,
            },
            None,
        );
        seed_terminal_usage_graph(
            &store,
            ownership,
            "day-one-child",
            "failed",
            DAY_MS + 300,
            UsageSeed {
                model_calls: 1,
                tool_calls: 2,
                delegated_runs: 0,
                retries: 1,
                input_tokens: 20,
                output_tokens: 6,
                cost_microunits: 200,
                output_bytes: 60,
            },
            Some(("run-day-one-root", "task-day-one-root", "run-day-one-root")),
        );
        seed_terminal_usage_graph(
            &store,
            ownership,
            "day-two-root",
            "cancelled",
            2 * DAY_MS + 400,
            UsageSeed {
                model_calls: 4,
                tool_calls: 0,
                delegated_runs: 0,
                retries: 2,
                input_tokens: 30,
                output_tokens: 7,
                cost_microunits: 400,
                output_bytes: 70,
            },
            None,
        );

        let other = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
        store
            .register_local_identity(other, 1)
            .expect("register other owner");
        seed_terminal_usage_graph(
            &store,
            other,
            "other-owner",
            "succeeded",
            DAY_MS + 500,
            UsageSeed {
                model_calls: 99,
                tool_calls: 99,
                delegated_runs: 0,
                retries: 0,
                input_tokens: 99,
                output_tokens: 99,
                cost_microunits: 99,
                output_bytes: 99,
            },
            None,
        );

        let query_plan = store
            .connection
            .prepare(
                "EXPLAIN QUERY PLAN \
                 SELECT (run.completed_at_ms / ?1) * ?1, COUNT(*) \
                 FROM run INDEXED BY run_terminal_completion_idx \
                 JOIN run_lineage lineage ON lineage.run_id = run.id \
                 JOIN turn ON turn.run_id = lineage.root_run_id \
                 JOIN session ON session.id = turn.session_id \
                 JOIN run_budget_usage usage ON usage.run_id = run.id \
                 WHERE session.principal_id = ?2 AND session.channel_binding_id = ?3 \
                   AND run.completed_at_ms >= ?4 AND run.completed_at_ms < ?5 \
                   AND run.status IN ('succeeded', 'failed', 'cancelled') \
                 GROUP BY 1",
            )
            .expect("prepare usage query plan")
            .query_map(
                params![
                    DAY_MS,
                    ownership.principal_id().to_string(),
                    ownership.channel_binding_id().to_string(),
                    DAY_MS + 100,
                    3 * DAY_MS,
                ],
                |row| row.get::<_, String>(3),
            )
            .expect("query usage plan")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect usage plan");
        assert!(
            query_plan
                .iter()
                .any(|detail| detail.contains("run_terminal_completion_idx")),
            "terminal usage query did not use its completion index: {query_plan:?}"
        );

        let report = store
            .completed_usage_report(ownership, DAY_MS + 100, 3 * DAY_MS)
            .expect("usage report");
        assert_eq!(report.from_ms, DAY_MS + 100);
        assert_eq!(report.to_ms, 3 * DAY_MS);
        assert_eq!(report.buckets.len(), 2);
        let first = &report.buckets[0];
        assert_eq!(first.bucket_start_ms, DAY_MS);
        assert_eq!(first.bucket_end_ms, 2 * DAY_MS);
        assert_eq!(first.completed_runs, 2);
        assert_eq!(first.succeeded_runs, 1);
        assert_eq!(first.failed_runs, 1);
        assert_eq!(first.cancelled_runs, 0);
        assert_eq!(first.used_model_calls, 3);
        assert_eq!(first.used_tool_calls, 3);
        assert_eq!(first.used_delegated_runs, 1);
        assert_eq!(first.used_retries, 1);
        assert_eq!(first.used_input_tokens, 30);
        assert_eq!(first.used_output_tokens, 11);
        assert_eq!(first.used_cost_microunits, 300);
        assert_eq!(first.used_output_bytes, 110);
        assert_eq!(report.buckets[1].cancelled_runs, 1);
        assert_eq!(report.buckets[1].used_cost_microunits, 400);

        assert!(
            store
                .completed_usage_report(other, 3 * DAY_MS, 4 * DAY_MS)
                .expect("empty other-owner report")
                .buckets
                .is_empty()
        );
        assert!(matches!(
            store.completed_usage_report(ownership, 0, 32 * DAY_MS),
            Err(OperationalStoreError::InvalidContract(_))
        ));

        store
            .connection
            .execute(
                "UPDATE run_budget_usage SET reserved_model_calls = 1 \
                 WHERE run_id = 'run-day-two-root'",
                [],
            )
            .expect("tamper terminal reservation");
        assert!(matches!(
            store.completed_usage_report(ownership, 2 * DAY_MS, 3 * DAY_MS),
            Err(OperationalStoreError::InvariantViolation(_))
        ));
    }
}
