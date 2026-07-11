use super::{SqliteStore, agent};
use mealy_application::{
    CorrectMemoryCommit, DeleteMemoryCommit, ExpireMemoryCommit, MEMORY_POLICY_VERSION,
    MemoryIndexRebuildReceipt, MemoryRevisionView, MemorySearchHit, MemorySearchQuery,
    MemorySource, MemoryStore, MemoryStoreError, MemoryView, OwnershipContext, PromoteMemoryCommit,
    ProposeMemoryCommit, RejectMemoryCommit, SetMemoryPinCommit, is_sha256_digest, sha256_digest,
    validate_memory_proposal, validate_memory_search,
};
use mealy_domain::{
    CorrelationId, EventId, MemoryCategory, MemoryConfidence, MemoryId,
    MemoryPromotionAuthorization, MemoryRetention, MemoryRevisionId, MemorySensitivity,
    MemoryStatus, PrincipalId,
};
use rusqlite::{ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use std::{str::FromStr, time::SystemTime};

impl MemoryStore for SqliteStore {
    fn propose_memory(
        &mut self,
        commit: ProposeMemoryCommit,
    ) -> Result<MemoryView, MemoryStoreError> {
        validate_memory_proposal(&commit)?;
        let proposed_at_ms = epoch_milliseconds(commit.proposed_at)?;
        if commit.metadata.created_at_ms != proposed_at_ms
            || commit.metadata.last_verified_at_ms != proposed_at_ms
        {
            return Err(invalid_contract(
                "initial creation and verification times must equal the proposal time",
            ));
        }
        let content_digest = sha256_digest(commit.content.as_bytes());
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        authorize_workspace(
            &transaction,
            commit.ownership,
            &commit.metadata.namespace.workspace_identity,
        )?;
        append_memory_event(
            &transaction,
            commit.event_id,
            commit.memory_id,
            "memory.proposed",
            proposed_at_ms,
            commit.ownership.principal_id(),
            commit.correlation_id,
            &json!({
                "memory_id": commit.memory_id,
                "revision_id": commit.revision_id,
                "workspace_identity": commit.metadata.namespace.workspace_identity,
                "category": commit.metadata.category,
                "confidence_basis_points": commit.metadata.confidence.basis_points(),
                "sensitivity": commit.metadata.sensitivity,
                "retention": commit.metadata.retention,
                "content_digest": content_digest,
                "source_digests": commit.metadata.provenance.source_digests,
            }),
        )?;
        transaction
            .execute(
                "INSERT INTO memory(\
                    id, principal_id, workspace_identity, status, revision, category, \
                    confidence_basis_points, sensitivity, retention_class, \
                    proposed_by_principal_id, created_event_id, updated_event_id, \
                    created_at_ms, last_verified_at_ms\
                 ) VALUES (?1, ?2, ?3, 'proposed', 0, ?4, ?5, ?6, ?7, ?2, ?8, ?8, ?9, ?9)",
                params![
                    commit.memory_id.to_string(),
                    commit.ownership.principal_id().to_string(),
                    commit.metadata.namespace.workspace_identity,
                    category_text(commit.metadata.category),
                    i64::from(commit.metadata.confidence.basis_points()),
                    sensitivity_text(commit.metadata.sensitivity),
                    retention_text(commit.metadata.retention),
                    commit.event_id.to_string(),
                    proposed_at_ms,
                ],
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO memory_revision(\
                    id, memory_id, ordinal, status, content_text, content_digest, \
                    confidence_basis_points, sensitivity, retention_class, \
                    created_event_id, status_event_id, created_at_ms, last_verified_at_ms\
                 ) VALUES (?1, ?2, 1, 'proposed', ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?9)",
                params![
                    commit.revision_id.to_string(),
                    commit.memory_id.to_string(),
                    commit.content,
                    content_digest,
                    i64::from(commit.metadata.confidence.basis_points()),
                    sensitivity_text(commit.metadata.sensitivity),
                    retention_text(commit.metadata.retention),
                    commit.event_id.to_string(),
                    proposed_at_ms,
                ],
            )
            .map_err(map_sqlite_error)?;
        insert_sources(&transaction, commit.revision_id, &commit.sources)?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_memory_view(
            &self.connection,
            commit.ownership,
            &commit.metadata.namespace.workspace_identity,
            commit.memory_id,
        )
    }

    fn promote_memory(
        &mut self,
        commit: PromoteMemoryCommit,
    ) -> Result<MemoryView, MemoryStoreError> {
        let activated_at_ms = epoch_milliseconds(commit.activated_at)?;
        validate_authorization_pair(commit.authorization.as_ref(), commit.authorization_event_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let stored = load_revision_for_mutation(
            &transaction,
            commit.ownership,
            commit.memory_id,
            commit.revision_id,
        )?;
        if stored.memory_status != "proposed" || stored.revision_status != "proposed" {
            return Err(MemoryStoreError::Conflict);
        }
        validate_promotion_authorization(
            &stored.category,
            &stored.sensitivity,
            commit.authorization.as_ref(),
        )?;
        if let (Some(authorization), Some(event_id)) =
            (&commit.authorization, commit.authorization_event_id)
        {
            record_authorization(
                &transaction,
                commit.ownership,
                commit.memory_id,
                commit.revision_id,
                &stored.content_digest,
                authorization,
                event_id,
                commit.correlation_id,
                activated_at_ms,
            )?;
        }
        append_memory_event(
            &transaction,
            commit.activation_event_id,
            commit.memory_id,
            "memory.activated",
            activated_at_ms,
            commit.ownership.principal_id(),
            commit.correlation_id,
            &json!({
                "memory_id": commit.memory_id,
                "revision_id": commit.revision_id,
                "content_digest": stored.content_digest,
            }),
        )?;
        let revision_changed = transaction
            .execute(
                "UPDATE memory_revision SET status = 'active', status_event_id = ?1 \
                 WHERE id = ?2 AND memory_id = ?3 AND status = 'proposed'",
                params![
                    commit.activation_event_id.to_string(),
                    commit.revision_id.to_string(),
                    commit.memory_id.to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;
        let memory_changed = transaction
            .execute(
                "UPDATE memory SET status = 'active', revision = revision + 1, \
                    updated_event_id = ?1 \
                 WHERE id = ?2 AND principal_id = ?3 AND status = 'proposed'",
                params![
                    commit.activation_event_id.to_string(),
                    commit.memory_id.to_string(),
                    commit.ownership.principal_id().to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;
        if [revision_changed, memory_changed] != [1, 1] {
            return Err(MemoryStoreError::Conflict);
        }
        let workspace_identity = stored.workspace_identity;
        transaction.commit().map_err(map_sqlite_error)?;
        load_memory_view(
            &self.connection,
            commit.ownership,
            &workspace_identity,
            commit.memory_id,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn correct_memory(
        &mut self,
        commit: CorrectMemoryCommit,
    ) -> Result<MemoryView, MemoryStoreError> {
        validate_correction(&commit)?;
        let corrected_at_ms = epoch_milliseconds(commit.corrected_at)?;
        validate_authorization_pair(commit.authorization.as_ref(), commit.authorization_event_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let current = load_active_for_mutation(
            &transaction,
            commit.ownership,
            commit.memory_id,
            commit.expected_revision,
        )?;
        validate_promotion_authorization(
            &current.category,
            sensitivity_text(commit.sensitivity),
            commit.authorization.as_ref(),
        )?;
        let content_digest = sha256_digest(commit.content.as_bytes());
        append_memory_event(
            &transaction,
            commit.revision_event_id,
            commit.memory_id,
            "memory.revision_proposed",
            corrected_at_ms,
            commit.ownership.principal_id(),
            commit.correlation_id,
            &json!({
                "memory_id": commit.memory_id,
                "revision_id": commit.revision_id,
                "supersedes_revision_id": current.revision_id,
                "content_digest": content_digest,
            }),
        )?;
        transaction
            .execute(
                "INSERT INTO memory_revision(\
                    id, memory_id, ordinal, status, content_text, content_digest, \
                    confidence_basis_points, sensitivity, retention_class, \
                    supersedes_revision_id, created_event_id, status_event_id, created_at_ms, \
                    last_verified_at_ms\
                 ) VALUES (?1, ?2, ?3, 'proposed', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?11, ?11)",
                params![
                    commit.revision_id.to_string(),
                    commit.memory_id.to_string(),
                    current
                        .ordinal
                        .checked_add(1)
                        .ok_or_else(|| { invariant("memory revision ordinal overflowed") })?,
                    commit.content,
                    content_digest,
                    i64::from(commit.confidence.basis_points()),
                    sensitivity_text(commit.sensitivity),
                    retention_text(commit.retention),
                    current.revision_id.to_string(),
                    commit.revision_event_id.to_string(),
                    corrected_at_ms,
                ],
            )
            .map_err(map_sqlite_error)?;
        insert_sources(&transaction, commit.revision_id, &commit.sources)?;
        if let (Some(authorization), Some(event_id)) =
            (&commit.authorization, commit.authorization_event_id)
        {
            record_authorization(
                &transaction,
                commit.ownership,
                commit.memory_id,
                commit.revision_id,
                &content_digest,
                authorization,
                event_id,
                commit.correlation_id,
                corrected_at_ms,
            )?;
        }
        append_memory_event(
            &transaction,
            commit.corrected_event_id,
            commit.memory_id,
            "memory.corrected",
            corrected_at_ms,
            commit.ownership.principal_id(),
            commit.correlation_id,
            &json!({
                "memory_id": commit.memory_id,
                "revision_id": commit.revision_id,
                "superseded_revision_id": current.revision_id,
                "content_digest": content_digest,
            }),
        )?;
        let old_changed = transaction
            .execute(
                "UPDATE memory_revision SET status = 'superseded', status_event_id = ?1 \
                 WHERE id = ?2 AND memory_id = ?3 AND status = 'active'",
                params![
                    commit.corrected_event_id.to_string(),
                    current.revision_id.to_string(),
                    commit.memory_id.to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;
        let new_changed = transaction
            .execute(
                "UPDATE memory_revision SET status = 'active', status_event_id = ?1 \
                 WHERE id = ?2 AND memory_id = ?3 AND status = 'proposed'",
                params![
                    commit.corrected_event_id.to_string(),
                    commit.revision_id.to_string(),
                    commit.memory_id.to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;
        let memory_changed = transaction
            .execute(
                "UPDATE memory SET status = 'active', revision = revision + 1, \
                    confidence_basis_points = ?1, sensitivity = ?2, retention_class = ?3, \
                    last_verified_at_ms = ?4, updated_event_id = ?5 \
                 WHERE id = ?6 AND principal_id = ?7 AND status = 'active' AND revision = ?8",
                params![
                    i64::from(commit.confidence.basis_points()),
                    sensitivity_text(commit.sensitivity),
                    retention_text(commit.retention),
                    corrected_at_ms,
                    commit.corrected_event_id.to_string(),
                    commit.memory_id.to_string(),
                    commit.ownership.principal_id().to_string(),
                    to_i64(commit.expected_revision, "expected memory revision")?,
                ],
            )
            .map_err(map_sqlite_error)?;
        if [old_changed, new_changed, memory_changed] != [1, 1, 1] {
            return Err(MemoryStoreError::Conflict);
        }
        let workspace_identity = current.workspace_identity;
        transaction.commit().map_err(map_sqlite_error)?;
        load_memory_view(
            &self.connection,
            commit.ownership,
            &workspace_identity,
            commit.memory_id,
        )
    }

    fn set_memory_pin(
        &mut self,
        commit: SetMemoryPinCommit,
    ) -> Result<MemoryView, MemoryStoreError> {
        let updated_at_ms = epoch_milliseconds(commit.updated_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let current = load_active_for_mutation(
            &transaction,
            commit.ownership,
            commit.memory_id,
            commit.expected_revision,
        )?;
        let retention = if commit.pinned { "pinned" } else { "standard" };
        let event_type = if commit.pinned {
            "memory.pinned"
        } else {
            "memory.unpinned"
        };
        append_memory_event(
            &transaction,
            commit.event_id,
            commit.memory_id,
            event_type,
            updated_at_ms,
            commit.ownership.principal_id(),
            commit.correlation_id,
            &json!({"memory_id": commit.memory_id, "retention": retention}),
        )?;
        let changed = transaction
            .execute(
                "UPDATE memory SET revision = revision + 1, retention_class = ?1, \
                    updated_event_id = ?2 \
                 WHERE id = ?3 AND principal_id = ?4 AND status = 'active' AND revision = ?5",
                params![
                    retention,
                    commit.event_id.to_string(),
                    commit.memory_id.to_string(),
                    commit.ownership.principal_id().to_string(),
                    to_i64(commit.expected_revision, "expected memory revision")?,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(MemoryStoreError::Conflict);
        }
        let workspace_identity = current.workspace_identity;
        transaction.commit().map_err(map_sqlite_error)?;
        load_memory_view(
            &self.connection,
            commit.ownership,
            &workspace_identity,
            commit.memory_id,
        )
    }

    fn expire_memory(
        &mut self,
        commit: ExpireMemoryCommit,
    ) -> Result<MemoryView, MemoryStoreError> {
        let expired_at_ms = epoch_milliseconds(commit.expired_at)?;
        transition_out_of_retrieval(
            &mut self.connection,
            commit.ownership,
            commit.memory_id,
            commit.expected_revision,
            commit.event_id,
            commit.correlation_id,
            expired_at_ms,
            "expired",
            "memory.expired",
            false,
        )
    }

    fn reject_memory(
        &mut self,
        commit: RejectMemoryCommit,
    ) -> Result<MemoryView, MemoryStoreError> {
        let rejected_at_ms = epoch_milliseconds(commit.rejected_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let (workspace_identity, revision_id) = transaction
            .query_row(
                "SELECT owner.workspace_identity, revision.id FROM memory owner \
                 JOIN memory_revision revision \
                   ON revision.memory_id = owner.id AND revision.status = 'proposed' \
                 WHERE owner.id = ?1 AND owner.principal_id = ?2 \
                   AND owner.status = 'proposed' AND owner.revision = ?3 \
                   AND EXISTS(\
                       SELECT 1 FROM session owner_session \
                       JOIN context_epoch epoch ON epoch.session_id = owner_session.id \
                       WHERE owner_session.principal_id = owner.principal_id \
                         AND owner_session.channel_binding_id = ?4 \
                         AND epoch.workspace_identity = owner.workspace_identity\
                   )",
                params![
                    commit.memory_id.to_string(),
                    commit.ownership.principal_id().to_string(),
                    to_i64(commit.expected_revision, "expected memory revision")?,
                    commit.ownership.channel_binding_id().to_string(),
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(map_sqlite_error)?
            .ok_or(MemoryStoreError::NotFound)?;
        append_memory_event(
            &transaction,
            commit.event_id,
            commit.memory_id,
            "memory.rejected",
            rejected_at_ms,
            commit.ownership.principal_id(),
            commit.correlation_id,
            &json!({
                "memory_id": commit.memory_id,
                "revision_id": revision_id,
                "status": "rejected",
            }),
        )?;
        let revision_changed = transaction
            .execute(
                "UPDATE memory_revision SET status = 'rejected', status_event_id = ?1 \
                 WHERE id = ?2 AND memory_id = ?3 AND status = 'proposed'",
                params![
                    commit.event_id.to_string(),
                    revision_id,
                    commit.memory_id.to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;
        let memory_changed = transaction
            .execute(
                "UPDATE memory SET status = 'rejected', revision = revision + 1, \
                    updated_event_id = ?1 \
                 WHERE id = ?2 AND principal_id = ?3 AND status = 'proposed' AND revision = ?4",
                params![
                    commit.event_id.to_string(),
                    commit.memory_id.to_string(),
                    commit.ownership.principal_id().to_string(),
                    to_i64(commit.expected_revision, "expected memory revision")?,
                ],
            )
            .map_err(map_sqlite_error)?;
        if [revision_changed, memory_changed] != [1, 1] {
            return Err(MemoryStoreError::Conflict);
        }
        transaction.commit().map_err(map_sqlite_error)?;
        load_memory_view(
            &self.connection,
            commit.ownership,
            &workspace_identity,
            commit.memory_id,
        )
    }

    fn delete_memory(
        &mut self,
        commit: DeleteMemoryCommit,
    ) -> Result<MemoryView, MemoryStoreError> {
        let deleted_at_ms = epoch_milliseconds(commit.deleted_at)?;
        transition_out_of_retrieval(
            &mut self.connection,
            commit.ownership,
            commit.memory_id,
            commit.expected_revision,
            commit.event_id,
            commit.correlation_id,
            deleted_at_ms,
            "deleted",
            "memory.deleted",
            true,
        )
    }

    fn memory(
        &self,
        ownership: OwnershipContext,
        workspace_identity: &str,
        memory_id: MemoryId,
    ) -> Result<MemoryView, MemoryStoreError> {
        load_memory_view(&self.connection, ownership, workspace_identity, memory_id)
    }

    fn memories(
        &self,
        ownership: OwnershipContext,
        workspace_identity: &str,
        include_deleted: bool,
    ) -> Result<Vec<MemoryView>, MemoryStoreError> {
        authorize_workspace(&self.connection, ownership, workspace_identity)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT id FROM memory \
                 WHERE principal_id = ?1 AND workspace_identity = ?2 \
                   AND (?3 = 1 OR status <> 'deleted') \
                 ORDER BY created_at_ms, id",
            )
            .map_err(map_sqlite_error)?;
        let ids = statement
            .query_map(
                params![
                    ownership.principal_id().to_string(),
                    workspace_identity,
                    i64::from(include_deleted),
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(map_sqlite_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_sqlite_error)?;
        ids.into_iter()
            .map(|id| {
                load_memory_view(
                    &self.connection,
                    ownership,
                    workspace_identity,
                    parse_id(&id, "memory ID")?,
                )
            })
            .collect()
    }

    fn search_memories(
        &self,
        query: MemorySearchQuery,
    ) -> Result<Vec<MemorySearchHit>, MemoryStoreError> {
        validate_memory_search(&query)?;
        authorize_workspace(&self.connection, query.ownership, &query.workspace_identity)?;
        let maximum_sensitivity = sensitivity_rank(query.maximum_sensitivity);
        let degraded = self
            .connection
            .query_row(
                "SELECT lexical_status = 'degraded' FROM memory_index_state WHERE singleton = 1",
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(map_sqlite_error)?;
        let ranked = if query.query.trim().is_empty() {
            newest_filtered_memories(&self.connection, &query, maximum_sensitivity)?
        } else if degraded {
            fallback_filtered_memories(&self.connection, &query, maximum_sensitivity)?
        } else {
            lexical_filtered_memories(&self.connection, &query, maximum_sensitivity)?
        };
        ranked
            .into_iter()
            .map(|(memory_id, lexical_rank)| {
                Ok(MemorySearchHit {
                    memory: load_memory_view(
                        &self.connection,
                        query.ownership,
                        &query.workspace_identity,
                        memory_id,
                    )?,
                    lexical_rank,
                })
            })
            .collect()
    }

    fn rebuild_memory_index(
        &mut self,
        ownership: OwnershipContext,
        rebuilt_at: SystemTime,
    ) -> Result<MemoryIndexRebuildReceipt, MemoryStoreError> {
        let rebuilt_at_ms = epoch_milliseconds(rebuilt_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        authorize_principal_channel(&transaction, ownership)?;
        transaction
            .execute(
                "UPDATE memory_index_state SET lexical_status = 'rebuilding', last_error = NULL \
                 WHERE singleton = 1",
                [],
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "DELETE FROM memory_fts WHERE principal_id = ?1",
                [ownership.principal_id().to_string()],
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO memory_fts(\
                    memory_id, revision_id, principal_id, workspace_identity, content\
                 ) \
                 SELECT owner.id, revision.id, owner.principal_id, owner.workspace_identity, \
                        revision.content_text \
                 FROM memory owner \
                 JOIN memory_revision revision ON revision.memory_id = owner.id \
                 WHERE owner.principal_id = ?1 AND owner.status = 'active' \
                   AND revision.status = 'active' AND revision.content_text IS NOT NULL",
                [ownership.principal_id().to_string()],
            )
            .map_err(map_sqlite_error)?;
        let principal_count = transaction
            .query_row(
                "SELECT COUNT(*) FROM memory_fts WHERE principal_id = ?1",
                [ownership.principal_id().to_string()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "UPDATE memory_index_state SET lexical_status = 'healthy', \
                    indexed_revision_count = (SELECT COUNT(*) FROM memory_fts), \
                    last_rebuilt_at_ms = ?1, last_error = NULL \
                 WHERE singleton = 1",
                [rebuilt_at_ms],
            )
            .map_err(map_sqlite_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(MemoryIndexRebuildReceipt {
            indexed_revision_count: u64::try_from(principal_count)
                .map_err(|_| invariant("indexed revision count is negative"))?,
            rebuilt_at_ms,
        })
    }
}

#[derive(Debug)]
struct StoredRevisionMutation {
    workspace_identity: String,
    category: String,
    sensitivity: String,
    memory_status: String,
    revision_status: String,
    content_digest: String,
}

#[derive(Debug)]
struct StoredActiveMutation {
    workspace_identity: String,
    category: String,
    revision_id: MemoryRevisionId,
    ordinal: i64,
}

fn load_revision_for_mutation(
    transaction: &Transaction<'_>,
    ownership: OwnershipContext,
    memory_id: MemoryId,
    revision_id: MemoryRevisionId,
) -> Result<StoredRevisionMutation, MemoryStoreError> {
    transaction
        .query_row(
            "SELECT owner.workspace_identity, owner.category, revision.sensitivity, \
                    owner.status, revision.status, revision.content_digest \
             FROM memory owner \
             JOIN memory_revision revision ON revision.memory_id = owner.id \
             WHERE owner.id = ?1 AND revision.id = ?2 AND owner.principal_id = ?3 \
               AND EXISTS(\
                   SELECT 1 FROM session owner_session \
                   JOIN context_epoch epoch ON epoch.session_id = owner_session.id \
                   WHERE owner_session.principal_id = owner.principal_id \
                     AND owner_session.channel_binding_id = ?4 \
                     AND epoch.workspace_identity = owner.workspace_identity\
               )",
            params![
                memory_id.to_string(),
                revision_id.to_string(),
                ownership.principal_id().to_string(),
                ownership.channel_binding_id().to_string(),
            ],
            |row| {
                Ok(StoredRevisionMutation {
                    workspace_identity: row.get(0)?,
                    category: row.get(1)?,
                    sensitivity: row.get(2)?,
                    memory_status: row.get(3)?,
                    revision_status: row.get(4)?,
                    content_digest: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(MemoryStoreError::NotFound)
}

fn load_active_for_mutation(
    transaction: &Transaction<'_>,
    ownership: OwnershipContext,
    memory_id: MemoryId,
    expected_revision: u64,
) -> Result<StoredActiveMutation, MemoryStoreError> {
    transaction
        .query_row(
            "SELECT owner.workspace_identity, owner.category, revision.id, revision.ordinal \
             FROM memory owner \
             JOIN memory_revision revision \
               ON revision.memory_id = owner.id AND revision.status = 'active' \
             WHERE owner.id = ?1 AND owner.principal_id = ?2 AND owner.status = 'active' \
               AND owner.revision = ?3 \
               AND EXISTS(\
                   SELECT 1 FROM session owner_session \
                   JOIN context_epoch epoch ON epoch.session_id = owner_session.id \
                   WHERE owner_session.principal_id = owner.principal_id \
                     AND owner_session.channel_binding_id = ?4 \
                     AND epoch.workspace_identity = owner.workspace_identity\
               )",
            params![
                memory_id.to_string(),
                ownership.principal_id().to_string(),
                to_i64(expected_revision, "expected memory revision")?,
                ownership.channel_binding_id().to_string(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(MemoryStoreError::NotFound)
        .and_then(|(workspace_identity, category, revision_id, ordinal)| {
            Ok(StoredActiveMutation {
                workspace_identity,
                category,
                revision_id: parse_id(&revision_id, "memory revision ID")?,
                ordinal,
            })
        })
}

#[allow(clippy::too_many_arguments)]
fn transition_out_of_retrieval(
    connection: &mut rusqlite::Connection,
    ownership: OwnershipContext,
    memory_id: MemoryId,
    expected_revision: u64,
    event_id: EventId,
    correlation_id: CorrelationId,
    occurred_at_ms: i64,
    target_status: &str,
    event_type: &str,
    scrub: bool,
) -> Result<MemoryView, MemoryStoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sqlite_error)?;
    let workspace_identity = transaction
        .query_row(
            "SELECT owner.workspace_identity FROM memory owner \
             WHERE owner.id = ?1 AND owner.principal_id = ?2 AND owner.revision = ?3 \
               AND owner.status <> 'deleted' \
               AND EXISTS(\
                   SELECT 1 FROM session owner_session \
                   JOIN context_epoch epoch ON epoch.session_id = owner_session.id \
                   WHERE owner_session.principal_id = owner.principal_id \
                     AND owner_session.channel_binding_id = ?4 \
                     AND epoch.workspace_identity = owner.workspace_identity\
               )",
            params![
                memory_id.to_string(),
                ownership.principal_id().to_string(),
                to_i64(expected_revision, "expected memory revision")?,
                ownership.channel_binding_id().to_string(),
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(MemoryStoreError::NotFound)?;
    append_memory_event(
        &transaction,
        event_id,
        memory_id,
        event_type,
        occurred_at_ms,
        ownership.principal_id(),
        correlation_id,
        &json!({"memory_id": memory_id, "status": target_status}),
    )?;
    let revision_changed = if scrub {
        transaction
            .execute(
                "UPDATE memory_revision SET status = 'deleted', content_text = NULL, \
                    status_event_id = ?1, deleted_at_ms = ?2 \
                 WHERE memory_id = ?3 AND status <> 'deleted'",
                params![event_id.to_string(), occurred_at_ms, memory_id.to_string()],
            )
            .map_err(map_sqlite_error)?
    } else {
        transaction
            .execute(
                "UPDATE memory_revision SET status = 'expired', status_event_id = ?1 \
                 WHERE memory_id = ?2 AND status = 'active'",
                params![event_id.to_string(), memory_id.to_string()],
            )
            .map_err(map_sqlite_error)?
    };
    let memory_changed = transaction
        .execute(
            "UPDATE memory SET status = ?1, revision = revision + 1, updated_event_id = ?2, \
                deleted_at_ms = CASE WHEN ?1 = 'deleted' THEN ?3 ELSE NULL END \
             WHERE id = ?4 AND principal_id = ?5 AND revision = ?6 AND status <> 'deleted'",
            params![
                target_status,
                event_id.to_string(),
                occurred_at_ms,
                memory_id.to_string(),
                ownership.principal_id().to_string(),
                to_i64(expected_revision, "expected memory revision")?,
            ],
        )
        .map_err(map_sqlite_error)?;
    if revision_changed == 0 || memory_changed != 1 {
        return Err(MemoryStoreError::Conflict);
    }
    transaction.commit().map_err(map_sqlite_error)?;
    load_memory_view(connection, ownership, &workspace_identity, memory_id)
}

#[allow(clippy::too_many_arguments)]
fn record_authorization(
    transaction: &Transaction<'_>,
    ownership: OwnershipContext,
    memory_id: MemoryId,
    revision_id: MemoryRevisionId,
    subject_digest: &str,
    authorization: &MemoryPromotionAuthorization,
    event_id: EventId,
    correlation_id: CorrelationId,
    authorized_at_ms: i64,
) -> Result<(), MemoryStoreError> {
    let (kind, authorization_id, policy_version) = match authorization {
        MemoryPromotionAuthorization::OwnerPolicy { policy_version } => {
            ("owner_policy", None, policy_version.as_str())
        }
        MemoryPromotionAuthorization::Approval { approval_id } => (
            "owner_approval",
            Some(approval_id.to_string()),
            MEMORY_POLICY_VERSION,
        ),
    };
    if policy_version != MEMORY_POLICY_VERSION {
        return Err(MemoryStoreError::PolicyDenied);
    }
    append_memory_event(
        transaction,
        event_id,
        memory_id,
        "memory.promotion_authorized",
        authorized_at_ms,
        ownership.principal_id(),
        correlation_id,
        &json!({
            "memory_id": memory_id,
            "revision_id": revision_id,
            "authorization_kind": kind,
            "authorization_id": authorization_id,
            "subject_digest": subject_digest,
            "policy_version": policy_version,
        }),
    )?;
    transaction
        .execute(
            "INSERT INTO memory_promotion_authorization(\
                revision_id, memory_id, authorization_kind, authorization_id, subject_digest, \
                policy_version, actor_principal_id, event_id, authorized_at_ms\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                revision_id.to_string(),
                memory_id.to_string(),
                kind,
                authorization_id,
                subject_digest,
                policy_version,
                ownership.principal_id().to_string(),
                event_id.to_string(),
                authorized_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn insert_sources(
    transaction: &Transaction<'_>,
    revision_id: MemoryRevisionId,
    sources: &[MemorySource],
) -> Result<(), MemoryStoreError> {
    for (index, source) in sources.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO memory_source(revision_id, ordinal, source_locator, source_digest) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    revision_id.to_string(),
                    i64::try_from(index)
                        .ok()
                        .and_then(|value| value.checked_add(1))
                        .ok_or_else(|| invariant("memory source ordinal overflowed"))?,
                    source.locator,
                    source.digest,
                ],
            )
            .map_err(map_sqlite_error)?;
    }
    Ok(())
}

fn validate_correction(commit: &CorrectMemoryCommit) -> Result<(), MemoryStoreError> {
    if commit.content.is_empty()
        || commit.content.len() > 65_536
        || commit.content.contains('\0')
        || commit.sources.is_empty()
        || commit.sources.len() > 64
    {
        return Err(invalid_contract(
            "corrected memory content or sources are invalid",
        ));
    }
    let mut locators = std::collections::BTreeSet::new();
    if commit.sources.iter().any(|source| {
        source.locator.is_empty()
            || source.locator.len() > 4_096
            || source.locator.trim() != source.locator
            || source.locator.chars().any(char::is_control)
            || !is_sha256_digest(&source.digest)
            || !locators.insert(source.locator.as_str())
    }) {
        return Err(invalid_contract("corrected memory provenance is invalid"));
    }
    Ok(())
}

fn validate_authorization_pair(
    authorization: Option<&MemoryPromotionAuthorization>,
    event_id: Option<EventId>,
) -> Result<(), MemoryStoreError> {
    if authorization.is_some() != event_id.is_some() {
        return Err(invalid_contract(
            "memory promotion authorization and event must be supplied together",
        ));
    }
    Ok(())
}

fn validate_promotion_authorization(
    category: &str,
    sensitivity: &str,
    authorization: Option<&MemoryPromotionAuthorization>,
) -> Result<(), MemoryStoreError> {
    let sensitive = matches!(
        category,
        "identity" | "credential" | "health" | "financial" | "third_party_private"
    ) || sensitivity == "restricted";
    if sensitive && authorization.is_none() {
        return Err(MemoryStoreError::PolicyDenied);
    }
    if let Some(MemoryPromotionAuthorization::OwnerPolicy { policy_version }) = authorization
        && policy_version != MEMORY_POLICY_VERSION
    {
        return Err(MemoryStoreError::PolicyDenied);
    }
    Ok(())
}

fn load_memory_view(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
    workspace_identity: &str,
    memory_id: MemoryId,
) -> Result<MemoryView, MemoryStoreError> {
    authorize_workspace(connection, ownership, workspace_identity)?;
    let stored = connection
        .query_row(
            "SELECT principal_id, workspace_identity, status, revision, category, \
                    confidence_basis_points, sensitivity, retention_class, created_at_ms, \
                    last_verified_at_ms \
             FROM memory \
             WHERE id = ?1 AND principal_id = ?2 AND workspace_identity = ?3",
            params![
                memory_id.to_string(),
                ownership.principal_id().to_string(),
                workspace_identity,
            ],
            |row| {
                Ok(StoredMemoryView {
                    principal_id: row.get(0)?,
                    workspace_identity: row.get(1)?,
                    status: row.get(2)?,
                    revision: row.get(3)?,
                    category: row.get(4)?,
                    confidence: row.get(5)?,
                    sensitivity: row.get(6)?,
                    retention: row.get(7)?,
                    created_at_ms: row.get(8)?,
                    last_verified_at_ms: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(MemoryStoreError::NotFound)?;
    let revisions = load_revisions(connection, memory_id)?;
    let view = MemoryView {
        memory_id,
        principal_id: parse_id(&stored.principal_id, "memory principal ID")?,
        workspace_identity: stored.workspace_identity,
        status: parse_status(&stored.status)?,
        revision: nonnegative(stored.revision, "memory revision")?,
        category: parse_category(&stored.category)?,
        confidence: parse_confidence(stored.confidence)?,
        sensitivity: parse_sensitivity(&stored.sensitivity)?,
        retention: parse_retention(&stored.retention)?,
        created_at_ms: stored.created_at_ms,
        last_verified_at_ms: stored.last_verified_at_ms,
        revisions,
    };
    validate_view(&view)?;
    Ok(view)
}

struct StoredMemoryView {
    principal_id: String,
    workspace_identity: String,
    status: String,
    revision: i64,
    category: String,
    confidence: i64,
    sensitivity: String,
    retention: String,
    created_at_ms: i64,
    last_verified_at_ms: i64,
}

#[allow(clippy::too_many_lines)]
fn load_revisions(
    connection: &rusqlite::Connection,
    memory_id: MemoryId,
) -> Result<Vec<MemoryRevisionView>, MemoryStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT id, ordinal, status, content_text, content_digest, confidence_basis_points, \
                    sensitivity, retention_class, supersedes_revision_id, created_at_ms, \
                    last_verified_at_ms \
             FROM memory_revision WHERE memory_id = ?1 ORDER BY ordinal",
        )
        .map_err(map_sqlite_error)?;
    let rows = statement
        .query_map([memory_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, i64>(10)?,
            ))
        })
        .map_err(map_sqlite_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_sqlite_error)?;
    rows.into_iter()
        .map(
            |(
                id,
                ordinal,
                status,
                content,
                content_digest,
                confidence,
                sensitivity,
                retention,
                supersedes,
                created_at_ms,
                last_verified_at_ms,
            )| {
                let revision_id = parse_id(&id, "memory revision ID")?;
                let sources = load_sources(connection, revision_id)?;
                Ok(MemoryRevisionView {
                    revision_id,
                    ordinal: nonnegative(ordinal, "memory revision ordinal")?,
                    status: parse_status(&status)?,
                    content,
                    content_digest,
                    confidence: parse_confidence(confidence)?,
                    sensitivity: parse_sensitivity(&sensitivity)?,
                    retention: parse_retention(&retention)?,
                    supersedes_revision_id: supersedes
                        .as_deref()
                        .map(|value| parse_id(value, "superseded memory revision ID"))
                        .transpose()?,
                    sources,
                    created_at_ms,
                    last_verified_at_ms,
                })
            },
        )
        .collect()
}

fn load_sources(
    connection: &rusqlite::Connection,
    revision_id: MemoryRevisionId,
) -> Result<Vec<MemorySource>, MemoryStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT source_locator, source_digest FROM memory_source \
             WHERE revision_id = ?1 ORDER BY ordinal",
        )
        .map_err(map_sqlite_error)?;
    statement
        .query_map([revision_id.to_string()], |row| {
            Ok(MemorySource {
                locator: row.get(0)?,
                digest: row.get(1)?,
            })
        })
        .map_err(map_sqlite_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_sqlite_error)
}

fn validate_view(view: &MemoryView) -> Result<(), MemoryStoreError> {
    if view.created_at_ms < 0
        || view.last_verified_at_ms < view.created_at_ms
        || view.revisions.is_empty()
    {
        return Err(invariant(
            "stored memory timestamps or revision history are invalid",
        ));
    }
    let mut active = 0;
    for (index, revision) in view.revisions.iter().enumerate() {
        if revision.ordinal
            != u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| invariant("memory revision order overflowed"))?
            || !is_sha256_digest(&revision.content_digest)
            || revision.sources.is_empty()
            || revision
                .sources
                .iter()
                .any(|source| !is_sha256_digest(&source.digest))
            || revision
                .content
                .as_deref()
                .is_some_and(|content| sha256_digest(content.as_bytes()) != revision.content_digest)
            || (revision.status == MemoryStatus::Deleted) != revision.content.is_none()
        {
            return Err(invariant("stored memory revision evidence is inconsistent"));
        }
        active += usize::from(revision.status == MemoryStatus::Active);
    }
    if active > 1 || (view.status == MemoryStatus::Active && active != 1) {
        return Err(invariant("logical memory and active revision diverged"));
    }
    Ok(())
}

fn newest_filtered_memories(
    connection: &rusqlite::Connection,
    query: &MemorySearchQuery,
    maximum_sensitivity: i64,
) -> Result<Vec<(MemoryId, f64)>, MemoryStoreError> {
    filtered_query(
        connection,
        "SELECT owner.id, 0.0 FROM memory owner \
         WHERE owner.principal_id = ?1 AND owner.workspace_identity = ?2 \
           AND owner.status = 'active' \
           AND CASE owner.sensitivity \
               WHEN 'public' THEN 0 WHEN 'internal' THEN 1 \
               WHEN 'private' THEN 2 ELSE 3 END <= ?3 \
         ORDER BY owner.last_verified_at_ms DESC, owner.id LIMIT ?4",
        query,
        maximum_sensitivity,
        None,
    )
}

fn fallback_filtered_memories(
    connection: &rusqlite::Connection,
    query: &MemorySearchQuery,
    maximum_sensitivity: i64,
) -> Result<Vec<(MemoryId, f64)>, MemoryStoreError> {
    let pattern = format!("%{}%", escape_like(query.query.trim()));
    filtered_query(
        connection,
        "SELECT owner.id, 0.0 FROM memory owner \
         JOIN memory_revision revision \
           ON revision.memory_id = owner.id AND revision.status = 'active' \
         WHERE owner.principal_id = ?1 AND owner.workspace_identity = ?2 \
           AND owner.status = 'active' \
           AND CASE owner.sensitivity \
               WHEN 'public' THEN 0 WHEN 'internal' THEN 1 \
               WHEN 'private' THEN 2 ELSE 3 END <= ?3 \
           AND revision.content_text LIKE ?5 ESCAPE '\\' \
         ORDER BY owner.last_verified_at_ms DESC, owner.id LIMIT ?4",
        query,
        maximum_sensitivity,
        Some(pattern),
    )
}

fn lexical_filtered_memories(
    connection: &rusqlite::Connection,
    query: &MemorySearchQuery,
    maximum_sensitivity: i64,
) -> Result<Vec<(MemoryId, f64)>, MemoryStoreError> {
    let fts_query = query
        .query
        .split_whitespace()
        .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" AND ");
    filtered_query(
        connection,
        "SELECT owner.id, bm25(memory_fts) FROM memory_fts \
         JOIN memory owner ON owner.id = memory_fts.memory_id \
         JOIN memory_revision revision ON revision.id = memory_fts.revision_id \
         WHERE memory_fts MATCH ?5 \
           AND memory_fts.principal_id = ?1 AND memory_fts.workspace_identity = ?2 \
           AND owner.principal_id = ?1 AND owner.workspace_identity = ?2 \
           AND owner.status = 'active' AND revision.status = 'active' \
           AND CASE owner.sensitivity \
               WHEN 'public' THEN 0 WHEN 'internal' THEN 1 \
               WHEN 'private' THEN 2 ELSE 3 END <= ?3 \
         ORDER BY bm25(memory_fts), owner.last_verified_at_ms DESC, owner.id LIMIT ?4",
        query,
        maximum_sensitivity,
        Some(fts_query),
    )
}

fn filtered_query(
    connection: &rusqlite::Connection,
    sql: &str,
    query: &MemorySearchQuery,
    maximum_sensitivity: i64,
    lexical_query: Option<String>,
) -> Result<Vec<(MemoryId, f64)>, MemoryStoreError> {
    let limit =
        i64::try_from(query.limit).map_err(|_| invalid_contract("search limit overflow"))?;
    let mut statement = connection.prepare(sql).map_err(map_sqlite_error)?;
    let rows = if let Some(lexical_query) = lexical_query {
        statement
            .query_map(
                params![
                    query.ownership.principal_id().to_string(),
                    query.workspace_identity,
                    maximum_sensitivity,
                    limit,
                    lexical_query,
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?)),
            )
            .map_err(map_sqlite_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_sqlite_error)?
    } else {
        statement
            .query_map(
                params![
                    query.ownership.principal_id().to_string(),
                    query.workspace_identity,
                    maximum_sensitivity,
                    limit,
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?)),
            )
            .map_err(map_sqlite_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_sqlite_error)?
    };
    rows.into_iter()
        .map(|(id, rank)| Ok((parse_id(&id, "memory ID")?, rank)))
        .collect()
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn authorize_workspace(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
    workspace_identity: &str,
) -> Result<(), MemoryStoreError> {
    let authorized = connection
        .query_row(
            "SELECT EXISTS(\
                SELECT 1 FROM session owner_session \
                JOIN context_epoch epoch ON epoch.session_id = owner_session.id \
                WHERE owner_session.principal_id = ?1 \
                  AND owner_session.channel_binding_id = ?2 \
                  AND epoch.workspace_identity = ?3\
             )",
            params![
                ownership.principal_id().to_string(),
                ownership.channel_binding_id().to_string(),
                workspace_identity,
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(map_sqlite_error)?;
    if authorized {
        Ok(())
    } else {
        Err(MemoryStoreError::NotFound)
    }
}

fn authorize_principal_channel(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
) -> Result<(), MemoryStoreError> {
    let authorized = connection
        .query_row(
            "SELECT EXISTS(\
                SELECT 1 FROM session WHERE principal_id = ?1 AND channel_binding_id = ?2\
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
        Err(MemoryStoreError::NotFound)
    }
}

#[allow(clippy::too_many_arguments)]
fn append_memory_event(
    transaction: &Transaction<'_>,
    event_id: EventId,
    memory_id: MemoryId,
    event_type: &str,
    occurred_at_ms: i64,
    actor_principal_id: PrincipalId,
    correlation_id: CorrelationId,
    payload: &serde_json::Value,
) -> Result<(), MemoryStoreError> {
    let sequence = agent::next_sequence(transaction, "memory", &memory_id.to_string())
        .map_err(map_agent_error)?;
    transaction
        .execute(
            "INSERT INTO journal_event(\
                event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                event_version, occurred_at_ms, actor_principal_id, correlation_id, sensitivity, \
                payload_json\
             ) VALUES (?1, 'memory', ?2, ?3, ?4, 1, ?5, ?6, ?7, 'private', ?8)",
            params![
                event_id.to_string(),
                memory_id.to_string(),
                sequence,
                event_type,
                occurred_at_ms,
                actor_principal_id.to_string(),
                correlation_id.to_string(),
                payload.to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO aggregate_sequence(aggregate_kind, aggregate_id, sequence) \
             VALUES ('memory', ?1, ?2) ON CONFLICT(aggregate_kind, aggregate_id) \
             DO UPDATE SET sequence = excluded.sequence",
            params![memory_id.to_string(), sequence],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn category_text(value: MemoryCategory) -> &'static str {
    match value {
        MemoryCategory::Preference => "preference",
        MemoryCategory::Fact => "fact",
        MemoryCategory::Goal => "goal",
        MemoryCategory::Decision => "decision",
        MemoryCategory::Constraint => "constraint",
        MemoryCategory::Identity => "identity",
        MemoryCategory::Credential => "credential",
        MemoryCategory::Health => "health",
        MemoryCategory::Financial => "financial",
        MemoryCategory::ThirdPartyPrivate => "third_party_private",
    }
}

fn parse_category(value: &str) -> Result<MemoryCategory, MemoryStoreError> {
    match value {
        "preference" => Ok(MemoryCategory::Preference),
        "fact" => Ok(MemoryCategory::Fact),
        "goal" => Ok(MemoryCategory::Goal),
        "decision" => Ok(MemoryCategory::Decision),
        "constraint" => Ok(MemoryCategory::Constraint),
        "identity" => Ok(MemoryCategory::Identity),
        "credential" => Ok(MemoryCategory::Credential),
        "health" => Ok(MemoryCategory::Health),
        "financial" => Ok(MemoryCategory::Financial),
        "third_party_private" => Ok(MemoryCategory::ThirdPartyPrivate),
        _ => Err(invariant("stored memory category is invalid")),
    }
}

fn sensitivity_text(value: MemorySensitivity) -> &'static str {
    match value {
        MemorySensitivity::Public => "public",
        MemorySensitivity::Internal => "internal",
        MemorySensitivity::Private => "private",
        MemorySensitivity::Restricted => "restricted",
    }
}

fn parse_sensitivity(value: &str) -> Result<MemorySensitivity, MemoryStoreError> {
    match value {
        "public" => Ok(MemorySensitivity::Public),
        "internal" => Ok(MemorySensitivity::Internal),
        "private" => Ok(MemorySensitivity::Private),
        "restricted" => Ok(MemorySensitivity::Restricted),
        _ => Err(invariant("stored memory sensitivity is invalid")),
    }
}

fn sensitivity_rank(value: MemorySensitivity) -> i64 {
    match value {
        MemorySensitivity::Public => 0,
        MemorySensitivity::Internal => 1,
        MemorySensitivity::Private => 2,
        MemorySensitivity::Restricted => 3,
    }
}

fn retention_text(value: MemoryRetention) -> &'static str {
    match value {
        MemoryRetention::Session => "session",
        MemoryRetention::Standard => "standard",
        MemoryRetention::Pinned => "pinned",
        MemoryRetention::PolicyHold => "policy_hold",
    }
}

fn parse_retention(value: &str) -> Result<MemoryRetention, MemoryStoreError> {
    match value {
        "session" => Ok(MemoryRetention::Session),
        "standard" => Ok(MemoryRetention::Standard),
        "pinned" => Ok(MemoryRetention::Pinned),
        "policy_hold" => Ok(MemoryRetention::PolicyHold),
        _ => Err(invariant("stored memory retention is invalid")),
    }
}

fn parse_status(value: &str) -> Result<MemoryStatus, MemoryStoreError> {
    match value {
        "proposed" => Ok(MemoryStatus::Proposed),
        "active" => Ok(MemoryStatus::Active),
        "superseded" => Ok(MemoryStatus::Superseded),
        "expired" => Ok(MemoryStatus::Expired),
        "rejected" => Ok(MemoryStatus::Rejected),
        "deleted" => Ok(MemoryStatus::Deleted),
        _ => Err(invariant("stored memory status is invalid")),
    }
}

fn parse_confidence(value: i64) -> Result<MemoryConfidence, MemoryStoreError> {
    let value = u16::try_from(value).map_err(|_| invariant("memory confidence is negative"))?;
    MemoryConfidence::new(value).map_err(|error| invariant(error.to_string()))
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, MemoryStoreError> {
    agent::epoch_milliseconds(time).map_err(map_agent_error)
}

fn to_i64(value: u64, field: &str) -> Result<i64, MemoryStoreError> {
    i64::try_from(value).map_err(|_| invalid_contract(format!("{field} exceeds SQLite range")))
}

fn nonnegative(value: i64, field: &str) -> Result<u64, MemoryStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("stored {field} is negative")))
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, MemoryStoreError> {
    value
        .parse()
        .map_err(|_| invariant(format!("stored {field} is invalid")))
}

fn map_agent_error(error: mealy_application::AgentStoreError) -> MemoryStoreError {
    match error {
        mealy_application::AgentStoreError::Conflict => MemoryStoreError::Conflict,
        mealy_application::AgentStoreError::Unavailable(message) => {
            MemoryStoreError::Unavailable(message)
        }
        other => MemoryStoreError::InvariantViolation(other.to_string()),
    }
}

fn map_sqlite_error(error: rusqlite::Error) -> MemoryStoreError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation =>
        {
            MemoryStoreError::Conflict
        }
        other => MemoryStoreError::Unavailable(other.to_string()),
    }
}

fn invalid_contract(message: impl Into<String>) -> MemoryStoreError {
    MemoryStoreError::InvalidContract(message.into())
}

fn invariant(message: impl Into<String>) -> MemoryStoreError {
    MemoryStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::SqliteStore;
    use mealy_application::{
        CorrectMemoryCommit, DeleteMemoryCommit, MEMORY_POLICY_VERSION, MemorySearchQuery,
        MemorySource, MemoryStore, MemoryStoreError, OwnershipContext, PromoteMemoryCommit,
        ProposeMemoryCommit, SetMemoryPinCommit,
    };
    use mealy_domain::{
        ChannelBindingId, ContextEpochId, CorrelationId, EventId, MemoryCategory, MemoryConfidence,
        MemoryId, MemoryMetadata, MemoryNamespace, MemoryPromotionAuthorization, MemoryProvenance,
        MemoryRetention, MemoryRevisionId, MemorySensitivity, MemoryStatus, PrincipalId, SessionId,
    };
    use rusqlite::params;
    use std::{collections::BTreeSet, time::Duration};

    const NOW: i64 = 1_783_123_200_000;
    const WORKSPACE: &str = "workspace-phase5";

    struct Fixture {
        store: SqliteStore,
        ownership: OwnershipContext,
        other_ownership: OwnershipContext,
    }

    impl Fixture {
        fn new() -> Self {
            let store = SqliteStore::open_in_memory(NOW).expect("open Phase 5 store");
            let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
            let other_ownership =
                OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
            seed_workspace(&store, ownership, WORKSPACE, "owner");
            seed_workspace(&store, other_ownership, WORKSPACE, "other");
            Self {
                store,
                ownership,
                other_ownership,
            }
        }

        fn proposal(
            &self,
            category: MemoryCategory,
            sensitivity: MemorySensitivity,
            content: &str,
            at_ms: i64,
        ) -> ProposeMemoryCommit {
            let source = MemorySource {
                locator: format!("event://source-{at_ms}"),
                digest: "a".repeat(64),
            };
            ProposeMemoryCommit {
                ownership: self.ownership,
                memory_id: MemoryId::new(),
                revision_id: MemoryRevisionId::new(),
                content: content.to_owned(),
                metadata: MemoryMetadata {
                    namespace: MemoryNamespace {
                        principal_id: self.ownership.principal_id(),
                        workspace_identity: WORKSPACE.to_owned(),
                    },
                    category,
                    provenance: MemoryProvenance {
                        proposed_by_principal_id: self.ownership.principal_id(),
                        source_locators: BTreeSet::from([source.locator.clone()]),
                        source_digests: BTreeSet::from([source.digest.clone()]),
                    },
                    confidence: MemoryConfidence::new(8_000).expect("confidence"),
                    sensitivity,
                    retention: MemoryRetention::Standard,
                    created_at_ms: at_ms,
                    last_verified_at_ms: at_ms,
                },
                sources: vec![source],
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                proposed_at: at(at_ms),
            }
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn lifecycle_is_namespaced_searchable_correctable_pinnable_and_scrubbable() {
        let mut fixture = Fixture::new();
        let proposal = fixture.proposal(
            MemoryCategory::Fact,
            MemorySensitivity::Internal,
            "The deployment window is Tuesday",
            NOW + 1,
        );
        let memory_id = proposal.memory_id;
        let first_revision_id = proposal.revision_id;
        let proposed = fixture
            .store
            .propose_memory(proposal)
            .expect("propose governed memory");
        assert_eq!(proposed.status, MemoryStatus::Proposed);
        assert!(
            fixture
                .store
                .search_memories(search(fixture.ownership, "deployment"))
                .expect("search proposed")
                .is_empty()
        );

        let active = fixture
            .store
            .promote_memory(PromoteMemoryCommit {
                ownership: fixture.ownership,
                memory_id,
                revision_id: first_revision_id,
                authorization: None,
                authorization_event_id: None,
                activation_event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                activated_at: at(NOW + 2),
            })
            .expect("activate ordinary memory");
        assert_eq!(active.status, MemoryStatus::Active);
        assert_eq!(active.revision, 1);
        let hits = fixture
            .store
            .search_memories(search(fixture.ownership, "deployment"))
            .expect("lexical memory search");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].memory.memory_id, memory_id);
        assert_eq!(hits[0].memory.revisions[0].sources.len(), 1);

        assert_eq!(
            fixture
                .store
                .memory(fixture.other_ownership, WORKSPACE, memory_id),
            Err(MemoryStoreError::NotFound)
        );
        assert!(
            fixture
                .store
                .search_memories(search(fixture.other_ownership, "deployment"))
                .expect("cross-principal search fails closed")
                .is_empty()
        );

        let replacement_id = MemoryRevisionId::new();
        let corrected = fixture
            .store
            .correct_memory(CorrectMemoryCommit {
                ownership: fixture.ownership,
                memory_id,
                expected_revision: 1,
                revision_id: replacement_id,
                content: "The deployment window is Wednesday".to_owned(),
                confidence: MemoryConfidence::new(9_000).expect("confidence"),
                sensitivity: MemorySensitivity::Internal,
                retention: MemoryRetention::Standard,
                sources: vec![MemorySource {
                    locator: "event://source-correction".to_owned(),
                    digest: "b".repeat(64),
                }],
                authorization: None,
                revision_event_id: EventId::new(),
                authorization_event_id: None,
                corrected_event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                corrected_at: at(NOW + 3),
            })
            .expect("correct memory atomically");
        assert_eq!(corrected.revision, 2);
        assert_eq!(corrected.revisions.len(), 2);
        assert_eq!(corrected.revisions[0].status, MemoryStatus::Superseded);
        assert_eq!(corrected.revisions[1].status, MemoryStatus::Active);
        assert_eq!(
            corrected.revisions[1].supersedes_revision_id,
            Some(first_revision_id)
        );
        assert!(
            fixture
                .store
                .search_memories(search(fixture.ownership, "Tuesday"))
                .expect("old revision removed from FTS")
                .is_empty()
        );
        assert_eq!(
            fixture
                .store
                .search_memories(search(fixture.ownership, "Wednesday"))
                .expect("replacement indexed")
                .len(),
            1
        );

        let pinned = fixture
            .store
            .set_memory_pin(SetMemoryPinCommit {
                ownership: fixture.ownership,
                memory_id,
                expected_revision: 2,
                pinned: true,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                updated_at: at(NOW + 4),
            })
            .expect("pin memory");
        assert_eq!(pinned.retention, MemoryRetention::Pinned);
        assert_eq!(pinned.revision, 3);

        fixture
            .store
            .connection
            .execute(
                "UPDATE memory_index_state SET lexical_status = 'degraded', \
                    last_error = 'simulated derived index failure' WHERE singleton = 1",
                [],
            )
            .expect("mark derived index degraded");
        assert_eq!(
            fixture
                .store
                .search_memories(search(fixture.ownership, "Wednesday"))
                .expect("canonical lexical fallback")
                .len(),
            1
        );
        let rebuilt = fixture
            .store
            .rebuild_memory_index(fixture.ownership, at(NOW + 5))
            .expect("rebuild owner lexical index");
        assert_eq!(rebuilt.indexed_revision_count, 1);

        let deleted = fixture
            .store
            .delete_memory(DeleteMemoryCommit {
                ownership: fixture.ownership,
                memory_id,
                expected_revision: 3,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                deleted_at: at(NOW + 6),
            })
            .expect("delete memory content");
        assert_eq!(deleted.status, MemoryStatus::Deleted);
        assert!(
            deleted
                .revisions
                .iter()
                .all(|revision| revision.content.is_none())
        );
        assert!(
            deleted
                .revisions
                .iter()
                .all(|revision| !revision.sources.is_empty())
        );
        assert!(
            fixture
                .store
                .search_memories(search(fixture.ownership, "Wednesday"))
                .expect("deleted memory removed from retrieval")
                .is_empty()
        );
        assert_eq!(
            fixture
                .store
                .memories(fixture.ownership, WORKSPACE, true)
                .expect("export tombstones")
                .len(),
            1
        );
    }

    #[test]
    fn sensitive_memory_requires_exact_owner_policy_evidence() {
        let mut fixture = Fixture::new();
        let proposal = fixture.proposal(
            MemoryCategory::Health,
            MemorySensitivity::Restricted,
            "Owner-provided health accommodation",
            NOW + 10,
        );
        let memory_id = proposal.memory_id;
        let revision_id = proposal.revision_id;
        fixture
            .store
            .propose_memory(proposal)
            .expect("propose sensitive memory");
        assert_eq!(
            fixture.store.promote_memory(PromoteMemoryCommit {
                ownership: fixture.ownership,
                memory_id,
                revision_id,
                authorization: None,
                authorization_event_id: None,
                activation_event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                activated_at: at(NOW + 11),
            }),
            Err(MemoryStoreError::PolicyDenied)
        );
        let active = fixture
            .store
            .promote_memory(PromoteMemoryCommit {
                ownership: fixture.ownership,
                memory_id,
                revision_id,
                authorization: Some(MemoryPromotionAuthorization::OwnerPolicy {
                    policy_version: MEMORY_POLICY_VERSION.to_owned(),
                }),
                authorization_event_id: Some(EventId::new()),
                activation_event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                activated_at: at(NOW + 12),
            })
            .expect("owner policy authorizes exact sensitive revision");
        assert_eq!(active.status, MemoryStatus::Active);
    }

    fn search(ownership: OwnershipContext, query: &str) -> MemorySearchQuery {
        MemorySearchQuery {
            ownership,
            workspace_identity: WORKSPACE.to_owned(),
            query: query.to_owned(),
            maximum_sensitivity: MemorySensitivity::Restricted,
            limit: 20,
        }
    }

    fn seed_workspace(
        store: &SqliteStore,
        ownership: OwnershipContext,
        workspace_identity: &str,
        suffix: &str,
    ) {
        let session_id = SessionId::new();
        let epoch_id = ContextEpochId::new();
        store
            .connection
            .execute(
                "INSERT INTO session(\
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?4)",
                params![
                    session_id.to_string(),
                    ownership.principal_id().to_string(),
                    ownership.channel_binding_id().to_string(),
                    NOW,
                ],
            )
            .expect("seed owner session");
        store
            .connection
            .execute(
                "INSERT INTO context_epoch(\
                    id, session_id, epoch_number, baseline_version, baseline_digest, \
                    baseline_text, agent_profile_json, workspace_identity, config_digest, \
                    policy_digest, created_at_ms\
                 ) VALUES (?1, ?2, 1, ?3, ?4, 'baseline', '{}', ?5, ?4, ?4, ?6)",
                params![
                    epoch_id.to_string(),
                    session_id.to_string(),
                    format!("baseline-{suffix}"),
                    "c".repeat(64),
                    workspace_identity,
                    NOW,
                ],
            )
            .expect("seed workspace epoch");
        store
            .connection
            .execute(
                "UPDATE session SET current_context_epoch_id = ?1 WHERE id = ?2",
                params![epoch_id.to_string(), session_id.to_string()],
            )
            .expect("activate workspace epoch");
    }

    fn at(milliseconds: i64) -> std::time::SystemTime {
        std::time::UNIX_EPOCH
            + Duration::from_millis(u64::try_from(milliseconds).expect("positive test time"))
    }
}
