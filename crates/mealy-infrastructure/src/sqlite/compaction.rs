use super::{SqliteStore, agent};
use mealy_application::{
    CommitCompaction, CompactionSourceEvent, CompactionSourceSnapshot, CompactionStore,
    CompactionStoreError, CompactionView, OwnershipContext, TimelineCursor, TimelineQuery,
    TimelineStore, compaction_citations, compaction_source_event_digest, sha256_digest,
    validate_compaction_commit,
};
use mealy_domain::{
    CompactionCarryForward, CompactionId, CompactionRecord, CompactionSourceRange, CorrelationId,
    EventId, PrincipalId, SessionId,
};
use rusqlite::{ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use std::{collections::BTreeMap, str::FromStr};

const MAXIMUM_SOURCE_EVENTS: u64 = 1_000;

impl CompactionStore for SqliteStore {
    fn compaction_source_snapshot(
        &self,
        ownership: OwnershipContext,
        session_id: SessionId,
        first_cursor: TimelineCursor,
        last_cursor: TimelineCursor,
    ) -> Result<CompactionSourceSnapshot, CompactionStoreError> {
        if first_cursor.0 == 0 || first_cursor > last_cursor {
            return Err(CompactionStoreError::InvalidSourceRange);
        }
        let span = last_cursor
            .0
            .checked_sub(first_cursor.0)
            .and_then(|value| value.checked_add(1))
            .ok_or(CompactionStoreError::InvalidSourceRange)?;
        if span > MAXIMUM_SOURCE_EVENTS {
            return Err(CompactionStoreError::InvalidSourceRange);
        }
        let workspace_identity = authorized_workspace(&self.connection, ownership, session_id)?;
        let page = self
            .timeline_page(TimelineQuery {
                session_id,
                ownership,
                after: Some(TimelineCursor(first_cursor.0 - 1)),
                limit: usize::try_from(span)
                    .map_err(|_| CompactionStoreError::InvalidSourceRange)?,
            })
            .map_err(map_timeline_error)?;
        let events = page
            .events
            .into_iter()
            .take_while(|event| event.cursor <= last_cursor)
            .map(|event| {
                Ok(CompactionSourceEvent {
                    event_digest: compaction_source_event_digest(&event)?,
                    event,
                })
            })
            .collect::<Result<Vec<_>, CompactionStoreError>>()?;
        if events.first().map(|event| event.event.cursor) != Some(first_cursor)
            || events.last().map(|event| event.event.cursor) != Some(last_cursor)
        {
            return Err(CompactionStoreError::InvalidSourceRange);
        }
        Ok(CompactionSourceSnapshot {
            session_id,
            workspace_identity,
            first_cursor,
            last_cursor,
            events,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn commit_compaction(
        &mut self,
        commit: CommitCompaction,
    ) -> Result<CompactionView, CompactionStoreError> {
        validate_compaction_commit(&commit)?;
        let snapshot = self.compaction_source_snapshot(
            commit.ownership,
            commit.session_id,
            TimelineCursor(commit.record.source_range.first_cursor),
            TimelineCursor(commit.record.source_range.last_cursor),
        )?;
        validate_snapshot_citations(&commit.record, &snapshot)?;
        validate_required_carry_forward(
            &self.connection,
            commit.session_id,
            &commit.record,
            &snapshot,
        )?;
        let created_at_ms = epoch_milliseconds(commit.created_at)?;
        let first_event_id = snapshot
            .events
            .first()
            .map(|event| event.event.event_id)
            .ok_or(CompactionStoreError::InvalidSourceRange)?;
        let last_event_id = snapshot
            .events
            .last()
            .map(|event| event.event.event_id)
            .ok_or(CompactionStoreError::InvalidSourceRange)?;
        let carry_forward_json = serde_json::to_string(&commit.record.carry_forward)
            .map_err(|error| invalid_contract(error.to_string()))?;
        let carry_forward_digest = sha256_digest(carry_forward_json.as_bytes());
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let principal_id = authorized_session(&transaction, commit.ownership, commit.session_id)?;
        insert_compaction_artifact(&transaction, &commit, principal_id, created_at_ms)?;
        append_compaction_event(
            &transaction,
            commit.event_id,
            commit.record.compaction_id,
            created_at_ms,
            principal_id,
            commit.correlation_id,
            &json!({
                "compaction_id": commit.record.compaction_id,
                "session_id": commit.session_id,
                "artifact_id": commit.record.artifact_id,
                "artifact_digest": commit.record.artifact_digest,
                "source_first_cursor": commit.record.source_range.first_cursor,
                "source_last_cursor": commit.record.source_range.last_cursor,
                "prompt_version": commit.record.prompt_version,
                "config_digest": commit.record.config_digest,
                "carry_forward_digest": carry_forward_digest,
            }),
        )?;
        transaction
            .execute(
                "INSERT INTO session_compaction(\
                    id, principal_id, session_id, artifact_id, source_first_cursor, \
                    source_last_cursor, source_first_event_id, source_last_event_id, \
                    prompt_version, config_digest, artifact_digest, summary_text, \
                    carry_forward_json, carry_forward_digest, event_id, created_at_ms\
                 ) VALUES (\
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16\
                 )",
                params![
                    commit.record.compaction_id.to_string(),
                    principal_id.to_string(),
                    commit.session_id.to_string(),
                    commit.record.artifact_id.to_string(),
                    to_i64(
                        commit.record.source_range.first_cursor,
                        "first compaction cursor"
                    )?,
                    to_i64(
                        commit.record.source_range.last_cursor,
                        "last compaction cursor"
                    )?,
                    first_event_id.to_string(),
                    last_event_id.to_string(),
                    commit.record.prompt_version,
                    commit.record.config_digest,
                    commit.record.artifact_digest,
                    commit.summary_text,
                    carry_forward_json,
                    carry_forward_digest,
                    commit.event_id.to_string(),
                    created_at_ms,
                ],
            )
            .map_err(map_sqlite_error)?;
        insert_compaction_citations(&transaction, &commit.record)?;
        transaction
            .execute(
                "INSERT INTO artifact_reference(\
                    artifact_id, principal_id, session_id, owner_kind, owner_id, relation, \
                    created_at_ms\
                 ) VALUES (?1, ?2, ?3, 'compaction', ?4, 'derived_summary', ?5)",
                params![
                    commit.record.artifact_id.to_string(),
                    principal_id.to_string(),
                    commit.session_id.to_string(),
                    commit.record.compaction_id.to_string(),
                    created_at_ms,
                ],
            )
            .map_err(map_sqlite_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_compaction(
            &self.connection,
            commit.ownership,
            commit.record.compaction_id,
        )
    }

    fn compaction(
        &self,
        ownership: OwnershipContext,
        compaction_id: CompactionId,
    ) -> Result<CompactionView, CompactionStoreError> {
        load_compaction(&self.connection, ownership, compaction_id)
    }

    fn latest_compaction(
        &self,
        ownership: OwnershipContext,
        session_id: SessionId,
    ) -> Result<Option<CompactionView>, CompactionStoreError> {
        authorized_session(&self.connection, ownership, session_id)?;
        let id = self
            .connection
            .query_row(
                "SELECT id FROM session_compaction \
                 WHERE session_id = ?1 AND principal_id = ?2 \
                 ORDER BY source_last_cursor DESC, created_at_ms DESC, id DESC LIMIT 1",
                params![session_id.to_string(), ownership.principal_id().to_string(),],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(map_sqlite_error)?;
        id.map(|id| load_compaction(&self.connection, ownership, parse_id(&id, "compaction ID")?))
            .transpose()
    }
}

fn validate_snapshot_citations(
    record: &CompactionRecord,
    snapshot: &CompactionSourceSnapshot,
) -> Result<(), CompactionStoreError> {
    let canonical = snapshot
        .events
        .iter()
        .map(|source| {
            (
                (source.event.event_id, source.event.cursor.0),
                source.event_digest.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if compaction_citations(record).iter().any(|(_, _, citation)| {
        canonical
            .get(&(citation.event_id, citation.cursor))
            .is_none_or(|digest| *digest != citation.event_digest)
    }) {
        return Err(invalid_contract(
            "compaction citation does not match the authorized canonical source event",
        ));
    }
    Ok(())
}

fn validate_required_carry_forward(
    connection: &rusqlite::Connection,
    session_id: SessionId,
    record: &CompactionRecord,
    snapshot: &CompactionSourceSnapshot,
) -> Result<(), CompactionStoreError> {
    if record.carry_forward.current_goals.is_empty()
        || record.carry_forward.safety_constraints.is_empty()
    {
        return Err(invalid_contract(
            "compaction must retain typed current goals and safety constraints",
        ));
    }
    let pending = load_pending_approvals(connection, session_id, record.source_range)?;
    if pending.len() != record.carry_forward.unresolved_approvals.len()
        || pending.iter().any(|(approval_id, subject_digest)| {
            record
                .carry_forward
                .unresolved_approvals
                .iter()
                .find(|approval| approval.approval_id.to_string() == *approval_id)
                .is_none_or(|approval| {
                    approval.subject_digest != *subject_digest
                        || !citations_bind_aggregate(
                            snapshot,
                            &approval.citations,
                            "approval",
                            approval_id,
                        )
                })
        })
    {
        return Err(invalid_contract(
            "compaction unresolved approvals diverge from canonical pending subjects",
        ));
    }
    let effects = load_effect_outcomes(connection, session_id, record.source_range)?;
    if effects.len() != record.carry_forward.effect_outcomes.len()
        || effects.iter().any(|(effect_id, status)| {
            record
                .carry_forward
                .effect_outcomes
                .iter()
                .find(|effect| effect.effect_id.to_string() == *effect_id)
                .is_none_or(|effect| {
                    effect_status_text(effect.status) != status
                        || !citations_bind_aggregate(
                            snapshot,
                            &effect.citations,
                            "effect",
                            effect_id,
                        )
                })
        })
    {
        return Err(invalid_contract(
            "compaction effect outcomes diverge from canonical external state",
        ));
    }
    Ok(())
}

fn load_pending_approvals(
    connection: &rusqlite::Connection,
    session_id: SessionId,
    range: CompactionSourceRange,
) -> Result<Vec<(String, String)>, CompactionStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT approval.approval_id, approval.subject_digest, timeline.cursor \
             FROM approval_request approval \
             JOIN effect_intent intent ON intent.effect_id = approval.effect_id \
             JOIN timeline_event timeline ON timeline.event_id = approval.requested_event_id \
             WHERE intent.session_id = ?1 AND approval.status = 'pending' \
               AND timeline.cursor <= ?2 \
             ORDER BY approval.approval_id",
        )
        .map_err(map_sqlite_error)?;
    let rows = statement
        .query_map(
            params![
                session_id.to_string(),
                to_i64(range.last_cursor, "last compaction cursor")?,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(map_sqlite_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_sqlite_error)?;
    if rows.iter().any(|(_, _, cursor)| {
        u64::try_from(*cursor).map_or(true, |cursor| cursor < range.first_cursor)
    }) {
        return Err(CompactionStoreError::InvalidSourceRange);
    }
    Ok(rows
        .into_iter()
        .map(|(approval_id, digest, _)| (approval_id, digest))
        .collect())
}

fn load_effect_outcomes(
    connection: &rusqlite::Connection,
    session_id: SessionId,
    range: CompactionSourceRange,
) -> Result<Vec<(String, String)>, CompactionStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT effect.id, effect.status, MAX(timeline.cursor) \
             FROM effect \
             JOIN effect_intent intent ON intent.effect_id = effect.id \
             JOIN journal_event event \
               ON event.aggregate_kind = 'effect' AND event.aggregate_id = effect.id \
             JOIN timeline_event timeline ON timeline.event_id = event.event_id \
             WHERE intent.session_id = ?1 \
               AND effect.status IN (\
                   'dispatching', 'succeeded', 'failed', 'outcome_unknown', 'compensated', 'denied'\
               ) \
             GROUP BY effect.id, effect.status \
             HAVING MAX(timeline.cursor) <= ?2 \
             ORDER BY effect.id",
        )
        .map_err(map_sqlite_error)?;
    let rows = statement
        .query_map(
            params![
                session_id.to_string(),
                to_i64(range.last_cursor, "last compaction cursor")?,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(map_sqlite_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_sqlite_error)?;
    if rows.iter().any(|(_, _, cursor)| {
        u64::try_from(*cursor).map_or(true, |cursor| cursor < range.first_cursor)
    }) {
        return Err(CompactionStoreError::InvalidSourceRange);
    }
    Ok(rows
        .into_iter()
        .map(|(effect_id, status, _)| (effect_id, status))
        .collect())
}

fn citations_bind_aggregate(
    snapshot: &CompactionSourceSnapshot,
    citations: &[mealy_domain::CompactionCitation],
    aggregate_kind: &str,
    aggregate_id: &str,
) -> bool {
    citations.iter().any(|citation| {
        snapshot.events.iter().any(|source| {
            source.event.event_id == citation.event_id
                && source.event.cursor.0 == citation.cursor
                && source.event.aggregate_kind == aggregate_kind
                && source.event.aggregate_id == aggregate_id
        })
    })
}

const fn effect_status_text(status: mealy_domain::EffectStatus) -> &'static str {
    match status {
        mealy_domain::EffectStatus::Proposed => "proposed",
        mealy_domain::EffectStatus::AwaitingApproval => "awaiting_approval",
        mealy_domain::EffectStatus::Authorized => "authorized",
        mealy_domain::EffectStatus::Dispatching => "dispatching",
        mealy_domain::EffectStatus::Succeeded => "succeeded",
        mealy_domain::EffectStatus::Failed => "failed",
        mealy_domain::EffectStatus::OutcomeUnknown => "outcome_unknown",
        mealy_domain::EffectStatus::Compensated => "compensated",
        mealy_domain::EffectStatus::Denied => "denied",
    }
}

fn insert_compaction_artifact(
    transaction: &Transaction<'_>,
    commit: &CommitCompaction,
    principal_id: PrincipalId,
    created_at_ms: i64,
) -> Result<(), CompactionStoreError> {
    transaction
        .execute(
            "INSERT INTO artifact_blob(algorithm, digest, size_bytes, relative_path, committed_at_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT(algorithm, digest) DO NOTHING",
            params![
                commit.artifact_blob.algorithm,
                commit.artifact_blob.digest,
                to_i64(commit.artifact_blob.size_bytes, "compaction artifact size")?,
                commit.artifact_blob.relative_path,
                created_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    let blob_matches = transaction
        .query_row(
            "SELECT size_bytes = ?1 AND relative_path = ?2 \
             FROM artifact_blob WHERE algorithm = ?3 AND digest = ?4",
            params![
                to_i64(commit.artifact_blob.size_bytes, "compaction artifact size")?,
                commit.artifact_blob.relative_path,
                commit.artifact_blob.algorithm,
                commit.artifact_blob.digest,
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(map_sqlite_error)?;
    if !blob_matches {
        return Err(invariant(
            "compaction artifact metadata conflicts with its content address",
        ));
    }
    let access_policy = json!({
        "principalId": principal_id.to_string(),
        "sessionId": commit.session_id.to_string(),
    })
    .to_string();
    transaction
        .execute(
            "INSERT INTO artifact(\
                id, blob_algorithm, blob_digest, principal_id, session_id, media_type, \
                origin_kind, origin_id, producer_kind, producer_id, sensitivity, \
                retention_class, access_policy_json, access_policy_digest, created_at_ms\
             ) VALUES (\
                ?1, ?2, ?3, ?4, ?5, 'text/markdown', 'compaction', ?6, 'builtin', \
                'mealyd.phase5', 'private', 'session_history', ?7, ?8, ?9\
             )",
            params![
                commit.record.artifact_id.to_string(),
                commit.artifact_blob.algorithm,
                commit.artifact_blob.digest,
                principal_id.to_string(),
                commit.session_id.to_string(),
                commit.record.compaction_id.to_string(),
                access_policy,
                sha256_digest(access_policy.as_bytes()),
                created_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn insert_compaction_citations(
    transaction: &Transaction<'_>,
    record: &CompactionRecord,
) -> Result<(), CompactionStoreError> {
    let mut ordinals = BTreeMap::<(&str, String), i64>::new();
    for (kind, item_key, citation) in compaction_citations(record) {
        let ordinal = ordinals.entry((kind, item_key.clone())).or_insert(0);
        *ordinal = ordinal
            .checked_add(1)
            .ok_or_else(|| invariant("compaction citation ordinal overflowed"))?;
        transaction
            .execute(
                "INSERT INTO session_compaction_citation(\
                    compaction_id, item_kind, item_key, citation_ordinal, event_id, cursor, \
                    event_digest\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    record.compaction_id.to_string(),
                    kind,
                    item_key,
                    *ordinal,
                    citation.event_id.to_string(),
                    to_i64(citation.cursor, "compaction citation cursor")?,
                    citation.event_digest,
                ],
            )
            .map_err(map_sqlite_error)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn load_compaction(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
    compaction_id: CompactionId,
) -> Result<CompactionView, CompactionStoreError> {
    let row = connection
        .query_row(
            "SELECT compaction.artifact_id, compaction.source_first_cursor, \
                    compaction.source_last_cursor, compaction.prompt_version, \
                    compaction.config_digest, compaction.artifact_digest, \
                    compaction.summary_text, compaction.carry_forward_json, \
                    compaction.carry_forward_digest, compaction.event_id, artifact.blob_digest, \
                    blob.size_bytes, timeline.cursor \
             FROM session_compaction compaction \
             JOIN session owner_session ON owner_session.id = compaction.session_id \
             JOIN artifact ON artifact.id = compaction.artifact_id \
             JOIN artifact_blob blob \
               ON blob.algorithm = artifact.blob_algorithm AND blob.digest = artifact.blob_digest \
             JOIN timeline_event timeline ON timeline.event_id = compaction.event_id \
             WHERE compaction.id = ?1 AND compaction.principal_id = ?2 \
               AND owner_session.principal_id = ?2 AND owner_session.channel_binding_id = ?3",
            params![
                compaction_id.to_string(),
                ownership.principal_id().to_string(),
                ownership.channel_binding_id().to_string(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(CompactionStoreError::NotFound)?;
    let carry_forward = serde_json::from_str::<CompactionCarryForward>(&row.7)
        .map_err(|error| invariant(error.to_string()))?;
    if serde_json::to_string(&carry_forward).map_err(|error| invariant(error.to_string()))? != row.7
        || sha256_digest(row.7.as_bytes()) != row.8
        || row.5 != row.10
        || sha256_digest(row.6.as_bytes()) != row.5
        || usize::try_from(row.11).ok() != Some(row.6.len())
    {
        return Err(invariant(
            "stored compaction artifact or typed carry-forward digest diverged",
        ));
    }
    let record = CompactionRecord {
        compaction_id,
        artifact_id: parse_id(&row.0, "compaction artifact ID")?,
        source_range: CompactionSourceRange {
            first_cursor: nonnegative(row.1, "first compaction cursor")?,
            last_cursor: nonnegative(row.2, "last compaction cursor")?,
        },
        prompt_version: row.3,
        config_digest: row.4,
        artifact_digest: row.5,
        carry_forward,
    };
    record
        .validate()
        .map_err(|error| invariant(error.to_string()))?;
    validate_stored_citations(connection, &record)?;
    Ok(CompactionView {
        record,
        summary_text: row.6,
        cursor: TimelineCursor(nonnegative(row.12, "compaction event cursor")?),
    })
}

fn validate_stored_citations(
    connection: &rusqlite::Connection,
    record: &CompactionRecord,
) -> Result<(), CompactionStoreError> {
    let mut expected = compaction_citations(record)
        .into_iter()
        .map(|(kind, key, citation)| {
            (
                kind.to_owned(),
                key,
                citation.event_id.to_string(),
                citation.cursor,
                citation.event_digest.clone(),
            )
        })
        .collect::<Vec<_>>();
    expected.sort();
    let mut statement = connection
        .prepare(
            "SELECT item_kind, item_key, event_id, cursor, event_digest \
             FROM session_compaction_citation WHERE compaction_id = ?1 \
             ORDER BY item_kind, item_key, event_id, cursor, event_digest",
        )
        .map_err(map_sqlite_error)?;
    let stored = statement
        .query_map([record.compaction_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(map_sqlite_error)?
        .map(|row| {
            let (kind, key, event_id, cursor, digest) = row.map_err(map_sqlite_error)?;
            Ok((
                kind,
                key,
                event_id,
                nonnegative(cursor, "compaction citation cursor")?,
                digest,
            ))
        })
        .collect::<Result<Vec<_>, CompactionStoreError>>()?;
    if stored != expected {
        return Err(invariant(
            "stored compaction citation rows diverge from typed carry-forward",
        ));
    }
    Ok(())
}

fn authorized_workspace(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
    session_id: SessionId,
) -> Result<String, CompactionStoreError> {
    connection
        .query_row(
            "SELECT epoch.workspace_identity FROM session owner_session \
             JOIN context_epoch epoch ON epoch.id = owner_session.current_context_epoch_id \
             WHERE owner_session.id = ?1 AND owner_session.principal_id = ?2 \
               AND owner_session.channel_binding_id = ?3",
            params![
                session_id.to_string(),
                ownership.principal_id().to_string(),
                ownership.channel_binding_id().to_string(),
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(CompactionStoreError::NotFound)
}

fn authorized_session(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
    session_id: SessionId,
) -> Result<PrincipalId, CompactionStoreError> {
    connection
        .query_row(
            "SELECT principal_id FROM session \
             WHERE id = ?1 AND principal_id = ?2 AND channel_binding_id = ?3",
            params![
                session_id.to_string(),
                ownership.principal_id().to_string(),
                ownership.channel_binding_id().to_string(),
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(CompactionStoreError::NotFound)
        .and_then(|value| parse_id(&value, "compaction principal ID"))
}

#[allow(clippy::too_many_arguments)]
fn append_compaction_event(
    transaction: &Transaction<'_>,
    event_id: EventId,
    compaction_id: CompactionId,
    occurred_at_ms: i64,
    actor_principal_id: PrincipalId,
    correlation_id: CorrelationId,
    payload: &serde_json::Value,
) -> Result<(), CompactionStoreError> {
    let sequence = agent::next_sequence(transaction, "compaction", &compaction_id.to_string())
        .map_err(map_agent_error)?;
    transaction
        .execute(
            "INSERT INTO journal_event(\
                event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                event_version, occurred_at_ms, actor_principal_id, correlation_id, sensitivity, \
                payload_json\
             ) VALUES (?1, 'compaction', ?2, ?3, 'context.compacted', 1, ?4, ?5, ?6, \
                       'private', ?7)",
            params![
                event_id.to_string(),
                compaction_id.to_string(),
                sequence,
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
             VALUES ('compaction', ?1, ?2) ON CONFLICT(aggregate_kind, aggregate_id) \
             DO UPDATE SET sequence = excluded.sequence",
            params![compaction_id.to_string(), sequence],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn map_timeline_error(error: mealy_application::TimelineStoreError) -> CompactionStoreError {
    match error {
        mealy_application::TimelineStoreError::SessionNotFound
        | mealy_application::TimelineStoreError::Unauthorized => CompactionStoreError::NotFound,
        mealy_application::TimelineStoreError::Gap { .. }
        | mealy_application::TimelineStoreError::CursorAhead => {
            CompactionStoreError::InvalidSourceRange
        }
        mealy_application::TimelineStoreError::Unavailable(message) => {
            CompactionStoreError::Unavailable(message)
        }
        mealy_application::TimelineStoreError::InvariantViolation(message) => {
            CompactionStoreError::InvariantViolation(message)
        }
    }
}

fn epoch_milliseconds(time: std::time::SystemTime) -> Result<i64, CompactionStoreError> {
    agent::epoch_milliseconds(time).map_err(map_agent_error)
}

fn map_agent_error(error: mealy_application::AgentStoreError) -> CompactionStoreError {
    match error {
        mealy_application::AgentStoreError::Conflict => CompactionStoreError::Conflict,
        mealy_application::AgentStoreError::Unavailable(message) => {
            CompactionStoreError::Unavailable(message)
        }
        other => CompactionStoreError::InvariantViolation(other.to_string()),
    }
}

fn map_sqlite_error(error: rusqlite::Error) -> CompactionStoreError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation =>
        {
            CompactionStoreError::Conflict
        }
        other => CompactionStoreError::Unavailable(other.to_string()),
    }
}

fn to_i64(value: u64, field: &str) -> Result<i64, CompactionStoreError> {
    i64::try_from(value).map_err(|_| invalid_contract(format!("{field} exceeds SQLite range")))
}

fn nonnegative(value: i64, field: &str) -> Result<u64, CompactionStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("stored {field} is negative")))
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, CompactionStoreError> {
    value
        .parse()
        .map_err(|_| invariant(format!("stored {field} is invalid")))
}

fn invalid_contract(message: impl Into<String>) -> CompactionStoreError {
    CompactionStoreError::InvalidContract(message.into())
}

fn invariant(message: impl Into<String>) -> CompactionStoreError {
    CompactionStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::SqliteStore;
    use mealy_application::{
        COMPACTION_PROMPT_VERSION, CommitCompaction, CommittedArtifactBlob, CompactionStore,
        CompactionStoreError, OwnershipContext, TimelineCursor, sha256_digest,
    };
    use mealy_domain::{
        ArtifactId, ChannelBindingId, CitedCompactionItem, CompactionCarryForward,
        CompactionCitation, CompactionId, CompactionRecord, CompactionSourceRange, ContextEpochId,
        CorrelationId, EventId, PrincipalId, SessionId,
    };
    use rusqlite::params;
    use std::time::Duration;

    const NOW: i64 = 1_783_209_600_000;

    struct Fixture {
        store: SqliteStore,
        ownership: OwnershipContext,
        other_ownership: OwnershipContext,
        session_id: SessionId,
        source_event_ids: [EventId; 2],
        source_cursors: [u64; 2],
    }

    impl Fixture {
        fn new() -> Self {
            let store = SqliteStore::open_in_memory(NOW).expect("open compaction store");
            let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
            let other_ownership =
                OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
            let session_id = seed_session(&store, ownership, "workspace-compaction", "owner");
            let _other_session =
                seed_session(&store, other_ownership, "workspace-compaction", "other");
            let source_event_ids = [EventId::new(), EventId::new()];
            for (sequence, event_id) in source_event_ids.iter().enumerate() {
                store
                    .connection
                    .execute(
                        "INSERT INTO journal_event(\
                            event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                            event_version, occurred_at_ms, actor_principal_id, correlation_id, \
                            sensitivity, payload_json\
                         ) VALUES (?1, 'session', ?2, ?3, ?4, 1, ?5, ?6, ?7, 'private', ?8)",
                        params![
                            event_id.to_string(),
                            session_id.to_string(),
                            i64::try_from(sequence).expect("sequence"),
                            if sequence == 0 {
                                "session.goal_recorded"
                            } else {
                                "session.constraint_recorded"
                            },
                            NOW + i64::try_from(sequence).expect("time") + 1,
                            ownership.principal_id().to_string(),
                            CorrelationId::new().to_string(),
                            serde_json::json!({
                                "session_id": session_id,
                                "sequence": sequence,
                            })
                            .to_string(),
                        ],
                    )
                    .expect("seed canonical source event");
            }
            store
                .connection
                .execute(
                    "INSERT INTO aggregate_sequence(aggregate_kind, aggregate_id, sequence) \
                     VALUES ('session', ?1, 1)",
                    [session_id.to_string()],
                )
                .expect("seed session sequence");
            let source_cursors = source_event_ids.map(|event_id| {
                u64::try_from(
                    store
                        .connection
                        .query_row(
                            "SELECT cursor FROM timeline_event WHERE event_id = ?1",
                            [event_id.to_string()],
                            |row| row.get::<_, i64>(0),
                        )
                        .expect("load source cursor"),
                )
                .expect("positive cursor")
            });
            Self {
                store,
                ownership,
                other_ownership,
                session_id,
                source_event_ids,
                source_cursors,
            }
        }

        fn commit(&self) -> CommitCompaction {
            let snapshot = self
                .store
                .compaction_source_snapshot(
                    self.ownership,
                    self.session_id,
                    TimelineCursor(self.source_cursors[0]),
                    TimelineCursor(self.source_cursors[1]),
                )
                .expect("authorized source snapshot");
            let citations = [
                CompactionCitation {
                    event_id: self.source_event_ids[0],
                    cursor: self.source_cursors[0],
                    event_digest: snapshot.events[0].event_digest.clone(),
                },
                CompactionCitation {
                    event_id: self.source_event_ids[1],
                    cursor: self.source_cursors[1],
                    event_digest: snapshot.events[1].event_digest.clone(),
                },
            ];
            let summary = "# Compaction\n\nGoal and safety state remain cited.".to_owned();
            let digest = sha256_digest(summary.as_bytes());
            CommitCompaction {
                ownership: self.ownership,
                session_id: self.session_id,
                record: CompactionRecord {
                    compaction_id: CompactionId::new(),
                    artifact_id: ArtifactId::new(),
                    source_range: CompactionSourceRange {
                        first_cursor: self.source_cursors[0],
                        last_cursor: self.source_cursors[1],
                    },
                    prompt_version: COMPACTION_PROMPT_VERSION.to_owned(),
                    config_digest: "d".repeat(64),
                    artifact_digest: digest.clone(),
                    carry_forward: CompactionCarryForward {
                        current_goals: vec![CitedCompactionItem {
                            item_key: "goal:finish".to_owned(),
                            text: "Finish the durable build".to_owned(),
                            citations: vec![citations[0].clone()],
                        }],
                        safety_constraints: vec![CitedCompactionItem {
                            item_key: "constraint:owner".to_owned(),
                            text: "Preserve owner and workspace boundaries".to_owned(),
                            citations: vec![citations[1].clone()],
                        }],
                        ..CompactionCarryForward::default()
                    },
                },
                summary_text: summary.clone(),
                artifact_blob: CommittedArtifactBlob::new_sha256(
                    digest,
                    u64::try_from(summary.len()).expect("summary length"),
                )
                .expect("artifact blob"),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at: at(NOW + 10),
            }
        }
    }

    #[test]
    fn compaction_is_a_cited_immutable_artifact_and_preserves_source_history() {
        let mut fixture = Fixture::new();
        let source_count_before = fixture.store.journal_count().expect("source count");
        let commit = fixture.commit();
        let compaction_id = commit.record.compaction_id;
        let view = fixture
            .store
            .commit_compaction(commit)
            .expect("commit cited compaction");
        assert_eq!(view.record.compaction_id, compaction_id);
        assert_eq!(view.record.carry_forward.current_goals.len(), 1);
        assert!(view.record.carry_forward.unresolved_approvals.is_empty());
        assert!(view.record.carry_forward.effect_outcomes.is_empty());
        assert_eq!(
            fixture
                .store
                .journal_count()
                .expect("post-compaction count"),
            source_count_before + 1
        );
        for event_id in fixture.source_event_ids {
            let preserved: bool = fixture
                .store
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM journal_event WHERE event_id = ?1)",
                    [event_id.to_string()],
                    |row| row.get(0),
                )
                .expect("source history query");
            assert!(preserved);
        }
        assert_eq!(
            fixture
                .store
                .compaction(fixture.other_ownership, compaction_id),
            Err(CompactionStoreError::NotFound)
        );
        assert_eq!(
            fixture
                .store
                .latest_compaction(fixture.ownership, fixture.session_id)
                .expect("latest compaction")
                .expect("compaction exists")
                .record
                .compaction_id,
            compaction_id
        );
        assert!(
            fixture
                .store
                .connection
                .execute(
                    "DELETE FROM session_compaction WHERE id = ?1",
                    [compaction_id.to_string()],
                )
                .is_err()
        );
    }

    #[test]
    fn citation_digest_must_match_the_authorized_canonical_event() {
        let mut fixture = Fixture::new();
        let mut commit = fixture.commit();
        commit.record.carry_forward.current_goals[0].citations[0].event_digest = "f".repeat(64);
        assert!(matches!(
            fixture.store.commit_compaction(commit),
            Err(CompactionStoreError::InvalidContract(_))
        ));
        assert_eq!(fixture.store.journal_count().expect("journal unchanged"), 2);
    }

    #[test]
    fn compaction_cannot_omit_typed_goals_or_safety_constraints() {
        for omit_goals in [true, false] {
            let mut fixture = Fixture::new();
            let mut commit = fixture.commit();
            if omit_goals {
                commit.record.carry_forward.current_goals.clear();
            } else {
                commit.record.carry_forward.safety_constraints.clear();
            }
            assert!(matches!(
                fixture.store.commit_compaction(commit),
                Err(CompactionStoreError::InvalidContract(_))
            ));
            assert_eq!(fixture.store.journal_count().expect("journal unchanged"), 2);
        }
    }

    fn seed_session(
        store: &SqliteStore,
        ownership: OwnershipContext,
        workspace_identity: &str,
        suffix: &str,
    ) -> SessionId {
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
            .expect("seed compaction session");
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
            .expect("seed compaction epoch");
        store
            .connection
            .execute(
                "UPDATE session SET current_context_epoch_id = ?1 WHERE id = ?2",
                params![epoch_id.to_string(), session_id.to_string()],
            )
            .expect("activate compaction epoch");
        session_id
    }

    fn at(milliseconds: i64) -> std::time::SystemTime {
        std::time::UNIX_EPOCH
            + Duration::from_millis(u64::try_from(milliseconds).expect("positive test time"))
    }
}
