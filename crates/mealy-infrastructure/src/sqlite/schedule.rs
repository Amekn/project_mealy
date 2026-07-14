use super::SqliteStore;
use mealy_application::{
    ClaimScheduleRunCommit, CompleteScheduleRunCommit, CreateScheduleCommit, MissedRunPolicy,
    OwnershipContext, ScheduleClaimOutcome, ScheduleDefinition, ScheduleOverlapPolicy,
    ScheduleRunIntent, ScheduleRunStatus, ScheduleRunView, ScheduleStatus, ScheduleStore,
    ScheduleStoreError, ScheduleTransition, ScheduleView, TransitionScheduleCommit,
    next_schedule_occurrence_ms, sha256_digest, validate_schedule_definition,
    validate_schedule_view,
};
use mealy_domain::{InboxEntryId, ScheduleId, ScheduleRunId, SessionId};
use rusqlite::{ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use std::str::FromStr;

const MAXIMUM_HISTORY_LIMIT: usize = 1_000;
const MAXIMUM_DUE_LIMIT: usize = 100;
const MAXIMUM_CLAIM_MS: i64 = 5 * 60 * 1_000;
const MAXIMUM_REASON_BYTES: usize = 4_096;

impl ScheduleStore for SqliteStore {
    fn create_schedule(
        &mut self,
        commit: CreateScheduleCommit,
    ) -> Result<ScheduleView, ScheduleStoreError> {
        validate_create_schedule_commit(&commit)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        authorize_administrator(&transaction, commit.ownership)?;
        let delivery_ownership = delivery_ownership(
            &transaction,
            commit.ownership.principal_id(),
            commit.session_id,
        )?;
        match load_schedule(&transaction, commit.schedule_id, Some(commit.ownership)) {
            Ok(existing) if schedule_matches_create(&existing, &commit, delivery_ownership) => {
                return Ok(existing);
            }
            Ok(_) => return Err(ScheduleStoreError::Conflict),
            Err(ScheduleStoreError::NotFound) => {}
            Err(error) => return Err(error),
        }
        transaction
            .execute(
                "INSERT INTO agent_schedule(\
                    schedule_id, principal_id, channel_binding_id, session_id, name, prompt, \
                    cron_expression, timezone, missed_run_policy, overlap_policy, \
                    misfire_grace_ms, approval_required_actions_allowed, status, next_due_at_ms, \
                    revision, created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'active', \
                           ?13, 0, ?14, ?14)",
                params![
                    commit.schedule_id.to_string(),
                    delivery_ownership.principal_id().to_string(),
                    delivery_ownership.channel_binding_id().to_string(),
                    commit.session_id.to_string(),
                    commit.name,
                    commit.prompt,
                    commit.cron_expression,
                    commit.timezone,
                    missed_policy_text(commit.missed_run_policy),
                    overlap_policy_text(commit.overlap_policy),
                    commit.misfire_grace_ms,
                    i64::from(commit.approval_required_actions_allowed),
                    commit.next_due_at_ms,
                    commit.created_at_ms,
                ],
            )
            .map_err(map_constraint_error)?;
        transaction
            .execute(
                "INSERT INTO aggregate_sequence(aggregate_kind, aggregate_id, sequence) \
                 VALUES ('schedule', ?1, 0)",
                [commit.schedule_id.to_string()],
            )
            .map_err(map_constraint_error)?;
        transaction
            .execute(
                "INSERT INTO journal_event(\
                    event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                    event_version, occurred_at_ms, actor_principal_id, correlation_id, \
                    sensitivity, payload_json\
                 ) VALUES (?1, 'schedule', ?2, 0, 'schedule.created', 1, ?3, ?4, ?5, \
                           'private', ?6)",
                params![
                    commit.event_id.to_string(),
                    commit.schedule_id.to_string(),
                    commit.created_at_ms,
                    commit.ownership.principal_id().to_string(),
                    commit.correlation_id.to_string(),
                    json!({
                        "approval_required_actions_allowed": commit.approval_required_actions_allowed,
                        "cron_expression": commit.cron_expression,
                        "missed_run_policy": missed_policy_text(commit.missed_run_policy),
                        "misfire_grace_ms": commit.misfire_grace_ms,
                        "name": commit.name,
                        "next_due_at_ms": commit.next_due_at_ms,
                        "overlap_policy": overlap_policy_text(commit.overlap_policy),
                        "prompt_digest": sha256_digest(commit.prompt.as_bytes()),
                        "session_id": commit.session_id,
                        "delivery_channel_binding_id": delivery_ownership.channel_binding_id(),
                        "timezone": commit.timezone,
                    })
                    .to_string(),
                ],
            )
            .map_err(map_constraint_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_schedule(&self.connection, commit.schedule_id, Some(commit.ownership))
    }

    fn schedule(
        &self,
        ownership: OwnershipContext,
        schedule_id: ScheduleId,
    ) -> Result<ScheduleView, ScheduleStoreError> {
        authorize_administrator(&self.connection, ownership)?;
        load_schedule(&self.connection, schedule_id, Some(ownership))
    }

    fn schedules(
        &self,
        ownership: OwnershipContext,
    ) -> Result<Vec<ScheduleView>, ScheduleStoreError> {
        authorize_administrator(&self.connection, ownership)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT schedule_id FROM agent_schedule \
                 WHERE principal_id = ?1 \
                 ORDER BY created_at_ms, schedule_id",
            )
            .map_err(map_sqlite_error)?;
        let ids = statement
            .query_map([ownership.principal_id().to_string()], |row| {
                row.get::<_, String>(0)
            })
            .map_err(map_sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sqlite_error)?;
        ids.into_iter()
            .map(|id| {
                let id = parse_id(&id, "schedule ID")?;
                load_schedule(&self.connection, id, Some(ownership))
            })
            .collect()
    }

    #[allow(clippy::too_many_lines)]
    fn transition_schedule(
        &mut self,
        commit: TransitionScheduleCommit,
    ) -> Result<ScheduleView, ScheduleStoreError> {
        authorize_administrator(&self.connection, commit.ownership)?;
        let current = load_schedule(&self.connection, commit.schedule_id, Some(commit.ownership))?;
        if commit.transitioned_at_ms < current.updated_at_ms
            || current.revision != commit.expected_revision
        {
            return Err(ScheduleStoreError::Conflict);
        }
        let (expected_status, new_status, next_due_at_ms, event_type) = match commit.transition {
            ScheduleTransition::Pause
                if current.status == ScheduleStatus::Active
                    && commit.resumed_next_due_at_ms.is_none() =>
            {
                (
                    "active",
                    "paused",
                    current.next_due_at_ms,
                    "schedule.paused",
                )
            }
            ScheduleTransition::Resume
                if current.status == ScheduleStatus::Paused
                    && commit.resumed_next_due_at_ms.is_some() =>
            {
                let next = next_schedule_occurrence_ms(
                    &current.cron_expression,
                    &current.timezone,
                    commit.transitioned_at_ms,
                )
                .map_err(|error| invalid_contract(error.to_string()))?;
                if commit.resumed_next_due_at_ms != Some(next) {
                    return Err(invalid_contract("resume cursor is invalid"));
                }
                ("paused", "active", Some(next), "schedule.resumed")
            }
            ScheduleTransition::Cancel
                if matches!(
                    current.status,
                    ScheduleStatus::Active | ScheduleStatus::Paused
                ) && commit.resumed_next_due_at_ms.is_none() =>
            {
                (
                    status_text(current.status),
                    "cancelled",
                    None,
                    "schedule.cancelled",
                )
            }
            _ => return Err(ScheduleStoreError::Conflict),
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let changed = transaction
            .execute(
                "UPDATE agent_schedule SET status = ?1, next_due_at_ms = ?2, \
                    revision = revision + 1, updated_at_ms = ?3 \
                 WHERE schedule_id = ?4 AND principal_id = ?5 AND channel_binding_id = ?6 \
                   AND revision = ?7 AND status = ?8 \
                   AND NOT EXISTS (SELECT 1 FROM agent_schedule_run run \
                                   WHERE run.schedule_id = agent_schedule.schedule_id \
                                     AND run.status = 'claimed')",
                params![
                    new_status,
                    next_due_at_ms,
                    commit.transitioned_at_ms,
                    commit.schedule_id.to_string(),
                    current.ownership.principal_id().to_string(),
                    current.ownership.channel_binding_id().to_string(),
                    to_i64(commit.expected_revision)?,
                    expected_status,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(ScheduleStoreError::Conflict);
        }
        let sequence = increment_sequence(&transaction, commit.schedule_id)?;
        transaction
            .execute(
                "INSERT INTO journal_event(\
                    event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                    event_version, occurred_at_ms, actor_principal_id, correlation_id, \
                    sensitivity, payload_json\
                 ) VALUES (?1, 'schedule', ?2, ?3, ?4, 1, ?5, ?6, ?7, 'private', ?8)",
                params![
                    commit.event_id.to_string(),
                    commit.schedule_id.to_string(),
                    sequence,
                    event_type,
                    commit.transitioned_at_ms,
                    commit.ownership.principal_id().to_string(),
                    commit.correlation_id.to_string(),
                    json!({
                        "next_due_at_ms": next_due_at_ms,
                        "revision": commit.expected_revision + 1,
                        "status": new_status,
                    })
                    .to_string(),
                ],
            )
            .map_err(map_constraint_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_schedule(&self.connection, commit.schedule_id, Some(commit.ownership))
    }

    fn due_schedules(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<ScheduleView>, ScheduleStoreError> {
        if now_ms < 0 || !(1..=MAXIMUM_DUE_LIMIT).contains(&limit) {
            return Err(invalid_contract("due schedule query is invalid"));
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT schedule.schedule_id FROM agent_schedule schedule \
                 WHERE schedule.status = 'active' AND schedule.next_due_at_ms <= ?1 \
                   AND NOT EXISTS (SELECT 1 FROM agent_schedule_run run \
                                   WHERE run.schedule_id = schedule.schedule_id \
                                     AND run.status = 'claimed' \
                                     AND run.claim_expires_at_ms > ?1) \
                 ORDER BY schedule.next_due_at_ms, schedule.created_at_ms, schedule.schedule_id \
                 LIMIT ?2",
            )
            .map_err(map_sqlite_error)?;
        let ids = statement
            .query_map(params![now_ms, usize_to_i64(limit)?], |row| {
                row.get::<_, String>(0)
            })
            .map_err(map_sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sqlite_error)?;
        ids.into_iter()
            .map(|id| load_schedule(&self.connection, parse_id(&id, "schedule ID")?, None))
            .collect()
    }

    fn schedule_has_active_run(&self, schedule_id: ScheduleId) -> Result<bool, ScheduleStoreError> {
        self.connection
            .query_row(
                "SELECT EXISTS(\
                    SELECT 1 FROM agent_schedule_run run \
                    JOIN session_inbox inbox ON inbox.inbox_entry_id = run.inbox_entry_id \
                    LEFT JOIN turn ON turn.inbox_entry_id = inbox.inbox_entry_id \
                    WHERE run.schedule_id = ?1 AND run.status = 'admitted' \
                      AND (inbox.state = 'pending' OR turn.status = 'active')\
                 )",
                [schedule_id.to_string()],
                |row| row.get(0),
            )
            .map_err(map_sqlite_error)
    }

    fn claim_schedule_run(
        &mut self,
        commit: ClaimScheduleRunCommit,
    ) -> Result<ScheduleClaimOutcome, ScheduleStoreError> {
        if commit.claimed_at_ms < 0
            || commit.scheduled_for_ms < commit.expected_next_due_at_ms
            || commit.claim_expires_at_ms <= commit.claimed_at_ms
            || commit.claim_expires_at_ms - commit.claimed_at_ms > MAXIMUM_CLAIM_MS
        {
            return Err(invalid_contract("schedule claim is invalid"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let current = transaction
            .query_row(
                "SELECT revision, next_due_at_ms, status FROM agent_schedule \
                 WHERE schedule_id = ?1",
                [commit.schedule_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(map_sqlite_error)?;
        if current
            != Some((
                to_i64(commit.expected_revision)?,
                Some(commit.expected_next_due_at_ms),
                "active".to_owned(),
            ))
        {
            return Ok(ScheduleClaimOutcome::Busy);
        }
        let existing = transaction
            .query_row(
                "SELECT schedule_run_id, claim_expires_at_ms FROM agent_schedule_run \
                 WHERE schedule_id = ?1 AND status = 'claimed'",
                [commit.schedule_id.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(map_sqlite_error)?;
        let schedule_run_id = if let Some((run_id, expires_at_ms)) = existing {
            if expires_at_ms > commit.claimed_at_ms {
                return Ok(ScheduleClaimOutcome::Busy);
            }
            let changed = transaction
                .execute(
                    "UPDATE agent_schedule_run SET claim_owner_id = ?1, claim_expires_at_ms = ?2, \
                        coalesced = MAX(coalesced, ?3) \
                     WHERE schedule_run_id = ?4 AND status = 'claimed' \
                       AND claim_expires_at_ms <= ?5",
                    params![
                        commit.owner_id.to_string(),
                        commit.claim_expires_at_ms,
                        i64::from(commit.coalesced),
                        run_id,
                        commit.claimed_at_ms,
                    ],
                )
                .map_err(map_sqlite_error)?;
            if changed != 1 {
                return Ok(ScheduleClaimOutcome::Busy);
            }
            parse_id(&run_id, "schedule run ID")?
        } else {
            transaction
                .execute(
                    "INSERT INTO agent_schedule_run(\
                        schedule_run_id, schedule_id, scheduled_for_ms, coalesced, intent, status, \
                        claim_owner_id, claim_expires_at_ms, created_at_ms\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, 'claimed', ?6, ?7, ?8)",
                    params![
                        commit.proposed_schedule_run_id.to_string(),
                        commit.schedule_id.to_string(),
                        commit.scheduled_for_ms,
                        i64::from(commit.coalesced),
                        run_intent_text(commit.intent),
                        commit.owner_id.to_string(),
                        commit.claim_expires_at_ms,
                        commit.claimed_at_ms,
                    ],
                )
                .map_err(map_constraint_error)?;
            commit.proposed_schedule_run_id
        };
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(ScheduleClaimOutcome::Claimed(load_schedule_run(
            &self.connection,
            schedule_run_id,
        )?))
    }

    fn complete_schedule_run(
        &mut self,
        commit: CompleteScheduleRunCommit,
    ) -> Result<ScheduleRunView, ScheduleStoreError> {
        if commit.completed_at_ms < 0
            || commit.next_due_at_ms <= 0
            || !valid_completion_shape(
                commit.status,
                commit.inbox_entry_id,
                commit.reason.as_deref(),
            )
        {
            return Err(invalid_contract("schedule completion is invalid"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let changed = transaction
            .execute(
                "UPDATE agent_schedule_run SET status = ?1, inbox_entry_id = ?2, reason = ?3, \
                    completed_at_ms = ?4 \
                 WHERE schedule_run_id = ?5 AND schedule_id = ?6 AND status = 'claimed' \
                   AND claim_owner_id = ?7 AND created_at_ms <= ?4",
                params![
                    run_status_text(commit.status),
                    commit.inbox_entry_id.map(|id| id.to_string()),
                    commit.reason,
                    commit.completed_at_ms,
                    commit.schedule_run_id.to_string(),
                    commit.schedule_id.to_string(),
                    commit.owner_id.to_string(),
                ],
            )
            .map_err(map_constraint_error)?;
        if changed != 1 {
            return Err(ScheduleStoreError::Conflict);
        }
        let changed = transaction
            .execute(
                "UPDATE agent_schedule SET next_due_at_ms = ?1, revision = revision + 1, \
                    updated_at_ms = ?2 \
                 WHERE schedule_id = ?3 AND status = 'active' \
                   AND next_due_at_ms <= ?2",
                params![
                    commit.next_due_at_ms,
                    commit.completed_at_ms,
                    commit.schedule_id.to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(ScheduleStoreError::Conflict);
        }
        transaction.commit().map_err(map_sqlite_error)?;
        load_schedule_run(&self.connection, commit.schedule_run_id)
    }

    fn schedule_runs(
        &self,
        ownership: OwnershipContext,
        schedule_id: ScheduleId,
        limit: usize,
    ) -> Result<Vec<ScheduleRunView>, ScheduleStoreError> {
        if !(1..=MAXIMUM_HISTORY_LIMIT).contains(&limit) {
            return Err(invalid_contract("schedule history limit is invalid"));
        }
        authorize_administrator(&self.connection, ownership)?;
        load_schedule(&self.connection, schedule_id, Some(ownership))?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT schedule_run_id FROM agent_schedule_run WHERE schedule_id = ?1 \
                 ORDER BY scheduled_for_ms DESC, schedule_run_id DESC LIMIT ?2",
            )
            .map_err(map_sqlite_error)?;
        let ids = statement
            .query_map(
                params![schedule_id.to_string(), usize_to_i64(limit)?],
                |row| row.get::<_, String>(0),
            )
            .map_err(map_sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sqlite_error)?;
        ids.into_iter()
            .map(|id| load_schedule_run(&self.connection, parse_id(&id, "schedule run ID")?))
            .collect()
    }
}

fn validate_create_schedule_commit(
    commit: &CreateScheduleCommit,
) -> Result<(), ScheduleStoreError> {
    validate_schedule_definition(ScheduleDefinition {
        name: &commit.name,
        prompt: &commit.prompt,
        cron_expression: &commit.cron_expression,
        timezone: &commit.timezone,
        misfire_grace_ms: commit.misfire_grace_ms,
        approval_required_actions_allowed: commit.approval_required_actions_allowed,
    })
    .map_err(|error| invalid_contract(error.to_string()))?;
    if commit.created_at_ms < 0
        || next_schedule_occurrence_ms(
            &commit.cron_expression,
            &commit.timezone,
            commit.created_at_ms,
        )
        .map_err(|error| invalid_contract(error.to_string()))?
            != commit.next_due_at_ms
    {
        return Err(invalid_contract("initial schedule cursor is invalid"));
    }
    Ok(())
}

fn schedule_matches_create(
    existing: &ScheduleView,
    commit: &CreateScheduleCommit,
    delivery_ownership: OwnershipContext,
) -> bool {
    existing.ownership == delivery_ownership
        && existing.session_id == commit.session_id
        && existing.name == commit.name
        && existing.prompt == commit.prompt
        && existing.cron_expression == commit.cron_expression
        && existing.timezone == commit.timezone
        && existing.missed_run_policy == commit.missed_run_policy
        && existing.overlap_policy == commit.overlap_policy
        && existing.misfire_grace_ms == commit.misfire_grace_ms
        && existing.approval_required_actions_allowed == commit.approval_required_actions_allowed
}

fn delivery_ownership(
    transaction: &Transaction<'_>,
    principal_id: mealy_domain::PrincipalId,
    session_id: SessionId,
) -> Result<OwnershipContext, ScheduleStoreError> {
    let binding_id = transaction
        .query_row(
            "SELECT session.channel_binding_id FROM session \
             JOIN principal_registry principal ON principal.principal_id = session.principal_id \
             JOIN channel_binding_registry binding \
               ON binding.binding_id = session.channel_binding_id \
              AND binding.principal_id = session.principal_id \
             WHERE session.id = ?1 AND session.principal_id = ?2 AND session.status <> 'closed' \
               AND principal.status = 'active' AND binding.status = 'active'",
            params![session_id.to_string(), principal_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(ScheduleStoreError::Unauthorized)?;
    Ok(OwnershipContext::new(
        principal_id,
        parse_id(&binding_id, "schedule delivery channel binding ID")?,
    ))
}

fn authorize_administrator(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
) -> Result<(), ScheduleStoreError> {
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
        Err(ScheduleStoreError::Unauthorized)
    }
}

fn load_schedule(
    connection: &rusqlite::Connection,
    schedule_id: ScheduleId,
    ownership: Option<OwnershipContext>,
) -> Result<ScheduleView, ScheduleStoreError> {
    let row = connection
        .query_row(
            "SELECT principal_id, channel_binding_id, session_id, name, prompt, cron_expression, \
                    timezone, missed_run_policy, overlap_policy, misfire_grace_ms, \
                    approval_required_actions_allowed, status, next_due_at_ms, revision, \
                    created_at_ms, updated_at_ms \
             FROM agent_schedule WHERE schedule_id = ?1",
            [schedule_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, bool>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, Option<i64>>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, i64>(15)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(ScheduleStoreError::NotFound)?;
    let stored_ownership = OwnershipContext::new(
        parse_id(&row.0, "schedule principal ID")?,
        parse_id(&row.1, "schedule channel binding ID")?,
    );
    if ownership
        .is_some_and(|ownership| ownership.principal_id() != stored_ownership.principal_id())
    {
        return Err(ScheduleStoreError::NotFound);
    }
    let view = ScheduleView {
        schedule_id,
        ownership: stored_ownership,
        session_id: parse_id(&row.2, "schedule session ID")?,
        name: row.3,
        prompt: row.4,
        cron_expression: row.5,
        timezone: row.6,
        missed_run_policy: parse_missed_policy(&row.7)?,
        overlap_policy: parse_overlap_policy(&row.8)?,
        misfire_grace_ms: row.9,
        approval_required_actions_allowed: row.10,
        status: parse_status(&row.11)?,
        next_due_at_ms: row.12,
        revision: nonnegative(row.13, "schedule revision")?,
        created_at_ms: row.14,
        updated_at_ms: row.15,
    };
    validate_schedule_view(&view).map_err(|error| invariant(error.to_string()))?;
    Ok(view)
}

fn load_schedule_run(
    connection: &rusqlite::Connection,
    schedule_run_id: ScheduleRunId,
) -> Result<ScheduleRunView, ScheduleStoreError> {
    let row = connection
        .query_row(
            "SELECT schedule_id, scheduled_for_ms, coalesced, intent, status, inbox_entry_id, reason, \
                    created_at_ms, completed_at_ms FROM agent_schedule_run \
             WHERE schedule_run_id = ?1",
            [schedule_run_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(ScheduleStoreError::NotFound)?;
    let intent = parse_run_intent(&row.3)?;
    let status = parse_run_status(&row.4)?;
    let inbox_entry_id = row
        .5
        .as_deref()
        .map(|value| parse_id(value, "schedule inbox entry ID"))
        .transpose()?;
    if row.1 < 0
        || row.7 < 0
        || row.8.is_some_and(|completed| completed < row.7)
        || !valid_completion_shape(status, inbox_entry_id, row.6.as_deref())
            && status != ScheduleRunStatus::Claimed
        || status == ScheduleRunStatus::Claimed
            && (inbox_entry_id.is_some() || row.6.is_some() || row.8.is_some())
    {
        return Err(invariant("stored schedule run is invalid"));
    }
    Ok(ScheduleRunView {
        schedule_run_id,
        schedule_id: parse_id(&row.0, "schedule run schedule ID")?,
        scheduled_for_ms: row.1,
        coalesced: row.2,
        intent,
        status,
        inbox_entry_id,
        reason: row.6,
        created_at_ms: row.7,
        completed_at_ms: row.8,
    })
}

fn valid_completion_shape(
    status: ScheduleRunStatus,
    inbox_entry_id: Option<InboxEntryId>,
    reason: Option<&str>,
) -> bool {
    match status {
        ScheduleRunStatus::Admitted => inbox_entry_id.is_some() && reason.is_none(),
        ScheduleRunStatus::Skipped | ScheduleRunStatus::Failed => {
            inbox_entry_id.is_none()
                && reason.is_some_and(|reason| {
                    !reason.is_empty()
                        && reason.len() <= MAXIMUM_REASON_BYTES
                        && !reason.chars().any(char::is_control)
                })
        }
        ScheduleRunStatus::Claimed => false,
    }
}

fn increment_sequence(
    transaction: &Transaction<'_>,
    schedule_id: ScheduleId,
) -> Result<i64, ScheduleStoreError> {
    transaction
        .query_row(
            "UPDATE aggregate_sequence SET sequence = sequence + 1 \
             WHERE aggregate_kind = 'schedule' AND aggregate_id = ?1 RETURNING sequence",
            [schedule_id.to_string()],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or_else(|| invariant("schedule aggregate sequence is missing"))
}

const fn missed_policy_text(value: MissedRunPolicy) -> &'static str {
    match value {
        MissedRunPolicy::Skip => "skip",
        MissedRunPolicy::Latest => "latest",
    }
}

fn parse_missed_policy(value: &str) -> Result<MissedRunPolicy, ScheduleStoreError> {
    match value {
        "skip" => Ok(MissedRunPolicy::Skip),
        "latest" => Ok(MissedRunPolicy::Latest),
        _ => Err(invariant("stored missed-run policy is invalid")),
    }
}

const fn overlap_policy_text(value: ScheduleOverlapPolicy) -> &'static str {
    match value {
        ScheduleOverlapPolicy::Queue => "queue",
        ScheduleOverlapPolicy::SkipIfRunning => "skip_if_running",
    }
}

fn parse_overlap_policy(value: &str) -> Result<ScheduleOverlapPolicy, ScheduleStoreError> {
    match value {
        "queue" => Ok(ScheduleOverlapPolicy::Queue),
        "skip_if_running" => Ok(ScheduleOverlapPolicy::SkipIfRunning),
        _ => Err(invariant("stored overlap policy is invalid")),
    }
}

const fn status_text(value: ScheduleStatus) -> &'static str {
    match value {
        ScheduleStatus::Active => "active",
        ScheduleStatus::Paused => "paused",
        ScheduleStatus::Cancelled => "cancelled",
    }
}

fn parse_status(value: &str) -> Result<ScheduleStatus, ScheduleStoreError> {
    match value {
        "active" => Ok(ScheduleStatus::Active),
        "paused" => Ok(ScheduleStatus::Paused),
        "cancelled" => Ok(ScheduleStatus::Cancelled),
        _ => Err(invariant("stored schedule status is invalid")),
    }
}

const fn run_status_text(value: ScheduleRunStatus) -> &'static str {
    match value {
        ScheduleRunStatus::Claimed => "claimed",
        ScheduleRunStatus::Admitted => "admitted",
        ScheduleRunStatus::Skipped => "skipped",
        ScheduleRunStatus::Failed => "failed",
    }
}

fn parse_run_status(value: &str) -> Result<ScheduleRunStatus, ScheduleStoreError> {
    match value {
        "claimed" => Ok(ScheduleRunStatus::Claimed),
        "admitted" => Ok(ScheduleRunStatus::Admitted),
        "skipped" => Ok(ScheduleRunStatus::Skipped),
        "failed" => Ok(ScheduleRunStatus::Failed),
        _ => Err(invariant("stored schedule run status is invalid")),
    }
}

const fn run_intent_text(value: ScheduleRunIntent) -> &'static str {
    match value {
        ScheduleRunIntent::Fire => "fire",
        ScheduleRunIntent::SkipMisfire => "skip_misfire",
        ScheduleRunIntent::SkipOverlap => "skip_overlap",
    }
}

fn parse_run_intent(value: &str) -> Result<ScheduleRunIntent, ScheduleStoreError> {
    match value {
        "fire" => Ok(ScheduleRunIntent::Fire),
        "skip_misfire" => Ok(ScheduleRunIntent::SkipMisfire),
        "skip_overlap" => Ok(ScheduleRunIntent::SkipOverlap),
        _ => Err(invariant("stored schedule run intent is invalid")),
    }
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, ScheduleStoreError> {
    T::from_str(value).map_err(|_| invariant(format!("stored {field} is invalid")))
}

fn nonnegative(value: i64, field: &str) -> Result<u64, ScheduleStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("stored {field} is negative")))
}

fn to_i64(value: u64) -> Result<i64, ScheduleStoreError> {
    i64::try_from(value).map_err(|_| invalid_contract("schedule revision exceeds SQLite"))
}

fn usize_to_i64(value: usize) -> Result<i64, ScheduleStoreError> {
    i64::try_from(value).map_err(|_| invalid_contract("schedule limit exceeds SQLite"))
}

fn map_constraint_error(error: rusqlite::Error) -> ScheduleStoreError {
    if matches!(
        error.sqlite_error_code(),
        Some(ErrorCode::ConstraintViolation)
    ) {
        ScheduleStoreError::Conflict
    } else {
        map_sqlite_error(error)
    }
}

#[allow(clippy::needless_pass_by_value)]
fn map_sqlite_error(error: rusqlite::Error) -> ScheduleStoreError {
    ScheduleStoreError::Unavailable(error.to_string())
}

fn invalid_contract(message: impl Into<String>) -> ScheduleStoreError {
    ScheduleStoreError::InvalidContract(message.into())
}

fn invariant(message: impl Into<String>) -> ScheduleStoreError {
    ScheduleStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::ScheduleStore;
    use crate::{SqliteStore, SystemClock, SystemIdGenerator};
    use mealy_application::{
        AdmitInputCommand, ClaimScheduleRunCommit, CompleteScheduleRunCommit, CreateScheduleCommit,
        InputAdmissionLimits, MissedRunPolicy, OwnershipContext, ScheduleClaimOutcome,
        ScheduleDueDecision, ScheduleOverlapPolicy, ScheduleRunIntent, ScheduleRunStatus,
        ScheduleStatus, ScheduleStoreError, ScheduleTransition, TransitionScheduleCommit,
        admit_input, create_session, next_schedule_occurrence_ms, plan_due_schedule,
    };
    use mealy_domain::{
        ChannelBindingId, CorrelationId, DeliveryMode, EventId, PrincipalId, ScheduleId,
        ScheduleRunId, WorkerId,
    };

    fn create_fixture() -> (SqliteStore, OwnershipContext, mealy_domain::SessionId) {
        let mut store = SqliteStore::open_in_memory(0).expect("schedule store");
        let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
        let session_id = create_session(&mut store, &SystemClock, &SystemIdGenerator, ownership)
            .expect("destination session");
        (store, ownership, session_id)
    }

    fn create_schedule_fixture(
        store: &mut SqliteStore,
        ownership: OwnershipContext,
        session_id: mealy_domain::SessionId,
        created_at_ms: i64,
    ) -> mealy_application::ScheduleView {
        let cron_expression = "* * * * *";
        let timezone = "Pacific/Auckland";
        let next_due_at_ms = next_schedule_occurrence_ms(cron_expression, timezone, created_at_ms)
            .expect("next due");
        store
            .create_schedule(CreateScheduleCommit {
                schedule_id: ScheduleId::new(),
                ownership,
                session_id,
                name: "durable brief".to_owned(),
                prompt: "Prepare the scheduled brief.".to_owned(),
                cron_expression: cron_expression.to_owned(),
                timezone: timezone.to_owned(),
                missed_run_policy: MissedRunPolicy::Latest,
                overlap_policy: ScheduleOverlapPolicy::SkipIfRunning,
                misfire_grace_ms: 60_000,
                approval_required_actions_allowed: false,
                next_due_at_ms,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at_ms,
            })
            .expect("create schedule")
    }

    #[test]
    fn lifecycle_is_owner_scoped_revision_fenced_and_audited() {
        let (mut store, ownership, session_id) = create_fixture();
        let schedule =
            create_schedule_fixture(&mut store, ownership, session_id, 1_800_000_000_000);
        assert_eq!(schedule.status, ScheduleStatus::Active);
        assert_eq!(
            store.schedules(ownership).expect("list").as_slice(),
            std::slice::from_ref(&schedule)
        );
        let wrong = OwnershipContext::new(PrincipalId::new(), ownership.channel_binding_id());
        assert!(store.schedule(wrong, schedule.schedule_id).is_err());

        let paused = store
            .transition_schedule(TransitionScheduleCommit {
                schedule_id: schedule.schedule_id,
                ownership,
                expected_revision: 0,
                transition: ScheduleTransition::Pause,
                resumed_next_due_at_ms: None,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                transitioned_at_ms: schedule.created_at_ms + 1,
            })
            .expect("pause");
        assert_eq!(
            (paused.status, paused.revision),
            (ScheduleStatus::Paused, 1)
        );
        let resume_at = paused.updated_at_ms + 1;
        let resumed_next =
            next_schedule_occurrence_ms(&paused.cron_expression, &paused.timezone, resume_at)
                .expect("resume cursor");
        let resumed = store
            .transition_schedule(TransitionScheduleCommit {
                schedule_id: paused.schedule_id,
                ownership,
                expected_revision: 1,
                transition: ScheduleTransition::Resume,
                resumed_next_due_at_ms: Some(resumed_next),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                transitioned_at_ms: resume_at,
            })
            .expect("resume");
        assert_eq!(
            (resumed.status, resumed.revision),
            (ScheduleStatus::Active, 2)
        );
        let cancelled = store
            .transition_schedule(TransitionScheduleCommit {
                schedule_id: resumed.schedule_id,
                ownership,
                expected_revision: 2,
                transition: ScheduleTransition::Cancel,
                resumed_next_due_at_ms: None,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                transitioned_at_ms: resume_at + 1,
            })
            .expect("cancel");
        assert_eq!(cancelled.status, ScheduleStatus::Cancelled);
        assert!(cancelled.next_due_at_ms.is_none());
    }

    #[test]
    fn create_schedule_id_is_an_exact_durable_idempotency_boundary() {
        let (mut store, ownership, session_id) = create_fixture();
        let created_at_ms = 1_800_000_000_000;
        let schedule = create_schedule_fixture(&mut store, ownership, session_id, created_at_ms);
        let retry_at_ms = created_at_ms + 10_000;
        let retry_next = next_schedule_occurrence_ms("* * * * *", "Pacific/Auckland", retry_at_ms)
            .expect("retry next due");
        let replay = store
            .create_schedule(CreateScheduleCommit {
                schedule_id: schedule.schedule_id,
                ownership,
                session_id,
                name: schedule.name.clone(),
                prompt: schedule.prompt.clone(),
                cron_expression: schedule.cron_expression.clone(),
                timezone: schedule.timezone.clone(),
                missed_run_policy: schedule.missed_run_policy,
                overlap_policy: schedule.overlap_policy,
                misfire_grace_ms: schedule.misfire_grace_ms,
                approval_required_actions_allowed: schedule.approval_required_actions_allowed,
                next_due_at_ms: retry_next,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at_ms: retry_at_ms,
            })
            .expect("exact create replay");
        assert_eq!(replay, schedule);
        assert_eq!(store.schedules(ownership).expect("one schedule").len(), 1);
        let created_events = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM journal_event WHERE aggregate_kind = 'schedule' AND aggregate_id = ?1 AND event_type = 'schedule.created'",
                [schedule.schedule_id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .expect("count schedule-created events");
        assert_eq!(created_events, 1);

        let conflict = store.create_schedule(CreateScheduleCommit {
            schedule_id: schedule.schedule_id,
            ownership,
            session_id,
            name: "changed definition".to_owned(),
            prompt: schedule.prompt,
            cron_expression: schedule.cron_expression,
            timezone: schedule.timezone,
            missed_run_policy: schedule.missed_run_policy,
            overlap_policy: schedule.overlap_policy,
            misfire_grace_ms: schedule.misfire_grace_ms,
            approval_required_actions_allowed: schedule.approval_required_actions_allowed,
            next_due_at_ms: retry_next,
            event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            created_at_ms: retry_at_ms,
        });
        assert_eq!(conflict, Err(ScheduleStoreError::Conflict));
    }

    #[test]
    fn local_owner_can_schedule_a_same_principal_remote_channel_session() {
        let (mut store, administrator, _local_session_id) = create_fixture();
        let delivery = OwnershipContext::new(administrator.principal_id(), ChannelBindingId::new());
        let remote_session_id =
            create_session(&mut store, &SystemClock, &SystemIdGenerator, delivery)
                .expect("remote destination session");
        let schedule = create_schedule_fixture(
            &mut store,
            administrator,
            remote_session_id,
            1_800_000_000_000,
        );
        assert_eq!(schedule.ownership, delivery);
        assert_eq!(schedule.session_id, remote_session_id);
        assert_eq!(
            store
                .schedule(administrator, schedule.schedule_id)
                .expect("administrator schedule"),
            schedule
        );
        assert_eq!(
            store.schedules(administrator).expect("administrator list"),
            vec![schedule]
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn occurrence_claim_recovery_admission_and_history_are_exact() {
        let (mut store, ownership, session_id) = create_fixture();
        let schedule =
            create_schedule_fixture(&mut store, ownership, session_id, 1_800_000_000_000);
        let due_at = schedule.next_due_at_ms.expect("due cursor");
        let decision = plan_due_schedule(&schedule, due_at).expect("due plan");
        let ScheduleDueDecision::Fire {
            scheduled_for_ms,
            next_due_at_ms,
            coalesced,
        } = decision
        else {
            panic!("latest policy should fire")
        };
        let first_owner = WorkerId::new();
        let proposed = ScheduleRunId::new();
        let claim = store
            .claim_schedule_run(ClaimScheduleRunCommit {
                schedule_id: schedule.schedule_id,
                expected_revision: schedule.revision,
                expected_next_due_at_ms: due_at,
                proposed_schedule_run_id: proposed,
                scheduled_for_ms,
                coalesced,
                intent: ScheduleRunIntent::Fire,
                owner_id: first_owner,
                claimed_at_ms: due_at,
                claim_expires_at_ms: due_at + 100,
            })
            .expect("claim");
        assert!(
            matches!(claim, ScheduleClaimOutcome::Claimed(ref run) if run.schedule_run_id == proposed)
        );
        assert_eq!(
            store
                .claim_schedule_run(ClaimScheduleRunCommit {
                    schedule_id: schedule.schedule_id,
                    expected_revision: schedule.revision,
                    expected_next_due_at_ms: due_at,
                    proposed_schedule_run_id: ScheduleRunId::new(),
                    scheduled_for_ms,
                    coalesced,
                    intent: ScheduleRunIntent::SkipMisfire,
                    owner_id: WorkerId::new(),
                    claimed_at_ms: due_at + 50,
                    claim_expires_at_ms: due_at + 150,
                })
                .expect("busy claim"),
            ScheduleClaimOutcome::Busy
        );
        let recovered_owner = WorkerId::new();
        let recovered = store
            .claim_schedule_run(ClaimScheduleRunCommit {
                schedule_id: schedule.schedule_id,
                expected_revision: schedule.revision,
                expected_next_due_at_ms: due_at,
                proposed_schedule_run_id: ScheduleRunId::new(),
                scheduled_for_ms,
                coalesced: true,
                intent: ScheduleRunIntent::SkipMisfire,
                owner_id: recovered_owner,
                claimed_at_ms: due_at + 100,
                claim_expires_at_ms: due_at + 200,
            })
            .expect("recover claim");
        let ScheduleClaimOutcome::Claimed(recovered) = recovered else {
            panic!("expired claim should recover")
        };
        assert_eq!(recovered.schedule_run_id, proposed);
        assert_eq!(recovered.intent, ScheduleRunIntent::Fire);
        assert!(recovered.coalesced);

        let admission = admit_input(
            &mut store,
            &SystemClock,
            &SystemIdGenerator,
            InputAdmissionLimits::default(),
            AdmitInputCommand {
                session_id,
                ownership,
                dedupe_key: format!("schedule:{}:{scheduled_for_ms}", schedule.schedule_id),
                delivery_mode: DeliveryMode::Queue,
                content: schedule.prompt.clone(),
            },
        )
        .expect("scheduled admission");
        let completed = store
            .complete_schedule_run(CompleteScheduleRunCommit {
                schedule_id: schedule.schedule_id,
                schedule_run_id: recovered.schedule_run_id,
                owner_id: recovered_owner,
                status: ScheduleRunStatus::Admitted,
                inbox_entry_id: Some(admission.receipt().inbox_entry_id),
                reason: None,
                next_due_at_ms,
                completed_at_ms: due_at + 101,
            })
            .expect("complete occurrence");
        assert_eq!(completed.status, ScheduleRunStatus::Admitted);
        assert!(
            store
                .schedule_has_active_run(schedule.schedule_id)
                .expect("overlap check")
        );
        assert_eq!(
            store
                .schedule_runs(ownership, schedule.schedule_id, 10)
                .expect("history"),
            [completed]
        );
        assert_eq!(
            store
                .schedule(ownership, schedule.schedule_id)
                .expect("advanced schedule")
                .next_due_at_ms,
            Some(next_due_at_ms)
        );
    }
}
