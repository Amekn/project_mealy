use super::SqliteStore;
use mealy_application::{
    CompleteTelegramUpdateCommit, OutboundTelegramTarget, OwnershipContext,
    RecordTelegramPollCommit, RegisterTelegramChannelCommit, ReserveTelegramUpdateCommit,
    RevokeTelegramChannelCommit, TELEGRAM_MAXIMUM_ERROR_CODE_BYTES,
    TELEGRAM_MAXIMUM_IGNORE_REASON_BYTES, TelegramChannelBindingView, TelegramChannelStatus,
    TelegramChannelStore, TelegramChannelStoreError, TelegramPollTarget, TelegramUpdateDisposition,
    TelegramUpdateReservation, is_sha256_digest, sha256_digest, telegram_input_dedupe_key,
    validate_telegram_binding,
};
use mealy_domain::{ChannelBindingId, PrincipalId, SessionId};
use rusqlite::{ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use std::{str::FromStr, time::SystemTime};

const TELEGRAM_INSTALLATION_ID: &str = "builtin.telegram.v1";
const MAXIMUM_POLL_TARGETS: usize = 100;

impl TelegramChannelStore for SqliteStore {
    #[allow(clippy::too_many_lines)]
    fn register_telegram_channel(
        &mut self,
        commit: RegisterTelegramChannelCommit,
    ) -> Result<TelegramChannelBindingView, TelegramChannelStoreError> {
        validate_telegram_binding(
            commit.telegram_user_id,
            commit.telegram_chat_id,
            commit.bot_user_id,
            &commit.bot_username,
            &commit.token_secret_id,
            &commit.token_digest,
        )?;
        if commit.initial_next_update_id < 0 {
            return Err(TelegramChannelStoreError::InvalidContract(
                "initial Telegram cursor is negative".to_owned(),
            ));
        }
        let created_at_ms = epoch_milliseconds(commit.created_at)?;
        let principal_id = commit.administrative_ownership.principal_id();
        let external_subject = format!(
            "telegram:user:{}:chat:{}",
            commit.telegram_user_id, commit.telegram_chat_id
        );
        let external_subject_digest = sha256_digest(external_subject.as_bytes());
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        authorize_administrator(&transaction, commit.administrative_ownership)?;
        transaction
            .execute(
                "INSERT INTO channel_binding_registry(\
                    binding_id, principal_id, channel_kind, status, revision, installation_id, \
                    external_subject, external_subject_digest, created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, 'extension_channel', 'active', 0, ?3, ?4, ?5, ?6, ?6)",
                params![
                    commit.binding_id.to_string(),
                    principal_id.to_string(),
                    TELEGRAM_INSTALLATION_ID,
                    external_subject,
                    external_subject_digest,
                    created_at_ms,
                ],
            )
            .map_err(map_registration_error)?;
        transaction
            .execute(
                "INSERT INTO session(\
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?4)",
                params![
                    commit.session_id.to_string(),
                    principal_id.to_string(),
                    commit.binding_id.to_string(),
                    created_at_ms,
                ],
            )
            .map_err(map_registration_error)?;
        transaction
            .execute(
                "INSERT INTO journal_event(\
                    event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                    event_version, occurred_at_ms, actor_principal_id, correlation_id, \
                    sensitivity, payload_json\
                 ) VALUES (?1, 'session', ?2, 0, 'session.created', 1, ?3, ?4, ?5, \
                           'private', ?6)",
                params![
                    commit.session_event_id.to_string(),
                    commit.session_id.to_string(),
                    created_at_ms,
                    principal_id.to_string(),
                    commit.correlation_id.to_string(),
                    json!({
                        "channel_binding_id": commit.binding_id,
                        "channel_kind": "telegram",
                    })
                    .to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO aggregate_sequence(aggregate_kind, aggregate_id, sequence) \
                 VALUES ('session', ?1, 0)",
                [commit.session_id.to_string()],
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO journal_event(\
                    event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                    event_version, occurred_at_ms, actor_principal_id, correlation_id, \
                    sensitivity, payload_json\
                 ) VALUES (?1, 'channel_binding', ?2, 0, 'channel.telegram_registered', 1, ?3, \
                           ?4, ?5, 'private', ?6)",
                params![
                    commit.binding_event_id.to_string(),
                    commit.binding_id.to_string(),
                    created_at_ms,
                    principal_id.to_string(),
                    commit.correlation_id.to_string(),
                    json!({
                        "binding_id": commit.binding_id,
                        "session_id": commit.session_id,
                        "telegram_user_id": commit.telegram_user_id,
                        "telegram_chat_id": commit.telegram_chat_id,
                        "bot_user_id": commit.bot_user_id,
                        "bot_username": commit.bot_username,
                        "token_secret_id": commit.token_secret_id,
                        "token_digest": commit.token_digest,
                        "initial_next_update_id": commit.initial_next_update_id,
                    })
                    .to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO aggregate_sequence(aggregate_kind, aggregate_id, sequence) \
                 VALUES ('channel_binding', ?1, 0)",
                [commit.binding_id.to_string()],
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO telegram_channel_binding(\
                    binding_id, principal_id, session_id, telegram_user_id, telegram_chat_id, \
                    bot_user_id, bot_username, token_secret_id, token_digest, status, revision, \
                    created_event_id, created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'active', 0, ?10, ?11, ?11)",
                params![
                    commit.binding_id.to_string(),
                    principal_id.to_string(),
                    commit.session_id.to_string(),
                    commit.telegram_user_id,
                    commit.telegram_chat_id,
                    commit.bot_user_id,
                    commit.bot_username,
                    commit.token_secret_id,
                    commit.token_digest,
                    commit.binding_event_id.to_string(),
                    created_at_ms,
                ],
            )
            .map_err(map_registration_error)?;
        transaction
            .execute(
                "INSERT INTO telegram_channel_cursor(\
                    binding_id, next_update_id, revision, updated_at_ms\
                 ) VALUES (?1, ?2, 0, ?3)",
                params![
                    commit.binding_id.to_string(),
                    commit.initial_next_update_id,
                    created_at_ms
                ],
            )
            .map_err(map_registration_error)?;
        transaction
            .execute(
                "INSERT INTO telegram_channel_health(\
                    binding_id, consecutive_failures, revision, updated_at_ms\
                 ) VALUES (?1, 0, 0, ?2)",
                params![commit.binding_id.to_string(), created_at_ms],
            )
            .map_err(map_registration_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_binding(&self.connection, commit.binding_id)
    }

    fn revoke_telegram_channel(
        &mut self,
        commit: RevokeTelegramChannelCommit,
    ) -> Result<TelegramChannelBindingView, TelegramChannelStoreError> {
        let revoked_at_ms = epoch_milliseconds(commit.revoked_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        authorize_administrator(&transaction, commit.administrative_ownership)?;
        let current = load_binding(&transaction, commit.binding_id)?;
        if current.principal_id != commit.administrative_ownership.principal_id() {
            return Err(TelegramChannelStoreError::NotFound);
        }
        if current.status != TelegramChannelStatus::Active
            || current.revision != commit.expected_revision
        {
            return Err(TelegramChannelStoreError::Conflict);
        }
        let revision = to_i64(commit.expected_revision)?;
        let changed_registry = transaction
            .execute(
                "UPDATE channel_binding_registry SET status = 'revoked', revision = revision + 1, \
                    updated_at_ms = ?1, revoked_at_ms = ?1 \
                 WHERE binding_id = ?2 AND principal_id = ?3 AND status = 'active' \
                   AND revision = ?4",
                params![
                    revoked_at_ms,
                    commit.binding_id.to_string(),
                    current.principal_id.to_string(),
                    revision,
                ],
            )
            .map_err(map_sqlite_error)?;
        let changed_binding = transaction
            .execute(
                "UPDATE telegram_channel_binding SET status = 'revoked', \
                    revision = revision + 1, updated_at_ms = ?1, revoked_at_ms = ?1 \
                 WHERE binding_id = ?2 AND principal_id = ?3 AND status = 'active' \
                   AND revision = ?4",
                params![
                    revoked_at_ms,
                    commit.binding_id.to_string(),
                    current.principal_id.to_string(),
                    revision,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed_registry != 1 || changed_binding != 1 {
            return Err(TelegramChannelStoreError::Conflict);
        }
        append_revocation_event(&transaction, &commit, current.principal_id, revoked_at_ms)?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_binding(&self.connection, commit.binding_id)
    }

    fn telegram_channel(
        &self,
        ownership: OwnershipContext,
        binding_id: ChannelBindingId,
    ) -> Result<TelegramChannelBindingView, TelegramChannelStoreError> {
        authorize_administrator(&self.connection, ownership)?;
        let view = load_binding(&self.connection, binding_id)?;
        if view.principal_id == ownership.principal_id() {
            Ok(view)
        } else {
            Err(TelegramChannelStoreError::NotFound)
        }
    }

    fn telegram_channels(
        &self,
        ownership: OwnershipContext,
    ) -> Result<Vec<TelegramChannelBindingView>, TelegramChannelStoreError> {
        authorize_administrator(&self.connection, ownership)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT binding_id FROM telegram_channel_binding WHERE principal_id = ?1 \
                 ORDER BY created_at_ms, binding_id",
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
            .map(|id| load_binding(&self.connection, parse_id(&id, "Telegram binding ID")?))
            .collect()
    }

    fn active_telegram_poll_targets(
        &self,
        limit: usize,
    ) -> Result<Vec<TelegramPollTarget>, TelegramChannelStoreError> {
        if limit == 0 || limit > MAXIMUM_POLL_TARGETS {
            return Err(invalid_contract("Telegram poll target limit is invalid"));
        }
        let sql_limit = i64::try_from(limit)
            .map_err(|_| invalid_contract("Telegram poll target limit exceeds SQLite"))?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT binding.binding_id, binding.principal_id, binding.session_id, \
                        binding.telegram_user_id, binding.telegram_chat_id, \
                        binding.token_secret_id, binding.token_digest, cursor.next_update_id \
                 FROM telegram_channel_binding binding \
                 JOIN telegram_channel_cursor cursor ON cursor.binding_id = binding.binding_id \
                 JOIN channel_binding_registry registry ON registry.binding_id = binding.binding_id \
                 WHERE binding.status = 'active' AND registry.status = 'active' \
                 ORDER BY binding.created_at_ms, binding.binding_id LIMIT ?1",
            )
            .map_err(map_sqlite_error)?;
        statement
            .query_map([sql_limit], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })
            .map_err(map_sqlite_error)?
            .map(|row| {
                let row = row.map_err(map_sqlite_error)?;
                if row.7 < 0
                    || !is_sha256_digest(&row.6)
                    || !mealy_application::valid_provider_secret_id(&row.5)
                {
                    return Err(invariant("Telegram poll target is invalid"));
                }
                let binding_id = parse_id(&row.0, "Telegram binding ID")?;
                let principal_id = parse_id(&row.1, "Telegram principal ID")?;
                Ok(TelegramPollTarget {
                    binding_id,
                    telegram_user_id: row.3,
                    telegram_chat_id: row.4,
                    session_id: parse_id(&row.2, "Telegram session ID")?,
                    ownership: OwnershipContext::new(principal_id, binding_id),
                    token_secret_id: row.5,
                    token_digest: row.6,
                    next_update_id: row.7,
                })
            })
            .collect()
    }

    fn reserve_telegram_update(
        &mut self,
        commit: ReserveTelegramUpdateCommit,
    ) -> Result<TelegramUpdateReservation, TelegramChannelStoreError> {
        telegram_input_dedupe_key(commit.binding_id, commit.update_id)?;
        if !is_sha256_digest(&commit.body_digest) {
            return Err(invalid_contract("Telegram update body digest is invalid"));
        }
        let received_at_ms = epoch_milliseconds(commit.received_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let binding = load_binding(&transaction, commit.binding_id)?;
        if binding.status != TelegramChannelStatus::Active {
            return Err(TelegramChannelStoreError::Revoked);
        }
        let existing = transaction
            .query_row(
                "SELECT body_digest, state FROM telegram_update_receipt \
                 WHERE binding_id = ?1 AND update_id = ?2",
                params![commit.binding_id.to_string(), commit.update_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(map_sqlite_error)?;
        if let Some((body_digest, state)) = existing {
            if body_digest != commit.body_digest {
                return Err(TelegramChannelStoreError::Conflict);
            }
            transaction.commit().map_err(map_sqlite_error)?;
            return match state.as_str() {
                "reserved" => Ok(TelegramUpdateReservation::ExistingReserved),
                "admitted" | "ignored" => Ok(TelegramUpdateReservation::ExistingCompleted),
                _ => Err(invariant("Telegram update state is invalid")),
            };
        }
        if commit.update_id < binding.next_update_id {
            return Err(TelegramChannelStoreError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO telegram_update_receipt(\
                    binding_id, update_id, body_digest, state, session_id, received_at_ms\
                 ) VALUES (?1, ?2, ?3, 'reserved', ?4, ?5)",
                params![
                    commit.binding_id.to_string(),
                    commit.update_id,
                    commit.body_digest,
                    binding.session_id.to_string(),
                    received_at_ms,
                ],
            )
            .map_err(map_registration_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(TelegramUpdateReservation::Reserved)
    }

    fn complete_telegram_update(
        &mut self,
        commit: CompleteTelegramUpdateCommit,
    ) -> Result<(), TelegramChannelStoreError> {
        telegram_input_dedupe_key(commit.binding_id, commit.update_id)?;
        let completed_at_ms = epoch_milliseconds(commit.completed_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let binding = load_binding(&transaction, commit.binding_id)?;
        let current = transaction
            .query_row(
                "SELECT state, inbox_entry_id, acknowledgement_outbox_id, ignore_reason \
                 FROM telegram_update_receipt WHERE binding_id = ?1 AND update_id = ?2",
                params![commit.binding_id.to_string(), commit.update_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(map_sqlite_error)?
            .ok_or(TelegramChannelStoreError::Conflict)?;
        let (state, inbox_id, outbox_id, reason) = match &commit.disposition {
            TelegramUpdateDisposition::Admitted(admission) => {
                if admission.session_id != binding.session_id {
                    return Err(invalid_contract(
                        "Telegram admission belongs to another session",
                    ));
                }
                (
                    "admitted",
                    Some(admission.inbox_entry_id.to_string()),
                    Some(admission.outbox_id.to_string()),
                    None,
                )
            }
            TelegramUpdateDisposition::Ignored(reason) => {
                if !valid_reason(reason) {
                    return Err(invalid_contract("Telegram ignore reason is invalid"));
                }
                ("ignored", None, None, Some(reason.clone()))
            }
        };
        if current.0 != "reserved" {
            if current
                == (
                    state.to_owned(),
                    inbox_id.clone(),
                    outbox_id.clone(),
                    reason.clone(),
                )
            {
                transaction.commit().map_err(map_sqlite_error)?;
                return Ok(());
            }
            return Err(TelegramChannelStoreError::Conflict);
        }
        let changed_receipt = transaction
            .execute(
                "UPDATE telegram_update_receipt SET state = ?1, inbox_entry_id = ?2, \
                    acknowledgement_outbox_id = ?3, ignore_reason = ?4, completed_at_ms = ?5 \
                 WHERE binding_id = ?6 AND update_id = ?7 AND state = 'reserved' \
                   AND received_at_ms <= ?5",
                params![
                    state,
                    inbox_id,
                    outbox_id,
                    reason,
                    completed_at_ms,
                    commit.binding_id.to_string(),
                    commit.update_id,
                ],
            )
            .map_err(map_sqlite_error)?;
        let next_update_id = commit
            .update_id
            .checked_add(1)
            .ok_or_else(|| invalid_contract("Telegram update cursor overflowed"))?;
        let changed_cursor = transaction
            .execute(
                "UPDATE telegram_channel_cursor SET next_update_id = ?1, revision = revision + 1, \
                    updated_at_ms = ?2 WHERE binding_id = ?3 AND next_update_id <= ?4",
                params![
                    next_update_id,
                    completed_at_ms,
                    commit.binding_id.to_string(),
                    commit.update_id,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed_receipt != 1 || changed_cursor != 1 {
            return Err(TelegramChannelStoreError::Conflict);
        }
        transaction.commit().map_err(map_sqlite_error)
    }

    fn record_telegram_poll(
        &mut self,
        commit: RecordTelegramPollCommit,
    ) -> Result<(), TelegramChannelStoreError> {
        if commit.succeeded != commit.error_code.is_none()
            || commit.error_code.as_deref().is_some_and(|code| {
                code.is_empty()
                    || code.len() > TELEGRAM_MAXIMUM_ERROR_CODE_BYTES
                    || code.trim() != code
                    || code.chars().any(char::is_control)
            })
        {
            return Err(invalid_contract("Telegram poll health evidence is invalid"));
        }
        let observed_at_ms = epoch_milliseconds(commit.observed_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        if load_binding(&transaction, commit.binding_id)?.status != TelegramChannelStatus::Active {
            return Err(TelegramChannelStoreError::Revoked);
        }
        let changed = if commit.succeeded {
            transaction.execute(
                "UPDATE telegram_channel_health SET last_success_at_ms = ?1, \
                    consecutive_failures = 0, last_error_code = NULL, revision = revision + 1, \
                    updated_at_ms = ?1 WHERE binding_id = ?2",
                params![observed_at_ms, commit.binding_id.to_string()],
            )
        } else {
            transaction.execute(
                "UPDATE telegram_channel_health SET last_failure_at_ms = ?1, \
                    consecutive_failures = MIN(consecutive_failures + 1, 1000000000), \
                    last_error_code = ?2, revision = revision + 1, updated_at_ms = ?1 \
                 WHERE binding_id = ?3",
                params![
                    observed_at_ms,
                    commit.error_code,
                    commit.binding_id.to_string(),
                ],
            )
        }
        .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(TelegramChannelStoreError::Conflict);
        }
        transaction.commit().map_err(map_sqlite_error)
    }

    fn outbound_telegram_target(
        &self,
        session_id: SessionId,
        topic: &str,
    ) -> Result<Option<OutboundTelegramTarget>, TelegramChannelStoreError> {
        if !matches!(
            topic,
            "session.input_acknowledgement"
                | "session.input_promoted"
                | "session.input_steered"
                | "session.interrupt_requested"
                | "session.turn_completed"
                | "effect.approval_requested"
        ) {
            return Ok(None);
        }
        let target = self
            .connection
            .query_row(
                "SELECT binding.binding_id, binding.telegram_chat_id, \
                        binding.token_secret_id, binding.token_digest \
                 FROM session \
                 JOIN telegram_channel_binding binding \
                   ON binding.binding_id = session.channel_binding_id \
                  AND binding.session_id = session.id \
                 JOIN channel_binding_registry registry \
                   ON registry.binding_id = binding.binding_id \
                 WHERE session.id = ?1 AND binding.status = 'active' \
                   AND registry.status = 'active'",
                [session_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(map_sqlite_error)?;
        target
            .map(|row| {
                if row.1 == 0
                    || !mealy_application::valid_provider_secret_id(&row.2)
                    || !is_sha256_digest(&row.3)
                {
                    return Err(invariant("Telegram outbox target is invalid"));
                }
                Ok(OutboundTelegramTarget {
                    binding_id: parse_id(&row.0, "Telegram binding ID")?,
                    telegram_chat_id: row.1,
                    token_secret_id: row.2,
                    token_digest: row.3,
                })
            })
            .transpose()
    }
}

fn append_revocation_event(
    transaction: &Transaction<'_>,
    commit: &RevokeTelegramChannelCommit,
    principal_id: PrincipalId,
    revoked_at_ms: i64,
) -> Result<(), TelegramChannelStoreError> {
    let sequence = transaction
        .query_row(
            "SELECT sequence FROM aggregate_sequence \
             WHERE aggregate_kind = 'channel_binding' AND aggregate_id = ?1",
            [commit.binding_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .map_err(map_sqlite_error)?;
    if sequence != 0 {
        return Err(invariant("Telegram channel sequence is invalid"));
    }
    transaction
        .execute(
            "INSERT INTO journal_event(\
                event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                event_version, occurred_at_ms, actor_principal_id, correlation_id, sensitivity, \
                payload_json\
             ) VALUES (?1, 'channel_binding', ?2, 1, 'channel.telegram_revoked', 1, ?3, ?4, ?5, \
                       'private', ?6)",
            params![
                commit.event_id.to_string(),
                commit.binding_id.to_string(),
                revoked_at_ms,
                principal_id.to_string(),
                commit.correlation_id.to_string(),
                json!({"binding_id": commit.binding_id}).to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    let changed = transaction
        .execute(
            "UPDATE aggregate_sequence SET sequence = 1 \
             WHERE aggregate_kind = 'channel_binding' AND aggregate_id = ?1 AND sequence = 0",
            [commit.binding_id.to_string()],
        )
        .map_err(map_sqlite_error)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(TelegramChannelStoreError::Conflict)
    }
}

fn authorize_administrator(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
) -> Result<(), TelegramChannelStoreError> {
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
        Err(TelegramChannelStoreError::NotFound)
    }
}

fn load_binding(
    connection: &rusqlite::Connection,
    binding_id: ChannelBindingId,
) -> Result<TelegramChannelBindingView, TelegramChannelStoreError> {
    let row = connection
        .query_row(
            "SELECT binding.principal_id, binding.session_id, binding.telegram_user_id, \
                    binding.telegram_chat_id, binding.bot_user_id, binding.bot_username, \
                    binding.token_secret_id, binding.token_digest, binding.status, \
                    binding.revision, binding.created_at_ms, binding.updated_at_ms, \
                    cursor.next_update_id, health.last_success_at_ms, health.last_failure_at_ms, \
                    health.consecutive_failures, health.last_error_code, registry.principal_id, \
                    registry.channel_kind, registry.installation_id, registry.status, \
                    registry.revision \
             FROM telegram_channel_binding binding \
             JOIN telegram_channel_cursor cursor ON cursor.binding_id = binding.binding_id \
             JOIN telegram_channel_health health ON health.binding_id = binding.binding_id \
             JOIN channel_binding_registry registry ON registry.binding_id = binding.binding_id \
             WHERE binding.binding_id = ?1",
            [binding_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                    row.get::<_, Option<i64>>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, Option<String>>(16)?,
                    row.get::<_, String>(17)?,
                    row.get::<_, String>(18)?,
                    row.get::<_, Option<String>>(19)?,
                    row.get::<_, String>(20)?,
                    row.get::<_, i64>(21)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(TelegramChannelStoreError::NotFound)?;
    if row.0 != row.17
        || row.18 != "extension_channel"
        || row.19.as_deref() != Some(TELEGRAM_INSTALLATION_ID)
        || row.8 != row.20
        || row.9 != row.21
        || row.12 < 0
        || row.15 < 0
    {
        return Err(invariant("Telegram binding and registry diverged"));
    }
    validate_telegram_binding(row.2, row.3, row.4, &row.5, &row.6, &row.7)
        .map_err(|_| invariant("stored Telegram binding is invalid"))?;
    Ok(TelegramChannelBindingView {
        binding_id,
        principal_id: parse_id(&row.0, "Telegram principal ID")?,
        session_id: parse_id(&row.1, "Telegram session ID")?,
        telegram_user_id: row.2,
        telegram_chat_id: row.3,
        bot_user_id: row.4,
        bot_username: row.5,
        token_secret_id: row.6,
        token_digest: row.7,
        next_update_id: row.12,
        status: match row.8.as_str() {
            "active" => TelegramChannelStatus::Active,
            "revoked" => TelegramChannelStatus::Revoked,
            _ => return Err(invariant("Telegram binding status is invalid")),
        },
        revision: nonnegative(row.9, "Telegram binding revision")?,
        last_success_at_ms: row.13,
        last_failure_at_ms: row.14,
        consecutive_failures: nonnegative(row.15, "Telegram consecutive failures")?,
        last_error_code: row.16,
        created_at_ms: row.10,
        updated_at_ms: row.11,
    })
}

fn valid_reason(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= TELEGRAM_MAXIMUM_IGNORE_REASON_BYTES
        && reason.trim() == reason
        && !reason.chars().any(char::is_control)
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, TelegramChannelStoreError> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invariant("Telegram channel time precedes the Unix epoch"))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| invariant("Telegram channel time exceeds SQLite"))
}

fn nonnegative(value: i64, field: &str) -> Result<u64, TelegramChannelStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("stored {field} is negative")))
}

fn to_i64(value: u64) -> Result<i64, TelegramChannelStoreError> {
    i64::try_from(value).map_err(|_| invalid_contract("Telegram revision exceeds SQLite"))
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, TelegramChannelStoreError> {
    T::from_str(value).map_err(|_| invariant(format!("stored {field} is invalid")))
}

fn map_registration_error(error: rusqlite::Error) -> TelegramChannelStoreError {
    if matches!(
        error.sqlite_error_code(),
        Some(ErrorCode::ConstraintViolation)
    ) {
        TelegramChannelStoreError::Conflict
    } else {
        map_sqlite_error(error)
    }
}

#[allow(clippy::needless_pass_by_value)]
fn map_sqlite_error(error: rusqlite::Error) -> TelegramChannelStoreError {
    TelegramChannelStoreError::Unavailable(error.to_string())
}

fn invalid_contract(message: impl Into<String>) -> TelegramChannelStoreError {
    TelegramChannelStoreError::InvalidContract(message.into())
}

fn invariant(message: impl Into<String>) -> TelegramChannelStoreError {
    TelegramChannelStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::TelegramChannelStore;
    use mealy_application::{
        AdmitInputCommand, CompleteTelegramUpdateCommit, InputAdmissionLimits, OwnershipContext,
        RecordTelegramPollCommit, RegisterTelegramChannelCommit, ReserveTelegramUpdateCommit,
        RevokeTelegramChannelCommit, TelegramChannelStatus, TelegramChannelStoreError,
        TelegramUpdateDisposition, TelegramUpdateReservation, admit_input, sha256_digest,
        telegram_input_dedupe_key,
    };
    use mealy_domain::{
        ChannelBindingId, CorrelationId, DeliveryMode, EventId, PrincipalId, SessionId,
    };
    use mealy_testkit::{TestClock, TestIdGenerator};
    use std::time::{Duration, SystemTime};

    fn register(
        store: &mut super::SqliteStore,
        administrator: OwnershipContext,
        binding_id: ChannelBindingId,
        session_id: SessionId,
        token_digest: String,
        now: SystemTime,
    ) -> mealy_application::TelegramChannelBindingView {
        store
            .register_telegram_channel(RegisterTelegramChannelCommit {
                administrative_ownership: administrator,
                binding_id,
                session_id,
                telegram_user_id: 7_001,
                telegram_chat_id: 8_001,
                initial_next_update_id: 40,
                bot_user_id: 9_001,
                bot_username: "mealy_test_bot".to_owned(),
                token_secret_id: format!("telegram.{binding_id}"),
                token_digest,
                session_event_id: EventId::new(),
                binding_event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at: now,
            })
            .expect("register Telegram channel")
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn exact_binding_update_recovery_health_routing_and_revocation_are_durable() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_hours(500_000);
        let clock = TestClock::new(1_800_000_000_000);
        let ids = TestIdGenerator::new(1_800_000_000_000);
        let mut store = super::SqliteStore::open_in_memory(1).expect("store");
        let principal_id = PrincipalId::new();
        let administrator = OwnershipContext::new(principal_id, ChannelBindingId::new());
        store
            .register_local_identity(administrator, 1)
            .expect("register administrator");
        let binding_id = ChannelBindingId::new();
        let session_id = SessionId::new();
        let token_digest = sha256_digest(b"123:telegram-token");
        let channel = register(
            &mut store,
            administrator,
            binding_id,
            session_id,
            token_digest.clone(),
            now,
        );
        assert_eq!(channel.status, TelegramChannelStatus::Active);
        assert_eq!(channel.next_update_id, 40);
        assert_eq!(
            store
                .active_telegram_poll_targets(10)
                .expect("poll targets")[0]
                .token_digest,
            token_digest
        );

        let update_id = 41_i64;
        let body_digest = sha256_digest(br#"{"update_id":41}"#);
        assert_eq!(
            store
                .reserve_telegram_update(ReserveTelegramUpdateCommit {
                    binding_id,
                    update_id,
                    body_digest: body_digest.clone(),
                    received_at: now,
                })
                .expect("reserve update"),
            TelegramUpdateReservation::Reserved
        );
        assert_eq!(
            store
                .reserve_telegram_update(ReserveTelegramUpdateCommit {
                    binding_id,
                    update_id,
                    body_digest: body_digest.clone(),
                    received_at: now,
                })
                .expect("recover reservation"),
            TelegramUpdateReservation::ExistingReserved
        );
        let outcome = admit_input(
            &mut store,
            &clock,
            &ids,
            InputAdmissionLimits::default(),
            AdmitInputCommand {
                session_id,
                ownership: OwnershipContext::new(principal_id, binding_id),
                dedupe_key: telegram_input_dedupe_key(binding_id, update_id).expect("dedupe key"),
                delivery_mode: DeliveryMode::Queue,
                content: "hello from Telegram".to_owned(),
            },
        )
        .expect("admit Telegram input");
        store
            .complete_telegram_update(CompleteTelegramUpdateCommit {
                binding_id,
                update_id,
                disposition: TelegramUpdateDisposition::Admitted(outcome.receipt().clone()),
                completed_at: now + Duration::from_millis(1),
            })
            .expect("complete update");
        assert_eq!(
            store
                .reserve_telegram_update(ReserveTelegramUpdateCommit {
                    binding_id,
                    update_id,
                    body_digest,
                    received_at: now,
                })
                .expect("recognize completed update"),
            TelegramUpdateReservation::ExistingCompleted
        );
        assert_eq!(
            store
                .telegram_channel(administrator, binding_id)
                .expect("advanced channel")
                .next_update_id,
            42
        );
        assert!(
            store
                .outbound_telegram_target(session_id, "session.turn_completed")
                .expect("Telegram route")
                .is_some()
        );

        store
            .record_telegram_poll(RecordTelegramPollCommit {
                binding_id,
                succeeded: false,
                error_code: Some("telegram_http_429".to_owned()),
                observed_at: now + Duration::from_millis(2),
            })
            .expect("failed health");
        let failed = store
            .telegram_channel(administrator, binding_id)
            .expect("failed health view");
        assert_eq!(failed.consecutive_failures, 1);
        assert_eq!(failed.last_error_code.as_deref(), Some("telegram_http_429"));
        store
            .record_telegram_poll(RecordTelegramPollCommit {
                binding_id,
                succeeded: true,
                error_code: None,
                observed_at: now + Duration::from_millis(3),
            })
            .expect("healthy poll");
        assert_eq!(
            store
                .telegram_channel(administrator, binding_id)
                .expect("healthy view")
                .consecutive_failures,
            0
        );

        let wrong_owner =
            OwnershipContext::new(PrincipalId::new(), administrator.channel_binding_id());
        assert_eq!(
            store.telegram_channel(wrong_owner, binding_id),
            Err(TelegramChannelStoreError::NotFound)
        );
        let revoked = store
            .revoke_telegram_channel(RevokeTelegramChannelCommit {
                administrative_ownership: administrator,
                binding_id,
                expected_revision: 0,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                revoked_at: now + Duration::from_millis(4),
            })
            .expect("revoke channel");
        assert_eq!(revoked.status, TelegramChannelStatus::Revoked);
        assert!(
            store
                .active_telegram_poll_targets(10)
                .expect("no active targets")
                .is_empty()
        );
        assert!(
            store
                .outbound_telegram_target(session_id, "session.turn_completed")
                .expect("revoked route")
                .is_none()
        );
    }

    #[test]
    fn one_token_digest_cannot_own_multiple_poll_cursors() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_hours(500_000);
        let mut store = super::SqliteStore::open_in_memory(1).expect("store");
        let administrator = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
        store
            .register_local_identity(administrator, 1)
            .expect("register administrator");
        let digest = sha256_digest(b"same Telegram token");
        register(
            &mut store,
            administrator,
            ChannelBindingId::new(),
            SessionId::new(),
            digest.clone(),
            now,
        );
        let duplicate = store.register_telegram_channel(RegisterTelegramChannelCommit {
            administrative_ownership: administrator,
            binding_id: ChannelBindingId::new(),
            session_id: SessionId::new(),
            telegram_user_id: 7_002,
            telegram_chat_id: 8_002,
            initial_next_update_id: 0,
            bot_user_id: 9_002,
            bot_username: "another_mealy_bot".to_owned(),
            token_secret_id: "telegram.second".to_owned(),
            token_digest: digest,
            session_event_id: EventId::new(),
            binding_event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            created_at: now,
        });
        assert_eq!(duplicate, Err(TelegramChannelStoreError::Conflict));
    }
}
