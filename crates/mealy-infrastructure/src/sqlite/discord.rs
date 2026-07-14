use super::SqliteStore;
use mealy_application::{
    CompleteDiscordMessageCommit, DISCORD_MAXIMUM_ERROR_CODE_BYTES,
    DISCORD_MAXIMUM_IGNORE_REASON_BYTES, DiscordChannelBindingView, DiscordChannelStatus,
    DiscordChannelStore, DiscordChannelStoreError, DiscordMessageDisposition,
    DiscordMessageReservation, DiscordPollTarget, OutboundDiscordTarget, OwnershipContext,
    RecordDiscordPollCommit, RegisterDiscordChannelCommit, ReserveDiscordMessageCommit,
    RevokeDiscordChannelCommit, discord_input_dedupe_key, is_sha256_digest, sha256_digest,
    validate_discord_binding, validate_discord_snowflake,
};
use mealy_domain::{ChannelBindingId, PrincipalId, SessionId};
use rusqlite::{ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use std::{cmp::Ordering, str::FromStr, time::SystemTime};

const DISCORD_INSTALLATION_ID: &str = "builtin.discord.dm.v1";
const MAXIMUM_POLL_TARGETS: usize = 100;

impl DiscordChannelStore for SqliteStore {
    #[allow(clippy::too_many_lines)]
    fn register_discord_channel(
        &mut self,
        commit: RegisterDiscordChannelCommit,
    ) -> Result<DiscordChannelBindingView, DiscordChannelStoreError> {
        validate_discord_binding(
            &commit.discord_user_id,
            &commit.discord_channel_id,
            &commit.bot_user_id,
            &commit.bot_username,
            &commit.token_secret_id,
            &commit.token_digest,
        )?;
        if commit
            .initial_after_message_id
            .as_deref()
            .is_some_and(|value| !validate_discord_snowflake(value))
        {
            return Err(invalid_contract("initial Discord cursor is invalid"));
        }
        let created_at_ms = epoch_milliseconds(commit.created_at)?;
        let principal_id = commit.administrative_ownership.principal_id();
        let external_subject = format!(
            "discord:user:{}:dm:{}",
            commit.discord_user_id, commit.discord_channel_id
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
                    DISCORD_INSTALLATION_ID,
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
                        "channel_kind": "discord_dm",
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
                 ) VALUES (?1, 'channel_binding', ?2, 0, 'channel.discord_registered', 1, ?3, \
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
                        "discord_user_id": commit.discord_user_id,
                        "discord_channel_id": commit.discord_channel_id,
                        "bot_user_id": commit.bot_user_id,
                        "bot_username": commit.bot_username,
                        "token_secret_id": commit.token_secret_id,
                        "token_digest": commit.token_digest,
                        "initial_after_message_id": commit.initial_after_message_id,
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
                "INSERT INTO discord_channel_binding(\
                    binding_id, principal_id, session_id, discord_user_id, discord_channel_id, \
                    bot_user_id, bot_username, token_secret_id, token_digest, status, revision, \
                    created_event_id, created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'active', 0, ?10, ?11, ?11)",
                params![
                    commit.binding_id.to_string(),
                    principal_id.to_string(),
                    commit.session_id.to_string(),
                    commit.discord_user_id,
                    commit.discord_channel_id,
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
                "INSERT INTO discord_channel_cursor(\
                    binding_id, after_message_id, revision, updated_at_ms\
                 ) VALUES (?1, ?2, 0, ?3)",
                params![
                    commit.binding_id.to_string(),
                    commit.initial_after_message_id,
                    created_at_ms,
                ],
            )
            .map_err(map_registration_error)?;
        transaction
            .execute(
                "INSERT INTO discord_channel_health(\
                    binding_id, consecutive_failures, revision, updated_at_ms\
                 ) VALUES (?1, 0, 0, ?2)",
                params![commit.binding_id.to_string(), created_at_ms],
            )
            .map_err(map_registration_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_binding(&self.connection, commit.binding_id)
    }

    fn revoke_discord_channel(
        &mut self,
        commit: RevokeDiscordChannelCommit,
    ) -> Result<DiscordChannelBindingView, DiscordChannelStoreError> {
        let revoked_at_ms = epoch_milliseconds(commit.revoked_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        authorize_administrator(&transaction, commit.administrative_ownership)?;
        let current = load_binding(&transaction, commit.binding_id)?;
        if current.principal_id != commit.administrative_ownership.principal_id() {
            return Err(DiscordChannelStoreError::NotFound);
        }
        if current.status != DiscordChannelStatus::Active
            || current.revision != commit.expected_revision
        {
            return Err(DiscordChannelStoreError::Conflict);
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
                "UPDATE discord_channel_binding SET status = 'revoked', \
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
            return Err(DiscordChannelStoreError::Conflict);
        }
        append_revocation_event(&transaction, &commit, current.principal_id, revoked_at_ms)?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_binding(&self.connection, commit.binding_id)
    }

    fn discord_channel(
        &self,
        ownership: OwnershipContext,
        binding_id: ChannelBindingId,
    ) -> Result<DiscordChannelBindingView, DiscordChannelStoreError> {
        authorize_administrator(&self.connection, ownership)?;
        let view = load_binding(&self.connection, binding_id)?;
        if view.principal_id == ownership.principal_id() {
            Ok(view)
        } else {
            Err(DiscordChannelStoreError::NotFound)
        }
    }

    fn discord_channels(
        &self,
        ownership: OwnershipContext,
    ) -> Result<Vec<DiscordChannelBindingView>, DiscordChannelStoreError> {
        authorize_administrator(&self.connection, ownership)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT binding_id FROM discord_channel_binding WHERE principal_id = ?1 \
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
            .map(|id| load_binding(&self.connection, parse_id(&id, "Discord binding ID")?))
            .collect()
    }

    fn active_discord_poll_targets(
        &self,
        limit: usize,
    ) -> Result<Vec<DiscordPollTarget>, DiscordChannelStoreError> {
        if limit == 0 || limit > MAXIMUM_POLL_TARGETS {
            return Err(invalid_contract("Discord poll target limit is invalid"));
        }
        let sql_limit = i64::try_from(limit)
            .map_err(|_| invalid_contract("Discord poll target limit exceeds SQLite"))?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT binding.binding_id, binding.principal_id, binding.session_id, \
                        binding.discord_user_id, binding.discord_channel_id, binding.bot_user_id, \
                        binding.token_secret_id, binding.token_digest, cursor.after_message_id \
                 FROM discord_channel_binding binding \
                 JOIN discord_channel_cursor cursor ON cursor.binding_id = binding.binding_id \
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
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            })
            .map_err(map_sqlite_error)?
            .map(|row| {
                let row = row.map_err(map_sqlite_error)?;
                if !validate_discord_snowflake(&row.3)
                    || !validate_discord_snowflake(&row.4)
                    || !validate_discord_snowflake(&row.5)
                    || row
                        .8
                        .as_deref()
                        .is_some_and(|id| !validate_discord_snowflake(id))
                    || !is_sha256_digest(&row.7)
                    || !mealy_application::valid_provider_secret_id(&row.6)
                {
                    return Err(invariant("Discord poll target is invalid"));
                }
                let binding_id = parse_id(&row.0, "Discord binding ID")?;
                let principal_id = parse_id(&row.1, "Discord principal ID")?;
                Ok(DiscordPollTarget {
                    binding_id,
                    discord_user_id: row.3,
                    discord_channel_id: row.4,
                    bot_user_id: row.5,
                    session_id: parse_id(&row.2, "Discord session ID")?,
                    ownership: OwnershipContext::new(principal_id, binding_id),
                    token_secret_id: row.6,
                    token_digest: row.7,
                    after_message_id: row.8,
                })
            })
            .collect()
    }

    fn reserve_discord_message(
        &mut self,
        commit: ReserveDiscordMessageCommit,
    ) -> Result<DiscordMessageReservation, DiscordChannelStoreError> {
        discord_input_dedupe_key(commit.binding_id, &commit.message_id)?;
        if !is_sha256_digest(&commit.body_digest) {
            return Err(invalid_contract("Discord message body digest is invalid"));
        }
        let received_at_ms = epoch_milliseconds(commit.received_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let binding = load_binding(&transaction, commit.binding_id)?;
        if binding.status != DiscordChannelStatus::Active {
            return Err(DiscordChannelStoreError::Revoked);
        }
        let existing = transaction
            .query_row(
                "SELECT body_digest, state FROM discord_message_receipt \
                 WHERE binding_id = ?1 AND message_id = ?2",
                params![commit.binding_id.to_string(), commit.message_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(map_sqlite_error)?;
        if let Some((body_digest, state)) = existing {
            if body_digest != commit.body_digest {
                return Err(DiscordChannelStoreError::Conflict);
            }
            transaction.commit().map_err(map_sqlite_error)?;
            return match state.as_str() {
                "reserved" => Ok(DiscordMessageReservation::ExistingReserved),
                "admitted" | "ignored" => Ok(DiscordMessageReservation::ExistingCompleted),
                _ => Err(invariant("Discord message state is invalid")),
            };
        }
        if binding
            .after_message_id
            .as_deref()
            .is_some_and(|cursor| snowflake_cmp(&commit.message_id, cursor) != Ordering::Greater)
        {
            return Err(DiscordChannelStoreError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO discord_message_receipt(\
                    binding_id, message_id, body_digest, state, session_id, received_at_ms\
                 ) VALUES (?1, ?2, ?3, 'reserved', ?4, ?5)",
                params![
                    commit.binding_id.to_string(),
                    commit.message_id,
                    commit.body_digest,
                    binding.session_id.to_string(),
                    received_at_ms,
                ],
            )
            .map_err(map_registration_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(DiscordMessageReservation::Reserved)
    }

    fn complete_discord_message(
        &mut self,
        commit: CompleteDiscordMessageCommit,
    ) -> Result<(), DiscordChannelStoreError> {
        discord_input_dedupe_key(commit.binding_id, &commit.message_id)?;
        let completed_at_ms = epoch_milliseconds(commit.completed_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let binding = load_binding(&transaction, commit.binding_id)?;
        let current = transaction
            .query_row(
                "SELECT state, inbox_entry_id, acknowledgement_outbox_id, ignore_reason \
                 FROM discord_message_receipt WHERE binding_id = ?1 AND message_id = ?2",
                params![commit.binding_id.to_string(), commit.message_id],
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
            .ok_or(DiscordChannelStoreError::Conflict)?;
        let (state, inbox_id, outbox_id, reason) = match &commit.disposition {
            DiscordMessageDisposition::Admitted(admission) => {
                if admission.session_id != binding.session_id {
                    return Err(invalid_contract(
                        "Discord admission belongs to another session",
                    ));
                }
                (
                    "admitted",
                    Some(admission.inbox_entry_id.to_string()),
                    Some(admission.outbox_id.to_string()),
                    None,
                )
            }
            DiscordMessageDisposition::Ignored(reason) => {
                if !valid_reason(reason) {
                    return Err(invalid_contract("Discord ignore reason is invalid"));
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
            return Err(DiscordChannelStoreError::Conflict);
        }
        let changed_receipt = transaction
            .execute(
                "UPDATE discord_message_receipt SET state = ?1, inbox_entry_id = ?2, \
                    acknowledgement_outbox_id = ?3, ignore_reason = ?4, completed_at_ms = ?5 \
                 WHERE binding_id = ?6 AND message_id = ?7 AND state = 'reserved' \
                   AND received_at_ms <= ?5",
                params![
                    state,
                    inbox_id,
                    outbox_id,
                    reason,
                    completed_at_ms,
                    commit.binding_id.to_string(),
                    commit.message_id,
                ],
            )
            .map_err(map_sqlite_error)?;
        let changed_cursor = transaction
            .execute(
                "UPDATE discord_channel_cursor SET after_message_id = ?1, \
                    revision = revision + 1, updated_at_ms = ?2 \
                 WHERE binding_id = ?3 AND (after_message_id IS NULL \
                    OR length(after_message_id) < length(?1) \
                    OR (length(after_message_id) = length(?1) AND after_message_id < ?1))",
                params![
                    commit.message_id,
                    completed_at_ms,
                    commit.binding_id.to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed_receipt != 1 || changed_cursor != 1 {
            return Err(DiscordChannelStoreError::Conflict);
        }
        transaction.commit().map_err(map_sqlite_error)
    }

    fn record_discord_poll(
        &mut self,
        commit: RecordDiscordPollCommit,
    ) -> Result<(), DiscordChannelStoreError> {
        if commit.succeeded != commit.error_code.is_none()
            || commit.error_code.as_deref().is_some_and(|code| {
                code.is_empty()
                    || code.len() > DISCORD_MAXIMUM_ERROR_CODE_BYTES
                    || code.trim() != code
                    || code.chars().any(char::is_control)
            })
        {
            return Err(invalid_contract("Discord poll health evidence is invalid"));
        }
        let observed_at_ms = epoch_milliseconds(commit.observed_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        if load_binding(&transaction, commit.binding_id)?.status != DiscordChannelStatus::Active {
            return Err(DiscordChannelStoreError::Revoked);
        }
        let changed = if commit.succeeded {
            transaction.execute(
                "UPDATE discord_channel_health SET last_success_at_ms = ?1, \
                    consecutive_failures = 0, last_error_code = NULL, revision = revision + 1, \
                    updated_at_ms = ?1 WHERE binding_id = ?2",
                params![observed_at_ms, commit.binding_id.to_string()],
            )
        } else {
            transaction.execute(
                "UPDATE discord_channel_health SET last_failure_at_ms = ?1, \
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
            return Err(DiscordChannelStoreError::Conflict);
        }
        transaction.commit().map_err(map_sqlite_error)
    }

    fn outbound_discord_target(
        &self,
        session_id: SessionId,
        topic: &str,
    ) -> Result<Option<OutboundDiscordTarget>, DiscordChannelStoreError> {
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
                "SELECT binding.binding_id, binding.discord_channel_id, binding.bot_user_id, \
                        binding.token_secret_id, binding.token_digest \
                 FROM session \
                 JOIN discord_channel_binding binding \
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
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(map_sqlite_error)?;
        target
            .map(|row| {
                if !validate_discord_snowflake(&row.1)
                    || !validate_discord_snowflake(&row.2)
                    || !mealy_application::valid_provider_secret_id(&row.3)
                    || !is_sha256_digest(&row.4)
                {
                    return Err(invariant("Discord outbox target is invalid"));
                }
                Ok(OutboundDiscordTarget {
                    binding_id: parse_id(&row.0, "Discord binding ID")?,
                    discord_channel_id: row.1,
                    bot_user_id: row.2,
                    token_secret_id: row.3,
                    token_digest: row.4,
                })
            })
            .transpose()
    }
}

fn append_revocation_event(
    transaction: &Transaction<'_>,
    commit: &RevokeDiscordChannelCommit,
    principal_id: PrincipalId,
    revoked_at_ms: i64,
) -> Result<(), DiscordChannelStoreError> {
    let sequence = transaction
        .query_row(
            "SELECT sequence FROM aggregate_sequence \
             WHERE aggregate_kind = 'channel_binding' AND aggregate_id = ?1",
            [commit.binding_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .map_err(map_sqlite_error)?;
    if sequence != 0 {
        return Err(invariant("Discord channel sequence is invalid"));
    }
    transaction
        .execute(
            "INSERT INTO journal_event(\
                event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                event_version, occurred_at_ms, actor_principal_id, correlation_id, sensitivity, \
                payload_json\
             ) VALUES (?1, 'channel_binding', ?2, 1, 'channel.discord_revoked', 1, ?3, ?4, ?5, \
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
        Err(DiscordChannelStoreError::Conflict)
    }
}

fn authorize_administrator(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
) -> Result<(), DiscordChannelStoreError> {
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
        Err(DiscordChannelStoreError::NotFound)
    }
}

fn load_binding(
    connection: &rusqlite::Connection,
    binding_id: ChannelBindingId,
) -> Result<DiscordChannelBindingView, DiscordChannelStoreError> {
    let row = connection
        .query_row(
            "SELECT binding.principal_id, binding.session_id, binding.discord_user_id, \
                    binding.discord_channel_id, binding.bot_user_id, binding.bot_username, \
                    binding.token_secret_id, binding.token_digest, binding.status, \
                    binding.revision, binding.created_at_ms, binding.updated_at_ms, \
                    cursor.after_message_id, health.last_success_at_ms, health.last_failure_at_ms, \
                    health.consecutive_failures, health.last_error_code, registry.principal_id, \
                    registry.channel_kind, registry.installation_id, registry.status, \
                    registry.revision \
             FROM discord_channel_binding binding \
             JOIN discord_channel_cursor cursor ON cursor.binding_id = binding.binding_id \
             JOIN discord_channel_health health ON health.binding_id = binding.binding_id \
             JOIN channel_binding_registry registry ON registry.binding_id = binding.binding_id \
             WHERE binding.binding_id = ?1",
            [binding_id.to_string()],
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
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, Option<String>>(12)?,
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
        .ok_or(DiscordChannelStoreError::NotFound)?;
    if row.0 != row.17
        || row.18 != "extension_channel"
        || row.19.as_deref() != Some(DISCORD_INSTALLATION_ID)
        || row.8 != row.20
        || row.9 != row.21
        || row
            .12
            .as_deref()
            .is_some_and(|id| !validate_discord_snowflake(id))
        || row.15 < 0
    {
        return Err(invariant("Discord binding and registry diverged"));
    }
    validate_discord_binding(&row.2, &row.3, &row.4, &row.5, &row.6, &row.7)
        .map_err(|_| invariant("stored Discord binding is invalid"))?;
    Ok(DiscordChannelBindingView {
        binding_id,
        principal_id: parse_id(&row.0, "Discord principal ID")?,
        session_id: parse_id(&row.1, "Discord session ID")?,
        discord_user_id: row.2,
        discord_channel_id: row.3,
        bot_user_id: row.4,
        bot_username: row.5,
        token_secret_id: row.6,
        token_digest: row.7,
        after_message_id: row.12,
        status: match row.8.as_str() {
            "active" => DiscordChannelStatus::Active,
            "revoked" => DiscordChannelStatus::Revoked,
            _ => return Err(invariant("Discord binding status is invalid")),
        },
        revision: nonnegative(row.9, "Discord binding revision")?,
        last_success_at_ms: row.13,
        last_failure_at_ms: row.14,
        consecutive_failures: nonnegative(row.15, "Discord consecutive failures")?,
        last_error_code: row.16,
        created_at_ms: row.10,
        updated_at_ms: row.11,
    })
}

fn snowflake_cmp(left: &str, right: &str) -> Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

fn valid_reason(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= DISCORD_MAXIMUM_IGNORE_REASON_BYTES
        && reason.trim() == reason
        && !reason.chars().any(char::is_control)
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, DiscordChannelStoreError> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invariant("Discord channel time precedes the Unix epoch"))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| invariant("Discord channel time exceeds SQLite"))
}

fn nonnegative(value: i64, field: &str) -> Result<u64, DiscordChannelStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("stored {field} is negative")))
}

fn to_i64(value: u64) -> Result<i64, DiscordChannelStoreError> {
    i64::try_from(value).map_err(|_| invalid_contract("Discord revision exceeds SQLite"))
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, DiscordChannelStoreError> {
    T::from_str(value).map_err(|_| invariant(format!("stored {field} is invalid")))
}

fn map_registration_error(error: rusqlite::Error) -> DiscordChannelStoreError {
    if matches!(
        error.sqlite_error_code(),
        Some(ErrorCode::ConstraintViolation)
    ) {
        DiscordChannelStoreError::Conflict
    } else {
        map_sqlite_error(error)
    }
}

#[allow(clippy::needless_pass_by_value)]
fn map_sqlite_error(error: rusqlite::Error) -> DiscordChannelStoreError {
    DiscordChannelStoreError::Unavailable(error.to_string())
}

fn invalid_contract(message: impl Into<String>) -> DiscordChannelStoreError {
    DiscordChannelStoreError::InvalidContract(message.into())
}

fn invariant(message: impl Into<String>) -> DiscordChannelStoreError {
    DiscordChannelStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::DiscordChannelStore;
    use mealy_application::{
        AdmitInputCommand, CompleteDiscordMessageCommit, DiscordChannelStatus,
        DiscordMessageDisposition, DiscordMessageReservation, InputAdmissionLimits,
        OwnershipContext, RecordDiscordPollCommit, RegisterDiscordChannelCommit,
        ReserveDiscordMessageCommit, RevokeDiscordChannelCommit, admit_input,
        discord_input_dedupe_key, sha256_digest,
    };
    use mealy_domain::{
        ChannelBindingId, CorrelationId, DeliveryMode, EventId, PrincipalId, SessionId,
    };
    use mealy_testkit::{TestClock, TestIdGenerator};
    use std::time::{Duration, SystemTime};

    #[test]
    #[allow(clippy::too_many_lines)]
    fn exact_dm_message_recovery_health_routing_and_revocation_are_durable() {
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
        let token_digest = sha256_digest(b"discord-token");
        let channel = store
            .register_discord_channel(RegisterDiscordChannelCommit {
                administrative_ownership: administrator,
                binding_id,
                session_id,
                discord_user_id: "18446744073709551610".to_owned(),
                discord_channel_id: "18446744073709551611".to_owned(),
                initial_after_message_id: Some("18446744073709551612".to_owned()),
                bot_user_id: "18446744073709551613".to_owned(),
                bot_username: "mealy_test_bot".to_owned(),
                token_secret_id: format!("discord.{binding_id}"),
                token_digest: token_digest.clone(),
                session_event_id: EventId::new(),
                binding_event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at: now,
            })
            .expect("register Discord channel");
        assert_eq!(channel.status, DiscordChannelStatus::Active);
        assert_eq!(
            channel.after_message_id.as_deref(),
            Some("18446744073709551612")
        );
        assert_eq!(
            store.active_discord_poll_targets(10).expect("poll targets")[0].token_digest,
            token_digest
        );

        let message_id = "18446744073709551614".to_owned();
        let body_digest = sha256_digest(br#"{"id":"18446744073709551614"}"#);
        assert_eq!(
            store
                .reserve_discord_message(ReserveDiscordMessageCommit {
                    binding_id,
                    message_id: message_id.clone(),
                    body_digest: body_digest.clone(),
                    received_at: now,
                })
                .expect("reserve message"),
            DiscordMessageReservation::Reserved
        );
        assert_eq!(
            store
                .reserve_discord_message(ReserveDiscordMessageCommit {
                    binding_id,
                    message_id: message_id.clone(),
                    body_digest: body_digest.clone(),
                    received_at: now,
                })
                .expect("recover reservation"),
            DiscordMessageReservation::ExistingReserved
        );
        let outcome = admit_input(
            &mut store,
            &clock,
            &ids,
            InputAdmissionLimits::default(),
            AdmitInputCommand {
                session_id,
                ownership: OwnershipContext::new(principal_id, binding_id),
                dedupe_key: discord_input_dedupe_key(binding_id, &message_id).expect("dedupe key"),
                delivery_mode: DeliveryMode::Queue,
                content: "hello from Discord".to_owned(),
            },
        )
        .expect("admit Discord input");
        store
            .complete_discord_message(CompleteDiscordMessageCommit {
                binding_id,
                message_id: message_id.clone(),
                disposition: DiscordMessageDisposition::Admitted(outcome.receipt().clone()),
                completed_at: now + Duration::from_millis(1),
            })
            .expect("complete message");
        assert_eq!(
            store
                .reserve_discord_message(ReserveDiscordMessageCommit {
                    binding_id,
                    message_id: message_id.clone(),
                    body_digest,
                    received_at: now,
                })
                .expect("recognize completed message"),
            DiscordMessageReservation::ExistingCompleted
        );
        assert_eq!(
            store
                .discord_channel(administrator, binding_id)
                .expect("advanced channel")
                .after_message_id,
            Some(message_id)
        );
        assert!(
            store
                .outbound_discord_target(session_id, "session.turn_completed")
                .expect("Discord route")
                .is_some()
        );

        store
            .record_discord_poll(RecordDiscordPollCommit {
                binding_id,
                succeeded: false,
                error_code: Some("discord_rate_limited".to_owned()),
                observed_at: now + Duration::from_millis(2),
            })
            .expect("failed health");
        assert_eq!(
            store
                .discord_channel(administrator, binding_id)
                .expect("failed health view")
                .consecutive_failures,
            1
        );
        store
            .record_discord_poll(RecordDiscordPollCommit {
                binding_id,
                succeeded: true,
                error_code: None,
                observed_at: now + Duration::from_millis(3),
            })
            .expect("healthy poll");
        let revoked = store
            .revoke_discord_channel(RevokeDiscordChannelCommit {
                administrative_ownership: administrator,
                binding_id,
                expected_revision: 0,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                revoked_at: now + Duration::from_millis(4),
            })
            .expect("revoke channel");
        assert_eq!(revoked.status, DiscordChannelStatus::Revoked);
        assert!(
            store
                .active_discord_poll_targets(10)
                .expect("no active targets")
                .is_empty()
        );
    }
}
