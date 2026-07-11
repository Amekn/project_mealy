use super::SqliteStore;
use mealy_application::{
    CompleteWebhookDeliveryCommit, OutboundWebhookTarget, OwnershipContext,
    RegisterWebhookChannelCommit, ReserveWebhookDeliveryCommit, RevokeWebhookChannelCommit,
    WebhookChannelBindingView, WebhookChannelStatus, WebhookChannelStore, WebhookChannelStoreError,
    WebhookDeliveryReservation, is_sha256_digest, sha256_digest, validate_webhook_binding_fields,
    webhook_input_dedupe_key,
};
use mealy_domain::{ChannelBindingId, PrincipalId, SessionId};
use rusqlite::{ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use std::{str::FromStr, time::SystemTime};

const SIGNED_WEBHOOK_INSTALLATION_ID: &str = "builtin.signed_webhook.v1";

impl WebhookChannelStore for SqliteStore {
    #[allow(clippy::too_many_lines)]
    fn register_webhook_channel(
        &mut self,
        commit: RegisterWebhookChannelCommit,
    ) -> Result<WebhookChannelBindingView, WebhookChannelStoreError> {
        validate_webhook_binding_fields(
            &commit.external_subject,
            &commit.callback_url,
            &commit.secret_digest,
        )
        .map_err(|error| invalid_contract(error.to_string()))?;
        let created_at_ms = epoch_milliseconds(commit.created_at)?;
        let principal_id = commit.administrative_ownership.principal_id();
        let external_subject_digest = sha256_digest(commit.external_subject.as_bytes());
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
                 ) VALUES (?1, ?2, 'signed_webhook', 'active', 0, ?3, ?4, ?5, ?6, ?6)",
                params![
                    commit.binding_id.to_string(),
                    principal_id.to_string(),
                    SIGNED_WEBHOOK_INSTALLATION_ID,
                    commit.external_subject,
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
                        "channel_kind": "signed_webhook",
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
                 ) VALUES (?1, 'channel_binding', ?2, 0, 'channel.webhook_registered', 1, ?3, \
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
                        "external_subject_digest": external_subject_digest,
                        "secret_digest": commit.secret_digest,
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
                "INSERT INTO webhook_channel_binding(\
                    binding_id, principal_id, session_id, external_subject, callback_url, \
                    secret_digest, status, revision, created_event_id, created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', 0, ?7, ?8, ?8)",
                params![
                    commit.binding_id.to_string(),
                    principal_id.to_string(),
                    commit.session_id.to_string(),
                    commit.external_subject,
                    commit.callback_url,
                    commit.secret_digest,
                    commit.binding_event_id.to_string(),
                    created_at_ms,
                ],
            )
            .map_err(map_registration_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_binding(&self.connection, commit.binding_id)
    }

    fn revoke_webhook_channel(
        &mut self,
        commit: RevokeWebhookChannelCommit,
    ) -> Result<WebhookChannelBindingView, WebhookChannelStoreError> {
        let revoked_at_ms = epoch_milliseconds(commit.revoked_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        authorize_administrator(&transaction, commit.administrative_ownership)?;
        let current = load_binding(&transaction, commit.binding_id)?;
        if current.principal_id != commit.administrative_ownership.principal_id() {
            return Err(WebhookChannelStoreError::NotFound);
        }
        if current.status != WebhookChannelStatus::Active
            || current.revision != commit.expected_revision
        {
            return Err(WebhookChannelStoreError::Conflict);
        }
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
                    to_i64(commit.expected_revision)?,
                ],
            )
            .map_err(map_sqlite_error)?;
        let changed_binding = transaction
            .execute(
                "UPDATE webhook_channel_binding SET status = 'revoked', revision = revision + 1, \
                    updated_at_ms = ?1, revoked_at_ms = ?1 \
                 WHERE binding_id = ?2 AND principal_id = ?3 AND status = 'active' \
                   AND revision = ?4",
                params![
                    revoked_at_ms,
                    commit.binding_id.to_string(),
                    current.principal_id.to_string(),
                    to_i64(commit.expected_revision)?,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed_registry != 1 || changed_binding != 1 {
            return Err(WebhookChannelStoreError::Conflict);
        }
        append_revocation_event(&transaction, &commit, current.principal_id, revoked_at_ms)?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_binding(&self.connection, commit.binding_id)
    }

    fn webhook_channel_for_verification(
        &self,
        binding_id: ChannelBindingId,
    ) -> Result<WebhookChannelBindingView, WebhookChannelStoreError> {
        load_binding(&self.connection, binding_id)
    }

    fn webhook_channel(
        &self,
        ownership: OwnershipContext,
        binding_id: ChannelBindingId,
    ) -> Result<WebhookChannelBindingView, WebhookChannelStoreError> {
        authorize_administrator(&self.connection, ownership)?;
        let view = load_binding(&self.connection, binding_id)?;
        if view.principal_id == ownership.principal_id() {
            Ok(view)
        } else {
            Err(WebhookChannelStoreError::NotFound)
        }
    }

    fn webhook_channels(
        &self,
        ownership: OwnershipContext,
    ) -> Result<Vec<WebhookChannelBindingView>, WebhookChannelStoreError> {
        authorize_administrator(&self.connection, ownership)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT binding_id FROM webhook_channel_binding WHERE principal_id = ?1 \
                 ORDER BY created_at_ms, binding_id",
            )
            .map_err(map_sqlite_error)?;
        let ids = statement
            .query_map([ownership.principal_id().to_string()], |row| {
                row.get::<_, String>(0)
            })
            .map_err(map_sqlite_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_sqlite_error)?;
        ids.into_iter()
            .map(|id| load_binding(&self.connection, parse_id(&id, "webhook binding ID")?))
            .collect()
    }

    fn reserve_webhook_delivery(
        &mut self,
        commit: ReserveWebhookDeliveryCommit,
    ) -> Result<WebhookDeliveryReservation, WebhookChannelStoreError> {
        webhook_input_dedupe_key(commit.binding_id, &commit.delivery_id)
            .map_err(|error| invalid_contract(error.to_string()))?;
        if commit.nonce.is_empty()
            || commit.nonce.len() > mealy_application::WEBHOOK_MAXIMUM_NONCE_BYTES
            || commit.nonce.trim() != commit.nonce
            || commit.nonce.chars().any(char::is_control)
            || !is_sha256_digest(&commit.body_digest)
            || !is_sha256_digest(&commit.signature_digest)
        {
            return Err(invalid_contract("webhook replay evidence is invalid"));
        }
        let received_at_ms = epoch_milliseconds(commit.received_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let binding = load_binding(&transaction, commit.binding_id)?;
        if binding.status != WebhookChannelStatus::Active {
            return Err(WebhookChannelStoreError::Revoked);
        }
        let existing = transaction
            .query_row(
                "SELECT body_digest FROM webhook_delivery_receipt \
                 WHERE binding_id = ?1 AND delivery_id = ?2",
                params![commit.binding_id.to_string(), commit.delivery_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(map_sqlite_error)?;
        if let Some(body_digest) = existing {
            if body_digest == commit.body_digest {
                transaction.commit().map_err(map_sqlite_error)?;
                return Ok(WebhookDeliveryReservation::Existing);
            }
            return Err(WebhookChannelStoreError::Conflict);
        }
        let nonce_consumed = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM webhook_delivery_receipt \
                 WHERE binding_id = ?1 AND nonce = ?2)",
                params![commit.binding_id.to_string(), commit.nonce],
                |row| row.get::<_, bool>(0),
            )
            .map_err(map_sqlite_error)?;
        if nonce_consumed {
            return Err(WebhookChannelStoreError::Replay);
        }
        transaction
            .execute(
                "INSERT INTO webhook_delivery_receipt(\
                    binding_id, delivery_id, nonce, body_digest, signature_digest, state, \
                    session_id, received_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'reserved', ?6, ?7)",
                params![
                    commit.binding_id.to_string(),
                    commit.delivery_id,
                    commit.nonce,
                    commit.body_digest,
                    commit.signature_digest,
                    binding.session_id.to_string(),
                    received_at_ms,
                ],
            )
            .map_err(map_reservation_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(WebhookDeliveryReservation::Reserved)
    }

    fn complete_webhook_delivery(
        &mut self,
        commit: CompleteWebhookDeliveryCommit,
    ) -> Result<(), WebhookChannelStoreError> {
        webhook_input_dedupe_key(commit.binding_id, &commit.delivery_id)
            .map_err(|error| invalid_contract(error.to_string()))?;
        let completed_at_ms = epoch_milliseconds(commit.completed_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let binding = load_binding(&transaction, commit.binding_id)?;
        if binding.session_id != commit.admission.session_id {
            return Err(invalid_contract(
                "webhook receipt session does not bind the channel",
            ));
        }
        let current = transaction
            .query_row(
                "SELECT state, inbox_entry_id, acknowledgement_outbox_id \
                 FROM webhook_delivery_receipt WHERE binding_id = ?1 AND delivery_id = ?2",
                params![commit.binding_id.to_string(), commit.delivery_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(map_sqlite_error)?
            .ok_or(WebhookChannelStoreError::Conflict)?;
        if current.0 == "completed" {
            if current.1.as_deref() == Some(commit.admission.inbox_entry_id.to_string().as_str())
                && current.2.as_deref() == Some(commit.admission.outbox_id.to_string().as_str())
            {
                transaction.commit().map_err(map_sqlite_error)?;
                return Ok(());
            }
            return Err(WebhookChannelStoreError::Conflict);
        }
        let changed = transaction
            .execute(
                "UPDATE webhook_delivery_receipt SET state = 'completed', inbox_entry_id = ?1, \
                    acknowledgement_outbox_id = ?2, completed_at_ms = ?3 \
                 WHERE binding_id = ?4 AND delivery_id = ?5 AND state = 'reserved' \
                   AND received_at_ms <= ?3",
                params![
                    commit.admission.inbox_entry_id.to_string(),
                    commit.admission.outbox_id.to_string(),
                    completed_at_ms,
                    commit.binding_id.to_string(),
                    commit.delivery_id,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(WebhookChannelStoreError::Conflict);
        }
        transaction.commit().map_err(map_sqlite_error)
    }

    fn outbound_webhook_target(
        &self,
        session_id: SessionId,
        topic: &str,
    ) -> Result<Option<OutboundWebhookTarget>, WebhookChannelStoreError> {
        if !matches!(
            topic,
            "session.input_acknowledgement" | "session.turn_completed"
        ) {
            return Ok(None);
        }
        let target = self
            .connection
            .query_row(
                "SELECT binding.binding_id, binding.callback_url, binding.secret_digest \
                 FROM session \
                 JOIN webhook_channel_binding binding \
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
                    ))
                },
            )
            .optional()
            .map_err(map_sqlite_error)?;
        target
            .map(|(binding_id, callback_url, secret_digest)| {
                if !is_sha256_digest(&secret_digest) {
                    return Err(invariant("webhook target secret digest is invalid"));
                }
                Ok(OutboundWebhookTarget {
                    binding_id: parse_id(&binding_id, "webhook binding ID")?,
                    callback_url,
                    secret_digest,
                })
            })
            .transpose()
    }
}

fn append_revocation_event(
    transaction: &Transaction<'_>,
    commit: &RevokeWebhookChannelCommit,
    principal_id: PrincipalId,
    revoked_at_ms: i64,
) -> Result<(), WebhookChannelStoreError> {
    let sequence = transaction
        .query_row(
            "SELECT sequence FROM aggregate_sequence \
             WHERE aggregate_kind = 'channel_binding' AND aggregate_id = ?1",
            [commit.binding_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .map_err(map_sqlite_error)?;
    if sequence != 0 {
        return Err(invariant("webhook channel sequence is invalid"));
    }
    transaction
        .execute(
            "INSERT INTO journal_event(\
                event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                event_version, occurred_at_ms, actor_principal_id, correlation_id, sensitivity, \
                payload_json\
             ) VALUES (?1, 'channel_binding', ?2, 1, 'channel.webhook_revoked', 1, ?3, ?4, ?5, \
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
        Err(WebhookChannelStoreError::Conflict)
    }
}

fn authorize_administrator(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
) -> Result<(), WebhookChannelStoreError> {
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
        Err(WebhookChannelStoreError::NotFound)
    }
}

fn load_binding(
    connection: &rusqlite::Connection,
    binding_id: ChannelBindingId,
) -> Result<WebhookChannelBindingView, WebhookChannelStoreError> {
    let row = connection
        .query_row(
            "SELECT binding.principal_id, binding.session_id, binding.external_subject, \
                    binding.callback_url, binding.secret_digest, binding.status, \
                    binding.revision, binding.created_at_ms, binding.updated_at_ms, \
                    registry.principal_id, registry.channel_kind, registry.status, \
                    registry.revision \
             FROM webhook_channel_binding binding \
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
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, i64>(12)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(WebhookChannelStoreError::NotFound)?;
    if row.0 != row.9
        || row.10 != "signed_webhook"
        || row.5 != row.11
        || row.6 != row.12
        || !is_sha256_digest(&row.4)
    {
        return Err(invariant("webhook binding and identity registry diverged"));
    }
    Ok(WebhookChannelBindingView {
        binding_id,
        principal_id: parse_id(&row.0, "webhook principal ID")?,
        session_id: parse_id(&row.1, "webhook session ID")?,
        external_subject: row.2,
        callback_url: row.3,
        secret_digest: row.4,
        status: match row.5.as_str() {
            "active" => WebhookChannelStatus::Active,
            "revoked" => WebhookChannelStatus::Revoked,
            _ => return Err(invariant("webhook binding status is invalid")),
        },
        revision: nonnegative(row.6, "webhook binding revision")?,
        created_at_ms: row.7,
        updated_at_ms: row.8,
    })
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, WebhookChannelStoreError> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invariant("webhook channel time is before the Unix epoch"))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| invariant("webhook channel time exceeds SQLite"))
}

fn nonnegative(value: i64, field: &str) -> Result<u64, WebhookChannelStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("stored {field} is negative")))
}

fn to_i64(value: u64) -> Result<i64, WebhookChannelStoreError> {
    i64::try_from(value).map_err(|_| invalid_contract("webhook revision exceeds SQLite"))
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, WebhookChannelStoreError> {
    T::from_str(value).map_err(|_| invariant(format!("stored {field} is invalid")))
}

fn map_registration_error(error: rusqlite::Error) -> WebhookChannelStoreError {
    if matches!(
        error.sqlite_error_code(),
        Some(ErrorCode::ConstraintViolation)
    ) {
        WebhookChannelStoreError::Conflict
    } else {
        map_sqlite_error(error)
    }
}

fn map_reservation_error(error: rusqlite::Error) -> WebhookChannelStoreError {
    if matches!(
        error.sqlite_error_code(),
        Some(ErrorCode::ConstraintViolation)
    ) {
        WebhookChannelStoreError::Replay
    } else {
        map_sqlite_error(error)
    }
}

#[allow(clippy::needless_pass_by_value)]
fn map_sqlite_error(error: rusqlite::Error) -> WebhookChannelStoreError {
    WebhookChannelStoreError::Unavailable(error.to_string())
}

fn invalid_contract(message: impl Into<String>) -> WebhookChannelStoreError {
    WebhookChannelStoreError::InvalidContract(message.into())
}

fn invariant(message: impl Into<String>) -> WebhookChannelStoreError {
    WebhookChannelStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::WebhookChannelStore;
    use mealy_application::{
        AdmitInputCommand, CompleteWebhookDeliveryCommit, InputAdmissionLimits, OwnershipContext,
        RegisterWebhookChannelCommit, ReserveWebhookDeliveryCommit, RevokeWebhookChannelCommit,
        WebhookChannelStatus, WebhookChannelStoreError, WebhookDeliveryReservation, admit_input,
        sha256_digest,
    };
    use mealy_domain::{
        ChannelBindingId, CorrelationId, DeliveryMode, EventId, PrincipalId, SessionId,
    };
    use mealy_testkit::{TestClock, TestIdGenerator};
    use std::time::{Duration, SystemTime};

    #[test]
    #[allow(clippy::too_many_lines)]
    fn binding_reservation_admission_outbox_routing_and_revocation_are_durable() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock = TestClock::new(1_700_000_000_000);
        let ids = TestIdGenerator::new(1_700_000_000_000);
        let mut store = super::SqliteStore::open_in_memory(1).expect("store");
        let principal_id = PrincipalId::new();
        let administrator = OwnershipContext::new(principal_id, ChannelBindingId::new());
        store
            .register_local_identity(administrator, 1)
            .expect("local administrator");
        let binding_id = ChannelBindingId::new();
        let session_id = SessionId::new();
        let binding = store
            .register_webhook_channel(RegisterWebhookChannelCommit {
                administrative_ownership: administrator,
                binding_id,
                session_id,
                external_subject: "platform-user-7".to_owned(),
                callback_url: "http://127.0.0.1:4318/callback".to_owned(),
                secret_digest: "a".repeat(64),
                session_event_id: EventId::new(),
                binding_event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at: now,
            })
            .expect("register signed channel");
        assert_eq!(binding.status, WebhookChannelStatus::Active);
        assert_eq!(binding.session_id, session_id);
        assert!(
            store
                .outbound_webhook_target(session_id, "session.input_acknowledgement")
                .expect("outbound target")
                .is_some()
        );

        let reservation = ReserveWebhookDeliveryCommit {
            binding_id,
            delivery_id: "delivery-1".to_owned(),
            nonce: "nonce-1".to_owned(),
            body_digest: sha256_digest(b"body-1"),
            signature_digest: sha256_digest(b"signature-1"),
            received_at: now,
        };
        assert_eq!(
            store
                .reserve_webhook_delivery(reservation.clone())
                .expect("reserve delivery"),
            WebhookDeliveryReservation::Reserved
        );
        assert_eq!(
            store
                .reserve_webhook_delivery(reservation.clone())
                .expect("recognize exact delivery"),
            WebhookDeliveryReservation::Existing
        );
        let mut replay = reservation.clone();
        replay.delivery_id = "delivery-2".to_owned();
        replay.body_digest = sha256_digest(b"body-2");
        assert_eq!(
            store.reserve_webhook_delivery(replay),
            Err(WebhookChannelStoreError::Replay)
        );

        let external_ownership = OwnershipContext::new(principal_id, binding_id);
        let admission = admit_input(
            &mut store,
            &clock,
            &ids,
            InputAdmissionLimits::default(),
            AdmitInputCommand {
                session_id,
                ownership: external_ownership,
                dedupe_key: format!("webhook:{binding_id}:delivery-1"),
                delivery_mode: DeliveryMode::Queue,
                content: "signed hello".to_owned(),
            },
        )
        .expect("admit verified channel input")
        .receipt()
        .clone();
        let completion = CompleteWebhookDeliveryCommit {
            binding_id,
            delivery_id: "delivery-1".to_owned(),
            admission,
            completed_at: now,
        };
        store
            .complete_webhook_delivery(completion.clone())
            .expect("complete receipt");
        store
            .complete_webhook_delivery(completion)
            .expect("idempotent completion");

        let revoked = store
            .revoke_webhook_channel(RevokeWebhookChannelCommit {
                administrative_ownership: administrator,
                binding_id,
                expected_revision: 0,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                revoked_at: now,
            })
            .expect("terminal revocation");
        assert_eq!(revoked.status, WebhookChannelStatus::Revoked);
        assert!(
            store
                .outbound_webhook_target(session_id, "session.input_acknowledgement")
                .expect("revoked route")
                .is_none()
        );
        let mut after_revoke = reservation;
        after_revoke.delivery_id = "delivery-3".to_owned();
        after_revoke.nonce = "nonce-3".to_owned();
        after_revoke.body_digest = sha256_digest(b"body-3");
        assert_eq!(
            store.reserve_webhook_delivery(after_revoke),
            Err(WebhookChannelStoreError::Revoked)
        );
    }
}
