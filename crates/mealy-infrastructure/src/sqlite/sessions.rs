use super::SqliteStore;
use mealy_application::{
    InputAdmissionCommit, InputAdmissionOutcome, InputAdmissionReceipt, SessionCreationCommit,
    SessionStore, SessionStoreError,
};
use mealy_domain::{DeliveryMode, SessionId};
use rusqlite::{ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use std::{fmt::Display, str::FromStr, time::SystemTime};

impl SessionStore for SqliteStore {
    fn create_session(&mut self, commit: SessionCreationCommit) -> Result<(), SessionStoreError> {
        let created_at_ms = epoch_milliseconds(commit.created_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;

        transaction
            .execute(
                "INSERT INTO session(\
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?4)",
                params![
                    commit.session_id.to_string(),
                    commit.ownership.principal_id().to_string(),
                    commit.ownership.channel_binding_id().to_string(),
                    created_at_ms,
                ],
            )
            .map_err(map_sqlite_error)?;

        transaction
            .execute(
                "INSERT INTO journal_event(\
                    event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                    event_version, occurred_at_ms, actor_principal_id, correlation_id, \
                    sensitivity, payload_json\
                 ) VALUES (?1, 'session', ?2, 0, 'session.created', 1, ?3, ?4, ?5, \
                           'private', ?6)",
                params![
                    commit.event_id.to_string(),
                    commit.session_id.to_string(),
                    created_at_ms,
                    commit.ownership.principal_id().to_string(),
                    commit.correlation_id.to_string(),
                    json!({
                        "channel_binding_id": commit.ownership.channel_binding_id(),
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
        transaction.commit().map_err(map_sqlite_error)
    }

    fn admit_input(
        &mut self,
        commit: InputAdmissionCommit,
    ) -> Result<InputAdmissionOutcome, SessionStoreError> {
        let accepted_at_ms = epoch_milliseconds(commit.accepted_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;

        if !active_identity(&transaction, commit.ownership)? {
            return Err(SessionStoreError::Unauthorized);
        }

        let session = load_session(&transaction, commit.session_id)?;

        if session.principal_id != commit.ownership.principal_id().to_string()
            || session.channel_binding_id != commit.ownership.channel_binding_id().to_string()
        {
            return Err(SessionStoreError::Unauthorized);
        }

        if let Some(stored) = load_admission(&transaction, commit.session_id, &commit.dedupe_key)? {
            if stored.delivery_mode != commit.delivery_mode.as_str()
                || stored.content != commit.content
            {
                return Err(SessionStoreError::IdempotencyConflict);
            }
            return stored
                .into_receipt(commit.session_id)
                .map(InputAdmissionOutcome::Duplicate);
        }

        let pending_inputs = transaction
            .query_row(
                "SELECT COUNT(*) FROM session_inbox WHERE session_id = ?1 AND state = 'pending'",
                [commit.session_id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(map_sqlite_error)?;
        let maximum_pending_inputs = i64::try_from(commit.maximum_pending_inputs)
            .map_err(|_| invariant("session pending-input limit exceeds SQLite"))?;
        if maximum_pending_inputs == 0 || pending_inputs >= maximum_pending_inputs {
            return Err(SessionStoreError::Backpressure);
        }

        let inbox_sequence =
            insert_inbox_and_advance(&transaction, &commit, &session, accepted_at_ms)?;
        append_input_journal(&transaction, &commit, inbox_sequence, accepted_at_ms)?;
        append_acknowledgement(&transaction, &commit, inbox_sequence, accepted_at_ms)?;
        let timeline_cursor = admission_cursor(&transaction, &commit.event_id.to_string())?;

        transaction.commit().map_err(map_sqlite_error)?;
        Ok(InputAdmissionOutcome::Accepted(InputAdmissionReceipt {
            session_id: commit.session_id,
            inbox_entry_id: commit.inbox_entry_id,
            inbox_sequence,
            delivery_mode: commit.delivery_mode,
            event_id: commit.event_id,
            outbox_id: commit.outbox_id,
            correlation_id: commit.correlation_id,
            accepted_at: system_time_from_epoch_milliseconds(accepted_at_ms)?,
            timeline_cursor,
        }))
    }
}

fn active_identity(
    transaction: &Transaction<'_>,
    ownership: mealy_application::OwnershipContext,
) -> Result<bool, SessionStoreError> {
    transaction
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
            |row| row.get(0),
        )
        .map_err(map_sqlite_error)
}

struct SessionRow {
    principal_id: String,
    channel_binding_id: String,
    next_inbox_sequence: i64,
    revision: i64,
}

struct StoredAdmission {
    inbox_entry_id: String,
    inbox_sequence: i64,
    delivery_mode: String,
    content: String,
    event_id: String,
    outbox_id: String,
    correlation_id: String,
    accepted_at_ms: i64,
    timeline_cursor: i64,
}

fn load_session(
    transaction: &Transaction<'_>,
    session_id: SessionId,
) -> Result<SessionRow, SessionStoreError> {
    transaction
        .query_row(
            "SELECT principal_id, channel_binding_id, next_inbox_sequence, revision \
             FROM session WHERE id = ?1",
            [session_id.to_string()],
            |row| {
                Ok(SessionRow {
                    principal_id: row.get(0)?,
                    channel_binding_id: row.get(1)?,
                    next_inbox_sequence: row.get(2)?,
                    revision: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(SessionStoreError::SessionNotFound)
}

fn insert_inbox_and_advance(
    transaction: &Transaction<'_>,
    commit: &InputAdmissionCommit,
    session: &SessionRow,
    accepted_at_ms: i64,
) -> Result<u64, SessionStoreError> {
    let inbox_sequence = positive_u64(session.next_inbox_sequence, "inbox sequence")?;
    let following_sequence = session
        .next_inbox_sequence
        .checked_add(1)
        .ok_or_else(|| invariant("session inbox sequence overflow"))?;
    let following_revision = session
        .revision
        .checked_add(1)
        .ok_or_else(|| invariant("session revision overflow"))?;

    transaction
        .execute(
            "INSERT INTO session_inbox(\
                inbox_entry_id, session_id, sequence, dedupe_key, delivery_mode, content, \
                admission_event_id, acknowledgement_outbox_id, correlation_id, accepted_at_ms\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                commit.inbox_entry_id.to_string(),
                commit.session_id.to_string(),
                session.next_inbox_sequence,
                commit.dedupe_key,
                commit.delivery_mode.as_str(),
                commit.content,
                commit.event_id.to_string(),
                commit.outbox_id.to_string(),
                commit.correlation_id.to_string(),
                accepted_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;

    let updated = transaction
        .execute(
            "UPDATE session \
             SET next_inbox_sequence = ?1, revision = ?2, updated_at_ms = MAX(updated_at_ms, ?3) \
             WHERE id = ?4 AND principal_id = ?5 AND channel_binding_id = ?6 \
               AND next_inbox_sequence = ?7 AND revision = ?8",
            params![
                following_sequence,
                following_revision,
                accepted_at_ms,
                commit.session_id.to_string(),
                commit.ownership.principal_id().to_string(),
                commit.ownership.channel_binding_id().to_string(),
                session.next_inbox_sequence,
                session.revision,
            ],
        )
        .map_err(map_sqlite_error)?;
    if updated != 1 {
        return Err(SessionStoreError::Conflict);
    }
    Ok(inbox_sequence)
}

fn append_input_journal(
    transaction: &Transaction<'_>,
    commit: &InputAdmissionCommit,
    inbox_sequence: u64,
    accepted_at_ms: i64,
) -> Result<(), SessionStoreError> {
    let journal_sequence = next_journal_sequence(transaction, commit.session_id)?;
    transaction
        .execute(
            "INSERT INTO journal_event(\
                event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                event_version, occurred_at_ms, actor_principal_id, correlation_id, \
                sensitivity, payload_json\
             ) VALUES (?1, 'session', ?2, ?3, 'input.accepted', 1, ?4, ?5, ?6, \
                       'private', ?7)",
            params![
                commit.event_id.to_string(),
                commit.session_id.to_string(),
                journal_sequence,
                accepted_at_ms,
                commit.ownership.principal_id().to_string(),
                commit.correlation_id.to_string(),
                json!({
                    "inbox_entry_id": commit.inbox_entry_id,
                    "inbox_sequence": inbox_sequence,
                    "delivery_mode": commit.delivery_mode,
                })
                .to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    transaction
        .execute(
            "UPDATE aggregate_sequence SET sequence = ?1 \
             WHERE aggregate_kind = 'session' AND aggregate_id = ?2",
            params![journal_sequence, commit.session_id.to_string()],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn append_acknowledgement(
    transaction: &Transaction<'_>,
    commit: &InputAdmissionCommit,
    inbox_sequence: u64,
    accepted_at_ms: i64,
) -> Result<(), SessionStoreError> {
    transaction
        .execute(
            "INSERT INTO outbox(outbox_id, topic, payload_json, created_at_ms) \
             VALUES (?1, 'session.input_acknowledgement', ?2, ?3)",
            params![
                commit.outbox_id.to_string(),
                json!({
                    "session_id": commit.session_id,
                    "inbox_entry_id": commit.inbox_entry_id,
                    "inbox_sequence": inbox_sequence,
                    "event_id": commit.event_id,
                })
                .to_string(),
                accepted_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

impl StoredAdmission {
    fn into_receipt(
        self,
        session_id: SessionId,
    ) -> Result<InputAdmissionReceipt, SessionStoreError> {
        Ok(InputAdmissionReceipt {
            session_id,
            inbox_entry_id: parse_id(&self.inbox_entry_id, "inbox entry ID")?,
            inbox_sequence: positive_u64(self.inbox_sequence, "inbox sequence")?,
            delivery_mode: parse_delivery_mode(&self.delivery_mode)?,
            event_id: parse_id(&self.event_id, "event ID")?,
            outbox_id: parse_id(&self.outbox_id, "outbox ID")?,
            correlation_id: parse_id(&self.correlation_id, "correlation ID")?,
            accepted_at: system_time_from_epoch_milliseconds(self.accepted_at_ms)?,
            timeline_cursor: positive_u64(self.timeline_cursor, "admission timeline cursor")?,
        })
    }
}

fn load_admission(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    dedupe_key: &str,
) -> Result<Option<StoredAdmission>, SessionStoreError> {
    transaction
        .query_row(
            "SELECT i.inbox_entry_id, i.sequence, i.delivery_mode, i.content, \
                    i.admission_event_id, i.acknowledgement_outbox_id, i.correlation_id, \
                    i.accepted_at_ms, te.cursor \
             FROM session_inbox i \
             JOIN timeline_event te ON te.event_id = i.admission_event_id \
             WHERE i.session_id = ?1 AND i.dedupe_key = ?2",
            params![session_id.to_string(), dedupe_key],
            |row| {
                Ok(StoredAdmission {
                    inbox_entry_id: row.get(0)?,
                    inbox_sequence: row.get(1)?,
                    delivery_mode: row.get(2)?,
                    content: row.get(3)?,
                    event_id: row.get(4)?,
                    outbox_id: row.get(5)?,
                    correlation_id: row.get(6)?,
                    accepted_at_ms: row.get(7)?,
                    timeline_cursor: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)
}

fn admission_cursor(
    transaction: &Transaction<'_>,
    event_id: &str,
) -> Result<u64, SessionStoreError> {
    let cursor = transaction
        .query_row(
            "SELECT cursor FROM timeline_event WHERE event_id = ?1",
            [event_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or_else(|| invariant("accepted input is missing its timeline cursor"))?;
    positive_u64(cursor, "admission timeline cursor")
}

fn next_journal_sequence(
    transaction: &Transaction<'_>,
    session_id: SessionId,
) -> Result<i64, SessionStoreError> {
    let current = transaction
        .query_row(
            "SELECT sequence FROM aggregate_sequence \
             WHERE aggregate_kind = 'session' AND aggregate_id = ?1",
            [session_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or_else(|| invariant("session aggregate sequence is missing"))?;
    current
        .checked_add(1)
        .ok_or_else(|| invariant("session journal sequence overflow"))
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, SessionStoreError> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invariant("application clock returned a time before the Unix epoch"))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| invariant("application clock exceeds the SQLite timestamp range"))
}

fn system_time_from_epoch_milliseconds(value: i64) -> Result<SystemTime, SessionStoreError> {
    let milliseconds = u64::try_from(value)
        .map_err(|_| invariant("stored acceptance time precedes the Unix epoch"))?;
    SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_millis(milliseconds))
        .ok_or_else(|| invariant("stored acceptance time exceeds SystemTime"))
}

fn positive_u64(value: i64, field: &str) -> Result<u64, SessionStoreError> {
    let value =
        u64::try_from(value).map_err(|_| invariant(format!("stored {field} is negative")))?;
    if value == 0 {
        return Err(invariant(format!("stored {field} is zero")));
    }
    Ok(value)
}

fn parse_id<T>(value: &str, field: &str) -> Result<T, SessionStoreError>
where
    T: FromStr,
    T::Err: Display,
{
    value
        .parse()
        .map_err(|error| invariant(format!("stored {field} is invalid: {error}")))
}

fn parse_delivery_mode(value: &str) -> Result<DeliveryMode, SessionStoreError> {
    match value {
        "queue" => Ok(DeliveryMode::Queue),
        "steer_at_boundary" => Ok(DeliveryMode::SteerAtBoundary),
        "interrupt_then_queue" => Ok(DeliveryMode::InterruptThenQueue),
        _ => Err(invariant(format!(
            "stored delivery mode {value:?} is invalid"
        ))),
    }
}

fn map_sqlite_error(error: rusqlite::Error) -> SessionStoreError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation =>
        {
            SessionStoreError::Conflict
        }
        other => SessionStoreError::Unavailable(other.to_string()),
    }
}

fn invariant(message: impl Into<String>) -> SessionStoreError {
    SessionStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::SqliteStore;
    use mealy_application::{
        InputAdmissionCommit, InputAdmissionOutcome, OwnershipContext, SessionCreationCommit,
        SessionStore, SessionStoreError,
    };
    use mealy_domain::{
        ChannelBindingId, CorrelationId, DeliveryMode, EventId, InboxEntryId, OutboxId,
        PrincipalId, SessionId,
    };
    use std::time::{Duration, SystemTime};

    const NOW_MS: i64 = 1_782_062_400_000;

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_millis(NOW_MS as u64)
    }

    fn owner() -> OwnershipContext {
        OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new())
    }

    fn create_commit(session_id: SessionId, ownership: OwnershipContext) -> SessionCreationCommit {
        SessionCreationCommit {
            session_id,
            ownership,
            event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            created_at: now(),
        }
    }

    fn admission_commit(
        session_id: SessionId,
        ownership: OwnershipContext,
        dedupe_key: &str,
        content: &str,
    ) -> InputAdmissionCommit {
        InputAdmissionCommit {
            session_id,
            ownership,
            inbox_entry_id: InboxEntryId::new(),
            delivery_mode: DeliveryMode::Queue,
            dedupe_key: dedupe_key.to_owned(),
            content: content.to_owned(),
            maximum_pending_inputs: 1_024,
            event_id: EventId::new(),
            outbox_id: OutboxId::new(),
            correlation_id: CorrelationId::new(),
            accepted_at: now(),
        }
    }

    #[test]
    fn input_admission_is_atomic_monotonic_and_idempotent() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let session_id = SessionId::new();
        let ownership = owner();
        store
            .create_session(create_commit(session_id, ownership))
            .expect("create session");

        let first_commit = admission_commit(session_id, ownership, "delivery-1", "hello");
        let accepted = store
            .admit_input(first_commit.clone())
            .expect("accept first input");
        assert!(matches!(accepted, InputAdmissionOutcome::Accepted(_)));
        assert_eq!(accepted.receipt().inbox_sequence, 1);

        let duplicate = store
            .admit_input(first_commit)
            .expect("return original duplicate receipt");
        assert!(duplicate.is_duplicate());
        assert_eq!(duplicate.receipt(), accepted.receipt());

        let second = store
            .admit_input(admission_commit(
                session_id,
                ownership,
                "delivery-2",
                "world",
            ))
            .expect("accept second input");
        assert_eq!(second.receipt().inbox_sequence, 2);
        assert_eq!(store.journal_count().expect("journal count"), 3);
        assert_eq!(store.outbox_count().expect("outbox count"), 2);
    }

    #[test]
    fn changed_input_with_same_key_is_rejected_without_writes() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let session_id = SessionId::new();
        let ownership = owner();
        store
            .create_session(create_commit(session_id, ownership))
            .expect("create session");
        store
            .admit_input(admission_commit(
                session_id,
                ownership,
                "delivery-1",
                "original",
            ))
            .expect("accept original input");

        let error = store
            .admit_input(admission_commit(
                session_id,
                ownership,
                "delivery-1",
                "changed",
            ))
            .expect_err("same key cannot bind changed content");
        assert_eq!(error, SessionStoreError::IdempotencyConflict);
        assert_eq!(store.journal_count().expect("journal count"), 2);
        assert_eq!(store.outbox_count().expect("outbox count"), 1);
    }

    #[test]
    fn pending_queue_limit_rejects_new_work_but_preserves_exact_idempotency() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let session_id = SessionId::new();
        let ownership = owner();
        store
            .create_session(create_commit(session_id, ownership))
            .expect("create session");
        let mut first = admission_commit(session_id, ownership, "delivery-1", "first");
        first.maximum_pending_inputs = 1;
        let receipt = store
            .admit_input(first.clone())
            .expect("first input fits queue");
        assert!(!receipt.is_duplicate());

        let duplicate = store
            .admit_input(first)
            .expect("exact duplicate remains idempotent at capacity");
        assert!(duplicate.is_duplicate());
        assert_eq!(duplicate.receipt(), receipt.receipt());

        let mut second = admission_commit(session_id, ownership, "delivery-2", "second");
        second.maximum_pending_inputs = 1;
        assert_eq!(
            store.admit_input(second),
            Err(SessionStoreError::Backpressure)
        );
        assert_eq!(store.journal_count().expect("journal count"), 2);
        assert_eq!(store.outbox_count().expect("outbox count"), 1);
    }

    #[test]
    fn principal_and_channel_binding_must_both_match() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let session_id = SessionId::new();
        let ownership = owner();
        store
            .create_session(create_commit(session_id, ownership))
            .expect("create session");
        let wrong_binding =
            OwnershipContext::new(ownership.principal_id(), ChannelBindingId::new());

        let error = store
            .admit_input(admission_commit(
                session_id,
                wrong_binding,
                "delivery-1",
                "forged",
            ))
            .expect_err("wrong channel binding must not access session");
        assert_eq!(error, SessionStoreError::Unauthorized);
        assert_eq!(store.journal_count().expect("journal count"), 1);
        assert_eq!(store.outbox_count().expect("outbox count"), 0);
    }

    #[test]
    fn late_outbox_failure_rolls_back_inbox_session_and_journal() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let session_id = SessionId::new();
        let ownership = owner();
        store
            .create_session(create_commit(session_id, ownership))
            .expect("create session");
        let first = admission_commit(session_id, ownership, "delivery-1", "first");
        store
            .admit_input(first.clone())
            .expect("accept first input");

        let mut colliding = admission_commit(session_id, ownership, "delivery-2", "second");
        colliding.outbox_id = first.outbox_id;
        let error = store
            .admit_input(colliding)
            .expect_err("duplicate outbox ID must abort the full transaction");
        assert_eq!(error, SessionStoreError::Conflict);

        let counts: (i64, i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT \
                    (SELECT COUNT(*) FROM session_inbox), \
                    (SELECT COUNT(*) FROM journal_event), \
                    (SELECT COUNT(*) FROM outbox), \
                    (SELECT next_inbox_sequence FROM session WHERE id = ?1)",
                [session_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read canonical counts");
        assert_eq!(counts, (1, 2, 1, 2));
    }
}
