use super::SqliteStore;
use mealy_application::{
    CompleteOutboxCommit, OutboxClaimCommit, OutboxClaimOutcome, OutboxDelivery,
    OutboxDeliveryStore, OutboxStoreError, RetryOutboxCommit,
};
use mealy_domain::OutboxId;
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use std::{str::FromStr, time::SystemTime};

impl OutboxDeliveryStore for SqliteStore {
    fn claim_next_outbox(
        &mut self,
        commit: OutboxClaimCommit,
    ) -> Result<OutboxClaimOutcome, OutboxStoreError> {
        let claimed_at_ms = epoch_milliseconds(commit.claimed_at)?;
        let stale_before_ms = epoch_milliseconds(commit.stale_before)?;
        if stale_before_ms > claimed_at_ms || commit.maximum_attempts == 0 {
            return Err(invariant("invalid outbox claim policy reached storage"));
        }
        let maximum_attempts = i64::from(commit.maximum_attempts);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;

        transaction
            .execute(
                "UPDATE outbox \
                 SET state = 'pending', delivery_owner_id = NULL, delivery_started_at_ms = NULL, \
                     next_attempt_at_ms = MIN(COALESCE(next_attempt_at_ms, ?1), ?1), \
                     last_error = COALESCE(last_error, 'dispatcher claim timed out') \
                 WHERE state = 'delivering' \
                   AND (delivery_started_at_ms IS NULL OR delivery_started_at_ms <= ?2)",
                params![claimed_at_ms, stale_before_ms],
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "UPDATE outbox \
                 SET state = 'failed', next_attempt_at_ms = NULL, \
                     last_error = COALESCE(last_error, 'maximum delivery attempts exhausted') \
                 WHERE state = 'pending' AND attempts >= ?1",
                [maximum_attempts],
            )
            .map_err(map_sqlite_error)?;

        let row = transaction
            .query_row(
                "SELECT outbox_id, topic, payload_json, attempts \
                 FROM outbox \
                 WHERE state = 'pending' AND attempts < ?1 \
                   AND (next_attempt_at_ms IS NULL OR next_attempt_at_ms <= ?2) \
                 ORDER BY COALESCE(next_attempt_at_ms, created_at_ms), created_at_ms, outbox_id \
                 LIMIT 1",
                params![maximum_attempts, claimed_at_ms],
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
            .map_err(map_sqlite_error)?;
        let Some((outbox_id, topic, payload_json, attempts)) = row else {
            transaction.commit().map_err(map_sqlite_error)?;
            return Ok(OutboxClaimOutcome::NoPendingDelivery);
        };
        let next_attempt = attempts
            .checked_add(1)
            .ok_or_else(|| invariant("outbox attempt counter overflow"))?;
        let changed = transaction
            .execute(
                "UPDATE outbox \
                 SET state = 'delivering', attempts = ?1, delivery_owner_id = ?2, \
                     delivery_started_at_ms = ?3, next_attempt_at_ms = NULL \
                 WHERE outbox_id = ?4 AND state = 'pending' AND attempts = ?5",
                params![
                    next_attempt,
                    commit.owner_id.to_string(),
                    claimed_at_ms,
                    outbox_id,
                    attempts,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(OutboxStoreError::StaleClaim);
        }
        let outbox_id =
            OutboxId::from_str(&outbox_id).map_err(|_| invariant("stored outbox ID is invalid"))?;
        let attempt =
            u32::try_from(next_attempt).map_err(|_| invariant("outbox attempt exceeds u32"))?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(OutboxClaimOutcome::Claimed(OutboxDelivery {
            outbox_id,
            topic,
            payload_json,
            attempt,
        }))
    }

    fn complete_outbox(&mut self, commit: CompleteOutboxCommit) -> Result<(), OutboxStoreError> {
        let delivered_at_ms = epoch_milliseconds(commit.delivered_at)?;
        let changed = self
            .connection
            .execute(
                "UPDATE outbox \
                 SET state = 'delivered', delivered_at_ms = ?1, next_attempt_at_ms = NULL, \
                     last_error = NULL \
                 WHERE outbox_id = ?2 AND state = 'delivering' AND delivery_owner_id = ?3 \
                   AND delivery_started_at_ms <= ?1",
                params![
                    delivered_at_ms,
                    commit.outbox_id.to_string(),
                    commit.owner_id.to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(OutboxStoreError::StaleClaim)
        }
    }

    fn retry_outbox(&mut self, commit: RetryOutboxCommit) -> Result<(), OutboxStoreError> {
        let failed_at_ms = epoch_milliseconds(commit.failed_at)?;
        let retry_at_ms = commit.retry_at.map(epoch_milliseconds).transpose()?;
        if retry_at_ms.is_some_and(|retry_at| retry_at <= failed_at_ms) {
            return Err(invariant("outbox retry must be scheduled after failure"));
        }
        let (state, next_attempt_at_ms) = if retry_at_ms.is_some() {
            ("pending", retry_at_ms)
        } else {
            ("failed", None)
        };
        let changed = self
            .connection
            .execute(
                "UPDATE outbox \
                 SET state = ?1, next_attempt_at_ms = ?2, last_error = ?3, \
                     delivery_owner_id = NULL, delivery_started_at_ms = NULL \
                 WHERE outbox_id = ?4 AND state = 'delivering' AND delivery_owner_id = ?5 \
                   AND delivery_started_at_ms <= ?6",
                params![
                    state,
                    next_attempt_at_ms,
                    commit.error,
                    commit.outbox_id.to_string(),
                    commit.owner_id.to_string(),
                    failed_at_ms,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(OutboxStoreError::StaleClaim)
        }
    }
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, OutboxStoreError> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invariant("outbox clock returned a time before the Unix epoch"))?;
    i64::try_from(duration.as_millis()).map_err(|_| invariant("outbox timestamp exceeds SQLite"))
}

#[allow(clippy::needless_pass_by_value)]
fn map_sqlite_error(error: rusqlite::Error) -> OutboxStoreError {
    OutboxStoreError::Unavailable(error.to_string())
}

fn invariant(message: impl Into<String>) -> OutboxStoreError {
    OutboxStoreError::InvariantViolation(message.into())
}
