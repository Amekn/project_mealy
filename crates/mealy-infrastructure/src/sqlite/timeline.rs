use super::SqliteStore;
use mealy_application::{
    OwnershipContext, SessionStatusView, TimelineCursor, TimelineEvent, TimelinePage,
    TimelineQuery, TimelineStore, TimelineStoreError,
};
use mealy_domain::SessionId;
use rusqlite::{OptionalExtension, params};
use std::{str::FromStr, time::SystemTime};

impl TimelineStore for SqliteStore {
    #[allow(clippy::too_many_lines)]
    fn timeline_page(&self, query: TimelineQuery) -> Result<TimelinePage, TimelineStoreError> {
        authorize(&self.connection, query.session_id, query.ownership)?;
        let high_watermark = high_watermark(&self.connection, query.session_id)?;
        if let Some(after) = query.after {
            let earliest = retention_floor(&self.connection)?;
            if after.0.saturating_add(1) < earliest.0 {
                return Err(TimelineStoreError::Gap { earliest });
            }
            if after.0 > high_watermark.0 {
                return Err(TimelineStoreError::CursorAhead);
            }
        }

        let after = query.after.unwrap_or_default().0;
        let sql_limit = i64::try_from(query.limit.saturating_add(1))
            .map_err(|_| invariant("timeline page limit exceeds SQLite range"))?;
        let after =
            i64::try_from(after).map_err(|_| invariant("timeline cursor exceeds SQLite range"))?;
        let mut statement = self
            .connection
            .prepare(
                "WITH session_runs(run_id) AS (\
                    SELECT lineage.run_id FROM run_lineage lineage \
                    WHERE lineage.root_run_id IN (\
                        SELECT run_id FROM turn WHERE session_id = ?2 AND turn_kind = 'canonical'\
                    )\
                 ) \
                 SELECT te.cursor, je.event_id, je.aggregate_kind, je.aggregate_id, \
                        je.aggregate_sequence, je.event_type, je.event_version, je.occurred_at_ms, \
                        je.correlation_id, je.causation_id, je.payload_json \
                 FROM timeline_event te JOIN journal_event je ON je.event_id = te.event_id \
                 WHERE te.cursor > ?1 AND (\
                    (je.aggregate_kind = 'session' AND je.aggregate_id = ?2) OR \
                    (je.aggregate_kind = 'task' AND je.aggregate_id IN \
                        (SELECT task_id FROM run WHERE id IN (SELECT run_id FROM session_runs))) OR \
                    (je.aggregate_kind = 'run' AND je.aggregate_id IN \
                        (SELECT run_id FROM session_runs)) OR \
                    (je.aggregate_kind = 'turn' AND je.aggregate_id IN \
                        (SELECT id FROM turn WHERE session_id = ?2)) OR \
                    (je.aggregate_kind = 'context_epoch' AND je.aggregate_id IN \
                        (SELECT id FROM context_epoch WHERE session_id = ?2)) OR \
                    (je.aggregate_kind = 'context_manifest' AND je.aggregate_id IN \
                        (SELECT id FROM context_manifest WHERE session_id = ?2)) OR \
                    (je.aggregate_kind = 'model_attempt' AND je.aggregate_id IN \
                        (SELECT attempt_id FROM model_attempt WHERE run_id IN \
                            (SELECT run_id FROM session_runs))) OR \
                    (je.aggregate_kind = 'tool_call' AND je.aggregate_id IN \
                        (SELECT tool_call_id FROM tool_call WHERE run_id IN \
                            (SELECT run_id FROM session_runs))) OR \
                    (je.aggregate_kind = 'effect' AND je.aggregate_id IN \
                        (SELECT id FROM effect WHERE run_id IN \
                            (SELECT run_id FROM session_runs))) OR \
                    (je.aggregate_kind = 'approval' AND je.aggregate_id IN \
                        (SELECT approval_id FROM approval_request WHERE effect_id IN \
                            (SELECT id FROM effect WHERE run_id IN \
                                (SELECT run_id FROM session_runs)))) OR \
                    (je.aggregate_kind = 'validation' AND je.aggregate_id IN \
                        (SELECT id FROM validation_record WHERE producer_run_id IN \
                            (SELECT run_id FROM session_runs))) OR \
                    (je.aggregate_kind = 'delegation' AND je.aggregate_id IN \
                        (SELECT id FROM delegation WHERE parent_run_id IN \
                            (SELECT run_id FROM session_runs) OR child_run_id IN \
                            (SELECT run_id FROM session_runs))) OR \
                    (je.aggregate_kind = 'resource_claim' AND je.aggregate_id IN \
                        (SELECT claim_id FROM resource_claim WHERE run_id IN \
                            (SELECT run_id FROM session_runs))) OR \
                    (je.aggregate_kind = 'compaction' AND je.aggregate_id IN \
                        (SELECT id FROM session_compaction WHERE session_id = ?2)) OR \
                    (je.aggregate_kind = 'memory' AND je.aggregate_id IN (\
                        SELECT memory.id FROM memory \
                        JOIN session owner_session ON owner_session.id = ?2 \
                        WHERE memory.principal_id = owner_session.principal_id \
                          AND memory.workspace_identity IN (\
                              SELECT workspace_identity FROM context_epoch WHERE session_id = ?2\
                          )\
                    )) OR \
                    (je.aggregate_kind = 'artifact' AND je.aggregate_id IN \
                        (SELECT id FROM artifact WHERE session_id = ?2)) OR \
                    (je.aggregate_kind = 'message' AND je.aggregate_id IN \
                        (SELECT id FROM message WHERE session_id = ?2))\
                 ) ORDER BY te.cursor LIMIT ?3",
            )
            .map_err(map_sqlite_error)?;
        let mut events = statement
            .query_map(
                params![after, query.session_id.to_string(), sql_limit],
                |row| {
                    Ok(StoredTimelineEvent {
                        cursor: row.get(0)?,
                        event_id: row.get(1)?,
                        aggregate_kind: row.get(2)?,
                        aggregate_id: row.get(3)?,
                        aggregate_sequence: row.get(4)?,
                        event_type: row.get(5)?,
                        event_version: row.get(6)?,
                        occurred_at_ms: row.get(7)?,
                        correlation_id: row.get(8)?,
                        causation_id: row.get(9)?,
                        payload_json: row.get(10)?,
                    })
                },
            )
            .map_err(map_sqlite_error)?
            .map(|row| {
                row.map_err(map_sqlite_error)
                    .and_then(StoredTimelineEvent::try_into_event)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = events.len() > query.limit;
        events.truncate(query.limit);
        Ok(TimelinePage {
            events,
            high_watermark,
            has_more,
        })
    }

    fn session_status(
        &self,
        session_id: SessionId,
        ownership: OwnershipContext,
    ) -> Result<SessionStatusView, TimelineStoreError> {
        authorize(&self.connection, session_id, ownership)?;
        let (revision, pending_inputs, active_turn_id): (i64, i64, Option<String>) = self
            .connection
            .query_row(
                "SELECT s.revision, \
                        (SELECT COUNT(*) FROM session_inbox i \
                         WHERE i.session_id = s.id AND i.state = 'pending'), \
                        s.active_turn_id \
                 FROM session s WHERE s.id = ?1",
                [session_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(map_sqlite_error)?;
        let latest_cursor = high_watermark(&self.connection, session_id)?;
        Ok(SessionStatusView {
            session_id,
            revision: nonnegative_u64(revision, "session revision")?,
            pending_inputs: nonnegative_u64(pending_inputs, "pending input count")?,
            active_turn_id: active_turn_id
                .as_deref()
                .map(|value| parse_id(value, "active turn ID"))
                .transpose()?,
            latest_cursor,
        })
    }
}

fn retention_floor(
    connection: &rusqlite::Connection,
) -> Result<TimelineCursor, TimelineStoreError> {
    let value = connection
        .query_row(
            "SELECT earliest_available_cursor FROM timeline_retention WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(map_sqlite_error)?;
    positive_u64(value, "timeline retention floor").map(TimelineCursor)
}

struct StoredTimelineEvent {
    cursor: i64,
    event_id: String,
    aggregate_kind: String,
    aggregate_id: String,
    aggregate_sequence: i64,
    event_type: String,
    event_version: i64,
    occurred_at_ms: i64,
    correlation_id: String,
    causation_id: Option<String>,
    payload_json: String,
}

impl StoredTimelineEvent {
    fn try_into_event(self) -> Result<TimelineEvent, TimelineStoreError> {
        Ok(TimelineEvent {
            cursor: TimelineCursor(positive_u64(self.cursor, "timeline cursor")?),
            event_id: parse_id(&self.event_id, "event ID")?,
            aggregate_kind: self.aggregate_kind,
            aggregate_id: self.aggregate_id,
            aggregate_sequence: nonnegative_u64(self.aggregate_sequence, "aggregate sequence")?,
            event_type: self.event_type,
            event_version: u32::try_from(self.event_version)
                .map_err(|_| invariant("event version is outside u32 range"))?,
            occurred_at: system_time(self.occurred_at_ms)?,
            correlation_id: parse_id(&self.correlation_id, "correlation ID")?,
            causation_id: self
                .causation_id
                .as_deref()
                .map(|value| parse_id(value, "causation ID"))
                .transpose()?,
            payload_json: self.payload_json,
        })
    }
}

fn authorize(
    connection: &rusqlite::Connection,
    session_id: SessionId,
    ownership: OwnershipContext,
) -> Result<(), TimelineStoreError> {
    let stored = connection
        .query_row(
            "SELECT principal_id, channel_binding_id FROM session WHERE id = ?1",
            [session_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(TimelineStoreError::SessionNotFound)?;
    if stored.0 == ownership.principal_id().to_string()
        && stored.1 == ownership.channel_binding_id().to_string()
    {
        Ok(())
    } else {
        Err(TimelineStoreError::Unauthorized)
    }
}

fn high_watermark(
    connection: &rusqlite::Connection,
    session_id: SessionId,
) -> Result<TimelineCursor, TimelineStoreError> {
    let maximum: Option<i64> = connection
        .query_row(
            "WITH session_runs(run_id) AS (\
                SELECT lineage.run_id FROM run_lineage lineage \
                WHERE lineage.root_run_id IN (\
                    SELECT run_id FROM turn WHERE session_id = ?1 AND turn_kind = 'canonical'\
                )\
             ) \
             SELECT MAX(te.cursor) \
             FROM timeline_event te JOIN journal_event je ON je.event_id = te.event_id \
             WHERE (je.aggregate_kind = 'session' AND je.aggregate_id = ?1) OR \
                   (je.aggregate_kind = 'task' AND je.aggregate_id IN \
                       (SELECT task_id FROM run WHERE id IN (SELECT run_id FROM session_runs))) OR \
                   (je.aggregate_kind = 'run' AND je.aggregate_id IN \
                       (SELECT run_id FROM session_runs)) OR \
                   (je.aggregate_kind = 'turn' AND je.aggregate_id IN \
                       (SELECT id FROM turn WHERE session_id = ?1)) OR \
                   (je.aggregate_kind = 'context_epoch' AND je.aggregate_id IN \
                       (SELECT id FROM context_epoch WHERE session_id = ?1)) OR \
                   (je.aggregate_kind = 'context_manifest' AND je.aggregate_id IN \
                       (SELECT id FROM context_manifest WHERE session_id = ?1)) OR \
                   (je.aggregate_kind = 'model_attempt' AND je.aggregate_id IN \
                       (SELECT attempt_id FROM model_attempt WHERE run_id IN \
                           (SELECT run_id FROM session_runs))) OR \
                   (je.aggregate_kind = 'tool_call' AND je.aggregate_id IN \
                       (SELECT tool_call_id FROM tool_call WHERE run_id IN \
                           (SELECT run_id FROM session_runs))) OR \
                   (je.aggregate_kind = 'effect' AND je.aggregate_id IN \
                       (SELECT id FROM effect WHERE run_id IN \
                           (SELECT run_id FROM session_runs))) OR \
                   (je.aggregate_kind = 'approval' AND je.aggregate_id IN \
                       (SELECT approval_id FROM approval_request WHERE effect_id IN \
                           (SELECT id FROM effect WHERE run_id IN \
                               (SELECT run_id FROM session_runs)))) OR \
                   (je.aggregate_kind = 'validation' AND je.aggregate_id IN \
                       (SELECT id FROM validation_record WHERE producer_run_id IN \
                           (SELECT run_id FROM session_runs))) OR \
                   (je.aggregate_kind = 'delegation' AND je.aggregate_id IN \
                       (SELECT id FROM delegation WHERE parent_run_id IN \
                           (SELECT run_id FROM session_runs) OR child_run_id IN \
                           (SELECT run_id FROM session_runs))) OR \
                   (je.aggregate_kind = 'resource_claim' AND je.aggregate_id IN \
                       (SELECT claim_id FROM resource_claim WHERE run_id IN \
                           (SELECT run_id FROM session_runs))) OR \
                   (je.aggregate_kind = 'compaction' AND je.aggregate_id IN \
                       (SELECT id FROM session_compaction WHERE session_id = ?1)) OR \
                   (je.aggregate_kind = 'memory' AND je.aggregate_id IN (\
                       SELECT memory.id FROM memory \
                       JOIN session owner_session ON owner_session.id = ?1 \
                       WHERE memory.principal_id = owner_session.principal_id \
                         AND memory.workspace_identity IN (\
                             SELECT workspace_identity FROM context_epoch WHERE session_id = ?1\
                         )\
                   )) OR \
                   (je.aggregate_kind = 'artifact' AND je.aggregate_id IN \
                       (SELECT id FROM artifact WHERE session_id = ?1)) OR \
                   (je.aggregate_kind = 'message' AND je.aggregate_id IN \
                       (SELECT id FROM message WHERE session_id = ?1))",
            [session_id.to_string()],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error)?;
    maximum
        .map(|value| positive_u64(value, "maximum timeline cursor").map(TimelineCursor))
        .transpose()?
        .map_or_else(|| Ok(TimelineCursor::default()), Ok)
}

fn system_time(value: i64) -> Result<SystemTime, TimelineStoreError> {
    let value = u64::try_from(value).map_err(|_| invariant("stored timestamp is negative"))?;
    SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_millis(value))
        .ok_or_else(|| invariant("stored timestamp exceeds SystemTime"))
}

fn positive_u64(value: i64, field: &str) -> Result<u64, TimelineStoreError> {
    let value = nonnegative_u64(value, field)?;
    if value == 0 {
        Err(invariant(format!("stored {field} is zero")))
    } else {
        Ok(value)
    }
}

fn nonnegative_u64(value: i64, field: &str) -> Result<u64, TimelineStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("stored {field} is negative")))
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, TimelineStoreError> {
    value
        .parse()
        .map_err(|_| invariant(format!("stored {field} is invalid")))
}

#[allow(clippy::needless_pass_by_value)]
fn map_sqlite_error(error: rusqlite::Error) -> TimelineStoreError {
    TimelineStoreError::Unavailable(error.to_string())
}

fn invariant(message: impl Into<String>) -> TimelineStoreError {
    TimelineStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::SqliteStore;
    use mealy_application::{
        OwnershipContext, TimelineCursor, TimelineQuery, TimelineStoreError, create_session,
        query_timeline,
    };
    use mealy_domain::{ChannelBindingId, PrincipalId};
    use mealy_testkit::{TestClock, TestIdGenerator};

    #[test]
    fn explicit_retention_floor_reports_a_real_cursor_gap() {
        let now = 1_782_062_400_000;
        let clock = TestClock::new(now);
        let ids = TestIdGenerator::new(now.cast_unsigned());
        let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
        let mut store = SqliteStore::open_in_memory(now).expect("open store");
        let session_id =
            create_session(&mut store, &clock, &ids, ownership).expect("create session");
        store
            .connection
            .execute("DELETE FROM timeline_event WHERE cursor = 1", [])
            .expect("simulate retained presentation row");
        store
            .connection
            .execute(
                "UPDATE timeline_retention \
                 SET earliest_available_cursor = 2, updated_at_ms = ?1 WHERE singleton = 1",
                [now],
            )
            .expect("advance explicit retention floor");

        let error = query_timeline(
            &store,
            TimelineQuery {
                session_id,
                ownership,
                after: Some(TimelineCursor(0)),
                limit: 100,
            },
        )
        .expect_err("cursor before explicit retention floor must report a gap");
        assert_eq!(
            error,
            mealy_application::TimelineUseCaseError::Store(TimelineStoreError::Gap {
                earliest: TimelineCursor(2)
            })
        );
    }
}
