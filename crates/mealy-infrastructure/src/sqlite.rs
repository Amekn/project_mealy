use mealy_domain::{
    CorrelationId, EventId, OutboxId, PrincipalId, TaskId, TaskState, TaskStatus, TaskTransition,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::Value;
use std::{path::Path, time::Duration};
use thiserror::Error;

mod sessions;

const MIGRATION_0001: &str = include_str!("../migrations/0001_foundation.sql");
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const SYNCHRONOUS_POLICY: &str = "FULL";

/// SQLite-backed transition store.
pub struct SqliteStore {
    connection: Connection,
}

impl SqliteStore {
    /// Opens or creates a store at the supplied path and applies migrations.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the database cannot be opened, configured, or migrated.
    pub fn open(path: impl AsRef<Path>, applied_at_ms: i64) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        Self::from_connection(connection, applied_at_ms, true)
    }

    /// Creates an in-memory store for tests and ephemeral tooling.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the database cannot be configured or migrated.
    pub fn open_in_memory(applied_at_ms: i64) -> Result<Self, StoreError> {
        let connection = Connection::open_in_memory()?;
        Self::from_connection(connection, applied_at_ms, false)
    }

    fn from_connection(
        mut connection: Connection,
        applied_at_ms: i64,
        file_backed: bool,
    ) -> Result<Self, StoreError> {
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        if file_backed {
            let journal_mode: String =
                connection
                    .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
            if !journal_mode.eq_ignore_ascii_case("wal") {
                return Err(StoreError::JournalModeUnavailable { journal_mode });
            }
        }
        connection.pragma_update(None, "synchronous", SYNCHRONOUS_POLICY)?;

        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(MIGRATION_0001)?;
        ensure_initial_journal_envelope(&transaction)?;
        transaction.execute(
            "INSERT OR IGNORE INTO schema_version(version, applied_at_ms) VALUES (1, ?1)",
            [applied_at_ms],
        )?;
        transaction.commit()?;
        Ok(Self { connection })
    }

    /// Atomically commits canonical task state, one journal fact, and outbox rows.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for an inconsistent mutation, stale revision, unrepresentable
    /// value, or any database failure. The transaction is rolled back on every error.
    pub fn commit_task(
        &mut self,
        state: &TaskState,
        mutation: TaskMutation,
        journal: &JournalRecord,
        outbox: &[OutboxRecord],
    ) -> Result<u64, StoreError> {
        validate_mutation(state, mutation)?;
        let revision = to_sql_integer(state.revision())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        match mutation {
            TaskMutation::Create => {
                transaction.execute(
                    "INSERT INTO task(id, status, revision, validation_required, validation_id) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        state.id().to_string(),
                        status_text(state.status()),
                        revision,
                        i64::from(state.validation_required()),
                        state.validation_id().map(|id| id.to_string()),
                    ],
                )?;
            }
            TaskMutation::Transition(transition) => {
                let changed = transaction.execute(
                    "UPDATE task SET status = ?1, revision = ?2, validation_id = ?3 \
                     WHERE id = ?4 AND revision = ?5 AND status = ?6",
                    params![
                        status_text(state.status()),
                        revision,
                        state.validation_id().map(|id| id.to_string()),
                        state.id().to_string(),
                        to_sql_integer(transition.previous_revision())?,
                        status_text(transition.from()),
                    ],
                )?;
                if changed != 1 {
                    return Err(StoreError::Conflict {
                        task_id: state.id(),
                        expected_revision: transition.previous_revision(),
                    });
                }
            }
        }

        let previous_sequence = transaction
            .query_row(
                "SELECT sequence FROM aggregate_sequence \
                 WHERE aggregate_kind = 'task' AND aggregate_id = ?1",
                [state.id().to_string()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let next_sequence = previous_sequence.map_or(0, |value| value + 1);

        transaction.execute(
            "INSERT INTO journal_event(\
                event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                event_version, occurred_at_ms, actor_principal_id, correlation_id, causation_id, \
                policy_version, sensitivity, payload_json\
             ) VALUES (?1, 'task', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                journal.event_id.to_string(),
                state.id().to_string(),
                next_sequence,
                journal.event_type.as_str(),
                i64::from(journal.event_version),
                journal.occurred_at_ms,
                journal.actor_principal_id.map(|id| id.to_string()),
                journal.correlation_id.to_string(),
                journal.causation_id.map(|id| id.to_string()),
                journal.policy_version.as_deref(),
                journal.sensitivity.as_str(),
                journal.payload.to_string(),
            ],
        )?;

        transaction.execute(
            "INSERT INTO aggregate_sequence(aggregate_kind, aggregate_id, sequence) \
             VALUES ('task', ?1, ?2) \
             ON CONFLICT(aggregate_kind, aggregate_id) DO UPDATE SET sequence = excluded.sequence",
            params![state.id().to_string(), next_sequence],
        )?;

        for record in outbox {
            transaction.execute(
                "INSERT INTO outbox(outbox_id, topic, payload_json, created_at_ms) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    record.outbox_id.to_string(),
                    record.topic.as_str(),
                    record.payload.to_string(),
                    record.created_at_ms,
                ],
            )?;
        }

        transaction.commit()?;
        u64::try_from(next_sequence).map_err(|_| StoreError::SequenceOutOfRange(next_sequence))
    }

    /// Loads the current task projection.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the query fails.
    pub fn task_snapshot(&self, task_id: TaskId) -> Result<Option<TaskSnapshot>, StoreError> {
        self.connection
            .query_row(
                "SELECT status, revision FROM task WHERE id = ?1",
                [task_id.to_string()],
                |row| {
                    Ok(TaskSnapshot {
                        status: row.get(0)?,
                        revision: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Returns the number of journal rows for tests and diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the query fails or the count is invalid.
    pub fn journal_count(&self) -> Result<u64, StoreError> {
        count(&self.connection, "journal_event")
    }

    /// Returns the number of outbox rows for tests and diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the query fails or the count is invalid.
    pub fn outbox_count(&self) -> Result<u64, StoreError> {
        count(&self.connection, "outbox")
    }
}

/// Kind of canonical task mutation being committed.
#[derive(Clone, Copy, Debug)]
pub enum TaskMutation {
    /// Inserts a new revision-zero task.
    Create,
    /// Applies a previously accepted domain transition.
    Transition(TaskTransition),
}

/// Versioned journal event committed with canonical state.
#[derive(Clone, Debug)]
pub struct JournalRecord {
    /// Unique event ID.
    pub event_id: EventId,
    /// Stable semantic event name.
    pub event_type: String,
    /// Schema version for the payload.
    pub event_version: u32,
    /// UTC epoch milliseconds.
    pub occurred_at_ms: i64,
    /// Authenticated actor, or `None` for system bootstrap facts.
    pub actor_principal_id: Option<PrincipalId>,
    /// Correlation ID shared by related facts.
    pub correlation_id: CorrelationId,
    /// Command or event that directly caused this fact, when one exists.
    pub causation_id: Option<EventId>,
    /// Policy bundle version responsible for a security-sensitive decision.
    pub policy_version: Option<String>,
    /// Data classification used by retention and presentation policy.
    pub sensitivity: String,
    /// Bounded JSON payload.
    pub payload: Value,
}

/// Outbound delivery committed with a state transition.
#[derive(Clone, Debug)]
pub struct OutboxRecord {
    /// Stable delivery ID used for deduplication.
    pub outbox_id: OutboxId,
    /// Destination class, such as a timeline or channel adapter.
    pub topic: String,
    /// Bounded JSON delivery body.
    pub payload: Value,
    /// UTC epoch milliseconds.
    pub created_at_ms: i64,
}

/// Current task projection returned by the foundation adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskSnapshot {
    /// Stored snake-case status.
    pub status: String,
    /// Optimistic-concurrency revision.
    pub revision: i64,
}

/// Storage adapter failure.
#[derive(Debug, Error)]
pub enum StoreError {
    /// `SQLite` rejected an operation.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    /// The expected task revision was stale.
    #[error("task {task_id} no longer has expected revision {expected_revision}")]
    Conflict {
        /// Task being updated.
        task_id: TaskId,
        /// Revision expected by the transition.
        expected_revision: u64,
    },
    /// The supplied state does not match its domain transition.
    #[error("task mutation is inconsistent with canonical domain state")]
    InvalidMutation,
    /// A domain revision cannot be represented by `SQLite`'s signed integer.
    #[error("revision {0} exceeds SQLite integer range")]
    RevisionOutOfRange(u64),
    /// A stored sequence was unexpectedly negative.
    #[error("journal sequence {0} is outside the supported range")]
    SequenceOutOfRange(i64),
    /// A file-backed connection could not enable write-ahead logging.
    #[error("SQLite returned journal mode {journal_mode:?} when WAL was required")]
    JournalModeUnavailable {
        /// Actual mode selected by `SQLite`.
        journal_mode: String,
    },
}

fn ensure_initial_journal_envelope(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    add_column_if_missing(
        transaction,
        "causation_id",
        "ALTER TABLE journal_event ADD COLUMN causation_id TEXT \
         CHECK (causation_id IS NULL OR length(causation_id) > 0)",
    )?;
    add_column_if_missing(
        transaction,
        "policy_version",
        "ALTER TABLE journal_event ADD COLUMN policy_version TEXT \
         CHECK (policy_version IS NULL OR length(policy_version) > 0)",
    )?;
    add_column_if_missing(
        transaction,
        "sensitivity",
        "ALTER TABLE journal_event ADD COLUMN sensitivity TEXT NOT NULL \
         DEFAULT 'internal' CHECK (length(sensitivity) > 0)",
    )?;
    Ok(())
}

fn add_column_if_missing(
    transaction: &Transaction<'_>,
    column: &str,
    alter_table: &str,
) -> Result<(), StoreError> {
    let exists = transaction.query_row(
        "SELECT EXISTS(\
            SELECT 1 FROM pragma_table_info('journal_event') WHERE name = ?1\
         )",
        [column],
        |row| row.get::<_, bool>(0),
    )?;
    if !exists {
        transaction.execute_batch(alter_table)?;
    }
    Ok(())
}

fn validate_mutation(state: &TaskState, mutation: TaskMutation) -> Result<(), StoreError> {
    match mutation {
        TaskMutation::Create => {
            if state.status() != TaskStatus::Queued || state.revision() != 0 {
                return Err(StoreError::InvalidMutation);
            }
        }
        TaskMutation::Transition(transition) => {
            if transition.task_id() != state.id()
                || transition.to() != state.status()
                || transition.new_revision() != state.revision()
                || transition.previous_revision().checked_add(1) != Some(transition.new_revision())
            {
                return Err(StoreError::InvalidMutation);
            }
        }
    }
    Ok(())
}

const fn status_text(status: TaskStatus) -> &'static str {
    match status {
        TaskStatus::Queued => "queued",
        TaskStatus::Running => "running",
        TaskStatus::Waiting => "waiting",
        TaskStatus::Paused => "paused",
        TaskStatus::Cancelling => "cancelling",
        TaskStatus::Succeeded => "succeeded",
        TaskStatus::Failed => "failed",
        TaskStatus::Cancelled => "cancelled",
    }
}

fn to_sql_integer(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::RevisionOutOfRange(value))
}

fn count(connection: &Connection, table: &str) -> Result<u64, StoreError> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    let value = connection.query_row(&sql, [], |row| row.get::<_, i64>(0))?;
    u64::try_from(value).map_err(|_| StoreError::SequenceOutOfRange(value))
}

#[cfg(test)]
mod tests {
    use super::{JournalRecord, OutboxRecord, SqliteStore, StoreError, TaskMutation};
    use mealy_domain::{CorrelationId, EventId, OutboxId, PrincipalId, TaskId, TaskState};
    use serde_json::json;
    use std::{collections::BTreeSet, fs, path::PathBuf};

    const NOW: i64 = 1_782_062_400_000;

    struct TemporaryDatabase {
        path: PathBuf,
    }

    impl TemporaryDatabase {
        fn new() -> Self {
            Self {
                path: std::env::temp_dir().join(format!("mealy-{}.sqlite3", TaskId::new())),
            }
        }

        fn sidecar(&self, suffix: &str) -> PathBuf {
            let mut path = self.path.as_os_str().to_owned();
            path.push(suffix);
            PathBuf::from(path)
        }
    }

    impl Drop for TemporaryDatabase {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let _ = fs::remove_file(self.sidecar(suffix));
            }
        }
    }

    fn journal(event_id: EventId, event_type: &str) -> JournalRecord {
        JournalRecord {
            event_id,
            event_type: event_type.to_owned(),
            event_version: 1,
            occurred_at_ms: NOW,
            actor_principal_id: Some(PrincipalId::new()),
            correlation_id: CorrelationId::new(),
            causation_id: None,
            policy_version: None,
            sensitivity: "internal".to_owned(),
            payload: json!({ "test": true }),
        }
    }

    fn outbox() -> OutboxRecord {
        OutboxRecord {
            outbox_id: OutboxId::new(),
            topic: "timeline".to_owned(),
            payload: json!({ "kind": "task" }),
            created_at_ms: NOW,
        }
    }

    #[test]
    fn state_event_and_outbox_commit_atomically() {
        let mut store = SqliteStore::open_in_memory(NOW).expect("open store");
        let mut task = TaskState::new(TaskId::new(), false);
        store
            .commit_task(
                &task,
                TaskMutation::Create,
                &journal(EventId::new(), "task.created"),
                &[outbox()],
            )
            .expect("create task");

        let transition = task.start().expect("start task");
        store
            .commit_task(
                &task,
                TaskMutation::Transition(transition),
                &journal(EventId::new(), "task.started"),
                &[outbox()],
            )
            .expect("commit transition");

        let snapshot = store
            .task_snapshot(task.id())
            .expect("load task")
            .expect("task exists");
        assert_eq!(snapshot.status, "running");
        assert_eq!(snapshot.revision, 1);
        assert_eq!(store.journal_count().expect("journal count"), 2);
        assert_eq!(store.outbox_count().expect("outbox count"), 2);
    }

    #[test]
    fn journal_failure_rolls_back_state_and_outbox() {
        let mut store = SqliteStore::open_in_memory(NOW).expect("open store");
        let mut task = TaskState::new(TaskId::new(), false);
        let duplicate_event_id = EventId::new();
        store
            .commit_task(
                &task,
                TaskMutation::Create,
                &journal(duplicate_event_id, "task.created"),
                &[outbox()],
            )
            .expect("create task");

        let transition = task.start().expect("start task");
        let error = store
            .commit_task(
                &task,
                TaskMutation::Transition(transition),
                &journal(duplicate_event_id, "task.started"),
                &[outbox()],
            )
            .expect_err("duplicate event must fail");
        assert!(matches!(error, StoreError::Sqlite(_)));

        let snapshot = store
            .task_snapshot(task.id())
            .expect("load task")
            .expect("task exists");
        assert_eq!(snapshot.status, "queued");
        assert_eq!(snapshot.revision, 0);
        assert_eq!(store.journal_count().expect("journal count"), 1);
        assert_eq!(store.outbox_count().expect("outbox count"), 1);
    }

    #[test]
    fn stale_transition_is_fenced_by_revision() {
        let mut store = SqliteStore::open_in_memory(NOW).expect("open store");
        let mut task = TaskState::new(TaskId::new(), false);
        store
            .commit_task(
                &task,
                TaskMutation::Create,
                &journal(EventId::new(), "task.created"),
                &[],
            )
            .expect("create task");
        let transition = task.start().expect("start task");
        store
            .commit_task(
                &task,
                TaskMutation::Transition(transition),
                &journal(EventId::new(), "task.started"),
                &[],
            )
            .expect("commit transition");

        let error = store
            .commit_task(
                &task,
                TaskMutation::Transition(transition),
                &journal(EventId::new(), "task.started-again"),
                &[],
            )
            .expect_err("stale transition must fail");
        assert!(matches!(error, StoreError::Conflict { .. }));
    }

    #[test]
    fn file_database_uses_durable_pragmas_and_survives_reopen() {
        let database = TemporaryDatabase::new();
        let task_id = TaskId::new();

        {
            let mut store = SqliteStore::open(&database.path, NOW).expect("open file store");
            let journal_mode: String = store
                .connection
                .pragma_query_value(None, "journal_mode", |row| row.get(0))
                .expect("read journal mode");
            let synchronous: i64 = store
                .connection
                .pragma_query_value(None, "synchronous", |row| row.get(0))
                .expect("read synchronous policy");
            let foreign_keys: i64 = store
                .connection
                .pragma_query_value(None, "foreign_keys", |row| row.get(0))
                .expect("read foreign-key policy");

            assert_eq!(journal_mode, "wal");
            assert_eq!(synchronous, 2, "SQLite FULL synchronous mode is 2");
            assert_eq!(foreign_keys, 1);

            let task = TaskState::new(task_id, false);
            store
                .commit_task(
                    &task,
                    TaskMutation::Create,
                    &journal(EventId::new(), "task.created"),
                    &[outbox()],
                )
                .expect("persist task");

            let foreign_key_error = store
                .connection
                .execute(
                    "INSERT INTO session_inbox(\
                        inbox_entry_id, session_id, sequence, dedupe_key, delivery_mode, state, \
                        content, admission_event_id, acknowledgement_outbox_id, correlation_id, \
                        accepted_at_ms, promoted_at_ms, promoted_turn_id\
                     ) VALUES (\
                        'entry', 'missing-session', 1, 'delivery', 'queue', 'pending', \
                        'hello', 'event', 'outbox', 'correlation', ?1, NULL, NULL\
                     )",
                    [NOW],
                )
                .expect_err("orphan inbox row must violate its session foreign key");
            assert!(matches!(
                foreign_key_error,
                rusqlite::Error::SqliteFailure(failure, _)
                    if failure.code == rusqlite::ErrorCode::ConstraintViolation
            ));
        }

        let reopened = SqliteStore::open(&database.path, NOW + 1).expect("reopen file store");
        let snapshot = reopened
            .task_snapshot(task_id)
            .expect("load persisted task")
            .expect("persisted task exists");
        assert_eq!(snapshot.status, "queued");
        assert_eq!(snapshot.revision, 0);
        assert_eq!(reopened.journal_count().expect("journal count"), 1);
        assert_eq!(reopened.outbox_count().expect("outbox count"), 1);
        let journal_mode: String = reopened
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("read journal mode after reopen");
        assert_eq!(journal_mode, "wal");
    }

    #[test]
    fn file_database_contains_complete_phase_zero_schema() {
        let database = TemporaryDatabase::new();
        let store = SqliteStore::open(&database.path, NOW).expect("open file store");
        let mut statement = store
            .connection
            .prepare("SELECT name FROM sqlite_schema WHERE type = 'table'")
            .expect("prepare table query");
        let tables = statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query tables")
            .collect::<rusqlite::Result<BTreeSet<_>>>()
            .expect("collect tables");
        let expected = [
            "aggregate_sequence",
            "effect",
            "journal_event",
            "outbox",
            "run",
            "schema_version",
            "session",
            "session_inbox",
            "task",
            "work_lease",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        assert!(
            expected.is_subset(&tables),
            "missing Phase 0 tables: {:?}",
            expected.difference(&tables).collect::<Vec<_>>()
        );

        let mut statement = store
            .connection
            .prepare("SELECT name FROM pragma_table_info('journal_event')")
            .expect("prepare journal column query");
        let columns = statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query journal columns")
            .collect::<rusqlite::Result<BTreeSet<_>>>()
            .expect("collect journal columns");
        for column in ["causation_id", "policy_version", "sensitivity"] {
            assert!(columns.contains(column), "missing journal column {column}");
        }
    }

    #[test]
    fn session_inbox_deduplicates_each_delivery() {
        let store = SqliteStore::open_in_memory(NOW).expect("open store");
        store
            .connection
            .execute(
                "INSERT INTO session(\
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms\
                 ) VALUES ('session', 'principal', 'binding', ?1, ?1)",
                [NOW],
            )
            .expect("insert session");
        store
            .connection
            .execute(
                "INSERT INTO session_inbox(\
                    inbox_entry_id, session_id, sequence, dedupe_key, delivery_mode, content, \
                    admission_event_id, acknowledgement_outbox_id, correlation_id, accepted_at_ms\
                 ) VALUES (\
                    'entry-1', 'session', 1, 'delivery', 'queue', 'hello', \
                    'event-1', 'outbox-1', 'correlation', ?1\
                 )",
                [NOW],
            )
            .expect("insert inbox entry");
        let duplicate_delivery = store
            .connection
            .execute(
                "INSERT INTO session_inbox(\
                    inbox_entry_id, session_id, sequence, dedupe_key, delivery_mode, content, \
                    admission_event_id, acknowledgement_outbox_id, correlation_id, accepted_at_ms\
                 ) VALUES (\
                    'entry-2', 'session', 2, 'delivery', 'queue', 'duplicate', \
                    'event-2', 'outbox-2', 'correlation', ?1\
                 )",
                [NOW],
            )
            .expect_err("session delivery dedupe key must be unique");
        assert!(matches!(
            duplicate_delivery,
            rusqlite::Error::SqliteFailure(failure, _)
                if failure.code == rusqlite::ErrorCode::ConstraintViolation
        ));
    }

    #[test]
    fn foundation_constraints_guard_leases_and_effect_retries() {
        let store = SqliteStore::open_in_memory(NOW).expect("open store");
        store
            .connection
            .execute(
                "INSERT INTO task(id, status, revision, validation_required)
                 VALUES ('task', 'queued', 0, 0)",
                [],
            )
            .expect("insert task");
        store
            .connection
            .execute(
                "INSERT INTO run(\
                    id, task_id, agent_role, capability_ceiling_json, budget_json, correlation_id, \
                    created_at_ms, updated_at_ms\
                 ) VALUES ('run', 'task', 'worker', '{}', '{}', 'correlation', ?1, ?1)",
                [NOW],
            )
            .expect("insert run");
        store
            .connection
            .execute(
                "INSERT INTO work_lease(\
                    lease_id, run_id, owner_id, fencing_token, acquired_at_ms, heartbeat_at_ms, \
                    expires_at_ms\
                 ) VALUES ('lease-1', 'run', 'worker-1', 1, ?1, ?1, ?2)",
                [NOW, NOW + 100],
            )
            .expect("insert active lease");
        let competing_lease = store
            .connection
            .execute(
                "INSERT INTO work_lease(\
                    lease_id, run_id, owner_id, fencing_token, acquired_at_ms, heartbeat_at_ms, \
                    expires_at_ms\
                 ) VALUES ('lease-2', 'run', 'worker-2', 2, ?1, ?1, ?2)",
                [NOW, NOW + 100],
            )
            .expect_err("run cannot have two active leases");
        assert!(matches!(
            competing_lease,
            rusqlite::Error::SqliteFailure(failure, _)
                if failure.code == rusqlite::ErrorCode::ConstraintViolation
        ));

        let unsafe_effect = store
            .connection
            .execute(
                "INSERT INTO effect(\
                    id, task_id, run_id, tool_id, tool_version, normalized_arguments_json, \
                    subject_digest, idempotency_class, recovery_action, created_at_ms, updated_at_ms\
                 ) VALUES (\
                    'effect', 'task', 'run', 'tool', '1', '{}', \
                    'digest', 'non_idempotent', 'retry', ?1, ?1\
                 )",
                [NOW],
            )
            .expect_err("non-idempotent effect cannot be classified for automatic retry");
        assert!(matches!(
            unsafe_effect,
            rusqlite::Error::SqliteFailure(failure, _)
                if failure.code == rusqlite::ErrorCode::ConstraintViolation
        ));
    }

    #[test]
    fn old_initial_journal_schema_is_extended_in_place() {
        let database = TemporaryDatabase::new();
        let connection = rusqlite::Connection::open(&database.path).expect("create old database");
        connection
            .execute_batch(
                "CREATE TABLE journal_event (
                    event_id TEXT PRIMARY KEY,
                    aggregate_kind TEXT NOT NULL,
                    aggregate_id TEXT NOT NULL,
                    aggregate_sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    event_version INTEGER NOT NULL,
                    occurred_at_ms INTEGER NOT NULL,
                    actor_principal_id TEXT,
                    correlation_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
                    UNIQUE (aggregate_kind, aggregate_id, aggregate_sequence)
                ) STRICT;
                INSERT INTO journal_event(
                    event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type,
                    event_version, occurred_at_ms, actor_principal_id, correlation_id, payload_json
                ) VALUES (
                    'old-event', 'task', 'old-task', 0, 'task.created',
                    1, 1, NULL, 'old-correlation', '{}'
                );",
            )
            .expect("seed old initial schema");
        drop(connection);

        let store = SqliteStore::open(&database.path, NOW).expect("upgrade old initial schema");
        let envelope: (Option<String>, Option<String>, String) = store
            .connection
            .query_row(
                "SELECT causation_id, policy_version, sensitivity
                 FROM journal_event WHERE event_id = 'old-event'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("load upgraded journal row");
        assert_eq!(envelope, (None, None, "internal".to_owned()));
    }
}
