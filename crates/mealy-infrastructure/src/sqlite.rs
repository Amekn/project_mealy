use mealy_domain::{
    CorrelationId, EventId, OutboxId, PrincipalId, TaskId, TaskState, TaskStatus, TaskTransition,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::Value;
use std::{path::Path, time::Duration};
use thiserror::Error;

mod agent;
mod agent_effect;
mod artifact;
mod channel;
mod compaction;
mod context;
mod delegation;
mod discord;
mod effects;
mod extension;
mod memory;
mod operations;
mod outbox;
mod promotion;
mod recovery;
mod schedule;
mod scheduler;
mod sessions;
mod telegram;
mod timeline;
mod validation;

const MIGRATION_0001: &str = include_str!("../migrations/0001_foundation.sql");
const MIGRATION_0002: &str = include_str!("../migrations/0002_phase1_runtime.sql");
const MIGRATION_0003: &str = include_str!("../migrations/0003_phase1_services.sql");
const MIGRATION_0004: &str = include_str!("../migrations/0004_agent_loop.sql");
const MIGRATION_0005: &str = include_str!("../migrations/0005_effect_ledger.sql");
const MIGRATION_0006: &str = include_str!("../migrations/0006_effect_command_receipts.sql");
const MIGRATION_0007: &str = include_str!("../migrations/0007_agent_effect_loop.sql");
const MIGRATION_0008: &str = include_str!("../migrations/0008_validation_delegation.sql");
const MIGRATION_0009: &str = include_str!("../migrations/0009_memory_compaction.sql");
const MIGRATION_0010: &str = include_str!("../migrations/0010_extension_boundary.sql");
const MIGRATION_0011: &str = include_str!("../migrations/0011_operational_hardening.sql");
const MIGRATION_0012: &str = include_str!("../migrations/0012_agent_schedules.sql");
const MIGRATION_0013: &str = include_str!("../migrations/0013_telegram_channel.sql");
const MIGRATION_0014: &str = include_str!("../migrations/0014_discord_dm_channel.sql");
const MIGRATION_0015: &str = include_str!("../migrations/0015_usage_reporting.sql");
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const SYNCHRONOUS_POLICY: &str = "FULL";
/// Latest canonical schema revision understood by this binary.
pub const LATEST_SCHEMA_VERSION: i64 = 15;

/// SQLite-backed transition store.
pub struct SqliteStore {
    connection: Connection,
}

pub use operations::ArtifactBlobRecord;

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

    #[allow(clippy::too_many_lines)]
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
        let mut existing_version = read_schema_version(&transaction)?;
        if existing_version < 0 {
            return Err(StoreError::InvalidSchemaVersion(existing_version));
        }
        if existing_version > LATEST_SCHEMA_VERSION {
            return Err(StoreError::NewerSchema {
                found: existing_version,
                supported: LATEST_SCHEMA_VERSION,
            });
        }
        if existing_version == 0 {
            transaction.execute_batch(MIGRATION_0001)?;
            ensure_initial_journal_envelope(&transaction)?;
            transaction.execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (1, ?1)",
                [applied_at_ms],
            )?;
            existing_version = 1;
        }
        if existing_version == 1 {
            ensure_initial_journal_envelope(&transaction)?;
            transaction.execute_batch(MIGRATION_0002)?;
            ensure_phase_one_run_columns(&transaction)?;
            transaction.execute_batch(
                "CREATE INDEX IF NOT EXISTS run_claim_order_idx \
                 ON run (status, next_attempt_at_ms, created_at_ms, id);",
            )?;
            transaction.execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (2, ?1)",
                [applied_at_ms],
            )?;
            existing_version = 2;
        }
        if existing_version == 2 {
            transaction.execute_batch(MIGRATION_0003)?;
            transaction.execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (3, ?1)",
                [applied_at_ms],
            )?;
            existing_version = 3;
        }
        if existing_version == 3 {
            transaction.execute_batch(MIGRATION_0004)?;
            transaction.execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (4, ?1)",
                [applied_at_ms],
            )?;
            existing_version = 4;
        }
        if existing_version == 4 {
            transaction.execute_batch(MIGRATION_0005)?;
            transaction.execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (5, ?1)",
                [applied_at_ms],
            )?;
            existing_version = 5;
        }
        if existing_version == 5 {
            transaction.execute_batch(MIGRATION_0006)?;
            transaction.execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (6, ?1)",
                [applied_at_ms],
            )?;
            existing_version = 6;
        }
        if existing_version == 6 {
            transaction.execute_batch(MIGRATION_0007)?;
            transaction.execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (7, ?1)",
                [applied_at_ms],
            )?;
            existing_version = 7;
        }
        if existing_version == 7 {
            transaction.execute_batch(MIGRATION_0008)?;
            transaction.execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (8, ?1)",
                [applied_at_ms],
            )?;
            existing_version = 8;
        }
        if existing_version == 8 {
            transaction.execute_batch(MIGRATION_0009)?;
            transaction.execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (9, ?1)",
                [applied_at_ms],
            )?;
            existing_version = 9;
        }
        if existing_version == 9 {
            transaction.execute_batch(MIGRATION_0010)?;
            transaction.execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (10, ?1)",
                [applied_at_ms],
            )?;
            existing_version = 10;
        }
        if existing_version == 10 {
            transaction.execute_batch(MIGRATION_0011)?;
            transaction.execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (11, ?1)",
                [applied_at_ms],
            )?;
            existing_version = 11;
        }
        if existing_version == 11 {
            transaction.execute_batch(MIGRATION_0012)?;
            transaction.execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (12, ?1)",
                [applied_at_ms],
            )?;
            existing_version = 12;
        }
        if existing_version == 12 {
            transaction.execute_batch(MIGRATION_0013)?;
            transaction.execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (13, ?1)",
                [applied_at_ms],
            )?;
            existing_version = 13;
        }
        if existing_version == 13 {
            transaction.execute_batch(MIGRATION_0014)?;
            transaction.execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (14, ?1)",
                [applied_at_ms],
            )?;
            existing_version = 14;
        }
        if existing_version == 14 {
            transaction.execute_batch(MIGRATION_0015)?;
            transaction.execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (15, ?1)",
                [applied_at_ms],
            )?;
        }
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

    /// Verifies the active schema, foreign-key enforcement, and a bounded `SQLite` quick check.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if canonical storage is not ready for commands.
    pub fn readiness_check(&self) -> Result<(), StoreError> {
        let version = self.connection.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if version != LATEST_SCHEMA_VERSION {
            return Err(StoreError::NotReady(format!(
                "schema version {version} is not {LATEST_SCHEMA_VERSION}"
            )));
        }
        let foreign_keys: bool =
            self.connection
                .pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
        if !foreign_keys {
            return Err(StoreError::NotReady(
                "foreign-key enforcement is disabled".to_owned(),
            ));
        }
        let usage_index = self
            .connection
            .query_row(
                "SELECT sql FROM sqlite_schema \
                 WHERE type = 'index' AND tbl_name = 'run' \
                   AND name = 'run_terminal_completion_idx'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if usage_index.as_deref().is_none_or(|sql| {
            !sql.contains("ON run(completed_at_ms, id)")
                || !sql.contains("status IN ('succeeded', 'failed', 'cancelled')")
        }) {
            return Err(StoreError::NotReady(
                "terminal usage-report index is missing or malformed".to_owned(),
            ));
        }
        let quick_check = self
            .connection
            .query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0))?;
        if quick_check == "ok" {
            Ok(())
        } else {
            Err(StoreError::NotReady(format!(
                "SQLite quick check failed: {quick_check}"
            )))
        }
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
    /// The database was written by a newer Mealy schema than this binary understands.
    #[error("database schema version {found} is newer than supported version {supported}")]
    NewerSchema {
        /// Highest version recorded by the database.
        found: i64,
        /// Highest version implemented by this binary.
        supported: i64,
    },
    /// The schema history contained a nonsensical negative version.
    #[error("database schema version {0} is invalid")]
    InvalidSchemaVersion(i64),
    /// Canonical storage opened but cannot safely serve commands.
    #[error("store is not ready: {0}")]
    NotReady(String),
}

fn read_schema_version(transaction: &Transaction<'_>) -> Result<i64, StoreError> {
    let exists = transaction.query_row(
        "SELECT EXISTS(\
            SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'schema_version'\
        )",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if exists {
        transaction
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(StoreError::from)
    } else {
        Ok(0)
    }
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

fn ensure_phase_one_run_columns(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    add_column_if_missing_on(
        transaction,
        "run",
        "current_fencing_token",
        "ALTER TABLE run ADD COLUMN current_fencing_token INTEGER NOT NULL DEFAULT 0 \
         CHECK (current_fencing_token >= 0)",
    )?;
    add_column_if_missing_on(
        transaction,
        "run",
        "next_attempt_at_ms",
        "ALTER TABLE run ADD COLUMN next_attempt_at_ms INTEGER",
    )
}

fn add_column_if_missing(
    transaction: &Transaction<'_>,
    column: &str,
    alter_table: &str,
) -> Result<(), StoreError> {
    add_column_if_missing_on(transaction, "journal_event", column, alter_table)
}

fn add_column_if_missing_on(
    transaction: &Transaction<'_>,
    table: &str,
    column: &str,
    alter_table: &str,
) -> Result<(), StoreError> {
    let exists = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2)",
        params![table, column],
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
    use super::{
        JournalRecord, LATEST_SCHEMA_VERSION, MIGRATION_0001, MIGRATION_0002, MIGRATION_0003,
        MIGRATION_0004, MIGRATION_0005, MIGRATION_0006, MIGRATION_0007, MIGRATION_0008,
        MIGRATION_0009, MIGRATION_0010, OutboxRecord, SqliteStore, StoreError, TaskMutation,
        ensure_initial_journal_envelope, ensure_phase_one_run_columns,
    };
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

    #[test]
    fn phase_one_migration_assigns_stable_global_timeline_cursors() {
        let mut store = SqliteStore::open_in_memory(NOW).expect("open store");
        let mut task = TaskState::new(TaskId::new(), false);
        let created_event = EventId::new();
        let started_event = EventId::new();
        store
            .commit_task(
                &task,
                TaskMutation::Create,
                &journal(created_event, "task.created"),
                &[],
            )
            .expect("create task");
        let transition = task.start().expect("start task");
        store
            .commit_task(
                &task,
                TaskMutation::Transition(transition),
                &journal(started_event, "task.started"),
                &[],
            )
            .expect("start task");

        let cursors = store
            .connection
            .prepare("SELECT cursor, event_id FROM timeline_event ORDER BY cursor")
            .expect("prepare timeline query")
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .expect("query timeline")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect timeline");
        assert_eq!(
            cursors,
            vec![
                (1, created_event.to_string()),
                (2, started_event.to_string())
            ]
        );

        store
            .connection
            .execute_batch("VACUUM")
            .expect("vacuum database");
        let after_vacuum = store
            .connection
            .query_row(
                "SELECT MIN(cursor), MAX(cursor), COUNT(*) FROM timeline_event",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .expect("query cursors after vacuum");
        assert_eq!(after_vacuum, (1, 2, 2));
    }

    #[test]
    fn phase_one_upgrade_preserves_v1_journal_insertion_order_for_equal_timestamps() {
        let database = TemporaryDatabase::new();
        let connection = rusqlite::Connection::open(&database.path).expect("create v1 database");
        connection
            .execute_batch(MIGRATION_0001)
            .expect("install v1 schema");
        connection
            .execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (1, ?1)",
                [NOW],
            )
            .expect("record v1 migration");
        connection
            .execute_batch(
                "INSERT INTO journal_event(
                    event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type,
                    event_version, occurred_at_ms, correlation_id, payload_json
                 ) VALUES
                    ('event-z', 'task', 'task-z', 0, 'task.created', 1, 7, 'correlation', '{}');
                 INSERT INTO journal_event(
                    event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type,
                    event_version, occurred_at_ms, correlation_id, payload_json
                 ) VALUES
                    ('event-a', 'task', 'task-a', 0, 'task.created', 1, 7, 'correlation', '{}');",
            )
            .expect("seed equal-timestamp v1 events in non-lexical order");
        drop(connection);

        let store = SqliteStore::open(&database.path, NOW + 1).expect("upgrade v1 database");
        let event_ids = store
            .connection
            .prepare("SELECT event_id FROM timeline_event ORDER BY cursor")
            .expect("prepare cursor query")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query upgraded cursors")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect upgraded cursors");
        assert_eq!(event_ids, vec!["event-z", "event-a"]);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn phase_two_upgrade_preserves_live_phase_one_graph() {
        let database = TemporaryDatabase::new();
        let mut connection =
            rusqlite::Connection::open(&database.path).expect("create v3 database");
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("enable foreign keys");
        let transaction = connection.transaction().expect("begin v3 setup");
        transaction
            .execute_batch(MIGRATION_0001)
            .expect("install v1 schema");
        ensure_initial_journal_envelope(&transaction).expect("extend journal envelope");
        transaction
            .execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (1, ?1)",
                [NOW],
            )
            .expect("record v1 migration");
        transaction
            .execute_batch(MIGRATION_0002)
            .expect("install v2 schema");
        ensure_phase_one_run_columns(&transaction).expect("extend run claim fields");
        transaction
            .execute_batch(
                "CREATE INDEX IF NOT EXISTS run_claim_order_idx
                    ON run (status, next_attempt_at_ms, created_at_ms, id);",
            )
            .expect("install v2 run index");
        transaction
            .execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (2, ?1)",
                [NOW],
            )
            .expect("record v2 migration");
        transaction
            .execute_batch(MIGRATION_0003)
            .expect("install v3 schema");
        transaction
            .execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (3, ?1)",
                [NOW],
            )
            .expect("record v3 migration");
        transaction
            .execute_batch(
                "INSERT INTO session(
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms
                 ) VALUES ('session', 'principal', 'binding', 1, 1);
                 INSERT INTO session_inbox(
                    inbox_entry_id, session_id, sequence, dedupe_key, delivery_mode, content,
                    admission_event_id, acknowledgement_outbox_id, correlation_id, accepted_at_ms
                 ) VALUES (
                    'inbox', 'session', 1, 'delivery', 'queue', 'hello',
                    'admission', 'ack', 'correlation', 1
                 );
                 INSERT INTO task(id, status, revision, validation_required)
                    VALUES ('task', 'running', 1, 0);
                 INSERT INTO run(
                    id, task_id, status, revision, agent_role, capability_ceiling_json,
                    budget_json, correlation_id, created_at_ms, updated_at_ms,
                    current_fencing_token
                 ) VALUES (
                    'run', 'task', 'running', 1, 'assistant', '{}', '{}', 'correlation',
                    1, 1, 1
                 );
                 INSERT INTO turn(
                    id, session_id, inbox_entry_id, task_id, run_id, correlation_id, created_at_ms
                 ) VALUES ('turn', 'session', 'inbox', 'task', 'run', 'correlation', 1);
                 INSERT INTO work_lease(
                    lease_id, run_id, owner_id, fencing_token, acquired_at_ms,
                    heartbeat_at_ms, expires_at_ms
                 ) VALUES ('lease', 'run', 'worker', 1, 1, 1, 10);
                 UPDATE session SET active_turn_id = 'turn', revision = 1 WHERE id = 'session';
                 UPDATE session_inbox
                    SET state = 'promoted', promoted_at_ms = 1, promoted_turn_id = 'turn'
                    WHERE inbox_entry_id = 'inbox';",
            )
            .expect("seed live v3 graph");
        transaction.commit().expect("commit v3 setup");
        drop(connection);

        let store = SqliteStore::open(&database.path, NOW + 1).expect("upgrade v3 database");
        let preserved: (
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
        ) = store
            .connection
            .query_row(
                "SELECT s.id, t.id, r.id, l.lease_id,
                        s.current_context_epoch_id, t.context_epoch_id
                 FROM session s
                 JOIN turn t ON t.session_id = s.id
                 JOIN run r ON r.id = t.run_id
                 JOIN work_lease l ON l.run_id = r.id",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .expect("load preserved graph");
        assert_eq!(
            preserved,
            (
                "session".to_owned(),
                "turn".to_owned(),
                "run".to_owned(),
                "lease".to_owned(),
                None,
                None,
            )
        );
        let version: i64 = store
            .connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .expect("read upgraded version");
        assert_eq!(version, LATEST_SCHEMA_VERSION);
        let foreign_key_violations: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .expect("check upgraded foreign keys");
        assert_eq!(foreign_key_violations, 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn phase_three_upgrade_preserves_live_phase_two_graph_and_history() {
        let database = TemporaryDatabase::new();
        let mut connection =
            rusqlite::Connection::open(&database.path).expect("create v4 database");
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("enable foreign keys");
        let transaction = connection.transaction().expect("begin v4 setup");
        transaction
            .execute_batch(MIGRATION_0001)
            .expect("install v1 schema");
        ensure_initial_journal_envelope(&transaction).expect("extend journal envelope");
        transaction
            .execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (1, ?1)",
                [NOW],
            )
            .expect("record v1 migration");
        transaction
            .execute_batch(MIGRATION_0002)
            .expect("install v2 schema");
        ensure_phase_one_run_columns(&transaction).expect("extend run claim fields");
        transaction
            .execute_batch(
                "CREATE INDEX IF NOT EXISTS run_claim_order_idx
                    ON run (status, next_attempt_at_ms, created_at_ms, id);",
            )
            .expect("install v2 run index");
        transaction
            .execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (2, ?1)",
                [NOW],
            )
            .expect("record v2 migration");
        transaction
            .execute_batch(MIGRATION_0003)
            .expect("install v3 schema");
        transaction
            .execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (3, ?1)",
                [NOW],
            )
            .expect("record v3 migration");
        transaction
            .execute_batch(MIGRATION_0004)
            .expect("install v4 schema");
        transaction
            .execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (4, ?1)",
                [NOW],
            )
            .expect("record v4 migration");
        transaction
            .execute_batch(
                "INSERT INTO session(
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms
                 ) VALUES ('session-v4', 'principal-v4', 'binding-v4', 1, 1);
                 INSERT INTO session_inbox(
                    inbox_entry_id, session_id, sequence, dedupe_key, delivery_mode, content,
                    admission_event_id, acknowledgement_outbox_id, correlation_id, accepted_at_ms
                 ) VALUES (
                    'inbox-v4', 'session-v4', 1, 'delivery-v4', 'queue', 'hello',
                    'admission-v4', 'ack-v4', 'correlation-v4', 1
                 );
                 INSERT INTO task(id, status, revision, validation_required)
                    VALUES ('task-v4', 'running', 1, 0);
                 INSERT INTO run(
                    id, task_id, status, revision, agent_role, capability_ceiling_json,
                    budget_json, correlation_id, created_at_ms, updated_at_ms,
                    current_fencing_token
                 ) VALUES (
                    'run-v4', 'task-v4', 'running', 1, 'assistant', '{}', '{}',
                    'correlation-v4', 1, 1, 1
                 );
                 INSERT INTO turn(
                    id, session_id, inbox_entry_id, task_id, run_id, correlation_id, created_at_ms
                 ) VALUES (
                    'turn-v4', 'session-v4', 'inbox-v4', 'task-v4', 'run-v4',
                    'correlation-v4', 1
                 );
                 INSERT INTO work_lease(
                    lease_id, run_id, owner_id, fencing_token, acquired_at_ms,
                    heartbeat_at_ms, expires_at_ms
                 ) VALUES ('lease-v4', 'run-v4', 'worker-v4', 1, 1, 1, 1000);
                 INSERT INTO context_epoch(
                    id, session_id, epoch_number, baseline_version, baseline_digest,
                    baseline_text, agent_profile_json, workspace_identity, config_digest,
                    policy_digest, created_at_ms
                 ) VALUES (
                    'epoch-v4', 'session-v4', 1, 'baseline-v1',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    'durable baseline', '{}', 'workspace-v4',
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                    'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 2
                 );
                 UPDATE session SET current_context_epoch_id = 'epoch-v4', revision = 1
                    WHERE id = 'session-v4';
                 UPDATE turn SET context_epoch_id = 'epoch-v4' WHERE id = 'turn-v4';
                 INSERT INTO context_manifest(
                    id, run_id, session_id, turn_id, epoch_id, iteration, compiler_version,
                    provider_residency, token_budget, total_token_estimate,
                    tool_schema_set_digest, policy_version, projection_digest, created_at_ms
                 ) VALUES (
                    'manifest-v4', 'run-v4', 'session-v4', 'turn-v4', 'epoch-v4', 1,
                    'compiler-v1', 'local', 1024, 4,
                    'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
                    'policy-v1',
                    'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 3
                 );
                 INSERT INTO context_manifest_item(
                    manifest_id, ordinal, item_id, disposition, source_type, source_locator,
                    source_content_digest, rendered_content_digest, inclusion_reason,
                    sensitivity, token_estimate, transformation, policy_decision, content_text
                 ) VALUES (
                    'manifest-v4', 0, 'item-v4', 'included', 'input', 'inbox-v4',
                    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                    'owner input', 'internal', 4, 'none', 'included', 'hello'
                 );
                 INSERT INTO run_loop_state(
                    run_id, revision, iteration, next_action, current_manifest_id, updated_at_ms
                 ) VALUES ('run-v4', 1, 1, 'compile_context', 'manifest-v4', 3);
                 INSERT INTO journal_event(
                    event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type,
                    event_version, occurred_at_ms, correlation_id, sensitivity, payload_json
                 ) VALUES (
                    'checkpoint-event-v4', 'run', 'run-v4', 0, 'loop.checkpointed', 1, 3,
                    'correlation-v4', 'internal', '{\"nextAction\":\"compile_context\"}'
                 );
                 INSERT INTO aggregate_sequence(aggregate_kind, aggregate_id, sequence)
                    VALUES ('run', 'run-v4', 0);
                 INSERT INTO loop_checkpoint(
                    run_id, sequence, prior_sequence, loop_version, next_action, manifest_id,
                    decision_json, prior_checkpoint_digest, checkpoint_digest, event_id,
                    created_at_ms
                 ) VALUES (
                    'run-v4', 0, NULL, 'loop-v1', 'compile_context', 'manifest-v4', '{}', NULL,
                    '1111111111111111111111111111111111111111111111111111111111111111',
                    'checkpoint-event-v4', 3
                 );",
            )
            .expect("seed live v4 graph and history");
        transaction.commit().expect("commit v4 setup");
        drop(connection);

        let store = SqliteStore::open(&database.path, NOW + 1).expect("upgrade v4 database");
        let preserved: (String, String, String, String, String, String, i64) = store
            .connection
            .query_row(
                "SELECT session.id, turn.id, run.id, lease.lease_id, epoch.id, manifest.id,
                        checkpoint.sequence
                 FROM session
                 JOIN turn ON turn.session_id = session.id
                 JOIN run ON run.id = turn.run_id
                 JOIN work_lease lease ON lease.run_id = run.id
                 JOIN context_epoch epoch ON epoch.id = session.current_context_epoch_id
                 JOIN context_manifest manifest ON manifest.epoch_id = epoch.id
                 JOIN loop_checkpoint checkpoint ON checkpoint.run_id = run.id",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .expect("load preserved phase two graph");
        assert_eq!(
            preserved,
            (
                "session-v4".to_owned(),
                "turn-v4".to_owned(),
                "run-v4".to_owned(),
                "lease-v4".to_owned(),
                "epoch-v4".to_owned(),
                "manifest-v4".to_owned(),
                0,
            )
        );
        let history: (String, i64) = store
            .connection
            .query_row(
                "SELECT journal.event_type, timeline.cursor
                 FROM journal_event journal
                 JOIN timeline_event timeline ON timeline.event_id = journal.event_id
                 WHERE journal.event_id = 'checkpoint-event-v4'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("load preserved phase two history");
        assert_eq!(history.0, "loop.checkpointed");
        assert!(history.1 > 0);
        let version: i64 = store
            .connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .expect("read upgraded version");
        assert_eq!(version, LATEST_SCHEMA_VERSION);
        let foreign_key_violations: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .expect("check upgraded foreign keys");
        assert_eq!(foreign_key_violations, 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn phase_four_upgrade_preserves_v7_tasks_and_backfills_explicit_contracts() {
        let database = TemporaryDatabase::new();
        let mut connection =
            rusqlite::Connection::open(&database.path).expect("create v7 database");
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("enable foreign keys");
        let transaction = connection.transaction().expect("begin v7 setup");
        transaction
            .execute_batch(MIGRATION_0001)
            .expect("install v1 schema");
        ensure_initial_journal_envelope(&transaction).expect("extend journal envelope");
        transaction
            .execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (1, ?1)",
                [NOW],
            )
            .expect("record v1 migration");
        transaction
            .execute_batch(MIGRATION_0002)
            .expect("install v2 schema");
        ensure_phase_one_run_columns(&transaction).expect("extend run claim fields");
        transaction
            .execute_batch(
                "CREATE INDEX IF NOT EXISTS run_claim_order_idx \
                 ON run (status, next_attempt_at_ms, created_at_ms, id);",
            )
            .expect("install v2 run index");
        transaction
            .execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (2, ?1)",
                [NOW],
            )
            .expect("record v2 migration");
        for (version, migration) in [
            (3_i64, MIGRATION_0003),
            (4, MIGRATION_0004),
            (5, MIGRATION_0005),
            (6, MIGRATION_0006),
            (7, MIGRATION_0007),
        ] {
            transaction
                .execute_batch(migration)
                .unwrap_or_else(|error| panic!("install v{version} schema: {error}"));
            transaction
                .execute(
                    "INSERT INTO schema_version(version, applied_at_ms) VALUES (?1, ?2)",
                    [version, NOW],
                )
                .unwrap_or_else(|error| panic!("record v{version} migration: {error}"));
        }
        transaction
            .execute_batch(
                "INSERT INTO session(\
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms\
                 ) VALUES ('session-v7', 'principal-v7', 'binding-v7', 1, 5);\
                 INSERT INTO session_inbox(\
                    inbox_entry_id, session_id, sequence, dedupe_key, delivery_mode, content,\
                    admission_event_id, acknowledgement_outbox_id, correlation_id, accepted_at_ms\
                 ) VALUES (\
                    'inbox-v7', 'session-v7', 1, 'delivery-v7', 'queue', 'legacy task input',\
                    'admission-v7', 'ack-v7', 'correlation-v7', 1\
                 );\
                 INSERT INTO task(id, status, revision, validation_required)\
                    VALUES ('task-v7', 'succeeded', 2, 0);\
                 INSERT INTO run(\
                    id, task_id, status, revision, agent_role, capability_ceiling_json,\
                    budget_json, correlation_id, created_at_ms, updated_at_ms, completed_at_ms,\
                    current_fencing_token, result_json\
                 ) VALUES (\
                    'run-v7', 'task-v7', 'succeeded', 2, 'assistant', '{}', '{}',\
                    'correlation-v7', 2, 5, 5, 0, '{\"status\":\"succeeded\"}'\
                 );\
                 INSERT INTO turn(\
                    id, session_id, inbox_entry_id, task_id, run_id, status, revision,\
                    correlation_id, created_at_ms, completed_at_ms\
                 ) VALUES (\
                    'turn-v7', 'session-v7', 'inbox-v7', 'task-v7', 'run-v7', 'completed', 1,\
                    'correlation-v7', 2, 5\
                 );\
                 UPDATE session_inbox SET state = 'promoted', promoted_at_ms = 2,\
                    promoted_turn_id = 'turn-v7' WHERE inbox_entry_id = 'inbox-v7';\
                 INSERT INTO run_budget_usage(\
                    run_id, maximum_model_calls, maximum_tool_calls, maximum_retries,\
                    maximum_input_tokens, maximum_output_tokens, maximum_cost_microunits,\
                    maximum_output_bytes, maximum_wall_time_ms, started_at_ms, deadline_at_ms\
                 ) VALUES ('run-v7', 4, 2, 1, 32768, 4096, 1000000, 4194304, 120000, 2, 120002);",
            )
            .expect("seed terminal v7 task graph");
        transaction.commit().expect("commit v7 setup");
        drop(connection);

        let store = SqliteStore::open(&database.path, NOW + 1).expect("upgrade v7 database");
        let preserved: (String, String, String, String, i64, i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT session.id, turn.id, task.id, run.id, task.revision, run.revision, \
                        run_budget.maximum_delegated_runs, \
                        run_budget.used_delegated_runs + run_budget.reserved_delegated_runs \
                 FROM session \
                 JOIN turn ON turn.session_id = session.id \
                 JOIN task ON task.id = turn.task_id \
                 JOIN run ON run.id = turn.run_id \
                 JOIN run_budget_usage run_budget ON run_budget.run_id = run.id",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .expect("load preserved v7 graph");
        assert_eq!(
            preserved,
            (
                "session-v7".to_owned(),
                "turn-v7".to_owned(),
                "task-v7".to_owned(),
                "run-v7".to_owned(),
                2,
                2,
                0,
                0,
            )
        );
        let criteria: (String, String, String, String) = store
            .connection
            .query_row(
                "SELECT objective, criteria_json, no_objective_criteria_reason, risk_class \
                 FROM task_success_criteria WHERE task_id = 'task-v7'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("load legacy criteria backfill");
        assert_eq!(criteria.1, "[]");
        assert!(!criteria.0.is_empty());
        assert!(!criteria.2.is_empty());
        assert_eq!(criteria.3, "low");
        let lineage: (String, Option<String>, i64, String, Option<String>) = store
            .connection
            .query_row(
                "SELECT root_run_id, parent_run_id, depth, relation_kind, relation_id \
                 FROM run_lineage WHERE run_id = 'run-v7'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("load root lineage backfill");
        assert_eq!(
            lineage,
            ("run-v7".to_owned(), None, 0, "root".to_owned(), None)
        );
        let version: i64 = store
            .connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .expect("read upgraded version");
        assert_eq!(version, LATEST_SCHEMA_VERSION);
        let foreign_key_violations: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .expect("check upgraded foreign keys");
        assert_eq!(foreign_key_violations, 0);
    }

    #[test]
    fn phase_five_upgrade_preserves_v8_sessions_and_installs_lexical_memory_schema() {
        let mut connection = rusqlite::Connection::open_in_memory().expect("create v8 database");
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("enable foreign keys");
        let transaction = connection.transaction().expect("begin v8 setup");
        transaction
            .execute_batch(MIGRATION_0001)
            .expect("install v1 schema");
        ensure_initial_journal_envelope(&transaction).expect("extend journal envelope");
        transaction
            .execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (1, ?1)",
                [NOW],
            )
            .expect("record v1 migration");
        transaction
            .execute_batch(MIGRATION_0002)
            .expect("install v2 schema");
        ensure_phase_one_run_columns(&transaction).expect("extend run claim fields");
        transaction
            .execute_batch(
                "CREATE INDEX IF NOT EXISTS run_claim_order_idx \
                 ON run (status, next_attempt_at_ms, created_at_ms, id);",
            )
            .expect("install v2 run index");
        transaction
            .execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (2, ?1)",
                [NOW],
            )
            .expect("record v2 migration");
        for (version, migration) in [
            (3_i64, MIGRATION_0003),
            (4, MIGRATION_0004),
            (5, MIGRATION_0005),
            (6, MIGRATION_0006),
            (7, MIGRATION_0007),
            (8, MIGRATION_0008),
        ] {
            transaction
                .execute_batch(migration)
                .unwrap_or_else(|error| panic!("install v{version} schema: {error}"));
            transaction
                .execute(
                    "INSERT INTO schema_version(version, applied_at_ms) VALUES (?1, ?2)",
                    [version, NOW],
                )
                .unwrap_or_else(|error| panic!("record v{version} migration: {error}"));
        }
        transaction
            .execute(
                "INSERT INTO session(\
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms\
                 ) VALUES ('session-v8', 'principal-v8', 'binding-v8', 1, 2)",
                [],
            )
            .expect("seed v8 session");
        transaction.commit().expect("commit v8 setup");

        let store =
            SqliteStore::from_connection(connection, NOW + 1, false).expect("upgrade v8 database");
        let preserved: (String, String, String) = store
            .connection
            .query_row(
                "SELECT id, principal_id, channel_binding_id FROM session WHERE id = 'session-v8'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("load preserved v8 session");
        assert_eq!(
            preserved,
            (
                "session-v8".to_owned(),
                "principal-v8".to_owned(),
                "binding-v8".to_owned(),
            )
        );
        let version: i64 = store
            .connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .expect("load v9 schema version");
        assert_eq!(version, LATEST_SCHEMA_VERSION);
        let lexical_rows: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM memory_fts", [], |row| row.get(0))
            .expect("query Phase 5 lexical index");
        assert_eq!(lexical_rows, 0);
        let foreign_key_violations: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .expect("check upgraded foreign keys");
        assert_eq!(foreign_key_violations, 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn phase_six_upgrade_preserves_v9_identity_and_installs_revocable_boundaries() {
        let mut connection = rusqlite::Connection::open_in_memory().expect("create v9 database");
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("enable foreign keys");
        let transaction = connection.transaction().expect("begin v9 setup");
        transaction
            .execute_batch(MIGRATION_0001)
            .expect("install v1 schema");
        ensure_initial_journal_envelope(&transaction).expect("extend journal envelope");
        transaction
            .execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (1, ?1)",
                [NOW],
            )
            .expect("record v1 migration");
        transaction
            .execute_batch(MIGRATION_0002)
            .expect("install v2 schema");
        ensure_phase_one_run_columns(&transaction).expect("extend run claim fields");
        transaction
            .execute_batch(
                "CREATE INDEX IF NOT EXISTS run_claim_order_idx \
                 ON run (status, next_attempt_at_ms, created_at_ms, id);",
            )
            .expect("install v2 run index");
        transaction
            .execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (2, ?1)",
                [NOW],
            )
            .expect("record v2 migration");
        for (version, migration) in [
            (3_i64, MIGRATION_0003),
            (4, MIGRATION_0004),
            (5, MIGRATION_0005),
            (6, MIGRATION_0006),
            (7, MIGRATION_0007),
            (8, MIGRATION_0008),
            (9, MIGRATION_0009),
        ] {
            transaction
                .execute_batch(migration)
                .unwrap_or_else(|error| panic!("install v{version} schema: {error}"));
            transaction
                .execute(
                    "INSERT INTO schema_version(version, applied_at_ms) VALUES (?1, ?2)",
                    [version, NOW],
                )
                .unwrap_or_else(|error| panic!("record v{version} migration: {error}"));
        }
        transaction
            .execute(
                "INSERT INTO session(\
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms\
                 ) VALUES ('session-v9', 'principal-v9', 'binding-v9', 1, 2)",
                [],
            )
            .expect("seed v9 identity");
        transaction.commit().expect("commit v9 setup");

        let store =
            SqliteStore::from_connection(connection, NOW + 1, false).expect("upgrade v9 database");
        let preserved: (String, String, String, String, String) = store
            .connection
            .query_row(
                "SELECT session.id, principal.status, binding.status, binding.channel_kind, \
                        binding.principal_id \
                 FROM session \
                 JOIN principal_registry principal ON principal.principal_id = session.principal_id \
                 JOIN channel_binding_registry binding \
                   ON binding.binding_id = session.channel_binding_id",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("load preserved Phase 6 identity registry");
        assert_eq!(
            preserved,
            (
                "session-v9".to_owned(),
                "active".to_owned(),
                "active".to_owned(),
                "legacy_session".to_owned(),
                "principal-v9".to_owned(),
            )
        );
        for table in [
            "extension_installation",
            "extension_invocation",
            "webhook_channel_binding",
            "webhook_delivery_receipt",
        ] {
            let installed: bool = store
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
                    [table],
                    |row| row.get(0),
                )
                .expect("query Phase 6 table");
            assert!(installed, "Phase 6 table {table} is absent");
        }
        let version: i64 = store
            .connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .expect("load v10 schema version");
        assert_eq!(version, LATEST_SCHEMA_VERSION);
        let foreign_key_violations: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .expect("check upgraded foreign keys");
        assert_eq!(foreign_key_violations, 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn phase_seven_upgrade_preserves_v10_boundaries_and_installs_lifetime_evidence() {
        let mut connection = rusqlite::Connection::open_in_memory().expect("create v10 database");
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("enable foreign keys");
        let transaction = connection.transaction().expect("begin v10 setup");
        transaction
            .execute_batch(MIGRATION_0001)
            .expect("install v1 schema");
        ensure_initial_journal_envelope(&transaction).expect("extend journal envelope");
        transaction
            .execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (1, ?1)",
                [NOW],
            )
            .expect("record v1 migration");
        transaction
            .execute_batch(MIGRATION_0002)
            .expect("install v2 schema");
        ensure_phase_one_run_columns(&transaction).expect("extend run claim fields");
        transaction
            .execute_batch(
                "CREATE INDEX IF NOT EXISTS run_claim_order_idx \
                 ON run (status, next_attempt_at_ms, created_at_ms, id);",
            )
            .expect("install v2 run index");
        transaction
            .execute(
                "INSERT INTO schema_version(version, applied_at_ms) VALUES (2, ?1)",
                [NOW],
            )
            .expect("record v2 migration");
        for (version, migration) in [
            (3_i64, MIGRATION_0003),
            (4, MIGRATION_0004),
            (5, MIGRATION_0005),
            (6, MIGRATION_0006),
            (7, MIGRATION_0007),
            (8, MIGRATION_0008),
            (9, MIGRATION_0009),
            (10, MIGRATION_0010),
        ] {
            transaction
                .execute_batch(migration)
                .unwrap_or_else(|error| panic!("install v{version} schema: {error}"));
            transaction
                .execute(
                    "INSERT INTO schema_version(version, applied_at_ms) VALUES (?1, ?2)",
                    [version, NOW],
                )
                .unwrap_or_else(|error| panic!("record v{version} migration: {error}"));
        }
        transaction
            .execute_batch(
                "INSERT INTO principal_registry(
                    principal_id, status, revision, created_at_ms, updated_at_ms
                 ) VALUES ('principal-v10', 'active', 0, 1, 1);
                 INSERT INTO channel_binding_registry(
                    binding_id, principal_id, channel_kind, status, revision,
                    created_at_ms, updated_at_ms
                 ) VALUES (
                    'binding-v10', 'principal-v10', 'local_cli', 'active', 0, 1, 1
                 );
                 INSERT INTO session(
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms
                 ) VALUES ('session-v10', 'principal-v10', 'binding-v10', 1, 2);",
            )
            .expect("seed v10 identity and session");
        transaction.commit().expect("commit v10 setup");

        let store =
            SqliteStore::from_connection(connection, NOW + 1, false).expect("upgrade v10 database");
        let preserved: (String, String, String) = store
            .connection
            .query_row(
                "SELECT session.id, principal.status, binding.status
                 FROM session
                 JOIN principal_registry principal ON principal.principal_id = session.principal_id
                 JOIN channel_binding_registry binding
                   ON binding.binding_id = session.channel_binding_id",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("load preserved v10 identity");
        assert_eq!(
            preserved,
            (
                "session-v10".to_owned(),
                "active".to_owned(),
                "active".to_owned()
            )
        );
        let daemon_table: bool = store
            .connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_schema
                    WHERE type = 'table' AND name = 'daemon_run_record'
                 )",
                [],
                |row| row.get(0),
            )
            .expect("query daemon lifetime table");
        assert!(daemon_table);
        assert_eq!(
            store.schema_version().expect("schema version"),
            u64::try_from(LATEST_SCHEMA_VERSION).expect("nonnegative schema version")
        );
        store
            .verify_storage_integrity()
            .expect("upgraded integrity");
    }

    #[test]
    fn usage_reporting_upgrade_installs_only_the_terminal_completion_index() {
        let store = SqliteStore::open_in_memory(NOW).expect("current in-memory store");
        store
            .connection
            .execute_batch(
                "DROP INDEX run_terminal_completion_idx;
                 DELETE FROM schema_version WHERE version = 15;",
            )
            .expect("construct exact v14 predecessor");
        let connection = store.connection;
        let upgraded = SqliteStore::from_connection(connection, NOW + 1, false)
            .expect("upgrade v14 usage schema");
        assert_eq!(
            upgraded.schema_version().expect("schema version"),
            u64::try_from(LATEST_SCHEMA_VERSION).expect("nonnegative schema version")
        );
        let index_sql: String = upgraded
            .connection
            .query_row(
                "SELECT sql FROM sqlite_schema \
                 WHERE type = 'index' AND name = 'run_terminal_completion_idx'",
                [],
                |row| row.get(0),
            )
            .expect("terminal completion index");
        assert!(index_sql.contains("ON run(completed_at_ms, id)"));
        assert!(index_sql.contains("status IN ('succeeded', 'failed', 'cancelled')"));
        upgraded
            .verify_storage_integrity()
            .expect("upgraded integrity");
        upgraded
            .connection
            .execute("DROP INDEX run_terminal_completion_idx", [])
            .expect("tamper usage index");
        assert!(matches!(
            upgraded.readiness_check(),
            Err(StoreError::NotReady(message))
                if message == "terminal usage-report index is missing or malformed"
        ));
    }

    #[test]
    fn malformed_schema_version_table_fails_without_bootstrapping_over_it() {
        let database = TemporaryDatabase::new();
        let connection =
            rusqlite::Connection::open(&database.path).expect("create malformed database");
        connection
            .execute_batch(
                "CREATE TABLE schema_version(applied_at_ms INTEGER NOT NULL) STRICT;
                 INSERT INTO schema_version(applied_at_ms) VALUES (1);",
            )
            .expect("seed malformed migration history");
        drop(connection);

        let error = SqliteStore::open(&database.path, NOW)
            .err()
            .expect("malformed migration history must fail closed");
        assert!(matches!(error, StoreError::Sqlite(_)));
        let connection =
            rusqlite::Connection::open(&database.path).expect("reopen malformed database");
        let bootstrapped: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'session')",
                [],
                |row| row.get(0),
            )
            .expect("inspect rollback");
        assert!(!bootstrapped);
    }

    #[test]
    fn phase_two_schema_rejects_cross_principal_artifacts_and_unsafe_blob_paths() {
        let store = SqliteStore::open_in_memory(NOW).expect("open store");
        store
            .connection
            .execute_batch(
                "INSERT INTO session(
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms
                 ) VALUES
                    ('session-1', 'principal-1', 'binding-1', 1, 1),
                    ('session-2', 'principal-2', 'binding-2', 1, 1);",
            )
            .expect("seed owners");

        store
            .connection
            .execute(
                "INSERT INTO artifact_blob(
                    algorithm, digest, size_bytes, relative_path, committed_at_ms
                 ) VALUES ('sha256', ?1, 1, '../escape', 1)",
                ["a".repeat(64)],
            )
            .expect_err("artifact paths must remain beneath the private root");
        let digest = "b".repeat(64);
        store
            .connection
            .execute(
                "INSERT INTO artifact_blob(
                    algorithm, digest, size_bytes, relative_path, committed_at_ms
                 ) VALUES ('sha256', ?1, 1, 'sha256/redirected', 1)",
                [&digest],
            )
            .expect_err("artifact path must correspond to its content address");
        let relative_path = format!("sha256/{digest}");
        store
            .connection
            .execute(
                "INSERT INTO artifact_blob(
                    algorithm, digest, size_bytes, relative_path, committed_at_ms
                 ) VALUES ('sha256', ?1, 1, ?2, 1)",
                rusqlite::params![&digest, relative_path],
            )
            .expect("insert safe blob");

        let cross_principal = store.connection.execute(
            r#"INSERT INTO artifact(
                id, blob_algorithm, blob_digest, principal_id, session_id, media_type,
                origin_kind, origin_id, producer_kind, producer_id, sensitivity,
                retention_class, access_policy_json, access_policy_digest, created_at_ms
             ) VALUES (
                'artifact-cross', 'sha256', ?1, 'principal-1', 'session-2', 'text/plain',
                'provider', 'attempt', 'provider', 'fake', 'private', 'turn',
                '{"principalId":"principal-1","sessionId":"session-2"}', ?2, 1
             )"#,
            rusqlite::params![digest, "c".repeat(64)],
        );
        cross_principal.expect_err("artifact principal must own its session");

        store
            .connection
            .execute(
                r#"INSERT INTO artifact(
                    id, blob_algorithm, blob_digest, principal_id, session_id, media_type,
                    origin_kind, origin_id, producer_kind, producer_id, sensitivity,
                    retention_class, access_policy_json, access_policy_digest, created_at_ms
                 ) VALUES (
                    'artifact-1', 'sha256', ?1, 'principal-1', 'session-1', 'text/plain',
                    'provider', 'attempt', 'provider', 'fake', 'private', 'turn',
                    '{"principalId":"principal-1","sessionId":"session-1"}', ?2, 1
                 )"#,
                rusqlite::params![digest, "d".repeat(64)],
            )
            .expect("insert owned artifact");
        store
            .connection
            .execute(
                "INSERT INTO artifact_reference(
                    artifact_id, principal_id, session_id, owner_kind, owner_id, relation,
                    created_at_ms
                 ) VALUES ('artifact-1', 'principal-2', 'session-2', 'run', 'run-2', 'output', 1)",
                [],
            )
            .expect_err("artifact reference cannot relabel ownership");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn phase_two_schema_keeps_context_within_the_session_run_graph() {
        let store = SqliteStore::open_in_memory(NOW).expect("open store");
        store
            .connection
            .execute_batch(
                r#"INSERT INTO session(
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms
                 ) VALUES
                    ('session-1', 'principal-1', 'binding-1', 1, 1),
                    ('session-2', 'principal-2', 'binding-2', 1, 1);
                 INSERT INTO session_inbox(
                    inbox_entry_id, session_id, sequence, dedupe_key, delivery_mode, content,
                    admission_event_id, acknowledgement_outbox_id, correlation_id, accepted_at_ms
                 ) VALUES
                    ('inbox-1', 'session-1', 1, 'delivery-1', 'queue', 'one',
                     'admission-1', 'ack-1', 'correlation-1', 1),
                    ('inbox-2', 'session-2', 1, 'delivery-2', 'queue', 'two',
                     'admission-2', 'ack-2', 'correlation-2', 1);
                 INSERT INTO task(id, status, revision, validation_required) VALUES
                    ('task-1', 'queued', 0, 0), ('task-2', 'queued', 0, 0);
                 INSERT INTO run(
                    id, task_id, agent_role, capability_ceiling_json, budget_json,
                    correlation_id, created_at_ms, updated_at_ms
                 ) VALUES
                    ('run-1', 'task-1', 'assistant', '{}', '{}', 'correlation-1', 1, 1),
                    ('run-2', 'task-2', 'assistant', '{}', '{}', 'correlation-2', 1, 1);
                 INSERT INTO turn(
                    id, session_id, inbox_entry_id, task_id, run_id, correlation_id, created_at_ms
                 ) VALUES
                    ('turn-1', 'session-1', 'inbox-1', 'task-1', 'run-1', 'correlation-1', 1),
                    ('turn-2', 'session-2', 'inbox-2', 'task-2', 'run-2', 'correlation-2', 1);
                 INSERT INTO context_epoch(
                    id, session_id, epoch_number, baseline_version, baseline_digest, baseline_text,
                    agent_profile_json, workspace_identity, config_digest, policy_digest,
                    created_at_ms
                 ) VALUES
                    ('epoch-1', 'session-1', 1, 'v1',
                     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'baseline', '{}', 'workspace-1',
                     'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 1),
                    ('epoch-2', 'session-2', 1, 'v1',
                     'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
                     'baseline', '{}', 'workspace-2',
                     'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                     'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 1);
                 INSERT INTO artifact_blob(
                    algorithm, digest, size_bytes, relative_path, committed_at_ms
                 ) VALUES (
                    'sha256',
                    '9999999999999999999999999999999999999999999999999999999999999999',
                    1,
                    'sha256/9999999999999999999999999999999999999999999999999999999999999999',
                    1
                 );
                 INSERT INTO artifact(
                    id, blob_algorithm, blob_digest, principal_id, session_id, media_type,
                    origin_kind, origin_id, producer_kind, producer_id, sensitivity,
                    retention_class, access_policy_json, access_policy_digest, created_at_ms
                 ) VALUES (
                    'artifact-2', 'sha256',
                    '9999999999999999999999999999999999999999999999999999999999999999',
                    'principal-2', 'session-2', 'text/plain', 'provider', 'attempt-2',
                    'provider', 'fake', 'private', 'turn',
                    '{"principalId":"principal-2","sessionId":"session-2"}',
                    '8888888888888888888888888888888888888888888888888888888888888888', 1
                 );"#,
            )
            .expect("seed two work graphs");

        store
            .connection
            .execute(
                "UPDATE session SET current_context_epoch_id = 'epoch-2' WHERE id = 'session-1'",
                [],
            )
            .expect_err("session cannot select another session's epoch");
        store
            .connection
            .execute(
                "UPDATE turn SET context_epoch_id = 'epoch-2' WHERE id = 'turn-1'",
                [],
            )
            .expect_err("turn cannot pin another session's epoch");
        store
            .connection
            .execute(
                "UPDATE session SET current_context_epoch_id = 'epoch-1' WHERE id = 'session-1'",
                [],
            )
            .expect("session selects its active epoch");
        store
            .connection
            .execute(
                "UPDATE context_epoch SET retired_at_ms = 2 WHERE id = 'epoch-1'",
                [],
            )
            .expect_err("session's current epoch cannot be retired");
        store
            .connection
            .execute(
                "UPDATE turn SET context_epoch_id = 'epoch-1' WHERE id = 'turn-1'",
                [],
            )
            .expect("turn pins its session epoch");

        store
            .connection
            .execute(
                "INSERT INTO context_manifest(
                    id, run_id, session_id, turn_id, epoch_id, iteration, compiler_version,
                    provider_residency, token_budget, total_token_estimate,
                    tool_schema_set_digest, policy_version, projection_digest, created_at_ms
                 ) VALUES (
                    'manifest-cross', 'run-1', 'session-1', 'turn-1', 'epoch-2', 1, 'v1',
                    'local', 100, 10,
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'v1',
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 1
                 )",
                [],
            )
            .expect_err("manifest epoch must belong to its session");
        store
            .connection
            .execute(
                "INSERT INTO context_manifest(
                    id, run_id, session_id, turn_id, epoch_id, iteration, compiler_version,
                    provider_residency, token_budget, total_token_estimate,
                    tool_schema_set_digest, policy_version, projection_digest, created_at_ms
                 ) VALUES (
                    'manifest-over-budget', 'run-1', 'session-1', 'turn-1', 'epoch-1', 1, 'v1',
                    'local', 10, 11,
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'v1',
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 1
                 )",
                [],
            )
            .expect_err("manifest estimate cannot exceed its token budget");
        store
            .connection
            .execute_batch(
                "INSERT INTO context_manifest(
                    id, run_id, session_id, turn_id, epoch_id, iteration, compiler_version,
                    provider_residency, token_budget, total_token_estimate,
                    tool_schema_set_digest, policy_version, projection_digest, created_at_ms
                 ) VALUES (
                    'manifest-1', 'run-1', 'session-1', 'turn-1', 'epoch-1', 1, 'v1',
                    'local', 10, 1,
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'v1',
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 1
                 );",
            )
            .expect("insert valid manifest");
        store
            .connection
            .execute(
                "INSERT INTO context_manifest_item(
                    manifest_id, ordinal, item_id, disposition, source_type, source_locator,
                    source_content_digest, rendered_content_digest, inclusion_reason,
                    sensitivity, token_estimate, transformation, policy_decision,
                    content_artifact_id
                 ) VALUES (
                    'manifest-1', 0, 'cross-artifact', 'included', 'artifact', 'artifact-2',
                    '9999999999999999999999999999999999999999999999999999999999999999',
                    '9999999999999999999999999999999999999999999999999999999999999999',
                    'fixture', 'private', 1, 'none', 'included', 'artifact-2'
                 )",
                [],
            )
            .expect_err("context cannot include an artifact from another session");
    }

    #[test]
    fn phase_two_schema_commits_final_message_at_terminal_boundary() {
        let store = SqliteStore::open_in_memory(NOW).expect("open store");
        store
            .connection
            .execute_batch(
                "INSERT INTO session(
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms
                 ) VALUES ('session', 'principal', 'binding', 1, 1);
                 INSERT INTO session_inbox(
                    inbox_entry_id, session_id, sequence, dedupe_key, delivery_mode, content,
                    admission_event_id, acknowledgement_outbox_id, correlation_id, accepted_at_ms
                 ) VALUES (
                    'inbox', 'session', 1, 'delivery', 'queue', 'hello',
                    'admission', 'ack', 'correlation', 1
                 );
                 INSERT INTO task(id, status, revision, validation_required)
                    VALUES ('task', 'running', 0, 0);
                 INSERT INTO run(
                    id, task_id, status, agent_role, capability_ceiling_json, budget_json,
                    correlation_id, created_at_ms, updated_at_ms
                 ) VALUES (
                    'run', 'task', 'running', 'assistant', '{}', '{}', 'correlation', 1, 1
                 );
                 INSERT INTO turn(
                    id, session_id, inbox_entry_id, task_id, run_id, correlation_id, created_at_ms
                 ) VALUES ('turn', 'session', 'inbox', 'task', 'run', 'correlation', 1);
                 INSERT INTO work_lease(
                    lease_id, run_id, owner_id, fencing_token, acquired_at_ms,
                    heartbeat_at_ms, expires_at_ms
                 ) VALUES ('lease', 'run', 'worker', 1, 1, 1, 10);
                 INSERT INTO context_epoch(
                    id, session_id, epoch_number, baseline_version, baseline_digest, baseline_text,
                    agent_profile_json, workspace_identity, config_digest, policy_digest,
                    created_at_ms
                 ) VALUES (
                    'epoch', 'session', 1, 'v1',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    'baseline', '{}', 'workspace',
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                    'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 1
                 );
                 UPDATE session SET current_context_epoch_id = 'epoch' WHERE id = 'session';
                 UPDATE turn SET context_epoch_id = 'epoch' WHERE id = 'turn';
                 INSERT INTO context_manifest(
                    id, run_id, session_id, turn_id, epoch_id, iteration, compiler_version,
                    provider_residency, token_budget, total_token_estimate,
                    tool_schema_set_digest, policy_version, projection_digest, created_at_ms
                 ) VALUES (
                    'manifest', 'run', 'session', 'turn', 'epoch', 1, 'v1', 'local', 100, 0,
                    'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
                    'v1',
                    'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 1
                 );
                 INSERT INTO model_attempt(
                    attempt_id, run_id, ordinal, state, provider_id, adapter_version, model_id,
                    capability_snapshot_json, capability_digest, context_manifest_id,
                    routing_decision_json, tool_schema_digests_json, budget_reservation_json,
                    request_json, request_digest, timeout_ms, prepared_at_ms, dispatched_at_ms,
                    deadline_at_ms, completed_at_ms, response_kind, response_json, response_digest,
                    finish_reason, input_tokens, output_tokens, total_tokens, cost_microunits,
                    prepared_lease_id, prepared_owner_id, prepared_fencing_token
                 ) VALUES (
                    'attempt', 'run', 1, 'completed', 'provider', 'v1', 'model', '{}',
                    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                    'manifest', '{}', '[]', '{}', '{}',
                    '1111111111111111111111111111111111111111111111111111111111111111',
                    5, 1, 2, 6, 3, 'final', '{\"kind\":\"final\",\"text\":\"done\"}',
                    '2222222222222222222222222222222222222222222222222222222222222222',
                    'stop', 1, 1, 2, 0, 'lease', 'worker', 1
                 );
                 INSERT INTO run_loop_state(
                    run_id, iteration, next_action, current_manifest_id, current_attempt_id,
                    updated_at_ms
                 ) VALUES ('run', 1, 'commit_final', 'manifest', 'attempt', 3);",
            )
            .expect("commit-final boundary must exist before its final message");

        store
            .connection
            .execute(
                "UPDATE run_loop_state SET next_action = 'terminal' WHERE run_id = 'run'",
                [],
            )
            .expect_err("terminal state must bind the durable final message");
        store
            .connection
            .execute_batch(
                "INSERT INTO message(
                    id, principal_id, session_id, turn_id, task_id, run_id, ordinal, role,
                    media_type, byte_length, content_digest, content_inline, sensitivity,
                    source_attempt_id, created_at_ms
                 ) VALUES (
                    'message', 'principal', 'session', 'turn', 'task', 'run', 1, 'assistant',
                    'text/plain', 4,
                    '3333333333333333333333333333333333333333333333333333333333333333',
                    'done', 'internal', 'attempt', 4
                 );
                 UPDATE run_loop_state
                    SET next_action = 'terminal', final_message_id = 'message', updated_at_ms = 4
                    WHERE run_id = 'run';",
            )
            .expect("message insertion and terminal transition may share one transaction");
    }

    #[test]
    fn phase_two_schema_enforces_budget_caps_and_checkpoint_predecessors() {
        let store = SqliteStore::open_in_memory(NOW).expect("open store");
        store
            .connection
            .execute_batch(
                "INSERT INTO task(id, status, revision, validation_required)
                    VALUES ('task', 'queued', 0, 0);
                 INSERT INTO run(
                    id, task_id, agent_role, capability_ceiling_json, budget_json,
                    correlation_id, created_at_ms, updated_at_ms
                 ) VALUES ('run', 'task', 'assistant', '{}', '{}', 'correlation', 1, 1);",
            )
            .expect("seed run");

        store
            .connection
            .execute(
                "INSERT INTO run_budget_usage(
                    run_id, maximum_model_calls, maximum_tool_calls, maximum_retries,
                    maximum_input_tokens, maximum_output_tokens, maximum_cost_microunits,
                    maximum_output_bytes, maximum_wall_time_ms, used_input_tokens,
                    started_at_ms, deadline_at_ms
                 ) VALUES ('run', 1, 1, 0, 10, 10, 10, 10, 100, 11, 1, 101)",
                [],
            )
            .expect_err("used input tokens cannot exceed the configured maximum");
        store
            .connection
            .execute(
                "INSERT INTO run_loop_state(run_id, next_action, updated_at_ms)
                 VALUES ('run', 'dispatch_model', 1)",
                [],
            )
            .expect_err("dispatch requires a manifest and prepared attempt");

        store
            .connection
            .execute_batch(
                "INSERT INTO journal_event(
                    event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type,
                    event_version, occurred_at_ms, correlation_id, payload_json
                 ) VALUES
                    ('checkpoint-event-0', 'run', 'run', 0, 'loop.started', 1, 1,
                     'correlation', '{}'),
                    ('checkpoint-event-1', 'run', 'run', 1, 'loop.advanced', 1, 2,
                     'correlation', '{}');
                 INSERT INTO loop_checkpoint(
                    run_id, sequence, prior_sequence, loop_version, next_action, decision_json,
                    prior_checkpoint_digest, checkpoint_digest, event_id, created_at_ms
                 ) VALUES (
                    'run', 0, NULL, 'v1', 'compile_context', '{}', NULL,
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    'checkpoint-event-0', 1
                 );",
            )
            .expect("seed first checkpoint");
        store
            .connection
            .execute(
                "INSERT INTO loop_checkpoint(
                    run_id, sequence, prior_sequence, loop_version, next_action, decision_json,
                    prior_checkpoint_digest, checkpoint_digest, event_id, created_at_ms
                 ) VALUES (
                    'run', 1, 0, 'v1', 'compile_context', '{}',
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                    'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
                    'checkpoint-event-1', 2
                 )",
                [],
            )
            .expect_err("checkpoint must bind the exact predecessor digest");
    }

    #[test]
    fn newer_schema_is_rejected_without_modification() {
        let database = TemporaryDatabase::new();
        let connection =
            rusqlite::Connection::open(&database.path).expect("create future database");
        connection
            .execute_batch(
                "CREATE TABLE schema_version(
                    version INTEGER PRIMARY KEY,
                    applied_at_ms INTEGER NOT NULL
                ) STRICT;
                INSERT INTO schema_version(version, applied_at_ms) VALUES (99, 1);",
            )
            .expect("seed future version");
        drop(connection);

        let Err(error) = SqliteStore::open(&database.path, NOW) else {
            panic!("newer schema must fail closed");
        };
        assert!(matches!(
            error,
            StoreError::NewerSchema {
                found: 99,
                supported: LATEST_SCHEMA_VERSION
            }
        ));
        let connection =
            rusqlite::Connection::open(&database.path).expect("reopen future database");
        let session_table_exists: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'session'
                )",
                [],
                |row| row.get(0),
            )
            .expect("check future database");
        assert!(!session_table_exists);
    }
}
