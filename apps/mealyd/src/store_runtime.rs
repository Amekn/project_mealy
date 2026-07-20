//! Bounded `SQLite` runtime with one canonical writer and concurrent WAL snapshot readers.

use mealy_infrastructure::{SqliteStore, StoreError};
use std::{
    ops::Deref,
    path::{Path, PathBuf},
    sync::{
        Condvar, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use thiserror::Error;

/// Process-local access to the canonical `SQLite` database.
///
/// All mutations retain one serialized writer lane. Read-only compound use cases borrow a
/// separate connection and execute inside a deferred WAL snapshot, so unrelated history reads do
/// not create head-of-line blocking at provider, tool, heartbeat, or admission commits.
pub(crate) struct RuntimeStore {
    writer: Mutex<SqliteStore>,
    readers: Mutex<Vec<SqliteStore>>,
    reader_available: Condvar,
    reader_capacity: usize,
    database_path: PathBuf,
    writer_waits: AtomicU64,
    writer_maximum_wait_us: AtomicU64,
    reader_waits: AtomicU64,
    reader_maximum_wait_us: AtomicU64,
}

impl RuntimeStore {
    /// Builds a runtime around an already migrated primary connection.
    pub(crate) fn open(
        writer: SqliteStore,
        database_path: &Path,
        reader_capacity: usize,
    ) -> Result<Self, StoreError> {
        let reader_capacity = reader_capacity.max(1);
        let mut readers = Vec::with_capacity(reader_capacity);
        for _ in 0..reader_capacity {
            readers.push(SqliteStore::open_reader(database_path)?);
        }
        Ok(Self {
            writer: Mutex::new(writer),
            readers: Mutex::new(readers),
            reader_available: Condvar::new(),
            reader_capacity,
            database_path: database_path.to_path_buf(),
            writer_waits: AtomicU64::new(0),
            writer_maximum_wait_us: AtomicU64::new(0),
            reader_waits: AtomicU64::new(0),
            reader_maximum_wait_us: AtomicU64::new(0),
        })
    }

    /// Builds a one-reader runtime for in-memory unit tests.
    #[cfg(test)]
    pub(crate) fn single_for_test(writer: SqliteStore, reader: SqliteStore) -> Self {
        Self {
            writer: Mutex::new(writer),
            readers: Mutex::new(vec![reader]),
            reader_available: Condvar::new(),
            reader_capacity: 1,
            database_path: PathBuf::new(),
            writer_waits: AtomicU64::new(0),
            writer_maximum_wait_us: AtomicU64::new(0),
            reader_waits: AtomicU64::new(0),
            reader_maximum_wait_us: AtomicU64::new(0),
        }
    }

    /// Acquires the single canonical writer lane.
    pub(crate) fn write(&self) -> Result<MutexGuard<'_, SqliteStore>, StoreAccessError> {
        match self.writer.try_lock() {
            Ok(writer) => Ok(writer),
            Err(std::sync::TryLockError::Poisoned(_)) => Err(StoreAccessError::Poisoned),
            Err(std::sync::TryLockError::WouldBlock) => {
                self.writer_waits.fetch_add(1, Ordering::Relaxed);
                let started = Instant::now();
                let writer = self.writer.lock().map_err(|_| StoreAccessError::Poisoned)?;
                self.writer_maximum_wait_us.fetch_max(
                    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
                Ok(writer)
            }
        }
    }

    /// Attempts to acquire the writer lane without blocking.
    pub(crate) fn try_write(&self) -> Result<MutexGuard<'_, SqliteStore>, TryStoreAccessError> {
        self.writer.try_lock().map_err(|error| match error {
            std::sync::TryLockError::Poisoned(_) => TryStoreAccessError::Poisoned,
            std::sync::TryLockError::WouldBlock => TryStoreAccessError::WouldBlock,
        })
    }

    /// Acquires a query-only connection and begins one stable deferred snapshot.
    pub(crate) fn read(&self) -> Result<RuntimeStoreReadGuard<'_>, StoreAccessError> {
        let started = Instant::now();
        let mut readers = self
            .readers
            .lock()
            .map_err(|_| StoreAccessError::Poisoned)?;
        let waited = readers.is_empty();
        if waited {
            self.reader_waits.fetch_add(1, Ordering::Relaxed);
        }
        while readers.is_empty() {
            readers = self
                .reader_available
                .wait(readers)
                .map_err(|_| StoreAccessError::Poisoned)?;
        }
        let reader = readers.pop().ok_or(StoreAccessError::Poisoned)?;
        drop(readers);
        if waited {
            self.reader_maximum_wait_us.fetch_max(
                u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
        self.start_snapshot(reader)
    }

    /// Attempts to borrow a snapshot reader without blocking.
    pub(crate) fn try_read(&self) -> Result<RuntimeStoreReadGuard<'_>, TryStoreAccessError> {
        let mut readers = self.readers.try_lock().map_err(|error| match error {
            std::sync::TryLockError::Poisoned(_) => TryStoreAccessError::Poisoned,
            std::sync::TryLockError::WouldBlock => TryStoreAccessError::WouldBlock,
        })?;
        let reader = readers.pop().ok_or(TryStoreAccessError::WouldBlock)?;
        drop(readers);
        self.start_snapshot(reader).map_err(|error| match error {
            StoreAccessError::Poisoned => TryStoreAccessError::Poisoned,
            StoreAccessError::Storage(error) => TryStoreAccessError::Storage(error),
        })
    }

    fn start_snapshot(
        &self,
        reader: SqliteStore,
    ) -> Result<RuntimeStoreReadGuard<'_>, StoreAccessError> {
        if let Err(error) = reader.begin_read_snapshot() {
            self.return_reader(reader);
            return Err(StoreAccessError::Storage(error));
        }
        Ok(RuntimeStoreReadGuard {
            runtime: self,
            reader: Some(reader),
        })
    }

    fn return_reader(&self, reader: SqliteStore) {
        if let Ok(mut readers) = self.readers.lock() {
            readers.push(reader);
            self.reader_available.notify_one();
        }
    }

    pub(crate) const fn reader_capacity(&self) -> usize {
        self.reader_capacity
    }

    pub(crate) fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub(crate) fn metrics(&self) -> RuntimeStoreMetrics {
        RuntimeStoreMetrics {
            writer_waits: self.writer_waits.load(Ordering::Relaxed),
            writer_maximum_wait_us: self.writer_maximum_wait_us.load(Ordering::Relaxed),
            reader_waits: self.reader_waits.load(Ordering::Relaxed),
            reader_maximum_wait_us: self.reader_maximum_wait_us.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeStoreMetrics {
    pub(crate) writer_waits: u64,
    pub(crate) writer_maximum_wait_us: u64,
    pub(crate) reader_waits: u64,
    pub(crate) reader_maximum_wait_us: u64,
}

/// Borrowed query-only `SQLite` snapshot.
pub(crate) struct RuntimeStoreReadGuard<'a> {
    runtime: &'a RuntimeStore,
    reader: Option<SqliteStore>,
}

impl Deref for RuntimeStoreReadGuard<'_> {
    type Target = SqliteStore;

    fn deref(&self) -> &Self::Target {
        self.reader
            .as_ref()
            .expect("runtime reader remains present until drop")
    }
}

impl Drop for RuntimeStoreReadGuard<'_> {
    fn drop(&mut self) {
        let Some(reader) = self.reader.take() else {
            return;
        };
        if let Err(error) = reader.end_read_snapshot() {
            tracing::error!(%error, "SQLite reader snapshot could not be closed; replacing connection");
            if !self.runtime.database_path.as_os_str().is_empty()
                && let Ok(replacement) = SqliteStore::open_reader(&self.runtime.database_path)
            {
                self.runtime.return_reader(replacement);
            }
            return;
        }
        self.runtime.return_reader(reader);
    }
}

#[derive(Debug, Error)]
pub(crate) enum StoreAccessError {
    #[error("canonical store synchronization is poisoned")]
    Poisoned,
    #[error(transparent)]
    Storage(#[from] StoreError),
}

#[derive(Debug, Error)]
pub(crate) enum TryStoreAccessError {
    #[error("canonical store synchronization is poisoned")]
    Poisoned,
    #[error("no canonical store connection is immediately available")]
    WouldBlock,
    #[error(transparent)]
    Storage(#[from] StoreError),
}

#[cfg(test)]
mod tests {
    use super::RuntimeStore;
    use mealy_application::{OwnershipContext, create_session};
    use mealy_domain::{ChannelBindingId, PrincipalId};
    use mealy_infrastructure::{SqliteStore, SystemClock, SystemIdGenerator};
    use tempfile::TempDir;

    #[test]
    fn established_reader_snapshot_does_not_hold_the_writer_lane() {
        let home = TempDir::new().expect("temporary runtime store");
        let database = home.path().join("mealy.sqlite3");
        let writer = SqliteStore::open(&database, 0).expect("writer store");
        let runtime = RuntimeStore::open(writer, &database, 2).expect("runtime store");
        let reader = runtime.read().expect("reader snapshot");
        let original_journal_rows = reader.journal_count().expect("original journal count");

        let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
        let mut writer = runtime
            .write()
            .expect("writer lane while snapshot is active");
        writer
            .register_local_identity(ownership, 1)
            .expect("register local identity");
        create_session(&mut *writer, &SystemClock, &SystemIdGenerator, ownership)
            .expect("commit while reader snapshot is active");
        drop(writer);

        assert_eq!(
            reader.journal_count().expect("stable snapshot count"),
            original_journal_rows
        );
        drop(reader);
        assert!(
            runtime
                .read()
                .expect("new reader snapshot")
                .journal_count()
                .expect("new journal count")
                > original_journal_rows
        );
    }
}
