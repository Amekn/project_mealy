//! Concrete infrastructure adapters for Mealy.

mod sqlite;
mod system;

pub use sqlite::{
    JournalRecord, OutboxRecord, SqliteStore, StoreError, TaskMutation, TaskSnapshot,
};
pub use system::{SystemClock, SystemIdGenerator};
