//! Versioned transport-facing data types.

use mealy_domain::{TaskId, TaskStatus};
use serde::{Deserialize, Serialize};

/// Initial public API version.
pub const API_VERSION: &str = "v1";

/// Opaque durable position used to resume a timeline stream.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TimelineCursor(pub u64);

/// Stable public projection of a task.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskView {
    /// Stable task ID.
    pub id: TaskId,
    /// Current lifecycle state.
    pub status: TaskStatus,
    /// Current optimistic-concurrency revision.
    pub revision: u64,
}
