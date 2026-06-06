use mealy_core::{EventId, SessionId, TaskId, Timestamp};
use mealy_events::{EventType, Sensitivity};
use mealy_task::TaskState;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateTaskRequest {
    pub session_id: Option<SessionId>,
    pub title: String,
    pub user_message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateTaskResponse {
    pub task_id: TaskId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskSummary {
    pub task_id: TaskId,
    pub title: String,
    pub state: TaskState,
    pub updated_at: Timestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub event_id: EventId,
    pub event_type: EventType,
    pub occurred_at: Timestamp,
    pub sensitivity: Sensitivity,
    pub summary: String,
}
