use mealy_core::{AgentRunId, ApprovalId, SessionId, TaskId, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TaskState {
    Created,
    Queued,
    Running,
    Paused,
    WaitingForApproval,
    Interrupted,
    Completed,
    Failed,
    Cancelled,
}

impl TaskState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskSnapshot {
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub state: TaskState,
    pub title: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AgentRunState {
    Created,
    Running,
    WaitingForTool,
    WaitingForProvider,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentRunSnapshot {
    pub agent_run_id: AgentRunId,
    pub task_id: TaskId,
    pub state: AgentRunState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalSnapshot {
    pub approval_id: ApprovalId,
    pub task_id: TaskId,
    pub state: ApprovalState,
}
