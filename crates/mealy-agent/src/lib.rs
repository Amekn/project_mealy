use async_trait::async_trait;
use mealy_core::{AgentId, Result, TaskId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentProfile {
    pub agent_id: AgentId,
    pub name: String,
    pub role: String,
    pub policy_profile: String,
    pub memory_namespace: String,
    pub workspace_namespace: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentRunRequest {
    pub task_id: TaskId,
    pub profile: AgentProfile,
}

#[async_trait]
pub trait AgentRuntime: Send + Sync {
    async fn run(&self, request: AgentRunRequest) -> Result<()>;
}
