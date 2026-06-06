use mealy_core::{AgentRunId, ArtifactId, EventId, TaskId, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ArtifactType {
    Patch,
    File,
    CommandOutput,
    Screenshot,
    Report,
    ContextSnapshot,
    ValidationEvidence,
    Log,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub artifact_id: ArtifactId,
    pub task_id: TaskId,
    pub agent_run_id: Option<AgentRunId>,
    pub event_id: Option<EventId>,
    pub artifact_type: ArtifactType,
    pub content_hash: String,
    pub content_ref: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub created_at: Timestamp,
}
