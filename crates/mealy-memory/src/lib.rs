use mealy_core::{AgentId, ArtifactId, EventId, MemoryId, PrincipalId, Timestamp};
use mealy_events::Sensitivity;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MemoryReviewState {
    Proposed,
    Accepted,
    Rejected,
    Stale,
    Deleted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryRecord {
    pub memory_id: MemoryId,
    pub namespace: String,
    pub owner_principal_id: PrincipalId,
    pub agent_id: Option<AgentId>,
    pub source_event_id: Option<EventId>,
    pub source_artifact_id: Option<ArtifactId>,
    pub content: String,
    pub summary: String,
    pub tags: Vec<String>,
    pub sensitivity: Sensitivity,
    pub confidence: f32,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub review_state: MemoryReviewState,
}
