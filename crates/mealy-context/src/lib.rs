use mealy_artifacts::ArtifactRef;
use mealy_core::{AgentRunId, ContextBundleId, TaskId};
use mealy_events::Sensitivity;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContextItem {
    pub item_type: String,
    pub source_type: String,
    pub source_id: String,
    pub namespace: String,
    pub sensitivity: Sensitivity,
    pub confidence: f32,
    pub token_estimate: u32,
    pub inclusion_reason: String,
    pub content_ref: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContextBundle {
    pub context_bundle_id: ContextBundleId,
    pub task_id: TaskId,
    pub agent_run_id: AgentRunId,
    pub schema_version: u32,
    pub token_budget: u32,
    pub items: Vec<ContextItem>,
    pub excluded_items: Vec<ContextItem>,
    pub artifact_refs: Vec<ArtifactRef>,
}
