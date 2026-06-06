use async_trait::async_trait;
use mealy_core::{Result, ToolCallId};
use mealy_policy::RiskClass;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolCapability {
    pub name: String,
    pub risk_class: RiskClass,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolRequest {
    pub tool_call_id: ToolCallId,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolOutcome {
    pub tool_call_id: ToolCallId,
    pub output: serde_json::Value,
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn capability(&self) -> ToolCapability;
    async fn execute(&self, request: ToolRequest) -> Result<ToolOutcome>;
}
