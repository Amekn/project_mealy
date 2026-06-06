use async_trait::async_trait;
use mealy_core::{ProviderId, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderRequest {
    pub model: String,
    pub input: serde_json::Value,
    pub stream: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderResponse {
    pub provider_id: ProviderId,
    pub model: String,
    pub output: serde_json::Value,
}

#[async_trait]
pub trait Provider: Send + Sync {
    fn provider_id(&self) -> ProviderId;
    async fn complete(&self, request: ProviderRequest) -> Result<ProviderResponse>;
}
