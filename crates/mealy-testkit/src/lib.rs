use async_trait::async_trait;
use mealy_core::{ProviderId, Result};
use mealy_provider::{Provider, ProviderRequest, ProviderResponse};
pub use mealy_store::InMemoryEventStore;

pub struct FakeProvider {
    provider_id: ProviderId,
}

impl FakeProvider {
    pub fn new() -> Self {
        Self {
            provider_id: ProviderId::new(),
        }
    }
}

impl Default for FakeProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Provider for FakeProvider {
    fn provider_id(&self) -> ProviderId {
        self.provider_id
    }

    async fn complete(&self, request: ProviderRequest) -> Result<ProviderResponse> {
        Ok(ProviderResponse {
            provider_id: self.provider_id,
            model: request.model,
            output: serde_json::json!({ "text": "fake provider response" }),
        })
    }
}
