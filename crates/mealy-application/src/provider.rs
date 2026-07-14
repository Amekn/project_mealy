use mealy_domain::{AttemptId, ContextManifestId, RunId};
use serde::{Deserialize, Serialize};
use std::{cmp::Reverse, collections::BTreeSet};
use thiserror::Error;

/// Versioned capability contract used for routing and request validation.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCapabilities {
    /// Contract schema version.
    pub contract_version: String,
    /// Stable provider adapter identity.
    pub provider_id: String,
    /// Stable model identity.
    pub model_id: String,
    /// Normalized accepted input modalities such as `text` or `image`.
    pub input_modalities: BTreeSet<String>,
    /// Maximum normalized input tokens.
    pub context_tokens: u64,
    /// Maximum normalized generated tokens.
    pub maximum_output_tokens: u64,
    /// Whether normalized tool calls are supported.
    pub tool_calling: bool,
    /// Whether structured JSON outputs are supported.
    pub structured_output: bool,
    /// Supported normalized reasoning-control names.
    pub reasoning_controls: BTreeSet<String>,
    /// Whether the adapter can emit transient deltas.
    pub streaming: bool,
    /// Data-residency classification used by routing policy.
    pub residency: String,
    /// Whether this provider is local to the daemon boundary.
    pub local: bool,
    /// Provider price snapshot used by deterministic routing.
    pub pricing: ProviderPricing,
    /// Maximum simultaneous requests supported by this adapter instance.
    pub maximum_concurrent_requests: u64,
    /// Configured request-rate ceiling per minute.
    pub requests_per_minute: u64,
    /// Whether normalized errors may carry a downstream retry-after hint.
    pub retry_after_hints: bool,
}

/// Provider-neutral immutable pricing snapshot.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderPricing {
    /// Input-token price per one million tokens in configured currency microunits.
    pub input_microunits_per_million_tokens: u64,
    /// Output-token price per one million tokens in configured currency microunits.
    pub output_microunits_per_million_tokens: u64,
}

/// One health/latency/trust-qualified routing candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRouteCandidate {
    /// Immutable adapter capability snapshot.
    pub capabilities: ProviderCapabilities,
    /// Current deterministic health state.
    pub available: bool,
    /// Bounded recent latency estimate.
    pub estimated_latency_ms: u64,
    /// Monotonic trust tier; fallback may never decrease it.
    pub trust_tier: u8,
}

/// Owner/policy constraints for deterministic provider routing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRoutingPolicy {
    /// Required normalized input modalities.
    pub required_input_modalities: BTreeSet<String>,
    /// Tool-call capability requirement.
    pub tool_calling: CapabilityRequirement,
    /// Structured-output capability requirement.
    pub structured_output: CapabilityRequirement,
    /// Required reasoning control, when any.
    pub required_reasoning_control: Option<String>,
    /// Allowed residency classifications.
    pub allowed_residencies: BTreeSet<String>,
    /// Permitted provider locality.
    pub locality: ProviderLocality,
    /// Maximum accepted input-token unit price.
    pub maximum_input_microunits_per_million_tokens: u64,
    /// Maximum accepted output-token unit price.
    pub maximum_output_microunits_per_million_tokens: u64,
    /// Maximum accepted latency estimate.
    pub maximum_latency_ms: u64,
    /// Minimum provider trust tier.
    pub minimum_trust_tier: u8,
    /// Ordered owner preference; omitted providers follow deterministic cost/latency ordering.
    pub preferred_provider_ids: Vec<String>,
    /// Explicit fallback policy.
    pub fallback: ProviderFallbackPolicy,
}

/// Whether a provider capability is optional or required by a route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityRequirement {
    /// The route does not depend on this capability.
    Optional,
    /// Every selected provider must expose this capability.
    Required,
}

/// Locality boundary accepted by a provider route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderLocality {
    /// Any provider allowed by residency and trust policy may be selected.
    Any,
    /// Only providers inside the daemon's local trust boundary may be selected.
    LocalOnly,
}

/// Explicit provider fallback behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFallbackPolicy {
    /// Return a primary route only.
    Disabled,
    /// Return compatible fallbacks whose trust is no lower than the primary route.
    SameOrHigherTrust,
}

/// Deterministic primary route and explicitly authorized fallbacks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRoutePlan {
    /// Selected primary adapter/model snapshot.
    pub primary: ProviderRouteCandidate,
    /// Ordered compatible fallback candidates, empty unless policy explicitly allows fallback.
    pub fallbacks: Vec<ProviderRouteCandidate>,
    /// Stable owner-inspectable routing explanation.
    pub explanation: String,
}

/// Provider routing policy or candidate failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderRoutingError {
    /// Policy is empty, unbounded, or contradictory.
    #[error("provider routing policy is invalid")]
    InvalidPolicy,
    /// No healthy provider satisfies capability, privacy, cost, latency, and trust constraints.
    #[error("no provider satisfies the routing policy")]
    NoCompatibleProvider,
}

/// Selects a deterministic provider route without silently weakening privacy or tool semantics.
///
/// # Errors
///
/// Returns [`ProviderRoutingError`] for invalid policy or no compatible healthy candidate.
pub fn route_provider(
    policy: &ProviderRoutingPolicy,
    candidates: impl IntoIterator<Item = ProviderRouteCandidate>,
) -> Result<ProviderRoutePlan, ProviderRoutingError> {
    if policy.required_input_modalities.is_empty()
        || policy.allowed_residencies.is_empty()
        || policy.maximum_latency_ms == 0
        || policy.preferred_provider_ids.len() > 256
        || policy
            .preferred_provider_ids
            .iter()
            .any(|value| value.is_empty() || value.len() > 128)
    {
        return Err(ProviderRoutingError::InvalidPolicy);
    }
    let mut compatible = candidates
        .into_iter()
        .filter(|candidate| candidate_matches(policy, candidate))
        .collect::<Vec<_>>();
    compatible.sort_by_key(|candidate| {
        let preference = policy
            .preferred_provider_ids
            .iter()
            .position(|provider| provider == &candidate.capabilities.provider_id)
            .unwrap_or(usize::MAX);
        (
            preference,
            Reverse(candidate.capabilities.local),
            candidate
                .capabilities
                .pricing
                .input_microunits_per_million_tokens
                .saturating_add(
                    candidate
                        .capabilities
                        .pricing
                        .output_microunits_per_million_tokens,
                ),
            candidate.estimated_latency_ms,
            Reverse(candidate.trust_tier),
            candidate.capabilities.provider_id.clone(),
            candidate.capabilities.model_id.clone(),
        )
    });
    let primary = compatible
        .first()
        .cloned()
        .ok_or(ProviderRoutingError::NoCompatibleProvider)?;
    let fallbacks = if policy.fallback == ProviderFallbackPolicy::SameOrHigherTrust {
        compatible
            .into_iter()
            .skip(1)
            .filter(|candidate| candidate.trust_tier >= primary.trust_tier)
            .collect()
    } else {
        Vec::new()
    };
    Ok(ProviderRoutePlan {
        explanation: format!(
            "selected {}@{} within capability, residency, locality, trust, cost, and latency policy; fallback={}",
            primary.capabilities.provider_id,
            primary.capabilities.model_id,
            policy.fallback == ProviderFallbackPolicy::SameOrHigherTrust,
        ),
        primary,
        fallbacks,
    })
}

fn candidate_matches(policy: &ProviderRoutingPolicy, candidate: &ProviderRouteCandidate) -> bool {
    let capabilities = &candidate.capabilities;
    candidate.available
        && candidate.trust_tier >= policy.minimum_trust_tier
        && (policy.locality == ProviderLocality::Any || capabilities.local)
        && policy.allowed_residencies.contains(&capabilities.residency)
        && policy
            .required_input_modalities
            .is_subset(&capabilities.input_modalities)
        && (policy.tool_calling == CapabilityRequirement::Optional || capabilities.tool_calling)
        && (policy.structured_output == CapabilityRequirement::Optional
            || capabilities.structured_output)
        && policy
            .required_reasoning_control
            .as_ref()
            .is_none_or(|control| capabilities.reasoning_controls.contains(control))
        && capabilities.pricing.input_microunits_per_million_tokens
            <= policy.maximum_input_microunits_per_million_tokens
        && capabilities.pricing.output_microunits_per_million_tokens
            <= policy.maximum_output_microunits_per_million_tokens
        && candidate.estimated_latency_ms <= policy.maximum_latency_ms
        && capabilities.maximum_concurrent_requests != 0
        && capabilities.requests_per_minute != 0
}

/// Provider-neutral message role.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    /// Versioned baseline instructions.
    System,
    /// Authenticated session input.
    User,
    /// Final assistant output carried into a later attempt.
    Assistant,
    /// Recorded read-only tool observation.
    Tool,
}

/// Provider-neutral message supplied by a context manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedMessage {
    /// Semantic role.
    pub role: MessageRole,
    /// Bounded UTF-8 content.
    pub content: String,
    /// Tool call whose observation this message carries, when applicable.
    pub tool_call_id: Option<String>,
}

/// Provider-neutral tool definition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderToolDefinition {
    /// Stable tool identity.
    pub tool_id: String,
    /// Tool contract version.
    pub version: String,
    /// Human-readable purpose.
    pub description: String,
    /// Normalized JSON Schema.
    pub input_schema: serde_json::Value,
    /// Digest bound into the context manifest.
    pub schema_digest: String,
}

/// Complete normalized model request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderRequest {
    /// Owning run.
    pub run_id: RunId,
    /// Durable attempt allocated before dispatch.
    pub attempt_id: AttemptId,
    /// Exact committed manifest used to build `messages`.
    pub context_manifest_id: ContextManifestId,
    /// Selected provider.
    pub provider_id: String,
    /// Selected model.
    pub model_id: String,
    /// Ordered manifest-derived messages.
    pub messages: Vec<NormalizedMessage>,
    /// Allowed tool contracts.
    pub tools: Vec<ProviderToolDefinition>,
    /// Bounded output-token request.
    pub maximum_output_tokens: u64,
    /// Absolute dispatch deadline in Unix milliseconds.
    pub deadline_at_ms: i64,
}

/// Normalized provider decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderResponse {
    /// Provider completed with user-facing text.
    Final {
        /// Bounded final content.
        text: String,
    },
    /// Provider requested one validated tool invocation.
    ToolCall {
        /// Stable declared tool identity.
        tool_id: String,
        /// Provider-neutral normalized arguments.
        arguments: serde_json::Value,
    },
}

/// Normalized provider usage accounting.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelUsage {
    /// Estimated or provider-reported input tokens.
    pub input_tokens: u64,
    /// Provider-reported output tokens.
    pub output_tokens: u64,
    /// Total tokens charged to the attempt.
    pub total_tokens: u64,
    /// Cost in provider-neutral millionths of the configured currency unit.
    pub cost_microunits: u64,
}

/// Complete terminal normalized provider output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderOutput {
    /// Normalized decision.
    pub response: ProviderResponse,
    /// Stable finish classification.
    pub finish_reason: String,
    /// Usage accounting.
    pub usage: ModelUsage,
    /// Opaque downstream request ID, if supplied.
    pub provider_request_id: Option<String>,
}

/// Stable provider failure class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorClass {
    /// Request violated the normalized contract.
    #[error("invalid request")]
    InvalidRequest,
    /// Provider was unavailable before a usable response.
    #[error("provider unavailable")]
    Unavailable,
    /// Provider rate limit rejected the attempt.
    #[error("provider rate limited")]
    RateLimited,
    /// Attempt deadline elapsed.
    #[error("provider timeout")]
    Timeout,
    /// Cancellation was observed.
    #[error("provider cancelled")]
    Cancelled,
    /// Provider returned an invalid or unsupported response.
    #[error("invalid provider response")]
    InvalidResponse,
}

impl ProviderErrorClass {
    /// Stable storage and event spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unavailable => "unavailable",
            Self::RateLimited => "rate_limited",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::InvalidResponse => "invalid_response",
        }
    }
}

/// Whether a failed adapter call proved the downstream provider outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFailureDisposition {
    /// The provider did not accept work or returned a definite terminal response.
    Known,
    /// Dispatch crossed the network boundary without a provable terminal response.
    OutcomeUnknown,
}

/// Normalized provider failure with retry guidance.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{class}: {message}")]
pub struct ProviderError {
    /// Stable class.
    pub class: ProviderErrorClass,
    /// Redacted bounded detail.
    pub message: String,
    /// Whether retry under the same residency/tool policy may succeed.
    pub retryable: bool,
    /// Whether retry could duplicate downstream work or hide unknown usage/cost.
    pub disposition: ProviderFailureDisposition,
}

/// Cancellation probe passed into a provider dispatch without exposing storage internals.
pub trait CancellationProbe: Send + Sync {
    /// Returns whether the current run should stop at the next safe boundary.
    fn is_cancelled(&self) -> bool;
}

/// Non-authoritative bounded progress emitted before a normalized provider result is committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderProgress {
    /// Exact UTF-8 assistant text delta received from the provider stream.
    TextDelta(String),
}

/// Best-effort progress port kept separate from canonical provider result settlement.
pub trait ProviderProgressSink: Send + Sync {
    /// Observes one provider progress item. Implementations must remain bounded and must not treat
    /// this preview as the authoritative model response.
    fn emit(&self, progress: ProviderProgress);
}

/// Provider capability and normalized-completion port.
pub trait ModelProvider: Send + Sync + 'static {
    /// Returns the immutable routing capability snapshot.
    fn capabilities(&self) -> ProviderCapabilities;

    /// Performs one bounded normalized completion.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError`] for classified dispatch or response failures.
    fn complete(
        &self,
        request: &ProviderRequest,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ProviderOutput, ProviderError>;

    /// Performs one bounded completion while optionally emitting non-authoritative progress.
    ///
    /// Providers without streaming support use the terminal-only implementation by default.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError`] for classified dispatch or response failures.
    fn complete_with_progress(
        &self,
        request: &ProviderRequest,
        cancellation: &dyn CancellationProbe,
        _progress: &dyn ProviderProgressSink,
    ) -> Result<ProviderOutput, ProviderError> {
        self.complete(request, cancellation)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CapabilityRequirement, ProviderCapabilities, ProviderFallbackPolicy, ProviderLocality,
        ProviderPricing, ProviderRouteCandidate, ProviderRoutingPolicy, route_provider,
    };
    use std::collections::BTreeSet;

    #[test]
    fn routing_enforces_capability_privacy_cost_latency_and_explicit_fallback() {
        let policy = ProviderRoutingPolicy {
            required_input_modalities: BTreeSet::from(["text".to_owned()]),
            tool_calling: CapabilityRequirement::Required,
            structured_output: CapabilityRequirement::Required,
            required_reasoning_control: Some("none".to_owned()),
            allowed_residencies: BTreeSet::from(["local".to_owned(), "trusted-region".to_owned()]),
            locality: ProviderLocality::Any,
            maximum_input_microunits_per_million_tokens: 10,
            maximum_output_microunits_per_million_tokens: 20,
            maximum_latency_ms: 500,
            minimum_trust_tier: 5,
            preferred_provider_ids: vec!["primary".to_owned()],
            fallback: ProviderFallbackPolicy::SameOrHigherTrust,
        };
        let primary = candidate("primary", "local", true, 7, 50, 2);
        let trusted_fallback = candidate("fallback", "trusted-region", false, 7, 100, 1);
        let less_trusted = candidate("less-trusted", "trusted-region", false, 6, 40, 0);
        let unavailable = ProviderRouteCandidate {
            available: false,
            ..candidate("unavailable", "local", true, 9, 1, 0)
        };
        let plan = route_provider(
            &policy,
            [
                less_trusted,
                trusted_fallback.clone(),
                unavailable,
                primary.clone(),
            ],
        )
        .expect("route");
        assert_eq!(plan.primary, primary);
        assert_eq!(plan.fallbacks, vec![trusted_fallback]);

        let no_fallback = ProviderRoutingPolicy {
            fallback: ProviderFallbackPolicy::Disabled,
            ..policy
        };
        let plan = route_provider(
            &no_fallback,
            [
                candidate("primary", "local", true, 7, 50, 2),
                candidate("fallback", "trusted-region", false, 7, 100, 1),
            ],
        )
        .expect("primary-only route");
        assert!(plan.fallbacks.is_empty());
    }

    fn candidate(
        provider_id: &str,
        residency: &str,
        local: bool,
        trust_tier: u8,
        latency_ms: u64,
        price: u64,
    ) -> ProviderRouteCandidate {
        ProviderRouteCandidate {
            capabilities: ProviderCapabilities {
                contract_version: "mealy.provider.v1".to_owned(),
                provider_id: provider_id.to_owned(),
                model_id: "model".to_owned(),
                input_modalities: BTreeSet::from(["text".to_owned()]),
                context_tokens: 8_192,
                maximum_output_tokens: 1_024,
                tool_calling: true,
                structured_output: true,
                reasoning_controls: BTreeSet::from(["none".to_owned()]),
                streaming: true,
                residency: residency.to_owned(),
                local,
                pricing: ProviderPricing {
                    input_microunits_per_million_tokens: price,
                    output_microunits_per_million_tokens: price,
                },
                maximum_concurrent_requests: 2,
                requests_per_minute: 60,
                retry_after_hints: true,
            },
            available: true,
            estimated_latency_ms: latency_ms,
            trust_tier,
        }
    }
}
