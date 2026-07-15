use crate::{ProviderPricing, is_sha256_digest};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr, path::Path};
use thiserror::Error;
use url::Url;

/// Maximum accepted provider bearer credential bytes at every broker and adapter boundary.
pub const MAXIMUM_PROVIDER_CREDENTIAL_BYTES: usize = 4_096;
/// Maximum explicit fallback endpoints behind one primary provider.
pub const MAXIMUM_PROVIDER_FALLBACKS: usize = 7;

/// Non-secret model-provider selection activated only after complete validation.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ProviderConfig {
    /// Deterministic local provider retained for conformance and offline evaluation.
    #[default]
    BuiltinFixture,
    /// `OpenAI` Responses-compatible HTTPS or literal-loopback endpoint.
    OpenAiResponses {
        /// Stable provider identity retained in routing and attempt evidence.
        provider_id: String,
        /// API base ending at the version prefix, such as `https://api.openai.com/v1`.
        base_url: String,
        /// Exact configured model name or snapshot.
        model: String,
        /// Opaque credential reference; optional only on literal loopback.
        credential: Option<ProviderCredentialReference>,
        /// Owner-declared residency label used by routing policy.
        residency: String,
        /// Maximum normalized input-token window advertised by this model.
        context_tokens: u64,
        /// Maximum requested output tokens.
        maximum_output_tokens: u64,
        /// Request Responses SSE and expose bounded non-authoritative text progress.
        #[serde(default)]
        streaming: bool,
        /// Input price snapshot in currency microunits per million tokens.
        input_microunits_per_million_tokens: u64,
        /// Output price snapshot in currency microunits per million tokens.
        output_microunits_per_million_tokens: u64,
        /// Bounded routing estimate, not a dispatch timeout.
        estimated_latency_ms: u64,
    },
    /// Anthropic Messages-compatible HTTPS or literal-loopback endpoint.
    AnthropicMessages {
        /// Stable provider identity retained in routing and attempt evidence.
        provider_id: String,
        /// API base ending at the version prefix, such as `https://api.anthropic.com/v1`.
        base_url: String,
        /// Exact configured model name or snapshot.
        model: String,
        /// Opaque credential reference; optional only on literal loopback.
        credential: Option<ProviderCredentialReference>,
        /// Owner-declared residency label used by routing policy.
        residency: String,
        /// Maximum normalized input-token window advertised by this model.
        context_tokens: u64,
        /// Maximum requested output tokens.
        maximum_output_tokens: u64,
        /// Request Messages SSE and expose bounded non-authoritative text progress.
        #[serde(default)]
        streaming: bool,
        /// Input price snapshot in currency microunits per million tokens.
        input_microunits_per_million_tokens: u64,
        /// Output price snapshot in currency microunits per million tokens.
        output_microunits_per_million_tokens: u64,
        /// Bounded routing estimate, not a dispatch timeout.
        estimated_latency_ms: u64,
    },
    /// Owner-local official client using that client's existing subscription authentication.
    SubscriptionCli {
        /// Stable provider identity retained in routing and attempt evidence.
        provider_id: String,
        /// Official client whose own authenticated process performs the request.
        client: SubscriptionCliClient,
        /// Exact canonical official-client executable path.
        executable_path: String,
        /// SHA-256 identity checked before every invocation.
        executable_sha256: String,
        /// Exact model name selected through the official client.
        model: String,
        /// Owner-declared remote residency label used by routing policy.
        residency: String,
        /// Maximum normalized input-token window advertised by this model.
        context_tokens: u64,
        /// Maximum accepted output tokens; over-limit client results fail closed.
        maximum_output_tokens: u64,
        /// Bounded routing estimate, not a dispatch timeout.
        estimated_latency_ms: u64,
    },
}

/// Official local client allowed to broker its own subscription session.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionCliClient {
    /// `OpenAI` Codex CLI authenticated with `ChatGPT` sign-in.
    OpenAiCodex,
    /// Anthropic Claude Code authenticated with a Claude subscription.
    AnthropicClaude,
}

impl SubscriptionCliClient {
    /// Stable adapter protocol identity.
    #[must_use]
    pub const fn protocol(self) -> &'static str {
        match self {
            Self::OpenAiCodex => "openai_subscription_cli",
            Self::AnthropicClaude => "claude_subscription_cli",
        }
    }

    /// Conservative provider-owned input allowance reserved on every request.
    #[must_use]
    pub const fn input_token_overhead(self) -> u64 {
        match self {
            Self::OpenAiCodex => 16_384,
            Self::AnthropicClaude => 24_576,
        }
    }
}

/// Trusted-process reference to provider credential material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "source",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ProviderCredentialReference {
    /// Resolve the credential from the daemon's startup environment.
    Environment {
        /// Exact environment variable name.
        variable: String,
    },
    /// Resolve the credential from Mealy's owner-private provider secret broker.
    Broker {
        /// Portable opaque secret identity, never the secret value.
        secret_id: String,
    },
}

/// Invalid non-secret provider configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderConfigError {
    /// One or more endpoint, identity, limit, price, or reference values are invalid.
    #[error("model-provider configuration is invalid")]
    Invalid,
}

impl ProviderConfig {
    /// Returns whether task promotion should retain the deterministic fixture contract.
    #[must_use]
    pub const fn is_builtin_fixture(&self) -> bool {
        matches!(self, Self::BuiltinFixture)
    }

    /// Validates transport, identity, credential-reference, token, price, and latency bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderConfigError::Invalid`] without including any credential material.
    pub fn validate(&self) -> Result<(), ProviderConfigError> {
        match self {
            Self::BuiltinFixture => Ok(()),
            Self::OpenAiResponses {
                provider_id,
                base_url,
                model,
                credential,
                residency,
                context_tokens,
                maximum_output_tokens,
                streaming: _,
                input_microunits_per_million_tokens,
                output_microunits_per_million_tokens,
                estimated_latency_ms,
            }
            | Self::AnthropicMessages {
                provider_id,
                base_url,
                model,
                credential,
                residency,
                context_tokens,
                maximum_output_tokens,
                streaming: _,
                input_microunits_per_million_tokens,
                output_microunits_per_million_tokens,
                estimated_latency_ms,
            } => {
                let Some(local) = validated_provider_url(base_url) else {
                    return Err(ProviderConfigError::Invalid);
                };
                if valid_label(provider_id, 128)
                    && valid_label(model, 256)
                    && valid_label(residency, 128)
                    && (1..=2_000_000).contains(context_tokens)
                    && (1..=*context_tokens).contains(maximum_output_tokens)
                    && *input_microunits_per_million_tokens <= 1_000_000_000_000
                    && *output_microunits_per_million_tokens <= 1_000_000_000_000
                    && (1..=300_000).contains(estimated_latency_ms)
                    && credential
                        .as_ref()
                        .is_none_or(ProviderCredentialReference::valid)
                    && (local || credential.is_some())
                {
                    Ok(())
                } else {
                    Err(ProviderConfigError::Invalid)
                }
            }
            Self::SubscriptionCli {
                provider_id,
                client,
                executable_path,
                executable_sha256,
                model,
                residency,
                context_tokens,
                maximum_output_tokens,
                estimated_latency_ms,
            } => {
                if valid_label(provider_id, 128)
                    && valid_absolute_executable_path(executable_path)
                    && is_sha256_digest(executable_sha256)
                    && valid_label(model, 256)
                    && valid_label(residency, 128)
                    && (1..=2_000_000).contains(context_tokens)
                    && client.input_token_overhead() < *context_tokens
                    && (1..=*context_tokens).contains(maximum_output_tokens)
                    && (1..=300_000).contains(estimated_latency_ms)
                {
                    Ok(())
                } else {
                    Err(ProviderConfigError::Invalid)
                }
            }
        }
    }

    /// Returns the declared provider price snapshot.
    #[must_use]
    pub const fn pricing(&self) -> ProviderPricing {
        match self {
            Self::BuiltinFixture | Self::SubscriptionCli { .. } => ProviderPricing {
                input_microunits_per_million_tokens: 0,
                output_microunits_per_million_tokens: 0,
            },
            Self::OpenAiResponses {
                input_microunits_per_million_tokens,
                output_microunits_per_million_tokens,
                ..
            }
            | Self::AnthropicMessages {
                input_microunits_per_million_tokens,
                output_microunits_per_million_tokens,
                ..
            } => ProviderPricing {
                input_microunits_per_million_tokens: *input_microunits_per_million_tokens,
                output_microunits_per_million_tokens: *output_microunits_per_million_tokens,
            },
        }
    }

    /// Stable provider identity when this is an external endpoint.
    #[must_use]
    pub fn provider_id(&self) -> Option<&str> {
        match self {
            Self::BuiltinFixture => None,
            Self::OpenAiResponses { provider_id, .. }
            | Self::AnthropicMessages { provider_id, .. }
            | Self::SubscriptionCli { provider_id, .. } => Some(provider_id),
        }
    }

    /// Owner-declared residency and endpoint locality when externally configured.
    #[must_use]
    pub fn trust_boundary(&self) -> Option<(&str, bool)> {
        match self {
            Self::BuiltinFixture => None,
            Self::OpenAiResponses {
                base_url,
                residency,
                ..
            }
            | Self::AnthropicMessages {
                base_url,
                residency,
                ..
            } => validated_provider_url(base_url).map(|local| (residency.as_str(), local)),
            Self::SubscriptionCli { residency, .. } => Some((residency.as_str(), false)),
        }
    }
}

/// Validates an ordered fallback chain without allowing a weaker residency or locality boundary.
///
/// # Errors
///
/// Returns [`ProviderConfigError::Invalid`] for duplicate identities, fixture/external mixing,
/// too many fallbacks, invalid members, or any fallback outside the primary trust boundary.
pub fn validate_provider_chain(
    primary: &ProviderConfig,
    fallbacks: &[ProviderConfig],
) -> Result<(), ProviderConfigError> {
    primary.validate()?;
    if fallbacks.len() > MAXIMUM_PROVIDER_FALLBACKS
        || primary.is_builtin_fixture() && !fallbacks.is_empty()
    {
        return Err(ProviderConfigError::Invalid);
    }
    let mut identities = BTreeSet::new();
    if let Some(provider_id) = primary.provider_id() {
        identities.insert(provider_id);
    }
    let primary_boundary = primary.trust_boundary();
    for fallback in fallbacks {
        fallback.validate()?;
        let Some(provider_id) = fallback.provider_id() else {
            return Err(ProviderConfigError::Invalid);
        };
        if fallback.trust_boundary() != primary_boundary || !identities.insert(provider_id) {
            return Err(ProviderConfigError::Invalid);
        }
    }
    Ok(())
}

impl ProviderCredentialReference {
    /// Validates the opaque environment or broker identity without resolving secret material.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderConfigError::Invalid`] for a malformed reference.
    pub fn validate(&self) -> Result<(), ProviderConfigError> {
        self.valid()
            .then_some(())
            .ok_or(ProviderConfigError::Invalid)
    }

    /// Stable non-secret capability claim for this credential reference.
    #[must_use]
    pub fn capability_reference(&self) -> String {
        match self {
            Self::Environment { variable } => format!("environment:{variable}"),
            Self::Broker { secret_id } => format!("broker:{secret_id}"),
        }
    }

    fn valid(&self) -> bool {
        match self {
            Self::Environment { variable } => valid_environment_name(variable),
            Self::Broker { secret_id } => valid_provider_secret_id(secret_id),
        }
    }
}

/// Returns whether a provider-broker identity is safe as one portable filename stem.
#[must_use]
pub fn valid_provider_secret_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Validates a provider API base and reports whether it is a literal-loopback endpoint.
///
/// Remote endpoints must use HTTPS. Plain HTTP is accepted only for a literal loopback IP;
/// credentials embedded in the URL, queries, and fragments are always rejected.
///
/// # Errors
///
/// Returns [`ProviderConfigError::Invalid`] when the URL is not an admissible provider base.
pub fn validate_provider_base_url(value: &str) -> Result<bool, ProviderConfigError> {
    validated_provider_url(value).ok_or(ProviderConfigError::Invalid)
}

fn validated_provider_url(value: &str) -> Option<bool> {
    if value.is_empty() || value.len() > 2_048 || value.trim() != value {
        return None;
    }
    let url = Url::parse(value).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let local = url
        .host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    if url.scheme() == "https" || (url.scheme() == "http" && local) {
        Some(local)
    } else {
        None
    }
}

fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_uppercase())
        && value.len() <= 128
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn valid_label(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_absolute_executable_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2_048
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && Path::new(value).is_absolute()
}

#[cfg(test)]
mod tests {
    use super::{
        ProviderConfig, ProviderCredentialReference, SubscriptionCliClient,
        valid_provider_secret_id, validate_provider_base_url, validate_provider_chain,
    };

    fn remote(credential: Option<ProviderCredentialReference>) -> ProviderConfig {
        ProviderConfig::OpenAiResponses {
            provider_id: "openai.responses".to_owned(),
            base_url: "https://api.example.test/v1".to_owned(),
            model: "model-snapshot".to_owned(),
            credential,
            residency: "trusted-remote".to_owned(),
            context_tokens: 128_000,
            maximum_output_tokens: 4_096,
            streaming: true,
            input_microunits_per_million_tokens: 1_000_000,
            output_microunits_per_million_tokens: 2_000_000,
            estimated_latency_ms: 10_000,
        }
    }

    #[test]
    fn subscription_config_reserves_its_client_owned_context() {
        let mut subscription = ProviderConfig::SubscriptionCli {
            provider_id: "openai.subscription".to_owned(),
            client: SubscriptionCliClient::OpenAiCodex,
            executable_path: "/usr/bin/codex".to_owned(),
            executable_sha256: "0".repeat(64),
            model: "codex-snapshot".to_owned(),
            residency: "trusted-remote".to_owned(),
            context_tokens: 16_385,
            maximum_output_tokens: 1_024,
            estimated_latency_ms: 60_000,
        };
        assert!(subscription.validate().is_ok());
        let ProviderConfig::SubscriptionCli { context_tokens, .. } = &mut subscription else {
            unreachable!()
        };
        *context_tokens = SubscriptionCliClient::OpenAiCodex.input_token_overhead();
        assert!(subscription.validate().is_err());
        assert_eq!(
            SubscriptionCliClient::AnthropicClaude.input_token_overhead(),
            24_576
        );
    }

    #[test]
    fn transport_and_credential_references_fail_closed() {
        assert!(
            remote(Some(ProviderCredentialReference::Broker {
                secret_id: "openai-primary".to_owned()
            }))
            .validate()
            .is_ok()
        );
        assert!(remote(None).validate().is_err());
        let mut local = remote(None);
        let ProviderConfig::OpenAiResponses { base_url, .. } = &mut local else {
            unreachable!()
        };
        *base_url = "http://127.0.0.1:8080/v1".to_owned();
        assert!(local.validate().is_ok());
        assert!(valid_provider_secret_id("provider.primary-1"));
        assert!(!valid_provider_secret_id("../provider"));
        assert_eq!(
            validate_provider_base_url("http://127.0.0.1:8080/v1"),
            Ok(true)
        );
        assert_eq!(
            validate_provider_base_url("https://api.example.test/v1"),
            Ok(false)
        );
        assert!(validate_provider_base_url("http://api.example.test/v1").is_err());
        assert!(validate_provider_base_url("https://user@api.example.test/v1").is_err());

        let legacy = serde_json::json!({
            "kind": "open_ai_responses",
            "providerId": "legacy.responses",
            "baseUrl": "http://127.0.0.1:8080/v1",
            "model": "legacy-model",
            "credential": null,
            "residency": "local",
            "contextTokens": 32_768,
            "maximumOutputTokens": 4_096,
            "inputMicrounitsPerMillionTokens": 0,
            "outputMicrounitsPerMillionTokens": 0,
            "estimatedLatencyMs": 10
        });
        let legacy = serde_json::from_value::<ProviderConfig>(legacy).expect("legacy config");
        assert!(matches!(
            legacy,
            ProviderConfig::OpenAiResponses {
                streaming: false,
                ..
            }
        ));
    }

    #[test]
    fn fallback_chain_preserves_trust_boundary_and_unique_identity() {
        let primary = remote(Some(ProviderCredentialReference::Broker {
            secret_id: "primary".to_owned(),
        }));
        let anthropic = ProviderConfig::AnthropicMessages {
            provider_id: "anthropic.messages".to_owned(),
            base_url: "https://api.anthropic.example/v1".to_owned(),
            model: "claude-snapshot".to_owned(),
            credential: Some(ProviderCredentialReference::Broker {
                secret_id: "anthropic".to_owned(),
            }),
            residency: "trusted-remote".to_owned(),
            context_tokens: 128_000,
            maximum_output_tokens: 4_096,
            streaming: true,
            input_microunits_per_million_tokens: 1_000_000,
            output_microunits_per_million_tokens: 2_000_000,
            estimated_latency_ms: 10_000,
        };
        assert!(anthropic.validate().is_ok());
        assert_eq!(
            serde_json::to_value(&anthropic).expect("Anthropic config"),
            serde_json::json!({
                "kind": "anthropic_messages",
                "providerId": "anthropic.messages",
                "baseUrl": "https://api.anthropic.example/v1",
                "model": "claude-snapshot",
                "credential": {"source": "broker", "secretId": "anthropic"},
                "residency": "trusted-remote",
                "contextTokens": 128_000,
                "maximumOutputTokens": 4_096,
                "streaming": true,
                "inputMicrounitsPerMillionTokens": 1_000_000,
                "outputMicrounitsPerMillionTokens": 2_000_000,
                "estimatedLatencyMs": 10_000
            })
        );
        assert!(validate_provider_chain(&primary, std::slice::from_ref(&anthropic)).is_ok());
        let mut fallback = remote(Some(ProviderCredentialReference::Broker {
            secret_id: "fallback".to_owned(),
        }));
        let ProviderConfig::OpenAiResponses {
            provider_id, model, ..
        } = &mut fallback
        else {
            unreachable!()
        };
        *provider_id = "alternate.responses".to_owned();
        *model = "alternate-model".to_owned();
        assert!(validate_provider_chain(&primary, &[fallback.clone()]).is_ok());

        let ProviderConfig::OpenAiResponses { residency, .. } = &mut fallback else {
            unreachable!()
        };
        *residency = "weaker-remote".to_owned();
        assert_eq!(
            validate_provider_chain(&primary, &[fallback]),
            Err(super::ProviderConfigError::Invalid)
        );
        assert_eq!(
            validate_provider_chain(&primary, std::slice::from_ref(&primary)),
            Err(super::ProviderConfigError::Invalid)
        );
    }
}
