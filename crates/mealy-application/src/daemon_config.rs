use crate::{AgentLoopLimits, ProviderConfig};
use serde_json::{Value, json};

/// Current non-secret configuration document installed by first-run setup.
pub const DAEMON_CONFIG_FORMAT_VERSION: u64 = 1;

/// Returns the canonical release-one default daemon configuration document.
///
/// This shared constructor lets the stopped-daemon setup client initialize a clean home without
/// starting the service or duplicating an independently drifting JSON template. `mealyd` tests
/// require its typed [`Default`] projection to remain exactly equal to this document.
#[must_use]
pub fn default_daemon_config_document() -> Value {
    json!({
        "agentLoopLimits": AgentLoopLimits::default(),
        "artifactGcMinimumAgeHours": 24,
        "concurrencyLimits": {
            "agentRoleRuns": 1,
            "daemonAgentRuns": 1,
            "extensionInvocations": 1,
            "principalAgentRuns": 1,
            "providerRequests": 1,
            "providerRequestsPerMinute": 600,
            "resourceClassInvocations": 1,
            "sessionAgentRuns": 1
        },
        "drainDeadlineMs": 10_000,
        "forensicBackupOnOpenFailure": true,
        "formatVersion": DAEMON_CONFIG_FORMAT_VERSION,
        "maximumPendingInputsPerSession": 1_024,
        "provider": ProviderConfig::default(),
        "retentionPolicy": {
            "dataClassMinimumAgeHours": {
                "canonical_audit": 24 * 365 * 10,
                "temporary_artifact": 24,
                "unreferenced_artifact": 24
            },
            "legalHoldLabels": [],
            "protectedChannelBindingIds": [],
            "protectedPrincipalIds": [],
            "protectedTaskIds": [],
            "sensitivityMinimumAgeHours": {
                "internal": 24 * 30,
                "private": 24 * 365,
                "public": 24,
                "restricted": 24 * 365 * 10
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{DAEMON_CONFIG_FORMAT_VERSION, default_daemon_config_document};

    #[test]
    fn first_run_document_is_non_secret_complete_and_stable() {
        let document = default_daemon_config_document();
        assert_eq!(document["formatVersion"], DAEMON_CONFIG_FORMAT_VERSION);
        assert_eq!(document["provider"]["kind"], "builtin_fixture");
        assert_eq!(document.as_object().map(serde_json::Map::len), Some(9));
        assert!(!document.to_string().to_ascii_lowercase().contains("secret"));
    }
}
