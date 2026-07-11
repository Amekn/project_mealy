use serde::{Deserialize, Serialize};

/// Named security posture that a policy decision asks the executor to enforce.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyProfile {
    /// Read-only observation with no mutation or network access.
    Observe,
    /// Mutation constrained to explicitly writable workspace paths.
    WorkspaceWrite,
    /// Explicitly scoped outbound network access.
    Networked,
    /// Mutation of a named external service under scoped credentials.
    ServiceOperator,
    /// Clearly marked execution without an enforceable least-privilege sandbox.
    FullTrust,
}

#[cfg(test)]
mod tests {
    use super::PolicyProfile;

    #[test]
    fn required_profiles_have_stable_contract_names() {
        let profiles = [
            (PolicyProfile::Observe, "observe"),
            (PolicyProfile::WorkspaceWrite, "workspace-write"),
            (PolicyProfile::Networked, "networked"),
            (PolicyProfile::ServiceOperator, "service-operator"),
            (PolicyProfile::FullTrust, "full-trust"),
        ];
        for (profile, expected) in profiles {
            assert_eq!(
                serde_json::to_string(&profile).expect("serialize policy profile"),
                format!("\"{expected}\"")
            );
        }
    }
}
