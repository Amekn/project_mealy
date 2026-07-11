use serde::{Deserialize, Serialize};

/// Authenticated owner decision for a bound approval subject.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    /// Permit the exact bound effect subject.
    Approve,
    /// Refuse the exact bound effect subject.
    Deny,
}

/// Canonical lifecycle status of an approval request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// No authenticated owner decision has been recorded.
    Pending,
    /// The exact current subject was approved.
    Approved,
    /// The exact current subject was denied.
    Denied,
    /// The approval subject passed its bound expiry.
    Expired,
    /// A previously granted decision was explicitly withdrawn.
    Revoked,
}

impl ApprovalStatus {
    /// Maps an authenticated decision to its durable status.
    #[must_use]
    pub const fn from_decision(decision: ApprovalDecision) -> Self {
        match decision {
            ApprovalDecision::Approve => Self::Approved,
            ApprovalDecision::Deny => Self::Denied,
        }
    }

    /// Returns whether this status currently permits effect dispatch.
    #[must_use]
    pub const fn permits_dispatch(self) -> bool {
        matches!(self, Self::Approved)
    }

    /// Returns whether a later owner decision is no longer accepted for this request.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending)
    }
}

#[cfg(test)]
mod tests {
    use super::{ApprovalDecision, ApprovalStatus};

    #[test]
    fn only_an_approved_current_subject_permits_dispatch() {
        assert!(ApprovalStatus::from_decision(ApprovalDecision::Approve).permits_dispatch());
        for status in [
            ApprovalStatus::Pending,
            ApprovalStatus::Denied,
            ApprovalStatus::Expired,
            ApprovalStatus::Revoked,
        ] {
            assert!(!status.permits_dispatch());
        }
        assert_eq!(
            ApprovalStatus::from_decision(ApprovalDecision::Deny),
            ApprovalStatus::Denied
        );
    }
}
