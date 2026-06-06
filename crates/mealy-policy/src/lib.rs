use mealy_core::{AgentRunId, ChannelId, PrincipalId, TaskId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SecurityProfile {
    ReadOnly,
    WorkspaceWrite,
    Networked,
    ServiceUser,
    ServiceAdmin,
    FullTrust,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RiskClass {
    HarmlessRead,
    SensitiveRead,
    LocalWrite,
    DestructiveLocalWrite,
    NetworkRead,
    NetworkWrite,
    ServiceMutation,
    CredentialAccess,
    PrivilegedCommand,
    IrreversibleOperation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PolicyOutcome {
    Allow,
    Deny,
    RequireApproval,
    RequireStrongerProfile,
    RequireUserInterrupt,
    RequireValidationFirst,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyRequest {
    pub requesting_principal_id: PrincipalId,
    pub task_id: Option<TaskId>,
    pub agent_run_id: Option<AgentRunId>,
    pub channel_id: Option<ChannelId>,
    pub capability: String,
    pub risk_class: RiskClass,
    pub target_resource: Option<String>,
    pub arguments_summary: serde_json::Value,
    pub current_security_profile: SecurityProfile,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub outcome: PolicyOutcome,
    pub reason: String,
}

impl PolicyDecision {
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            outcome: PolicyOutcome::Allow,
            reason: reason.into(),
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            outcome: PolicyOutcome::Deny,
            reason: reason.into(),
        }
    }
}
