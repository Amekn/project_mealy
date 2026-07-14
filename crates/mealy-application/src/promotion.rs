use crate::{
    AgentLoopLimits, Clock, FIXTURE_WRITE_FILE_TOOL_ID, FIXTURE_WRITE_INPUT_PREFIX, IdGenerator,
    OwnershipContext, VALIDATION_POLICY_VERSION,
};
use mealy_domain::{
    CapabilityGrant, DeliveryMode, EffectClass, EventId, InboxEntryId, OutboxId, PolicyProfile,
    RiskClass, RunId, SessionId, SuccessCriterion, TaskId, TaskSuccessCriteria, TurnId,
};
use std::collections::BTreeSet;
use std::time::SystemTime;
use thiserror::Error;

/// IDs and immutable values supplied to one atomic FIFO promotion attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionCommit {
    /// Session whose pending inbox head is considered.
    pub session_id: SessionId,
    /// Authenticated owner and channel binding.
    pub ownership: OwnershipContext,
    /// ID reserved for a newly promoted turn.
    pub turn_id: TurnId,
    /// ID reserved for the turn's user-visible task.
    pub task_id: TaskId,
    /// ID reserved for the initial agent run.
    pub run_id: RunId,
    /// Event ID for `input.promoted`.
    pub promotion_event_id: EventId,
    /// Event ID for `task.created`.
    pub task_event_id: EventId,
    /// Event ID for `run.created`.
    pub run_event_id: EventId,
    /// Durable notification delivery ID.
    pub outbox_id: OutboxId,
    /// Transaction time supplied by the application clock.
    pub promoted_at: SystemTime,
    /// Initial first-party agent role.
    pub initial_agent_role: String,
    /// Validated effective budget copied onto the new root run.
    pub initial_budget: AgentLoopLimits,
    /// Policy/tool contract used to classify the admitted input.
    pub initial_task_profile: InitialTaskProfile,
    /// Trusted configuration-derived authority override for a general-assistant root task.
    pub initial_capability_ceiling: Option<CapabilityGrant>,
}

/// Canonical result of promoting one inbox record into runnable work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionReceipt {
    /// Owning session.
    pub session_id: SessionId,
    /// Inbox record that was promoted.
    pub inbox_entry_id: InboxEntryId,
    /// Monotonic session inbox sequence.
    pub inbox_sequence: u64,
    /// Delivery behavior attached at admission.
    pub delivery_mode: DeliveryMode,
    /// Newly active turn.
    pub turn_id: TurnId,
    /// Newly queued task.
    pub task_id: TaskId,
    /// Newly queued initial run.
    pub run_id: RunId,
    /// Highest durable timeline cursor committed by promotion.
    pub cursor: u64,
}

/// Receipt for an inbox input durably attached to the active run's next safe boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SteeringReceipt {
    /// Owning session.
    pub session_id: SessionId,
    /// Attached inbox record.
    pub inbox_entry_id: InboxEntryId,
    /// Monotonic session inbox sequence.
    pub inbox_sequence: u64,
    /// Existing turn receiving the steering input.
    pub turn_id: TurnId,
    /// Existing run receiving the steering input.
    pub run_id: RunId,
    /// Highest cursor committed with the attachment.
    pub cursor: u64,
}

/// Receipt for a durable interrupt-before-queue request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptionReceipt {
    /// Owning session.
    pub session_id: SessionId,
    /// Pending inbox record that will be promoted after cancellation.
    pub inbox_entry_id: InboxEntryId,
    /// Monotonic session inbox sequence.
    pub inbox_sequence: u64,
    /// Turn asked to stop.
    pub turn_id: TurnId,
    /// Run asked to stop.
    pub run_id: RunId,
    /// Whether unclaimed queued work was cancelled immediately.
    pub cancelled_before_claim: bool,
    /// Highest cursor committed with the request.
    pub cursor: u64,
}

/// Session eligible for an automatic driver promotion attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PromotionCandidate {
    /// Session with a pending FIFO head that can make progress now.
    pub session_id: SessionId,
    /// Persisted owner identity used for the internal driver command.
    pub ownership: OwnershipContext,
}

/// Typed authority, success criteria, and budget admitted for one initial task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialTaskContract {
    /// Maximum authority copied onto the root run.
    pub capability_ceiling: CapabilityGrant,
    /// Explicit objective, criteria, risk, and validation policy.
    pub success_criteria: TaskSuccessCriteria,
    /// Separately enforceable root-run budget.
    pub budget: AgentLoopLimits,
    /// Context baseline compatible with this task's selected policy/tool profile.
    pub context_baseline_version: String,
}

/// First-party root-task contract selected by validated daemon configuration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum InitialTaskProfile {
    /// Deterministic fixture read/write proof retained for conformance and replay testing.
    #[default]
    FixtureProof,
    /// Low-risk conversational task with no model-visible effect capability.
    GeneralAssistant,
}

/// Derives the deterministic fixture task contract from exact admitted input.
///
/// This is deliberately a pure classifier so atomic FIFO promotion can select the pending input
/// and apply the same policy without widening authority in the storage adapter.
#[must_use]
pub fn initial_task_contract(content: &str) -> InitialTaskContract {
    initial_task_contract_for_profile(content, InitialTaskProfile::FixtureProof)
}

/// Derives the exact root-task contract for the configured first-party profile.
///
/// The profile is selected before promotion and copied into the atomic commit. User content cannot
/// switch a production conversational task into the fixture mutation profile.
#[must_use]
pub fn initial_task_contract_for_profile(
    content: &str,
    profile: InitialTaskProfile,
) -> InitialTaskContract {
    match profile {
        InitialTaskProfile::FixtureProof => fixture_task_contract(content),
        InitialTaskProfile::GeneralAssistant => general_assistant_task_contract(content),
    }
}

fn general_assistant_task_contract(content: &str) -> InitialTaskContract {
    if content.starts_with(crate::PROCESS_RUN_INPUT_PREFIX) {
        let contract = InitialTaskContract {
            capability_ceiling: CapabilityGrant::default(),
            success_criteria: TaskSuccessCriteria {
                objective: "Run at most one explicitly approved digest-pinned process and report its durable result"
                    .to_owned(),
                criteria: vec![
                    SuccessCriterion {
                        criterion_id: "authorization".to_owned(),
                        requirement: "Any process has authenticated unexpired approval bound to exact arguments, workspace, executable digest, worker digest, and policy"
                            .to_owned(),
                    },
                    SuccessCriterion {
                        criterion_id: "effect_outcome".to_owned(),
                        requirement: "The non-idempotent process effect has durable terminal evidence and crosses dispatch at most once"
                            .to_owned(),
                    },
                    SuccessCriterion {
                        criterion_id: "response_grounding".to_owned(),
                        requirement: "The final response is grounded only in the recorded process effect observation"
                            .to_owned(),
                    },
                ],
                no_objective_criteria_reason: None,
                risk_class: RiskClass::High,
                policy_version: VALIDATION_POLICY_VERSION.to_owned(),
            },
            budget: AgentLoopLimits::default(),
            context_baseline_version: "mealy.general-assistant.process.v1".to_owned(),
        };
        debug_assert!(contract.capability_ceiling.validate().is_ok());
        debug_assert!(contract.success_criteria.validate().is_ok());
        return contract;
    }
    if content.starts_with(crate::WORKSPACE_ACTION_INPUT_PREFIX)
        || content.starts_with(crate::WORKSPACE_EDIT_INPUT_PREFIX)
        || content.starts_with(crate::WORKSPACE_MANAGE_INPUT_PREFIX)
    {
        return workspace_action_task_contract(content);
    }
    let contract = InitialTaskContract {
        capability_ceiling: CapabilityGrant::default(),
        success_criteria: TaskSuccessCriteria {
            objective: "Produce one bounded assistant response to the authenticated admitted request"
                .to_owned(),
            criteria: vec![
                SuccessCriterion {
                    criterion_id: "response_present".to_owned(),
                    requirement: "The provider produces a non-empty bounded final response"
                        .to_owned(),
                },
                SuccessCriterion {
                    criterion_id: "response_integrity".to_owned(),
                    requirement: "The delivered response exactly matches the durably recorded provider result"
                        .to_owned(),
                },
            ],
            no_objective_criteria_reason: None,
            risk_class: RiskClass::Low,
            policy_version: VALIDATION_POLICY_VERSION.to_owned(),
        },
        budget: AgentLoopLimits::default(),
        context_baseline_version: "mealy.general-assistant.baseline.v1".to_owned(),
    };
    debug_assert!(contract.capability_ceiling.validate().is_ok());
    debug_assert!(contract.success_criteria.validate().is_ok());
    contract
}

fn workspace_action_task_contract(content: &str) -> InitialTaskContract {
    let contract = InitialTaskContract {
        capability_ceiling: CapabilityGrant::default(),
        success_criteria: TaskSuccessCriteria {
            objective:
                "Perform at most one explicitly approved workspace action and report its durable result"
                    .to_owned(),
            criteria: vec![
                SuccessCriterion {
                    criterion_id: "authorization".to_owned(),
                    requirement: "Any mutation has an authenticated, unexpired approval bound to its exact arguments, logical target, executable identity, and policy"
                        .to_owned(),
                },
                SuccessCriterion {
                    criterion_id: "effect_outcome".to_owned(),
                    requirement: "The governed effect has durable terminal evidence and external dispatch occurs at most once"
                        .to_owned(),
                },
                SuccessCriterion {
                    criterion_id: "response_grounding".to_owned(),
                    requirement: "The final response is grounded only in the recorded effect observation"
                        .to_owned(),
                },
            ],
            no_objective_criteria_reason: None,
            risk_class: RiskClass::Medium,
            policy_version: VALIDATION_POLICY_VERSION.to_owned(),
        },
        budget: AgentLoopLimits::default(),
        context_baseline_version: if content.starts_with(crate::WORKSPACE_EDIT_INPUT_PREFIX) {
            "mealy.general-assistant.edit.v2"
        } else if content.starts_with(crate::WORKSPACE_MANAGE_INPUT_PREFIX) {
            "mealy.general-assistant.manage.v1"
        } else {
            "mealy.general-assistant.action.v1"
        }
        .to_owned(),
    };
    debug_assert!(contract.capability_ceiling.validate().is_ok());
    debug_assert!(contract.success_criteria.validate().is_ok());
    contract
}

fn fixture_task_contract(content: &str) -> InitialTaskContract {
    let write = content.starts_with(FIXTURE_WRITE_INPUT_PREFIX);
    let capability_ceiling = if write {
        CapabilityGrant {
            tools: BTreeSet::from([FIXTURE_WRITE_FILE_TOOL_ID.to_owned()]),
            effect_classes: BTreeSet::from([EffectClass::Idempotent]),
            workspace_roots: BTreeSet::from(["fixture://phase3/workspace".to_owned()]),
            profiles: BTreeSet::from([PolicyProfile::WorkspaceWrite]),
            maximum_delegated_runs: 2,
            ..CapabilityGrant::default()
        }
    } else {
        CapabilityGrant {
            tools: BTreeSet::from(["fixture.read".to_owned()]),
            effect_classes: BTreeSet::from([EffectClass::ReadOnly]),
            profiles: BTreeSet::from([PolicyProfile::Observe]),
            maximum_delegated_runs: 2,
            ..CapabilityGrant::default()
        }
    };
    let success_criteria = if write {
        TaskSuccessCriteria {
            objective: "Process one approval-gated fixture-write request and report its durable result"
                .to_owned(),
            criteria: vec![
                SuccessCriterion {
                    criterion_id: "authorization".to_owned(),
                    requirement: "Any mutation has an authenticated, unexpired approval bound to its exact normalized arguments, target, executable identity, and policy"
                        .to_owned(),
                },
                SuccessCriterion {
                    criterion_id: "effect_outcome".to_owned(),
                    requirement: "The fixture-write effect has durable terminal evidence and the external mutation occurs at most once"
                        .to_owned(),
                },
                SuccessCriterion {
                    criterion_id: "response_grounding".to_owned(),
                    requirement: "The final response is grounded only in the recorded effect observation"
                        .to_owned(),
                },
            ],
            no_objective_criteria_reason: None,
            risk_class: RiskClass::Medium,
            policy_version: VALIDATION_POLICY_VERSION.to_owned(),
        }
    } else {
        TaskSuccessCriteria {
            objective: "Answer the admitted request from durable fixture-read evidence".to_owned(),
            criteria: vec![
                SuccessCriterion {
                    criterion_id: "tool_evidence".to_owned(),
                    requirement: "The fixture resource is read through the declared read-only tool and its result is durably recorded"
                        .to_owned(),
                },
                SuccessCriterion {
                    criterion_id: "response_grounding".to_owned(),
                    requirement: "The final response is grounded in the recorded fixture-read observation"
                        .to_owned(),
                },
            ],
            no_objective_criteria_reason: None,
            risk_class: RiskClass::Low,
            policy_version: VALIDATION_POLICY_VERSION.to_owned(),
        }
    };
    debug_assert!(capability_ceiling.validate().is_ok());
    debug_assert!(success_criteria.validate().is_ok());
    InitialTaskContract {
        capability_ceiling,
        success_criteria,
        budget: AgentLoopLimits::default(),
        context_baseline_version: if write {
            "mealy.phase3.baseline.v1"
        } else {
            "mealy.phase2.baseline.v1"
        }
        .to_owned(),
    }
}

/// Result of considering the FIFO inbox head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PromotionOutcome {
    /// One pending input was atomically promoted.
    Promoted(PromotionReceipt),
    /// A steer-at-boundary input was durably attached to the active run.
    Steered(SteeringReceipt),
    /// An interrupt request was durably attached before the input remains queued.
    InterruptRequested(InterruptionReceipt),
    /// No pending input exists.
    InboxEmpty,
    /// A canonical turn already owns this session's mutation slot.
    ActiveTurn {
        /// Active turn preventing a new promotion.
        turn_id: TurnId,
        /// Delivery mode at the blocked FIFO head, when a head exists.
        pending_mode: Option<DeliveryMode>,
    },
}

/// Persistence failures for FIFO promotion.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PromotionStoreError {
    /// Session does not exist.
    #[error("session was not found")]
    SessionNotFound,
    /// Principal or channel binding does not own the session.
    #[error("session access is unauthorized")]
    Unauthorized,
    /// A concurrent driver won the promotion race.
    #[error("promotion conflicted with concurrent session state")]
    Conflict,
    /// Persistence is temporarily unavailable.
    #[error("promotion store is unavailable: {0}")]
    Unavailable(String),
    /// Canonical data violates a required invariant.
    #[error("promotion store invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port that owns the atomic inbox-to-turn transition.
pub trait InboxPromotionStore {
    /// Lists a bounded set of sessions whose FIFO head can be promoted.
    ///
    /// # Errors
    ///
    /// Returns [`PromotionStoreError`] on persistence or invariant failure.
    fn pending_sessions(
        &self,
        limit: usize,
    ) -> Result<Vec<PromotionCandidate>, PromotionStoreError>;

    /// Considers and, when possible, promotes the lowest pending inbox sequence.
    ///
    /// # Errors
    ///
    /// Returns [`PromotionStoreError`] on authorization, conflict, or persistence failure.
    fn promote_next(
        &mut self,
        commit: PromotionCommit,
    ) -> Result<PromotionOutcome, PromotionStoreError>;
}

/// Lists bounded automatic-promotion candidates.
///
/// # Errors
///
/// Returns [`PromotionUseCaseError`] for an invalid limit or store failure.
pub fn pending_promotion_sessions(
    store: &impl InboxPromotionStore,
    limit: usize,
) -> Result<Vec<PromotionCandidate>, PromotionUseCaseError> {
    if !(1..=1000).contains(&limit) {
        return Err(PromotionUseCaseError::InvalidCandidateLimit);
    }
    store
        .pending_sessions(limit)
        .map_err(PromotionUseCaseError::from)
}

/// Validated defaults for initial run creation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionDefaults {
    agent_role: String,
    budget: AgentLoopLimits,
    task_profile: InitialTaskProfile,
    capability_ceiling: Option<CapabilityGrant>,
}

impl PromotionDefaults {
    /// Creates promotion defaults with a bounded, nonempty first-party role.
    ///
    /// # Errors
    ///
    /// Returns [`PromotionUseCaseError`] when the role is empty or longer than 128 bytes.
    pub fn new(
        initial_agent_role: impl Into<String>,
        initial_budget: AgentLoopLimits,
    ) -> Result<Self, PromotionUseCaseError> {
        let initial_agent_role = initial_agent_role.into();
        if initial_agent_role.is_empty() {
            return Err(PromotionUseCaseError::EmptyAgentRole);
        }
        if initial_agent_role.len() > 128 {
            return Err(PromotionUseCaseError::AgentRoleTooLarge);
        }
        initial_budget
            .validate()
            .map_err(|_| PromotionUseCaseError::InvalidAgentBudget)?;
        Ok(Self {
            agent_role: initial_agent_role,
            budget: initial_budget,
            task_profile: InitialTaskProfile::FixtureProof,
            capability_ceiling: None,
        })
    }

    /// Selects the immutable root-task contract applied by atomic promotion.
    #[must_use]
    pub const fn with_initial_task_profile(mut self, profile: InitialTaskProfile) -> Self {
        self.task_profile = profile;
        self
    }

    /// Binds exact configured read and separately scoped action authority into new root tasks.
    ///
    /// # Errors
    ///
    /// Returns [`PromotionUseCaseError::InvalidInitialCapabilities`] when the grant is malformed,
    /// contains unsupported authority or names an unsupported tool family.
    pub fn with_general_assistant_capability_ceiling(
        mut self,
        capability_ceiling: CapabilityGrant,
    ) -> Result<Self, PromotionUseCaseError> {
        if self.task_profile != InitialTaskProfile::GeneralAssistant
            || !valid_general_assistant_capability_ceiling(&capability_ceiling)
        {
            return Err(PromotionUseCaseError::InvalidInitialCapabilities);
        }
        self.capability_ceiling = Some(capability_ceiling);
        Ok(self)
    }

    /// Returns the role stored on the initial run.
    #[must_use]
    pub fn initial_agent_role(&self) -> &str {
        &self.agent_role
    }

    /// Returns the effective budget copied onto every new root run.
    #[must_use]
    pub const fn initial_budget(&self) -> AgentLoopLimits {
        self.budget
    }

    /// Returns the configured root-task contract profile.
    #[must_use]
    pub const fn initial_task_profile(&self) -> InitialTaskProfile {
        self.task_profile
    }

    /// Returns the exact configuration-derived root-task authority, when selected.
    #[must_use]
    pub const fn initial_capability_ceiling(&self) -> Option<&CapabilityGrant> {
        self.capability_ceiling.as_ref()
    }
}

/// Returns whether a configured conversational root grant is an exact supported read-only shape.
#[must_use]
pub fn valid_general_assistant_capability_ceiling(grant: &CapabilityGrant) -> bool {
    let has_workspace_read = grant
        .tools
        .iter()
        .any(|tool| tool.starts_with("workspace."));
    let has_write = grant.tools.contains(crate::WORKSPACE_CREATE_FILE_TOOL_ID)
        || grant.tools.contains(crate::WORKSPACE_REPLACE_FILE_TOOL_ID);
    let has_manage = grant.tools.contains(crate::WORKSPACE_MANAGE_PATH_TOOL_ID);
    let has_process = grant.tools.contains(crate::PROCESS_RUN_TOOL_ID);
    let has_workspace = has_workspace_read || has_write || has_manage || has_process;
    let has_web = grant
        .tools
        .iter()
        .any(|tool| tool.starts_with("web.") || tool == crate::BROWSER_SNAPSHOT_TOOL_ID);
    let has_mcp = grant.tools.iter().any(|tool| valid_mcp_tool_id(tool));
    let has_delegation = grant.tools.contains(crate::AGENT_DELEGATE_TOOL_ID);
    let has_read = has_mcp
        || grant.tools.iter().any(|tool| {
            matches!(
                tool.as_str(),
                "workspace.list"
                    | "workspace.stat"
                    | "workspace.read"
                    | "workspace.search"
                    | crate::AGENT_DELEGATE_TOOL_ID
                    | "skill.read_resource"
                    | "web.fetch"
                    | "web.search"
                    | crate::BROWSER_SNAPSHOT_TOOL_ID
            )
        });
    let mut expected_effect_classes = BTreeSet::new();
    let mut expected_profiles = BTreeSet::new();
    if has_read {
        expected_effect_classes.insert(EffectClass::ReadOnly);
        expected_profiles.insert(PolicyProfile::Observe);
    }
    if has_write {
        expected_effect_classes.insert(EffectClass::Idempotent);
        expected_profiles.insert(PolicyProfile::WorkspaceWrite);
    }
    if has_manage || has_process {
        expected_effect_classes.insert(EffectClass::NonIdempotent);
        expected_profiles.insert(PolicyProfile::WorkspaceWrite);
    }
    grant.validate().is_ok()
        && grant.tools.iter().all(|tool| {
            valid_mcp_tool_id(tool)
                || matches!(
                    tool.as_str(),
                    "workspace.list"
                        | "workspace.stat"
                        | "workspace.read"
                        | "workspace.search"
                        | crate::AGENT_DELEGATE_TOOL_ID
                        | "skill.read_resource"
                        | crate::WORKSPACE_CREATE_FILE_TOOL_ID
                        | crate::WORKSPACE_REPLACE_FILE_TOOL_ID
                        | crate::WORKSPACE_MANAGE_PATH_TOOL_ID
                        | crate::PROCESS_RUN_TOOL_ID
                        | "web.fetch"
                        | "web.search"
                        | crate::BROWSER_SNAPSHOT_TOOL_ID
                )
        })
        && grant.effect_classes == expected_effect_classes
        && grant.profiles == expected_profiles
        && if has_delegation {
            (1..=32).contains(&grant.maximum_delegated_runs)
        } else {
            grant.maximum_delegated_runs == 0
        }
        && has_workspace != grant.workspace_roots.is_empty()
        && grant
            .workspace_roots
            .iter()
            .all(|root| root.starts_with("workspace://") && root.ends_with('/'))
        && (has_write || has_manage || has_process) != grant.writable_workspace_roots.is_empty()
        && grant
            .writable_workspace_roots
            .iter()
            .all(|root| root.starts_with("workspace://") && root.ends_with('/'))
        && has_web != grant.network_destinations.is_empty()
        && has_process != grant.executable_identity_digests.is_empty()
        && grant
            .executable_identity_digests
            .iter()
            .all(|digest| crate::is_sha256_digest(digest))
        && (has_web || grant.secret_references.is_empty())
        && (grant.secret_references.is_empty() || grant.tools.contains("web.search"))
}

fn valid_mcp_tool_id(tool_id: &str) -> bool {
    let Some(remainder) = tool_id.strip_prefix("mcp.") else {
        return false;
    };
    let Some((server_id, remote_name)) = remainder.split_once('.') else {
        return false;
    };
    !server_id.is_empty()
        && server_id.len() <= 32
        && !remote_name.is_empty()
        && remote_name.len() <= 64
        && tool_id.len() <= 128
        && tool_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

impl Default for PromotionDefaults {
    fn default() -> Self {
        Self {
            agent_role: "assistant".to_owned(),
            budget: AgentLoopLimits::default(),
            task_profile: InitialTaskProfile::FixtureProof,
            capability_ceiling: None,
        }
    }
}

/// Rejected promotion use case.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PromotionUseCaseError {
    /// Agent role cannot be empty.
    #[error("initial agent role must not be empty")]
    EmptyAgentRole,
    /// Agent role is too large for canonical scheduling metadata.
    #[error("initial agent role exceeds 128 bytes")]
    AgentRoleTooLarge,
    /// Initial run budget is internally inconsistent or unbounded.
    #[error("initial agent budget is invalid")]
    InvalidAgentBudget,
    /// Configured general-assistant authority is malformed or wider than read-only observation.
    #[error("initial general-assistant capabilities are invalid")]
    InvalidInitialCapabilities,
    /// Candidate scans must be bounded to 1 through 1,000 sessions.
    #[error("promotion candidate limit must be between 1 and 1000")]
    InvalidCandidateLimit,
    /// Atomic storage failed.
    #[error(transparent)]
    Store(#[from] PromotionStoreError),
}

/// Promotes the FIFO inbox head through the application transaction port.
///
/// # Errors
///
/// Returns [`PromotionUseCaseError`] if the store rejects the atomic transition.
pub fn promote_next_input(
    store: &mut impl InboxPromotionStore,
    clock: &impl Clock,
    ids: &impl IdGenerator,
    session_id: SessionId,
    ownership: OwnershipContext,
    defaults: &PromotionDefaults,
) -> Result<PromotionOutcome, PromotionUseCaseError> {
    store
        .promote_next(PromotionCommit {
            session_id,
            ownership,
            turn_id: ids.generate_turn_id(),
            task_id: ids.generate_task_id(),
            run_id: ids.generate_run_id(),
            promotion_event_id: ids.generate_event_id(),
            task_event_id: ids.generate_event_id(),
            run_event_id: ids.generate_event_id(),
            outbox_id: ids.generate_outbox_id(),
            promoted_at: clock.now(),
            initial_agent_role: defaults.initial_agent_role().to_owned(),
            initial_budget: defaults.initial_budget(),
            initial_task_profile: defaults.initial_task_profile(),
            initial_capability_ceiling: defaults.initial_capability_ceiling().cloned(),
        })
        .map_err(PromotionUseCaseError::from)
}

#[cfg(test)]
mod tests {
    use super::{
        InitialTaskProfile, PromotionDefaults, initial_task_contract,
        initial_task_contract_for_profile,
    };
    use crate::{
        AgentLoopLimits, FIXTURE_WRITE_FILE_TOOL_ID, FIXTURE_WRITE_INPUT_PREFIX,
        WORKSPACE_ACTION_INPUT_PREFIX, WORKSPACE_CREATE_FILE_TOOL_ID, WORKSPACE_EDIT_INPUT_PREFIX,
        WORKSPACE_MANAGE_INPUT_PREFIX, WORKSPACE_MANAGE_PATH_TOOL_ID,
    };
    use mealy_domain::{CapabilityGrant, EffectClass, PolicyProfile, RiskClass};
    use std::collections::BTreeSet;

    #[test]
    fn initial_contract_classifies_mutation_before_persistence() {
        let contract = initial_task_contract(&format!(
            "{FIXTURE_WRITE_INPUT_PREFIX}{{\"operation\":\"write_file\"}}"
        ));
        assert_eq!(contract.success_criteria.risk_class, RiskClass::Medium);
        assert!(contract.success_criteria.independent_validation_required());
        assert!(
            contract
                .capability_ceiling
                .tools
                .contains(FIXTURE_WRITE_FILE_TOOL_ID)
        );
        assert_eq!(
            contract.capability_ceiling.effect_classes,
            [EffectClass::Idempotent].into_iter().collect()
        );
        assert_eq!(
            contract.capability_ceiling.profiles,
            [PolicyProfile::WorkspaceWrite].into_iter().collect()
        );
    }

    #[test]
    fn initial_read_contract_is_low_risk_and_observe_only() {
        let contract = initial_task_contract("Read the fixture report");
        assert_eq!(contract.success_criteria.risk_class, RiskClass::Low);
        assert!(!contract.success_criteria.independent_validation_required());
        assert_eq!(
            contract.capability_ceiling.effect_classes,
            [EffectClass::ReadOnly].into_iter().collect()
        );
        assert_eq!(
            contract.capability_ceiling.profiles,
            [PolicyProfile::Observe].into_iter().collect()
        );
        assert!(contract.capability_ceiling.network_destinations.is_empty());
        assert!(contract.capability_ceiling.secret_references.is_empty());
    }

    #[test]
    fn general_assistant_contract_cannot_be_widened_by_fixture_prefix() {
        let contract = initial_task_contract_for_profile(
            &format!("{FIXTURE_WRITE_INPUT_PREFIX}{{\"operation\":\"write_file\"}}"),
            InitialTaskProfile::GeneralAssistant,
        );
        assert_eq!(contract.success_criteria.risk_class, RiskClass::Low);
        assert_eq!(
            contract.context_baseline_version,
            "mealy.general-assistant.baseline.v1"
        );
        assert!(contract.capability_ceiling.tools.is_empty());
        assert!(contract.capability_ceiling.effect_classes.is_empty());
        assert!(contract.capability_ceiling.workspace_roots.is_empty());
        assert!(contract.capability_ceiling.network_destinations.is_empty());
    }

    #[test]
    fn explicit_action_prefix_selects_medium_risk_validation_without_ambient_authority() {
        let contract = initial_task_contract_for_profile(
            &format!("{WORKSPACE_ACTION_INPUT_PREFIX}Create a report"),
            InitialTaskProfile::GeneralAssistant,
        );

        let edit = initial_task_contract_for_profile(
            &format!("{WORKSPACE_EDIT_INPUT_PREFIX}Replace the report"),
            InitialTaskProfile::GeneralAssistant,
        );
        let manage = initial_task_contract_for_profile(
            &format!("{WORKSPACE_MANAGE_INPUT_PREFIX}Move the report"),
            InitialTaskProfile::GeneralAssistant,
        );
        assert_eq!(manage.success_criteria.risk_class, RiskClass::Medium);
        assert!(manage.success_criteria.independent_validation_required());
        assert_eq!(
            manage.context_baseline_version,
            "mealy.general-assistant.manage.v1"
        );
        assert!(manage.capability_ceiling.tools.is_empty());
        assert_eq!(edit.success_criteria.risk_class, RiskClass::Medium);
        assert!(edit.success_criteria.independent_validation_required());
        assert_eq!(
            edit.context_baseline_version,
            "mealy.general-assistant.edit.v2"
        );
        assert!(edit.capability_ceiling.tools.is_empty());
        assert_eq!(contract.success_criteria.risk_class, RiskClass::Medium);
        assert!(contract.success_criteria.independent_validation_required());
        assert_eq!(
            contract.context_baseline_version,
            "mealy.general-assistant.action.v1"
        );
        assert!(contract.capability_ceiling.tools.is_empty());
        assert!(
            contract
                .capability_ceiling
                .writable_workspace_roots
                .is_empty()
        );
    }

    #[test]
    fn configured_authority_accepts_exact_writable_subset_and_rejects_latent_grants() {
        let defaults = PromotionDefaults::new("assistant", AgentLoopLimits::default())
            .expect("defaults")
            .with_initial_task_profile(InitialTaskProfile::GeneralAssistant);
        let valid = CapabilityGrant {
            tools: BTreeSet::from(["web.fetch".to_owned(), "workspace.read".to_owned()]),
            effect_classes: BTreeSet::from([EffectClass::ReadOnly]),
            workspace_roots: BTreeSet::from(["workspace://project/".to_owned()]),
            network_destinations: BTreeSet::from(["public:https".to_owned()]),
            profiles: BTreeSet::from([PolicyProfile::Observe]),
            ..CapabilityGrant::default()
        };
        assert!(
            defaults
                .clone()
                .with_general_assistant_capability_ceiling(valid)
                .is_ok()
        );
        let valid_skill_resource = CapabilityGrant {
            tools: BTreeSet::from(["skill.read_resource".to_owned()]),
            effect_classes: BTreeSet::from([EffectClass::ReadOnly]),
            profiles: BTreeSet::from([PolicyProfile::Observe]),
            ..CapabilityGrant::default()
        };
        assert!(
            defaults
                .clone()
                .with_general_assistant_capability_ceiling(valid_skill_resource)
                .is_ok()
        );

        let valid_action = CapabilityGrant {
            tools: BTreeSet::from([
                "workspace.read".to_owned(),
                WORKSPACE_CREATE_FILE_TOOL_ID.to_owned(),
            ]),
            effect_classes: BTreeSet::from([EffectClass::ReadOnly, EffectClass::Idempotent]),
            workspace_roots: BTreeSet::from([
                "workspace://project/".to_owned(),
                "workspace://reference/".to_owned(),
            ]),
            writable_workspace_roots: BTreeSet::from(["workspace://project/".to_owned()]),
            profiles: BTreeSet::from([PolicyProfile::Observe, PolicyProfile::WorkspaceWrite]),
            ..CapabilityGrant::default()
        };
        assert!(
            defaults
                .clone()
                .with_general_assistant_capability_ceiling(valid_action)
                .is_ok()
        );

        let latent_web = CapabilityGrant {
            tools: BTreeSet::from(["web.fetch".to_owned()]),
            effect_classes: BTreeSet::from([EffectClass::ReadOnly]),
            profiles: BTreeSet::from([PolicyProfile::Observe]),
            ..CapabilityGrant::default()
        };
        assert!(
            defaults
                .clone()
                .with_general_assistant_capability_ceiling(latent_web)
                .is_err()
        );
        let effectful = CapabilityGrant {
            tools: BTreeSet::from(["workspace.read".to_owned()]),
            effect_classes: BTreeSet::from([EffectClass::Idempotent]),
            workspace_roots: BTreeSet::from(["workspace://project/".to_owned()]),
            profiles: BTreeSet::from([PolicyProfile::WorkspaceWrite]),
            ..CapabilityGrant::default()
        };
        assert!(
            defaults
                .clone()
                .with_general_assistant_capability_ceiling(effectful)
                .is_err()
        );

        let latent_write = CapabilityGrant {
            tools: BTreeSet::from([WORKSPACE_CREATE_FILE_TOOL_ID.to_owned()]),
            effect_classes: BTreeSet::from([EffectClass::Idempotent]),
            workspace_roots: BTreeSet::from(["workspace://project/".to_owned()]),
            profiles: BTreeSet::from([PolicyProfile::WorkspaceWrite]),
            ..CapabilityGrant::default()
        };
        assert!(
            defaults
                .with_general_assistant_capability_ceiling(latent_write)
                .is_err()
        );
    }

    #[test]
    fn configured_authority_accepts_exact_manage_path_subset() {
        let defaults = PromotionDefaults::new("assistant", AgentLoopLimits::default())
            .expect("defaults")
            .with_initial_task_profile(InitialTaskProfile::GeneralAssistant);
        let valid_manage = CapabilityGrant {
            tools: BTreeSet::from([
                "workspace.read".to_owned(),
                WORKSPACE_MANAGE_PATH_TOOL_ID.to_owned(),
            ]),
            effect_classes: BTreeSet::from([EffectClass::ReadOnly, EffectClass::NonIdempotent]),
            workspace_roots: BTreeSet::from(["workspace://project/".to_owned()]),
            writable_workspace_roots: BTreeSet::from(["workspace://project/".to_owned()]),
            profiles: BTreeSet::from([PolicyProfile::Observe, PolicyProfile::WorkspaceWrite]),
            ..CapabilityGrant::default()
        };
        assert!(
            defaults
                .with_general_assistant_capability_ceiling(valid_manage)
                .is_ok()
        );
    }
}
