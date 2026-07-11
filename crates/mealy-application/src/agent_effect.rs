use crate::{AgentStoreError, RecordEffectProposalCommit};
use mealy_domain::{
    ApprovalId, AttemptId, CorrelationId, EffectId, EventId, LeaseFence, MessageId, RunId, TaskId,
    ToolCallId,
};
use std::time::SystemTime;

/// Version bound into the canonical model-facing observation of a governed effect.
pub const AGENT_EFFECT_OBSERVATION_CONTRACT_VERSION: &str = "mealy.agent-effect-observation.v1";

/// Immutable origin link between one normalized model tool call and one governed effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentEffectInvocation {
    /// Governed effect proposed from the model result.
    pub effect_id: EffectId,
    /// Run that owns both the model attempt and effect.
    pub run_id: RunId,
    /// Task parked or resumed around the effect.
    pub task_id: TaskId,
    /// Completed normalized provider attempt that proposed the call.
    pub model_attempt_id: AttemptId,
    /// Stable normalized tool-call identity presented back to the provider.
    pub tool_call_id: ToolCallId,
}

/// Atomic boundary that links a committed model result to an effect and parks for approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordAgentEffectProposalCommit {
    /// Exact active worker lease that consumed the normalized model result.
    pub fence: LeaseFence,
    /// Completed provider attempt containing the exact tool proposal.
    pub model_attempt_id: AttemptId,
    /// Stable identity allocated for the normalized tool proposal.
    pub tool_call_id: ToolCallId,
    /// Complete effect-ledger proposal committed in the same transaction.
    pub proposal: RecordEffectProposalCommit,
    /// Journal fact retiring the active lease at the approval boundary.
    pub lease_event_id: EventId,
    /// `run.waiting_for_approval` journal fact.
    pub run_event_id: EventId,
    /// `task.waiting_for_approval` journal fact.
    pub task_event_id: EventId,
    /// Durable loop checkpoint that binds the effect origin.
    pub checkpoint_event_id: EventId,
    /// Time assigned to the complete proposal-and-park transaction.
    pub parked_at: SystemTime,
}

/// Internal transaction that makes a terminal or authorized parked effect runnable again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeAgentEffectRunCommit {
    /// Effect whose current lifecycle permits continued model-loop work.
    pub effect_id: EffectId,
    /// Run-aggregate resume event.
    pub run_event_id: EventId,
    /// Task-aggregate resume event.
    pub task_event_id: EventId,
    /// Correlates the maintenance transition with the original effect.
    pub correlation_id: CorrelationId,
    /// Time at which readiness was observed.
    pub resumed_at: SystemTime,
}

/// Fenced transition that parks a live run after an explicitly recorded unknown effect outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParkAgentEffectRunCommit {
    /// Exact active lease being retired after ambiguity was recorded.
    pub fence: LeaseFence,
    /// Linked effect that is currently `outcome_unknown`.
    pub effect_id: EffectId,
    /// Lease-retirement journal fact.
    pub lease_event_id: EventId,
    /// Run wait-state journal fact.
    pub run_event_id: EventId,
    /// Task wait-state journal fact.
    pub task_event_id: EventId,
    /// Correlates the park boundary with dispatch and outcome evidence.
    pub correlation_id: CorrelationId,
    /// Time assigned to the atomic park transition.
    pub parked_at: SystemTime,
}

/// Fenced commit that turns terminal effect evidence into one canonical tool observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordAgentEffectObservationCommit {
    /// Exact active worker lease consuming the effect result.
    pub fence: LeaseFence,
    /// Effect linked to the current normalized provider result.
    pub effect_id: EffectId,
    /// Provider attempt that proposed the original tool call.
    pub model_attempt_id: AttemptId,
    /// Original normalized tool-call identity.
    pub tool_call_id: ToolCallId,
    /// Durable message identity for the model-facing observation.
    pub message_id: MessageId,
    /// `message.tool.effect_observed` journal fact.
    pub event_id: EventId,
    /// Loop checkpoint advancing back to context compilation.
    pub checkpoint_event_id: EventId,
    /// Time at which already-recorded effect evidence was projected.
    pub observed_at: SystemTime,
}

/// Canonical observation committed from recorded effect evidence only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentEffectObservationReceipt {
    /// Effect whose terminal evidence was projected.
    pub effect_id: EffectId,
    /// Durable tool-role message inserted into canonical history.
    pub message_id: MessageId,
    /// Exact versioned canonical JSON text presented to the next model attempt.
    pub content: String,
    /// SHA-256 digest of [`Self::content`].
    pub content_digest: String,
    /// Effect revision bound into the projection.
    pub effect_revision: u64,
    /// Highest durable timeline cursor committed with the observation.
    pub cursor: u64,
    /// Whether the exact observation already existed.
    pub duplicate: bool,
}

/// Durable bridge between normalized provider tool calls and the effect ledger.
pub trait AgentEffectStore {
    /// Returns deterministically ordered pending approvals whose exclusive expiry has elapsed.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for invalid limits, corrupt evidence, or storage failure.
    fn expired_agent_effect_approvals(
        &self,
        observed_at: SystemTime,
        limit: usize,
    ) -> Result<Vec<ApprovalId>, AgentStoreError>;

    /// Finds the immutable effect origin for the current completed model attempt under an exact
    /// active lease.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for stale ownership, corrupt evidence, or storage failure.
    fn agent_effect_invocation(
        &self,
        fence: LeaseFence,
        model_attempt_id: AttemptId,
        observed_at: SystemTime,
    ) -> Result<Option<AgentEffectInvocation>, AgentStoreError>;

    /// Atomically records exact effect intent, its model origin, approval wait state, lease
    /// retirement, journal facts, timeline rows, and loop checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for a stale fence, divergent model result, invalid effect
    /// evidence, duplicate origin, or storage failure.
    fn record_agent_effect_proposal(
        &mut self,
        commit: RecordAgentEffectProposalCommit,
    ) -> Result<AgentEffectInvocation, AgentStoreError>;

    /// Returns deterministically ordered parked effects whose current state permits loop resume.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for invalid limits, corrupt evidence, or storage failure.
    fn ready_agent_effects(
        &self,
        observed_at: SystemTime,
        limit: usize,
    ) -> Result<Vec<EffectId>, AgentStoreError>;

    /// Atomically requeues one parked effect run and task with durable audit events.
    ///
    /// Exact repeats after another worker has already made the run runnable return `false`.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for corrupt linkage, conflict, or storage failure.
    fn resume_agent_effect_run(
        &mut self,
        commit: ResumeAgentEffectRunCommit,
    ) -> Result<bool, AgentStoreError>;

    /// Atomically retires the current lease and parks the linked run/task after an unknown outcome
    /// has already been committed. This method never dispatches or retries the effect.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for a stale fence, non-unknown effect, divergent linkage,
    /// conflict, or storage failure.
    fn park_agent_effect_run(
        &mut self,
        commit: ParkAgentEffectRunCommit,
    ) -> Result<(), AgentStoreError>;

    /// Atomically projects already-recorded terminal effect evidence into canonical model history
    /// and advances the loop. It never invokes an executor or external adapter.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for stale ownership, nonterminal/unknown effects, divergent
    /// origin evidence, conflict, or storage failure.
    fn record_agent_effect_observation(
        &mut self,
        commit: RecordAgentEffectObservationCommit,
    ) -> Result<AgentEffectObservationReceipt, AgentStoreError>;
}
