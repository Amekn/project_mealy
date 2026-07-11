use crate::{
    ApprovalSubject, OwnershipContext, PolicyEvaluation, PolicyRequest, PolicyRequestError,
    canonical_arguments_digest, is_sha256_digest, sha256_digest,
};
use mealy_domain::{
    ApprovalDecision, ApprovalId, ApprovalStatus, AttemptId, CorrelationId, EffectId, EffectStatus,
    EventId, IdempotencyClass, LeaseFence, RecoveryStrategy, RunId, TaskId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::SystemTime;
use thiserror::Error;

/// Version bound into the digest of every durable effect intent.
pub const EFFECT_INTENT_CONTRACT_VERSION: &str = "mealy.effect-intent.v1";

/// Version bound into every canonical effect outcome evidence envelope.
pub const EFFECT_OUTCOME_EVIDENCE_CONTRACT_VERSION: &str = "mealy.effect-outcome-evidence.v1";

/// Maximum serialized size accepted for caller-supplied outcome evidence details.
pub const MAXIMUM_EFFECT_OUTCOME_DETAILS_BYTES: usize = 32 * 1_024;

/// Version bound into every authenticated approval-resolution request digest.
pub const APPROVAL_RESOLUTION_REQUEST_CONTRACT_VERSION: &str =
    "mealy.approval-resolution-request.v1";

/// Version bound into every authenticated effect-reconciliation request digest.
pub const EFFECT_RECONCILIATION_REQUEST_CONTRACT_VERSION: &str =
    "mealy.effect-reconciliation-request.v1";

/// Maximum UTF-8 byte length accepted for an authenticated effect-command idempotency key.
pub const MAXIMUM_EFFECT_COMMAND_IDEMPOTENCY_KEY_BYTES: usize = 256;

/// Stable error classification for an interrupted worker whose dispatch outcome is unproven.
pub const INTERRUPTED_EFFECT_OUTCOME_ERROR_CLASS: &str = "worker_interrupted_after_dispatch";

/// Stable evidence classification for startup recovery of an interrupted effect dispatch.
pub const INTERRUPTED_EFFECT_OUTCOME_CLASSIFICATION: &str =
    "external_outcome_unproven_after_worker_interruption";

/// Stable error classification for an interrupted attempt whose contract proves retry safety.
pub const INTERRUPTED_EFFECT_RETRY_ERROR_CLASS: &str = "worker_interrupted_retryable";

/// Stable evidence classification for authorizing a new safely repeatable attempt.
pub const INTERRUPTED_EFFECT_RETRY_CLASSIFICATION: &str =
    "external_outcome_unproven_but_retry_is_contract_safe";

/// Stable classification for preparation abandoned before the external dispatch boundary.
pub const INTERRUPTED_EFFECT_UNDISPATCHED_CLASSIFICATION: &str =
    "worker_interrupted_before_external_dispatch";

/// Stable error class for an undispatched preparation retired during lease recovery.
pub const INTERRUPTED_EFFECT_UNDISPATCHED_ERROR_CLASS: &str = "worker_interrupted_undispatched";

/// Approval material allocated as part of an effect proposal that policy parked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRequestDraft {
    /// Stable approval request identifier.
    pub approval_id: ApprovalId,
    /// Exact immutable subject presented to the authenticated owner.
    pub subject: ApprovalSubject,
    /// Journal event for the durable `approval.requested` fact.
    pub requested_event_id: EventId,
}

/// Complete transaction input for persisting an effect intent and its authorization evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordEffectProposalCommit {
    /// Stable effect identity from which a downstream idempotency key is derived when needed.
    pub effect_id: EffectId,
    /// Authenticated owner and verified channel binding.
    pub ownership: OwnershipContext,
    /// Exact deterministic request supplied to policy.
    pub policy_request: PolicyRequest,
    /// Exact deterministic policy result and enforceable obligations.
    pub policy_evaluation: PolicyEvaluation,
    /// Present exactly when policy requires an authenticated approval.
    pub approval: Option<ApprovalRequestDraft>,
    /// Journal event for the durable `effect.proposed` fact.
    pub effect_event_id: EventId,
    /// Correlates the proposal, policy evidence, approval, and owning task.
    pub correlation_id: CorrelationId,
    /// Wall-clock instant assigned at the application transaction boundary.
    pub proposed_at: SystemTime,
}

/// Authenticated owner command resolving one exact pending approval subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveApprovalCommit {
    /// Approval being resolved.
    pub approval_id: ApprovalId,
    /// Authenticated owner and verified channel binding.
    pub ownership: OwnershipContext,
    /// Digest rendered to the owner and returned by the authenticated command.
    pub expected_subject_digest: String,
    /// Owner decision for the exact subject.
    pub decision: ApprovalDecision,
    /// Stable authenticated command-delivery key.
    pub idempotency_key: String,
    /// Journal event for the approval aggregate transition.
    pub approval_event_id: EventId,
    /// Journal event for the effect aggregate transition.
    pub effect_event_id: EventId,
    /// Correlates the authenticated command and both transition facts.
    pub correlation_id: CorrelationId,
    /// Decision time assigned at the application transaction boundary.
    pub decided_at: SystemTime,
}

/// Immutable receipt for a new or exact duplicate approval-resolution command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalResolutionReceipt {
    /// Approval resolved by the original command.
    pub approval_id: ApprovalId,
    /// Effect transitioned by the original command.
    pub effect_id: EffectId,
    /// Decision bound to the idempotency key.
    pub decision: ApprovalDecision,
    /// Effect revision committed by the original command.
    pub effect_revision: u64,
    /// Original approval lifecycle event.
    pub approval_event_id: EventId,
    /// Original effect lifecycle event.
    pub effect_event_id: EventId,
    /// Timeline cursor assigned to the original effect event.
    pub cursor: u64,
    /// Whether this invocation matched an already committed request.
    pub duplicate: bool,
}

/// System transaction that durably expires a still-pending approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpireApprovalCommit {
    /// Approval whose exclusive expiry has passed.
    pub approval_id: ApprovalId,
    /// Journal event for the `approval.expired` fact.
    pub approval_event_id: EventId,
    /// Journal event for the resulting `effect.denied` fact.
    pub effect_event_id: EventId,
    /// Correlates recovery/maintenance and both transition facts.
    pub correlation_id: CorrelationId,
    /// Time at which expiry was observed by deterministic application code.
    pub expired_at: SystemTime,
}

/// Durable owner-inspectable approval state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRequestView {
    /// Stable request identifier.
    pub approval_id: ApprovalId,
    /// Effect whose exact subject is bound.
    pub effect_id: EffectId,
    /// Exact immutable approval subject.
    pub subject: ApprovalSubject,
    /// Digest of the canonical subject material.
    pub subject_digest: String,
    /// Current durable lifecycle state.
    pub status: ApprovalStatus,
    /// Authenticated owner decision when resolved explicitly.
    pub decision: Option<ApprovalDecision>,
    /// Time at which the approval request was created.
    pub requested_at: SystemTime,
    /// Decision, expiry, or revocation time when terminal.
    pub resolved_at: Option<SystemTime>,
}

/// Durable current-state projection for one governed effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectLedgerView {
    /// Stable effect identity.
    pub effect_id: EffectId,
    /// Owning task.
    pub task_id: TaskId,
    /// Agent run that proposed the effect.
    pub run_id: RunId,
    /// Current effect lifecycle state.
    pub status: EffectStatus,
    /// Monotonic optimistic-concurrency revision.
    pub revision: u64,
    /// Exact deterministic policy input.
    pub policy_request: PolicyRequest,
    /// Exact deterministic policy result and obligations.
    pub policy_evaluation: PolicyEvaluation,
    /// Stable downstream key for keyed operations.
    pub idempotency_key: Option<String>,
    /// Pending or resolved approval, if policy required one.
    pub approval: Option<ApprovalRequestView>,
    /// Creation time of the immutable intent.
    pub created_at: SystemTime,
    /// Time of the latest accepted lifecycle transition.
    pub updated_at: SystemTime,
}

/// Durable state of one concrete external dispatch attempt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectAttemptState {
    /// Exact authorization, input, key, and worker fence are durable; dispatch has not begun.
    Prepared,
    /// The external dispatch boundary may have been crossed.
    Running,
    /// The external service confirmed success.
    Succeeded,
    /// The external service confirmed failure.
    Failed,
    /// The external outcome could not be proven.
    OutcomeUnknown,
    /// The external outcome is unproven, but the immutable contract permits a new bounded retry.
    InterruptedRetryable,
    /// The worker lease ended before dispatch, so no external outcome exists and a new preparation
    /// may be created safely.
    InterruptedUndispatched,
}

/// Initial or reconciled outcome recorded for an effect attempt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectOutcomeKind {
    /// External success was established.
    Succeeded,
    /// External failure was established.
    Failed,
    /// Dispatch happened but its external outcome remains ambiguous.
    OutcomeUnknown,
    /// A separately authorized compensation was established.
    Compensated,
}

/// Allowed terminal result from the worker that performed a dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectAttemptOutcome {
    /// The dispatch completed successfully.
    Succeeded,
    /// The dispatch completed with a confirmed failure.
    Failed,
    /// The dispatch result cannot be established safely.
    OutcomeUnknown,
}

impl EffectAttemptOutcome {
    /// Returns the durable outcome spelling shared by state, evidence, and journal records.
    #[must_use]
    pub const fn kind(self) -> EffectOutcomeKind {
        match self {
            Self::Succeeded => EffectOutcomeKind::Succeeded,
            Self::Failed => EffectOutcomeKind::Failed,
            Self::OutcomeUnknown => EffectOutcomeKind::OutcomeUnknown,
        }
    }
}

/// Explicit resolution accepted for an attempt whose original outcome was unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectReconciliationOutcome {
    /// External evidence established that the original dispatch succeeded.
    Succeeded,
    /// External evidence established that the original dispatch failed.
    Failed,
}

impl EffectReconciliationOutcome {
    /// Returns the durable outcome spelling shared by evidence and lifecycle projections.
    #[must_use]
    pub const fn kind(self) -> EffectOutcomeKind {
        match self {
            Self::Succeeded => EffectOutcomeKind::Succeeded,
            Self::Failed => EffectOutcomeKind::Failed,
        }
    }
}

/// Immutable canonical evidence for one initial result or later reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectOutcomeView {
    /// Sequence zero is the worker result; positive sequences are explicit reconciliations.
    pub sequence: u64,
    /// Established external outcome.
    pub kind: EffectOutcomeKind,
    /// Complete versioned canonical evidence envelope.
    pub evidence: Value,
    /// SHA-256 digest of the serialized canonical envelope.
    pub evidence_digest: String,
    /// Journal event that committed the evidence.
    pub event_id: EventId,
    /// Time at which Mealy accepted the evidence.
    pub recorded_at: SystemTime,
}

/// Durable projection of one effect execution attempt and all accepted outcome evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectAttemptView {
    /// Concrete attempt identifier.
    pub attempt_id: AttemptId,
    /// Effect whose exact immutable intent is being executed.
    pub effect_id: EffectId,
    /// One-based ordinal within the effect.
    pub ordinal: u64,
    /// Current durable dispatch boundary.
    pub state: EffectAttemptState,
    /// Stable downstream key for keyed operations.
    pub idempotency_key: Option<String>,
    /// Exact lease fence authorized to perform and settle the attempt.
    pub fence: LeaseFence,
    /// Journal event that made the preparation durable.
    pub prepared_event_id: EventId,
    /// Journal event that crossed the dispatch boundary, when present.
    pub started_event_id: Option<EventId>,
    /// Journal event for the initial terminal/unknown result, when present.
    pub terminal_event_id: Option<EventId>,
    /// Preparation time.
    pub prepared_at: SystemTime,
    /// Dispatch-boundary time, when crossed.
    pub started_at: Option<SystemTime>,
    /// Initial result time, when recorded.
    pub completed_at: Option<SystemTime>,
    /// Bounded stable failure classification for failed or unknown results.
    pub error_class: Option<String>,
    /// Initial outcome followed by any explicit reconciliation evidence.
    pub outcomes: Vec<EffectOutcomeView>,
}

/// Fenced transaction that durably prepares an exact authorized effect before dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareEffectAttemptCommit {
    /// Effect whose immutable intent is being prepared.
    pub effect_id: EffectId,
    /// Stable identity reserved for this attempt.
    pub attempt_id: AttemptId,
    /// Effect revision that must still be current.
    pub expected_effect_revision: u64,
    /// Exact active worker lease and fencing token.
    pub fence: LeaseFence,
    /// Journal event for `effect.attempt_prepared`.
    pub event_id: EventId,
    /// Correlates preparation with its run and later transitions.
    pub correlation_id: CorrelationId,
    /// Time assigned at the application transaction boundary.
    pub prepared_at: SystemTime,
}

/// Fenced transaction that records crossing the external dispatch boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarkEffectAttemptRunningCommit {
    /// Effect being dispatched.
    pub effect_id: EffectId,
    /// Exact prepared attempt being dispatched.
    pub attempt_id: AttemptId,
    /// Effect revision that must still be current.
    pub expected_effect_revision: u64,
    /// Exact active fence captured during preparation.
    pub fence: LeaseFence,
    /// Journal event for `effect.dispatched`.
    pub event_id: EventId,
    /// Correlates dispatch with its preparation and result.
    pub correlation_id: CorrelationId,
    /// Time immediately before invoking the external adapter.
    pub dispatched_at: SystemTime,
}

/// Fenced transaction that records the first established result of a running attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordEffectAttemptOutcomeCommit {
    /// Effect whose result is being recorded.
    pub effect_id: EffectId,
    /// Exact running attempt that produced the result.
    pub attempt_id: AttemptId,
    /// Effect revision that must still be current.
    pub expected_effect_revision: u64,
    /// Exact active fence captured during preparation.
    pub fence: LeaseFence,
    /// Established initial result.
    pub outcome: EffectAttemptOutcome,
    /// Non-empty structured external receipt, diagnostic, or ambiguity evidence.
    pub evidence_details: Value,
    /// Required for failed/unknown outcomes and forbidden for success.
    pub error_class: Option<String>,
    /// Journal event for the exact result.
    pub event_id: EventId,
    /// Correlates the result with preparation and dispatch.
    pub correlation_id: CorrelationId,
    /// Time at which the evidence was accepted.
    pub completed_at: SystemTime,
}

/// System recovery transaction for a running effect whose original worker lease is inactive.
///
/// This command records ambiguity only. It neither acquires a lease nor authorizes, invokes, or
/// retries an external adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverInterruptedEffectCommit {
    /// Effect left at the durable dispatch boundary.
    pub effect_id: EffectId,
    /// Exact running attempt bound to the now-inactive original lease.
    pub attempt_id: AttemptId,
    /// Effect revision that must still be current.
    pub expected_effect_revision: u64,
    /// Stable journal event reserved for the recovery fact and idempotent command retry.
    pub event_id: EventId,
    /// Correlates startup recovery with the interrupted run.
    pub correlation_id: CorrelationId,
    /// Time at which the inactive-lease evidence was observed.
    pub recovered_at: SystemTime,
}

/// Authenticated transaction that explicitly resolves a previously unknown outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconcileEffectOutcomeCommit {
    /// Effect whose unknown outcome is being resolved.
    pub effect_id: EffectId,
    /// Original attempt whose result was ambiguous.
    pub attempt_id: AttemptId,
    /// Authenticated owner and verified channel binding.
    pub ownership: OwnershipContext,
    /// Effect revision that must still be current.
    pub expected_effect_revision: u64,
    /// Established result of reconciliation.
    pub outcome: EffectReconciliationOutcome,
    /// Non-empty structured evidence establishing the result.
    pub evidence_details: Value,
    /// Stable authenticated command-delivery key.
    pub idempotency_key: String,
    /// Journal event for `effect.reconciled`.
    pub event_id: EventId,
    /// Correlates operator/reconciler evidence with the original attempt.
    pub correlation_id: CorrelationId,
    /// Time at which reconciliation evidence was accepted.
    pub reconciled_at: SystemTime,
}

/// Immutable receipt for a new or exact duplicate effect-reconciliation command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectReconciliationReceipt {
    /// Effect reconciled by the original command.
    pub effect_id: EffectId,
    /// Attempt whose ambiguous outcome was resolved.
    pub attempt_id: AttemptId,
    /// Reconciliation result bound to the idempotency key.
    pub outcome: EffectReconciliationOutcome,
    /// Effect revision committed by the original command.
    pub effect_revision: u64,
    /// Original `effect.reconciled` journal event.
    pub event_id: EventId,
    /// Timeline cursor assigned to the original event.
    pub cursor: u64,
    /// Whether this invocation matched an already committed request.
    pub duplicate: bool,
}

/// Durable effect-attempt boundary visible to startup recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectAttemptBoundary {
    /// Intent and authorization are durable; the external dispatch boundary was not crossed.
    Prepared,
    /// Dispatch may have crossed the external boundary and no terminal outcome is durable.
    Running,
    /// Dispatch crossed the boundary and its external outcome is explicitly ambiguous.
    OutcomeUnknown,
}

/// Fail-closed recovery classification for an interrupted effect attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectRecoveryDisposition {
    /// Resume the already-authorized preparation; no external mutation could have occurred.
    ResumePrepared,
    /// A bounded retry is mechanically safe by contract.
    Retry,
    /// A bounded retry is safe only with the persisted downstream key.
    RetryWithSameKey,
    /// External evidence must establish the outcome before any further dispatch.
    RequiresReconciliation,
    /// A declared compensating operation, separately authorized, is required.
    RequiresCompensation,
    /// The descriptor forbids automatic retry after the interrupted boundary.
    TerminallyFailed,
}

/// One deterministically ordered startup-recovery candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectRecoveryCandidate {
    /// Effect requiring classification.
    pub effect_id: EffectId,
    /// Concrete bounded dispatch attempt.
    pub attempt_id: AttemptId,
    /// Persisted attempt ordinal within the effect.
    pub ordinal: u64,
    /// Last durable dispatch boundary.
    pub boundary: EffectAttemptBoundary,
    /// Declared downstream repetition behavior.
    pub idempotency: IdempotencyClass,
    /// Declared interrupted-dispatch strategy.
    pub recovery: RecoveryStrategy,
    /// Stable downstream key, when required.
    pub idempotency_key: Option<String>,
    /// Mechanically safe next action. This is evidence, not a dispatch command.
    pub disposition: EffectRecoveryDisposition,
}

/// Persistence failures at the effect/approval application boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EffectLedgerStoreError {
    /// No authorized effect or approval exists for the supplied identity.
    #[error("effect or approval was not found")]
    NotFound,
    /// The approval subject digest returned by the command no longer matches.
    #[error("approval subject does not match the current durable request")]
    SubjectMismatch,
    /// An approval decision arrived at or after the subject's exclusive expiry.
    #[error("approval request has expired")]
    ApprovalExpired,
    /// A maintenance pass attempted to expire a subject before its exclusive expiry.
    #[error("approval request has not reached its expiry")]
    ExpiryNotReached,
    /// A concurrent transition, duplicate identifier, or stale request rejected the commit.
    #[error("effect ledger commit conflicted with current state")]
    Conflict,
    /// Proposed evidence is malformed, inconsistent, or fails closed.
    #[error("effect ledger evidence is invalid: {0}")]
    InvalidEvidence(String),
    /// Persistence could not complete the operation.
    #[error("effect ledger store is unavailable: {0}")]
    Unavailable(String),
    /// Stored canonical state and evidence disagree.
    #[error("effect ledger invariant violation: {0}")]
    InvariantViolation(String),
}

/// Invalid canonical material supplied for an authenticated effect command.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EffectCommandRequestError {
    /// The delivery key must be non-empty and remain within the durable storage bound.
    #[error(
        "effect command idempotency key must contain between 1 and {MAXIMUM_EFFECT_COMMAND_IDEMPOTENCY_KEY_BYTES} UTF-8 bytes"
    )]
    InvalidIdempotencyKey,
    /// Approval commands must bind the exact canonical SHA-256 subject digest.
    #[error("approval subject digest must be a lowercase SHA-256 digest")]
    InvalidSubjectDigest,
    /// Reconciliation details must be a non-empty JSON object.
    #[error("effect reconciliation evidence details must be a non-empty JSON object")]
    InvalidEvidenceDetails,
    /// Reconciliation details exceeded the shared bounded outcome-evidence contract.
    #[error(
        "effect reconciliation evidence details exceed {MAXIMUM_EFFECT_OUTCOME_DETAILS_BYTES} bytes"
    )]
    EvidenceDetailsTooLarge,
}

/// Invalid structured outcome evidence supplied at an application boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EffectOutcomeEvidenceError {
    /// Evidence details must be a non-empty JSON object.
    #[error("effect outcome evidence details must be a non-empty JSON object")]
    InvalidDetails,
    /// The canonical JSON representation exceeds the bounded evidence contract.
    #[error("effect outcome evidence details exceed {MAXIMUM_EFFECT_OUTCOME_DETAILS_BYTES} bytes")]
    DetailsTooLarge,
    /// The recorded timestamp cannot be represented by the durable contract.
    #[error("effect outcome evidence timestamp must be nonnegative")]
    InvalidTimestamp,
    /// A supplied error class is empty or exceeds the durable bound.
    #[error("effect outcome error class must contain between 1 and 128 UTF-8 bytes")]
    InvalidErrorClass,
}

/// Durable effect intent, approval, and recovery-evidence port.
pub trait EffectLedgerStore {
    /// Atomically persists exact intent, policy evidence, lifecycle state, journal facts, and any
    /// bound approval request.
    ///
    /// # Errors
    ///
    /// Returns [`EffectLedgerStoreError`] for invalid evidence, authorization failure, conflict,
    /// corruption, or dependency failure.
    fn record_effect_proposal(
        &mut self,
        commit: RecordEffectProposalCommit,
    ) -> Result<EffectLedgerView, EffectLedgerStoreError>;

    /// Loads one effect only through its authenticated owner/channel scope.
    ///
    /// # Errors
    ///
    /// Returns [`EffectLedgerStoreError`] for missing/unauthorized state, corruption, or a
    /// dependency failure.
    fn effect_ledger_view(
        &self,
        ownership: OwnershipContext,
        effect_id: EffectId,
    ) -> Result<EffectLedgerView, EffectLedgerStoreError>;

    /// Returns pending approval requests in deterministic request-time/ID order.
    ///
    /// # Errors
    ///
    /// Returns [`EffectLedgerStoreError`] for corrupt state or a dependency failure.
    fn pending_approval_requests(
        &self,
        ownership: OwnershipContext,
    ) -> Result<Vec<ApprovalRequestView>, EffectLedgerStoreError>;

    /// Atomically records an authenticated decision and the resulting effect transition. An exact
    /// owner/channel/key replay returns the original immutable revision, events, and cursor even
    /// after the effect advances further.
    ///
    /// # Errors
    ///
    /// Returns [`EffectLedgerStoreError`] when the subject changed, expired, was already resolved,
    /// a key is reused for different semantic request material, the command is unauthorized, or
    /// persistence fails.
    fn resolve_approval(
        &mut self,
        commit: ResolveApprovalCommit,
    ) -> Result<ApprovalResolutionReceipt, EffectLedgerStoreError>;

    /// Atomically records expiry of a still-pending approval and denies its effect.
    ///
    /// # Errors
    ///
    /// Returns [`EffectLedgerStoreError`] when expiry is premature, state changed concurrently, or
    /// persistence fails.
    fn expire_approval(
        &mut self,
        commit: ExpireApprovalCommit,
    ) -> Result<EffectLedgerView, EffectLedgerStoreError>;

    /// Atomically persists authorization, stable idempotency key, active fence, attempt row,
    /// effect revision, and the preparation journal/timeline fact before external dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`EffectLedgerStoreError`] when the effect is not exactly authorized, its revision
    /// or fence is stale, another attempt is unsettled, evidence is invalid, or persistence fails.
    fn prepare_effect_attempt(
        &mut self,
        commit: PrepareEffectAttemptCommit,
    ) -> Result<EffectAttemptView, EffectLedgerStoreError>;

    /// Atomically marks one exact prepared attempt and its effect as crossing dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`EffectLedgerStoreError`] when preparation is absent, state/revision/fence is
    /// stale, the dispatch time is outside the active lease, or persistence fails.
    fn mark_effect_attempt_running(
        &mut self,
        commit: MarkEffectAttemptRunningCommit,
    ) -> Result<EffectAttemptView, EffectLedgerStoreError>;

    /// Atomically records the first terminal or ambiguous outcome of one running attempt.
    ///
    /// # Errors
    ///
    /// Returns [`EffectLedgerStoreError`] when state/revision/fence is stale, evidence is invalid,
    /// the worker lease expired, or persistence fails.
    fn record_effect_attempt_outcome(
        &mut self,
        commit: RecordEffectAttemptOutcomeCommit,
    ) -> Result<EffectAttemptView, EffectLedgerStoreError>;

    /// Atomically records `outcome_unknown` for an interrupted running attempt after proving its
    /// original lease is inactive and the persisted recovery contract does not permit a bounded
    /// automatic retry. An exact repeat of the same committed command returns the same view.
    /// This operation never dispatches external work.
    ///
    /// # Errors
    ///
    /// Returns [`EffectLedgerStoreError`] while the original lease remains active, before its
    /// inactive boundary, for safe-retry dispositions, stale state/revision, mismatched duplicate
    /// commands, corrupt evidence, or persistence failure.
    fn recover_interrupted_effect(
        &mut self,
        commit: RecoverInterruptedEffectCommit,
    ) -> Result<EffectAttemptView, EffectLedgerStoreError>;

    /// Loads one attempt only through the authenticated ownership boundary of its effect.
    ///
    /// # Errors
    ///
    /// Returns [`EffectLedgerStoreError`] for missing/unauthorized state, corruption, or a
    /// dependency failure.
    fn effect_attempt_view(
        &self,
        ownership: OwnershipContext,
        attempt_id: AttemptId,
    ) -> Result<EffectAttemptView, EffectLedgerStoreError>;

    /// Loads every attempt for one owned effect in ascending ordinal order.
    ///
    /// # Errors
    ///
    /// Returns [`EffectLedgerStoreError`] for missing/unauthorized state, corrupt ordering or
    /// evidence, or a dependency failure.
    fn effect_attempt_views(
        &self,
        ownership: OwnershipContext,
        effect_id: EffectId,
    ) -> Result<Vec<EffectAttemptView>, EffectLedgerStoreError>;

    /// Atomically and explicitly resolves an `outcome_unknown` attempt from authenticated,
    /// canonical external evidence. An exact owner/channel/key replay returns the original
    /// immutable revision, event, and cursor. This method never dispatches or creates another
    /// attempt.
    ///
    /// # Errors
    ///
    /// Returns [`EffectLedgerStoreError`] when ownership, state, revision, or evidence is invalid,
    /// a key is reused for different semantic request material, reconciliation was already
    /// recorded, or persistence fails.
    fn reconcile_effect_outcome(
        &mut self,
        commit: ReconcileEffectOutcomeCommit,
    ) -> Result<EffectReconciliationReceipt, EffectLedgerStoreError>;

    /// Classifies every interrupted effect attempt without mutating or dispatching anything.
    ///
    /// # Errors
    ///
    /// Returns [`EffectLedgerStoreError`] when stored recovery evidence is corrupt or unavailable.
    fn interrupted_effect_recovery_candidates(
        &self,
    ) -> Result<Vec<EffectRecoveryCandidate>, EffectLedgerStoreError>;
}

/// Builds the exact versioned semantic request bound to an approval idempotency key.
///
/// Delivery metadata such as event IDs, correlation IDs, and timestamps is intentionally excluded
/// so a transport retry can reserve fresh delivery metadata while still retrieving the original
/// immutable receipt.
///
/// # Errors
///
/// Returns [`EffectCommandRequestError`] for an invalid key or subject digest.
pub fn approval_resolution_request_material(
    commit: &ResolveApprovalCommit,
) -> Result<Value, EffectCommandRequestError> {
    validate_effect_command_idempotency_key(&commit.idempotency_key)?;
    if !is_sha256_digest(&commit.expected_subject_digest) {
        return Err(EffectCommandRequestError::InvalidSubjectDigest);
    }
    Ok(serde_json::json!({
        "approvalId": commit.approval_id,
        "channelBindingId": commit.ownership.channel_binding_id(),
        "contractVersion": APPROVAL_RESOLUTION_REQUEST_CONTRACT_VERSION,
        "decision": approval_decision_name(commit.decision),
        "expectedSubjectDigest": commit.expected_subject_digest,
        "idempotencyKey": commit.idempotency_key,
        "principalId": commit.ownership.principal_id(),
    }))
}

/// Computes the SHA-256 digest of [`approval_resolution_request_material`].
///
/// # Errors
///
/// Returns [`EffectCommandRequestError`] under the same conditions as the material builder.
pub fn approval_resolution_request_digest(
    commit: &ResolveApprovalCommit,
) -> Result<String, EffectCommandRequestError> {
    Ok(sha256_digest(
        approval_resolution_request_material(commit)?
            .to_string()
            .as_bytes(),
    ))
}

/// Builds the exact versioned semantic request bound to a reconciliation idempotency key.
///
/// Delivery metadata such as event IDs, correlation IDs, and timestamps is intentionally excluded
/// so a transport retry can reserve fresh delivery metadata while still retrieving the original
/// immutable receipt.
///
/// # Errors
///
/// Returns [`EffectCommandRequestError`] for an invalid key or malformed/oversized evidence.
pub fn effect_reconciliation_request_material(
    commit: &ReconcileEffectOutcomeCommit,
) -> Result<Value, EffectCommandRequestError> {
    validate_effect_command_idempotency_key(&commit.idempotency_key)?;
    let Some(details) = commit.evidence_details.as_object() else {
        return Err(EffectCommandRequestError::InvalidEvidenceDetails);
    };
    if details.is_empty() {
        return Err(EffectCommandRequestError::InvalidEvidenceDetails);
    }
    if serde_json::to_vec(&commit.evidence_details).map_or(true, |encoded| {
        encoded.len() > MAXIMUM_EFFECT_OUTCOME_DETAILS_BYTES
    }) {
        return Err(EffectCommandRequestError::EvidenceDetailsTooLarge);
    }
    Ok(serde_json::json!({
        "attemptId": commit.attempt_id,
        "channelBindingId": commit.ownership.channel_binding_id(),
        "contractVersion": EFFECT_RECONCILIATION_REQUEST_CONTRACT_VERSION,
        "effectId": commit.effect_id,
        "evidenceDetails": commit.evidence_details,
        "expectedEffectRevision": commit.expected_effect_revision,
        "idempotencyKey": commit.idempotency_key,
        "outcome": effect_reconciliation_outcome_name(commit.outcome),
        "principalId": commit.ownership.principal_id(),
    }))
}

/// Computes the SHA-256 digest of [`effect_reconciliation_request_material`].
///
/// # Errors
///
/// Returns [`EffectCommandRequestError`] under the same conditions as the material builder.
pub fn effect_reconciliation_request_digest(
    commit: &ReconcileEffectOutcomeCommit,
) -> Result<String, EffectCommandRequestError> {
    Ok(sha256_digest(
        effect_reconciliation_request_material(commit)?
            .to_string()
            .as_bytes(),
    ))
}

fn validate_effect_command_idempotency_key(
    idempotency_key: &str,
) -> Result<(), EffectCommandRequestError> {
    if idempotency_key.is_empty()
        || idempotency_key.len() > MAXIMUM_EFFECT_COMMAND_IDEMPOTENCY_KEY_BYTES
    {
        return Err(EffectCommandRequestError::InvalidIdempotencyKey);
    }
    Ok(())
}

const fn approval_decision_name(decision: ApprovalDecision) -> &'static str {
    match decision {
        ApprovalDecision::Approve => "approve",
        ApprovalDecision::Deny => "deny",
    }
}

const fn effect_reconciliation_outcome_name(outcome: EffectReconciliationOutcome) -> &'static str {
    match outcome {
        EffectReconciliationOutcome::Succeeded => "succeeded",
        EffectReconciliationOutcome::Failed => "failed",
    }
}

/// Builds the exact versioned JSON material whose bytes are digested for one outcome record.
///
/// Object keys are emitted by `serde_json` in canonical lexical order under the workspace's
/// default map representation. Identity, sequence, outcome, time, and bounded details are all
/// included, so none can be substituted independently of the stored digest.
///
/// # Errors
///
/// Returns [`EffectOutcomeEvidenceError`] for empty/non-object details, oversized evidence,
/// negative timestamps, or malformed error classifications.
pub fn effect_outcome_evidence_material(
    effect_id: EffectId,
    attempt_id: AttemptId,
    sequence: u64,
    kind: EffectOutcomeKind,
    details: &Value,
    error_class: Option<&str>,
    recorded_at_ms: i64,
) -> Result<Value, EffectOutcomeEvidenceError> {
    if recorded_at_ms < 0 {
        return Err(EffectOutcomeEvidenceError::InvalidTimestamp);
    }
    let Some(details_object) = details.as_object() else {
        return Err(EffectOutcomeEvidenceError::InvalidDetails);
    };
    if details_object.is_empty() {
        return Err(EffectOutcomeEvidenceError::InvalidDetails);
    }
    if serde_json::to_vec(details).map_or(true, |encoded| {
        encoded.len() > MAXIMUM_EFFECT_OUTCOME_DETAILS_BYTES
    }) {
        return Err(EffectOutcomeEvidenceError::DetailsTooLarge);
    }
    if error_class.is_some_and(|value| value.is_empty() || value.len() > 128) {
        return Err(EffectOutcomeEvidenceError::InvalidErrorClass);
    }
    Ok(serde_json::json!({
        "attemptId": attempt_id,
        "contractVersion": EFFECT_OUTCOME_EVIDENCE_CONTRACT_VERSION,
        "effectId": effect_id,
        "errorClass": error_class,
        "evidence": details,
        "outcomeKind": kind,
        "recordedAtMs": recorded_at_ms,
        "sequence": sequence,
    }))
}

/// Computes the SHA-256 digest of [`effect_outcome_evidence_material`].
///
/// # Errors
///
/// Returns [`EffectOutcomeEvidenceError`] under the same conditions as the material builder.
pub fn effect_outcome_evidence_digest(
    effect_id: EffectId,
    attempt_id: AttemptId,
    sequence: u64,
    kind: EffectOutcomeKind,
    details: &Value,
    error_class: Option<&str>,
    recorded_at_ms: i64,
) -> Result<String, EffectOutcomeEvidenceError> {
    Ok(sha256_digest(
        effect_outcome_evidence_material(
            effect_id,
            attempt_id,
            sequence,
            kind,
            details,
            error_class,
            recorded_at_ms,
        )?
        .to_string()
        .as_bytes(),
    ))
}

/// Returns canonical versioned material for an exact durable effect intent.
///
/// # Errors
///
/// Returns [`PolicyRequestError`] when the policy request or tool evidence is malformed.
pub fn effect_intent_material(
    effect_id: EffectId,
    request: &PolicyRequest,
) -> Result<serde_json::Value, PolicyRequestError> {
    request.validate()?;
    Ok(serde_json::json!({
        "contractVersion": EFFECT_INTENT_CONTRACT_VERSION,
        "effectId": effect_id,
        "principalId": request.principal_id,
        "channelBindingId": request.channel_binding_id,
        "taskId": request.task_id,
        "runId": request.run_id,
        "toolDescriptorDigest": request.tool.descriptor_digest,
        "toolId": request.tool.tool_id,
        "toolVersion": request.tool.version,
        "canonicalArgumentsDigest": canonical_arguments_digest(&request.normalized_arguments),
        "capabilityScope": request.requested_capability,
        "targetResources": request.target_resources,
        "executableIdentityDigest": request.tool.executable_identity_digest,
        "effectClass": request.tool.effect_class,
        "riskClass": request.tool.risk_class,
        "idempotency": request.tool.idempotency,
        "recovery": request.tool.recovery,
        "executor": request.tool.executor,
        "policyVersion": request.policy_version,
    }))
}

/// Computes the SHA-256 digest of [`effect_intent_material`].
///
/// # Errors
///
/// Returns [`PolicyRequestError`] when the policy request or tool evidence is malformed.
pub fn effect_intent_digest(
    effect_id: EffectId,
    request: &PolicyRequest,
) -> Result<String, PolicyRequestError> {
    Ok(sha256_digest(
        effect_intent_material(effect_id, request)?
            .to_string()
            .as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        EffectCommandRequestError, EffectOutcomeEvidenceError, EffectOutcomeKind,
        EffectReconciliationOutcome, ReconcileEffectOutcomeCommit, ResolveApprovalCommit,
        approval_resolution_request_digest, effect_outcome_evidence_digest,
        effect_outcome_evidence_material, effect_reconciliation_request_digest,
    };
    use crate::OwnershipContext;
    use mealy_domain::{
        ApprovalDecision, ApprovalId, AttemptId, ChannelBindingId, CorrelationId, EffectId,
        EventId, PrincipalId,
    };
    use std::time::SystemTime;

    #[test]
    fn outcome_evidence_digest_binds_identity_sequence_kind_time_and_details() {
        let effect_id = EffectId::new();
        let attempt_id = AttemptId::new();
        let details = serde_json::json!({"receipt": "service-123", "version": 7});
        let digest = effect_outcome_evidence_digest(
            effect_id,
            attempt_id,
            0,
            EffectOutcomeKind::Succeeded,
            &details,
            None,
            42,
        )
        .expect("digest canonical outcome evidence");
        assert_eq!(
            digest,
            effect_outcome_evidence_digest(
                effect_id,
                attempt_id,
                0,
                EffectOutcomeKind::Succeeded,
                &details,
                None,
                42,
            )
            .expect("repeat canonical digest")
        );
        assert_ne!(
            digest,
            effect_outcome_evidence_digest(
                effect_id,
                attempt_id,
                1,
                EffectOutcomeKind::Succeeded,
                &details,
                None,
                42,
            )
            .expect("digest changed sequence")
        );
        assert_ne!(
            digest,
            effect_outcome_evidence_digest(
                effect_id,
                attempt_id,
                0,
                EffectOutcomeKind::Failed,
                &details,
                Some("rejected"),
                42,
            )
            .expect("digest changed outcome")
        );
    }

    #[test]
    fn outcome_evidence_rejects_empty_scalar_and_oversized_details() {
        let effect_id = EffectId::new();
        let attempt_id = AttemptId::new();
        for invalid in [serde_json::Value::Null, serde_json::json!({})] {
            assert_eq!(
                effect_outcome_evidence_material(
                    effect_id,
                    attempt_id,
                    0,
                    EffectOutcomeKind::Succeeded,
                    &invalid,
                    None,
                    42,
                ),
                Err(EffectOutcomeEvidenceError::InvalidDetails)
            );
        }
        assert_eq!(
            effect_outcome_evidence_material(
                effect_id,
                attempt_id,
                0,
                EffectOutcomeKind::Succeeded,
                &serde_json::json!({"payload": "x".repeat(33 * 1_024)}),
                None,
                42,
            ),
            Err(EffectOutcomeEvidenceError::DetailsTooLarge)
        );
    }

    #[test]
    fn approval_request_digest_binds_semantics_but_not_retry_delivery_metadata() {
        let commit = ResolveApprovalCommit {
            approval_id: ApprovalId::new(),
            ownership: OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new()),
            expected_subject_digest: crate::sha256_digest(b"approval subject"),
            decision: ApprovalDecision::Approve,
            idempotency_key: "approval-command-1".to_owned(),
            approval_event_id: EventId::new(),
            effect_event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            decided_at: SystemTime::UNIX_EPOCH,
        };
        let digest = approval_resolution_request_digest(&commit).expect("digest approval request");
        let retry = ResolveApprovalCommit {
            approval_event_id: EventId::new(),
            effect_event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            decided_at: SystemTime::now(),
            ..commit.clone()
        };
        assert_eq!(
            digest,
            approval_resolution_request_digest(&retry).expect("digest retry request")
        );
        assert_ne!(
            digest,
            approval_resolution_request_digest(&ResolveApprovalCommit {
                decision: ApprovalDecision::Deny,
                ..commit
            })
            .expect("digest changed decision")
        );
    }

    #[test]
    fn effect_command_requests_enforce_key_and_reconciliation_evidence_bounds() {
        let commit = ReconcileEffectOutcomeCommit {
            effect_id: EffectId::new(),
            attempt_id: AttemptId::new(),
            ownership: OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new()),
            expected_effect_revision: 4,
            outcome: EffectReconciliationOutcome::Succeeded,
            evidence_details: serde_json::json!({"receipt": "external-1"}),
            idempotency_key: "reconciliation-command-1".to_owned(),
            event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            reconciled_at: SystemTime::UNIX_EPOCH,
        };
        let digest =
            effect_reconciliation_request_digest(&commit).expect("digest reconciliation request");
        assert_ne!(
            digest,
            effect_reconciliation_request_digest(&ReconcileEffectOutcomeCommit {
                expected_effect_revision: 5,
                ..commit.clone()
            })
            .expect("digest changed revision")
        );
        assert_eq!(
            effect_reconciliation_request_digest(&ReconcileEffectOutcomeCommit {
                idempotency_key: String::new(),
                ..commit.clone()
            }),
            Err(EffectCommandRequestError::InvalidIdempotencyKey)
        );
        assert_eq!(
            effect_reconciliation_request_digest(&ReconcileEffectOutcomeCommit {
                evidence_details: serde_json::json!({}),
                ..commit
            }),
            Err(EffectCommandRequestError::InvalidEvidenceDetails)
        );
    }
}
