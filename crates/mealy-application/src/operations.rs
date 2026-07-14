use crate::OwnershipContext;
use mealy_domain::{CorrelationId, PrincipalId};
use std::{collections::BTreeMap, time::SystemTime};
use thiserror::Error;

/// Durable terminal classification of one daemon process lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonRunStatus {
    /// Process is serving or draining.
    Running,
    /// Bounded drain and checkpoint completed.
    Clean,
    /// Drain deadline or second signal forced termination.
    Forced,
    /// A later start observed that the process vanished without a terminal record.
    Unclean,
}

/// Records one recovered daemon start before readiness is published.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeginDaemonRunCommit {
    /// Stable process-lifetime identity.
    pub start_id: CorrelationId,
    /// Local owner principal.
    pub principal_id: PrincipalId,
    /// Digest of schema-validated non-secret effective configuration.
    pub config_digest: String,
    /// Digest of the compiled security-relevant policy bundle.
    pub policy_bundle_digest: String,
    /// Whether mutation and background dispatch are disabled.
    pub safe_mode: bool,
    /// Startup recovery classifications.
    pub recovery_counts: BTreeMap<String, u64>,
    /// Time bootstrap began.
    pub started_at: SystemTime,
    /// Time recovery completed and readiness may be published.
    pub ready_at: SystemTime,
}

/// Commits a bounded drain result for the current process lifetime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteDaemonRunCommit {
    /// Exact process-lifetime identity.
    pub start_id: CorrelationId,
    /// Clean or forced terminal classification.
    pub status: DaemonRunStatus,
    /// Bounded operator-safe reason.
    pub reason: String,
    /// Completion observation time.
    pub completed_at: SystemTime,
}

/// Owner-authorized operational health and queue snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalSnapshot {
    /// Latest daemon lifetime identity.
    pub start_id: CorrelationId,
    /// Latest daemon lifecycle status.
    pub run_status: DaemonRunStatus,
    /// Whether current process is intentionally query-only.
    pub safe_mode: bool,
    /// Effective non-secret configuration digest.
    pub config_digest: String,
    /// Effective security policy bundle digest.
    pub policy_bundle_digest: String,
    /// Current schema revision.
    pub schema_version: u64,
    /// Pending session inbox rows.
    pub pending_inputs: u64,
    /// Queued or running agent runs.
    pub nonterminal_runs: u64,
    /// Active fenced work leases.
    pub active_leases: u64,
    /// Pending exact approval subjects.
    pub pending_approvals: u64,
    /// Effects requiring explicit reconciliation.
    pub unknown_effects: u64,
    /// Pending or currently claimed outbox records.
    pub pending_outbox: u64,
    /// Terminally failed outbox records.
    pub failed_outbox: u64,
    /// Enabled extensions.
    pub enabled_extensions: u64,
    /// Failed extensions awaiting owner action.
    pub failed_extensions: u64,
    /// Active signed external channel bindings.
    pub active_channels: u64,
    /// Active external channels with consecutive durable transport failures.
    pub degraded_channels: u64,
    /// Reserved Telegram updates or Discord messages awaiting terminal evidence.
    pub reserved_channel_updates: u64,
    /// Active recurring agent schedules.
    pub active_schedules: u64,
    /// Paused recurring agent schedules retained for owner inspection.
    pub paused_schedules: u64,
    /// Schedule occurrences currently held by an unexpired daemon claim.
    pub claimed_schedule_runs: u64,
    /// Terminally failed schedule occurrence admissions retained in history.
    pub failed_schedule_runs: u64,
    /// Policy-skipped schedule occurrences retained in history.
    pub skipped_schedule_runs: u64,
    /// Ten newest durable failure/unknown event types and aggregate IDs.
    pub recent_failures: Vec<OperationalFailure>,
    /// UTC start time.
    pub started_at_ms: i64,
    /// UTC ready time.
    pub ready_at_ms: i64,
    /// UTC terminal time for a previous run.
    pub completed_at_ms: Option<i64>,
    /// Terminal reason for a previous run.
    pub completion_reason: Option<String>,
}

/// One bounded durable failure summary for owner health inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalFailure {
    /// Timeline cursor.
    pub cursor: u64,
    /// Stable event type.
    pub event_type: String,
    /// Aggregate category.
    pub aggregate_kind: String,
    /// Aggregate identity.
    pub aggregate_id: String,
    /// End-to-end correlation identity.
    pub correlation_id: String,
    /// UTC event time.
    pub occurred_at_ms: i64,
}

/// Durable aggregate of dispatched model attempts for one exact provider/model endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderEndpointHistory {
    /// Stable configured provider identity.
    pub provider_id: String,
    /// Exact configured model identity.
    pub model_id: String,
    /// Cumulative durably dispatched attempts across daemon lifetimes.
    pub invocation_count: u64,
    /// Most recent durably completed successful attempt.
    pub last_success_at_ms: Option<i64>,
    /// Most recent durably completed classified provider failure.
    pub last_failure_at_ms: Option<i64>,
}

/// One exact UTC-day aggregate of terminal run usage for an authenticated owner binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedUsageBucket {
    /// UTC day start in epoch milliseconds.
    pub bucket_start_ms: i64,
    /// UTC day end, clipped to the requested report bound.
    pub bucket_end_ms: i64,
    /// Terminal root, delegated, or validation runs settled in this bucket.
    pub completed_runs: u64,
    /// Runs whose canonical terminal state is succeeded.
    pub succeeded_runs: u64,
    /// Runs whose canonical terminal state is failed.
    pub failed_runs: u64,
    /// Runs whose canonical terminal state is cancelled.
    pub cancelled_runs: u64,
    /// Settled or conservatively charged provider calls.
    pub used_model_calls: u64,
    /// Settled read/effect tool calls.
    pub used_tool_calls: u64,
    /// Settled delegated child-run reservations.
    pub used_delegated_runs: u64,
    /// Classified provider/tool retries.
    pub used_retries: u64,
    /// Recorded provider input tokens.
    pub used_input_tokens: u64,
    /// Recorded provider output tokens.
    pub used_output_tokens: u64,
    /// Provider-neutral configured-price microunits.
    pub used_cost_microunits: u64,
    /// Recorded provider/tool output bytes.
    pub used_output_bytes: u64,
}

/// Bounded exact-owner terminal usage report grouped by UTC completion day.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedUsageReport {
    /// Inclusive requested lower epoch-millisecond bound.
    pub from_ms: i64,
    /// Exclusive requested upper epoch-millisecond bound.
    pub to_ms: i64,
    /// Ordered non-empty UTC-day buckets; empty days are omitted.
    pub buckets: Vec<CompletedUsageBucket>,
}

/// Persistence failures for daemon lifecycle and operational snapshots.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OperationalStoreError {
    /// Owner identity or start record is absent.
    #[error("operational state was not found")]
    NotFound,
    /// Lifecycle or immutable digest conflicts with canonical state.
    #[error("operational state conflicts with canonical state")]
    Conflict,
    /// Supplied lifecycle evidence violates its bounded contract.
    #[error("operational state contract is invalid: {0}")]
    InvalidContract(String),
    /// Persistence is temporarily unavailable.
    #[error("operational state is unavailable: {0}")]
    Unavailable(String),
    /// Stored canonical evidence violates an invariant.
    #[error("operational state invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port for process-lifetime evidence and owner operational inspection.
pub trait OperationalStore {
    /// Marks abandoned prior lifetimes unclean and records this recovered start.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalStoreError`] for invalid digests, times, or persistence failure.
    fn begin_daemon_run(
        &mut self,
        commit: BeginDaemonRunCommit,
    ) -> Result<(), OperationalStoreError>;

    /// Commits clean or forced terminal drain evidence.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalStoreError`] for stale lifecycle identity or persistence failure.
    fn complete_daemon_run(
        &mut self,
        commit: CompleteDaemonRunCommit,
    ) -> Result<(), OperationalStoreError>;

    /// Reads current operational health through an authenticated local owner binding.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalStoreError`] for authorization, persistence, or invariant failure.
    fn operational_snapshot(
        &self,
        ownership: OwnershipContext,
    ) -> Result<OperationalSnapshot, OperationalStoreError>;

    /// Reads cumulative durable dispatch history for exact configured endpoints.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalStoreError`] for malformed identities, authorization, or storage
    /// failure.
    fn provider_endpoint_history(
        &self,
        ownership: OwnershipContext,
        endpoints: &[(String, String)],
    ) -> Result<Vec<ProviderEndpointHistory>, OperationalStoreError>;

    /// Reads settled terminal-run usage over at most 31 days, grouped by UTC completion day.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalStoreError`] for an invalid range, malformed stored usage, owner
    /// mismatch, or storage failure.
    fn completed_usage_report(
        &self,
        ownership: OwnershipContext,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<CompletedUsageReport, OperationalStoreError>;

    /// Checkpoints WAL state after background workers stop.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalStoreError`] when `SQLite` cannot checkpoint safely.
    fn checkpoint_for_shutdown(&mut self) -> Result<(), OperationalStoreError>;
}
