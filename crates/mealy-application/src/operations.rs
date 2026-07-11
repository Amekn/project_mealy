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

    /// Checkpoints WAL state after background workers stop.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalStoreError`] when `SQLite` cannot checkpoint safely.
    fn checkpoint_for_shutdown(&mut self) -> Result<(), OperationalStoreError>;
}
