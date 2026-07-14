use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use croner::Cron;
use mealy_domain::{
    CorrelationId, EventId, InboxEntryId, ScheduleId, ScheduleRunId, SessionId, WorkerId,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use thiserror::Error;

use crate::OwnershipContext;

/// Maximum UTF-8 bytes in an owner-visible schedule name.
pub const MAXIMUM_SCHEDULE_NAME_BYTES: usize = 128;
/// Maximum UTF-8 bytes admitted as one scheduled agent input.
pub const MAXIMUM_SCHEDULE_PROMPT_BYTES: usize = 64 * 1024;
/// Maximum canonical cron expression bytes.
pub const MAXIMUM_CRON_EXPRESSION_BYTES: usize = 256;
/// Maximum IANA time-zone identity bytes.
pub const MAXIMUM_TIMEZONE_BYTES: usize = 128;
/// Maximum time after a due instant that `skip` may still fire it.
pub const MAXIMUM_MISFIRE_GRACE_MS: i64 = 24 * 60 * 60 * 1_000;
const MAXIMUM_OCCURRENCE_HORIZON_MS: i64 = 10 * 366 * 24 * 60 * 60 * 1_000;

/// Durable schedule lifecycle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleStatus {
    /// Due occurrences may be claimed.
    Active,
    /// The definition and history remain but no occurrence may be claimed.
    Paused,
    /// Terminally disabled while audit history remains.
    Cancelled,
}

/// Explicit behavior when the daemon was unavailable across one or more due instants.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissedRunPolicy {
    /// Fire the latest due occurrence only when it remains inside the grace window.
    Skip,
    /// Coalesce downtime and fire the latest due occurrence once after recovery.
    Latest,
}

/// Explicit behavior when an earlier occurrence from the same schedule is still active.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleOverlapPolicy {
    /// Admit the occurrence into the session's existing durable FIFO queue.
    Queue,
    /// Record the occurrence as skipped while earlier scheduled work remains non-terminal.
    SkipIfRunning,
}

/// Durable lifecycle of one schedule occurrence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleRunStatus {
    /// One daemon lifetime owns the bounded admission attempt.
    Claimed,
    /// The deterministic scheduled input was accepted or already present.
    Admitted,
    /// Explicit missed-run or overlap policy suppressed admission.
    Skipped,
    /// A terminal bounded admission failure was recorded.
    Failed,
}

/// Durable action selected before an occurrence claim is admitted or skipped.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleRunIntent {
    /// Admit the deterministic scheduled input.
    Fire,
    /// Advance because the latest due instant exceeded skip grace.
    SkipMisfire,
    /// Advance because an earlier occurrence remained active.
    SkipOverlap,
}

/// Owner-authorized canonical schedule projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduleView {
    /// Stable schedule identity.
    pub schedule_id: ScheduleId,
    /// Exact owner and channel binding.
    pub ownership: OwnershipContext,
    /// Existing durable session receiving each occurrence.
    pub session_id: SessionId,
    /// Bounded owner-visible label.
    pub name: String,
    /// Exact content admitted on each fired occurrence.
    pub prompt: String,
    /// Canonical five-field cron expression.
    pub cron_expression: String,
    /// Canonical IANA time-zone identity.
    pub timezone: String,
    /// Explicit downtime behavior.
    pub missed_run_policy: MissedRunPolicy,
    /// Explicit same-schedule overlap behavior.
    pub overlap_policy: ScheduleOverlapPolicy,
    /// Inclusive lateness tolerated by `skip`.
    pub misfire_grace_ms: i64,
    /// Whether the owner explicitly allowed `/act`, `/edit`, `/manage`, or `/run` input.
    pub approval_required_actions_allowed: bool,
    /// Current lifecycle.
    pub status: ScheduleStatus,
    /// Exact next cron instant while active or paused.
    pub next_due_at_ms: Option<i64>,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// Creation UTC epoch milliseconds.
    pub created_at_ms: i64,
    /// Last update UTC epoch milliseconds.
    pub updated_at_ms: i64,
}

/// Durable history projection for one occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduleRunView {
    /// Stable occurrence-run identity.
    pub schedule_run_id: ScheduleRunId,
    /// Owning schedule.
    pub schedule_id: ScheduleId,
    /// Exact cron instant selected for this coalesced occurrence.
    pub scheduled_for_ms: i64,
    /// Whether older due instants were deliberately coalesced.
    pub coalesced: bool,
    /// Crash-stable action selected before claiming.
    pub intent: ScheduleRunIntent,
    /// Current occurrence lifecycle.
    pub status: ScheduleRunStatus,
    /// Accepted inbox entry when admitted.
    pub inbox_entry_id: Option<InboxEntryId>,
    /// Stable bounded terminal reason for skipped or failed runs.
    pub reason: Option<String>,
    /// First claim UTC epoch milliseconds.
    pub created_at_ms: i64,
    /// Terminal UTC epoch milliseconds.
    pub completed_at_ms: Option<i64>,
}

/// Complete atomic schedule creation evidence.
pub struct CreateScheduleCommit {
    /// New stable schedule identity.
    pub schedule_id: ScheduleId,
    /// Authenticated owner/channel.
    pub ownership: OwnershipContext,
    /// Existing destination session.
    pub session_id: SessionId,
    /// Bounded owner label.
    pub name: String,
    /// Exact scheduled input.
    pub prompt: String,
    /// Canonical five-field expression.
    pub cron_expression: String,
    /// Canonical IANA zone.
    pub timezone: String,
    /// Downtime behavior.
    pub missed_run_policy: MissedRunPolicy,
    /// Overlap behavior.
    pub overlap_policy: ScheduleOverlapPolicy,
    /// Inclusive skip grace.
    pub misfire_grace_ms: i64,
    /// Explicit approval-required action opt-in.
    pub approval_required_actions_allowed: bool,
    /// First future cron instant.
    pub next_due_at_ms: i64,
    /// Canonical creation event.
    pub event_id: EventId,
    /// Command correlation identity.
    pub correlation_id: CorrelationId,
    /// Creation UTC epoch milliseconds.
    pub created_at_ms: i64,
}

/// Lifecycle command for one schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduleTransition {
    /// Stop claims while retaining the cursor.
    Pause,
    /// Re-enable claims from a recomputed cursor.
    Resume,
    /// Terminally disable the definition.
    Cancel,
}

/// Complete atomic schedule lifecycle evidence.
pub struct TransitionScheduleCommit {
    /// Target schedule.
    pub schedule_id: ScheduleId,
    /// Authenticated owner/channel.
    pub ownership: OwnershipContext,
    /// Optimistic-concurrency fence.
    pub expected_revision: u64,
    /// Requested lifecycle transition.
    pub transition: ScheduleTransition,
    /// Required new future cursor for resume only.
    pub resumed_next_due_at_ms: Option<i64>,
    /// Canonical transition event.
    pub event_id: EventId,
    /// Command correlation identity.
    pub correlation_id: CorrelationId,
    /// Transition UTC epoch milliseconds.
    pub transitioned_at_ms: i64,
}

/// One crash-recoverable due-occurrence claim.
pub struct ClaimScheduleRunCommit {
    /// Candidate schedule.
    pub schedule_id: ScheduleId,
    /// Observed schedule revision.
    pub expected_revision: u64,
    /// Observed stored due cursor.
    pub expected_next_due_at_ms: i64,
    /// New identity when no prior claim exists.
    pub proposed_schedule_run_id: ScheduleRunId,
    /// Latest selected cron instant.
    pub scheduled_for_ms: i64,
    /// Whether older instants were coalesced.
    pub coalesced: bool,
    /// Crash-stable action selected before claiming.
    pub intent: ScheduleRunIntent,
    /// Claiming daemon lifetime.
    pub owner_id: WorkerId,
    /// Claim UTC epoch milliseconds.
    pub claimed_at_ms: i64,
    /// Exclusive claim expiry.
    pub claim_expires_at_ms: i64,
}

/// Successful new or expired-claim recovery result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScheduleClaimOutcome {
    /// The caller owns the returned claim.
    Claimed(ScheduleRunView),
    /// Another claim or definition revision won.
    Busy,
}

/// Atomic terminal occurrence and next-cursor evidence.
pub struct CompleteScheduleRunCommit {
    /// Owning schedule.
    pub schedule_id: ScheduleId,
    /// Exact claimed occurrence.
    pub schedule_run_id: ScheduleRunId,
    /// Claiming daemon lifetime.
    pub owner_id: WorkerId,
    /// Terminal status; `Claimed` is rejected.
    pub status: ScheduleRunStatus,
    /// Accepted inbox entry for `Admitted` only.
    pub inbox_entry_id: Option<InboxEntryId>,
    /// Bounded reason for `Skipped` or `Failed` only.
    pub reason: Option<String>,
    /// First cron instant strictly after driver time.
    pub next_due_at_ms: i64,
    /// Completion UTC epoch milliseconds.
    pub completed_at_ms: i64,
}

/// Persistence failure for schedule administration and driving.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ScheduleStoreError {
    /// Schedule is absent or deliberately hidden.
    #[error("schedule was not found")]
    NotFound,
    /// Principal or channel does not own the schedule/session.
    #[error("schedule access is unauthorized")]
    Unauthorized,
    /// Revision, claim, uniqueness, or lifecycle conflict.
    #[error("schedule operation conflicts with canonical state")]
    Conflict,
    /// Proposed contract is invalid.
    #[error("schedule contract is invalid: {0}")]
    InvalidContract(String),
    /// Persistence dependency failed.
    #[error("schedule store is unavailable: {0}")]
    Unavailable(String),
    /// Stored canonical evidence is corrupt.
    #[error("schedule store invariant violation: {0}")]
    InvariantViolation(String),
}

/// Canonical `SQLite` schedule administration and crash-safe due-claim port.
pub trait ScheduleStore {
    /// Creates one active definition and its audit event atomically.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleStoreError`] for invalid, unauthorized, conflicting, or unavailable state.
    fn create_schedule(
        &mut self,
        commit: CreateScheduleCommit,
    ) -> Result<ScheduleView, ScheduleStoreError>;
    /// Reads one authorized definition.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleStoreError`] when absent, unauthorized, unavailable, or corrupt.
    fn schedule(
        &self,
        ownership: OwnershipContext,
        schedule_id: ScheduleId,
    ) -> Result<ScheduleView, ScheduleStoreError>;
    /// Lists authorized definitions in stable order.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleStoreError`] when persistence is unavailable or corrupt.
    fn schedules(
        &self,
        ownership: OwnershipContext,
    ) -> Result<Vec<ScheduleView>, ScheduleStoreError>;
    /// Applies a revision-fenced lifecycle transition.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleStoreError`] for invalid lifecycle, revision, ownership, or persistence.
    fn transition_schedule(
        &mut self,
        commit: TransitionScheduleCommit,
    ) -> Result<ScheduleView, ScheduleStoreError>;
    /// Reads a bounded batch of active due definitions for the trusted driver.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleStoreError`] for invalid bounds or unavailable/corrupt persistence.
    fn due_schedules(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<ScheduleView>, ScheduleStoreError>;
    /// Tests whether an earlier admitted occurrence remains non-terminal.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleStoreError`] when canonical history cannot be read safely.
    fn schedule_has_active_run(&self, schedule_id: ScheduleId) -> Result<bool, ScheduleStoreError>;
    /// Claims or reclaims one exact due occurrence.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleStoreError`] for invalid evidence or unavailable/corrupt persistence.
    fn claim_schedule_run(
        &mut self,
        commit: ClaimScheduleRunCommit,
    ) -> Result<ScheduleClaimOutcome, ScheduleStoreError>;
    /// Terminates a claim and advances its due cursor atomically.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleStoreError`] for stale ownership, invalid outcome, or persistence failure.
    fn complete_schedule_run(
        &mut self,
        commit: CompleteScheduleRunCommit,
    ) -> Result<ScheduleRunView, ScheduleStoreError>;
    /// Reads bounded newest-first occurrence history.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleStoreError`] for invalid bounds, authorization, or persistence failure.
    fn schedule_runs(
        &self,
        ownership: OwnershipContext,
        schedule_id: ScheduleId,
        limit: usize,
    ) -> Result<Vec<ScheduleRunView>, ScheduleStoreError>;
}

/// Validated owner input before a schedule is persisted.
#[derive(Clone, Copy)]
pub struct ScheduleDefinition<'a> {
    /// Human-readable bounded name.
    pub name: &'a str,
    /// Exact scheduled session input.
    pub prompt: &'a str,
    /// Canonical five-field cron expression.
    pub cron_expression: &'a str,
    /// Canonical IANA time-zone identity.
    pub timezone: &'a str,
    /// Inclusive lateness grace for `skip`.
    pub misfire_grace_ms: i64,
    /// Explicit owner opt-in for `/act`, `/edit`, `/manage`, or `/run`.
    pub approval_required_actions_allowed: bool,
}

/// Validates bounds, canonical syntax, time zone, and action-mode opt-in.
///
/// # Errors
///
/// Returns [`ScheduleContractError`] when any field is unsafe, ambiguous, or unbounded.
pub fn validate_schedule_definition(
    definition: ScheduleDefinition<'_>,
) -> Result<(), ScheduleContractError> {
    if definition.name.is_empty()
        || definition.name.len() > MAXIMUM_SCHEDULE_NAME_BYTES
        || definition.name.trim() != definition.name
        || definition.name.chars().any(char::is_control)
    {
        return Err(ScheduleContractError::InvalidName);
    }
    if definition.prompt.is_empty()
        || definition.prompt.len() > MAXIMUM_SCHEDULE_PROMPT_BYTES
        || definition.prompt.contains('\0')
    {
        return Err(ScheduleContractError::InvalidPrompt);
    }
    if approval_required_prefix(definition.prompt) && !definition.approval_required_actions_allowed
    {
        return Err(ScheduleContractError::ActionOptInRequired);
    }
    parse_schedule(definition.cron_expression, definition.timezone)?;
    if !(0..=MAXIMUM_MISFIRE_GRACE_MS).contains(&definition.misfire_grace_ms) {
        return Err(ScheduleContractError::InvalidMisfireGrace);
    }
    Ok(())
}

/// Returns the first cron occurrence strictly after a UTC epoch-millisecond instant.
///
/// # Errors
///
/// Returns [`ScheduleContractError`] for invalid syntax/timezone/time or an excessive horizon.
pub fn next_schedule_occurrence_ms(
    cron_expression: &str,
    timezone: &str,
    after_ms: i64,
) -> Result<i64, ScheduleContractError> {
    let (cron, timezone) = parse_schedule(cron_expression, timezone)?;
    let after = utc_datetime(after_ms)?.with_timezone(&timezone);
    let next = cron
        .find_next_occurrence(&after, false)
        .map_err(|_| ScheduleContractError::NoOccurrence)?
        .with_timezone(&Utc)
        .timestamp_millis();
    if next <= after_ms || next.saturating_sub(after_ms) > MAXIMUM_OCCURRENCE_HORIZON_MS {
        return Err(ScheduleContractError::NoOccurrence);
    }
    Ok(next)
}

/// Due-occurrence action calculated without changing durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduleDueDecision {
    /// Admit the selected occurrence once.
    Fire {
        /// Latest due cron instant.
        scheduled_for_ms: i64,
        /// First future cron instant.
        next_due_at_ms: i64,
        /// Whether earlier due instants were coalesced.
        coalesced: bool,
    },
    /// Advance without admission after grace elapsed.
    SkipMisfire {
        /// Latest due cron instant retained in history.
        scheduled_for_ms: i64,
        /// First future cron instant.
        next_due_at_ms: i64,
        /// Whether earlier due instants were coalesced.
        coalesced: bool,
    },
}

/// Calculates a deterministic coalesced due action from one canonical schedule snapshot.
///
/// # Errors
///
/// Returns [`ScheduleContractError`] unless the snapshot is active, due, and internally valid.
pub fn plan_due_schedule(
    schedule: &ScheduleView,
    now_ms: i64,
) -> Result<ScheduleDueDecision, ScheduleContractError> {
    validate_schedule_view(schedule)?;
    let next_cursor = schedule
        .next_due_at_ms
        .filter(|due| *due <= now_ms)
        .ok_or(ScheduleContractError::NotDue)?;
    if schedule.status != ScheduleStatus::Active {
        return Err(ScheduleContractError::NotDue);
    }
    let (cron, timezone) = parse_schedule(&schedule.cron_expression, &schedule.timezone)?;
    let now = utc_datetime(now_ms)?.with_timezone(&timezone);
    let scheduled_for_ms = cron
        .find_previous_occurrence(&now, true)
        .map_err(|_| ScheduleContractError::NoOccurrence)?
        .with_timezone(&Utc)
        .timestamp_millis();
    if scheduled_for_ms < next_cursor || scheduled_for_ms > now_ms {
        return Err(ScheduleContractError::InvalidView);
    }
    let next_due_at_ms = cron
        .find_next_occurrence(&now, false)
        .map_err(|_| ScheduleContractError::NoOccurrence)?
        .with_timezone(&Utc)
        .timestamp_millis();
    if next_due_at_ms <= now_ms
        || next_due_at_ms.saturating_sub(now_ms) > MAXIMUM_OCCURRENCE_HORIZON_MS
    {
        return Err(ScheduleContractError::NoOccurrence);
    }
    let coalesced = scheduled_for_ms != next_cursor;
    if schedule.missed_run_policy == MissedRunPolicy::Skip
        && now_ms.saturating_sub(scheduled_for_ms) > schedule.misfire_grace_ms
    {
        Ok(ScheduleDueDecision::SkipMisfire {
            scheduled_for_ms,
            next_due_at_ms,
            coalesced,
        })
    } else {
        Ok(ScheduleDueDecision::Fire {
            scheduled_for_ms,
            next_due_at_ms,
            coalesced,
        })
    }
}

/// Validates a rehydrated canonical schedule projection.
///
/// # Errors
///
/// Returns [`ScheduleContractError::InvalidView`] for contradictory lifecycle or timestamp data.
pub fn validate_schedule_view(schedule: &ScheduleView) -> Result<(), ScheduleContractError> {
    validate_schedule_definition(ScheduleDefinition {
        name: &schedule.name,
        prompt: &schedule.prompt,
        cron_expression: &schedule.cron_expression,
        timezone: &schedule.timezone,
        misfire_grace_ms: schedule.misfire_grace_ms,
        approval_required_actions_allowed: schedule.approval_required_actions_allowed,
    })?;
    if schedule.created_at_ms < 0
        || schedule.updated_at_ms < schedule.created_at_ms
        || schedule.status == ScheduleStatus::Cancelled && schedule.next_due_at_ms.is_some()
        || schedule.status != ScheduleStatus::Cancelled
            && schedule.next_due_at_ms.is_none_or(|due| due < 0)
    {
        return Err(ScheduleContractError::InvalidView);
    }
    Ok(())
}

fn parse_schedule(expression: &str, timezone: &str) -> Result<(Cron, Tz), ScheduleContractError> {
    if expression.is_empty()
        || expression.len() > MAXIMUM_CRON_EXPRESSION_BYTES
        || expression.split_whitespace().count() != 5
        || expression.split_whitespace().collect::<Vec<_>>().join(" ") != expression
    {
        return Err(ScheduleContractError::InvalidCron);
    }
    let cron = Cron::from_str(expression).map_err(|_| ScheduleContractError::InvalidCron)?;
    if timezone.is_empty() || timezone.len() > MAXIMUM_TIMEZONE_BYTES || timezone.trim() != timezone
    {
        return Err(ScheduleContractError::InvalidTimezone);
    }
    let timezone = Tz::from_str(timezone).map_err(|_| ScheduleContractError::InvalidTimezone)?;
    Ok((cron, timezone))
}

fn utc_datetime(value: i64) -> Result<DateTime<Utc>, ScheduleContractError> {
    DateTime::<Utc>::from_timestamp_millis(value).ok_or(ScheduleContractError::InvalidTime)
}

fn approval_required_prefix(prompt: &str) -> bool {
    ["/act ", "/run ", "/edit ", "/manage "]
        .iter()
        .any(|prefix| prompt.starts_with(prefix))
}

/// Invalid schedule definition, lifecycle projection, or due calculation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ScheduleContractError {
    /// Name is absent, padded, controlling, or oversized.
    #[error("schedule name is invalid")]
    InvalidName,
    /// Prompt is absent, contains NUL, or is oversized.
    #[error("schedule prompt is invalid")]
    InvalidPrompt,
    /// Approval-required prefix lacks explicit opt-in.
    #[error("scheduled approval-required action needs explicit opt-in")]
    ActionOptInRequired,
    /// Cron syntax is noncanonical, invalid, or oversized.
    #[error("schedule cron expression is invalid")]
    InvalidCron,
    /// Time-zone identity is invalid or oversized.
    #[error("schedule time zone is invalid")]
    InvalidTimezone,
    /// Misfire grace lies outside enforceable bounds.
    #[error("schedule misfire grace is invalid")]
    InvalidMisfireGrace,
    /// Epoch milliseconds cannot be represented.
    #[error("schedule time is invalid")]
    InvalidTime,
    /// No bounded future occurrence exists.
    #[error("schedule has no bounded future occurrence")]
    NoOccurrence,
    /// Snapshot is inactive or not yet due.
    #[error("schedule is not due")]
    NotDue,
    /// Rehydrated canonical evidence contradicts the contract.
    #[error("stored schedule projection is invalid")]
    InvalidView,
}

#[cfg(test)]
mod tests {
    use super::{
        MissedRunPolicy, ScheduleDefinition, ScheduleDueDecision, ScheduleOverlapPolicy,
        ScheduleStatus, ScheduleView, next_schedule_occurrence_ms, plan_due_schedule,
        validate_schedule_definition,
    };
    use crate::OwnershipContext;
    use mealy_domain::{ChannelBindingId, PrincipalId, ScheduleId, SessionId};

    fn schedule(next_due_at_ms: i64, policy: MissedRunPolicy, grace: i64) -> ScheduleView {
        ScheduleView {
            schedule_id: ScheduleId::new(),
            ownership: OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new()),
            session_id: SessionId::new(),
            name: "weekday brief".to_owned(),
            prompt: "Prepare a concise brief.".to_owned(),
            cron_expression: "0 9 * * MON-FRI".to_owned(),
            timezone: "Pacific/Auckland".to_owned(),
            missed_run_policy: policy,
            overlap_policy: ScheduleOverlapPolicy::SkipIfRunning,
            misfire_grace_ms: grace,
            approval_required_actions_allowed: false,
            status: ScheduleStatus::Active,
            next_due_at_ms: Some(next_due_at_ms),
            revision: 0,
            created_at_ms: 0,
            updated_at_ms: 0,
        }
    }

    #[test]
    fn definition_is_canonical_timezone_aware_and_action_opt_in_is_explicit() {
        assert!(
            validate_schedule_definition(ScheduleDefinition {
                name: "daily brief",
                prompt: "Summarize the project workspace.",
                cron_expression: "0 9 * * *",
                timezone: "Pacific/Auckland",
                misfire_grace_ms: 60_000,
                approval_required_actions_allowed: false,
            })
            .is_ok()
        );
        assert!(
            validate_schedule_definition(ScheduleDefinition {
                name: "unsafe",
                prompt: "/run mutate the workspace",
                cron_expression: "0 9 * * *",
                timezone: "Pacific/Auckland",
                misfire_grace_ms: 60_000,
                approval_required_actions_allowed: false,
            })
            .is_err()
        );
        assert!(
            validate_schedule_definition(ScheduleDefinition {
                name: "unsafe manage",
                prompt: "/manage remove an obsolete file",
                cron_expression: "0 9 * * *",
                timezone: "Pacific/Auckland",
                misfire_grace_ms: 60_000,
                approval_required_actions_allowed: false,
            })
            .is_err()
        );
        assert!(
            validate_schedule_definition(ScheduleDefinition {
                name: "bad cron",
                prompt: "hello",
                cron_expression: "0  9 * * *",
                timezone: "Pacific/Auckland",
                misfire_grace_ms: 60_000,
                approval_required_actions_allowed: false,
            })
            .is_err()
        );
    }

    #[test]
    fn occurrence_respects_named_timezone_and_dst() {
        let before = 1_790_451_000_000_i64;
        let next = next_schedule_occurrence_ms("0 10 * * *", "Pacific/Auckland", before)
            .expect("next Auckland occurrence");
        assert!(next > before);
        assert_eq!(next % 60_000, 0);
    }

    #[test]
    fn downtime_is_either_coalesced_or_explicitly_skipped() {
        let cursor = 1_790_000_000_000_i64;
        let now = cursor + 3 * 24 * 60 * 60 * 1_000;
        let latest = plan_due_schedule(&schedule(cursor, MissedRunPolicy::Latest, 0), now)
            .expect("latest due plan");
        assert!(matches!(
            latest,
            ScheduleDueDecision::Fire {
                coalesced: true,
                ..
            }
        ));
        let skipped = plan_due_schedule(&schedule(cursor, MissedRunPolicy::Skip, 1_000), now)
            .expect("skip due plan");
        assert!(matches!(skipped, ScheduleDueDecision::SkipMisfire { .. }));
    }
}
