use super::SqliteStore;
use mealy_application::{
    RecoverInterruptedEffectCommit, StartupRecoveryBatch, StartupRecoveryCommit,
    StartupRecoveryStore, StartupRecoveryStoreError, sha256_digest,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use std::time::SystemTime;

impl StartupRecoveryStore for SqliteStore {
    fn recover_startup_batch(
        &mut self,
        commit: StartupRecoveryCommit,
    ) -> Result<StartupRecoveryBatch, StartupRecoveryStoreError> {
        let now_ms = epoch_milliseconds(commit.now)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        if commit.recover_outbox_claims {
            transaction
                .execute(
                    "UPDATE outbox \
                     SET state = 'pending', next_attempt_at_ms = ?1, \
                         delivery_owner_id = NULL, delivery_started_at_ms = NULL, \
                         last_error = COALESCE(last_error, 'daemon restarted during delivery') \
                     WHERE state = 'delivering'",
                    [now_ms],
                )
                .map_err(map_sqlite_error)?;
        }
        let expired = load_expired(
            &transaction,
            now_ms,
            commit.batch_limit,
            commit.recover_outbox_claims,
        )?;
        if commit.event_ids.len() < expired.len() {
            return Err(invariant("recovery did not reserve enough event IDs"));
        }

        let mut last_cursor = None;
        let mut requeued_runs = 0_u64;
        let mut waiting_runs = 0_u64;
        for (index, lease) in expired.iter().enumerate() {
            let disposition = recover_lease(
                &transaction,
                &commit,
                commit.event_ids[index],
                lease,
                now_ms,
            )?;
            match disposition {
                RecoveredLeaseDisposition::Requeued => {
                    requeued_runs = requeued_runs
                        .checked_add(1)
                        .ok_or_else(|| invariant("requeued run count overflow"))?;
                }
                RecoveredLeaseDisposition::Waiting => {
                    waiting_runs = waiting_runs
                        .checked_add(1)
                        .ok_or_else(|| invariant("waiting run count overflow"))?;
                }
            }
            last_cursor = Some(high_cursor(&transaction)?);
        }
        let pending_outbox = count_pending_outbox(&transaction)?;
        let has_more = has_expired(&transaction, now_ms, commit.recover_outbox_claims)?;
        transaction.commit().map_err(map_sqlite_error)?;
        let count = u64::try_from(expired.len())
            .map_err(|_| invariant("expired lease count exceeds u64"))?;
        Ok(StartupRecoveryBatch {
            expired_leases: count,
            requeued_runs,
            waiting_runs,
            pending_outbox,
            has_more,
            cursor: last_cursor,
        })
    }
}

pub(super) struct ExpiredLease {
    pub(super) lease_id: String,
    pub(super) run_id: String,
    pub(super) owner_id: String,
    pub(super) fencing_token: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RecoveredLeaseDisposition {
    Requeued,
    Waiting,
}

struct InterruptedEffect {
    effect_id: String,
    attempt_id: String,
    effect_revision: i64,
    boundary: String,
    disposition: String,
}

fn load_expired(
    transaction: &Transaction<'_>,
    now_ms: i64,
    limit: usize,
    recover_all_active: bool,
) -> Result<Vec<ExpiredLease>, StartupRecoveryStoreError> {
    let limit =
        i64::try_from(limit).map_err(|_| invariant("recovery limit exceeds SQLite range"))?;
    let mut statement = transaction
        .prepare(
            "SELECT lease_id, run_id, owner_id, fencing_token FROM work_lease \
             WHERE state = 'active' AND (?3 = 1 OR expires_at_ms <= ?1) \
             ORDER BY expires_at_ms, lease_id LIMIT ?2",
        )
        .map_err(map_sqlite_error)?;
    statement
        .query_map(params![now_ms, limit, recover_all_active], |row| {
            Ok(ExpiredLease {
                lease_id: row.get(0)?,
                run_id: row.get(1)?,
                owner_id: row.get(2)?,
                fencing_token: row.get(3)?,
            })
        })
        .map_err(map_sqlite_error)?
        .map(|row| row.map_err(map_sqlite_error))
        .collect()
}

#[allow(clippy::too_many_lines)] // Atomic recovery deliberately keeps lease/effect/run/task ordering visible.
pub(super) fn recover_lease(
    transaction: &Transaction<'_>,
    commit: &StartupRecoveryCommit,
    event_ids: mealy_application::LeaseRecoveryEventIds,
    lease: &ExpiredLease,
    now_ms: i64,
) -> Result<RecoveredLeaseDisposition, StartupRecoveryStoreError> {
    let observed_agent_boundary = load_agent_boundary(transaction, &lease.run_id)?;
    let agent_recovery = recover_incomplete_agent_boundary(transaction, &lease.run_id, now_ms)?;
    let expired = transaction
        .execute(
            "UPDATE work_lease SET state = 'expired', released_at_ms = ?1 \
             WHERE lease_id = ?2 AND run_id = ?3 AND fencing_token = ?4 \
               AND state = 'active' AND (?5 = 1 OR expires_at_ms <= ?1)",
            params![
                now_ms,
                lease.lease_id,
                lease.run_id,
                lease.fencing_token,
                commit.recover_outbox_claims,
            ],
        )
        .map_err(map_sqlite_error)?;
    if expired != 1 {
        return Err(invariant("expired lease was no longer current"));
    }
    append_recovery_event(
        transaction,
        event_ids.lease_expired,
        "lease",
        &lease.lease_id,
        "lease.expired",
        now_ms,
        commit.correlation_id,
        &json!({
            "run_id": lease.run_id,
            "owner_id": lease.owner_id,
            "fencing_token": lease.fencing_token,
        }),
    )?;

    let interrupted_effect = load_interrupted_effect(transaction, lease)?;
    let recovery_disposition = classify_lease_recovery(interrupted_effect.as_ref())?;
    if recovery_disposition == RecoveredLeaseDisposition::Waiting {
        let effect = interrupted_effect
            .as_ref()
            .ok_or_else(|| invariant("waiting recovery has no interrupted effect"))?;
        match effect.boundary.as_str() {
            "running" => {
                let effect_id = effect
                    .effect_id
                    .parse()
                    .map_err(|_| invariant("interrupted effect ID is invalid"))?;
                let attempt_id = effect
                    .attempt_id
                    .parse()
                    .map_err(|_| invariant("interrupted effect attempt ID is invalid"))?;
                let expected_effect_revision = u64::try_from(effect.effect_revision)
                    .map_err(|_| invariant("interrupted effect revision is negative"))?;
                super::effects::recover_interrupted_effect_transaction(
                    transaction,
                    &RecoverInterruptedEffectCommit {
                        effect_id,
                        attempt_id,
                        expected_effect_revision,
                        event_id: event_ids.effect_recovered,
                        correlation_id: commit.correlation_id,
                        recovered_at: commit.now,
                    },
                    effect.effect_revision,
                    now_ms,
                )
                .map_err(|error| {
                    invariant(format!("interrupted effect recovery failed: {error}"))
                })?;
            }
            "outcome_unknown" => {}
            _ => return Err(invariant("waiting effect boundary is invalid")),
        }
    } else if let Some(effect) = &interrupted_effect {
        let effect_id = effect
            .effect_id
            .parse()
            .map_err(|_| invariant("retryable effect ID is invalid"))?;
        let attempt_id = effect
            .attempt_id
            .parse()
            .map_err(|_| invariant("retryable effect attempt ID is invalid"))?;
        let expected_effect_revision = u64::try_from(effect.effect_revision)
            .map_err(|_| invariant("retryable effect revision is negative"))?;
        let recovery_commit = RecoverInterruptedEffectCommit {
            effect_id,
            attempt_id,
            expected_effect_revision,
            event_id: event_ids.effect_recovered,
            correlation_id: commit.correlation_id,
            recovered_at: commit.now,
        };
        match effect.boundary.as_str() {
            "prepared" => super::effects::recover_undispatched_effect_transaction(
                transaction,
                &recovery_commit,
                effect.effect_revision,
                now_ms,
            )
            .map_err(|error| invariant(format!("undispatched effect recovery failed: {error}")))?,
            "running" => super::effects::recover_retryable_effect_transaction(
                transaction,
                &recovery_commit,
                effect.effect_revision,
                now_ms,
            )
            .map_err(|error| invariant(format!("retryable effect recovery failed: {error}")))?,
            _ => return Err(invariant("stored interrupted effect boundary is invalid")),
        }
    }

    let next_token = lease
        .fencing_token
        .checked_add(1)
        .ok_or_else(|| invariant("recovery fencing token overflow"))?;
    let run_status = match recovery_disposition {
        RecoveredLeaseDisposition::Requeued => "queued",
        RecoveredLeaseDisposition::Waiting => "waiting",
    };
    let run_changed = transaction
        .execute(
            "UPDATE run SET status = ?1, revision = revision + 1, \
                            current_fencing_token = MAX(current_fencing_token, ?2), \
                            updated_at_ms = MAX(updated_at_ms, ?3) \
             WHERE id = ?4 AND status = 'running' AND current_fencing_token = ?5",
            params![
                run_status,
                next_token,
                now_ms,
                lease.run_id,
                lease.fencing_token
            ],
        )
        .map_err(map_sqlite_error)?;
    if run_changed != 1 {
        return Err(invariant("expired lease run was no longer current"));
    }
    if !matches!(
        agent_recovery,
        "no_agent_boundary" | "resume_committed_boundary"
    ) {
        let mut boundary = load_recovered_agent_boundary(transaction, &lease.run_id)?;
        if let Some(observed) = observed_agent_boundary {
            boundary.attempt_id = observed.attempt_id;
            boundary.tool_call_id = observed.tool_call_id;
        }
        append_recovery_event(
            transaction,
            event_ids.agent_boundary_recovered,
            "run",
            &lease.run_id,
            "agent.boundary_recovered",
            now_ms,
            commit.correlation_id,
            &json!({
                "classification": agent_recovery,
                "current_attempt_id": boundary.attempt_id,
                "current_tool_call_id": boundary.tool_call_id,
                "next_action": boundary.next_action,
            }),
        )?;
        append_recovery_checkpoint(
            transaction,
            &lease.run_id,
            event_ids.agent_boundary_recovered,
            now_ms,
            &boundary,
            agent_recovery,
        )?;
    }
    let (run_event_type, run_reason) = match recovery_disposition {
        RecoveredLeaseDisposition::Requeued => ("run.requeued", "lease_expired"),
        RecoveredLeaseDisposition::Waiting => ("run.waiting", "interrupted_effect_outcome_unknown"),
    };
    append_recovery_event(
        transaction,
        event_ids.run_requeued,
        "run",
        &lease.run_id,
        run_event_type,
        now_ms,
        commit.correlation_id,
        &json!({
            "reason": run_reason,
            "invalidated_fencing_token": lease.fencing_token,
            "current_fencing_token": next_token,
            "agent_recovery": agent_recovery,
            "effect_id": interrupted_effect.as_ref().map(|effect| effect.effect_id.as_str()),
            "effect_attempt_id": interrupted_effect
                .as_ref()
                .map(|effect| effect.attempt_id.as_str()),
            "effect_recovery_disposition": interrupted_effect
                .as_ref()
                .map(|effect| effect.disposition.as_str()),
        }),
    )?;
    if recovery_disposition == RecoveredLeaseDisposition::Waiting {
        transition_task_to_waiting(
            transaction,
            commit,
            event_ids,
            lease,
            interrupted_effect
                .as_ref()
                .ok_or_else(|| invariant("waiting recovery lost its interrupted effect"))?,
            now_ms,
        )?;
    }
    Ok(recovery_disposition)
}

fn load_interrupted_effect(
    transaction: &Transaction<'_>,
    lease: &ExpiredLease,
) -> Result<Option<InterruptedEffect>, StartupRecoveryStoreError> {
    let mut statement = transaction
        .prepare(
            "SELECT attempt.effect_id, attempt.attempt_id, effect.revision, candidate.boundary, \
                    candidate.disposition \
             FROM effect_attempt attempt \
             JOIN effect ON effect.id = attempt.effect_id \
             JOIN effect_recovery_candidate candidate \
               ON candidate.attempt_id = attempt.attempt_id \
             WHERE attempt.prepared_lease_id = ?1 AND attempt.prepared_owner_id = ?2 \
               AND attempt.prepared_fencing_token = ?3 \
             ORDER BY attempt.effect_id, attempt.ordinal, attempt.attempt_id",
        )
        .map_err(map_sqlite_error)?;
    let rows = statement
        .query_map(
            params![lease.lease_id, lease.owner_id, lease.fencing_token],
            |row| {
                Ok(InterruptedEffect {
                    effect_id: row.get(0)?,
                    attempt_id: row.get(1)?,
                    effect_revision: row.get(2)?,
                    boundary: row.get(3)?,
                    disposition: row.get(4)?,
                })
            },
        )
        .map_err(map_sqlite_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_sqlite_error)?;
    match rows.len() {
        0 => Ok(None),
        1 => Ok(rows.into_iter().next()),
        _ => Err(invariant(
            "one expired lease owns multiple unsettled effect dispatches",
        )),
    }
}

fn classify_lease_recovery(
    effect: Option<&InterruptedEffect>,
) -> Result<RecoveredLeaseDisposition, StartupRecoveryStoreError> {
    match effect.map(|value| (value.boundary.as_str(), value.disposition.as_str())) {
        None
        | Some(("prepared", "resume_prepared") | ("running", "retry" | "retry_with_same_key")) => {
            Ok(RecoveredLeaseDisposition::Requeued)
        }
        Some((
            "running" | "outcome_unknown",
            "requires_reconciliation" | "requires_compensation" | "terminally_failed",
        )) => Ok(RecoveredLeaseDisposition::Waiting),
        Some(("prepared", _)) => Err(invariant(
            "an undispatched effect preparation has an invalid recovery disposition",
        )),
        Some(_) => Err(invariant("stored effect recovery disposition is invalid")),
    }
}

fn transition_task_to_waiting(
    transaction: &Transaction<'_>,
    commit: &StartupRecoveryCommit,
    event_ids: mealy_application::LeaseRecoveryEventIds,
    lease: &ExpiredLease,
    effect: &InterruptedEffect,
    now_ms: i64,
) -> Result<(), StartupRecoveryStoreError> {
    let (task_id, task_status) = transaction
        .query_row(
            "SELECT task.id, task.status FROM run \
             JOIN task ON task.id = run.task_id WHERE run.id = ?1",
            [lease.run_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or_else(|| invariant("waiting run has no owning task"))?;
    match task_status.as_str() {
        "running" => {
            let changed = transaction
                .execute(
                    "UPDATE task SET status = 'waiting', revision = revision + 1 \
                     WHERE id = ?1 AND status = 'running'",
                    [task_id.as_str()],
                )
                .map_err(map_sqlite_error)?;
            if changed != 1 {
                return Err(invariant("effect recovery task transition conflicted"));
            }
            append_recovery_event(
                transaction,
                event_ids.task_waiting,
                "task",
                &task_id,
                "task.waiting",
                now_ms,
                commit.correlation_id,
                &json!({
                    "reason": "interrupted_effect_outcome_unknown",
                    "run_id": lease.run_id,
                    "effect_id": effect.effect_id,
                    "effect_attempt_id": effect.attempt_id,
                    "effect_recovery_disposition": effect.disposition,
                }),
            )
        }
        "waiting" | "cancelling" => Ok(()),
        _ => Err(invariant(
            "unknown effect belongs to a task that cannot wait",
        )),
    }
}

struct RecoveredAgentBoundary {
    manifest_id: Option<String>,
    attempt_id: Option<String>,
    tool_call_id: Option<String>,
    next_action: String,
}

fn load_recovered_agent_boundary(
    transaction: &Transaction<'_>,
    run_id: &str,
) -> Result<RecoveredAgentBoundary, StartupRecoveryStoreError> {
    load_agent_boundary(transaction, run_id)?
        .ok_or_else(|| invariant("recovered agent boundary disappeared"))
}

fn load_agent_boundary(
    transaction: &Transaction<'_>,
    run_id: &str,
) -> Result<Option<RecoveredAgentBoundary>, StartupRecoveryStoreError> {
    transaction
        .query_row(
            "SELECT current_manifest_id, current_attempt_id, current_tool_call_id, next_action \
             FROM run_loop_state WHERE run_id = ?1",
            [run_id],
            |row| {
                Ok(RecoveredAgentBoundary {
                    manifest_id: row.get(0)?,
                    attempt_id: row.get(1)?,
                    tool_call_id: row.get(2)?,
                    next_action: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)
}

fn append_recovery_checkpoint(
    transaction: &Transaction<'_>,
    run_id: &str,
    event_id: mealy_domain::EventId,
    now_ms: i64,
    boundary: &RecoveredAgentBoundary,
    classification: &str,
) -> Result<(), StartupRecoveryStoreError> {
    let previous = transaction
        .query_row(
            "SELECT sequence, checkpoint_digest FROM loop_checkpoint \
             WHERE run_id = ?1 ORDER BY sequence DESC LIMIT 1",
            [run_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(map_sqlite_error)?;
    let sequence = previous.as_ref().map_or(Ok(0), |(sequence, _)| {
        sequence
            .checked_add(1)
            .ok_or_else(|| invariant("recovery checkpoint sequence overflow"))
    })?;
    let prior_sequence = previous.as_ref().map(|(sequence, _)| *sequence);
    let prior_digest = previous.map(|(_, digest)| digest);
    let decision = json!({
        "reason": "lease_expired",
        "recoveryClassification": classification,
    });
    let decision_json = decision.to_string();
    let digest_material = json!({
        "runId": run_id,
        "sequence": sequence,
        "priorDigest": prior_digest,
        "nextAction": boundary.next_action,
        "manifestId": boundary.manifest_id,
        "attemptId": boundary.attempt_id,
        "toolCallId": boundary.tool_call_id,
        "decision": decision,
    })
    .to_string();
    let checkpoint_digest = sha256_digest(digest_material.as_bytes());
    transaction
        .execute(
            "INSERT INTO loop_checkpoint(\
                run_id, sequence, prior_sequence, loop_version, next_action, manifest_id, \
                attempt_id, tool_call_id, decision_json, prior_checkpoint_digest, \
                checkpoint_digest, event_id, created_at_ms\
             ) VALUES (?1, ?2, ?3, 'mealy.agent-loop.v1', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                run_id,
                sequence,
                prior_sequence,
                boundary.next_action,
                boundary.manifest_id,
                boundary.attempt_id,
                boundary.tool_call_id,
                decision_json,
                prior_digest,
                checkpoint_digest,
                event_id.to_string(),
                now_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn recover_incomplete_agent_boundary(
    transaction: &Transaction<'_>,
    run_id: &str,
    now_ms: i64,
) -> Result<&'static str, StartupRecoveryStoreError> {
    let boundary = transaction
        .query_row(
            "SELECT ma.attempt_id, ma.state, tc.tool_call_id, tc.state \
             FROM run_loop_state ls \
             LEFT JOIN model_attempt ma ON ma.attempt_id = ls.current_attempt_id \
             LEFT JOIN tool_call tc ON tc.tool_call_id = ls.current_tool_call_id \
             WHERE ls.run_id = ?1",
            [run_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?;
    let Some((attempt_id, attempt_state, tool_call_id, tool_state)) = boundary else {
        return Ok("no_agent_boundary");
    };

    if let (Some(tool_call_id), Some(tool_state)) = (tool_call_id, tool_state)
        && matches!(tool_state.as_str(), "prepared" | "running")
    {
        let was_dispatched = tool_state == "running";
        let retry_budget_available = transaction
            .query_row(
                "SELECT used_retries < maximum_retries FROM run_budget_usage WHERE run_id = ?1",
                [run_id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(map_sqlite_error)?;
        let may_retry = !was_dispatched || retry_budget_available;
        let retry_charge = was_dispatched && may_retry;
        let changed = transaction
            .execute(
                "UPDATE tool_call SET state = 'interrupted', completed_at_ms = ?1, \
                    error_class = 'daemon_restart', \
                    error_message = CASE WHEN state = 'prepared' \
                        THEN 'pure read tool interrupted before dispatch by daemon restart' \
                        ELSE 'pure read tool interrupted during dispatch by daemon restart' END \
                 WHERE tool_call_id = ?2 AND run_id = ?3 AND state IN ('prepared', 'running')",
                params![now_ms, tool_call_id, run_id],
            )
            .map_err(map_sqlite_error)?;
        let budget_changed = transaction
            .execute(
                "UPDATE run_budget_usage SET revision = revision + 1, \
                    reserved_tool_calls = reserved_tool_calls - 1, \
                    used_tool_calls = used_tool_calls + ?2, \
                    used_retries = used_retries + ?3 \
                 WHERE run_id = ?1 AND reserved_tool_calls >= 1 \
                   AND used_tool_calls + ?2 <= maximum_tool_calls \
                   AND used_retries + ?3 <= maximum_retries",
                params![run_id, i64::from(was_dispatched), i64::from(retry_charge)],
            )
            .map_err(map_sqlite_error)?;
        let loop_changed = transaction
            .execute(
                "UPDATE run_loop_state SET revision = revision + 1, \
                    next_action = ?1, current_tool_call_id = CASE WHEN ?2 = 1 THEN NULL \
                                                                 ELSE current_tool_call_id END, \
                    updated_at_ms = ?3 \
                 WHERE run_id = ?4 AND current_tool_call_id = ?5",
                params![
                    if may_retry {
                        "consume_model_result"
                    } else {
                        "dispatch_read_tool"
                    },
                    may_retry,
                    now_ms,
                    run_id,
                    tool_call_id,
                ],
            )
            .map_err(map_sqlite_error)?;
        if [changed, budget_changed, loop_changed] != [1, 1, 1] {
            return Err(invariant("interrupted read-tool recovery conflicted"));
        }
        return Ok(if !was_dispatched {
            "retry_undispatched_read_tool"
        } else if may_retry {
            "retry_pure_read_tool"
        } else {
            "read_tool_retry_budget_exhausted"
        });
    }

    let (Some(attempt_id), Some(attempt_state)) = (attempt_id, attempt_state) else {
        return Ok("resume_committed_boundary");
    };
    match attempt_state.as_str() {
        "prepared" => {
            let reservation = load_reservation(transaction, &attempt_id)?;
            let budget_changed =
                release_model_reservation(transaction, run_id, &reservation, false, false)?;
            let reservation_changed = transaction
                .execute(
                    "UPDATE budget_reservation SET state = 'released', settled_at_ms = ?1 \
                     WHERE attempt_id = ?2 AND state = 'active'",
                    params![now_ms, attempt_id],
                )
                .map_err(map_sqlite_error)?;
            let attempt_changed = interrupt_model_attempt(
                transaction,
                &attempt_id,
                run_id,
                now_ms,
                "daemon_restart_before_dispatch",
            )?;
            let loop_changed = reset_model_loop(transaction, run_id, &attempt_id, now_ms, true)?;
            if [
                budget_changed,
                reservation_changed,
                attempt_changed,
                loop_changed,
            ] != [1, 1, 1, 1]
            {
                return Err(invariant("prepared model-attempt recovery conflicted"));
            }
            Ok("retry_undispatched_model")
        }
        "dispatching" => {
            let reservation = load_reservation(transaction, &attempt_id)?;
            let may_retry = transaction
                .query_row(
                    "SELECT used_retries < maximum_retries FROM run_budget_usage WHERE run_id = ?1",
                    [run_id],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(map_sqlite_error)?;
            let budget_changed =
                release_model_reservation(transaction, run_id, &reservation, true, may_retry)?;
            let reservation_changed = transaction
                .execute(
                    "UPDATE budget_reservation SET state = 'charged_unknown', settled_at_ms = ?1 \
                     WHERE attempt_id = ?2 AND state = 'active'",
                    params![now_ms, attempt_id],
                )
                .map_err(map_sqlite_error)?;
            let attempt_changed = interrupt_model_attempt(
                transaction,
                &attempt_id,
                run_id,
                now_ms,
                "provider_outcome_unknown_after_restart",
            )?;
            let loop_changed =
                reset_model_loop(transaction, run_id, &attempt_id, now_ms, may_retry)?;
            if [
                budget_changed,
                reservation_changed,
                attempt_changed,
                loop_changed,
            ] != [1, 1, 1, 1]
            {
                return Err(invariant("dispatching model-attempt recovery conflicted"));
            }
            Ok(if may_retry {
                "retry_provider_outcome_unknown"
            } else {
                "provider_retry_budget_exhausted"
            })
        }
        _ => Ok("resume_committed_boundary"),
    }
}

struct RecoveryReservation {
    input_tokens: i64,
    output_tokens: i64,
    cost_microunits: i64,
    output_bytes: i64,
}

fn load_reservation(
    transaction: &Transaction<'_>,
    attempt_id: &str,
) -> Result<RecoveryReservation, StartupRecoveryStoreError> {
    transaction
        .query_row(
            "SELECT input_tokens, output_tokens, cost_microunits, output_bytes \
             FROM budget_reservation WHERE attempt_id = ?1 AND state = 'active'",
            [attempt_id],
            |row| {
                Ok(RecoveryReservation {
                    input_tokens: row.get(0)?,
                    output_tokens: row.get(1)?,
                    cost_microunits: row.get(2)?,
                    output_bytes: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or_else(|| invariant("incomplete model attempt has no active reservation"))
}

fn release_model_reservation(
    transaction: &Transaction<'_>,
    run_id: &str,
    reservation: &RecoveryReservation,
    charge_unknown: bool,
    increment_retry: bool,
) -> Result<usize, StartupRecoveryStoreError> {
    transaction
        .execute(
            "UPDATE run_budget_usage SET revision = revision + 1, \
                reserved_model_calls = reserved_model_calls - 1, \
                reserved_input_tokens = reserved_input_tokens - ?1, \
                reserved_output_tokens = reserved_output_tokens - ?2, \
                reserved_cost_microunits = reserved_cost_microunits - ?3, \
                reserved_output_bytes = reserved_output_bytes - ?4, \
                used_model_calls = used_model_calls + ?5, \
                used_input_tokens = used_input_tokens + ?6, \
                used_output_tokens = used_output_tokens + ?7, \
                used_cost_microunits = used_cost_microunits + ?8, \
                used_output_bytes = used_output_bytes + ?9, \
                used_retries = used_retries + ?10 \
             WHERE run_id = ?11 AND reserved_model_calls >= 1 \
               AND reserved_input_tokens >= ?1 AND reserved_output_tokens >= ?2 \
               AND reserved_cost_microunits >= ?3 AND reserved_output_bytes >= ?4",
            params![
                reservation.input_tokens,
                reservation.output_tokens,
                reservation.cost_microunits,
                reservation.output_bytes,
                i64::from(charge_unknown),
                if charge_unknown {
                    reservation.input_tokens
                } else {
                    0
                },
                if charge_unknown {
                    reservation.output_tokens
                } else {
                    0
                },
                if charge_unknown {
                    reservation.cost_microunits
                } else {
                    0
                },
                if charge_unknown {
                    reservation.output_bytes
                } else {
                    0
                },
                i64::from(increment_retry),
                run_id,
            ],
        )
        .map_err(map_sqlite_error)
}

fn interrupt_model_attempt(
    transaction: &Transaction<'_>,
    attempt_id: &str,
    run_id: &str,
    now_ms: i64,
    error_class: &str,
) -> Result<usize, StartupRecoveryStoreError> {
    transaction
        .execute(
            "UPDATE model_attempt SET state = 'interrupted', completed_at_ms = ?1, \
                error_class = ?2, error_message = 'lease expired before durable completion', \
                retryable = 1 \
             WHERE attempt_id = ?3 AND run_id = ?4 AND state IN ('prepared', 'dispatching')",
            params![now_ms, error_class, attempt_id, run_id],
        )
        .map_err(map_sqlite_error)
}

fn reset_model_loop(
    transaction: &Transaction<'_>,
    run_id: &str,
    attempt_id: &str,
    now_ms: i64,
    may_retry: bool,
) -> Result<usize, StartupRecoveryStoreError> {
    transaction
        .execute(
            "UPDATE run_loop_state SET revision = revision + 1, next_action = ?1, \
                                      updated_at_ms = ?2 \
             WHERE run_id = ?3 AND current_attempt_id = ?4",
            params![
                if may_retry {
                    "compile_context"
                } else {
                    "dispatch_model"
                },
                now_ms,
                run_id,
                attempt_id,
            ],
        )
        .map_err(map_sqlite_error)
}

#[allow(clippy::too_many_arguments)]
fn append_recovery_event(
    transaction: &Transaction<'_>,
    event_id: mealy_domain::EventId,
    aggregate_kind: &str,
    aggregate_id: &str,
    event_type: &str,
    now_ms: i64,
    correlation_id: mealy_domain::CorrelationId,
    payload: &serde_json::Value,
) -> Result<(), StartupRecoveryStoreError> {
    let sequence = next_sequence(transaction, aggregate_kind, aggregate_id)?;
    transaction
        .execute(
            "INSERT INTO journal_event(\
                event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                event_version, occurred_at_ms, correlation_id, sensitivity, payload_json\
             ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, 'internal', ?8)",
            params![
                event_id.to_string(),
                aggregate_kind,
                aggregate_id,
                sequence,
                event_type,
                now_ms,
                correlation_id.to_string(),
                payload.to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    set_sequence(transaction, aggregate_kind, aggregate_id, sequence)
}

fn next_sequence(
    transaction: &Transaction<'_>,
    kind: &str,
    id: &str,
) -> Result<i64, StartupRecoveryStoreError> {
    transaction
        .query_row(
            "SELECT sequence FROM aggregate_sequence WHERE aggregate_kind = ?1 AND aggregate_id = ?2",
            params![kind, id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .map_or(Ok(0), |value| {
            value
                .checked_add(1)
                .ok_or_else(|| invariant("aggregate sequence overflow"))
        })
}

fn set_sequence(
    transaction: &Transaction<'_>,
    kind: &str,
    id: &str,
    sequence: i64,
) -> Result<(), StartupRecoveryStoreError> {
    transaction
        .execute(
            "INSERT INTO aggregate_sequence(aggregate_kind, aggregate_id, sequence) \
             VALUES (?1, ?2, ?3) ON CONFLICT(aggregate_kind, aggregate_id) \
             DO UPDATE SET sequence = excluded.sequence",
            params![kind, id, sequence],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn count_pending_outbox(transaction: &Transaction<'_>) -> Result<u64, StartupRecoveryStoreError> {
    let value = transaction
        .query_row(
            "SELECT COUNT(*) FROM outbox WHERE state IN ('pending', 'delivering')",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(map_sqlite_error)?;
    u64::try_from(value).map_err(|_| invariant("pending outbox count is negative"))
}

fn has_expired(
    transaction: &Transaction<'_>,
    now_ms: i64,
    recover_all_active: bool,
) -> Result<bool, StartupRecoveryStoreError> {
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM work_lease \
             WHERE state = 'active' AND (?2 = 1 OR expires_at_ms <= ?1))",
            params![now_ms, recover_all_active],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error)
}

fn high_cursor(transaction: &Transaction<'_>) -> Result<u64, StartupRecoveryStoreError> {
    let value = transaction
        .query_row(
            "SELECT COALESCE(MAX(cursor), 0) FROM timeline_event",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(map_sqlite_error)?;
    u64::try_from(value).map_err(|_| invariant("timeline cursor is negative"))
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, StartupRecoveryStoreError> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invariant("recovery time precedes Unix epoch"))?;
    i64::try_from(duration.as_millis()).map_err(|_| invariant("timestamp exceeds SQLite range"))
}

#[allow(clippy::needless_pass_by_value)]
fn map_sqlite_error(error: rusqlite::Error) -> StartupRecoveryStoreError {
    StartupRecoveryStoreError::Unavailable(error.to_string())
}

fn invariant(message: impl Into<String>) -> StartupRecoveryStoreError {
    StartupRecoveryStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::SqliteStore;
    use mealy_application::{recover_startup, sha256_digest};
    use mealy_testkit::{TestClock, TestIdGenerator};
    use rusqlite::OptionalExtension;
    use serde_json::{Value, json};

    const PRIOR_DIGEST: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    #[test]
    #[allow(clippy::too_many_lines)]
    fn boundary_event_and_canonical_checkpoint_commit_atomically() {
        let mut store = SqliteStore::open_in_memory(0).expect("open store");
        seed_prepared_agent_boundary(&store);
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER inject_recovery_checkpoint_failure \
                 BEFORE INSERT ON loop_checkpoint WHEN NEW.sequence = 1 \
                 BEGIN SELECT RAISE(ABORT, 'injected recovery checkpoint failure'); END;",
            )
            .expect("install failure trigger");
        let clock = TestClock::new(100);
        let ids = TestIdGenerator::new(100);

        assert!(recover_startup(&mut store, &clock, &ids, 8).is_err());
        assert_recovery_rolled_back(&store);

        store
            .connection
            .execute_batch("DROP TRIGGER inject_recovery_checkpoint_failure;")
            .expect("remove failure trigger");
        let summary = recover_startup(&mut store, &clock, &ids, 8).expect("recover boundary");
        assert_eq!(summary.expired_leases, 1);
        assert_eq!(summary.requeued_runs, 1);

        let (event_id, payload_json, boundary_cursor) = store
            .connection
            .query_row(
                "SELECT event.event_id, event.payload_json, timeline.cursor \
                 FROM journal_event event \
                 JOIN timeline_event timeline ON timeline.event_id = event.event_id \
                 WHERE event.aggregate_kind = 'run' AND event.aggregate_id = 'run' \
                   AND event.event_type = 'agent.boundary_recovered'",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .expect("boundary recovery event");
        let payload: Value = serde_json::from_str(&payload_json).expect("boundary event payload");
        assert_eq!(
            payload["classification"].as_str(),
            Some("retry_undispatched_model")
        );
        assert_eq!(payload["current_attempt_id"].as_str(), Some("attempt"));
        assert!(payload["current_tool_call_id"].is_null());
        assert_eq!(payload["next_action"].as_str(), Some("compile_context"));

        let checkpoint = store
            .connection
            .query_row(
                "SELECT sequence, prior_sequence, next_action, manifest_id, attempt_id, \
                        tool_call_id, decision_json, prior_checkpoint_digest, checkpoint_digest, \
                        event_id \
                 FROM loop_checkpoint WHERE run_id = 'run' AND sequence = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                    ))
                },
            )
            .expect("recovery checkpoint");
        assert_eq!(checkpoint.0, 1);
        assert_eq!(checkpoint.1, Some(0));
        assert_eq!(checkpoint.2, "compile_context");
        assert_eq!(checkpoint.3.as_deref(), Some("manifest"));
        assert_eq!(checkpoint.4.as_deref(), Some("attempt"));
        assert!(checkpoint.5.is_none());
        assert_eq!(checkpoint.7.as_deref(), Some(PRIOR_DIGEST));
        assert_eq!(checkpoint.9, event_id);
        let decision: Value =
            serde_json::from_str(&checkpoint.6).expect("checkpoint decision JSON");
        let expected_decision = json!({
            "reason": "lease_expired",
            "recoveryClassification": "retry_undispatched_model",
        });
        assert_eq!(decision, expected_decision);
        let digest_material = json!({
            "runId": "run",
            "sequence": 1,
            "priorDigest": PRIOR_DIGEST,
            "nextAction": "compile_context",
            "manifestId": "manifest",
            "attemptId": "attempt",
            "toolCallId": null,
            "decision": expected_decision,
        })
        .to_string();
        assert_eq!(checkpoint.8, sha256_digest(digest_material.as_bytes()));

        let requeued_cursor = store
            .connection
            .query_row(
                "SELECT timeline.cursor FROM journal_event event \
                 JOIN timeline_event timeline ON timeline.event_id = event.event_id \
                 WHERE event.aggregate_kind = 'run' AND event.aggregate_id = 'run' \
                   AND event.event_type = 'run.requeued'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("run requeue event");
        assert!(boundary_cursor < requeued_cursor);
    }

    fn assert_recovery_rolled_back(store: &SqliteStore) {
        let boundary_events = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM journal_event WHERE event_type = 'agent.boundary_recovered'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("count recovery events");
        assert_eq!(boundary_events, 0);
        let checkpoint = store
            .connection
            .query_row(
                "SELECT sequence FROM loop_checkpoint WHERE run_id = 'run' AND sequence = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .expect("query recovery checkpoint");
        assert!(checkpoint.is_none());
        let state = store
            .connection
            .query_row(
                "SELECT run.status, lease.state, attempt.state \
                 FROM run run \
                 JOIN work_lease lease ON lease.run_id = run.id \
                 JOIN model_attempt attempt ON attempt.run_id = run.id \
                 WHERE run.id = 'run'",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .expect("rolled-back recovery state");
        assert_eq!(
            state,
            (
                "running".to_owned(),
                "active".to_owned(),
                "prepared".to_owned()
            )
        );
    }

    #[allow(clippy::too_many_lines)]
    fn seed_prepared_agent_boundary(store: &SqliteStore) {
        store
            .connection
            .execute_batch(
                "INSERT INTO session(\
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms\
                 ) VALUES ('session', 'principal', 'binding', 1, 1); \
                 INSERT INTO session_inbox(\
                    inbox_entry_id, session_id, sequence, dedupe_key, delivery_mode, content, \
                    admission_event_id, acknowledgement_outbox_id, correlation_id, accepted_at_ms\
                 ) VALUES (\
                    'inbox', 'session', 1, 'delivery', 'queue', 'hello', \
                    'admission', 'ack', 'correlation', 1\
                 ); \
                 INSERT INTO task(id, status, revision, validation_required) \
                    VALUES ('task', 'running', 0, 0); \
                 INSERT INTO run(\
                    id, task_id, status, agent_role, capability_ceiling_json, budget_json, \
                    correlation_id, created_at_ms, updated_at_ms, current_fencing_token\
                 ) VALUES (\
                    'run', 'task', 'running', 'assistant', '{}', '{}', \
                    'correlation', 1, 1, 1\
                 ); \
                 INSERT INTO work_lease(\
                    lease_id, run_id, owner_id, fencing_token, state, acquired_at_ms, \
                    heartbeat_at_ms, expires_at_ms\
                 ) VALUES ('lease', 'run', 'worker', 1, 'active', 1, 1, 1000); \
                 INSERT INTO turn(\
                    id, session_id, inbox_entry_id, task_id, run_id, correlation_id, created_at_ms\
                 ) VALUES ('turn', 'session', 'inbox', 'task', 'run', 'correlation', 1); \
                 INSERT INTO context_epoch(\
                    id, session_id, epoch_number, baseline_version, baseline_digest, baseline_text, \
                    agent_profile_json, workspace_identity, config_digest, policy_digest, created_at_ms\
                 ) VALUES (\
                    'epoch', 'session', 1, 'v1', \
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
                    'baseline', '{}', 'workspace', \
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', \
                    'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 1\
                 ); \
                 UPDATE session SET current_context_epoch_id = 'epoch' WHERE id = 'session'; \
                 UPDATE turn SET context_epoch_id = 'epoch' WHERE id = 'turn'; \
                 INSERT INTO context_manifest(\
                    id, run_id, session_id, turn_id, epoch_id, iteration, compiler_version, \
                    provider_residency, token_budget, total_token_estimate, \
                    tool_schema_set_digest, policy_version, projection_digest, created_at_ms\
                 ) VALUES (\
                    'manifest', 'run', 'session', 'turn', 'epoch', 1, 'v1', 'local', 100, 0, \
                    'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', \
                    'v1', \
                    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 1\
                 ); \
                 INSERT INTO model_attempt(\
                    attempt_id, run_id, ordinal, state, provider_id, adapter_version, model_id, \
                    capability_snapshot_json, capability_digest, context_manifest_id, \
                    routing_decision_json, tool_schema_digests_json, budget_reservation_json, \
                    request_json, request_digest, timeout_ms, prepared_at_ms, deadline_at_ms, \
                    prepared_lease_id, prepared_owner_id, prepared_fencing_token\
                 ) VALUES (\
                    'attempt', 'run', 1, 'prepared', 'provider', 'v1', 'model', '{}', \
                    '1111111111111111111111111111111111111111111111111111111111111111', \
                    'manifest', '{}', '[]', '{}', '{}', \
                    '2222222222222222222222222222222222222222222222222222222222222222', \
                    100, 1, 101, 'lease', 'worker', 1\
                 ); \
                 INSERT INTO run_budget_usage(\
                    run_id, maximum_model_calls, maximum_tool_calls, maximum_retries, \
                    maximum_input_tokens, maximum_output_tokens, maximum_cost_microunits, \
                    maximum_output_bytes, maximum_wall_time_ms, reserved_model_calls, \
                    reserved_input_tokens, reserved_output_tokens, reserved_cost_microunits, \
                    reserved_output_bytes, started_at_ms, deadline_at_ms\
                 ) VALUES ('run', 4, 1, 2, 100, 100, 100, 100, 1000, 1, 1, 1, 1, 1, 1, 1001); \
                 INSERT INTO budget_reservation(\
                    attempt_id, model_calls, input_tokens, output_tokens, cost_microunits, \
                    output_bytes, state, created_at_ms\
                 ) VALUES ('attempt', 1, 1, 1, 1, 1, 'active', 1); \
                 INSERT INTO run_loop_state(\
                    run_id, iteration, next_action, current_manifest_id, current_attempt_id, \
                    updated_at_ms\
                 ) VALUES ('run', 1, 'dispatch_model', 'manifest', 'attempt', 1); \
                 INSERT INTO journal_event(\
                    event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                    event_version, occurred_at_ms, correlation_id, sensitivity, payload_json\
                 ) VALUES (\
                    'prior-checkpoint-event', 'run', 'run', 0, 'agent.loop.checkpoint', 1, 1, \
                    'correlation', 'internal', '{}'); \
                 INSERT INTO aggregate_sequence(aggregate_kind, aggregate_id, sequence) \
                    VALUES ('run', 'run', 0); \
                 INSERT INTO loop_checkpoint(\
                    run_id, sequence, prior_sequence, loop_version, next_action, manifest_id, \
                    attempt_id, decision_json, prior_checkpoint_digest, checkpoint_digest, \
                    event_id, created_at_ms\
                 ) VALUES (\
                    'run', 0, NULL, 'mealy.agent-loop.v1', 'dispatch_model', 'manifest', \
                    'attempt', '{}', NULL, \
                    'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', \
                    'prior-checkpoint-event', 1\
                 );",
            )
            .expect("seed prepared model boundary");
    }
}
