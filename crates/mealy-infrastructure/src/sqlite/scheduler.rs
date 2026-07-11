use super::SqliteStore;
use mealy_application::{
    CompleteRunCommit, HeartbeatCommit, LeaseClaimCommit, LeaseClaimOutcome, LeaseClaimReceipt,
    ReleaseLeaseCommit, RunCompletionReceipt, RunCompletionStatus, SchedulerStore,
    SchedulerStoreError, sha256_digest,
};
use mealy_domain::{
    CorrelationId, FencingToken, LeaseFence, LeaseStatus, RunId, TaskId, TurnId, WorkLease,
};
use rusqlite::{ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use std::{str::FromStr, time::SystemTime};

impl SchedulerStore for SqliteStore {
    fn claim_next(
        &mut self,
        commit: LeaseClaimCommit,
    ) -> Result<LeaseClaimOutcome, SchedulerStoreError> {
        let claimed_at_ms = epoch_milliseconds(commit.claimed_at)?;
        let expires_at_ms = epoch_milliseconds(commit.expires_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let Some(row) = load_runnable(&transaction, claimed_at_ms, commit.concurrency_limits)?
        else {
            return Ok(LeaseClaimOutcome::NoRunnableWork);
        };
        let token_value = row
            .current_fencing_token
            .checked_add(1)
            .ok_or_else(|| invariant("run fencing token overflow"))?;
        let token_u64 = u64::try_from(token_value)
            .map_err(|_| invariant("run fencing token is outside u64 range"))?;
        let token = FencingToken::new(token_u64)
            .ok_or_else(|| invariant("run fencing token must be nonzero"))?;
        let run_id: RunId = parse_id(&row.run_id, "run ID")?;
        let task_id: TaskId = parse_id(&row.task_id, "task ID")?;
        let turn_id: TurnId = parse_id(&row.turn_id, "turn ID")?;
        let correlation_id: CorrelationId = parse_id(&row.correlation_id, "correlation ID")?;
        let fence = LeaseFence::new(commit.lease_id, run_id, commit.owner_id, token);
        let lease = WorkLease::new(fence, commit.claimed_at, commit.expires_at)
            .map_err(|error| invariant(error.to_string()))?;

        insert_lease(
            &transaction,
            &commit,
            &row,
            token_value,
            claimed_at_ms,
            expires_at_ms,
        )?;
        let task_started = transition_claimed_work(&transaction, &row, token_value, claimed_at_ms)?;
        append_claim_events(
            &transaction,
            &commit,
            &row,
            correlation_id,
            token_value,
            claimed_at_ms,
            task_started,
        )?;
        let cursor = high_cursor(&transaction)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(LeaseClaimOutcome::Claimed(LeaseClaimReceipt {
            lease,
            task_id,
            turn_id,
            cursor,
        }))
    }

    fn heartbeat(&mut self, commit: HeartbeatCommit) -> Result<WorkLease, SchedulerStoreError> {
        let heartbeat_at_ms = epoch_milliseconds(commit.heartbeat_at)?;
        let expires_at_ms = epoch_milliseconds(commit.expires_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let changed = transaction
            .execute(
                "UPDATE work_lease SET heartbeat_at_ms = ?1, expires_at_ms = ?2 \
                 WHERE lease_id = ?3 AND run_id = ?4 AND owner_id = ?5 AND fencing_token = ?6 \
                   AND state = 'active' AND expires_at_ms > ?1 AND heartbeat_at_ms <= ?1 \
                   AND expires_at_ms < ?2 \
                   AND EXISTS(SELECT 1 FROM run WHERE id = ?4 AND current_fencing_token = ?6)",
                params![
                    heartbeat_at_ms,
                    expires_at_ms,
                    commit.fence.lease_id().to_string(),
                    commit.fence.run_id().to_string(),
                    commit.fence.owner_id().to_string(),
                    to_i64(commit.fence.fencing_token().get(), "fencing token")?,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(SchedulerStoreError::StaleFence);
        }
        let acquired_at_ms = transaction
            .query_row(
                "SELECT acquired_at_ms FROM work_lease WHERE lease_id = ?1",
                [commit.fence.lease_id().to_string()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(map_sqlite_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        hydrated_lease(commit.fence, acquired_at_ms, heartbeat_at_ms, expires_at_ms)
    }

    fn release(&mut self, commit: ReleaseLeaseCommit) -> Result<u64, SchedulerStoreError> {
        let released_at_ms = epoch_milliseconds(commit.released_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let token = to_i64(commit.fence.fencing_token().get(), "fencing token")?;
        let next_token = token
            .checked_add(1)
            .ok_or_else(|| invariant("release fencing token overflow"))?;
        let changed = transaction
            .execute(
                "UPDATE work_lease SET state = 'released', released_at_ms = ?1 \
                 WHERE lease_id = ?2 AND run_id = ?3 AND owner_id = ?4 AND fencing_token = ?5 \
                   AND state = 'active' AND heartbeat_at_ms <= ?1 AND expires_at_ms > ?1 \
                   AND EXISTS(SELECT 1 FROM run WHERE id = ?3 AND current_fencing_token = ?5)",
                params![
                    released_at_ms,
                    commit.fence.lease_id().to_string(),
                    commit.fence.run_id().to_string(),
                    commit.fence.owner_id().to_string(),
                    token,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(SchedulerStoreError::StaleFence);
        }
        let requeued = transaction
            .execute(
                "UPDATE run SET status = 'queued', revision = revision + 1, \
                                current_fencing_token = ?1, \
                                updated_at_ms = MAX(updated_at_ms, ?2) \
                 WHERE id = ?3 AND status = 'running' AND current_fencing_token = ?4",
                params![
                    next_token,
                    released_at_ms,
                    commit.fence.run_id().to_string(),
                    token
                ],
            )
            .map_err(map_sqlite_error)?;
        if requeued != 1 {
            return Err(SchedulerStoreError::StaleFence);
        }
        let run_id = commit.fence.run_id().to_string();
        let sequence = next_sequence(&transaction, "run", &run_id)?;
        append_event(
            &transaction,
            &EventAppend {
                event_id: commit.event_id,
                aggregate_kind: "run",
                aggregate_id: &run_id,
                sequence,
                event_type: "run.requeued",
                occurred_at_ms: released_at_ms,
                actor_id: None,
                correlation_id: commit.correlation_id,
                payload: json!({
                    "reason": commit.reason.as_str(),
                    "owner_id": commit.fence.owner_id(),
                    "invalidated_fencing_token": token,
                    "current_fencing_token": next_token,
                }),
            },
        )?;
        set_sequence(&transaction, "run", &run_id, sequence)?;
        let cursor = high_cursor(&transaction)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(cursor)
    }

    #[allow(clippy::too_many_lines)]
    fn complete_run(
        &mut self,
        commit: CompleteRunCommit,
    ) -> Result<RunCompletionReceipt, SchedulerStoreError> {
        let completed_at_ms = epoch_milliseconds(commit.completed_at)?;
        let token = to_i64(commit.fence.fencing_token().get(), "fencing token")?;
        let next_token = token
            .checked_add(1)
            .ok_or_else(|| invariant("completion fencing token overflow"))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let row = load_completion(&transaction, &commit, token, completed_at_ms)?;

        if let Some(message) = &commit.final_message {
            if commit.status != RunCompletionStatus::Succeeded {
                return Err(invariant(
                    "only a successful run may publish a final message",
                ));
            }
            insert_final_message(&transaction, &commit, &row, message, completed_at_ms)?;
        } else {
            settle_incomplete_agent_work(
                &transaction,
                commit.fence.run_id(),
                commit.status,
                completed_at_ms,
            )?;
        }

        let lease_changed = transaction
            .execute(
                "UPDATE work_lease SET state = 'released', released_at_ms = ?1 \
                 WHERE lease_id = ?2 AND run_id = ?3 AND owner_id = ?4 AND fencing_token = ?5 \
                   AND state = 'active' AND heartbeat_at_ms <= ?1 AND expires_at_ms > ?1",
                params![
                    completed_at_ms,
                    commit.fence.lease_id().to_string(),
                    commit.fence.run_id().to_string(),
                    commit.fence.owner_id().to_string(),
                    token,
                ],
            )
            .map_err(map_sqlite_error)?;
        let result_json = json!({
            "status": commit.status.as_str(),
            "summary": commit.summary,
        })
        .to_string();
        let run_changed = transaction
            .execute(
                "UPDATE run SET status = ?1, revision = revision + 1, \
                                current_fencing_token = ?2, updated_at_ms = ?3, \
                                completed_at_ms = ?3, result_json = ?4 \
                 WHERE id = ?5 AND status = 'running' AND revision = ?6 \
                   AND current_fencing_token = ?7",
                params![
                    commit.status.as_str(),
                    next_token,
                    completed_at_ms,
                    result_json,
                    commit.fence.run_id().to_string(),
                    row.run_revision,
                    token,
                ],
            )
            .map_err(map_sqlite_error)?;
        let task_changed = transaction
            .execute(
                "UPDATE task SET status = ?1, revision = revision + 1 \
                 WHERE id = ?2 AND status IN ('running', 'cancelling') AND revision = ?3",
                params![commit.status.as_str(), row.task_id, row.task_revision],
            )
            .map_err(map_sqlite_error)?;
        let session_changed = transaction
            .execute(
                "UPDATE session SET active_turn_id = NULL, revision = revision + 1, \
                                    updated_at_ms = MAX(updated_at_ms, ?1) \
                 WHERE id = ?2 AND active_turn_id = ?3 AND revision = ?4",
                params![
                    completed_at_ms,
                    row.session_id,
                    row.turn_id,
                    row.session_revision,
                ],
            )
            .map_err(map_sqlite_error)?;
        let turn_changed = transaction
            .execute(
                "UPDATE turn SET status = ?1, revision = revision + 1, completed_at_ms = ?2 \
                 WHERE id = ?3 AND status = 'active' AND revision = ?4",
                params![
                    commit.status.turn_status(),
                    completed_at_ms,
                    row.turn_id,
                    row.turn_revision,
                ],
            )
            .map_err(map_sqlite_error)?;
        if [
            lease_changed,
            run_changed,
            task_changed,
            session_changed,
            turn_changed,
        ] != [1, 1, 1, 1, 1]
        {
            return Err(SchedulerStoreError::StaleFence);
        }

        append_completion_events(&transaction, &commit, &row, completed_at_ms, next_token)?;
        transaction
            .execute(
                "INSERT INTO outbox(outbox_id, topic, payload_json, created_at_ms) \
                 VALUES (?1, 'session.turn_completed', ?2, ?3)",
                params![
                    commit.outbox_id.to_string(),
                    json!({
                        "session_id": row.session_id,
                        "turn_id": row.turn_id,
                        "task_id": row.task_id,
                        "run_id": commit.fence.run_id(),
                        "status": commit.status.as_str(),
                        "summary": commit.summary,
                    })
                    .to_string(),
                    completed_at_ms,
                ],
            )
            .map_err(map_sqlite_error)?;
        let cursor = high_cursor(&transaction)?;
        let receipt = RunCompletionReceipt {
            run_id: commit.fence.run_id(),
            task_id: parse_id(&row.task_id, "task ID")?,
            turn_id: parse_id(&row.turn_id, "turn ID")?,
            session_id: parse_id(&row.session_id, "session ID")?,
            outbox_id: commit.outbox_id,
            cursor,
        };
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(receipt)
    }
}

struct CompletionRow {
    task_id: String,
    turn_id: String,
    session_id: String,
    run_revision: i64,
    task_revision: i64,
    turn_revision: i64,
    session_revision: i64,
    principal_id: String,
}

fn load_completion(
    transaction: &Transaction<'_>,
    commit: &CompleteRunCommit,
    token: i64,
    completed_at_ms: i64,
) -> Result<CompletionRow, SchedulerStoreError> {
    transaction
        .query_row(
            "SELECT r.task_id, t.id, t.session_id, r.revision, task.revision, t.revision, \
                    s.revision, s.principal_id \
             FROM run r \
             JOIN task ON task.id = r.task_id \
             JOIN turn t ON t.run_id = r.id AND t.task_id = r.task_id \
             JOIN session s ON s.id = t.session_id AND s.active_turn_id = t.id \
             JOIN work_lease l ON l.run_id = r.id \
             WHERE r.id = ?1 AND r.status = 'running' AND r.current_fencing_token = ?2 \
               AND task.status IN ('running', 'cancelling') AND t.status = 'active' \
               AND l.lease_id = ?3 AND l.owner_id = ?4 AND l.fencing_token = ?2 \
               AND l.state = 'active' AND l.heartbeat_at_ms <= ?5 AND l.expires_at_ms > ?5 \
               AND (?6 <> 'succeeded' OR (task.status = 'running' \
                    AND r.cancellation_requested_at_ms IS NULL \
                    AND (NOT EXISTS(SELECT 1 FROM run_budget_usage WHERE run_id = r.id) \
                         OR EXISTS(SELECT 1 FROM run_budget_usage \
                                   WHERE run_id = r.id AND deadline_at_ms >= ?5))))",
            params![
                commit.fence.run_id().to_string(),
                token,
                commit.fence.lease_id().to_string(),
                commit.fence.owner_id().to_string(),
                completed_at_ms,
                commit.status.as_str(),
            ],
            |row| {
                Ok(CompletionRow {
                    task_id: row.get(0)?,
                    turn_id: row.get(1)?,
                    session_id: row.get(2)?,
                    run_revision: row.get(3)?,
                    task_revision: row.get(4)?,
                    turn_revision: row.get(5)?,
                    session_revision: row.get(6)?,
                    principal_id: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(SchedulerStoreError::StaleFence)
}

#[allow(clippy::too_many_lines)]
fn insert_final_message(
    transaction: &Transaction<'_>,
    commit: &CompleteRunCommit,
    row: &CompletionRow,
    message: &mealy_application::FinalMessageCommit,
    completed_at_ms: i64,
) -> Result<(), SchedulerStoreError> {
    let byte_length = i64::try_from(message.byte_length)
        .map_err(|_| invariant("final message byte length exceeds SQLite range"))?;
    if message.content.is_empty()
        || message.content.len() > 64 * 1024
        || message.byte_length != u64::try_from(message.content.len()).unwrap_or(u64::MAX)
        || sha256_digest(message.content.as_bytes()) != message.content_digest
    {
        return Err(invariant("final message content evidence is invalid"));
    }
    let response_json = transaction
        .query_row(
            "SELECT response_json FROM model_attempt \
             WHERE attempt_id = ?1 AND run_id = ?2 AND state = 'completed' \
               AND response_kind = 'final'",
            params![
                message.source_attempt_id.to_string(),
                commit.fence.run_id().to_string()
            ],
            |result| result.get::<_, String>(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or_else(|| invariant("final message has no committed final model result"))?;
    let response: serde_json::Value = serde_json::from_str(&response_json)
        .map_err(|_| invariant("stored final model response is invalid"))?;
    if response.get("kind").and_then(serde_json::Value::as_str) != Some("final")
        || response.get("text").and_then(serde_json::Value::as_str)
            != Some(message.content.as_str())
    {
        return Err(invariant(
            "final message differs from committed model result",
        ));
    }

    let ordinal = transaction
        .query_row(
            "SELECT COALESCE(MAX(ordinal), 0) + 1 FROM message WHERE turn_id = ?1",
            [row.turn_id.as_str()],
            |result| result.get::<_, i64>(0),
        )
        .map_err(map_sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO message(\
                id, principal_id, session_id, turn_id, task_id, run_id, ordinal, role, \
                media_type, byte_length, content_digest, content_inline, sensitivity, \
                source_attempt_id, created_at_ms\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'assistant', \
                       'text/plain; charset=utf-8', ?8, ?9, ?10, 'internal', ?11, ?12)",
            params![
                message.message_id.to_string(),
                row.principal_id,
                row.session_id,
                row.turn_id,
                row.task_id,
                commit.fence.run_id().to_string(),
                ordinal,
                byte_length,
                message.content_digest,
                message.content,
                message.source_attempt_id.to_string(),
                completed_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    let loop_changed = transaction
        .execute(
            "UPDATE run_loop_state \
             SET revision = revision + 1, next_action = 'terminal', final_message_id = ?1, \
                 updated_at_ms = ?2 \
             WHERE run_id = ?3 AND next_action = 'commit_final' AND current_attempt_id = ?4",
            params![
                message.message_id.to_string(),
                completed_at_ms,
                commit.fence.run_id().to_string(),
                message.source_attempt_id.to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    if loop_changed != 1 {
        return Err(invariant(
            "final message does not match the durable loop boundary",
        ));
    }

    let message_id = message.message_id.to_string();
    let sequence = next_sequence(transaction, "message", &message_id)?;
    append_event(
        transaction,
        &EventAppend {
            event_id: message.event_id,
            aggregate_kind: "message",
            aggregate_id: &message_id,
            sequence,
            event_type: "message.assistant.final",
            occurred_at_ms: completed_at_ms,
            actor_id: None,
            correlation_id: commit.correlation_id,
            payload: json!({
                "run_id": commit.fence.run_id(),
                "task_id": row.task_id,
                "turn_id": row.turn_id,
                "content_digest": message.content_digest,
                "byte_length": message.byte_length,
            }),
        },
    )?;
    set_sequence(transaction, "message", &message_id, sequence)?;
    Ok(())
}

fn settle_incomplete_agent_work(
    transaction: &Transaction<'_>,
    run_id: RunId,
    status: RunCompletionStatus,
    completed_at_ms: i64,
) -> Result<(), SchedulerStoreError> {
    let reason = match status {
        RunCompletionStatus::Cancelled => "run_cancelled",
        RunCompletionStatus::Failed => "run_failed",
        RunCompletionStatus::Succeeded => return Ok(()),
    };
    let settlement = load_incomplete_work_settlement(transaction, run_id)?;
    let reservations_changed = transaction
        .execute(
            "UPDATE budget_reservation \
             SET state = CASE \
                    WHEN (SELECT state FROM model_attempt \
                          WHERE attempt_id = budget_reservation.attempt_id) = 'prepared' \
                    THEN 'released' ELSE 'charged_unknown' END, \
                 settled_at_ms = ?1 \
             WHERE state = 'active' AND attempt_id IN (\
                 SELECT attempt_id FROM model_attempt \
                 WHERE run_id = ?2 AND state IN ('prepared', 'dispatching'))",
            params![completed_at_ms, run_id.to_string()],
        )
        .map_err(map_sqlite_error)?;
    let attempts_changed = transaction
        .execute(
            "UPDATE model_attempt SET \
                state = CASE WHEN state = 'prepared' THEN 'cancelled' ELSE 'interrupted' END, \
                completed_at_ms = ?1, \
                error_class = CASE WHEN state = 'prepared' THEN NULL ELSE ?2 END, \
                error_message = CASE WHEN state = 'prepared' THEN NULL \
                                     ELSE 'run terminated before a normalized result committed' END, \
                retryable = 0 \
             WHERE run_id = ?3 AND state IN ('prepared', 'dispatching')",
            params![completed_at_ms, reason, run_id.to_string()],
        )
        .map_err(map_sqlite_error)?;
    let tools_changed = transaction
        .execute(
            "UPDATE tool_call SET \
                state = CASE WHEN state = 'prepared' THEN 'cancelled' ELSE 'interrupted' END, \
                completed_at_ms = ?1, \
                error_class = CASE WHEN state = 'prepared' THEN NULL ELSE ?2 END, \
                error_message = CASE WHEN state = 'prepared' THEN NULL \
                                     ELSE 'run terminated before tool evidence committed' END \
             WHERE run_id = ?3 AND state IN ('prepared', 'running')",
            params![completed_at_ms, reason, run_id.to_string()],
        )
        .map_err(map_sqlite_error)?;
    let model = &settlement.model;
    let budget_changed = transaction
        .execute(
            "UPDATE run_budget_usage SET revision = revision + 1, \
                used_model_calls = used_model_calls + ?1, \
                used_tool_calls = used_tool_calls + ?2, \
                used_input_tokens = used_input_tokens + ?3, \
                used_output_tokens = used_output_tokens + ?4, \
                used_cost_microunits = used_cost_microunits + ?5, \
                used_output_bytes = used_output_bytes + ?6, \
                reserved_model_calls = 0, reserved_tool_calls = 0, \
                reserved_input_tokens = 0, reserved_output_tokens = 0, \
                reserved_cost_microunits = 0, reserved_output_bytes = 0 \
             WHERE run_id = ?7 \
               AND reserved_model_calls = ?8 AND reserved_tool_calls = ?9 \
               AND reserved_input_tokens = ?10 AND reserved_output_tokens = ?11 \
               AND reserved_cost_microunits = ?12 AND reserved_output_bytes = ?13",
            params![
                model.charged_calls,
                settlement.charged_tool_calls,
                model.charged_input_tokens,
                model.charged_output_tokens,
                model.charged_cost_microunits,
                model.charged_output_bytes,
                run_id.to_string(),
                model.reserved_calls,
                settlement.reserved_tool_calls,
                model.reserved_input_tokens,
                model.reserved_output_tokens,
                model.reserved_cost_microunits,
                model.reserved_output_bytes,
            ],
        )
        .map_err(map_sqlite_error)?;
    let expected_model = usize::try_from(model.reserved_calls)
        .map_err(|_| invariant("active model reservation count is invalid"))?;
    let expected_read_tools = usize::try_from(settlement.incomplete_read_tool_calls)
        .map_err(|_| invariant("incomplete read-tool count is invalid"))?;
    if reservations_changed != expected_model
        || attempts_changed != expected_model
        || tools_changed != expected_read_tools
        || (settlement.has_agent_budget && budget_changed != 1)
    {
        return Err(invariant(
            "incomplete agent work and its reservations were not current together",
        ));
    }
    Ok(())
}

fn load_incomplete_work_settlement(
    transaction: &Transaction<'_>,
    run_id: RunId,
) -> Result<IncompleteWorkSettlement, SchedulerStoreError> {
    let model = transaction
        .query_row(
            "SELECT \
                COALESCE(SUM(br.model_calls), 0), \
                COALESCE(SUM(br.input_tokens), 0), \
                COALESCE(SUM(br.output_tokens), 0), \
                COALESCE(SUM(br.cost_microunits), 0), \
                COALESCE(SUM(br.output_bytes), 0), \
                COALESCE(SUM(CASE WHEN ma.state = 'dispatching' THEN br.model_calls ELSE 0 END), 0), \
                COALESCE(SUM(CASE WHEN ma.state = 'dispatching' THEN br.input_tokens ELSE 0 END), 0), \
                COALESCE(SUM(CASE WHEN ma.state = 'dispatching' THEN br.output_tokens ELSE 0 END), 0), \
                COALESCE(SUM(CASE WHEN ma.state = 'dispatching' THEN br.cost_microunits ELSE 0 END), 0), \
                COALESCE(SUM(CASE WHEN ma.state = 'dispatching' THEN br.output_bytes ELSE 0 END), 0) \
             FROM model_attempt ma \
             JOIN budget_reservation br ON br.attempt_id = ma.attempt_id AND br.state = 'active' \
             WHERE ma.run_id = ?1 AND ma.state IN ('prepared', 'dispatching')",
            [run_id.to_string()],
            |row| {
                Ok(IncompleteModelSettlement {
                    reserved_calls: row.get(0)?,
                    reserved_input_tokens: row.get(1)?,
                    reserved_output_tokens: row.get(2)?,
                    reserved_cost_microunits: row.get(3)?,
                    reserved_output_bytes: row.get(4)?,
                    charged_calls: row.get(5)?,
                    charged_input_tokens: row.get(6)?,
                    charged_output_tokens: row.get(7)?,
                    charged_cost_microunits: row.get(8)?,
                    charged_output_bytes: row.get(9)?,
                })
            },
        )
        .map_err(map_sqlite_error)?;
    let (incomplete_read_tool_calls, charged_read_tool_calls, incomplete_effect_calls) =
        transaction
            .query_row(
                "SELECT \
                (SELECT COUNT(*) FROM tool_call \
                 WHERE run_id = ?1 AND state IN ('prepared', 'running')), \
                (SELECT COALESCE(SUM(CASE WHEN state = 'running' THEN 1 ELSE 0 END), 0) \
                 FROM tool_call WHERE run_id = ?1 AND state IN ('prepared', 'running')), \
                (SELECT COUNT(*) FROM agent_effect_invocation invocation \
                 WHERE invocation.run_id = ?1 \
                   AND NOT EXISTS(SELECT 1 FROM agent_effect_observation observation \
                                  WHERE observation.effect_id = invocation.effect_id))",
                [run_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .map_err(map_sqlite_error)?;
    let reserved_tool_calls = incomplete_read_tool_calls
        .checked_add(incomplete_effect_calls)
        .ok_or_else(|| invariant("active tool reservation count overflow"))?;
    let charged_tool_calls = charged_read_tool_calls
        .checked_add(incomplete_effect_calls)
        .ok_or_else(|| invariant("charged tool-call count overflow"))?;
    let invalid_active_reservations = transaction
        .query_row(
            "SELECT COUNT(*) FROM budget_reservation br \
             JOIN model_attempt ma ON ma.attempt_id = br.attempt_id \
             WHERE ma.run_id = ?1 AND br.state = 'active' \
               AND ma.state NOT IN ('prepared', 'dispatching')",
            [run_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .map_err(map_sqlite_error)?;
    if invalid_active_reservations != 0 {
        return Err(invariant(
            "active budget reservation is not attached to incomplete model work",
        ));
    }
    let has_agent_budget = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM run_budget_usage WHERE run_id = ?1)",
            [run_id.to_string()],
            |row| row.get::<_, bool>(0),
        )
        .map_err(map_sqlite_error)?;
    Ok(IncompleteWorkSettlement {
        model,
        reserved_tool_calls,
        charged_tool_calls,
        incomplete_read_tool_calls,
        has_agent_budget,
    })
}

struct IncompleteWorkSettlement {
    model: IncompleteModelSettlement,
    reserved_tool_calls: i64,
    charged_tool_calls: i64,
    incomplete_read_tool_calls: i64,
    has_agent_budget: bool,
}

struct IncompleteModelSettlement {
    reserved_calls: i64,
    reserved_input_tokens: i64,
    reserved_output_tokens: i64,
    reserved_cost_microunits: i64,
    reserved_output_bytes: i64,
    charged_calls: i64,
    charged_input_tokens: i64,
    charged_output_tokens: i64,
    charged_cost_microunits: i64,
    charged_output_bytes: i64,
}

fn append_completion_events(
    transaction: &Transaction<'_>,
    commit: &CompleteRunCommit,
    row: &CompletionRow,
    completed_at_ms: i64,
    current_token: i64,
) -> Result<(), SchedulerStoreError> {
    let run_id = commit.fence.run_id().to_string();
    let entries = [
        (
            commit.run_event_id,
            "run",
            run_id.as_str(),
            completion_event_type("run", commit.status),
            json!({
                "status": commit.status.as_str(),
                "summary": commit.summary,
                "owner_id": commit.fence.owner_id(),
                "invalidated_fencing_token": commit.fence.fencing_token().get(),
                "current_fencing_token": current_token,
            }),
        ),
        (
            commit.task_event_id,
            "task",
            row.task_id.as_str(),
            completion_event_type("task", commit.status),
            json!({ "run_id": run_id, "status": commit.status.as_str() }),
        ),
        (
            commit.turn_event_id,
            "turn",
            row.turn_id.as_str(),
            completion_event_type("turn", commit.status),
            json!({ "run_id": run_id, "status": commit.status.turn_status() }),
        ),
        (
            commit.session_event_id,
            "session",
            row.session_id.as_str(),
            completion_event_type("session", commit.status),
            json!({
                "turn_id": row.turn_id,
                "run_id": run_id,
                "status": commit.status.turn_status(),
            }),
        ),
    ];
    for (event_id, kind, id, event_type, payload) in entries {
        let sequence = next_sequence(transaction, kind, id)?;
        append_event(
            transaction,
            &EventAppend {
                event_id,
                aggregate_kind: kind,
                aggregate_id: id,
                sequence,
                event_type,
                occurred_at_ms: completed_at_ms,
                actor_id: None,
                correlation_id: commit.correlation_id,
                payload,
            },
        )?;
        set_sequence(transaction, kind, id, sequence)?;
    }
    Ok(())
}

fn completion_event_type(kind: &str, status: RunCompletionStatus) -> &'static str {
    match (kind, status) {
        ("run", RunCompletionStatus::Succeeded) => "run.succeeded",
        ("run", RunCompletionStatus::Failed) => "run.failed",
        ("run", RunCompletionStatus::Cancelled) => "run.cancelled",
        ("task", RunCompletionStatus::Succeeded) => "task.succeeded",
        ("task", RunCompletionStatus::Failed) => "task.failed",
        ("task", RunCompletionStatus::Cancelled) => "task.cancelled",
        ("turn" | "session", RunCompletionStatus::Succeeded) => "turn.completed",
        ("turn" | "session", RunCompletionStatus::Failed) => "turn.failed",
        ("turn" | "session", RunCompletionStatus::Cancelled) => "turn.cancelled",
        _ => "completion.invalid",
    }
}

struct RunnableRow {
    run_id: String,
    task_id: String,
    turn_id: String,
    correlation_id: String,
    current_fencing_token: i64,
    task_status: String,
}

fn load_runnable(
    transaction: &Transaction<'_>,
    now_ms: i64,
    limits: mealy_application::LeaseConcurrencyLimits,
) -> Result<Option<RunnableRow>, SchedulerStoreError> {
    transaction
        .query_row(
            "SELECT r.id, r.task_id, t.id, r.correlation_id, r.current_fencing_token, task.status \
             FROM run r JOIN turn t ON t.run_id = r.id JOIN task ON task.id = r.task_id \
             JOIN session candidate_session ON candidate_session.id = t.session_id \
             WHERE r.status = 'queued' \
               AND task.status IN ('queued', 'running', 'cancelling') \
               AND (r.next_attempt_at_ms IS NULL OR r.next_attempt_at_ms <= ?1) \
               AND NOT EXISTS(SELECT 1 FROM work_lease l WHERE l.run_id = r.id AND l.state = 'active') \
               AND (SELECT COUNT(*) FROM work_lease active \
                    JOIN run active_run ON active_run.id = active.run_id \
                    JOIN turn active_turn ON active_turn.run_id = active_run.id \
                    JOIN session active_session ON active_session.id = active_turn.session_id \
                    WHERE active.state = 'active' AND active.expires_at_ms > ?1 \
                      AND active_session.principal_id = candidate_session.principal_id) < ?2 \
               AND (SELECT COUNT(*) FROM work_lease active \
                    JOIN run active_run ON active_run.id = active.run_id \
                    JOIN turn active_turn ON active_turn.run_id = active_run.id \
                    WHERE active.state = 'active' AND active.expires_at_ms > ?1 \
                      AND active_turn.session_id = candidate_session.id) < ?3 \
               AND (SELECT COUNT(*) FROM work_lease active \
                    JOIN run active_run ON active_run.id = active.run_id \
                    WHERE active.state = 'active' AND active.expires_at_ms > ?1 \
                      AND active_run.agent_role = r.agent_role) < ?4 \
             ORDER BY COALESCE(r.next_attempt_at_ms, r.created_at_ms), r.created_at_ms, r.id LIMIT 1",
            params![
                now_ms,
                i64::from(limits.maximum_per_principal),
                i64::from(limits.maximum_per_session),
                i64::from(limits.maximum_per_agent_role),
            ],
            |row| {
                Ok(RunnableRow {
                    run_id: row.get(0)?,
                    task_id: row.get(1)?,
                    turn_id: row.get(2)?,
                    correlation_id: row.get(3)?,
                    current_fencing_token: row.get(4)?,
                    task_status: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)
}

fn insert_lease(
    transaction: &Transaction<'_>,
    commit: &LeaseClaimCommit,
    row: &RunnableRow,
    token: i64,
    claimed_at_ms: i64,
    expires_at_ms: i64,
) -> Result<(), SchedulerStoreError> {
    transaction
        .execute(
            "INSERT INTO work_lease(\
                lease_id, run_id, owner_id, fencing_token, state, acquired_at_ms, heartbeat_at_ms, \
                expires_at_ms\
             ) VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?5, ?6)",
            params![
                commit.lease_id.to_string(),
                row.run_id,
                commit.owner_id.to_string(),
                token,
                claimed_at_ms,
                expires_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn transition_claimed_work(
    transaction: &Transaction<'_>,
    row: &RunnableRow,
    token: i64,
    claimed_at_ms: i64,
) -> Result<bool, SchedulerStoreError> {
    let run_changed = transaction
        .execute(
            "UPDATE run SET status = 'running', revision = revision + 1, \
                            current_fencing_token = ?1, updated_at_ms = MAX(updated_at_ms, ?2) \
             WHERE id = ?3 AND status = 'queued' AND current_fencing_token = ?4",
            params![token, claimed_at_ms, row.run_id, row.current_fencing_token],
        )
        .map_err(map_sqlite_error)?;
    if run_changed != 1 {
        return Err(SchedulerStoreError::Conflict);
    }
    match row.task_status.as_str() {
        "queued" => {
            let changed = transaction
                .execute(
                    "UPDATE task SET status = 'running', revision = revision + 1 \
                     WHERE id = ?1 AND status = 'queued'",
                    [row.task_id.as_str()],
                )
                .map_err(map_sqlite_error)?;
            if changed == 1 {
                Ok(true)
            } else {
                Err(SchedulerStoreError::Conflict)
            }
        }
        "running" | "cancelling" => Ok(false),
        _ => Err(invariant("queued run belongs to a non-runnable task")),
    }
}

#[allow(clippy::too_many_arguments)]
fn append_claim_events(
    transaction: &Transaction<'_>,
    commit: &LeaseClaimCommit,
    row: &RunnableRow,
    correlation_id: CorrelationId,
    token: i64,
    claimed_at_ms: i64,
    task_started: bool,
) -> Result<(), SchedulerStoreError> {
    let run_sequence = next_sequence(transaction, "run", &row.run_id)?;
    append_event(
        transaction,
        &EventAppend {
            event_id: commit.run_event_id,
            aggregate_kind: "run",
            aggregate_id: &row.run_id,
            sequence: run_sequence,
            event_type: "run.started",
            occurred_at_ms: claimed_at_ms,
            actor_id: None,
            correlation_id,
            payload: json!({
                "lease_id": commit.lease_id,
                "owner_id": commit.owner_id,
                "fencing_token": token,
                "expires_at_ms": epoch_milliseconds(commit.expires_at)?,
            }),
        },
    )?;
    set_sequence(transaction, "run", &row.run_id, run_sequence)?;
    if task_started {
        let task_sequence = next_sequence(transaction, "task", &row.task_id)?;
        append_event(
            transaction,
            &EventAppend {
                event_id: commit.task_event_id,
                aggregate_kind: "task",
                aggregate_id: &row.task_id,
                sequence: task_sequence,
                event_type: "task.started",
                occurred_at_ms: claimed_at_ms,
                actor_id: None,
                correlation_id,
                payload: json!({ "run_id": row.run_id, "owner_id": commit.owner_id }),
            },
        )?;
        set_sequence(transaction, "task", &row.task_id, task_sequence)?;
    }
    Ok(())
}

struct EventAppend<'a> {
    event_id: mealy_domain::EventId,
    aggregate_kind: &'a str,
    aggregate_id: &'a str,
    sequence: i64,
    event_type: &'a str,
    occurred_at_ms: i64,
    actor_id: Option<String>,
    correlation_id: CorrelationId,
    payload: serde_json::Value,
}

fn append_event(
    transaction: &Transaction<'_>,
    event: &EventAppend<'_>,
) -> Result<(), SchedulerStoreError> {
    transaction
        .execute(
            "INSERT INTO journal_event(\
                event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                event_version, occurred_at_ms, actor_principal_id, correlation_id, sensitivity, \
                payload_json\
             ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, 'internal', ?9)",
            params![
                event.event_id.to_string(),
                event.aggregate_kind,
                event.aggregate_id,
                event.sequence,
                event.event_type,
                event.occurred_at_ms,
                event.actor_id,
                event.correlation_id.to_string(),
                event.payload.to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn next_sequence(
    transaction: &Transaction<'_>,
    kind: &str,
    id: &str,
) -> Result<i64, SchedulerStoreError> {
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
) -> Result<(), SchedulerStoreError> {
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

fn hydrated_lease(
    fence: LeaseFence,
    acquired_at_ms: i64,
    heartbeat_at_ms: i64,
    expires_at_ms: i64,
) -> Result<WorkLease, SchedulerStoreError> {
    let acquired_at = system_time(acquired_at_ms)?;
    let heartbeat_at = system_time(heartbeat_at_ms)?;
    let expires_at = system_time(expires_at_ms)?;
    WorkLease::rehydrate(
        fence,
        acquired_at,
        heartbeat_at,
        expires_at,
        LeaseStatus::Active,
    )
    .map_err(|error| invariant(error.to_string()))
}

fn high_cursor(transaction: &Transaction<'_>) -> Result<u64, SchedulerStoreError> {
    let value = transaction
        .query_row(
            "SELECT COALESCE(MAX(cursor), 0) FROM timeline_event",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(map_sqlite_error)?;
    u64::try_from(value).map_err(|_| invariant("timeline cursor is negative"))
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, SchedulerStoreError> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invariant("scheduler time precedes Unix epoch"))?;
    i64::try_from(duration.as_millis()).map_err(|_| invariant("timestamp exceeds SQLite range"))
}

fn system_time(value: i64) -> Result<SystemTime, SchedulerStoreError> {
    let value = u64::try_from(value).map_err(|_| invariant("stored timestamp is negative"))?;
    SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_millis(value))
        .ok_or_else(|| invariant("stored timestamp exceeds SystemTime"))
}

fn to_i64(value: u64, field: &str) -> Result<i64, SchedulerStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite range")))
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, SchedulerStoreError> {
    value
        .parse()
        .map_err(|_| invariant(format!("stored {field} is invalid")))
}

fn map_sqlite_error(error: rusqlite::Error) -> SchedulerStoreError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation =>
        {
            SchedulerStoreError::Conflict
        }
        other => SchedulerStoreError::Unavailable(other.to_string()),
    }
}

fn invariant(message: impl Into<String>) -> SchedulerStoreError {
    SchedulerStoreError::InvariantViolation(message.into())
}
