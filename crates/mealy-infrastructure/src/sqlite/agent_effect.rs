use super::{SqliteStore, agent};
use mealy_application::{
    AGENT_EFFECT_OBSERVATION_CONTRACT_VERSION, AgentEffectInvocation,
    AgentEffectObservationReceipt, AgentEffectStore, AgentNextAction, AgentStoreError,
    EffectAttemptState, ParkAgentEffectRunCommit, PolicyDecision, ProviderRequest,
    ProviderResponse, RecordAgentEffectObservationCommit, RecordAgentEffectProposalCommit,
    ResumeAgentEffectRunCommit, sha256_digest,
};
use mealy_domain::{ApprovalId, CorrelationId, EffectId, EffectStatus, TaskId};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use std::{str::FromStr, time::SystemTime};

const MAXIMUM_READY_EFFECTS: usize = 1_024;

impl AgentEffectStore for SqliteStore {
    fn expired_agent_effect_approvals(
        &self,
        observed_at: SystemTime,
        limit: usize,
    ) -> Result<Vec<ApprovalId>, AgentStoreError> {
        if limit == 0 || limit > MAXIMUM_READY_EFFECTS {
            return Err(AgentStoreError::Conflict);
        }
        let observed_at_ms = agent::epoch_milliseconds(observed_at)?;
        let limit = i64::try_from(limit)
            .map_err(|_| agent::invariant("expired approval limit exceeds SQLite range"))?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT approval.approval_id \
                 FROM approval_request approval \
                 JOIN agent_effect_invocation invocation \
                   ON invocation.effect_id = approval.effect_id \
                 JOIN run ON run.id = invocation.run_id AND run.task_id = invocation.task_id \
                 JOIN task ON task.id = invocation.task_id \
                 WHERE approval.status = 'pending' AND approval.expires_at_ms <= ?1 \
                   AND run.status = 'waiting' AND task.status = 'waiting' \
                 ORDER BY approval.expires_at_ms, approval.approval_id LIMIT ?2",
            )
            .map_err(agent::map_sqlite_error)?;
        statement
            .query_map(params![observed_at_ms, limit], |row| {
                row.get::<_, String>(0)
            })
            .map_err(agent::map_sqlite_error)?
            .map(|row| {
                let value = row.map_err(agent::map_sqlite_error)?;
                parse_id(&value, "expired approval ID")
            })
            .collect()
    }

    fn agent_effect_invocation(
        &self,
        fence: mealy_domain::LeaseFence,
        model_attempt_id: mealy_domain::AttemptId,
        observed_at: SystemTime,
    ) -> Result<Option<AgentEffectInvocation>, AgentStoreError> {
        let observed_at_ms = agent::epoch_milliseconds(observed_at)?;
        let owner =
            load_fenced_effect_owner(&self.connection, fence, model_attempt_id, observed_at_ms)?;
        load_invocation(&self.connection, model_attempt_id)?.map_or(Ok(None), |invocation| {
            if invocation.run_id != fence.run_id() || invocation.task_id != owner.task_id {
                return Err(agent::invariant(
                    "agent effect invocation diverged from its fenced owner",
                ));
            }
            Ok(Some(invocation))
        })
    }

    #[allow(clippy::too_many_lines)]
    fn record_agent_effect_proposal(
        &mut self,
        commit: RecordAgentEffectProposalCommit,
    ) -> Result<AgentEffectInvocation, AgentStoreError> {
        validate_proposal_commit(&commit)?;
        let parked_at_ms = agent::epoch_milliseconds(commit.parked_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(agent::map_sqlite_error)?;
        let owner = load_fenced_effect_owner(
            &transaction,
            commit.fence,
            commit.model_attempt_id,
            parked_at_ms,
        )?;
        if owner.task_id != commit.proposal.policy_request.task_id {
            return Err(AgentStoreError::Conflict);
        }

        let budget_changed = transaction
            .execute(
                "UPDATE run_budget_usage SET revision = revision + 1, \
                                             reserved_tool_calls = reserved_tool_calls + 1 \
                 WHERE run_id = ?1 AND cancellation_requested_at_ms IS NULL \
                   AND deadline_at_ms > ?2 \
                   AND used_tool_calls + reserved_tool_calls + 1 <= maximum_tool_calls",
                params![commit.fence.run_id().to_string(), parked_at_ms],
            )
            .map_err(agent::map_sqlite_error)?;
        if budget_changed != 1 {
            return Err(AgentStoreError::BudgetExceeded(
                "governed effect exceeds the effective run tool-call limit".to_owned(),
            ));
        }

        super::effects::record_effect_proposal_transaction(&transaction, &commit.proposal)
            .map_err(map_effect_error)?;
        transaction
            .execute(
                "INSERT INTO agent_effect_invocation(\
                    effect_id, run_id, task_id, model_attempt_id, tool_call_id, created_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    commit.proposal.effect_id.to_string(),
                    commit.fence.run_id().to_string(),
                    owner.task_id.to_string(),
                    commit.model_attempt_id.to_string(),
                    commit.tool_call_id.to_string(),
                    parked_at_ms,
                ],
            )
            .map_err(agent::map_sqlite_error)?;

        let token = i64::try_from(commit.fence.fencing_token().get())
            .map_err(|_| agent::invariant("agent effect fencing token exceeds SQLite range"))?;
        let next_token = token
            .checked_add(1)
            .ok_or_else(|| agent::invariant("agent effect fencing token overflow"))?;
        let lease_changed = transaction
            .execute(
                "UPDATE work_lease SET state = 'released', released_at_ms = ?1 \
                 WHERE lease_id = ?2 AND run_id = ?3 AND owner_id = ?4 AND fencing_token = ?5 \
                   AND state = 'active' AND acquired_at_ms <= ?1 AND ?1 < expires_at_ms",
                params![
                    parked_at_ms,
                    commit.fence.lease_id().to_string(),
                    commit.fence.run_id().to_string(),
                    commit.fence.owner_id().to_string(),
                    token,
                ],
            )
            .map_err(agent::map_sqlite_error)?;
        let run_changed = transaction
            .execute(
                "UPDATE run SET status = 'waiting', revision = revision + 1, \
                                current_fencing_token = ?1, updated_at_ms = MAX(updated_at_ms, ?2) \
                 WHERE id = ?3 AND task_id = ?4 AND status = 'running' \
                   AND current_fencing_token = ?5 AND cancellation_requested_at_ms IS NULL",
                params![
                    next_token,
                    parked_at_ms,
                    commit.fence.run_id().to_string(),
                    owner.task_id.to_string(),
                    token,
                ],
            )
            .map_err(agent::map_sqlite_error)?;
        let task_changed = transaction
            .execute(
                "UPDATE task SET status = 'waiting', revision = revision + 1 \
                 WHERE id = ?1 AND status = 'running'",
                [owner.task_id.to_string()],
            )
            .map_err(agent::map_sqlite_error)?;
        if [lease_changed, run_changed, task_changed] != [1, 1, 1] {
            return Err(AgentStoreError::StaleFence);
        }

        agent::append_agent_event(
            &transaction,
            commit.lease_event_id,
            "lease",
            &commit.fence.lease_id().to_string(),
            "lease.released_for_approval",
            parked_at_ms,
            owner.correlation_id,
            json!({
                "effect_id": commit.proposal.effect_id,
                "run_id": commit.fence.run_id(),
                "invalidated_fencing_token": token,
                "current_fencing_token": next_token,
            }),
        )?;
        agent::append_agent_event(
            &transaction,
            commit.run_event_id,
            "run",
            &commit.fence.run_id().to_string(),
            "run.waiting_for_approval",
            parked_at_ms,
            owner.correlation_id,
            json!({
                "effect_id": commit.proposal.effect_id,
                "approval_id": commit
                    .proposal
                    .approval
                    .as_ref()
                    .map(|approval| approval.approval_id),
            }),
        )?;
        agent::append_agent_event(
            &transaction,
            commit.task_event_id,
            "task",
            &owner.task_id.to_string(),
            "task.waiting_for_approval",
            parked_at_ms,
            owner.correlation_id,
            json!({
                "effect_id": commit.proposal.effect_id,
                "run_id": commit.fence.run_id(),
            }),
        )?;
        agent::append_checkpoint(
            &transaction,
            commit.fence.run_id(),
            AgentNextAction::ConsumeModelResult,
            None,
            Some(commit.model_attempt_id.to_string()),
            None,
            commit.checkpoint_event_id,
            parked_at_ms,
            owner.correlation_id,
            json!({
                "reason": "effect_proposed_waiting_for_approval",
                "effect_id": commit.proposal.effect_id,
                "tool_call_id": commit.tool_call_id,
            }),
        )?;
        let invocation = AgentEffectInvocation {
            effect_id: commit.proposal.effect_id,
            run_id: commit.fence.run_id(),
            task_id: owner.task_id,
            model_attempt_id: commit.model_attempt_id,
            tool_call_id: commit.tool_call_id,
        };
        transaction.commit().map_err(agent::map_sqlite_error)?;
        Ok(invocation)
    }

    fn ready_agent_effects(
        &self,
        observed_at: SystemTime,
        limit: usize,
    ) -> Result<Vec<EffectId>, AgentStoreError> {
        if limit == 0 || limit > MAXIMUM_READY_EFFECTS {
            return Err(AgentStoreError::Conflict);
        }
        let observed_at_ms = agent::epoch_milliseconds(observed_at)?;
        let limit = i64::try_from(limit)
            .map_err(|_| agent::invariant("ready effect limit exceeds SQLite range"))?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT invocation.effect_id \
                 FROM agent_effect_invocation invocation \
                 JOIN effect ON effect.id = invocation.effect_id \
                 JOIN run ON run.id = invocation.run_id AND run.task_id = invocation.task_id \
                 JOIN task ON task.id = invocation.task_id \
                 LEFT JOIN approval_request approval ON approval.effect_id = effect.id \
                 WHERE run.status = 'waiting' AND task.status = 'waiting' \
                   AND NOT EXISTS(SELECT 1 FROM work_lease lease \
                                  WHERE lease.run_id = run.id AND lease.state = 'active') \
                   AND NOT EXISTS(SELECT 1 FROM agent_effect_observation observation \
                                  WHERE observation.effect_id = effect.id) \
                   AND (effect.status IN ('denied', 'succeeded', 'failed', 'compensated') \
                        OR (effect.status = 'authorized' AND approval.status = 'approved' \
                            AND ?1 < approval.expires_at_ms)) \
                 ORDER BY invocation.created_at_ms, invocation.effect_id LIMIT ?2",
            )
            .map_err(agent::map_sqlite_error)?;
        statement
            .query_map(params![observed_at_ms, limit], |row| {
                row.get::<_, String>(0)
            })
            .map_err(agent::map_sqlite_error)?
            .map(|row| {
                let value = row.map_err(agent::map_sqlite_error)?;
                parse_id(&value, "ready effect ID")
            })
            .collect()
    }

    fn resume_agent_effect_run(
        &mut self,
        commit: ResumeAgentEffectRunCommit,
    ) -> Result<bool, AgentStoreError> {
        let resumed_at_ms = agent::epoch_milliseconds(commit.resumed_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(agent::map_sqlite_error)?;
        let ready = transaction
            .query_row(
                "SELECT invocation.run_id, invocation.task_id \
                 FROM agent_effect_invocation invocation \
                 JOIN effect ON effect.id = invocation.effect_id \
                 JOIN run ON run.id = invocation.run_id AND run.task_id = invocation.task_id \
                 JOIN task ON task.id = invocation.task_id \
                 LEFT JOIN approval_request approval ON approval.effect_id = effect.id \
                 WHERE invocation.effect_id = ?1 AND run.status = 'waiting' \
                   AND task.status = 'waiting' \
                   AND NOT EXISTS(SELECT 1 FROM work_lease lease \
                                  WHERE lease.run_id = run.id AND lease.state = 'active') \
                   AND NOT EXISTS(SELECT 1 FROM agent_effect_observation observation \
                                  WHERE observation.effect_id = effect.id) \
                   AND (effect.status IN ('denied', 'succeeded', 'failed', 'compensated') \
                        OR (effect.status = 'authorized' AND approval.status = 'approved' \
                            AND ?2 < approval.expires_at_ms))",
                params![commit.effect_id.to_string(), resumed_at_ms],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(agent::map_sqlite_error)?;
        let Some((run_id, task_id)) = ready else {
            return Ok(false);
        };
        let run_changed = transaction
            .execute(
                "UPDATE run SET status = 'queued', revision = revision + 1, \
                                next_attempt_at_ms = NULL, updated_at_ms = MAX(updated_at_ms, ?1) \
                 WHERE id = ?2 AND task_id = ?3 AND status = 'waiting'",
                params![resumed_at_ms, run_id, task_id],
            )
            .map_err(agent::map_sqlite_error)?;
        let task_changed = transaction
            .execute(
                "UPDATE task SET status = 'queued', revision = revision + 1 \
                 WHERE id = ?1 AND status = 'waiting'",
                [task_id.as_str()],
            )
            .map_err(agent::map_sqlite_error)?;
        if [run_changed, task_changed] != [1, 1] {
            return Err(AgentStoreError::Conflict);
        }
        agent::append_agent_event(
            &transaction,
            commit.run_event_id,
            "run",
            &run_id,
            "run.effect_ready",
            resumed_at_ms,
            commit.correlation_id,
            json!({"effect_id": commit.effect_id}),
        )?;
        agent::append_agent_event(
            &transaction,
            commit.task_event_id,
            "task",
            &task_id,
            "task.effect_ready",
            resumed_at_ms,
            commit.correlation_id,
            json!({"effect_id": commit.effect_id, "run_id": run_id}),
        )?;
        transaction.commit().map_err(agent::map_sqlite_error)?;
        Ok(true)
    }

    #[allow(clippy::too_many_lines)]
    fn park_agent_effect_run(
        &mut self,
        commit: ParkAgentEffectRunCommit,
    ) -> Result<(), AgentStoreError> {
        let parked_at_ms = agent::epoch_milliseconds(commit.parked_at)?;
        let token = i64::try_from(commit.fence.fencing_token().get())
            .map_err(|_| agent::invariant("agent effect fencing token exceeds SQLite range"))?;
        let next_token = token
            .checked_add(1)
            .ok_or_else(|| agent::invariant("agent effect fencing token overflow"))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(agent::map_sqlite_error)?;
        let task_id = transaction
            .query_row(
                "SELECT invocation.task_id \
                 FROM agent_effect_invocation invocation \
                 JOIN effect ON effect.id = invocation.effect_id \
                 JOIN run ON run.id = invocation.run_id AND run.task_id = invocation.task_id \
                 JOIN task ON task.id = invocation.task_id \
                 JOIN work_lease lease ON lease.run_id = run.id \
                 WHERE invocation.effect_id = ?1 AND invocation.run_id = ?2 \
                   AND effect.status = 'outcome_unknown' AND run.status = 'running' \
                   AND task.status = 'running' AND run.current_fencing_token = ?3 \
                   AND lease.lease_id = ?4 AND lease.owner_id = ?5 \
                   AND lease.fencing_token = ?3 AND lease.state = 'active' \
                   AND lease.acquired_at_ms <= ?6 AND ?6 < lease.expires_at_ms",
                params![
                    commit.effect_id.to_string(),
                    commit.fence.run_id().to_string(),
                    token,
                    commit.fence.lease_id().to_string(),
                    commit.fence.owner_id().to_string(),
                    parked_at_ms,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(agent::map_sqlite_error)?
            .ok_or(AgentStoreError::StaleFence)?;
        let lease_changed = transaction
            .execute(
                "UPDATE work_lease SET state = 'released', released_at_ms = ?1 \
                 WHERE lease_id = ?2 AND run_id = ?3 AND owner_id = ?4 AND fencing_token = ?5 \
                   AND state = 'active' AND ?1 < expires_at_ms",
                params![
                    parked_at_ms,
                    commit.fence.lease_id().to_string(),
                    commit.fence.run_id().to_string(),
                    commit.fence.owner_id().to_string(),
                    token,
                ],
            )
            .map_err(agent::map_sqlite_error)?;
        let run_changed = transaction
            .execute(
                "UPDATE run SET status = 'waiting', revision = revision + 1, \
                                current_fencing_token = ?1, updated_at_ms = MAX(updated_at_ms, ?2) \
                 WHERE id = ?3 AND task_id = ?4 AND status = 'running' \
                   AND current_fencing_token = ?5",
                params![
                    next_token,
                    parked_at_ms,
                    commit.fence.run_id().to_string(),
                    task_id,
                    token,
                ],
            )
            .map_err(agent::map_sqlite_error)?;
        let task_changed = transaction
            .execute(
                "UPDATE task SET status = 'waiting', revision = revision + 1 \
                 WHERE id = ?1 AND status = 'running'",
                [task_id.as_str()],
            )
            .map_err(agent::map_sqlite_error)?;
        if [lease_changed, run_changed, task_changed] != [1, 1, 1] {
            return Err(AgentStoreError::StaleFence);
        }
        agent::append_agent_event(
            &transaction,
            commit.lease_event_id,
            "lease",
            &commit.fence.lease_id().to_string(),
            "lease.released_for_reconciliation",
            parked_at_ms,
            commit.correlation_id,
            json!({
                "effect_id": commit.effect_id,
                "invalidated_fencing_token": token,
                "current_fencing_token": next_token,
            }),
        )?;
        agent::append_agent_event(
            &transaction,
            commit.run_event_id,
            "run",
            &commit.fence.run_id().to_string(),
            "run.waiting_for_reconciliation",
            parked_at_ms,
            commit.correlation_id,
            json!({"effect_id": commit.effect_id}),
        )?;
        agent::append_agent_event(
            &transaction,
            commit.task_event_id,
            "task",
            &task_id,
            "task.waiting_for_reconciliation",
            parked_at_ms,
            commit.correlation_id,
            json!({"effect_id": commit.effect_id, "run_id": commit.fence.run_id()}),
        )?;
        transaction.commit().map_err(agent::map_sqlite_error)
    }

    #[allow(clippy::too_many_lines)]
    fn record_agent_effect_observation(
        &mut self,
        commit: RecordAgentEffectObservationCommit,
    ) -> Result<AgentEffectObservationReceipt, AgentStoreError> {
        let observed_at_ms = agent::epoch_milliseconds(commit.observed_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(agent::map_sqlite_error)?;
        let owner = load_fenced_effect_owner(
            &transaction,
            commit.fence,
            commit.model_attempt_id,
            observed_at_ms,
        )?;
        let invocation = load_invocation(&transaction, commit.model_attempt_id)?
            .ok_or(AgentStoreError::Conflict)?;
        if invocation.effect_id != commit.effect_id
            || invocation.run_id != commit.fence.run_id()
            || invocation.task_id != owner.task_id
            || invocation.tool_call_id != commit.tool_call_id
        {
            return Err(AgentStoreError::Conflict);
        }
        let projection = load_terminal_projection(&transaction, &invocation)?;
        let content = projection.content.to_string();
        let content_digest = sha256_digest(content.as_bytes());
        let byte_length = i64::try_from(content.len())
            .map_err(|_| agent::invariant("effect observation size exceeds SQLite range"))?;
        if content.len() > 65_536 {
            return Err(agent::invariant(
                "canonical effect observation exceeds message bound",
            ));
        }
        let budget_changed = transaction
            .execute(
                "UPDATE run_budget_usage SET revision = revision + 1, \
                    reserved_tool_calls = reserved_tool_calls - 1, \
                    used_tool_calls = used_tool_calls + 1, \
                    used_output_bytes = used_output_bytes + ?1 \
                 WHERE run_id = ?2 AND reserved_tool_calls >= 1 \
                   AND used_output_bytes + reserved_output_bytes + ?1 <= maximum_output_bytes",
                params![byte_length, commit.fence.run_id().to_string()],
            )
            .map_err(agent::map_sqlite_error)?;
        if budget_changed != 1 {
            return Err(AgentStoreError::BudgetExceeded(
                "governed effect observation exceeds the effective run output limit".to_owned(),
            ));
        }
        let ordinal = transaction
            .query_row(
                "SELECT COALESCE(MAX(ordinal), 0) + 1 FROM message WHERE turn_id = ?1",
                [owner.turn_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(agent::map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO message(\
                    id, principal_id, session_id, turn_id, task_id, run_id, ordinal, role, \
                    media_type, byte_length, content_digest, content_inline, sensitivity, \
                    source_effect_id, created_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'tool', 'application/json', ?8, ?9, ?10, \
                           'internal', ?11, ?12)",
                params![
                    commit.message_id.to_string(),
                    owner.principal_id,
                    owner.session_id,
                    owner.turn_id,
                    owner.task_id.to_string(),
                    commit.fence.run_id().to_string(),
                    ordinal,
                    byte_length,
                    content_digest,
                    content,
                    commit.effect_id.to_string(),
                    observed_at_ms,
                ],
            )
            .map_err(agent::map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO agent_effect_observation(\
                    effect_id, run_id, model_attempt_id, tool_call_id, message_id, \
                    effect_revision, content_json, content_digest, created_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    commit.effect_id.to_string(),
                    commit.fence.run_id().to_string(),
                    commit.model_attempt_id.to_string(),
                    commit.tool_call_id.to_string(),
                    commit.message_id.to_string(),
                    projection.effect_revision,
                    content,
                    content_digest,
                    observed_at_ms,
                ],
            )
            .map_err(agent::map_sqlite_error)?;
        let loop_changed = transaction
            .execute(
                "UPDATE run_loop_state SET revision = revision + 1, next_action = 'compile_context', \
                                           current_tool_call_id = NULL, updated_at_ms = ?1 \
                 WHERE run_id = ?2 AND next_action = 'consume_model_result' \
                   AND current_attempt_id = ?3",
                params![
                    observed_at_ms,
                    commit.fence.run_id().to_string(),
                    commit.model_attempt_id.to_string(),
                ],
            )
            .map_err(agent::map_sqlite_error)?;
        if loop_changed != 1 {
            return Err(AgentStoreError::Conflict);
        }
        agent::append_agent_event(
            &transaction,
            commit.event_id,
            "message",
            &commit.message_id.to_string(),
            "message.tool.effect_observed",
            observed_at_ms,
            owner.correlation_id,
            json!({
                "effect_id": commit.effect_id,
                "effect_revision": projection.effect_revision,
                "model_attempt_id": commit.model_attempt_id,
                "tool_call_id": commit.tool_call_id,
                "content_digest": content_digest,
            }),
        )?;
        agent::append_checkpoint(
            &transaction,
            commit.fence.run_id(),
            AgentNextAction::CompileContext,
            None,
            Some(commit.model_attempt_id.to_string()),
            None,
            commit.checkpoint_event_id,
            observed_at_ms,
            owner.correlation_id,
            json!({
                "reason": "effect_observation_committed",
                "effect_id": commit.effect_id,
                "message_id": commit.message_id,
                "content_digest": content_digest,
            }),
        )?;
        let cursor = agent::high_cursor(&transaction)?;
        let receipt = AgentEffectObservationReceipt {
            effect_id: commit.effect_id,
            message_id: commit.message_id,
            content,
            content_digest,
            effect_revision: u64::try_from(projection.effect_revision)
                .map_err(|_| agent::invariant("effect revision is negative"))?,
            cursor,
            duplicate: false,
        };
        transaction.commit().map_err(agent::map_sqlite_error)?;
        Ok(receipt)
    }
}

#[derive(Debug)]
pub(super) struct ReplayAgentEffect {
    pub(super) effect_id: String,
    pub(super) model_attempt_id: String,
    pub(super) tool_call_id: String,
    pub(super) tool_id: String,
    pub(super) arguments: Value,
    pub(super) target_resources: Vec<String>,
    pub(super) message_id: String,
    pub(super) content: String,
    pub(super) content_digest: String,
    pub(super) proposed_at_ms: i64,
    pub(super) observed_at_ms: i64,
}

/// Loads and re-verifies model origin, complete effect-ledger state, outcome evidence, canonical
/// observation, message provenance, and immutable journal linkage without invoking an executor.
#[allow(clippy::too_many_lines)]
pub(super) fn load_replay_agent_effects(
    connection: &rusqlite::Connection,
    run_id: mealy_domain::RunId,
) -> Result<Option<Vec<ReplayAgentEffect>>, AgentStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT invocation.effect_id, invocation.task_id, invocation.model_attempt_id, \
                    invocation.tool_call_id, invocation.created_at_ms, \
                    observation.message_id, observation.effect_revision, \
                    observation.content_json, observation.content_digest, \
                    observation.created_at_ms, message.role, message.media_type, \
                    message.byte_length, message.content_inline, message.content_artifact_id, \
                    message.content_digest, message.source_attempt_id, \
                    message.source_tool_call_id, message.source_effect_id, message.created_at_ms \
             FROM agent_effect_invocation invocation \
             LEFT JOIN agent_effect_observation observation \
               ON observation.effect_id = invocation.effect_id \
             LEFT JOIN message ON message.id = observation.message_id \
             WHERE invocation.run_id = ?1 \
             ORDER BY invocation.created_at_ms, invocation.effect_id",
        )
        .map_err(agent::map_sqlite_error)?;
    let rows = statement
        .query_map([run_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
                row.get::<_, Option<i64>>(12)?,
                row.get::<_, Option<String>>(13)?,
                row.get::<_, Option<String>>(14)?,
                row.get::<_, Option<String>>(15)?,
                row.get::<_, Option<String>>(16)?,
                row.get::<_, Option<String>>(17)?,
                row.get::<_, Option<String>>(18)?,
                row.get::<_, Option<i64>>(19)?,
            ))
        })
        .map_err(agent::map_sqlite_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(agent::map_sqlite_error)?;
    let mut effects = Vec::with_capacity(rows.len());
    for row in rows {
        let (
            effect_id_text,
            task_id_text,
            model_attempt_id,
            tool_call_id,
            proposed_at_ms,
            message_id,
            observed_revision,
            content,
            content_digest,
            observed_at_ms,
            message_role,
            media_type,
            byte_length,
            message_content,
            content_artifact_id,
            message_digest,
            source_attempt_id,
            source_tool_call_id,
            source_effect_id,
            message_created_at_ms,
        ) = row;
        let Some(message_id) = message_id else {
            return Ok(None);
        };
        let Some(observed_revision) = observed_revision else {
            return Ok(None);
        };
        let Some(content) = content else {
            return Ok(None);
        };
        let Some(content_digest) = content_digest else {
            return Ok(None);
        };
        let Some(observed_at_ms) = observed_at_ms else {
            return Ok(None);
        };
        let effect_id: EffectId = parse_id(&effect_id_text, "replay effect ID")?;
        let task_id: TaskId = parse_id(&task_id_text, "replay effect task ID")?;
        let view = super::effects::load_effect_view(connection, None, effect_id)
            .map_err(map_effect_error)?;
        if view.run_id != run_id
            || view.task_id != task_id
            || !matches!(
                view.status,
                EffectStatus::Denied
                    | EffectStatus::Succeeded
                    | EffectStatus::Failed
                    | EffectStatus::Compensated
            )
            || i64::try_from(view.revision).ok() != Some(observed_revision)
            || !matches!(
                view.policy_request.tool.tool_id.as_str(),
                mealy_application::FIXTURE_WRITE_FILE_TOOL_ID
                    | mealy_application::WORKSPACE_CREATE_FILE_TOOL_ID
                    | mealy_application::WORKSPACE_REPLACE_FILE_TOOL_ID
                    | mealy_application::WORKSPACE_MANAGE_PATH_TOOL_ID
                    | mealy_application::PROCESS_RUN_TOOL_ID
            )
            || !valid_replay_write_contract(&view)
        {
            return Ok(None);
        }
        if !verify_effect_model_origin(connection, run_id, &model_attempt_id, &tool_call_id, &view)?
            || !verify_terminal_effect_attempt(connection, effect_id, view.status)?
        {
            return Ok(None);
        }
        let invocation = AgentEffectInvocation {
            effect_id,
            run_id,
            task_id,
            model_attempt_id: parse_id(&model_attempt_id, "replay model attempt ID")?,
            tool_call_id: parse_id(&tool_call_id, "replay tool-call ID")?,
        };
        let projection = load_terminal_projection(connection, &invocation)?;
        let expected_content = projection.content.to_string();
        let expected_digest = sha256_digest(expected_content.as_bytes());
        if content != expected_content
            || content_digest != expected_digest
            || message_role.as_deref() != Some("tool")
            || media_type.as_deref() != Some("application/json")
            || byte_length.and_then(|value| usize::try_from(value).ok()) != Some(content.len())
            || message_content.as_deref() != Some(content.as_str())
            || content_artifact_id.is_some()
            || message_digest.as_deref() != Some(content_digest.as_str())
            || source_attempt_id.is_some()
            || source_tool_call_id.is_some()
            || source_effect_id.as_deref() != Some(effect_id_text.as_str())
            || message_created_at_ms != Some(observed_at_ms)
            || !verify_effect_observation_event(
                connection,
                &message_id,
                effect_id,
                observed_revision,
                &model_attempt_id,
                &tool_call_id,
                &content_digest,
                observed_at_ms,
            )?
            || !agent::verify_aggregate_sequence_chain(connection, "effect", &effect_id_text)?
        {
            return Ok(None);
        }
        effects.push(ReplayAgentEffect {
            effect_id: effect_id_text,
            model_attempt_id,
            tool_call_id,
            tool_id: view.policy_request.tool.tool_id.clone(),
            arguments: view.policy_request.normalized_arguments.clone(),
            target_resources: view.policy_request.target_resources.clone(),
            message_id,
            content,
            content_digest,
            proposed_at_ms,
            observed_at_ms,
        });
    }
    Ok(Some(effects))
}

fn valid_replay_write_contract(view: &mealy_application::EffectLedgerView) -> bool {
    let Some(approval) = view.approval.as_ref() else {
        return false;
    };
    let request = &view.policy_request;
    let effect_id = view.effect_id;
    if request.tool.tool_id == mealy_application::FIXTURE_WRITE_FILE_TOOL_ID {
        let Some(workspace_root) = request.workspace_roots.first() else {
            return false;
        };
        let grant = mealy_application::FixtureWritePolicyGrant {
            principal_id: request.principal_id,
            channel_binding_id: request.channel_binding_id,
            task_id: request.task_id,
            run_id: request.run_id,
            tool_descriptor_digest: request.tool.descriptor_digest.clone(),
            worker_identity_digest: request.tool.executable_identity_digest.clone(),
            workspace_root: workspace_root.clone(),
            capability: mealy_application::FIXTURE_WRITE_CAPABILITY.to_owned(),
            profile: mealy_domain::PolicyProfile::WorkspaceWrite,
            valid_from_ms: request.evaluated_at_ms,
            expires_at_ms: approval.subject.expires_at_ms,
        };
        return mealy_application::evaluate_fixture_write_policy(request, &grant)
            == view.policy_evaluation
            && mealy_application::fixture_write_approval_subject(
                effect_id,
                request,
                approval.subject.expires_at_ms,
            )
            .is_ok_and(|subject| subject == approval.subject);
    }
    let Some(workspace_id) = request
        .normalized_arguments
        .get("workspaceId")
        .and_then(Value::as_str)
    else {
        return false;
    };
    let Some(workspace_root) = request.workspace_roots.first() else {
        return false;
    };
    if request.tool.tool_id == mealy_application::PROCESS_RUN_TOOL_ID {
        let Some(command_id) = request
            .normalized_arguments
            .get("commandId")
            .and_then(Value::as_str)
        else {
            return false;
        };
        let command_prefix = format!("command://{command_id}@sha256:");
        let Some(command_identity_digest) = request
            .target_resources
            .iter()
            .find_map(|target| target.strip_prefix(&command_prefix))
            .filter(|digest| mealy_application::is_sha256_digest(digest))
        else {
            return false;
        };
        let grant = mealy_application::ProcessRunPolicyGrant {
            principal_id: request.principal_id,
            channel_binding_id: request.channel_binding_id,
            task_id: request.task_id,
            run_id: request.run_id,
            tool_descriptor_digest: request.tool.descriptor_digest.clone(),
            worker_identity_digest: request.tool.executable_identity_digest.clone(),
            command_id: command_id.to_owned(),
            command_identity_digest: command_identity_digest.to_owned(),
            workspace_id: workspace_id.to_owned(),
            workspace_root: workspace_root.clone(),
            valid_from_ms: request.evaluated_at_ms,
            expires_at_ms: approval.subject.expires_at_ms,
        };
        return mealy_application::evaluate_process_run_policy(request, &grant)
            == view.policy_evaluation
            && mealy_application::process_run_approval_subject(
                effect_id,
                request,
                approval.subject.expires_at_ms,
            )
            .is_ok_and(|subject| subject == approval.subject);
    }
    if request.tool.tool_id == mealy_application::WORKSPACE_REPLACE_FILE_TOOL_ID {
        return valid_replay_workspace_replace_contract(view, workspace_id, workspace_root);
    }
    if request.tool.tool_id == mealy_application::WORKSPACE_MANAGE_PATH_TOOL_ID {
        return valid_replay_workspace_manage_contract(view, workspace_id, workspace_root);
    }
    if request.tool.tool_id != mealy_application::WORKSPACE_CREATE_FILE_TOOL_ID {
        return false;
    }
    valid_replay_workspace_create_contract(view, workspace_id, workspace_root)
}

fn valid_replay_workspace_create_contract(
    view: &mealy_application::EffectLedgerView,
    workspace_id: &str,
    workspace_root: &str,
) -> bool {
    let Some(approval) = view.approval.as_ref() else {
        return false;
    };
    let request = &view.policy_request;
    let grant = mealy_application::WorkspaceCreatePolicyGrant {
        principal_id: request.principal_id,
        channel_binding_id: request.channel_binding_id,
        task_id: request.task_id,
        run_id: request.run_id,
        tool_descriptor_digest: request.tool.descriptor_digest.clone(),
        worker_identity_digest: request.tool.executable_identity_digest.clone(),
        workspace_id: workspace_id.to_owned(),
        workspace_root: workspace_root.to_owned(),
        valid_from_ms: request.evaluated_at_ms,
        expires_at_ms: approval.subject.expires_at_ms,
    };
    mealy_application::evaluate_workspace_create_policy(request, &grant) == view.policy_evaluation
        && mealy_application::workspace_create_approval_subject(
            view.effect_id,
            request,
            approval.subject.expires_at_ms,
        )
        .is_ok_and(|subject| subject == approval.subject)
}

fn valid_replay_workspace_replace_contract(
    view: &mealy_application::EffectLedgerView,
    workspace_id: &str,
    workspace_root: &str,
) -> bool {
    let Some(approval) = view.approval.as_ref() else {
        return false;
    };
    let request = &view.policy_request;
    let grant = mealy_application::WorkspaceReplacePolicyGrant {
        principal_id: request.principal_id,
        channel_binding_id: request.channel_binding_id,
        task_id: request.task_id,
        run_id: request.run_id,
        tool_descriptor_digest: request.tool.descriptor_digest.clone(),
        worker_identity_digest: request.tool.executable_identity_digest.clone(),
        workspace_id: workspace_id.to_owned(),
        workspace_root: workspace_root.to_owned(),
        valid_from_ms: request.evaluated_at_ms,
        expires_at_ms: approval.subject.expires_at_ms,
    };
    mealy_application::evaluate_workspace_replace_policy(request, &grant) == view.policy_evaluation
        && mealy_application::workspace_replace_approval_subject(
            view.effect_id,
            request,
            approval.subject.expires_at_ms,
        )
        .is_ok_and(|subject| subject == approval.subject)
}

fn valid_replay_workspace_manage_contract(
    view: &mealy_application::EffectLedgerView,
    workspace_id: &str,
    workspace_root: &str,
) -> bool {
    let Some(approval) = view.approval.as_ref() else {
        return false;
    };
    let request = &view.policy_request;
    let grant = mealy_application::WorkspaceManagePolicyGrant {
        principal_id: request.principal_id,
        channel_binding_id: request.channel_binding_id,
        task_id: request.task_id,
        run_id: request.run_id,
        tool_descriptor_digest: request.tool.descriptor_digest.clone(),
        worker_identity_digest: request.tool.executable_identity_digest.clone(),
        workspace_id: workspace_id.to_owned(),
        workspace_root: workspace_root.to_owned(),
        valid_from_ms: request.evaluated_at_ms,
        expires_at_ms: approval.subject.expires_at_ms,
    };
    mealy_application::evaluate_workspace_manage_policy(request, &grant) == view.policy_evaluation
        && mealy_application::workspace_manage_approval_subject(
            view.effect_id,
            request,
            approval.subject.expires_at_ms,
        )
        .is_ok_and(|subject| subject == approval.subject)
}

fn verify_effect_model_origin(
    connection: &rusqlite::Connection,
    run_id: mealy_domain::RunId,
    model_attempt_id: &str,
    tool_call_id: &str,
    view: &mealy_application::EffectLedgerView,
) -> Result<bool, AgentStoreError> {
    let row = connection
        .query_row(
            "SELECT request_json, request_digest, response_json, state, response_kind \
             FROM model_attempt WHERE attempt_id = ?1 AND run_id = ?2",
            params![model_attempt_id, run_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
        .map_err(agent::map_sqlite_error)?;
    let Some((stored_request_json, request_digest, response_json, state, response_kind)) = row
    else {
        return Ok(false);
    };
    let request_json = agent::decode_durable_json(
        &stored_request_json,
        agent::MAXIMUM_MODEL_REQUEST_JSON_BYTES,
    )
    .map_err(|()| agent::invariant("replay effect model request encoding is invalid"))?;
    if sha256_digest(request_json.as_bytes()) != request_digest {
        return Err(agent::invariant(
            "replay effect model request digest does not match",
        ));
    }
    let request = serde_json::from_str::<ProviderRequest>(&request_json)
        .map_err(|_| agent::invariant("replay effect model request is invalid"))?;
    let response = serde_json::from_str::<ProviderResponse>(&response_json)
        .map_err(|_| agent::invariant("replay effect model response is invalid"))?;
    let Some(declared) = request.tools.iter().find(|tool| {
        tool.tool_id == view.policy_request.tool.tool_id
            && tool.version == view.policy_request.tool.version
    }) else {
        return Ok(false);
    };
    let origin_matches = matches!(
        response,
        ProviderResponse::ToolCall { ref tool_id, ref arguments }
            if tool_id == &view.policy_request.tool.tool_id
                && arguments == &view.policy_request.normalized_arguments
    );
    Ok(!tool_call_id.is_empty()
        && state == "completed"
        && response_kind == "tool_call"
        && request.run_id == run_id
        && origin_matches
        && declared.input_schema == view.policy_request.tool.input_schema
        && declared.schema_digest == view.policy_request.tool.input_schema_digest)
}

fn verify_terminal_effect_attempt(
    connection: &rusqlite::Connection,
    effect_id: EffectId,
    status: EffectStatus,
) -> Result<bool, AgentStoreError> {
    let attempt_id = connection
        .query_row(
            "SELECT attempt_id FROM effect_attempt WHERE effect_id = ?1 \
             ORDER BY ordinal DESC LIMIT 1",
            [effect_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(agent::map_sqlite_error)?;
    if status == EffectStatus::Denied {
        return Ok(attempt_id.is_none());
    }
    let Some(attempt_id) = attempt_id else {
        return Ok(false);
    };
    let attempt = super::effects::load_effect_attempt_view(
        connection,
        None,
        parse_id(&attempt_id, "replay effect attempt ID")?,
    )
    .map_err(map_effect_error)?;
    let terminal_outcome = attempt.outcomes.last().map(|outcome| outcome.kind);
    Ok(match status {
        EffectStatus::Succeeded => {
            matches!(
                attempt.state,
                EffectAttemptState::Succeeded | EffectAttemptState::OutcomeUnknown
            ) && terminal_outcome == Some(mealy_application::EffectOutcomeKind::Succeeded)
        }
        EffectStatus::Failed => {
            matches!(
                attempt.state,
                EffectAttemptState::Failed | EffectAttemptState::OutcomeUnknown
            ) && terminal_outcome == Some(mealy_application::EffectOutcomeKind::Failed)
        }
        EffectStatus::Compensated => {
            attempt.state == EffectAttemptState::OutcomeUnknown
                && terminal_outcome == Some(mealy_application::EffectOutcomeKind::Compensated)
        }
        EffectStatus::Denied
        | EffectStatus::Proposed
        | EffectStatus::AwaitingApproval
        | EffectStatus::Authorized
        | EffectStatus::Dispatching
        | EffectStatus::OutcomeUnknown => false,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_effect_observation_event(
    connection: &rusqlite::Connection,
    message_id: &str,
    effect_id: EffectId,
    effect_revision: i64,
    model_attempt_id: &str,
    tool_call_id: &str,
    content_digest: &str,
    observed_at_ms: i64,
) -> Result<bool, AgentStoreError> {
    let rows = connection
        .query_row(
            "SELECT COUNT(*), MIN(event_type), MIN(occurred_at_ms), MIN(payload_json), \
                    COUNT(timeline.cursor) \
             FROM journal_event event \
             LEFT JOIN timeline_event timeline ON timeline.event_id = event.event_id \
             WHERE event.aggregate_kind = 'message' AND event.aggregate_id = ?1",
            [message_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .map_err(agent::map_sqlite_error)?;
    let expected = json!({
        "effect_id": effect_id,
        "effect_revision": effect_revision,
        "model_attempt_id": model_attempt_id,
        "tool_call_id": tool_call_id,
        "content_digest": content_digest,
    })
    .to_string();
    Ok(rows.0 == 1
        && rows.1.as_deref() == Some("message.tool.effect_observed")
        && rows.2 == Some(observed_at_ms)
        && rows.3.as_deref() == Some(expected.as_str())
        && rows.4 == 1
        && agent::verify_aggregate_sequence_chain(connection, "message", message_id)?)
}

#[allow(clippy::struct_field_names)]
struct FencedEffectOwner {
    task_id: TaskId,
    turn_id: String,
    session_id: String,
    principal_id: String,
    correlation_id: CorrelationId,
}

fn load_fenced_effect_owner(
    connection: &rusqlite::Connection,
    fence: mealy_domain::LeaseFence,
    model_attempt_id: mealy_domain::AttemptId,
    observed_at_ms: i64,
) -> Result<FencedEffectOwner, AgentStoreError> {
    let token = i64::try_from(fence.fencing_token().get())
        .map_err(|_| agent::invariant("agent effect fencing token exceeds SQLite range"))?;
    connection
        .query_row(
            "SELECT run.task_id, turn.id, turn.session_id, session.principal_id, \
                    run.correlation_id \
             FROM run \
             JOIN task ON task.id = run.task_id \
             JOIN turn ON turn.run_id = run.id AND turn.task_id = run.task_id \
             JOIN session ON session.id = turn.session_id AND session.active_turn_id = turn.id \
             JOIN work_lease lease ON lease.run_id = run.id \
             JOIN run_loop_state loop ON loop.run_id = run.id \
             JOIN model_attempt attempt ON attempt.attempt_id = loop.current_attempt_id \
             WHERE run.id = ?1 AND run.status = 'running' AND task.status = 'running' \
               AND run.current_fencing_token = ?2 AND run.cancellation_requested_at_ms IS NULL \
               AND turn.status = 'active' AND lease.lease_id = ?3 AND lease.owner_id = ?4 \
               AND lease.fencing_token = ?2 AND lease.state = 'active' \
               AND lease.acquired_at_ms <= ?5 AND ?5 < lease.expires_at_ms \
               AND loop.next_action = 'consume_model_result' \
               AND loop.current_attempt_id = ?6 AND attempt.run_id = run.id \
               AND attempt.state = 'completed' AND attempt.response_kind = 'tool_call'",
            params![
                fence.run_id().to_string(),
                token,
                fence.lease_id().to_string(),
                fence.owner_id().to_string(),
                observed_at_ms,
                model_attempt_id.to_string(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
        .map_err(agent::map_sqlite_error)?
        .map(
            |(task_id, turn_id, session_id, principal_id, correlation_id)| {
                Ok(FencedEffectOwner {
                    task_id: parse_id(&task_id, "fenced effect task ID")?,
                    turn_id,
                    session_id,
                    principal_id,
                    correlation_id: parse_id(&correlation_id, "fenced effect correlation ID")?,
                })
            },
        )
        .transpose()?
        .ok_or(AgentStoreError::StaleFence)
}

fn load_invocation(
    connection: &rusqlite::Connection,
    model_attempt_id: mealy_domain::AttemptId,
) -> Result<Option<AgentEffectInvocation>, AgentStoreError> {
    connection
        .query_row(
            "SELECT effect_id, run_id, task_id, model_attempt_id, tool_call_id \
             FROM agent_effect_invocation WHERE model_attempt_id = ?1",
            [model_attempt_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
        .map_err(agent::map_sqlite_error)?
        .map(|(effect_id, run_id, task_id, attempt_id, tool_call_id)| {
            Ok(AgentEffectInvocation {
                effect_id: parse_id(&effect_id, "agent effect ID")?,
                run_id: parse_id(&run_id, "agent effect run ID")?,
                task_id: parse_id(&task_id, "agent effect task ID")?,
                model_attempt_id: parse_id(&attempt_id, "agent effect model attempt ID")?,
                tool_call_id: parse_id(&tool_call_id, "agent effect tool-call ID")?,
            })
        })
        .transpose()
}

fn validate_proposal_commit(
    commit: &RecordAgentEffectProposalCommit,
) -> Result<(), AgentStoreError> {
    if commit.proposal.policy_request.run_id != commit.fence.run_id()
        || commit.proposal.effect_id
            != commit
                .proposal
                .approval
                .as_ref()
                .map_or(commit.proposal.effect_id, |approval| {
                    approval.subject.effect_id
                })
        || commit.proposal.policy_evaluation.decision != PolicyDecision::RequireApproval
        || commit.proposal.approval.is_none()
        || commit.proposal.proposed_at != commit.parked_at
    {
        return Err(agent::invariant(
            "agent effect proposal does not match its approval wait boundary",
        ));
    }
    Ok(())
}

struct TerminalProjection {
    effect_revision: i64,
    content: Value,
}

fn load_terminal_projection(
    connection: &rusqlite::Connection,
    invocation: &AgentEffectInvocation,
) -> Result<TerminalProjection, AgentStoreError> {
    let row = connection
        .query_row(
            "SELECT effect.status, effect.revision, intent.arguments_digest, \
                    attempt.attempt_id, outcome.outcome_kind, outcome.evidence_json, \
                    outcome.evidence_digest \
             FROM effect \
             JOIN effect_intent intent ON intent.effect_id = effect.id \
             LEFT JOIN effect_attempt attempt ON attempt.effect_id = effect.id \
                  AND attempt.ordinal = (SELECT MAX(candidate.ordinal) FROM effect_attempt candidate \
                                         WHERE candidate.effect_id = effect.id) \
             LEFT JOIN effect_outcome outcome ON outcome.attempt_id = attempt.attempt_id \
                  AND outcome.sequence = (SELECT MAX(candidate.sequence) FROM effect_outcome candidate \
                                          WHERE candidate.attempt_id = attempt.attempt_id) \
             WHERE effect.id = ?1 AND effect.run_id = ?2 AND effect.task_id = ?3",
            params![
                invocation.effect_id.to_string(),
                invocation.run_id.to_string(),
                invocation.task_id.to_string(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .optional()
        .map_err(agent::map_sqlite_error)?
        .ok_or(AgentStoreError::NotFound)?;
    let (status, revision, arguments_digest, attempt_id, outcome_kind, evidence_json, digest) = row;
    let outcome = match status.as_str() {
        "denied" => {
            if attempt_id.is_some()
                || outcome_kind.is_some()
                || evidence_json.is_some()
                || digest.is_some()
            {
                return Err(agent::invariant(
                    "denied agent effect unexpectedly has dispatch evidence",
                ));
            }
            Value::Null
        }
        "succeeded" | "failed" | "compensated" => {
            let attempt_id = attempt_id
                .ok_or_else(|| agent::invariant("terminal agent effect has no attempt"))?;
            let outcome_kind = outcome_kind
                .ok_or_else(|| agent::invariant("terminal agent effect has no outcome kind"))?;
            let evidence_json = evidence_json
                .ok_or_else(|| agent::invariant("terminal agent effect has no evidence"))?;
            let digest = digest
                .ok_or_else(|| agent::invariant("terminal agent effect has no evidence digest"))?;
            if sha256_digest(evidence_json.as_bytes()) != digest || outcome_kind != status {
                return Err(agent::invariant(
                    "terminal agent effect evidence diverged from current status",
                ));
            }
            let evidence = serde_json::from_str::<Value>(&evidence_json)
                .map_err(|_| agent::invariant("terminal agent effect evidence is invalid JSON"))?;
            json!({
                "attemptId": attempt_id,
                "evidence": evidence,
                "evidenceDigest": digest,
                "kind": outcome_kind,
            })
        }
        "proposed" | "awaiting_approval" | "authorized" | "dispatching" | "outcome_unknown" => {
            return Err(AgentStoreError::Conflict);
        }
        _ => return Err(agent::invariant("stored agent effect status is invalid")),
    };
    Ok(TerminalProjection {
        effect_revision: revision,
        content: json!({
            "argumentsDigest": arguments_digest,
            "contractVersion": AGENT_EFFECT_OBSERVATION_CONTRACT_VERSION,
            "effectId": invocation.effect_id,
            "effectRevision": revision,
            "outcome": outcome,
            "status": status,
            "toolCallId": invocation.tool_call_id,
        }),
    })
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, AgentStoreError> {
    T::from_str(value).map_err(|_| agent::invariant(format!("stored {field} is invalid")))
}

pub(super) fn map_effect_error(
    error: mealy_application::EffectLedgerStoreError,
) -> AgentStoreError {
    use mealy_application::EffectLedgerStoreError;
    match error {
        EffectLedgerStoreError::NotFound => AgentStoreError::NotFound,
        EffectLedgerStoreError::Conflict
        | EffectLedgerStoreError::SubjectMismatch
        | EffectLedgerStoreError::ApprovalExpired
        | EffectLedgerStoreError::ExpiryNotReached => AgentStoreError::Conflict,
        EffectLedgerStoreError::InvalidEvidence(message) => agent::invariant(message),
        EffectLedgerStoreError::Unavailable(message) => AgentStoreError::Unavailable(message),
        EffectLedgerStoreError::InvariantViolation(message) => {
            AgentStoreError::InvariantViolation(message)
        }
    }
}
