//! Durable Phase 3 effect, policy-evidence, approval, and recovery projections.

use super::SqliteStore;
use mealy_application::{
    ApprovalRequestDraft, ApprovalRequestView, ApprovalResolutionReceipt, EffectAttemptBoundary,
    EffectAttemptOutcome, EffectAttemptState, EffectAttemptView, EffectCommandRequestError,
    EffectLedgerStore, EffectLedgerStoreError, EffectLedgerView, EffectOutcomeKind,
    EffectOutcomeView, EffectReconciliationOutcome, EffectReconciliationReceipt,
    EffectRecoveryCandidate, EffectRecoveryDisposition, ExpireApprovalCommit,
    INTERRUPTED_EFFECT_OUTCOME_CLASSIFICATION, INTERRUPTED_EFFECT_OUTCOME_ERROR_CLASS,
    INTERRUPTED_EFFECT_RETRY_CLASSIFICATION, INTERRUPTED_EFFECT_RETRY_ERROR_CLASS,
    INTERRUPTED_EFFECT_UNDISPATCHED_CLASSIFICATION, INTERRUPTED_EFFECT_UNDISPATCHED_ERROR_CLASS,
    MarkEffectAttemptRunningCommit, OwnershipContext, PolicyDecision, PolicyEvaluation,
    PolicyObligations, PolicyRequest, PrepareEffectAttemptCommit, ReconcileEffectOutcomeCommit,
    RecordEffectAttemptOutcomeCommit, RecordEffectProposalCommit, RecoverInterruptedEffectCommit,
    ResolveApprovalCommit, approval_resolution_request_material, canonical_arguments_digest,
    derive_effect_idempotency_key, effect_intent_digest, effect_intent_material,
    effect_outcome_evidence_material, effect_reconciliation_request_material, is_sha256_digest,
    sha256_digest,
};
use mealy_domain::{
    ApprovalDecision, ApprovalId, ApprovalStatus, AttemptId, CorrelationId, EffectId, EffectStatus,
    EventId, FencingToken, IdempotencyClass, LeaseFence, LeaseId, PrincipalId, RecoveryStrategy,
    RunId, TaskId, WorkerId,
};
use rusqlite::{
    Connection, ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::Serialize;
use serde_json::json;
use std::{str::FromStr, time::SystemTime};

/// Inserts one fully validated effect proposal into an existing caller-owned transaction.
///
/// This is used by the agent-loop bridge so the immutable model origin, approval wait state, and
/// lease retirement can commit atomically with the ordinary effect-ledger evidence.
pub(super) fn record_effect_proposal_transaction(
    transaction: &Transaction<'_>,
    commit: &RecordEffectProposalCommit,
) -> Result<(), EffectLedgerStoreError> {
    let evidence = ProposalEvidence::prepare(commit)?;
    let session_id = authorized_session_id(
        transaction,
        commit.ownership,
        commit.policy_request.task_id,
        commit.policy_request.run_id,
    )?;

    insert_effect(transaction, commit, &evidence)?;
    insert_effect_intent(transaction, commit, &evidence, &session_id)?;
    insert_policy_evidence(transaction, commit, &evidence)?;
    append_event(
        transaction,
        &EventAppend {
            event_id: commit.effect_event_id,
            aggregate_kind: "effect",
            aggregate_id: &commit.effect_id.to_string(),
            sequence: 0,
            event_type: "effect.proposed",
            occurred_at_ms: evidence.proposed_at_ms,
            actor_principal_id: Some(commit.ownership.principal_id()),
            correlation_id: commit.correlation_id,
            policy_version: Some(&commit.policy_evaluation.policy_version),
            payload: json!({
                "effect_id": commit.effect_id,
                "task_id": commit.policy_request.task_id,
                "run_id": commit.policy_request.run_id,
                "intent_digest": evidence.intent_digest,
                "tool_descriptor_digest": commit.policy_request.tool.descriptor_digest,
                "arguments_digest": evidence.arguments_digest,
                "policy_request_digest": evidence.policy_request_digest,
                "policy_decision": commit.policy_evaluation.decision,
                "policy_obligations_digest": evidence.obligations_digest,
                "status": evidence.status,
                "approval_id": commit.approval.as_ref().map(|approval| approval.approval_id),
            }),
        },
    )?;
    set_sequence(transaction, "effect", &commit.effect_id.to_string(), 0)?;

    if let Some(approval) = &commit.approval {
        insert_approval_request(
            transaction,
            commit,
            approval,
            &session_id,
            evidence.proposed_at_ms,
        )?;
    }
    Ok(())
}

/// Denies one approval-parked or authorized-but-undispatched agent effect when its owning task is
/// cancelled. A pending approval is revoked in the same caller-owned transaction.
#[allow(clippy::too_many_lines)] // The cross-aggregate cancellation boundary stays visibly atomic.
pub(super) fn cancel_undispatched_agent_effect_transaction(
    transaction: &Transaction<'_>,
    task_id: TaskId,
    approval_event_id: EventId,
    effect_event_id: EventId,
    correlation_id: CorrelationId,
    actor_principal_id: PrincipalId,
    cancelled_at_ms: i64,
) -> Result<Option<EffectId>, EffectLedgerStoreError> {
    let mut statement = transaction
        .prepare(
            "SELECT effect.id, effect.status, effect.updated_at_ms, approval.approval_id, \
                    approval.subject_digest, approval.policy_version, approval.expires_at_ms \
             FROM agent_effect_invocation invocation \
             JOIN effect ON effect.id = invocation.effect_id \
             JOIN approval_request approval ON approval.effect_id = effect.id \
             WHERE invocation.task_id = ?1 \
               AND effect.status IN ('awaiting_approval', 'authorized') \
               AND NOT EXISTS(SELECT 1 FROM effect_attempt attempt \
                              WHERE attempt.effect_id = effect.id) \
             ORDER BY invocation.created_at_ms, invocation.effect_id",
        )
        .map_err(map_sqlite_error)?;
    let rows = statement
        .query_map([task_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .map_err(map_sqlite_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_sqlite_error)?;
    if rows.len() > 1 {
        return Err(invariant(
            "one cancelled task owns multiple undispatched agent effects",
        ));
    }
    let Some((
        effect_id_text,
        status,
        updated_at_ms,
        approval_id,
        subject_digest,
        policy_version,
        expires_at_ms,
    )) = rows.into_iter().next()
    else {
        return Ok(None);
    };
    if cancelled_at_ms < updated_at_ms {
        return Err(EffectLedgerStoreError::Conflict);
    }
    let effect_id = parse_id(&effect_id_text, "cancelled agent effect ID")?;
    let pending = PendingApproval {
        approval_id: parse_id(&approval_id, "cancelled approval ID")?,
        effect_id,
        subject_digest,
        policy_version,
        expires_at_ms,
    };
    if status == "awaiting_approval" {
        append_approval_resolution_event(
            transaction,
            &pending,
            approval_event_id,
            correlation_id,
            cancelled_at_ms,
            Some(actor_principal_id),
            None,
            Some("task_cancelled"),
        )?;
        let changed = transaction
            .execute(
                "UPDATE approval_request \
                 SET status = 'revoked', decision = NULL, decided_by_principal_id = ?1, \
                     decision_event_id = ?2, resolved_at_ms = ?3 \
                 WHERE approval_id = ?4 AND status = 'pending'",
                params![
                    actor_principal_id.to_string(),
                    approval_event_id.to_string(),
                    cancelled_at_ms,
                    pending.approval_id.to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(EffectLedgerStoreError::Conflict);
        }
    }
    let changed = transaction
        .execute(
            "UPDATE effect SET status = 'denied', revision = revision + 1, updated_at_ms = ?1 \
             WHERE id = ?2 AND status = ?3",
            params![cancelled_at_ms, effect_id_text, status],
        )
        .map_err(map_sqlite_error)?;
    if changed != 1 {
        return Err(EffectLedgerStoreError::Conflict);
    }
    let sequence = next_sequence(transaction, "effect", &effect_id_text)?;
    append_event(
        transaction,
        &EventAppend {
            event_id: effect_event_id,
            aggregate_kind: "effect",
            aggregate_id: &effect_id_text,
            sequence,
            event_type: "effect.denied",
            occurred_at_ms: cancelled_at_ms,
            actor_principal_id: Some(actor_principal_id),
            correlation_id,
            policy_version: Some(&pending.policy_version),
            payload: json!({
                "effect_id": effect_id,
                "approval_id": pending.approval_id,
                "approval_subject_digest": pending.subject_digest,
                "approval_resolution": "task_cancelled",
                "status": EffectStatus::Denied,
            }),
        },
    )?;
    set_sequence(transaction, "effect", &effect_id_text, sequence)?;
    Ok(Some(effect_id))
}

impl EffectLedgerStore for SqliteStore {
    fn record_effect_proposal(
        &mut self,
        commit: RecordEffectProposalCommit,
    ) -> Result<EffectLedgerView, EffectLedgerStoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        record_effect_proposal_transaction(&transaction, &commit)?;
        let view = load_effect_view(&transaction, Some(commit.ownership), commit.effect_id)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(view)
    }

    fn effect_ledger_view(
        &self,
        ownership: OwnershipContext,
        effect_id: EffectId,
    ) -> Result<EffectLedgerView, EffectLedgerStoreError> {
        load_effect_view(&self.connection, Some(ownership), effect_id)
    }

    fn pending_approval_requests(
        &self,
        ownership: OwnershipContext,
    ) -> Result<Vec<ApprovalRequestView>, EffectLedgerStoreError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT approval.approval_id \
                 FROM approval_request approval \
                 JOIN effect_intent intent ON intent.effect_id = approval.effect_id \
                 JOIN session owner_session ON owner_session.id = intent.session_id \
                 WHERE approval.status = 'pending' \
                   AND owner_session.principal_id = ?1 \
                   AND owner_session.channel_binding_id = ?2 \
                 ORDER BY approval.requested_at_ms, approval.approval_id",
            )
            .map_err(map_sqlite_error)?;
        let approval_ids = statement
            .query_map(
                params![
                    ownership.principal_id().to_string(),
                    ownership.channel_binding_id().to_string(),
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(map_sqlite_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_sqlite_error)?;
        approval_ids
            .into_iter()
            .map(|value| {
                let approval_id = parse_id(&value, "approval ID")?;
                load_approval_view(&self.connection, Some(ownership), approval_id)
            })
            .collect()
    }

    fn resolve_approval(
        &mut self,
        commit: ResolveApprovalCommit,
    ) -> Result<ApprovalResolutionReceipt, EffectLedgerStoreError> {
        let request_json = approval_resolution_request_material(&commit)
            .map_err(|error| map_approval_command_error(&error))?
            .to_string();
        let request_digest = sha256_digest(request_json.as_bytes());
        let decided_at_ms = epoch_milliseconds(commit.decided_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        if let Some(row) = load_effect_command_receipt(
            &transaction,
            commit.ownership,
            "approval_resolution",
            &commit.idempotency_key,
        )? {
            let receipt = row.approval_receipt(
                &transaction,
                commit.ownership,
                &commit.idempotency_key,
                &request_json,
                &request_digest,
            )?;
            transaction.commit().map_err(map_sqlite_error)?;
            return Ok(receipt);
        }
        let pending =
            load_pending_approval(&transaction, Some(commit.ownership), commit.approval_id)?;
        if pending.subject_digest != commit.expected_subject_digest {
            return Err(EffectLedgerStoreError::SubjectMismatch);
        }
        if decided_at_ms >= pending.expires_at_ms {
            return Err(EffectLedgerStoreError::ApprovalExpired);
        }
        append_approval_resolution_event(
            &transaction,
            &pending,
            commit.approval_event_id,
            commit.correlation_id,
            decided_at_ms,
            Some(commit.ownership.principal_id()),
            Some(commit.decision),
            None,
        )?;
        let approval_status = ApprovalStatus::from_decision(commit.decision);
        let approval_changed = transaction
            .execute(
                "UPDATE approval_request \
                 SET status = ?1, decision = ?2, decided_by_principal_id = ?3, \
                     decision_event_id = ?4, resolved_at_ms = ?5 \
                 WHERE approval_id = ?6 AND status = 'pending'",
                params![
                    approval_status_text(approval_status),
                    approval_decision_text(commit.decision),
                    commit.ownership.principal_id().to_string(),
                    commit.approval_event_id.to_string(),
                    decided_at_ms,
                    commit.approval_id.to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;
        if approval_changed != 1 {
            return Err(EffectLedgerStoreError::Conflict);
        }
        let effect_status = match commit.decision {
            ApprovalDecision::Approve => EffectStatus::Authorized,
            ApprovalDecision::Deny => EffectStatus::Denied,
        };
        transition_effect_after_approval(
            &transaction,
            &pending,
            effect_status,
            commit.effect_event_id,
            commit.correlation_id,
            decided_at_ms,
            Some(commit.ownership.principal_id()),
            approval_status_text(approval_status),
        )?;
        let effect_revision = current_effect_revision(&transaction, pending.effect_id)?;
        let cursor = cursor_for_effect_event(&transaction, commit.effect_event_id)?;
        insert_approval_resolution_receipt(
            &transaction,
            &commit,
            pending.effect_id,
            &request_json,
            &request_digest,
            effect_revision,
            cursor,
            decided_at_ms,
        )?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(ApprovalResolutionReceipt {
            approval_id: commit.approval_id,
            effect_id: pending.effect_id,
            decision: commit.decision,
            effect_revision,
            approval_event_id: commit.approval_event_id,
            effect_event_id: commit.effect_event_id,
            cursor,
            duplicate: false,
        })
    }

    fn expire_approval(
        &mut self,
        commit: ExpireApprovalCommit,
    ) -> Result<EffectLedgerView, EffectLedgerStoreError> {
        let expired_at_ms = epoch_milliseconds(commit.expired_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let pending = load_pending_approval(&transaction, None, commit.approval_id)?;
        if expired_at_ms < pending.expires_at_ms {
            return Err(EffectLedgerStoreError::ExpiryNotReached);
        }
        append_approval_resolution_event(
            &transaction,
            &pending,
            commit.approval_event_id,
            commit.correlation_id,
            expired_at_ms,
            None,
            None,
            Some("expired"),
        )?;
        let approval_changed = transaction
            .execute(
                "UPDATE approval_request \
                 SET status = 'expired', decision = NULL, decided_by_principal_id = NULL, \
                     decision_event_id = ?1, resolved_at_ms = ?2 \
                 WHERE approval_id = ?3 AND status = 'pending'",
                params![
                    commit.approval_event_id.to_string(),
                    expired_at_ms,
                    commit.approval_id.to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;
        if approval_changed != 1 {
            return Err(EffectLedgerStoreError::Conflict);
        }
        transition_effect_after_approval(
            &transaction,
            &pending,
            EffectStatus::Denied,
            commit.effect_event_id,
            commit.correlation_id,
            expired_at_ms,
            None,
            "expired",
        )?;
        let view = load_effect_view(&transaction, None, pending.effect_id)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(view)
    }

    fn prepare_effect_attempt(
        &mut self,
        commit: PrepareEffectAttemptCommit,
    ) -> Result<EffectAttemptView, EffectLedgerStoreError> {
        let prepared_at_ms = epoch_milliseconds(commit.prepared_at)?;
        let expected_revision = sqlite_revision(commit.expected_effect_revision)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        validate_active_fence(&transaction, commit.fence, prepared_at_ms)?;
        prepare_effect_attempt_transaction(
            &transaction,
            &commit,
            expected_revision,
            prepared_at_ms,
        )?;
        let view = load_effect_attempt_view(&transaction, None, commit.attempt_id)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(view)
    }

    fn mark_effect_attempt_running(
        &mut self,
        commit: MarkEffectAttemptRunningCommit,
    ) -> Result<EffectAttemptView, EffectLedgerStoreError> {
        let dispatched_at_ms = epoch_milliseconds(commit.dispatched_at)?;
        let expected_revision = sqlite_revision(commit.expected_effect_revision)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        validate_active_fence(&transaction, commit.fence, dispatched_at_ms)?;
        mark_effect_attempt_running_transaction(
            &transaction,
            &commit,
            expected_revision,
            dispatched_at_ms,
        )?;
        let view = load_effect_attempt_view(&transaction, None, commit.attempt_id)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(view)
    }

    fn record_effect_attempt_outcome(
        &mut self,
        commit: RecordEffectAttemptOutcomeCommit,
    ) -> Result<EffectAttemptView, EffectLedgerStoreError> {
        validate_initial_outcome(&commit)?;
        let completed_at_ms = epoch_milliseconds(commit.completed_at)?;
        let expected_revision = sqlite_revision(commit.expected_effect_revision)?;
        let evidence = canonical_outcome_evidence(
            commit.effect_id,
            commit.attempt_id,
            0,
            commit.outcome.kind(),
            &commit.evidence_details,
            commit.error_class.as_deref(),
            completed_at_ms,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        validate_active_fence(&transaction, commit.fence, completed_at_ms)?;
        record_effect_attempt_outcome_transaction(
            &transaction,
            &commit,
            expected_revision,
            completed_at_ms,
            &evidence,
        )?;
        let view = load_effect_attempt_view(&transaction, None, commit.attempt_id)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(view)
    }

    fn recover_interrupted_effect(
        &mut self,
        commit: RecoverInterruptedEffectCommit,
    ) -> Result<EffectAttemptView, EffectLedgerStoreError> {
        let recovered_at_ms = epoch_milliseconds(commit.recovered_at)?;
        let expected_revision = sqlite_revision(commit.expected_effect_revision)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        if !interrupted_recovery_already_committed(
            &transaction,
            &commit,
            expected_revision,
            recovered_at_ms,
        )? {
            recover_interrupted_effect_transaction(
                &transaction,
                &commit,
                expected_revision,
                recovered_at_ms,
            )?;
        }
        let view = load_effect_attempt_view(&transaction, None, commit.attempt_id)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(view)
    }

    fn effect_attempt_view(
        &self,
        ownership: OwnershipContext,
        attempt_id: AttemptId,
    ) -> Result<EffectAttemptView, EffectLedgerStoreError> {
        load_effect_attempt_view(&self.connection, Some(ownership), attempt_id)
    }

    fn effect_attempt_views(
        &self,
        ownership: OwnershipContext,
        effect_id: EffectId,
    ) -> Result<Vec<EffectAttemptView>, EffectLedgerStoreError> {
        load_effect_view(&self.connection, Some(ownership), effect_id)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT attempt_id FROM effect_attempt \
                 WHERE effect_id = ?1 ORDER BY ordinal, attempt_id",
            )
            .map_err(map_sqlite_error)?;
        let attempt_ids = statement
            .query_map([effect_id.to_string()], |row| row.get::<_, String>(0))
            .map_err(map_sqlite_error)?
            .map(|row| {
                row.map_err(map_sqlite_error)
                    .and_then(|value| parse_id(&value, "effect attempt ID"))
            })
            .collect::<Result<Vec<AttemptId>, EffectLedgerStoreError>>()?;
        drop(statement);
        attempt_ids
            .into_iter()
            .map(|attempt_id| {
                load_effect_attempt_view(&self.connection, Some(ownership), attempt_id)
            })
            .collect()
    }

    fn reconcile_effect_outcome(
        &mut self,
        commit: ReconcileEffectOutcomeCommit,
    ) -> Result<EffectReconciliationReceipt, EffectLedgerStoreError> {
        let request_json = effect_reconciliation_request_material(&commit)
            .map_err(|error| map_effect_command_error(&error))?
            .to_string();
        let request_digest = sha256_digest(request_json.as_bytes());
        let reconciled_at_ms = epoch_milliseconds(commit.reconciled_at)?;
        let expected_revision = sqlite_revision(commit.expected_effect_revision)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        if let Some(row) = load_effect_command_receipt(
            &transaction,
            commit.ownership,
            "effect_reconciliation",
            &commit.idempotency_key,
        )? {
            let receipt = row.reconciliation_receipt(
                &transaction,
                commit.ownership,
                &commit.idempotency_key,
                &request_json,
                &request_digest,
            )?;
            transaction.commit().map_err(map_sqlite_error)?;
            return Ok(receipt);
        }
        reconcile_effect_outcome_transaction(
            &transaction,
            &commit,
            expected_revision,
            reconciled_at_ms,
        )?;
        let effect_revision = current_effect_revision(&transaction, commit.effect_id)?;
        let cursor = cursor_for_effect_event(&transaction, commit.event_id)?;
        insert_effect_reconciliation_receipt(
            &transaction,
            &commit,
            &request_json,
            &request_digest,
            effect_revision,
            cursor,
            reconciled_at_ms,
        )?;
        let receipt = EffectReconciliationReceipt {
            effect_id: commit.effect_id,
            attempt_id: commit.attempt_id,
            outcome: commit.outcome,
            effect_revision,
            event_id: commit.event_id,
            cursor,
            duplicate: false,
        };
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(receipt)
    }

    fn interrupted_effect_recovery_candidates(
        &self,
    ) -> Result<Vec<EffectRecoveryCandidate>, EffectLedgerStoreError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT attempt_id, effect_id, ordinal, boundary, idempotency_class, \
                        recovery_strategy, idempotency_key, disposition \
                 FROM effect_recovery_candidate \
                 ORDER BY prepared_at_ms, effect_id, ordinal, attempt_id",
            )
            .map_err(map_sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok(RecoveryRow {
                    attempt_id: row.get(0)?,
                    effect_id: row.get(1)?,
                    ordinal: row.get(2)?,
                    boundary: row.get(3)?,
                    idempotency: row.get(4)?,
                    recovery: row.get(5)?,
                    idempotency_key: row.get(6)?,
                    disposition: row.get(7)?,
                })
            })
            .map_err(map_sqlite_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_sqlite_error)?;
        rows.into_iter().map(RecoveryRow::hydrate).collect()
    }
}

struct EffectCommandReceiptRow {
    request_json: String,
    request_digest: String,
    effect_id: String,
    approval_id: Option<String>,
    attempt_id: Option<String>,
    result_kind: String,
    effect_revision: i64,
    approval_event_id: Option<String>,
    effect_event_id: String,
    cursor: i64,
    committed_at_ms: i64,
}

impl EffectCommandReceiptRow {
    fn approval_receipt(
        &self,
        connection: &Connection,
        ownership: OwnershipContext,
        idempotency_key: &str,
        expected_request_json: &str,
        expected_request_digest: &str,
    ) -> Result<ApprovalResolutionReceipt, EffectLedgerStoreError> {
        let request = self.validate_common_request(ownership, idempotency_key)?;
        let request_object = request
            .as_object()
            .ok_or_else(|| invariant("stored approval receipt request is not an object"))?;
        if request_object.len() != 7
            || request_string(request_object, "contractVersion")?
                != "mealy.approval-resolution-request.v1"
        {
            return Err(invariant(
                "stored approval receipt request contract is invalid",
            ));
        }
        let effect_id = parse_id(&self.effect_id, "receipt effect ID")?;
        let approval_id_text = self
            .approval_id
            .as_deref()
            .ok_or_else(|| invariant("approval receipt is missing its approval ID"))?;
        let approval_id = parse_id(approval_id_text, "receipt approval ID")?;
        if self.attempt_id.is_some()
            || request_string(request_object, "approvalId")? != approval_id_text
        {
            return Err(invariant("stored approval receipt identity is invalid"));
        }
        let decision = parse_approval_decision(&self.result_kind)?;
        if request_string(request_object, "decision")? != self.result_kind
            || !is_sha256_digest(request_string(request_object, "expectedSubjectDigest")?)
        {
            return Err(invariant("stored approval receipt request is invalid"));
        }
        let approval_event_id = self
            .approval_event_id
            .as_deref()
            .ok_or_else(|| invariant("approval receipt is missing its approval event"))?;
        let effect_revision = positive_u64(self.effect_revision, "receipt effect revision")?;
        let cursor = positive_u64(self.cursor, "receipt timeline cursor")?;
        self.validate_approval_graph(
            connection,
            ownership,
            approval_id_text,
            approval_event_id,
            request_string(request_object, "expectedSubjectDigest")?,
        )?;
        if self.request_json != expected_request_json
            || self.request_digest != expected_request_digest
        {
            return Err(EffectLedgerStoreError::Conflict);
        }
        Ok(ApprovalResolutionReceipt {
            approval_id,
            effect_id,
            decision,
            effect_revision,
            approval_event_id: parse_id(approval_event_id, "receipt approval event ID")?,
            effect_event_id: parse_id(&self.effect_event_id, "receipt effect event ID")?,
            cursor,
            duplicate: true,
        })
    }

    fn reconciliation_receipt(
        &self,
        connection: &Connection,
        ownership: OwnershipContext,
        idempotency_key: &str,
        expected_request_json: &str,
        expected_request_digest: &str,
    ) -> Result<EffectReconciliationReceipt, EffectLedgerStoreError> {
        let request = self.validate_common_request(ownership, idempotency_key)?;
        let request_object = request
            .as_object()
            .ok_or_else(|| invariant("stored reconciliation receipt request is not an object"))?;
        if request_object.len() != 9
            || request_string(request_object, "contractVersion")?
                != "mealy.effect-reconciliation-request.v1"
        {
            return Err(invariant(
                "stored reconciliation receipt request contract is invalid",
            ));
        }
        let effect_id = parse_id(&self.effect_id, "receipt effect ID")?;
        let attempt_id_text = self
            .attempt_id
            .as_deref()
            .ok_or_else(|| invariant("reconciliation receipt is missing its attempt ID"))?;
        let attempt_id = parse_id(attempt_id_text, "receipt attempt ID")?;
        if self.approval_id.is_some()
            || self.approval_event_id.is_some()
            || request_string(request_object, "effectId")? != self.effect_id
            || request_string(request_object, "attemptId")? != attempt_id_text
        {
            return Err(invariant(
                "stored reconciliation receipt identity is invalid",
            ));
        }
        let outcome = match self.result_kind.as_str() {
            "succeeded" => EffectReconciliationOutcome::Succeeded,
            "failed" => EffectReconciliationOutcome::Failed,
            _ => {
                return Err(invariant(
                    "stored reconciliation receipt outcome is invalid",
                ));
            }
        };
        let effect_revision = positive_u64(self.effect_revision, "receipt effect revision")?;
        if request_string(request_object, "outcome")? != self.result_kind
            || request_u64(request_object, "expectedEffectRevision")?
                != effect_revision.saturating_sub(1)
            || request_object
                .get("evidenceDetails")
                .and_then(serde_json::Value::as_object)
                .is_none_or(serde_json::Map::is_empty)
            || request_object
                .get("evidenceDetails")
                .and_then(|details| serde_json::to_vec(details).ok())
                .is_none_or(|encoded| {
                    encoded.len() > mealy_application::MAXIMUM_EFFECT_OUTCOME_DETAILS_BYTES
                })
        {
            return Err(invariant(
                "stored reconciliation receipt request is invalid",
            ));
        }
        let cursor = positive_u64(self.cursor, "receipt timeline cursor")?;
        self.validate_reconciliation_graph(connection, ownership, attempt_id_text, request_object)?;
        if self.request_json != expected_request_json
            || self.request_digest != expected_request_digest
        {
            return Err(EffectLedgerStoreError::Conflict);
        }
        Ok(EffectReconciliationReceipt {
            effect_id,
            attempt_id,
            outcome,
            effect_revision,
            event_id: parse_id(&self.effect_event_id, "receipt effect event ID")?,
            cursor,
            duplicate: true,
        })
    }

    fn validate_common_request(
        &self,
        ownership: OwnershipContext,
        idempotency_key: &str,
    ) -> Result<serde_json::Value, EffectLedgerStoreError> {
        if !is_sha256_digest(&self.request_digest)
            || sha256_digest(self.request_json.as_bytes()) != self.request_digest
        {
            return Err(invariant("stored effect command receipt digest is invalid"));
        }
        let request: serde_json::Value = serde_json::from_str(&self.request_json)
            .map_err(|_| invariant("stored effect command receipt JSON is invalid"))?;
        let canonical_request = serde_json::to_string(&request)
            .map_err(|_| invariant("stored effect command receipt JSON cannot be serialized"))?;
        if canonical_request != self.request_json {
            return Err(invariant(
                "stored effect command receipt JSON is not canonical",
            ));
        }
        let request_object = request
            .as_object()
            .ok_or_else(|| invariant("stored effect command receipt request is not an object"))?;
        if request_string(request_object, "principalId")? != ownership.principal_id().to_string()
            || request_string(request_object, "channelBindingId")?
                != ownership.channel_binding_id().to_string()
            || request_string(request_object, "idempotencyKey")? != idempotency_key
            || idempotency_key.is_empty()
            || idempotency_key.len() > 256
        {
            return Err(invariant("stored effect command receipt scope is invalid"));
        }
        Ok(request)
    }

    fn validate_approval_graph(
        &self,
        connection: &Connection,
        ownership: OwnershipContext,
        approval_id: &str,
        approval_event_id: &str,
        expected_subject_digest: &str,
    ) -> Result<(), EffectLedgerStoreError> {
        let valid = connection
            .query_row(
                "SELECT EXISTS(\
                    SELECT 1 \
                    FROM approval_request approval \
                    JOIN journal_event approval_event \
                      ON approval_event.event_id = ?1 \
                    JOIN journal_event effect_event \
                      ON effect_event.event_id = ?2 \
                    JOIN timeline_event timeline \
                      ON timeline.event_id = effect_event.event_id \
                    WHERE approval.approval_id = ?3 AND approval.effect_id = ?4 \
                      AND approval.subject_digest = ?5 \
                      AND approval_event.aggregate_kind = 'approval' \
                      AND approval_event.aggregate_id = approval.approval_id \
                      AND approval_event.event_type = CASE ?6 \
                          WHEN 'approve' THEN 'approval.approved' \
                          WHEN 'deny' THEN 'approval.denied' END \
                      AND approval_event.actor_principal_id = ?7 \
                      AND approval_event.occurred_at_ms = ?8 \
                      AND json_extract(approval_event.payload_json, '$.effect_id') = ?4 \
                      AND json_extract(approval_event.payload_json, '$.subject_digest') = ?5 \
                      AND json_extract(approval_event.payload_json, '$.decision') = ?6 \
                      AND effect_event.aggregate_kind = 'effect' \
                      AND effect_event.aggregate_id = ?4 \
                      AND effect_event.aggregate_sequence + 1 = ?9 \
                      AND effect_event.event_type = CASE ?6 \
                          WHEN 'approve' THEN 'effect.authorized' \
                          WHEN 'deny' THEN 'effect.denied' END \
                      AND effect_event.actor_principal_id = ?7 \
                      AND effect_event.occurred_at_ms = ?8 \
                      AND json_extract(effect_event.payload_json, '$.approval_id') = ?3 \
                      AND timeline.cursor = ?10\
                 )",
                params![
                    approval_event_id,
                    self.effect_event_id,
                    approval_id,
                    self.effect_id,
                    expected_subject_digest,
                    self.result_kind,
                    ownership.principal_id().to_string(),
                    self.committed_at_ms,
                    self.effect_revision,
                    self.cursor,
                ],
                |row| row.get::<_, bool>(0),
            )
            .map_err(map_sqlite_error)?;
        if !valid {
            return Err(invariant("stored approval receipt graph is invalid"));
        }
        Ok(())
    }

    fn validate_reconciliation_graph(
        &self,
        connection: &Connection,
        ownership: OwnershipContext,
        attempt_id: &str,
        request: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), EffectLedgerStoreError> {
        let evidence_details = request
            .get("evidenceDetails")
            .ok_or_else(|| invariant("stored reconciliation receipt lacks evidence details"))?;
        let valid = connection
            .query_row(
                "SELECT EXISTS(\
                    SELECT 1 \
                    FROM effect_attempt attempt \
                    JOIN effect_outcome outcome \
                      ON outcome.attempt_id = attempt.attempt_id \
                     AND outcome.effect_id = attempt.effect_id \
                    JOIN journal_event effect_event \
                      ON effect_event.event_id = outcome.event_id \
                    JOIN timeline_event timeline \
                      ON timeline.event_id = effect_event.event_id \
                    WHERE attempt.attempt_id = ?1 AND attempt.effect_id = ?2 \
                      AND outcome.sequence = 1 AND outcome.outcome_kind = ?3 \
                      AND outcome.event_id = ?4 AND outcome.recorded_at_ms = ?5 \
                      AND json(json_extract(outcome.evidence_json, '$.evidence')) = json(?6) \
                      AND effect_event.aggregate_kind = 'effect' \
                      AND effect_event.aggregate_id = ?2 \
                      AND effect_event.aggregate_sequence + 1 = ?7 \
                      AND effect_event.event_type = 'effect.reconciled' \
                      AND effect_event.actor_principal_id = ?8 \
                      AND effect_event.occurred_at_ms = ?5 \
                      AND json_extract(effect_event.payload_json, '$.attempt_id') = ?1 \
                      AND json_extract(effect_event.payload_json, '$.effect_revision') = ?7 \
                      AND json_extract(effect_event.payload_json, '$.outcome') = ?3 \
                      AND timeline.cursor = ?9\
                 )",
                params![
                    attempt_id,
                    self.effect_id,
                    self.result_kind,
                    self.effect_event_id,
                    self.committed_at_ms,
                    evidence_details.to_string(),
                    self.effect_revision,
                    ownership.principal_id().to_string(),
                    self.cursor,
                ],
                |row| row.get::<_, bool>(0),
            )
            .map_err(map_sqlite_error)?;
        if !valid {
            return Err(invariant(
                "stored effect reconciliation receipt graph is invalid",
            ));
        }
        Ok(())
    }
}

fn load_effect_command_receipt(
    connection: &Connection,
    ownership: OwnershipContext,
    command_kind: &str,
    idempotency_key: &str,
) -> Result<Option<EffectCommandReceiptRow>, EffectLedgerStoreError> {
    connection
        .query_row(
            "SELECT request_json, request_digest, effect_id, approval_id, attempt_id, \
                    result_kind, effect_revision, approval_event_id, effect_event_id, cursor, \
                    committed_at_ms \
             FROM effect_command_receipt \
             WHERE principal_id = ?1 AND channel_binding_id = ?2 \
               AND command_kind = ?3 AND idempotency_key = ?4",
            params![
                ownership.principal_id().to_string(),
                ownership.channel_binding_id().to_string(),
                command_kind,
                idempotency_key,
            ],
            |row| {
                Ok(EffectCommandReceiptRow {
                    request_json: row.get(0)?,
                    request_digest: row.get(1)?,
                    effect_id: row.get(2)?,
                    approval_id: row.get(3)?,
                    attempt_id: row.get(4)?,
                    result_kind: row.get(5)?,
                    effect_revision: row.get(6)?,
                    approval_event_id: row.get(7)?,
                    effect_event_id: row.get(8)?,
                    cursor: row.get(9)?,
                    committed_at_ms: row.get(10)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)
}

#[allow(clippy::too_many_arguments)]
fn insert_approval_resolution_receipt(
    transaction: &Transaction<'_>,
    commit: &ResolveApprovalCommit,
    effect_id: EffectId,
    request_json: &str,
    request_digest: &str,
    effect_revision: u64,
    cursor: u64,
    committed_at_ms: i64,
) -> Result<(), EffectLedgerStoreError> {
    transaction
        .execute(
            "INSERT INTO effect_command_receipt(\
                principal_id, channel_binding_id, command_kind, idempotency_key, request_json, \
                request_digest, effect_id, approval_id, result_kind, effect_revision, \
                approval_event_id, effect_event_id, cursor, committed_at_ms\
             ) VALUES (?1, ?2, 'approval_resolution', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                commit.ownership.principal_id().to_string(),
                commit.ownership.channel_binding_id().to_string(),
                commit.idempotency_key,
                request_json,
                request_digest,
                effect_id.to_string(),
                commit.approval_id.to_string(),
                approval_decision_text(commit.decision),
                sqlite_revision(effect_revision)?,
                commit.approval_event_id.to_string(),
                commit.effect_event_id.to_string(),
                sqlite_revision(cursor)?,
                committed_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_effect_reconciliation_receipt(
    transaction: &Transaction<'_>,
    commit: &ReconcileEffectOutcomeCommit,
    request_json: &str,
    request_digest: &str,
    effect_revision: u64,
    cursor: u64,
    committed_at_ms: i64,
) -> Result<(), EffectLedgerStoreError> {
    transaction
        .execute(
            "INSERT INTO effect_command_receipt(\
                principal_id, channel_binding_id, command_kind, idempotency_key, request_json, \
                request_digest, effect_id, attempt_id, result_kind, effect_revision, \
                effect_event_id, cursor, committed_at_ms\
             ) VALUES (?1, ?2, 'effect_reconciliation', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                commit.ownership.principal_id().to_string(),
                commit.ownership.channel_binding_id().to_string(),
                commit.idempotency_key,
                request_json,
                request_digest,
                commit.effect_id.to_string(),
                commit.attempt_id.to_string(),
                effect_outcome_kind_text(commit.outcome.kind()),
                sqlite_revision(effect_revision)?,
                commit.event_id.to_string(),
                sqlite_revision(cursor)?,
                committed_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn current_effect_revision(
    transaction: &Transaction<'_>,
    effect_id: EffectId,
) -> Result<u64, EffectLedgerStoreError> {
    let revision = transaction
        .query_row(
            "SELECT revision FROM effect WHERE id = ?1",
            [effect_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(EffectLedgerStoreError::Conflict)?;
    positive_u64(revision, "effect revision")
}

fn cursor_for_effect_event(
    transaction: &Transaction<'_>,
    event_id: EventId,
) -> Result<u64, EffectLedgerStoreError> {
    let cursor = transaction
        .query_row(
            "SELECT cursor FROM timeline_event WHERE event_id = ?1",
            [event_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or_else(|| invariant("effect command event is missing its timeline cursor"))?;
    positive_u64(cursor, "timeline cursor")
}

fn positive_u64(value: i64, field: &str) -> Result<u64, EffectLedgerStoreError> {
    let value =
        u64::try_from(value).map_err(|_| invariant(format!("stored {field} is negative")))?;
    if value == 0 {
        return Err(invariant(format!("stored {field} is zero")));
    }
    Ok(value)
}

fn request_string<'a>(
    request: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'a str, EffectLedgerStoreError> {
    request
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invariant(format!("stored effect command receipt lacks {field}")))
}

fn request_u64(
    request: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<u64, EffectLedgerStoreError> {
    request
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invariant(format!("stored effect command receipt lacks {field}")))
}

fn map_approval_command_error(error: &EffectCommandRequestError) -> EffectLedgerStoreError {
    if *error == EffectCommandRequestError::InvalidSubjectDigest {
        EffectLedgerStoreError::SubjectMismatch
    } else {
        map_effect_command_error(error)
    }
}

fn map_effect_command_error(error: &EffectCommandRequestError) -> EffectLedgerStoreError {
    EffectLedgerStoreError::InvalidEvidence(error.to_string())
}

struct AttemptPreparationEvidence {
    ordinal: i64,
    idempotency_key: Option<String>,
    policy_version: String,
    previous_updated_at_ms: i64,
}

fn prepare_effect_attempt_transaction(
    transaction: &Transaction<'_>,
    commit: &PrepareEffectAttemptCommit,
    expected_revision: i64,
    prepared_at_ms: i64,
) -> Result<(), EffectLedgerStoreError> {
    let new_revision = next_effect_revision(expected_revision)?;
    let evidence = load_attempt_preparation_evidence(
        transaction,
        commit.effect_id,
        commit.fence,
        expected_revision,
    )?;
    if prepared_at_ms < evidence.previous_updated_at_ms {
        return Err(EffectLedgerStoreError::Conflict);
    }
    transaction
        .execute(
            "INSERT OR IGNORE INTO effect_attempt_fence(\
                lease_id, effect_id, owner_id, fencing_token, run_id\
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                commit.fence.lease_id().to_string(),
                commit.effect_id.to_string(),
                commit.fence.owner_id().to_string(),
                fence_token_i64(commit.fence)?,
                commit.fence.run_id().to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    let effect_id = commit.effect_id.to_string();
    let sequence = next_sequence(transaction, "effect", &effect_id)?;
    append_event(
        transaction,
        &EventAppend {
            event_id: commit.event_id,
            aggregate_kind: "effect",
            aggregate_id: &effect_id,
            sequence,
            event_type: "effect.attempt_prepared",
            occurred_at_ms: prepared_at_ms,
            actor_principal_id: None,
            correlation_id: commit.correlation_id,
            policy_version: Some(&evidence.policy_version),
            payload: json!({
                "attempt_id": commit.attempt_id,
                "effect_id": commit.effect_id,
                "effect_revision": new_revision,
                "fencing_token": commit.fence.fencing_token().get(),
                "idempotency_key": evidence.idempotency_key,
                "lease_id": commit.fence.lease_id(),
                "ordinal": evidence.ordinal,
                "owner_id": commit.fence.owner_id(),
                "run_id": commit.fence.run_id(),
                "state": EffectAttemptState::Prepared,
            }),
        },
    )?;
    transaction
        .execute(
            "INSERT INTO effect_attempt(\
                attempt_id, effect_id, ordinal, state, idempotency_key, prepared_lease_id, \
                prepared_owner_id, prepared_fencing_token, prepared_event_id, prepared_at_ms\
             ) VALUES (?1, ?2, ?3, 'prepared', ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                commit.attempt_id.to_string(),
                effect_id,
                evidence.ordinal,
                evidence.idempotency_key,
                commit.fence.lease_id().to_string(),
                commit.fence.owner_id().to_string(),
                fence_token_i64(commit.fence)?,
                commit.event_id.to_string(),
                prepared_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    let changed = transaction
        .execute(
            "UPDATE effect SET revision = revision + 1, updated_at_ms = ?1 \
             WHERE id = ?2 AND status = 'authorized' AND revision = ?3",
            params![prepared_at_ms, effect_id, expected_revision],
        )
        .map_err(map_sqlite_error)?;
    if changed != 1 {
        return Err(EffectLedgerStoreError::Conflict);
    }
    set_sequence(transaction, "effect", &effect_id, sequence)
}

fn load_attempt_preparation_evidence(
    transaction: &Transaction<'_>,
    effect_id: EffectId,
    fence: LeaseFence,
    expected_revision: i64,
) -> Result<AttemptPreparationEvidence, EffectLedgerStoreError> {
    transaction
        .query_row(
            "SELECT intent.idempotency_key, policy.policy_version, effect.updated_at_ms, \
                    COALESCE(MAX(attempt.ordinal), 0) \
             FROM effect \
             JOIN effect_intent intent ON intent.effect_id = effect.id \
             JOIN effect_policy_evaluation policy ON policy.effect_id = effect.id \
             LEFT JOIN effect_attempt attempt ON attempt.effect_id = effect.id \
             WHERE effect.id = ?1 AND effect.run_id = ?2 AND effect.status = 'authorized' \
               AND effect.revision = ?3 \
             GROUP BY intent.idempotency_key, policy.policy_version, effect.updated_at_ms",
            params![
                effect_id.to_string(),
                fence.run_id().to_string(),
                expected_revision,
            ],
            |row| {
                let previous_ordinal = row.get::<_, i64>(3)?;
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    previous_ordinal,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(EffectLedgerStoreError::Conflict)
        .and_then(
            |(idempotency_key, policy_version, previous_updated_at_ms, previous_ordinal)| {
                let ordinal = previous_ordinal
                    .checked_add(1)
                    .ok_or_else(|| invariant("effect attempt ordinal overflow"))?;
                Ok(AttemptPreparationEvidence {
                    ordinal,
                    idempotency_key,
                    policy_version,
                    previous_updated_at_ms,
                })
            },
        )
}

struct RunningTransitionEvidence {
    policy_version: String,
    idempotency_key: Option<String>,
    prepared_at_ms: i64,
    previous_updated_at_ms: i64,
}

fn mark_effect_attempt_running_transaction(
    transaction: &Transaction<'_>,
    commit: &MarkEffectAttemptRunningCommit,
    expected_revision: i64,
    dispatched_at_ms: i64,
) -> Result<(), EffectLedgerStoreError> {
    let new_revision = next_effect_revision(expected_revision)?;
    let evidence = load_running_transition_evidence(
        transaction,
        commit.effect_id,
        commit.attempt_id,
        commit.fence,
        expected_revision,
        "prepared",
        "authorized",
    )?;
    if dispatched_at_ms < evidence.prepared_at_ms
        || dispatched_at_ms < evidence.previous_updated_at_ms
    {
        return Err(EffectLedgerStoreError::Conflict);
    }
    let effect_id = commit.effect_id.to_string();
    let sequence = next_sequence(transaction, "effect", &effect_id)?;
    append_event(
        transaction,
        &EventAppend {
            event_id: commit.event_id,
            aggregate_kind: "effect",
            aggregate_id: &effect_id,
            sequence,
            event_type: "effect.dispatched",
            occurred_at_ms: dispatched_at_ms,
            actor_principal_id: None,
            correlation_id: commit.correlation_id,
            policy_version: Some(&evidence.policy_version),
            payload: json!({
                "attempt_id": commit.attempt_id,
                "effect_id": commit.effect_id,
                "effect_revision": new_revision,
                "fencing_token": commit.fence.fencing_token().get(),
                "idempotency_key": evidence.idempotency_key,
                "lease_id": commit.fence.lease_id(),
                "owner_id": commit.fence.owner_id(),
                "state": EffectAttemptState::Running,
            }),
        },
    )?;
    let effect_changed = transaction
        .execute(
            "UPDATE effect \
             SET status = 'dispatching', revision = revision + 1, dispatched_at_ms = ?1, \
                 updated_at_ms = ?1 \
             WHERE id = ?2 AND status = 'authorized' AND revision = ?3",
            params![dispatched_at_ms, effect_id, expected_revision],
        )
        .map_err(map_sqlite_error)?;
    if effect_changed != 1 {
        return Err(EffectLedgerStoreError::Conflict);
    }
    let attempt_changed = transaction
        .execute(
            "UPDATE effect_attempt \
             SET state = 'running', started_event_id = ?1, started_at_ms = ?2 \
             WHERE attempt_id = ?3 AND effect_id = ?4 AND state = 'prepared' \
               AND prepared_lease_id = ?5 AND prepared_owner_id = ?6 \
               AND prepared_fencing_token = ?7",
            params![
                commit.event_id.to_string(),
                dispatched_at_ms,
                commit.attempt_id.to_string(),
                effect_id,
                commit.fence.lease_id().to_string(),
                commit.fence.owner_id().to_string(),
                fence_token_i64(commit.fence)?,
            ],
        )
        .map_err(map_sqlite_error)?;
    if attempt_changed != 1 {
        return Err(EffectLedgerStoreError::Conflict);
    }
    set_sequence(transaction, "effect", &effect_id, sequence)
}

fn load_running_transition_evidence(
    transaction: &Transaction<'_>,
    effect_id: EffectId,
    attempt_id: AttemptId,
    fence: LeaseFence,
    expected_revision: i64,
    attempt_state: &str,
    effect_status: &str,
) -> Result<RunningTransitionEvidence, EffectLedgerStoreError> {
    transaction
        .query_row(
            "SELECT policy.policy_version, intent.idempotency_key, attempt.prepared_at_ms, \
                    effect.updated_at_ms \
             FROM effect_attempt attempt \
             JOIN effect ON effect.id = attempt.effect_id \
             JOIN effect_intent intent ON intent.effect_id = effect.id \
             JOIN effect_policy_evaluation policy ON policy.effect_id = effect.id \
             WHERE attempt.attempt_id = ?1 AND attempt.effect_id = ?2 \
               AND attempt.state = ?3 AND effect.status = ?4 AND effect.revision = ?5 \
               AND effect.run_id = ?6 AND attempt.prepared_lease_id = ?7 \
               AND attempt.prepared_owner_id = ?8 AND attempt.prepared_fencing_token = ?9 \
               AND attempt.idempotency_key IS intent.idempotency_key",
            params![
                attempt_id.to_string(),
                effect_id.to_string(),
                attempt_state,
                effect_status,
                expected_revision,
                fence.run_id().to_string(),
                fence.lease_id().to_string(),
                fence.owner_id().to_string(),
                fence_token_i64(fence)?,
            ],
            |row| {
                Ok(RunningTransitionEvidence {
                    policy_version: row.get(0)?,
                    idempotency_key: row.get(1)?,
                    prepared_at_ms: row.get(2)?,
                    previous_updated_at_ms: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(EffectLedgerStoreError::Conflict)
}

struct CanonicalOutcomeEvidence {
    json: String,
    digest: String,
}

fn canonical_outcome_evidence(
    effect_id: EffectId,
    attempt_id: AttemptId,
    sequence: u64,
    kind: EffectOutcomeKind,
    details: &serde_json::Value,
    error_class: Option<&str>,
    recorded_at_ms: i64,
) -> Result<CanonicalOutcomeEvidence, EffectLedgerStoreError> {
    let material = effect_outcome_evidence_material(
        effect_id,
        attempt_id,
        sequence,
        kind,
        details,
        error_class,
        recorded_at_ms,
    )
    .map_err(|error| invalid(error.to_string()))?;
    let json = material.to_string();
    Ok(CanonicalOutcomeEvidence {
        digest: sha256_digest(json.as_bytes()),
        json,
    })
}

fn validate_initial_outcome(
    commit: &RecordEffectAttemptOutcomeCommit,
) -> Result<(), EffectLedgerStoreError> {
    let valid = match commit.outcome {
        EffectAttemptOutcome::Succeeded => commit.error_class.is_none(),
        EffectAttemptOutcome::Failed | EffectAttemptOutcome::OutcomeUnknown => commit
            .error_class
            .as_deref()
            .is_some_and(|value| !value.is_empty() && value.len() <= 128),
    };
    if valid {
        Ok(())
    } else {
        Err(invalid(
            "success forbids an error class; failed and unknown outcomes require one",
        ))
    }
}

fn record_effect_attempt_outcome_transaction(
    transaction: &Transaction<'_>,
    commit: &RecordEffectAttemptOutcomeCommit,
    expected_revision: i64,
    completed_at_ms: i64,
    evidence: &CanonicalOutcomeEvidence,
) -> Result<(), EffectLedgerStoreError> {
    let new_revision = next_effect_revision(expected_revision)?;
    let transition = load_running_transition_evidence(
        transaction,
        commit.effect_id,
        commit.attempt_id,
        commit.fence,
        expected_revision,
        "running",
        "dispatching",
    )?;
    let started_at_ms = load_attempt_started_at(transaction, commit.attempt_id)?;
    if completed_at_ms < started_at_ms || completed_at_ms < transition.previous_updated_at_ms {
        return Err(EffectLedgerStoreError::Conflict);
    }
    let kind = commit.outcome.kind();
    let outcome_text = effect_outcome_kind_text(kind);
    let effect_id = commit.effect_id.to_string();
    let sequence = next_sequence(transaction, "effect", &effect_id)?;
    append_event(
        transaction,
        &EventAppend {
            event_id: commit.event_id,
            aggregate_kind: "effect",
            aggregate_id: &effect_id,
            sequence,
            event_type: initial_outcome_event_type(commit.outcome),
            occurred_at_ms: completed_at_ms,
            actor_principal_id: None,
            correlation_id: commit.correlation_id,
            policy_version: Some(&transition.policy_version),
            payload: json!({
                "attempt_id": commit.attempt_id,
                "effect_id": commit.effect_id,
                "effect_revision": new_revision,
                "error_class": commit.error_class,
                "evidence_digest": evidence.digest,
                "outcome": kind,
            }),
        },
    )?;
    insert_effect_outcome(
        transaction,
        &EffectOutcomeInsert {
            attempt_id: commit.attempt_id,
            effect_id: commit.effect_id,
            sequence: 0,
            kind,
            evidence,
            event_id: commit.event_id,
            recorded_at_ms: completed_at_ms,
        },
    )?;
    let effect_changed = transaction
        .execute(
            "UPDATE effect \
             SET status = ?1, revision = revision + 1, completed_at_ms = ?2, updated_at_ms = ?2 \
             WHERE id = ?3 AND status = 'dispatching' AND revision = ?4",
            params![outcome_text, completed_at_ms, effect_id, expected_revision],
        )
        .map_err(map_sqlite_error)?;
    if effect_changed != 1 {
        return Err(EffectLedgerStoreError::Conflict);
    }
    let attempt_changed = transaction
        .execute(
            "UPDATE effect_attempt \
             SET state = ?1, terminal_event_id = ?2, completed_at_ms = ?3, error_class = ?4 \
             WHERE attempt_id = ?5 AND effect_id = ?6 AND state = 'running' \
               AND prepared_lease_id = ?7 AND prepared_owner_id = ?8 \
               AND prepared_fencing_token = ?9",
            params![
                outcome_text,
                commit.event_id.to_string(),
                completed_at_ms,
                commit.error_class,
                commit.attempt_id.to_string(),
                effect_id,
                commit.fence.lease_id().to_string(),
                commit.fence.owner_id().to_string(),
                fence_token_i64(commit.fence)?,
            ],
        )
        .map_err(map_sqlite_error)?;
    if attempt_changed != 1 {
        return Err(EffectLedgerStoreError::Conflict);
    }
    set_sequence(transaction, "effect", &effect_id, sequence)
}

fn interrupted_recovery_already_committed(
    transaction: &Transaction<'_>,
    commit: &RecoverInterruptedEffectCommit,
    expected_revision: i64,
    recovered_at_ms: i64,
) -> Result<bool, EffectLedgerStoreError> {
    let recovered_revision = next_effect_revision(expected_revision)?;
    transaction
        .query_row(
            "SELECT EXISTS(\
                SELECT 1 \
                FROM effect_attempt attempt \
                JOIN effect ON effect.id = attempt.effect_id \
                JOIN effect_outcome outcome \
                  ON outcome.attempt_id = attempt.attempt_id \
                 AND outcome.effect_id = attempt.effect_id \
                 AND outcome.sequence = 0 \
                JOIN journal_event event ON event.event_id = outcome.event_id \
                JOIN timeline_event timeline ON timeline.event_id = event.event_id \
                WHERE attempt.attempt_id = ?1 AND attempt.effect_id = ?2 \
                  AND attempt.state = 'outcome_unknown' \
                  AND attempt.terminal_event_id = ?3 \
                  AND attempt.completed_at_ms = ?4 \
                  AND attempt.error_class = ?5 \
                  AND effect.status = 'outcome_unknown' AND effect.revision = ?6 \
                  AND effect.completed_at_ms = ?4 AND effect.updated_at_ms = ?4 \
                  AND outcome.outcome_kind = 'outcome_unknown' \
                  AND outcome.event_id = ?3 AND outcome.recorded_at_ms = ?4 \
                  AND json_extract(outcome.evidence_json, '$.errorClass') = ?5 \
                  AND json_extract(outcome.evidence_json, '$.evidence.classification') = ?7 \
                  AND event.aggregate_kind = 'effect' AND event.aggregate_id = ?2 \
                  AND event.event_type = 'effect.outcome_unknown' AND event.event_version = 1 \
                  AND event.occurred_at_ms = ?4 AND event.correlation_id = ?8 \
                  AND json_extract(event.payload_json, '$.recovery') = 1\
            )",
            params![
                commit.attempt_id.to_string(),
                commit.effect_id.to_string(),
                commit.event_id.to_string(),
                recovered_at_ms,
                INTERRUPTED_EFFECT_OUTCOME_ERROR_CLASS,
                recovered_revision,
                INTERRUPTED_EFFECT_OUTCOME_CLASSIFICATION,
                commit.correlation_id.to_string(),
            ],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error)
}

struct InterruptedRecoveryEvidence {
    policy_version: String,
    idempotency: IdempotencyClass,
    recovery: RecoveryStrategy,
    idempotency_key: Option<String>,
    disposition: EffectRecoveryDisposition,
    lease_id: String,
    run_id: String,
    owner_id: String,
    fencing_token: i64,
    lease_state: String,
    lease_expires_at_ms: i64,
    lease_released_at_ms: i64,
}

#[allow(clippy::too_many_lines)] // Keep the journal, outcome, effect, and attempt writes auditable together.
pub(super) fn recover_interrupted_effect_transaction(
    transaction: &Transaction<'_>,
    commit: &RecoverInterruptedEffectCommit,
    expected_revision: i64,
    recovered_at_ms: i64,
) -> Result<(), EffectLedgerStoreError> {
    let evidence = load_interrupted_recovery_evidence(
        transaction,
        commit.effect_id,
        commit.attempt_id,
        expected_revision,
        recovered_at_ms,
    )?;
    if matches!(
        evidence.disposition,
        EffectRecoveryDisposition::ResumePrepared
            | EffectRecoveryDisposition::Retry
            | EffectRecoveryDisposition::RetryWithSameKey
    ) {
        return Err(EffectLedgerStoreError::Conflict);
    }
    let details = json!({
        "classification": INTERRUPTED_EFFECT_OUTCOME_CLASSIFICATION,
        "idempotency": evidence.idempotency,
        "idempotencyKey": evidence.idempotency_key,
        "interruptedBoundary": "running",
        "leaseExpiresAtMs": evidence.lease_expires_at_ms,
        "leaseId": evidence.lease_id,
        "leaseReleasedAtMs": evidence.lease_released_at_ms,
        "leaseState": evidence.lease_state,
        "ownerId": evidence.owner_id,
        "recoveryDisposition": disposition_text(evidence.disposition),
        "recoveryStrategy": evidence.recovery,
        "runId": evidence.run_id,
        "fencingToken": evidence.fencing_token,
    });
    let outcome_evidence = canonical_outcome_evidence(
        commit.effect_id,
        commit.attempt_id,
        0,
        EffectOutcomeKind::OutcomeUnknown,
        &details,
        Some(INTERRUPTED_EFFECT_OUTCOME_ERROR_CLASS),
        recovered_at_ms,
    )?;
    let new_revision = next_effect_revision(expected_revision)?;
    let effect_id = commit.effect_id.to_string();
    let sequence = next_sequence(transaction, "effect", &effect_id)?;
    append_event(
        transaction,
        &EventAppend {
            event_id: commit.event_id,
            aggregate_kind: "effect",
            aggregate_id: &effect_id,
            sequence,
            event_type: "effect.outcome_unknown",
            occurred_at_ms: recovered_at_ms,
            actor_principal_id: None,
            correlation_id: commit.correlation_id,
            policy_version: Some(&evidence.policy_version),
            payload: json!({
                "attempt_id": commit.attempt_id,
                "effect_id": commit.effect_id,
                "effect_revision": new_revision,
                "error_class": INTERRUPTED_EFFECT_OUTCOME_ERROR_CLASS,
                "evidence_digest": outcome_evidence.digest,
                "outcome": EffectOutcomeKind::OutcomeUnknown,
                "recovery": true,
                "recovery_disposition": disposition_text(evidence.disposition),
            }),
        },
    )?;
    insert_effect_outcome(
        transaction,
        &EffectOutcomeInsert {
            attempt_id: commit.attempt_id,
            effect_id: commit.effect_id,
            sequence: 0,
            kind: EffectOutcomeKind::OutcomeUnknown,
            evidence: &outcome_evidence,
            event_id: commit.event_id,
            recorded_at_ms: recovered_at_ms,
        },
    )?;
    let effect_changed = transaction
        .execute(
            "UPDATE effect \
             SET status = 'outcome_unknown', revision = revision + 1, \
                 completed_at_ms = ?1, updated_at_ms = ?1 \
             WHERE id = ?2 AND status = 'dispatching' AND revision = ?3",
            params![recovered_at_ms, effect_id, expected_revision],
        )
        .map_err(map_sqlite_error)?;
    if effect_changed != 1 {
        return Err(EffectLedgerStoreError::Conflict);
    }
    let attempt_changed = transaction
        .execute(
            "UPDATE effect_attempt \
             SET state = 'outcome_unknown', terminal_event_id = ?1, completed_at_ms = ?2, \
                 error_class = ?3 \
             WHERE attempt_id = ?4 AND effect_id = ?5 AND state = 'running'",
            params![
                commit.event_id.to_string(),
                recovered_at_ms,
                INTERRUPTED_EFFECT_OUTCOME_ERROR_CLASS,
                commit.attempt_id.to_string(),
                effect_id,
            ],
        )
        .map_err(map_sqlite_error)?;
    if attempt_changed != 1 {
        return Err(EffectLedgerStoreError::Conflict);
    }
    set_sequence(transaction, "effect", &effect_id, sequence)
}

#[allow(clippy::too_many_lines)] // One transaction intentionally exposes every undispatched invariant.
pub(super) fn recover_undispatched_effect_transaction(
    transaction: &Transaction<'_>,
    commit: &RecoverInterruptedEffectCommit,
    expected_revision: i64,
    recovered_at_ms: i64,
) -> Result<(), EffectLedgerStoreError> {
    let evidence = transaction
        .query_row(
            "SELECT policy.policy_version, intent.idempotency_key, attempt.prepared_at_ms, \
                    effect.updated_at_ms, lease.lease_id, lease.run_id, lease.owner_id, \
                    lease.fencing_token, lease.state, lease.expires_at_ms, lease.released_at_ms \
             FROM effect_attempt attempt \
             JOIN effect ON effect.id = attempt.effect_id \
             JOIN effect_intent intent ON intent.effect_id = effect.id \
             JOIN effect_policy_evaluation policy ON policy.effect_id = effect.id \
             JOIN work_lease lease \
               ON lease.lease_id = attempt.prepared_lease_id \
              AND lease.run_id = intent.run_id \
              AND lease.owner_id = attempt.prepared_owner_id \
              AND lease.fencing_token = attempt.prepared_fencing_token \
             WHERE attempt.attempt_id = ?1 AND attempt.effect_id = ?2 \
               AND attempt.state = 'prepared' AND effect.status = 'authorized' \
               AND effect.revision = ?3 AND attempt.idempotency_key IS intent.idempotency_key \
               AND lease.state IN ('released', 'expired')",
            params![
                commit.attempt_id.to_string(),
                commit.effect_id.to_string(),
                expected_revision,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(EffectLedgerStoreError::Conflict)?;
    let (
        policy_version,
        idempotency_key,
        prepared_at_ms,
        previous_updated_at_ms,
        lease_id,
        run_id,
        owner_id,
        fencing_token,
        lease_state,
        lease_expires_at_ms,
        lease_released_at_ms,
    ) = evidence;
    let released_at_ms = lease_released_at_ms.ok_or(EffectLedgerStoreError::Conflict)?;
    if recovered_at_ms < released_at_ms
        || recovered_at_ms < prepared_at_ms
        || recovered_at_ms < previous_updated_at_ms
    {
        return Err(EffectLedgerStoreError::Conflict);
    }
    let new_revision = next_effect_revision(expected_revision)?;
    let effect_id = commit.effect_id.to_string();
    let sequence = next_sequence(transaction, "effect", &effect_id)?;
    append_event(
        transaction,
        &EventAppend {
            event_id: commit.event_id,
            aggregate_kind: "effect",
            aggregate_id: &effect_id,
            sequence,
            event_type: "effect.preparation_interrupted",
            occurred_at_ms: recovered_at_ms,
            actor_principal_id: None,
            correlation_id: commit.correlation_id,
            policy_version: Some(&policy_version),
            payload: json!({
                "attempt_id": commit.attempt_id,
                "classification": INTERRUPTED_EFFECT_UNDISPATCHED_CLASSIFICATION,
                "effect_id": commit.effect_id,
                "effect_revision": new_revision,
                "error_class": INTERRUPTED_EFFECT_UNDISPATCHED_ERROR_CLASS,
                "fencing_token": fencing_token,
                "idempotency_key": idempotency_key,
                "lease_expires_at_ms": lease_expires_at_ms,
                "lease_id": lease_id,
                "lease_released_at_ms": released_at_ms,
                "lease_state": lease_state,
                "owner_id": owner_id,
                "run_id": run_id,
                "recovery": true,
            }),
        },
    )?;
    let attempt_changed = transaction
        .execute(
            "UPDATE effect_attempt \
             SET state = 'interrupted_undispatched', terminal_event_id = ?1, \
                 completed_at_ms = ?2, error_class = ?3 \
             WHERE attempt_id = ?4 AND effect_id = ?5 AND state = 'prepared'",
            params![
                commit.event_id.to_string(),
                recovered_at_ms,
                INTERRUPTED_EFFECT_UNDISPATCHED_ERROR_CLASS,
                commit.attempt_id.to_string(),
                effect_id,
            ],
        )
        .map_err(map_sqlite_error)?;
    if attempt_changed != 1 {
        return Err(EffectLedgerStoreError::Conflict);
    }
    let effect_changed = transaction
        .execute(
            "UPDATE effect SET revision = revision + 1, updated_at_ms = ?1 \
             WHERE id = ?2 AND status = 'authorized' AND revision = ?3",
            params![recovered_at_ms, effect_id, expected_revision],
        )
        .map_err(map_sqlite_error)?;
    if effect_changed != 1 {
        return Err(EffectLedgerStoreError::Conflict);
    }
    set_sequence(transaction, "effect", &effect_id, sequence)
}

#[allow(clippy::too_many_lines)] // Canonical evidence and retry authorization must remain co-located.
pub(super) fn recover_retryable_effect_transaction(
    transaction: &Transaction<'_>,
    commit: &RecoverInterruptedEffectCommit,
    expected_revision: i64,
    recovered_at_ms: i64,
) -> Result<(), EffectLedgerStoreError> {
    let evidence = load_interrupted_recovery_evidence(
        transaction,
        commit.effect_id,
        commit.attempt_id,
        expected_revision,
        recovered_at_ms,
    )?;
    if !matches!(
        evidence.disposition,
        EffectRecoveryDisposition::Retry | EffectRecoveryDisposition::RetryWithSameKey
    ) {
        return Err(EffectLedgerStoreError::Conflict);
    }
    let details = json!({
        "classification": INTERRUPTED_EFFECT_RETRY_CLASSIFICATION,
        "idempotency": evidence.idempotency,
        "idempotencyKey": evidence.idempotency_key,
        "interruptedBoundary": "running",
        "leaseExpiresAtMs": evidence.lease_expires_at_ms,
        "leaseId": evidence.lease_id,
        "leaseReleasedAtMs": evidence.lease_released_at_ms,
        "leaseState": evidence.lease_state,
        "ownerId": evidence.owner_id,
        "recoveryDisposition": disposition_text(evidence.disposition),
        "recoveryStrategy": evidence.recovery,
        "runId": evidence.run_id,
        "fencingToken": evidence.fencing_token,
    });
    let outcome_evidence = canonical_outcome_evidence(
        commit.effect_id,
        commit.attempt_id,
        0,
        EffectOutcomeKind::OutcomeUnknown,
        &details,
        Some(INTERRUPTED_EFFECT_RETRY_ERROR_CLASS),
        recovered_at_ms,
    )?;
    let new_revision = next_effect_revision(expected_revision)?;
    let effect_id = commit.effect_id.to_string();
    let sequence = next_sequence(transaction, "effect", &effect_id)?;
    append_event(
        transaction,
        &EventAppend {
            event_id: commit.event_id,
            aggregate_kind: "effect",
            aggregate_id: &effect_id,
            sequence,
            event_type: "effect.retry_authorized",
            occurred_at_ms: recovered_at_ms,
            actor_principal_id: None,
            correlation_id: commit.correlation_id,
            policy_version: Some(&evidence.policy_version),
            payload: json!({
                "attempt_id": commit.attempt_id,
                "effect_id": commit.effect_id,
                "effect_revision": new_revision,
                "error_class": INTERRUPTED_EFFECT_RETRY_ERROR_CLASS,
                "evidence_digest": outcome_evidence.digest,
                "outcome": EffectOutcomeKind::OutcomeUnknown,
                "recovery": true,
                "recovery_disposition": disposition_text(evidence.disposition),
                "retry_authorized": true,
            }),
        },
    )?;
    insert_effect_outcome(
        transaction,
        &EffectOutcomeInsert {
            attempt_id: commit.attempt_id,
            effect_id: commit.effect_id,
            sequence: 0,
            kind: EffectOutcomeKind::OutcomeUnknown,
            evidence: &outcome_evidence,
            event_id: commit.event_id,
            recorded_at_ms: recovered_at_ms,
        },
    )?;
    let effect_changed = transaction
        .execute(
            "UPDATE effect SET status = 'authorized', revision = revision + 1, updated_at_ms = ?1 \
             WHERE id = ?2 AND status = 'dispatching' AND revision = ?3",
            params![recovered_at_ms, effect_id, expected_revision],
        )
        .map_err(map_sqlite_error)?;
    if effect_changed != 1 {
        return Err(EffectLedgerStoreError::Conflict);
    }
    let attempt_changed = transaction
        .execute(
            "UPDATE effect_attempt \
             SET state = 'interrupted_retryable', terminal_event_id = ?1, \
                 completed_at_ms = ?2, error_class = ?3 \
             WHERE attempt_id = ?4 AND effect_id = ?5 AND state = 'running'",
            params![
                commit.event_id.to_string(),
                recovered_at_ms,
                INTERRUPTED_EFFECT_RETRY_ERROR_CLASS,
                commit.attempt_id.to_string(),
                effect_id,
            ],
        )
        .map_err(map_sqlite_error)?;
    if attempt_changed != 1 {
        return Err(EffectLedgerStoreError::Conflict);
    }
    set_sequence(transaction, "effect", &effect_id, sequence)
}

fn load_interrupted_recovery_evidence(
    transaction: &Transaction<'_>,
    effect_id: EffectId,
    attempt_id: AttemptId,
    expected_revision: i64,
    recovered_at_ms: i64,
) -> Result<InterruptedRecoveryEvidence, EffectLedgerStoreError> {
    let row = transaction
        .query_row(
            "SELECT policy.policy_version, intent.idempotency_class, intent.recovery_strategy, \
                    intent.idempotency_key, attempt.started_at_ms, effect.updated_at_ms, \
                    lease.lease_id, lease.run_id, lease.owner_id, lease.fencing_token, \
                    lease.state, lease.expires_at_ms, lease.released_at_ms \
             FROM effect_attempt attempt \
             JOIN effect ON effect.id = attempt.effect_id \
             JOIN effect_intent intent ON intent.effect_id = effect.id \
             JOIN effect_policy_evaluation policy ON policy.effect_id = effect.id \
             JOIN work_lease lease \
               ON lease.lease_id = attempt.prepared_lease_id \
              AND lease.run_id = intent.run_id \
              AND lease.owner_id = attempt.prepared_owner_id \
              AND lease.fencing_token = attempt.prepared_fencing_token \
             WHERE attempt.attempt_id = ?1 AND attempt.effect_id = ?2 \
               AND attempt.state = 'running' AND effect.status = 'dispatching' \
               AND effect.revision = ?3 AND attempt.idempotency_key IS intent.idempotency_key \
               AND NOT EXISTS(\
                   SELECT 1 FROM effect_outcome outcome \
                   WHERE outcome.attempt_id = attempt.attempt_id\
               )",
            params![
                attempt_id.to_string(),
                effect_id.to_string(),
                expected_revision
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, Option<i64>>(12)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(EffectLedgerStoreError::Conflict)?;
    let (
        policy_version,
        idempotency_text,
        recovery_text,
        idempotency_key,
        started_at_ms,
        previous_updated_at_ms,
        lease_id,
        run_id,
        owner_id,
        fencing_token,
        lease_state,
        lease_expires_at_ms,
        lease_released_at_ms,
    ) = row;
    let inactive_at_ms = match (lease_state.as_str(), lease_released_at_ms) {
        ("released" | "expired", Some(released_at_ms)) => released_at_ms,
        ("active", _) | (_, None) => return Err(EffectLedgerStoreError::Conflict),
        _ => return Err(invariant("stored work lease state is invalid")),
    };
    if recovered_at_ms < inactive_at_ms
        || recovered_at_ms < started_at_ms
        || recovered_at_ms < previous_updated_at_ms
    {
        return Err(EffectLedgerStoreError::Conflict);
    }
    let idempotency = parse_idempotency(&idempotency_text)?;
    let recovery = parse_recovery_strategy(&recovery_text)?;
    let disposition = classify_recovery(EffectAttemptBoundary::Running, idempotency, recovery);
    Ok(InterruptedRecoveryEvidence {
        policy_version,
        idempotency,
        recovery,
        idempotency_key,
        disposition,
        lease_id,
        run_id,
        owner_id,
        fencing_token,
        lease_state,
        lease_expires_at_ms,
        lease_released_at_ms: lease_released_at_ms
            .ok_or_else(|| invariant("inactive lease lacks release time"))?,
    })
}

fn load_attempt_started_at(
    transaction: &Transaction<'_>,
    attempt_id: AttemptId,
) -> Result<i64, EffectLedgerStoreError> {
    transaction
        .query_row(
            "SELECT started_at_ms FROM effect_attempt WHERE attempt_id = ?1",
            [attempt_id.to_string()],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .flatten()
        .ok_or(EffectLedgerStoreError::Conflict)
}

fn reconcile_effect_outcome_transaction(
    transaction: &Transaction<'_>,
    commit: &ReconcileEffectOutcomeCommit,
    expected_revision: i64,
    reconciled_at_ms: i64,
) -> Result<(), EffectLedgerStoreError> {
    let new_revision = next_effect_revision(expected_revision)?;
    authorize_effect_owner(transaction, commit.ownership, commit.effect_id)?;
    let (policy_version, previous_updated_at_ms) = transaction
        .query_row(
            "SELECT policy.policy_version, effect.updated_at_ms \
             FROM effect \
             JOIN effect_policy_evaluation policy ON policy.effect_id = effect.id \
             JOIN effect_attempt attempt ON attempt.effect_id = effect.id \
             JOIN effect_outcome outcome \
               ON outcome.attempt_id = attempt.attempt_id AND outcome.effect_id = attempt.effect_id \
             WHERE effect.id = ?1 AND effect.status = 'outcome_unknown' \
               AND effect.revision = ?2 AND attempt.attempt_id = ?3 \
               AND attempt.state = 'outcome_unknown' AND outcome.sequence = 0 \
               AND outcome.outcome_kind = 'outcome_unknown' \
               AND NOT EXISTS(\
                   SELECT 1 FROM effect_outcome later \
                   WHERE later.attempt_id = attempt.attempt_id AND later.sequence > 0\
               )",
            params![
                commit.effect_id.to_string(),
                expected_revision,
                commit.attempt_id.to_string(),
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(EffectLedgerStoreError::Conflict)?;
    if reconciled_at_ms < previous_updated_at_ms {
        return Err(EffectLedgerStoreError::Conflict);
    }
    let kind = commit.outcome.kind();
    let evidence = canonical_outcome_evidence(
        commit.effect_id,
        commit.attempt_id,
        1,
        kind,
        &commit.evidence_details,
        None,
        reconciled_at_ms,
    )?;
    let effect_id = commit.effect_id.to_string();
    let sequence = next_sequence(transaction, "effect", &effect_id)?;
    append_event(
        transaction,
        &EventAppend {
            event_id: commit.event_id,
            aggregate_kind: "effect",
            aggregate_id: &effect_id,
            sequence,
            event_type: "effect.reconciled",
            occurred_at_ms: reconciled_at_ms,
            actor_principal_id: Some(commit.ownership.principal_id()),
            correlation_id: commit.correlation_id,
            policy_version: Some(&policy_version),
            payload: json!({
                "attempt_id": commit.attempt_id,
                "effect_id": commit.effect_id,
                "effect_revision": new_revision,
                "evidence_digest": evidence.digest,
                "outcome": kind,
            }),
        },
    )?;
    insert_effect_outcome(
        transaction,
        &EffectOutcomeInsert {
            attempt_id: commit.attempt_id,
            effect_id: commit.effect_id,
            sequence: 1,
            kind,
            evidence: &evidence,
            event_id: commit.event_id,
            recorded_at_ms: reconciled_at_ms,
        },
    )?;
    let changed = transaction
        .execute(
            "UPDATE effect SET status = ?1, revision = revision + 1, updated_at_ms = ?2 \
             WHERE id = ?3 AND status = 'outcome_unknown' AND revision = ?4",
            params![
                effect_outcome_kind_text(kind),
                reconciled_at_ms,
                effect_id,
                expected_revision,
            ],
        )
        .map_err(map_sqlite_error)?;
    if changed != 1 {
        return Err(EffectLedgerStoreError::Conflict);
    }
    set_sequence(transaction, "effect", &effect_id, sequence)
}

struct EffectOutcomeInsert<'a> {
    attempt_id: AttemptId,
    effect_id: EffectId,
    sequence: i64,
    kind: EffectOutcomeKind,
    evidence: &'a CanonicalOutcomeEvidence,
    event_id: EventId,
    recorded_at_ms: i64,
}

fn insert_effect_outcome(
    transaction: &Transaction<'_>,
    outcome: &EffectOutcomeInsert<'_>,
) -> Result<(), EffectLedgerStoreError> {
    transaction
        .execute(
            "INSERT INTO effect_outcome(\
                attempt_id, effect_id, sequence, outcome_kind, evidence_json, evidence_digest, \
                event_id, recorded_at_ms\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                outcome.attempt_id.to_string(),
                outcome.effect_id.to_string(),
                outcome.sequence,
                effect_outcome_kind_text(outcome.kind),
                outcome.evidence.json,
                outcome.evidence.digest,
                outcome.event_id.to_string(),
                outcome.recorded_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn authorize_effect_owner(
    connection: &Connection,
    ownership: OwnershipContext,
    effect_id: EffectId,
) -> Result<(), EffectLedgerStoreError> {
    connection
        .query_row(
            "SELECT 1 FROM effect_intent intent \
             JOIN session owner_session ON owner_session.id = intent.session_id \
             WHERE intent.effect_id = ?1 AND owner_session.principal_id = ?2 \
               AND owner_session.channel_binding_id = ?3",
            params![
                effect_id.to_string(),
                ownership.principal_id().to_string(),
                ownership.channel_binding_id().to_string(),
            ],
            |_| Ok(()),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(EffectLedgerStoreError::NotFound)
}

fn validate_active_fence(
    connection: &Connection,
    fence: LeaseFence,
    observed_at_ms: i64,
) -> Result<(), EffectLedgerStoreError> {
    connection
        .query_row(
            "SELECT 1 FROM work_lease lease \
             JOIN run ON run.id = lease.run_id \
             WHERE lease.lease_id = ?1 AND lease.run_id = ?2 AND lease.owner_id = ?3 \
               AND lease.fencing_token = ?4 AND lease.state = 'active' \
               AND lease.acquired_at_ms <= ?5 AND ?5 < lease.expires_at_ms \
               AND run.status = 'running' AND run.current_fencing_token = lease.fencing_token",
            params![
                fence.lease_id().to_string(),
                fence.run_id().to_string(),
                fence.owner_id().to_string(),
                fence_token_i64(fence)?,
                observed_at_ms,
            ],
            |_| Ok(()),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(EffectLedgerStoreError::Conflict)
}

fn fence_token_i64(fence: LeaseFence) -> Result<i64, EffectLedgerStoreError> {
    i64::try_from(fence.fencing_token().get())
        .map_err(|_| invalid("fencing token exceeds SQLite range"))
}

fn sqlite_revision(revision: u64) -> Result<i64, EffectLedgerStoreError> {
    i64::try_from(revision).map_err(|_| invalid("effect revision exceeds SQLite range"))
}

fn next_effect_revision(revision: i64) -> Result<i64, EffectLedgerStoreError> {
    revision
        .checked_add(1)
        .ok_or_else(|| invariant("effect revision overflow"))
}

const fn initial_outcome_event_type(outcome: EffectAttemptOutcome) -> &'static str {
    match outcome {
        EffectAttemptOutcome::Succeeded => "effect.succeeded",
        EffectAttemptOutcome::Failed => "effect.failed",
        EffectAttemptOutcome::OutcomeUnknown => "effect.outcome_unknown",
    }
}

struct EffectAttemptRow {
    attempt_id: String,
    effect_id: String,
    ordinal: i64,
    state: String,
    idempotency_key: Option<String>,
    lease_id: String,
    owner_id: String,
    fencing_token: i64,
    prepared_event_id: String,
    started_event_id: Option<String>,
    terminal_event_id: Option<String>,
    prepared_at_ms: i64,
    started_at_ms: Option<i64>,
    completed_at_ms: Option<i64>,
    error_class: Option<String>,
    intent_idempotency_key: Option<String>,
    run_id: String,
}

pub(super) fn load_effect_attempt_view(
    connection: &Connection,
    ownership: Option<OwnershipContext>,
    attempt_id: AttemptId,
) -> Result<EffectAttemptView, EffectLedgerStoreError> {
    let owner_principal = ownership.map(|value| value.principal_id().to_string());
    let owner_channel = ownership.map(|value| value.channel_binding_id().to_string());
    let row = connection
        .query_row(
            "SELECT attempt.attempt_id, attempt.effect_id, attempt.ordinal, attempt.state, \
                    attempt.idempotency_key, attempt.prepared_lease_id, \
                    attempt.prepared_owner_id, attempt.prepared_fencing_token, \
                    attempt.prepared_event_id, attempt.started_event_id, \
                    attempt.terminal_event_id, attempt.prepared_at_ms, attempt.started_at_ms, \
                    attempt.completed_at_ms, attempt.error_class, intent.idempotency_key, \
                    intent.run_id \
             FROM effect_attempt attempt \
             JOIN effect_intent intent ON intent.effect_id = attempt.effect_id \
             JOIN session owner_session ON owner_session.id = intent.session_id \
             WHERE attempt.attempt_id = ?1 \
               AND (?2 IS NULL OR owner_session.principal_id = ?2) \
               AND (?3 IS NULL OR owner_session.channel_binding_id = ?3)",
            params![attempt_id.to_string(), owner_principal, owner_channel],
            |result| {
                Ok(EffectAttemptRow {
                    attempt_id: result.get(0)?,
                    effect_id: result.get(1)?,
                    ordinal: result.get(2)?,
                    state: result.get(3)?,
                    idempotency_key: result.get(4)?,
                    lease_id: result.get(5)?,
                    owner_id: result.get(6)?,
                    fencing_token: result.get(7)?,
                    prepared_event_id: result.get(8)?,
                    started_event_id: result.get(9)?,
                    terminal_event_id: result.get(10)?,
                    prepared_at_ms: result.get(11)?,
                    started_at_ms: result.get(12)?,
                    completed_at_ms: result.get(13)?,
                    error_class: result.get(14)?,
                    intent_idempotency_key: result.get(15)?,
                    run_id: result.get(16)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(EffectLedgerStoreError::NotFound)?;
    hydrate_effect_attempt_view(connection, row)
}

fn hydrate_effect_attempt_view(
    connection: &Connection,
    row: EffectAttemptRow,
) -> Result<EffectAttemptView, EffectLedgerStoreError> {
    let attempt_id = parse_id(&row.attempt_id, "effect attempt ID")?;
    let effect_id = parse_id(&row.effect_id, "effect ID")?;
    let run_id = parse_id(&row.run_id, "run ID")?;
    let lease_id: LeaseId = parse_id(&row.lease_id, "lease ID")?;
    let owner_id: WorkerId = parse_id(&row.owner_id, "worker ID")?;
    let fencing_token = u64::try_from(row.fencing_token)
        .ok()
        .and_then(FencingToken::new)
        .ok_or_else(|| invariant("stored effect attempt fencing token is invalid"))?;
    if row.idempotency_key != row.intent_idempotency_key {
        return Err(invariant(
            "stored attempt idempotency key diverged from intent",
        ));
    }
    let state = parse_effect_attempt_state(&row.state)?;
    let outcomes = load_effect_outcomes(connection, attempt_id, effect_id)?;
    validate_attempt_lifecycle(&row, state, &outcomes)?;
    Ok(EffectAttemptView {
        attempt_id,
        effect_id,
        ordinal: u64::try_from(row.ordinal)
            .map_err(|_| invariant("stored effect attempt ordinal is invalid"))?,
        state,
        idempotency_key: row.idempotency_key,
        fence: LeaseFence::new(lease_id, run_id, owner_id, fencing_token),
        prepared_event_id: parse_id(&row.prepared_event_id, "prepared event ID")?,
        started_event_id: row
            .started_event_id
            .as_deref()
            .map(|value| parse_id(value, "started event ID"))
            .transpose()?,
        terminal_event_id: row
            .terminal_event_id
            .as_deref()
            .map(|value| parse_id(value, "terminal event ID"))
            .transpose()?,
        prepared_at: system_time(row.prepared_at_ms)?,
        started_at: row.started_at_ms.map(system_time).transpose()?,
        completed_at: row.completed_at_ms.map(system_time).transpose()?,
        error_class: row.error_class,
        outcomes,
    })
}

fn load_effect_outcomes(
    connection: &Connection,
    attempt_id: AttemptId,
    effect_id: EffectId,
) -> Result<Vec<EffectOutcomeView>, EffectLedgerStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT sequence, outcome_kind, evidence_json, evidence_digest, event_id, \
                    recorded_at_ms \
             FROM effect_outcome WHERE attempt_id = ?1 AND effect_id = ?2 ORDER BY sequence",
        )
        .map_err(map_sqlite_error)?;
    let rows = statement
        .query_map(
            params![attempt_id.to_string(), effect_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .map_err(map_sqlite_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_sqlite_error)?;
    rows.into_iter()
        .enumerate()
        .map(
            |(expected_sequence, (sequence, kind, evidence_json, digest, event_id, recorded))| {
                let sequence = u64::try_from(sequence)
                    .map_err(|_| invariant("stored effect outcome sequence is invalid"))?;
                if sequence
                    != u64::try_from(expected_sequence)
                        .map_err(|_| invariant("effect outcome sequence overflow"))?
                {
                    return Err(invariant("stored effect outcome sequence has a gap"));
                }
                let kind = parse_effect_outcome_kind(&kind)?;
                let evidence: serde_json::Value =
                    serde_json::from_str(&evidence_json).map_err(|error| {
                        invariant(format!("stored outcome evidence is invalid: {error}"))
                    })?;
                validate_stored_outcome_evidence(
                    effect_id, attempt_id, sequence, kind, recorded, &evidence, &digest,
                )?;
                Ok(EffectOutcomeView {
                    sequence,
                    kind,
                    evidence,
                    evidence_digest: digest,
                    event_id: parse_id(&event_id, "effect outcome event ID")?,
                    recorded_at: system_time(recorded)?,
                })
            },
        )
        .collect()
}

fn validate_stored_outcome_evidence(
    effect_id: EffectId,
    attempt_id: AttemptId,
    sequence: u64,
    kind: EffectOutcomeKind,
    recorded_at_ms: i64,
    evidence: &serde_json::Value,
    digest: &str,
) -> Result<(), EffectLedgerStoreError> {
    let details = evidence
        .get("evidence")
        .ok_or_else(|| invariant("stored outcome evidence details are absent"))?;
    let error_class = match evidence.get("errorClass") {
        Some(serde_json::Value::String(value)) => Some(value.as_str()),
        Some(serde_json::Value::Null) => None,
        _ => return Err(invariant("stored outcome error class is invalid")),
    };
    let expected = effect_outcome_evidence_material(
        effect_id,
        attempt_id,
        sequence,
        kind,
        details,
        error_class,
        recorded_at_ms,
    )
    .map_err(|error| invariant(error.to_string()))?;
    if &expected != evidence || sha256_digest(evidence.to_string().as_bytes()) != digest {
        return Err(invariant("stored canonical outcome evidence diverged"));
    }
    Ok(())
}

fn validate_attempt_lifecycle(
    row: &EffectAttemptRow,
    state: EffectAttemptState,
    outcomes: &[EffectOutcomeView],
) -> Result<(), EffectLedgerStoreError> {
    let consistent = match state {
        EffectAttemptState::Prepared => {
            row.started_event_id.is_none()
                && row.terminal_event_id.is_none()
                && row.started_at_ms.is_none()
                && row.completed_at_ms.is_none()
                && row.error_class.is_none()
                && outcomes.is_empty()
        }
        EffectAttemptState::Running => {
            row.started_event_id.is_some()
                && row.terminal_event_id.is_none()
                && row.started_at_ms.is_some()
                && row.completed_at_ms.is_none()
                && row.error_class.is_none()
                && outcomes.is_empty()
        }
        EffectAttemptState::Succeeded => {
            completed_lifecycle(row, outcomes, EffectOutcomeKind::Succeeded)
                && row.error_class.is_none()
                && outcomes.len() == 1
        }
        EffectAttemptState::Failed => {
            completed_lifecycle(row, outcomes, EffectOutcomeKind::Failed)
                && row.error_class.is_some()
                && outcomes.len() == 1
        }
        EffectAttemptState::OutcomeUnknown => {
            completed_lifecycle(row, outcomes, EffectOutcomeKind::OutcomeUnknown)
                && row.error_class.is_some()
                && outcomes.len() <= 2
                && outcomes.get(1).is_none_or(|outcome| {
                    matches!(
                        outcome.kind,
                        EffectOutcomeKind::Succeeded
                            | EffectOutcomeKind::Failed
                            | EffectOutcomeKind::Compensated
                    )
                })
        }
        EffectAttemptState::InterruptedRetryable => {
            completed_lifecycle(row, outcomes, EffectOutcomeKind::OutcomeUnknown)
                && row.error_class.as_deref() == Some(INTERRUPTED_EFFECT_RETRY_ERROR_CLASS)
                && outcomes.len() == 1
        }
        EffectAttemptState::InterruptedUndispatched => {
            row.started_event_id.is_none()
                && row.terminal_event_id.is_some()
                && row.started_at_ms.is_none()
                && row.completed_at_ms.is_some()
                && row.error_class.as_deref() == Some(INTERRUPTED_EFFECT_UNDISPATCHED_ERROR_CLASS)
                && outcomes.is_empty()
        }
    };
    if !consistent {
        return Err(invariant(
            "stored effect attempt lifecycle evidence diverged",
        ));
    }
    Ok(())
}

fn completed_lifecycle(
    row: &EffectAttemptRow,
    outcomes: &[EffectOutcomeView],
    initial_kind: EffectOutcomeKind,
) -> bool {
    row.started_event_id.is_some()
        && row.terminal_event_id.is_some()
        && row.started_at_ms.is_some()
        && row.completed_at_ms.is_some()
        && outcomes
            .first()
            .is_some_and(|outcome| outcome.kind == initial_kind)
}

fn parse_effect_attempt_state(value: &str) -> Result<EffectAttemptState, EffectLedgerStoreError> {
    match value {
        "prepared" => Ok(EffectAttemptState::Prepared),
        "running" => Ok(EffectAttemptState::Running),
        "succeeded" => Ok(EffectAttemptState::Succeeded),
        "failed" => Ok(EffectAttemptState::Failed),
        "outcome_unknown" => Ok(EffectAttemptState::OutcomeUnknown),
        "interrupted_retryable" => Ok(EffectAttemptState::InterruptedRetryable),
        "interrupted_undispatched" => Ok(EffectAttemptState::InterruptedUndispatched),
        _ => Err(invariant("stored effect attempt state is invalid")),
    }
}

const fn effect_outcome_kind_text(kind: EffectOutcomeKind) -> &'static str {
    match kind {
        EffectOutcomeKind::Succeeded => "succeeded",
        EffectOutcomeKind::Failed => "failed",
        EffectOutcomeKind::OutcomeUnknown => "outcome_unknown",
        EffectOutcomeKind::Compensated => "compensated",
    }
}

fn parse_effect_outcome_kind(value: &str) -> Result<EffectOutcomeKind, EffectLedgerStoreError> {
    match value {
        "succeeded" => Ok(EffectOutcomeKind::Succeeded),
        "failed" => Ok(EffectOutcomeKind::Failed),
        "outcome_unknown" => Ok(EffectOutcomeKind::OutcomeUnknown),
        "compensated" => Ok(EffectOutcomeKind::Compensated),
        _ => Err(invariant("stored effect outcome kind is invalid")),
    }
}

struct ProposalEvidence {
    proposed_at_ms: i64,
    status: &'static str,
    intent_json: String,
    intent_digest: String,
    descriptor_json: String,
    arguments_json: String,
    arguments_digest: String,
    target_resources_json: String,
    policy_request_json: String,
    policy_request_digest: String,
    obligations_json: String,
    obligations_digest: String,
    idempotency_key: Option<String>,
    effect_class: String,
    risk_class: String,
    executor_kind: String,
    idempotency_class: String,
    recovery_strategy: String,
    recovery_action: &'static str,
}

impl ProposalEvidence {
    fn prepare(commit: &RecordEffectProposalCommit) -> Result<Self, EffectLedgerStoreError> {
        commit
            .policy_request
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        validate_policy_evaluation(&commit.policy_request, &commit.policy_evaluation)?;
        validate_approval_draft(commit)?;
        let proposed_at_ms = epoch_milliseconds(commit.proposed_at)?;
        if proposed_at_ms != commit.policy_request.evaluated_at_ms {
            return Err(invalid(
                "proposal time must equal the recorded policy evaluation time",
            ));
        }
        if commit.policy_request.principal_id != commit.ownership.principal_id()
            || commit.policy_request.channel_binding_id != commit.ownership.channel_binding_id()
        {
            return Err(EffectLedgerStoreError::NotFound);
        }
        let intent_json = effect_intent_material(commit.effect_id, &commit.policy_request)
            .map_err(|error| invalid(error.to_string()))?
            .to_string();
        let intent_digest = effect_intent_digest(commit.effect_id, &commit.policy_request)
            .map_err(|error| invalid(error.to_string()))?;
        let descriptor_json = serde_json::to_string(&commit.policy_request.tool)
            .map_err(|error| invalid(error.to_string()))?;
        let arguments_json = commit.policy_request.normalized_arguments.to_string();
        let arguments_digest =
            canonical_arguments_digest(&commit.policy_request.normalized_arguments);
        let target_resources_json = serde_json::to_string(&commit.policy_request.target_resources)
            .map_err(|error| invalid(error.to_string()))?;
        let policy_request_json = serde_json::to_string(&commit.policy_request)
            .map_err(|error| invalid(error.to_string()))?;
        let policy_request_digest = sha256_digest(policy_request_json.as_bytes());
        let obligations_json = serde_json::to_string(&commit.policy_evaluation.obligations)
            .map_err(|error| invalid(error.to_string()))?;
        let obligations_digest = sha256_digest(obligations_json.as_bytes());
        let idempotency_key = (commit.policy_request.tool.idempotency == IdempotencyClass::Keyed)
            .then(|| derive_effect_idempotency_key(commit.effect_id));
        let recovery_action = recovery_action(
            commit.policy_request.tool.idempotency,
            commit.policy_request.tool.recovery,
        );
        Ok(Self {
            proposed_at_ms,
            status: policy_effect_status(commit.policy_evaluation.decision),
            intent_json,
            intent_digest,
            descriptor_json,
            arguments_json,
            arguments_digest,
            target_resources_json,
            policy_request_json,
            policy_request_digest,
            obligations_json,
            obligations_digest,
            idempotency_key,
            effect_class: enum_text(commit.policy_request.tool.effect_class)?,
            risk_class: enum_text(commit.policy_request.tool.risk_class)?,
            executor_kind: commit.policy_request.tool.executor.as_contract(),
            idempotency_class: enum_text(commit.policy_request.tool.idempotency)?,
            recovery_strategy: enum_text(commit.policy_request.tool.recovery)?,
            recovery_action,
        })
    }
}

fn validate_policy_evaluation(
    request: &PolicyRequest,
    evaluation: &PolicyEvaluation,
) -> Result<(), EffectLedgerStoreError> {
    if evaluation.policy_version != request.policy_version
        || evaluation.explanation.is_empty()
        || evaluation.explanation.len() > 1_024
    {
        return Err(invalid("policy result identity is inconsistent"));
    }
    let obligations = &evaluation.obligations;
    if obligations.maximum_duration_ms
        > u64::try_from(request.tool.timeout.as_millis())
            .map_err(|_| invalid("tool timeout exceeds the durable representation"))?
        || obligations.maximum_output_bytes > request.tool.maximum_output_bytes
    {
        return Err(invalid("policy obligations expand the tool contract"));
    }
    if evaluation.decision == PolicyDecision::Deny && !obligations_deny_all(obligations) {
        return Err(invalid(
            "a deny decision must persist zero-authority default-deny obligations",
        ));
    }
    Ok(())
}

fn obligations_deny_all(obligations: &PolicyObligations) -> bool {
    obligations.readable_paths.is_empty()
        && obligations.writable_paths.is_empty()
        && obligations.allowed_executable_identity_digests.is_empty()
        && !obligations.allow_process_spawn
        && obligations.allowed_environment_variables.is_empty()
        && obligations.network_destinations.is_empty()
        && obligations.secret_references.is_empty()
        && obligations.argument_rewrite.is_none()
        && obligations.redactions.is_empty()
        && obligations.maximum_duration_ms == 0
        && obligations.maximum_output_bytes == 0
        && obligations.maximum_memory_bytes == 0
        && obligations.maximum_processes == 0
        && !obligations.validator_required
}

fn validate_approval_draft(
    commit: &RecordEffectProposalCommit,
) -> Result<(), EffectLedgerStoreError> {
    if commit.approval.is_some() != commit.approval_outbox_id.is_some() {
        return Err(invalid(
            "approval and remote notification identities must be allocated together",
        ));
    }
    match (commit.policy_evaluation.decision, &commit.approval) {
        (PolicyDecision::RequireApproval, Some(approval)) => {
            approval
                .subject
                .validate()
                .map_err(|error| invalid(error.to_string()))?;
            let request = &commit.policy_request;
            let subject = &approval.subject;
            let exact = subject.principal_id == request.principal_id
                && subject.task_id == request.task_id
                && subject.effect_id == commit.effect_id
                && subject.tool_id == request.tool.tool_id
                && subject.tool_version == request.tool.version
                && subject.canonical_arguments_digest
                    == canonical_arguments_digest(&request.normalized_arguments)
                && subject.capability_scope == request.requested_capability
                && subject.target_resources == request.target_resources
                && subject.executable_identity_digest == request.tool.executable_identity_digest
                && subject.policy_version == request.policy_version
                && subject.expires_at_ms > request.evaluated_at_ms;
            if !exact {
                return Err(invalid(
                    "approval subject does not exactly bind the policy request",
                ));
            }
            Ok(())
        }
        (PolicyDecision::RequireApproval, None) => {
            Err(invalid("policy requires a durable approval subject"))
        }
        (PolicyDecision::Allow | PolicyDecision::Deny, None) => Ok(()),
        (PolicyDecision::Allow | PolicyDecision::Deny, Some(_)) => Err(invalid(
            "an approval request exists without a require-approval decision",
        )),
    }
}

fn authorized_session_id(
    transaction: &Transaction<'_>,
    ownership: OwnershipContext,
    task_id: TaskId,
    run_id: RunId,
) -> Result<String, EffectLedgerStoreError> {
    transaction
        .query_row(
            "SELECT session.id \
             FROM turn \
             JOIN session ON session.id = turn.session_id \
             JOIN run ON run.id = turn.run_id AND run.task_id = turn.task_id \
             WHERE turn.task_id = ?1 AND turn.run_id = ?2 \
               AND session.principal_id = ?3 AND session.channel_binding_id = ?4",
            params![
                task_id.to_string(),
                run_id.to_string(),
                ownership.principal_id().to_string(),
                ownership.channel_binding_id().to_string(),
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(EffectLedgerStoreError::NotFound)
}

fn insert_effect(
    transaction: &Transaction<'_>,
    commit: &RecordEffectProposalCommit,
    evidence: &ProposalEvidence,
) -> Result<(), EffectLedgerStoreError> {
    transaction
        .execute(
            "INSERT INTO effect(\
                id, task_id, run_id, status, revision, tool_id, tool_version, \
                normalized_arguments_json, subject_digest, policy_version, idempotency_class, \
                idempotency_key, recovery_action, created_at_ms, updated_at_ms\
             ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13)",
            params![
                commit.effect_id.to_string(),
                commit.policy_request.task_id.to_string(),
                commit.policy_request.run_id.to_string(),
                evidence.status,
                commit.policy_request.tool.tool_id,
                commit.policy_request.tool.version,
                evidence.arguments_json,
                evidence.intent_digest,
                commit.policy_evaluation.policy_version,
                evidence.idempotency_class,
                evidence.idempotency_key,
                evidence.recovery_action,
                evidence.proposed_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn insert_effect_intent(
    transaction: &Transaction<'_>,
    commit: &RecordEffectProposalCommit,
    evidence: &ProposalEvidence,
    session_id: &str,
) -> Result<(), EffectLedgerStoreError> {
    transaction
        .execute(
            "INSERT INTO effect_intent(\
                effect_id, principal_id, channel_binding_id, session_id, task_id, run_id, \
                intent_json, intent_digest, descriptor_json, descriptor_digest, \
                normalized_arguments_json, arguments_digest, capability_scope, \
                target_resources_json, executable_identity_digest, effect_class, risk_class, \
                executor_kind, idempotency_class, recovery_strategy, idempotency_key, created_at_ms\
             ) VALUES (\
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
                ?16, ?17, ?18, ?19, ?20, ?21, ?22\
             )",
            params![
                commit.effect_id.to_string(),
                commit.ownership.principal_id().to_string(),
                commit.ownership.channel_binding_id().to_string(),
                session_id,
                commit.policy_request.task_id.to_string(),
                commit.policy_request.run_id.to_string(),
                evidence.intent_json,
                evidence.intent_digest,
                evidence.descriptor_json,
                commit.policy_request.tool.descriptor_digest,
                evidence.arguments_json,
                evidence.arguments_digest,
                commit.policy_request.requested_capability,
                evidence.target_resources_json,
                commit.policy_request.tool.executable_identity_digest,
                evidence.effect_class,
                evidence.risk_class,
                evidence.executor_kind,
                evidence.idempotency_class,
                evidence.recovery_strategy,
                evidence.idempotency_key,
                evidence.proposed_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn insert_policy_evidence(
    transaction: &Transaction<'_>,
    commit: &RecordEffectProposalCommit,
    evidence: &ProposalEvidence,
) -> Result<(), EffectLedgerStoreError> {
    transaction
        .execute(
            "INSERT INTO effect_policy_evaluation(\
                effect_id, request_json, request_digest, decision, obligations_json, \
                obligations_digest, policy_version, explanation, evaluated_at_ms\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                commit.effect_id.to_string(),
                evidence.policy_request_json,
                evidence.policy_request_digest,
                policy_decision_text(commit.policy_evaluation.decision),
                evidence.obligations_json,
                evidence.obligations_digest,
                commit.policy_evaluation.policy_version,
                commit.policy_evaluation.explanation,
                commit.policy_request.evaluated_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn insert_approval_request(
    transaction: &Transaction<'_>,
    commit: &RecordEffectProposalCommit,
    approval: &ApprovalRequestDraft,
    session_id: &str,
    requested_at_ms: i64,
) -> Result<(), EffectLedgerStoreError> {
    let subject_json =
        serde_json::to_string(&approval.subject).map_err(|error| invalid(error.to_string()))?;
    let subject_digest = approval
        .subject
        .subject_digest()
        .map_err(|error| invalid(error.to_string()))?;
    append_event(
        transaction,
        &EventAppend {
            event_id: approval.requested_event_id,
            aggregate_kind: "approval",
            aggregate_id: &approval.approval_id.to_string(),
            sequence: 0,
            event_type: "approval.requested",
            occurred_at_ms: requested_at_ms,
            actor_principal_id: Some(commit.ownership.principal_id()),
            correlation_id: commit.correlation_id,
            policy_version: Some(&approval.subject.policy_version),
            payload: json!({
                "approval_id": approval.approval_id,
                "effect_id": commit.effect_id,
                "subject_digest": subject_digest,
                "expires_at_ms": approval.subject.expires_at_ms,
            }),
        },
    )?;
    transaction
        .execute(
            "INSERT INTO approval_request(\
                approval_id, effect_id, principal_id, task_id, subject_json, subject_digest, \
                policy_version, status, requested_event_id, requested_at_ms, expires_at_ms\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8, ?9, ?10)",
            params![
                approval.approval_id.to_string(),
                commit.effect_id.to_string(),
                commit.ownership.principal_id().to_string(),
                commit.policy_request.task_id.to_string(),
                subject_json,
                subject_digest,
                approval.subject.policy_version,
                approval.requested_event_id.to_string(),
                requested_at_ms,
                approval.subject.expires_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO outbox(outbox_id, topic, payload_json, created_at_ms) \
             VALUES (?1, 'effect.approval_requested', ?2, ?3)",
            params![
                commit
                    .approval_outbox_id
                    .ok_or_else(|| invalid("approval notification identity is absent"))?
                    .to_string(),
                json!({
                    "session_id": session_id,
                    "approval_id": approval.approval_id,
                    "effect_id": commit.effect_id,
                    "subject_digest": subject_digest,
                    "tool_id": commit.policy_request.tool.tool_id,
                    "normalized_arguments": commit.policy_request.normalized_arguments,
                    "target_resources": commit.policy_request.target_resources,
                    "expires_at_ms": approval.subject.expires_at_ms,
                })
                .to_string(),
                requested_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    set_sequence(
        transaction,
        "approval",
        &approval.approval_id.to_string(),
        0,
    )
}

struct PendingApproval {
    approval_id: ApprovalId,
    effect_id: EffectId,
    subject_digest: String,
    policy_version: String,
    expires_at_ms: i64,
}

fn load_pending_approval(
    connection: &Connection,
    ownership: Option<OwnershipContext>,
    approval_id: ApprovalId,
) -> Result<PendingApproval, EffectLedgerStoreError> {
    let owner_principal = ownership.map(|value| value.principal_id().to_string());
    let owner_channel = ownership.map(|value| value.channel_binding_id().to_string());
    connection
        .query_row(
            "SELECT approval.effect_id, approval.subject_digest, approval.policy_version, \
                    approval.expires_at_ms \
             FROM approval_request approval \
             JOIN effect_intent intent ON intent.effect_id = approval.effect_id \
             JOIN session owner_session ON owner_session.id = intent.session_id \
             JOIN effect ON effect.id = approval.effect_id \
             WHERE approval.approval_id = ?1 AND approval.status = 'pending' \
               AND effect.status = 'awaiting_approval' \
               AND (?2 IS NULL OR owner_session.principal_id = ?2) \
               AND (?3 IS NULL OR owner_session.channel_binding_id = ?3)",
            params![approval_id.to_string(), owner_principal, owner_channel],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .map(
            |(effect_id, subject_digest, policy_version, expires_at_ms)| {
                Ok(PendingApproval {
                    approval_id,
                    effect_id: parse_id(&effect_id, "effect ID")?,
                    subject_digest,
                    policy_version,
                    expires_at_ms,
                })
            },
        )
        .transpose()?
        .ok_or(EffectLedgerStoreError::NotFound)
}

#[allow(clippy::too_many_arguments)]
fn append_approval_resolution_event(
    transaction: &Transaction<'_>,
    pending: &PendingApproval,
    event_id: EventId,
    correlation_id: CorrelationId,
    occurred_at_ms: i64,
    actor_principal_id: Option<PrincipalId>,
    decision: Option<ApprovalDecision>,
    system_resolution: Option<&str>,
) -> Result<(), EffectLedgerStoreError> {
    let sequence = next_sequence(transaction, "approval", &pending.approval_id.to_string())?;
    let event_type = match (decision, system_resolution) {
        (Some(ApprovalDecision::Approve), None) => "approval.approved",
        (Some(ApprovalDecision::Deny), None) => "approval.denied",
        (None, Some("expired")) => "approval.expired",
        (None, Some("task_cancelled")) => "approval.revoked",
        _ => return Err(invalid("unsupported approval resolution")),
    };
    append_event(
        transaction,
        &EventAppend {
            event_id,
            aggregate_kind: "approval",
            aggregate_id: &pending.approval_id.to_string(),
            sequence,
            event_type,
            occurred_at_ms,
            actor_principal_id,
            correlation_id,
            policy_version: Some(&pending.policy_version),
            payload: json!({
                "approval_id": pending.approval_id,
                "effect_id": pending.effect_id,
                "subject_digest": pending.subject_digest,
                "decision": decision,
                "resolution": system_resolution,
            }),
        },
    )?;
    set_sequence(
        transaction,
        "approval",
        &pending.approval_id.to_string(),
        sequence,
    )
}

#[allow(clippy::too_many_arguments)]
fn transition_effect_after_approval(
    transaction: &Transaction<'_>,
    pending: &PendingApproval,
    status: EffectStatus,
    event_id: EventId,
    correlation_id: CorrelationId,
    occurred_at_ms: i64,
    actor_principal_id: Option<PrincipalId>,
    approval_resolution: &str,
) -> Result<(), EffectLedgerStoreError> {
    let changed = transaction
        .execute(
            "UPDATE effect SET status = ?1, revision = revision + 1, updated_at_ms = ?2 \
             WHERE id = ?3 AND status = 'awaiting_approval'",
            params![
                effect_status_text(status),
                occurred_at_ms,
                pending.effect_id.to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    if changed != 1 {
        return Err(EffectLedgerStoreError::Conflict);
    }
    let sequence = next_sequence(transaction, "effect", &pending.effect_id.to_string())?;
    append_event(
        transaction,
        &EventAppend {
            event_id,
            aggregate_kind: "effect",
            aggregate_id: &pending.effect_id.to_string(),
            sequence,
            event_type: match status {
                EffectStatus::Authorized => "effect.authorized",
                EffectStatus::Denied => "effect.denied",
                _ => return Err(invalid("approval produced an invalid effect status")),
            },
            occurred_at_ms,
            actor_principal_id,
            correlation_id,
            policy_version: Some(&pending.policy_version),
            payload: json!({
                "effect_id": pending.effect_id,
                "approval_id": pending.approval_id,
                "approval_subject_digest": pending.subject_digest,
                "approval_resolution": approval_resolution,
                "status": status,
            }),
        },
    )?;
    set_sequence(
        transaction,
        "effect",
        &pending.effect_id.to_string(),
        sequence,
    )
}

struct EffectRow {
    effect_id: String,
    task_id: String,
    run_id: String,
    status: String,
    revision: i64,
    idempotency_key: Option<String>,
    created_at_ms: i64,
    updated_at_ms: i64,
    principal_id: String,
    channel_binding_id: String,
    intent_json: String,
    intent_digest: String,
    descriptor_json: String,
    descriptor_digest: String,
    arguments_json: String,
    arguments_digest: String,
    request_json: String,
    request_digest: String,
    decision: String,
    obligations_json: String,
    obligations_digest: String,
    policy_version: String,
    explanation: String,
    evaluated_at_ms: i64,
}

pub(super) fn load_effect_view(
    connection: &Connection,
    ownership: Option<OwnershipContext>,
    effect_id: EffectId,
) -> Result<EffectLedgerView, EffectLedgerStoreError> {
    let owner_principal = ownership.map(|value| value.principal_id().to_string());
    let owner_channel = ownership.map(|value| value.channel_binding_id().to_string());
    let row = connection
        .query_row(
            "SELECT effect.id, effect.task_id, effect.run_id, effect.status, effect.revision, \
                    effect.idempotency_key, effect.created_at_ms, effect.updated_at_ms, \
                    intent.principal_id, intent.channel_binding_id, intent.intent_json, \
                    intent.intent_digest, intent.descriptor_json, intent.descriptor_digest, \
                    intent.normalized_arguments_json, intent.arguments_digest, policy.request_json, \
                    policy.request_digest, policy.decision, policy.obligations_json, \
                    policy.obligations_digest, policy.policy_version, policy.explanation, \
                    policy.evaluated_at_ms \
             FROM effect \
             JOIN effect_intent intent ON intent.effect_id = effect.id \
             JOIN effect_policy_evaluation policy ON policy.effect_id = effect.id \
             JOIN session owner_session ON owner_session.id = intent.session_id \
             WHERE effect.id = ?1 \
               AND (?2 IS NULL OR owner_session.principal_id = ?2) \
               AND (?3 IS NULL OR owner_session.channel_binding_id = ?3)",
            params![effect_id.to_string(), owner_principal, owner_channel],
            |result| {
                Ok(EffectRow {
                    effect_id: result.get(0)?,
                    task_id: result.get(1)?,
                    run_id: result.get(2)?,
                    status: result.get(3)?,
                    revision: result.get(4)?,
                    idempotency_key: result.get(5)?,
                    created_at_ms: result.get(6)?,
                    updated_at_ms: result.get(7)?,
                    principal_id: result.get(8)?,
                    channel_binding_id: result.get(9)?,
                    intent_json: result.get(10)?,
                    intent_digest: result.get(11)?,
                    descriptor_json: result.get(12)?,
                    descriptor_digest: result.get(13)?,
                    arguments_json: result.get(14)?,
                    arguments_digest: result.get(15)?,
                    request_json: result.get(16)?,
                    request_digest: result.get(17)?,
                    decision: result.get(18)?,
                    obligations_json: result.get(19)?,
                    obligations_digest: result.get(20)?,
                    policy_version: result.get(21)?,
                    explanation: result.get(22)?,
                    evaluated_at_ms: result.get(23)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(EffectLedgerStoreError::NotFound)?;
    hydrate_effect_view(connection, row)
}

#[allow(clippy::too_many_lines)]
fn hydrate_effect_view(
    connection: &Connection,
    row: EffectRow,
) -> Result<EffectLedgerView, EffectLedgerStoreError> {
    let effect_id = parse_id(&row.effect_id, "effect ID")?;
    let task_id = parse_id(&row.task_id, "task ID")?;
    let run_id = parse_id(&row.run_id, "run ID")?;
    let principal_id = parse_id(&row.principal_id, "principal ID")?;
    let channel_binding_id = parse_id(&row.channel_binding_id, "channel binding ID")?;
    let request: PolicyRequest = serde_json::from_str(&row.request_json)
        .map_err(|error| invariant(format!("stored policy request is invalid: {error}")))?;
    request
        .validate()
        .map_err(|error| invariant(format!("stored policy request is invalid: {error}")))?;
    let stored_arguments: serde_json::Value = serde_json::from_str(&row.arguments_json)
        .map_err(|error| invariant(format!("stored effect arguments are invalid: {error}")))?;
    let stored_intent: serde_json::Value = serde_json::from_str(&row.intent_json)
        .map_err(|error| invariant(format!("stored effect intent is invalid: {error}")))?;
    if request.principal_id != principal_id
        || request.channel_binding_id != channel_binding_id
        || request.task_id != task_id
        || request.run_id != run_id
        || sha256_digest(row.request_json.as_bytes()) != row.request_digest
        || serde_json::to_string(&request.tool).map_err(|error| invariant(error.to_string()))?
            != row.descriptor_json
        || request.tool.descriptor_digest != row.descriptor_digest
        || request.normalized_arguments != stored_arguments
        || canonical_arguments_digest(&request.normalized_arguments) != row.arguments_digest
        || effect_intent_material(effect_id, &request)
            .map_err(|error| invariant(error.to_string()))?
            != stored_intent
        || effect_intent_digest(effect_id, &request)
            .map_err(|error| invariant(error.to_string()))?
            != row.intent_digest
        || request.evaluated_at_ms != row.evaluated_at_ms
    {
        return Err(invariant(
            "stored effect intent or policy request evidence diverged",
        ));
    }
    let obligations: PolicyObligations = serde_json::from_str(&row.obligations_json)
        .map_err(|error| invariant(format!("stored policy obligations are invalid: {error}")))?;
    if sha256_digest(row.obligations_json.as_bytes()) != row.obligations_digest {
        return Err(invariant("stored policy obligations digest diverged"));
    }
    let evaluation = PolicyEvaluation {
        decision: parse_policy_decision(&row.decision)?,
        obligations,
        policy_version: row.policy_version,
        explanation: row.explanation,
    };
    validate_policy_evaluation(&request, &evaluation)
        .map_err(|error| invariant(error.to_string()))?;
    let status = parse_effect_status(&row.status)?;
    let status_is_consistent = match evaluation.decision {
        PolicyDecision::Deny => status == EffectStatus::Denied,
        PolicyDecision::Allow => matches!(
            status,
            EffectStatus::Authorized
                | EffectStatus::Dispatching
                | EffectStatus::Succeeded
                | EffectStatus::Failed
                | EffectStatus::OutcomeUnknown
                | EffectStatus::Compensated
        ),
        PolicyDecision::RequireApproval => matches!(
            status,
            EffectStatus::AwaitingApproval
                | EffectStatus::Authorized
                | EffectStatus::Dispatching
                | EffectStatus::Succeeded
                | EffectStatus::Failed
                | EffectStatus::OutcomeUnknown
                | EffectStatus::Compensated
                | EffectStatus::Denied
        ),
    };
    if !status_is_consistent {
        return Err(invariant(
            "stored effect status contradicts its policy decision",
        ));
    }
    let expected_key = (request.tool.idempotency == IdempotencyClass::Keyed)
        .then(|| derive_effect_idempotency_key(effect_id));
    if row.idempotency_key != expected_key || row.updated_at_ms < row.created_at_ms {
        return Err(invariant("stored effect key or timestamps are invalid"));
    }
    let approval = connection
        .query_row(
            "SELECT approval_id FROM approval_request WHERE effect_id = ?1",
            [effect_id.to_string()],
            |value| value.get::<_, String>(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .map(|value| {
            let approval_id = parse_id(&value, "approval ID")?;
            load_approval_view(connection, None, approval_id)
        })
        .transpose()?;
    if (evaluation.decision == PolicyDecision::RequireApproval) != approval.is_some() {
        return Err(invariant("stored approval presence contradicts policy"));
    }
    if let Some(approval) = &approval {
        let approval_matches_effect = match status {
            EffectStatus::AwaitingApproval => approval.status == ApprovalStatus::Pending,
            EffectStatus::Authorized
            | EffectStatus::Dispatching
            | EffectStatus::Succeeded
            | EffectStatus::Failed
            | EffectStatus::OutcomeUnknown
            | EffectStatus::Compensated => approval.status == ApprovalStatus::Approved,
            EffectStatus::Denied => matches!(
                approval.status,
                ApprovalStatus::Denied | ApprovalStatus::Expired | ApprovalStatus::Revoked
            ),
            EffectStatus::Proposed => false,
        };
        if !approval_matches_effect {
            return Err(invariant(
                "stored effect lifecycle contradicts its approval lifecycle",
            ));
        }
    }
    Ok(EffectLedgerView {
        effect_id,
        task_id,
        run_id,
        status,
        revision: u64::try_from(row.revision)
            .map_err(|_| invariant("stored effect revision is negative"))?,
        policy_request: request,
        policy_evaluation: evaluation,
        idempotency_key: row.idempotency_key,
        approval,
        created_at: system_time(row.created_at_ms)?,
        updated_at: system_time(row.updated_at_ms)?,
    })
}

struct ApprovalRow {
    approval_id: String,
    effect_id: String,
    principal_id: String,
    task_id: String,
    subject_json: String,
    subject_digest: String,
    policy_version: String,
    status: String,
    decision: Option<String>,
    decided_by_principal_id: Option<String>,
    requested_at_ms: i64,
    expires_at_ms: i64,
    resolved_at_ms: Option<i64>,
}

fn load_approval_view(
    connection: &Connection,
    ownership: Option<OwnershipContext>,
    approval_id: ApprovalId,
) -> Result<ApprovalRequestView, EffectLedgerStoreError> {
    let owner_principal = ownership.map(|value| value.principal_id().to_string());
    let owner_channel = ownership.map(|value| value.channel_binding_id().to_string());
    let row = connection
        .query_row(
            "SELECT approval.approval_id, approval.effect_id, approval.principal_id, \
                    approval.task_id, approval.subject_json, approval.subject_digest, \
                    approval.policy_version, approval.status, approval.decision, \
                    approval.decided_by_principal_id, approval.requested_at_ms, \
                    approval.expires_at_ms, approval.resolved_at_ms \
             FROM approval_request approval \
             JOIN effect_intent intent ON intent.effect_id = approval.effect_id \
             JOIN session owner_session ON owner_session.id = intent.session_id \
             WHERE approval.approval_id = ?1 \
               AND (?2 IS NULL OR owner_session.principal_id = ?2) \
               AND (?3 IS NULL OR owner_session.channel_binding_id = ?3)",
            params![approval_id.to_string(), owner_principal, owner_channel],
            |result| {
                Ok(ApprovalRow {
                    approval_id: result.get(0)?,
                    effect_id: result.get(1)?,
                    principal_id: result.get(2)?,
                    task_id: result.get(3)?,
                    subject_json: result.get(4)?,
                    subject_digest: result.get(5)?,
                    policy_version: result.get(6)?,
                    status: result.get(7)?,
                    decision: result.get(8)?,
                    decided_by_principal_id: result.get(9)?,
                    requested_at_ms: result.get(10)?,
                    expires_at_ms: result.get(11)?,
                    resolved_at_ms: result.get(12)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(EffectLedgerStoreError::NotFound)?;
    hydrate_approval(row)
}

fn hydrate_approval(row: ApprovalRow) -> Result<ApprovalRequestView, EffectLedgerStoreError> {
    let approval_id = parse_id(&row.approval_id, "approval ID")?;
    let effect_id = parse_id(&row.effect_id, "effect ID")?;
    let principal_id = parse_id(&row.principal_id, "principal ID")?;
    let task_id = parse_id(&row.task_id, "task ID")?;
    let subject: mealy_application::ApprovalSubject = serde_json::from_str(&row.subject_json)
        .map_err(|error| invariant(format!("stored approval subject is invalid: {error}")))?;
    subject
        .validate()
        .map_err(|error| invariant(format!("stored approval subject is invalid: {error}")))?;
    if subject.principal_id != principal_id
        || subject.task_id != task_id
        || subject.effect_id != effect_id
        || subject.policy_version != row.policy_version
        || subject.expires_at_ms != row.expires_at_ms
        || subject
            .subject_digest()
            .map_err(|error| invariant(error.to_string()))?
            != row.subject_digest
    {
        return Err(invariant("stored approval subject evidence diverged"));
    }
    let status = parse_approval_status(&row.status)?;
    let decision = row
        .decision
        .as_deref()
        .map(parse_approval_decision)
        .transpose()?;
    let resolved_at = row.resolved_at_ms.map(system_time).transpose()?;
    let resolution_consistent = match status {
        ApprovalStatus::Pending => decision.is_none() && resolved_at.is_none(),
        ApprovalStatus::Approved => {
            decision == Some(ApprovalDecision::Approve)
                && row.decided_by_principal_id.as_deref() == Some(row.principal_id.as_str())
        }
        ApprovalStatus::Denied => {
            decision == Some(ApprovalDecision::Deny)
                && row.decided_by_principal_id.as_deref() == Some(row.principal_id.as_str())
        }
        ApprovalStatus::Expired => {
            decision.is_none()
                && row
                    .resolved_at_ms
                    .is_some_and(|resolved| resolved >= row.expires_at_ms)
        }
        ApprovalStatus::Revoked => decision.is_none() && row.decided_by_principal_id.is_some(),
    };
    if !resolution_consistent {
        return Err(invariant("stored approval lifecycle evidence diverged"));
    }
    Ok(ApprovalRequestView {
        approval_id,
        effect_id,
        subject,
        subject_digest: row.subject_digest,
        status,
        decision,
        requested_at: system_time(row.requested_at_ms)?,
        resolved_at,
    })
}

struct RecoveryRow {
    attempt_id: String,
    effect_id: String,
    ordinal: i64,
    boundary: String,
    idempotency: String,
    recovery: String,
    idempotency_key: Option<String>,
    disposition: String,
}

impl RecoveryRow {
    fn hydrate(self) -> Result<EffectRecoveryCandidate, EffectLedgerStoreError> {
        let effect_id = parse_id(&self.effect_id, "effect ID")?;
        let boundary = match self.boundary.as_str() {
            "prepared" => EffectAttemptBoundary::Prepared,
            "running" => EffectAttemptBoundary::Running,
            "outcome_unknown" => EffectAttemptBoundary::OutcomeUnknown,
            _ => return Err(invariant("stored effect attempt boundary is invalid")),
        };
        let idempotency = parse_idempotency(&self.idempotency)?;
        let recovery = parse_recovery_strategy(&self.recovery)?;
        let disposition = classify_recovery(boundary, idempotency, recovery);
        if disposition_text(disposition) != self.disposition {
            return Err(invariant("stored effect recovery view is inconsistent"));
        }
        let expected_key = (idempotency == IdempotencyClass::Keyed)
            .then(|| derive_effect_idempotency_key(effect_id));
        if self.idempotency_key != expected_key {
            return Err(invariant("stored recovery idempotency key is invalid"));
        }
        Ok(EffectRecoveryCandidate {
            effect_id,
            attempt_id: parse_id(&self.attempt_id, "effect attempt ID")?,
            ordinal: u64::try_from(self.ordinal)
                .map_err(|_| invariant("stored effect attempt ordinal is negative"))?,
            boundary,
            idempotency,
            recovery,
            idempotency_key: self.idempotency_key,
            disposition,
        })
    }
}

const fn classify_recovery(
    boundary: EffectAttemptBoundary,
    idempotency: IdempotencyClass,
    recovery: RecoveryStrategy,
) -> EffectRecoveryDisposition {
    if matches!(boundary, EffectAttemptBoundary::Prepared) {
        return EffectRecoveryDisposition::ResumePrepared;
    }
    if matches!(recovery, RecoveryStrategy::Compensate) {
        return EffectRecoveryDisposition::RequiresCompensation;
    }
    if matches!(recovery, RecoveryStrategy::NeverRetry) {
        return EffectRecoveryDisposition::TerminallyFailed;
    }
    if matches!(boundary, EffectAttemptBoundary::OutcomeUnknown) {
        return EffectRecoveryDisposition::RequiresReconciliation;
    }
    match (idempotency, recovery) {
        (IdempotencyClass::Keyed, RecoveryStrategy::Retry) => {
            EffectRecoveryDisposition::RetryWithSameKey
        }
        (IdempotencyClass::Pure | IdempotencyClass::Idempotent, RecoveryStrategy::Retry) => {
            EffectRecoveryDisposition::Retry
        }
        (
            IdempotencyClass::Pure
            | IdempotencyClass::Idempotent
            | IdempotencyClass::Keyed
            | IdempotencyClass::NonIdempotent,
            RecoveryStrategy::Reconcile,
        )
        | (IdempotencyClass::NonIdempotent, RecoveryStrategy::Retry) => {
            EffectRecoveryDisposition::RequiresReconciliation
        }
        (_, RecoveryStrategy::Compensate | RecoveryStrategy::NeverRetry) => unreachable!(),
    }
}

struct EventAppend<'a> {
    event_id: EventId,
    aggregate_kind: &'a str,
    aggregate_id: &'a str,
    sequence: i64,
    event_type: &'a str,
    occurred_at_ms: i64,
    actor_principal_id: Option<PrincipalId>,
    correlation_id: CorrelationId,
    policy_version: Option<&'a str>,
    payload: serde_json::Value,
}

fn append_event(
    transaction: &Transaction<'_>,
    event: &EventAppend<'_>,
) -> Result<(), EffectLedgerStoreError> {
    transaction
        .execute(
            "INSERT INTO journal_event(\
                event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                event_version, occurred_at_ms, actor_principal_id, correlation_id, \
                policy_version, sensitivity, payload_json\
             ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, ?9, 'internal', ?10)",
            params![
                event.event_id.to_string(),
                event.aggregate_kind,
                event.aggregate_id,
                event.sequence,
                event.event_type,
                event.occurred_at_ms,
                event.actor_principal_id.map(|value| value.to_string()),
                event.correlation_id.to_string(),
                event.policy_version,
                event.payload.to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn next_sequence(
    transaction: &Transaction<'_>,
    aggregate_kind: &str,
    aggregate_id: &str,
) -> Result<i64, EffectLedgerStoreError> {
    transaction
        .query_row(
            "SELECT sequence FROM aggregate_sequence \
             WHERE aggregate_kind = ?1 AND aggregate_id = ?2",
            params![aggregate_kind, aggregate_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .map_or(Ok(0), |sequence| {
            sequence
                .checked_add(1)
                .ok_or_else(|| invariant("aggregate sequence overflow"))
        })
}

fn set_sequence(
    transaction: &Transaction<'_>,
    aggregate_kind: &str,
    aggregate_id: &str,
    sequence: i64,
) -> Result<(), EffectLedgerStoreError> {
    transaction
        .execute(
            "INSERT INTO aggregate_sequence(aggregate_kind, aggregate_id, sequence) \
             VALUES (?1, ?2, ?3) \
             ON CONFLICT(aggregate_kind, aggregate_id) DO UPDATE SET sequence = excluded.sequence",
            params![aggregate_kind, aggregate_id, sequence],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn policy_effect_status(decision: PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Deny => "denied",
        PolicyDecision::Allow => "authorized",
        PolicyDecision::RequireApproval => "awaiting_approval",
    }
}

fn policy_decision_text(decision: PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Deny => "deny",
        PolicyDecision::Allow => "allow",
        PolicyDecision::RequireApproval => "require_approval",
    }
}

fn parse_policy_decision(value: &str) -> Result<PolicyDecision, EffectLedgerStoreError> {
    match value {
        "deny" => Ok(PolicyDecision::Deny),
        "allow" => Ok(PolicyDecision::Allow),
        "require_approval" => Ok(PolicyDecision::RequireApproval),
        _ => Err(invariant("stored policy decision is invalid")),
    }
}

fn approval_decision_text(decision: ApprovalDecision) -> &'static str {
    match decision {
        ApprovalDecision::Approve => "approve",
        ApprovalDecision::Deny => "deny",
    }
}

fn parse_approval_decision(value: &str) -> Result<ApprovalDecision, EffectLedgerStoreError> {
    match value {
        "approve" => Ok(ApprovalDecision::Approve),
        "deny" => Ok(ApprovalDecision::Deny),
        _ => Err(invariant("stored approval decision is invalid")),
    }
}

fn approval_status_text(status: ApprovalStatus) -> &'static str {
    match status {
        ApprovalStatus::Pending => "pending",
        ApprovalStatus::Approved => "approved",
        ApprovalStatus::Denied => "denied",
        ApprovalStatus::Expired => "expired",
        ApprovalStatus::Revoked => "revoked",
    }
}

fn parse_approval_status(value: &str) -> Result<ApprovalStatus, EffectLedgerStoreError> {
    match value {
        "pending" => Ok(ApprovalStatus::Pending),
        "approved" => Ok(ApprovalStatus::Approved),
        "denied" => Ok(ApprovalStatus::Denied),
        "expired" => Ok(ApprovalStatus::Expired),
        "revoked" => Ok(ApprovalStatus::Revoked),
        _ => Err(invariant("stored approval status is invalid")),
    }
}

fn effect_status_text(status: EffectStatus) -> &'static str {
    match status {
        EffectStatus::Proposed => "proposed",
        EffectStatus::AwaitingApproval => "awaiting_approval",
        EffectStatus::Authorized => "authorized",
        EffectStatus::Dispatching => "dispatching",
        EffectStatus::Succeeded => "succeeded",
        EffectStatus::Failed => "failed",
        EffectStatus::OutcomeUnknown => "outcome_unknown",
        EffectStatus::Compensated => "compensated",
        EffectStatus::Denied => "denied",
    }
}

fn parse_effect_status(value: &str) -> Result<EffectStatus, EffectLedgerStoreError> {
    match value {
        "proposed" => Ok(EffectStatus::Proposed),
        "awaiting_approval" => Ok(EffectStatus::AwaitingApproval),
        "authorized" => Ok(EffectStatus::Authorized),
        "dispatching" => Ok(EffectStatus::Dispatching),
        "succeeded" => Ok(EffectStatus::Succeeded),
        "failed" => Ok(EffectStatus::Failed),
        "outcome_unknown" => Ok(EffectStatus::OutcomeUnknown),
        "compensated" => Ok(EffectStatus::Compensated),
        "denied" => Ok(EffectStatus::Denied),
        _ => Err(invariant("stored effect status is invalid")),
    }
}

fn parse_idempotency(value: &str) -> Result<IdempotencyClass, EffectLedgerStoreError> {
    match value {
        "pure" => Ok(IdempotencyClass::Pure),
        "idempotent" => Ok(IdempotencyClass::Idempotent),
        "keyed" => Ok(IdempotencyClass::Keyed),
        "non_idempotent" => Ok(IdempotencyClass::NonIdempotent),
        _ => Err(invariant("stored idempotency class is invalid")),
    }
}

fn parse_recovery_strategy(value: &str) -> Result<RecoveryStrategy, EffectLedgerStoreError> {
    match value {
        "retry" => Ok(RecoveryStrategy::Retry),
        "reconcile" => Ok(RecoveryStrategy::Reconcile),
        "compensate" => Ok(RecoveryStrategy::Compensate),
        "never_retry" => Ok(RecoveryStrategy::NeverRetry),
        _ => Err(invariant("stored recovery strategy is invalid")),
    }
}

fn disposition_text(disposition: EffectRecoveryDisposition) -> &'static str {
    match disposition {
        EffectRecoveryDisposition::ResumePrepared => "resume_prepared",
        EffectRecoveryDisposition::Retry => "retry",
        EffectRecoveryDisposition::RetryWithSameKey => "retry_with_same_key",
        EffectRecoveryDisposition::RequiresReconciliation => "requires_reconciliation",
        EffectRecoveryDisposition::RequiresCompensation => "requires_compensation",
        EffectRecoveryDisposition::TerminallyFailed => "terminally_failed",
    }
}

fn recovery_action(idempotency: IdempotencyClass, recovery: RecoveryStrategy) -> &'static str {
    match (idempotency, recovery) {
        (IdempotencyClass::Keyed, RecoveryStrategy::Retry) => "retry_with_same_key",
        (IdempotencyClass::Pure | IdempotencyClass::Idempotent, RecoveryStrategy::Retry) => "retry",
        _ => "reconcile",
    }
}

fn enum_text(value: impl Serialize) -> Result<String, EffectLedgerStoreError> {
    let encoded = serde_json::to_value(value).map_err(|error| invalid(error.to_string()))?;
    encoded
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("enum did not serialize to its contract string"))
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, EffectLedgerStoreError> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invalid("effect ledger time precedes Unix epoch"))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| invalid("effect ledger timestamp exceeds SQLite range"))
}

fn system_time(value: i64) -> Result<SystemTime, EffectLedgerStoreError> {
    let milliseconds = u64::try_from(value)
        .map_err(|_| invariant("stored effect ledger timestamp is negative"))?;
    SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_millis(milliseconds))
        .ok_or_else(|| invariant("stored effect ledger timestamp exceeds SystemTime"))
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, EffectLedgerStoreError> {
    value
        .parse()
        .map_err(|_| invariant(format!("stored {field} is invalid")))
}

fn map_sqlite_error(error: rusqlite::Error) -> EffectLedgerStoreError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation =>
        {
            EffectLedgerStoreError::Conflict
        }
        other => EffectLedgerStoreError::Unavailable(other.to_string()),
    }
}

fn invalid(message: impl Into<String>) -> EffectLedgerStoreError {
    EffectLedgerStoreError::InvalidEvidence(message.into())
}

fn invariant(message: impl Into<String>) -> EffectLedgerStoreError {
    EffectLedgerStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::super::{
        LATEST_SCHEMA_VERSION, MIGRATION_0001, MIGRATION_0002, MIGRATION_0003, MIGRATION_0004,
        MIGRATION_0005, ensure_initial_journal_envelope, ensure_phase_one_run_columns,
    };
    use super::{EffectAttemptBoundary, EffectLedgerStore, EffectRecoveryDisposition, SqliteStore};
    use mealy_application::{
        ApprovalRequestDraft, ApprovalSubject, EffectAttemptOutcome, EffectAttemptState,
        EffectLedgerStoreError, EffectOutcomeKind, EffectReconciliationOutcome,
        ExpireApprovalCommit, INTERRUPTED_EFFECT_OUTCOME_CLASSIFICATION,
        INTERRUPTED_EFFECT_OUTCOME_ERROR_CLASS, INTERRUPTED_EFFECT_RETRY_CLASSIFICATION,
        INTERRUPTED_EFFECT_RETRY_ERROR_CLASS, LeaseClaimCommit, LeaseClaimOutcome,
        MarkEffectAttemptRunningCommit, OwnershipContext, PolicyDecision, PolicyEvaluation,
        PolicyObligations, PolicyRequest, PrepareEffectAttemptCommit, ReconcileEffectOutcomeCommit,
        RecordEffectAttemptOutcomeCommit, RecordEffectProposalCommit,
        RecoverInterruptedEffectCommit, ResolveApprovalCommit, SchedulerStore, ToolConcurrency,
        ToolDescriptor, canonical_arguments_digest, derive_effect_idempotency_key,
        effect_outcome_evidence_material, recover_startup, sha256_digest,
    };
    use mealy_domain::{
        ApprovalDecision, ApprovalId, ApprovalStatus, AttemptId, ChannelBindingId, CorrelationId,
        EffectClass, EffectId, EffectStatus, EventId, ExecutorKind, FencingToken, IdempotencyClass,
        InboxEntryId, LeaseFence, LeaseId, PolicyProfile, PrincipalId, RecoveryStrategy, RiskClass,
        RunId, SessionId, TaskId, TurnId, WorkerId,
    };
    use mealy_testkit::{TestClock, TestIdGenerator};
    use rusqlite::{Connection, params};
    use std::{
        fs,
        time::{Duration, SystemTime},
    };

    const NOW_MS: i64 = 1_783_843_200_000;

    #[derive(Clone, Copy)]
    struct Graph {
        ownership: OwnershipContext,
        task_id: TaskId,
        run_id: RunId,
        lease_id: LeaseId,
        worker_id: WorkerId,
    }

    fn time(milliseconds: i64) -> SystemTime {
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_millis(
                u64::try_from(milliseconds).expect("nonnegative test timestamp"),
            ))
            .expect("test timestamp fits")
    }

    fn fence(graph: Graph) -> LeaseFence {
        LeaseFence::new(
            graph.lease_id,
            graph.run_id,
            graph.worker_id,
            FencingToken::new(1).expect("nonzero test fence"),
        )
    }

    #[allow(clippy::too_many_lines)]
    fn seed_graph(store: &SqliteStore) -> Graph {
        let principal_id = PrincipalId::new();
        let channel_binding_id = ChannelBindingId::new();
        let session_id = SessionId::new();
        let inbox_entry_id = InboxEntryId::new();
        let task_id = TaskId::new();
        let run_id = RunId::new();
        let turn_id = TurnId::new();
        let lease_id = LeaseId::new();
        let worker_id = WorkerId::new();
        store
            .connection
            .execute(
                "INSERT INTO session(\
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?4)",
                params![
                    session_id.to_string(),
                    principal_id.to_string(),
                    channel_binding_id.to_string(),
                    NOW_MS,
                ],
            )
            .expect("seed session");
        store
            .connection
            .execute(
                "INSERT INTO session_inbox(\
                    inbox_entry_id, session_id, sequence, dedupe_key, delivery_mode, content, \
                    admission_event_id, acknowledgement_outbox_id, correlation_id, accepted_at_ms\
                 ) VALUES (?1, ?2, 1, ?3, 'queue', 'phase 3', ?4, ?5, ?6, ?7)",
                params![
                    inbox_entry_id.to_string(),
                    session_id.to_string(),
                    format!("delivery-{inbox_entry_id}"),
                    EventId::new().to_string(),
                    mealy_domain::OutboxId::new().to_string(),
                    CorrelationId::new().to_string(),
                    NOW_MS,
                ],
            )
            .expect("seed inbox");
        store
            .connection
            .execute(
                "INSERT INTO task(id, status, revision, validation_required) \
                 VALUES (?1, 'running', 1, 0)",
                [task_id.to_string()],
            )
            .expect("seed task");
        store
            .connection
            .execute(
                "INSERT INTO run(\
                    id, task_id, status, revision, agent_role, capability_ceiling_json, \
                    budget_json, correlation_id, created_at_ms, updated_at_ms, \
                    current_fencing_token\
                 ) VALUES (?1, ?2, 'running', 1, 'assistant', '{}', '{}', ?3, ?4, ?4, 1)",
                params![
                    run_id.to_string(),
                    task_id.to_string(),
                    CorrelationId::new().to_string(),
                    NOW_MS,
                ],
            )
            .expect("seed run");
        store
            .connection
            .execute(
                "INSERT INTO turn(\
                    id, session_id, inbox_entry_id, task_id, run_id, correlation_id, created_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    turn_id.to_string(),
                    session_id.to_string(),
                    inbox_entry_id.to_string(),
                    task_id.to_string(),
                    run_id.to_string(),
                    CorrelationId::new().to_string(),
                    NOW_MS,
                ],
            )
            .expect("seed turn");
        store
            .connection
            .execute(
                "INSERT INTO work_lease(\
                    lease_id, run_id, owner_id, fencing_token, acquired_at_ms, heartbeat_at_ms, \
                    expires_at_ms\
                 ) VALUES (?1, ?2, ?3, 1, ?4, ?4, ?5)",
                params![
                    lease_id.to_string(),
                    run_id.to_string(),
                    worker_id.to_string(),
                    NOW_MS,
                    NOW_MS + 60_000,
                ],
            )
            .expect("seed lease");
        Graph {
            ownership: OwnershipContext::new(principal_id, channel_binding_id),
            task_id,
            run_id,
            lease_id,
            worker_id,
        }
    }

    fn descriptor(
        effect_class: EffectClass,
        idempotency: IdempotencyClass,
        recovery: RecoveryStrategy,
    ) -> ToolDescriptor {
        let input_schema = serde_json::json!({
            "type": "object",
            "required": ["resourceId", "value"],
            "properties": {
                "resourceId": {"type": "string"},
                "value": {"type": "integer"},
            },
        });
        let output_schema = serde_json::json!({"type": "object"});
        let mut descriptor = ToolDescriptor {
            tool_id: "service.update".to_owned(),
            version: "3".to_owned(),
            input_schema_digest: sha256_digest(input_schema.to_string().as_bytes()),
            output_schema_digest: sha256_digest(output_schema.to_string().as_bytes()),
            input_schema,
            output_schema,
            descriptor_digest: String::new(),
            effect_class,
            risk_class: RiskClass::Medium,
            required_capabilities: vec!["service:item:update".to_owned()],
            timeout: Duration::from_secs(2),
            maximum_output_bytes: 4_096,
            concurrency: ToolConcurrency::Serial,
            conflict_key_templates: vec!["service-item:{resourceId}".to_owned()],
            idempotency,
            recovery,
            executor: ExecutorKind::Sandbox,
            executable_identity_digest: sha256_digest(b"service-update-v3"),
        };
        descriptor.descriptor_digest = descriptor
            .computed_descriptor_digest()
            .expect("compute descriptor digest");
        descriptor.validate().expect("valid effect descriptor");
        descriptor
    }

    fn obligations(tool: &ToolDescriptor) -> PolicyObligations {
        PolicyObligations {
            profile: PolicyProfile::ServiceOperator,
            readable_paths: Vec::new(),
            writable_paths: Vec::new(),
            allowed_executable_identity_digests: vec![tool.executable_identity_digest.clone()],
            allow_process_spawn: false,
            allowed_environment_variables: Vec::new(),
            network_destinations: Vec::new(),
            secret_references: Vec::new(),
            argument_rewrite: None,
            redactions: Vec::new(),
            maximum_duration_ms: 2_000,
            maximum_output_bytes: tool.maximum_output_bytes,
            maximum_memory_bytes: 64 * 1024 * 1024,
            maximum_processes: 1,
            validator_required: true,
        }
    }

    fn deny_obligations() -> PolicyObligations {
        PolicyObligations {
            profile: PolicyProfile::ServiceOperator,
            readable_paths: Vec::new(),
            writable_paths: Vec::new(),
            allowed_executable_identity_digests: Vec::new(),
            allow_process_spawn: false,
            allowed_environment_variables: Vec::new(),
            network_destinations: Vec::new(),
            secret_references: Vec::new(),
            argument_rewrite: None,
            redactions: Vec::new(),
            maximum_duration_ms: 0,
            maximum_output_bytes: 0,
            maximum_memory_bytes: 0,
            maximum_processes: 0,
            validator_required: false,
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn proposal(
        graph: Graph,
        effect_id: EffectId,
        tool: ToolDescriptor,
        decision: PolicyDecision,
    ) -> RecordEffectProposalCommit {
        let normalized_arguments = serde_json::json!({
            "resourceId": "service://example/item",
            "value": 7,
        });
        let request = PolicyRequest {
            principal_id: graph.ownership.principal_id(),
            channel_binding_id: graph.ownership.channel_binding_id(),
            task_id: graph.task_id,
            run_id: graph.run_id,
            agent_role: "assistant".to_owned(),
            task_risk: RiskClass::Medium,
            tool: tool.clone(),
            normalized_arguments: normalized_arguments.clone(),
            target_resources: vec!["service://example/item".to_owned()],
            workspace_roots: Vec::new(),
            resource_claims: vec!["service-mutate:example:item".to_owned()],
            secret_references: Vec::new(),
            network_destinations: Vec::new(),
            requested_capability: "service:item:update".to_owned(),
            requested_profile: PolicyProfile::ServiceOperator,
            enforceable_profiles: vec![PolicyProfile::ServiceOperator],
            evaluated_at_ms: NOW_MS,
            policy_version: "policy-phase3-v1".to_owned(),
        };
        let approval =
            (decision == PolicyDecision::RequireApproval).then(|| ApprovalRequestDraft {
                approval_id: ApprovalId::new(),
                subject: ApprovalSubject {
                    principal_id: request.principal_id,
                    task_id: request.task_id,
                    effect_id,
                    tool_id: tool.tool_id.clone(),
                    tool_version: tool.version.clone(),
                    canonical_arguments_digest: canonical_arguments_digest(&normalized_arguments),
                    capability_scope: request.requested_capability.clone(),
                    target_resources: request.target_resources.clone(),
                    executable_identity_digest: tool.executable_identity_digest.clone(),
                    policy_version: request.policy_version.clone(),
                    expires_at_ms: NOW_MS + 1_000,
                },
                requested_event_id: EventId::new(),
            });
        RecordEffectProposalCommit {
            effect_id,
            ownership: graph.ownership,
            policy_request: request,
            policy_evaluation: PolicyEvaluation {
                decision,
                obligations: if decision == PolicyDecision::Deny {
                    deny_obligations()
                } else {
                    obligations(&tool)
                },
                policy_version: "policy-phase3-v1".to_owned(),
                explanation: match decision {
                    PolicyDecision::Deny => "default_deny".to_owned(),
                    PolicyDecision::Allow => "exact_fixture_grant".to_owned(),
                    PolicyDecision::RequireApproval => "owner_approval_required".to_owned(),
                },
            },
            approval,
            approval_outbox_id: (decision == PolicyDecision::RequireApproval)
                .then(mealy_domain::OutboxId::new),
            effect_event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            proposed_at: time(NOW_MS),
        }
    }

    fn start_running_effect(
        store: &mut SqliteStore,
        graph: Graph,
        tool: ToolDescriptor,
    ) -> (EffectId, AttemptId, u64) {
        let effect_id = EffectId::new();
        let proposed = store
            .record_effect_proposal(proposal(graph, effect_id, tool, PolicyDecision::Allow))
            .expect("record authorized effect");
        let attempt_id = AttemptId::new();
        store
            .prepare_effect_attempt(PrepareEffectAttemptCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                prepared_at: time(NOW_MS + 10),
            })
            .expect("prepare effect attempt");
        store
            .mark_effect_attempt_running(MarkEffectAttemptRunningCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision + 1,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                dispatched_at: time(NOW_MS + 20),
            })
            .expect("cross effect dispatch boundary");
        (effect_id, attempt_id, proposed.revision + 2)
    }

    fn start_unknown_effect(store: &mut SqliteStore, graph: Graph) -> (EffectId, AttemptId, u64) {
        let (effect_id, attempt_id, dispatch_revision) = start_running_effect(
            store,
            graph,
            descriptor(
                EffectClass::NonIdempotent,
                IdempotencyClass::NonIdempotent,
                RecoveryStrategy::Reconcile,
            ),
        );
        store
            .record_effect_attempt_outcome(RecordEffectAttemptOutcomeCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: dispatch_revision,
                fence: fence(graph),
                outcome: EffectAttemptOutcome::OutcomeUnknown,
                evidence_details: serde_json::json!({
                    "lastObservedBoundary": "request_sent",
                    "reason": "connection_reset",
                }),
                error_class: Some("transport_ambiguous".to_owned()),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                completed_at: time(NOW_MS + 30),
            })
            .expect("record unknown effect outcome");
        let revision = store
            .effect_ledger_view(graph.ownership, effect_id)
            .expect("load unknown effect")
            .revision;
        (effect_id, attempt_id, revision)
    }

    fn expire_original_lease(store: &SqliteStore, graph: Graph, expired_at_ms: i64) {
        let changed = store
            .connection
            .execute(
                "UPDATE work_lease SET state = 'expired', released_at_ms = ?1 \
                 WHERE lease_id = ?2 AND run_id = ?3 AND owner_id = ?4 \
                   AND fencing_token = 1 AND state = 'active'",
                params![
                    expired_at_ms,
                    graph.lease_id.to_string(),
                    graph.run_id.to_string(),
                    graph.worker_id.to_string(),
                ],
            )
            .expect("expire original effect lease");
        assert_eq!(changed, 1);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn exact_approval_subject_is_durable_scoped_and_resolves_atomically() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let effect_id = EffectId::new();
        let commit = proposal(
            graph,
            effect_id,
            descriptor(
                EffectClass::NonIdempotent,
                IdempotencyClass::NonIdempotent,
                RecoveryStrategy::Reconcile,
            ),
            PolicyDecision::RequireApproval,
        );
        let approval_id = commit
            .approval
            .as_ref()
            .expect("approval draft")
            .approval_id;
        let view = store
            .record_effect_proposal(commit)
            .expect("record proposal");
        assert_eq!(view.status, EffectStatus::AwaitingApproval);
        assert_eq!(view.revision, 1);
        let approval = view.approval.expect("approval projection");
        assert_eq!(approval.status, ApprovalStatus::Pending);
        let approval_payload_json: String = store
            .connection
            .query_row(
                "SELECT payload_json FROM outbox WHERE topic = 'effect.approval_requested'",
                [],
                |row| row.get(0),
            )
            .expect("approval notification outbox");
        let approval_payload: serde_json::Value =
            serde_json::from_str(&approval_payload_json).expect("approval notification JSON");
        let approval_id_text = approval_id.to_string();
        let effect_id_text = effect_id.to_string();
        assert_eq!(
            approval_payload["approval_id"].as_str(),
            Some(approval_id_text.as_str())
        );
        assert_eq!(
            approval_payload["effect_id"].as_str(),
            Some(effect_id_text.as_str())
        );
        assert_eq!(
            approval_payload["subject_digest"].as_str(),
            Some(approval.subject_digest.as_str())
        );
        assert_eq!(approval_payload["tool_id"], "service.update");
        assert_eq!(
            approval_payload["normalized_arguments"],
            serde_json::json!({
                "resourceId": "service://example/item",
                "value": 7,
            })
        );
        assert_eq!(
            approval_payload["target_resources"],
            serde_json::json!(["service://example/item"])
        );
        assert_eq!(approval_payload["expires_at_ms"], NOW_MS + 1_000);
        approval_payload["session_id"]
            .as_str()
            .expect("approval session ID")
            .parse::<SessionId>()
            .expect("valid approval session ID");
        assert_eq!(
            store
                .pending_approval_requests(graph.ownership)
                .expect("query pending")
                .len(),
            1
        );
        let wrong_owner = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
        assert!(
            store
                .pending_approval_requests(wrong_owner)
                .expect("wrong owner sees an empty projection")
                .is_empty()
        );
        assert_eq!(
            store.effect_ledger_view(wrong_owner, effect_id),
            Err(EffectLedgerStoreError::NotFound)
        );

        let wrong_digest = ResolveApprovalCommit {
            approval_id,
            ownership: graph.ownership,
            expected_subject_digest: sha256_digest(b"wrong subject"),
            decision: ApprovalDecision::Approve,
            idempotency_key: "approval-wrong-digest".to_owned(),
            approval_event_id: EventId::new(),
            effect_event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            decided_at: time(NOW_MS + 10),
        };
        assert_eq!(
            store.resolve_approval(wrong_digest),
            Err(EffectLedgerStoreError::SubjectMismatch)
        );
        let resolved = store
            .resolve_approval(ResolveApprovalCommit {
                approval_id,
                ownership: graph.ownership,
                expected_subject_digest: approval.subject_digest,
                decision: ApprovalDecision::Approve,
                idempotency_key: "approval-resolve".to_owned(),
                approval_event_id: EventId::new(),
                effect_event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                decided_at: time(NOW_MS + 11),
            })
            .expect("resolve exact approval");
        assert_eq!(resolved.effect_id, effect_id);
        assert_eq!(resolved.effect_revision, 2);
        assert!(!resolved.duplicate);
        let resolved_view = store
            .effect_ledger_view(graph.ownership, effect_id)
            .expect("load resolved effect");
        assert_eq!(resolved_view.status, EffectStatus::Authorized);
        assert_eq!(resolved_view.revision, 2);
        assert_eq!(
            resolved_view.approval.expect("resolved approval").status,
            ApprovalStatus::Approved
        );
        assert!(
            store
                .pending_approval_requests(graph.ownership)
                .expect("query after resolution")
                .is_empty()
        );
        let event_types = store
            .connection
            .prepare(
                "SELECT journal.event_type FROM timeline_event timeline \
                 JOIN journal_event journal ON journal.event_id = timeline.event_id \
                 WHERE journal.aggregate_id IN (?1, ?2) ORDER BY timeline.cursor",
            )
            .expect("prepare event query")
            .query_map(
                params![effect_id.to_string(), approval_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .expect("query events")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect events");
        assert_eq!(
            event_types,
            [
                "effect.proposed",
                "approval.requested",
                "approval.approved",
                "effect.authorized",
            ]
        );
        store
            .connection
            .execute(
                "UPDATE approval_request SET subject_digest = ?1 WHERE approval_id = ?2",
                params![sha256_digest(b"forged"), approval_id.to_string()],
            )
            .expect_err("bound approval subject must remain immutable");
    }

    #[test]
    fn default_deny_requires_zero_authority_evidence_and_commits_no_partial_rows() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let effect_id = EffectId::new();
        let mut invalid = proposal(
            graph,
            effect_id,
            descriptor(
                EffectClass::Idempotent,
                IdempotencyClass::Keyed,
                RecoveryStrategy::Retry,
            ),
            PolicyDecision::Deny,
        );
        invalid.policy_evaluation.obligations.maximum_output_bytes = 1;
        assert!(matches!(
            store.record_effect_proposal(invalid),
            Err(EffectLedgerStoreError::InvalidEvidence(_))
        ));
        let partial_rows: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM effect WHERE id = ?1",
                [effect_id.to_string()],
                |row| row.get(0),
            )
            .expect("count rejected effect");
        assert_eq!(partial_rows, 0);

        let denied = store
            .record_effect_proposal(proposal(
                graph,
                effect_id,
                descriptor(
                    EffectClass::Idempotent,
                    IdempotencyClass::Keyed,
                    RecoveryStrategy::Retry,
                ),
                PolicyDecision::Deny,
            ))
            .expect("persist exact deny evidence");
        assert_eq!(denied.status, EffectStatus::Denied);
        assert!(denied.approval.is_none());
        assert_eq!(denied.policy_evaluation.decision, PolicyDecision::Deny);
        assert_eq!(denied.policy_evaluation.obligations.maximum_output_bytes, 0);
        store
            .connection
            .execute_batch("DROP TRIGGER effect_policy_evaluation_immutable_update")
            .expect("remove immutability trigger to exercise the table check directly");
        let mut forged_obligations = deny_obligations();
        forged_obligations.maximum_output_bytes = 1;
        store
            .connection
            .execute(
                "UPDATE effect_policy_evaluation SET obligations_json = ?1 WHERE effect_id = ?2",
                params![
                    serde_json::to_string(&forged_obligations)
                        .expect("serialize forged obligations"),
                    effect_id.to_string(),
                ],
            )
            .expect_err("SQLite must independently enforce zero-authority deny evidence");
        store
            .connection
            .execute(
                "UPDATE effect_intent SET capability_scope = 'forged' WHERE effect_id = ?1",
                [effect_id.to_string()],
            )
            .expect_err("effect intent evidence must be immutable");
    }

    #[test]
    fn expiry_is_exclusive_and_durably_denies_the_waiting_effect() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let effect_id = EffectId::new();
        let view = store
            .record_effect_proposal(proposal(
                graph,
                effect_id,
                descriptor(
                    EffectClass::NonIdempotent,
                    IdempotencyClass::NonIdempotent,
                    RecoveryStrategy::NeverRetry,
                ),
                PolicyDecision::RequireApproval,
            ))
            .expect("record proposal");
        let approval = view.approval.expect("pending approval");
        assert_eq!(
            store.resolve_approval(ResolveApprovalCommit {
                approval_id: approval.approval_id,
                ownership: graph.ownership,
                expected_subject_digest: approval.subject_digest,
                decision: ApprovalDecision::Approve,
                idempotency_key: "approval-at-exclusive-expiry".to_owned(),
                approval_event_id: EventId::new(),
                effect_event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                decided_at: time(approval.subject.expires_at_ms),
            }),
            Err(EffectLedgerStoreError::ApprovalExpired)
        );
        assert_eq!(
            store.expire_approval(ExpireApprovalCommit {
                approval_id: approval.approval_id,
                approval_event_id: EventId::new(),
                effect_event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                expired_at: time(approval.subject.expires_at_ms - 1),
            }),
            Err(EffectLedgerStoreError::ExpiryNotReached)
        );
        let expired = store
            .expire_approval(ExpireApprovalCommit {
                approval_id: approval.approval_id,
                approval_event_id: EventId::new(),
                effect_event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                expired_at: time(approval.subject.expires_at_ms),
            })
            .expect("expire approval at exclusive bound");
        assert_eq!(expired.status, EffectStatus::Denied);
        assert_eq!(
            expired.approval.expect("expired approval").status,
            ApprovalStatus::Expired
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn fenced_store_methods_commit_prepare_dispatch_and_success_atomically() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let effect_id = EffectId::new();
        let proposed = store
            .record_effect_proposal(proposal(
                graph,
                effect_id,
                descriptor(
                    EffectClass::Idempotent,
                    IdempotencyClass::Keyed,
                    RecoveryStrategy::Retry,
                ),
                PolicyDecision::Allow,
            ))
            .expect("record authorized effect");
        let attempt_id = AttemptId::new();
        let prepared = store
            .prepare_effect_attempt(PrepareEffectAttemptCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                prepared_at: time(NOW_MS + 10),
            })
            .expect("prepare exact effect attempt");
        assert_eq!(prepared.state, EffectAttemptState::Prepared);
        assert_eq!(prepared.ordinal, 1);
        assert_eq!(
            prepared.idempotency_key.as_deref(),
            Some(derive_effect_idempotency_key(effect_id).as_str())
        );
        let after_prepare = store
            .effect_ledger_view(graph.ownership, effect_id)
            .expect("load prepared effect");
        assert_eq!(after_prepare.status, EffectStatus::Authorized);
        assert_eq!(after_prepare.revision, proposed.revision + 1);

        let running = store
            .mark_effect_attempt_running(MarkEffectAttemptRunningCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: after_prepare.revision,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                dispatched_at: time(NOW_MS + 20),
            })
            .expect("cross dispatch boundary");
        assert_eq!(running.state, EffectAttemptState::Running);
        let after_dispatch = store
            .effect_ledger_view(graph.ownership, effect_id)
            .expect("load dispatching effect");
        assert_eq!(after_dispatch.status, EffectStatus::Dispatching);
        assert_eq!(after_dispatch.revision, after_prepare.revision + 1);

        let succeeded = store
            .record_effect_attempt_outcome(RecordEffectAttemptOutcomeCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: after_dispatch.revision,
                fence: fence(graph),
                outcome: EffectAttemptOutcome::Succeeded,
                evidence_details: serde_json::json!({
                    "externalReceiptId": "receipt-001",
                    "resourceVersion": "8",
                }),
                error_class: None,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                completed_at: time(NOW_MS + 30),
            })
            .expect("record successful outcome");
        assert_eq!(succeeded.state, EffectAttemptState::Succeeded);
        assert_eq!(succeeded.outcomes.len(), 1);
        assert_eq!(succeeded.outcomes[0].kind, EffectOutcomeKind::Succeeded);
        let completed = store
            .effect_ledger_view(graph.ownership, effect_id)
            .expect("load completed effect");
        assert_eq!(completed.status, EffectStatus::Succeeded);
        assert_eq!(completed.revision, after_dispatch.revision + 1);

        let event_types = store
            .connection
            .prepare(
                "SELECT journal.event_type FROM timeline_event timeline \
                 JOIN journal_event journal ON journal.event_id = timeline.event_id \
                 WHERE journal.aggregate_kind = 'effect' AND journal.aggregate_id = ?1 \
                 ORDER BY journal.aggregate_sequence",
            )
            .expect("prepare journal query")
            .query_map([effect_id.to_string()], |row| row.get::<_, String>(0))
            .expect("query journal")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect journal");
        assert_eq!(
            event_types,
            [
                "effect.proposed",
                "effect.attempt_prepared",
                "effect.dispatched",
                "effect.succeeded",
            ]
        );
        let aggregate_sequence: i64 = store
            .connection
            .query_row(
                "SELECT sequence FROM aggregate_sequence \
                 WHERE aggregate_kind = 'effect' AND aggregate_id = ?1",
                [effect_id.to_string()],
                |row| row.get(0),
            )
            .expect("load aggregate sequence");
        assert_eq!(aggregate_sequence, 3);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn stale_revision_fence_and_expired_lease_cannot_cross_dispatch() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let effect_id = EffectId::new();
        let proposed = store
            .record_effect_proposal(proposal(
                graph,
                effect_id,
                descriptor(
                    EffectClass::Idempotent,
                    IdempotencyClass::Idempotent,
                    RecoveryStrategy::Retry,
                ),
                PolicyDecision::Allow,
            ))
            .expect("record authorized effect");
        let attempt_id = AttemptId::new();
        assert_eq!(
            store.mark_effect_attempt_running(MarkEffectAttemptRunningCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                dispatched_at: time(NOW_MS + 10),
            }),
            Err(EffectLedgerStoreError::Conflict)
        );
        let stale_fence = LeaseFence::new(
            graph.lease_id,
            graph.run_id,
            graph.worker_id,
            FencingToken::new(2).expect("nonzero stale token"),
        );
        assert_eq!(
            store.prepare_effect_attempt(PrepareEffectAttemptCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision,
                fence: stale_fence,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                prepared_at: time(NOW_MS + 10),
            }),
            Err(EffectLedgerStoreError::Conflict)
        );
        let prepared = store
            .prepare_effect_attempt(PrepareEffectAttemptCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                prepared_at: time(NOW_MS + 10),
            })
            .expect("prepare with current fence");
        assert_eq!(
            store.mark_effect_attempt_running(MarkEffectAttemptRunningCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                dispatched_at: time(NOW_MS + 20),
            }),
            Err(EffectLedgerStoreError::Conflict)
        );
        let current_revision = proposed.revision + 1;
        assert_eq!(
            store.mark_effect_attempt_running(MarkEffectAttemptRunningCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: current_revision,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                dispatched_at: time(NOW_MS + 60_000),
            }),
            Err(EffectLedgerStoreError::Conflict)
        );
        assert_eq!(
            store
                .effect_attempt_view(graph.ownership, attempt_id)
                .expect("load unchanged prepared attempt"),
            prepared
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn unknown_non_idempotent_outcome_requires_owner_scoped_reconciliation() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let effect_id = EffectId::new();
        let proposed = store
            .record_effect_proposal(proposal(
                graph,
                effect_id,
                descriptor(
                    EffectClass::NonIdempotent,
                    IdempotencyClass::NonIdempotent,
                    RecoveryStrategy::Reconcile,
                ),
                PolicyDecision::Allow,
            ))
            .expect("record authorized effect");
        let attempt_id = AttemptId::new();
        store
            .prepare_effect_attempt(PrepareEffectAttemptCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                prepared_at: time(NOW_MS + 10),
            })
            .expect("prepare effect");
        store
            .mark_effect_attempt_running(MarkEffectAttemptRunningCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision + 1,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                dispatched_at: time(NOW_MS + 20),
            })
            .expect("dispatch effect");
        let unknown = store
            .record_effect_attempt_outcome(RecordEffectAttemptOutcomeCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision + 2,
                fence: fence(graph),
                outcome: EffectAttemptOutcome::OutcomeUnknown,
                evidence_details: serde_json::json!({
                    "lastObservedBoundary": "request_sent",
                    "reason": "connection_reset",
                }),
                error_class: Some("transport_ambiguous".to_owned()),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                completed_at: time(NOW_MS + 30),
            })
            .expect("record ambiguous outcome");
        assert_eq!(unknown.state, EffectAttemptState::OutcomeUnknown);
        let unknown_effect = store
            .effect_ledger_view(graph.ownership, effect_id)
            .expect("load unknown effect");
        let candidate = store
            .interrupted_effect_recovery_candidates()
            .expect("classify unknown effect")
            .into_iter()
            .find(|candidate| candidate.effect_id == effect_id)
            .expect("unknown recovery candidate");
        assert_eq!(
            candidate.disposition,
            EffectRecoveryDisposition::RequiresReconciliation
        );
        assert!(!matches!(
            candidate.disposition,
            EffectRecoveryDisposition::ResumePrepared
                | EffectRecoveryDisposition::Retry
                | EffectRecoveryDisposition::RetryWithSameKey
        ));

        let wrong_owner = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
        assert_eq!(
            store.reconcile_effect_outcome(ReconcileEffectOutcomeCommit {
                effect_id,
                attempt_id,
                ownership: wrong_owner,
                expected_effect_revision: unknown_effect.revision,
                outcome: EffectReconciliationOutcome::Succeeded,
                evidence_details: serde_json::json!({"externalReceiptId": "receipt-unknown"}),
                idempotency_key: "wrong-owner-reconciliation".to_owned(),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                reconciled_at: time(NOW_MS + 40),
            }),
            Err(EffectLedgerStoreError::NotFound)
        );
        let reconciled = store
            .reconcile_effect_outcome(ReconcileEffectOutcomeCommit {
                effect_id,
                attempt_id,
                ownership: graph.ownership,
                expected_effect_revision: unknown_effect.revision,
                outcome: EffectReconciliationOutcome::Succeeded,
                evidence_details: serde_json::json!({"externalReceiptId": "receipt-unknown"}),
                idempotency_key: "reconcile-unknown".to_owned(),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                reconciled_at: time(NOW_MS + 40),
            })
            .expect("reconcile exact unknown outcome");
        assert_eq!(reconciled.outcome, EffectReconciliationOutcome::Succeeded);
        assert_eq!(reconciled.effect_revision, unknown_effect.revision + 1);
        assert!(!reconciled.duplicate);
        let reconciled_attempt = store
            .effect_attempt_view(graph.ownership, attempt_id)
            .expect("load reconciled attempt");
        assert_eq!(reconciled_attempt.state, EffectAttemptState::OutcomeUnknown);
        assert_eq!(
            reconciled_attempt
                .outcomes
                .iter()
                .map(|outcome| outcome.kind)
                .collect::<Vec<_>>(),
            [
                EffectOutcomeKind::OutcomeUnknown,
                EffectOutcomeKind::Succeeded,
            ]
        );
        assert_eq!(
            store
                .effect_ledger_view(graph.ownership, effect_id)
                .expect("load reconciled effect")
                .status,
            EffectStatus::Succeeded
        );
        assert!(
            store
                .interrupted_effect_recovery_candidates()
                .expect("classify after reconciliation")
                .into_iter()
                .all(|candidate| candidate.effect_id != effect_id)
        );
        assert_eq!(
            store.prepare_effect_attempt(PrepareEffectAttemptCommit {
                effect_id,
                attempt_id: AttemptId::new(),
                expected_effect_revision: unknown_effect.revision + 1,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                prepared_at: time(NOW_MS + 50),
            }),
            Err(EffectLedgerStoreError::Conflict)
        );
    }

    #[test]
    fn keyed_recovery_exposes_only_the_original_stable_downstream_key() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let effect_id = EffectId::new();
        let proposed = store
            .record_effect_proposal(proposal(
                graph,
                effect_id,
                descriptor(
                    EffectClass::Idempotent,
                    IdempotencyClass::Keyed,
                    RecoveryStrategy::Retry,
                ),
                PolicyDecision::Allow,
            ))
            .expect("record authorized keyed effect");
        let attempt_id = AttemptId::new();
        let prepared = store
            .prepare_effect_attempt(PrepareEffectAttemptCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                prepared_at: time(NOW_MS + 10),
            })
            .expect("prepare keyed attempt");
        store
            .mark_effect_attempt_running(MarkEffectAttemptRunningCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision + 1,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                dispatched_at: time(NOW_MS + 20),
            })
            .expect("dispatch keyed attempt");
        let candidate = store
            .interrupted_effect_recovery_candidates()
            .expect("classify keyed interruption")
            .into_iter()
            .find(|candidate| candidate.effect_id == effect_id)
            .expect("keyed recovery candidate");
        assert_eq!(
            candidate.disposition,
            EffectRecoveryDisposition::RetryWithSameKey
        );
        assert_eq!(candidate.idempotency_key, prepared.idempotency_key);
        assert_eq!(
            candidate.idempotency_key.as_deref(),
            Some(derive_effect_idempotency_key(effect_id).as_str())
        );
    }

    #[test]
    fn outcome_history_is_immutable_and_digest_tampering_fails_closed() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let effect_id = EffectId::new();
        let proposed = store
            .record_effect_proposal(proposal(
                graph,
                effect_id,
                descriptor(
                    EffectClass::Idempotent,
                    IdempotencyClass::Idempotent,
                    RecoveryStrategy::Retry,
                ),
                PolicyDecision::Allow,
            ))
            .expect("record effect");
        let attempt_id = AttemptId::new();
        store
            .prepare_effect_attempt(PrepareEffectAttemptCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                prepared_at: time(NOW_MS + 10),
            })
            .expect("prepare effect");
        store
            .mark_effect_attempt_running(MarkEffectAttemptRunningCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision + 1,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                dispatched_at: time(NOW_MS + 20),
            })
            .expect("dispatch effect");
        store
            .record_effect_attempt_outcome(RecordEffectAttemptOutcomeCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision + 2,
                fence: fence(graph),
                outcome: EffectAttemptOutcome::Succeeded,
                evidence_details: serde_json::json!({"receipt": "immutable"}),
                error_class: None,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                completed_at: time(NOW_MS + 30),
            })
            .expect("record outcome");
        assert!(
            store
                .connection
                .execute(
                    "UPDATE effect_outcome SET evidence_digest = ?1 WHERE attempt_id = ?2",
                    params![sha256_digest(b"forged"), attempt_id.to_string()],
                )
                .is_err()
        );
        store
            .connection
            .execute_batch("DROP TRIGGER effect_outcome_immutable_update")
            .expect("drop immutability trigger for corruption probe");
        store
            .connection
            .execute(
                "UPDATE effect_outcome SET evidence_digest = ?1 WHERE attempt_id = ?2",
                params![sha256_digest(b"forged"), attempt_id.to_string()],
            )
            .expect("simulate corruption below the trust boundary");
        assert!(matches!(
            store.effect_attempt_view(graph.ownership, attempt_id),
            Err(EffectLedgerStoreError::InvariantViolation(_))
        ));
    }

    #[test]
    fn failed_outcome_requires_a_classification_and_commits_terminal_failure() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let effect_id = EffectId::new();
        let proposed = store
            .record_effect_proposal(proposal(
                graph,
                effect_id,
                descriptor(
                    EffectClass::Idempotent,
                    IdempotencyClass::Idempotent,
                    RecoveryStrategy::NeverRetry,
                ),
                PolicyDecision::Allow,
            ))
            .expect("record effect");
        let attempt_id = AttemptId::new();
        store
            .prepare_effect_attempt(PrepareEffectAttemptCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                prepared_at: time(NOW_MS + 10),
            })
            .expect("prepare effect");
        store
            .mark_effect_attempt_running(MarkEffectAttemptRunningCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision + 1,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                dispatched_at: time(NOW_MS + 20),
            })
            .expect("dispatch effect");
        let missing_classification = RecordEffectAttemptOutcomeCommit {
            effect_id,
            attempt_id,
            expected_effect_revision: proposed.revision + 2,
            fence: fence(graph),
            outcome: EffectAttemptOutcome::Failed,
            evidence_details: serde_json::json!({"serviceCode": "rejected"}),
            error_class: None,
            event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            completed_at: time(NOW_MS + 30),
        };
        assert!(matches!(
            store.record_effect_attempt_outcome(missing_classification.clone()),
            Err(EffectLedgerStoreError::InvalidEvidence(_))
        ));
        let failed = store
            .record_effect_attempt_outcome(RecordEffectAttemptOutcomeCommit {
                error_class: Some("service_rejected".to_owned()),
                event_id: EventId::new(),
                ..missing_classification
            })
            .expect("record classified failure");
        assert_eq!(failed.state, EffectAttemptState::Failed);
        assert_eq!(failed.error_class.as_deref(), Some("service_rejected"));
        assert_eq!(failed.outcomes[0].kind, EffectOutcomeKind::Failed);
        assert_eq!(
            store
                .effect_ledger_view(graph.ownership, effect_id)
                .expect("load failed effect")
                .status,
            EffectStatus::Failed
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn interrupted_recovery_requires_inactive_mature_lease_and_exact_revision() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let (effect_id, attempt_id, dispatch_revision) = start_running_effect(
            &mut store,
            graph,
            descriptor(
                EffectClass::NonIdempotent,
                IdempotencyClass::NonIdempotent,
                RecoveryStrategy::Reconcile,
            ),
        );
        let active_commit = RecoverInterruptedEffectCommit {
            effect_id,
            attempt_id,
            expected_effect_revision: dispatch_revision,
            event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            recovered_at: time(NOW_MS + 60_000),
        };
        assert_eq!(
            store.recover_interrupted_effect(active_commit.clone()),
            Err(EffectLedgerStoreError::Conflict)
        );
        assert_eq!(
            store
                .effect_attempt_view(graph.ownership, attempt_id)
                .expect("load still-running attempt")
                .state,
            EffectAttemptState::Running
        );

        expire_original_lease(&store, graph, NOW_MS + 60_000);
        assert_eq!(
            store.recover_interrupted_effect(RecoverInterruptedEffectCommit {
                recovered_at: time(NOW_MS + 59_999),
                ..active_commit.clone()
            }),
            Err(EffectLedgerStoreError::Conflict)
        );
        assert_eq!(
            store.recover_interrupted_effect(RecoverInterruptedEffectCommit {
                expected_effect_revision: dispatch_revision - 1,
                event_id: EventId::new(),
                recovered_at: time(NOW_MS + 60_000),
                ..active_commit
            }),
            Err(EffectLedgerStoreError::Conflict)
        );
        let outcome_count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM effect_outcome WHERE attempt_id = ?1",
                [attempt_id.to_string()],
                |row| row.get(0),
            )
            .expect("count rejected recovery outcomes");
        assert_eq!(outcome_count, 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn interrupted_recovery_is_deterministic_and_preserves_owner_reconciliation() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let (effect_id, attempt_id, dispatch_revision) = start_running_effect(
            &mut store,
            graph,
            descriptor(
                EffectClass::NonIdempotent,
                IdempotencyClass::NonIdempotent,
                RecoveryStrategy::Reconcile,
            ),
        );
        let running_candidate = store
            .interrupted_effect_recovery_candidates()
            .expect("classify running effect")
            .into_iter()
            .find(|candidate| candidate.effect_id == effect_id)
            .expect("running recovery candidate");
        assert_eq!(running_candidate.boundary, EffectAttemptBoundary::Running);
        assert_eq!(
            running_candidate.disposition,
            EffectRecoveryDisposition::RequiresReconciliation
        );
        expire_original_lease(&store, graph, NOW_MS + 60_000);
        let recovery = RecoverInterruptedEffectCommit {
            effect_id,
            attempt_id,
            expected_effect_revision: dispatch_revision,
            event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            recovered_at: time(NOW_MS + 60_000),
        };
        let recovered = store
            .recover_interrupted_effect(recovery.clone())
            .expect("record interrupted outcome as unknown");
        assert_eq!(recovered.state, EffectAttemptState::OutcomeUnknown);
        assert_eq!(
            recovered.error_class.as_deref(),
            Some(INTERRUPTED_EFFECT_OUTCOME_ERROR_CLASS)
        );
        assert_eq!(recovered.outcomes.len(), 1);
        assert_eq!(
            recovered.outcomes[0].kind,
            EffectOutcomeKind::OutcomeUnknown
        );
        assert_eq!(
            recovered.outcomes[0].evidence["evidence"]["classification"].as_str(),
            Some(INTERRUPTED_EFFECT_OUTCOME_CLASSIFICATION)
        );
        assert_eq!(
            recovered.outcomes[0].evidence["evidence"]["leaseState"].as_str(),
            Some("expired")
        );
        let journal_count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM journal_event WHERE event_id = ?1",
                [recovery.event_id.to_string()],
                |row| row.get(0),
            )
            .expect("count recovery event");
        let replayed = store
            .recover_interrupted_effect(recovery.clone())
            .expect("repeat exact recovery command");
        assert_eq!(replayed, recovered);
        let replay_journal_count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM journal_event WHERE event_id = ?1",
                [recovery.event_id.to_string()],
                |row| row.get(0),
            )
            .expect("count idempotent recovery event");
        assert_eq!(replay_journal_count, journal_count);
        assert_eq!(replay_journal_count, 1);
        assert_eq!(
            store.recover_interrupted_effect(RecoverInterruptedEffectCommit {
                event_id: EventId::new(),
                ..recovery.clone()
            }),
            Err(EffectLedgerStoreError::Conflict)
        );

        let unknown_candidate = store
            .interrupted_effect_recovery_candidates()
            .expect("classify unknown effect")
            .into_iter()
            .find(|candidate| candidate.effect_id == effect_id)
            .expect("unknown recovery candidate");
        assert_eq!(
            unknown_candidate.boundary,
            EffectAttemptBoundary::OutcomeUnknown
        );
        assert_eq!(
            unknown_candidate.disposition,
            EffectRecoveryDisposition::RequiresReconciliation
        );
        assert!(!matches!(
            unknown_candidate.disposition,
            EffectRecoveryDisposition::ResumePrepared
                | EffectRecoveryDisposition::Retry
                | EffectRecoveryDisposition::RetryWithSameKey
        ));
        assert!(
            store
                .connection
                .execute(
                    "UPDATE effect_outcome SET evidence_digest = ?1 WHERE attempt_id = ?2",
                    params![sha256_digest(b"forged"), attempt_id.to_string()],
                )
                .is_err()
        );

        let reconciled = store
            .reconcile_effect_outcome(ReconcileEffectOutcomeCommit {
                effect_id,
                attempt_id,
                ownership: graph.ownership,
                expected_effect_revision: dispatch_revision + 1,
                outcome: EffectReconciliationOutcome::Succeeded,
                evidence_details: serde_json::json!({"externalReceiptId": "recovered-001"}),
                idempotency_key: "reconcile-recovered".to_owned(),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                reconciled_at: time(NOW_MS + 60_001),
            })
            .expect("owner reconciles recovered unknown outcome");
        assert_eq!(reconciled.outcome, EffectReconciliationOutcome::Succeeded);
        let reconciled_attempt = store
            .effect_attempt_view(graph.ownership, attempt_id)
            .expect("load reconciled recovered attempt");
        assert_eq!(reconciled_attempt.state, EffectAttemptState::OutcomeUnknown);
        assert_eq!(reconciled_attempt.outcomes.len(), 2);
        assert_eq!(
            reconciled_attempt.outcomes[1].kind,
            EffectOutcomeKind::Succeeded
        );
        assert!(
            store
                .interrupted_effect_recovery_candidates()
                .expect("classify after owner reconciliation")
                .into_iter()
                .all(|candidate| candidate.effect_id != effect_id)
        );
    }

    #[test]
    fn interrupted_recovery_does_not_override_a_proven_safe_keyed_retry() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let (effect_id, attempt_id, dispatch_revision) = start_running_effect(
            &mut store,
            graph,
            descriptor(
                EffectClass::Idempotent,
                IdempotencyClass::Keyed,
                RecoveryStrategy::Retry,
            ),
        );
        expire_original_lease(&store, graph, NOW_MS + 60_000);
        assert_eq!(
            store.recover_interrupted_effect(RecoverInterruptedEffectCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: dispatch_revision,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                recovered_at: time(NOW_MS + 60_000),
            }),
            Err(EffectLedgerStoreError::Conflict)
        );
        let candidate = store
            .interrupted_effect_recovery_candidates()
            .expect("classify keyed retry")
            .into_iter()
            .find(|candidate| candidate.effect_id == effect_id)
            .expect("keyed retry candidate");
        assert_eq!(
            candidate.disposition,
            EffectRecoveryDisposition::RetryWithSameKey
        );
        assert_eq!(
            candidate.idempotency_key.as_deref(),
            Some(derive_effect_idempotency_key(effect_id).as_str())
        );
        assert_eq!(
            store
                .effect_attempt_view(graph.ownership, attempt_id)
                .expect("load unmodified keyed attempt")
                .state,
            EffectAttemptState::Running
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn startup_parks_non_idempotent_unknown_effect_run_and_task_atomically() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let (effect_id, attempt_id, _) = start_running_effect(
            &mut store,
            graph,
            descriptor(
                EffectClass::NonIdempotent,
                IdempotencyClass::NonIdempotent,
                RecoveryStrategy::Reconcile,
            ),
        );
        let clock = TestClock::new(NOW_MS + 100);
        let ids =
            TestIdGenerator::new(u64::try_from(NOW_MS + 100).expect("positive test ID timestamp"));
        let summary = recover_startup(&mut store, &clock, &ids, 8)
            .expect("recover unsafe interrupted effect");
        assert_eq!(summary.expired_leases, 1);
        assert_eq!(summary.requeued_runs, 0);
        assert_eq!(summary.waiting_runs, 1);
        let statuses: (String, String, String) = store
            .connection
            .query_row(
                "SELECT run.status, task.status, lease.state FROM run \
                 JOIN task ON task.id = run.task_id \
                 JOIN work_lease lease ON lease.run_id = run.id \
                 WHERE run.id = ?1",
                [graph.run_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("load atomically parked recovery graph");
        assert_eq!(
            statuses,
            (
                "waiting".to_owned(),
                "waiting".to_owned(),
                "expired".to_owned(),
            )
        );
        let recovered = store
            .effect_attempt_view(graph.ownership, attempt_id)
            .expect("load recovered unsafe attempt");
        assert_eq!(recovered.state, EffectAttemptState::OutcomeUnknown);
        assert_eq!(
            store
                .effect_ledger_view(graph.ownership, effect_id)
                .expect("load unknown effect")
                .status,
            EffectStatus::OutcomeUnknown
        );
        let candidate = store
            .interrupted_effect_recovery_candidates()
            .expect("classify startup-recovered effect")
            .into_iter()
            .find(|candidate| candidate.effect_id == effect_id)
            .expect("unknown candidate remains visible");
        assert_eq!(
            candidate.disposition,
            EffectRecoveryDisposition::RequiresReconciliation
        );
        let run_task_events = store
            .connection
            .prepare(
                "SELECT event.event_type FROM journal_event event \
                 JOIN timeline_event timeline ON timeline.event_id = event.event_id \
                 WHERE event.event_type IN ('lease.expired', 'effect.outcome_unknown', \
                                             'run.waiting', 'task.waiting') \
                 ORDER BY timeline.cursor",
            )
            .expect("prepare recovery event query")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query recovery events")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect recovery events");
        assert_eq!(
            run_task_events,
            [
                "lease.expired",
                "effect.outcome_unknown",
                "run.waiting",
                "task.waiting",
            ]
        );
        assert_eq!(
            store
                .claim_next(LeaseClaimCommit {
                    owner_id: WorkerId::new(),
                    lease_id: LeaseId::new(),
                    run_event_id: EventId::new(),
                    task_event_id: EventId::new(),
                    correlation_id: CorrelationId::new(),
                    claimed_at: time(NOW_MS + 101),
                    expires_at: time(NOW_MS + 1_000),
                    concurrency_limits: mealy_application::LeaseConcurrencyLimits::default(),
                })
                .expect("scheduler query after waiting transition"),
            LeaseClaimOutcome::NoRunnableWork
        );
    }

    #[test]
    fn startup_parks_already_unknown_effect_without_duplicate_outcome() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let (effect_id, attempt_id, dispatch_revision) = start_running_effect(
            &mut store,
            graph,
            descriptor(
                EffectClass::NonIdempotent,
                IdempotencyClass::NonIdempotent,
                RecoveryStrategy::Reconcile,
            ),
        );
        let unknown = store
            .record_effect_attempt_outcome(RecordEffectAttemptOutcomeCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: dispatch_revision,
                fence: fence(graph),
                outcome: EffectAttemptOutcome::OutcomeUnknown,
                evidence_details: serde_json::json!({"reason": "adapter_timeout"}),
                error_class: Some("adapter_timeout_ambiguous".to_owned()),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                completed_at: time(NOW_MS + 30),
            })
            .expect("commit unknown before daemon crash");
        let effect_before = store
            .effect_ledger_view(graph.ownership, effect_id)
            .expect("load unknown effect before startup");
        let clock = TestClock::new(NOW_MS + 100);
        let ids =
            TestIdGenerator::new(u64::try_from(NOW_MS + 100).expect("positive test ID timestamp"));
        let summary =
            recover_startup(&mut store, &clock, &ids, 8).expect("park already-unknown effect");
        assert_eq!(summary.requeued_runs, 0);
        assert_eq!(summary.waiting_runs, 1);
        assert_eq!(
            store
                .effect_attempt_view(graph.ownership, attempt_id)
                .expect("load unknown attempt after startup"),
            unknown
        );
        assert_eq!(
            store
                .effect_ledger_view(graph.ownership, effect_id)
                .expect("load unknown effect after startup"),
            effect_before
        );
        let outcome_count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM effect_outcome WHERE attempt_id = ?1",
                [attempt_id.to_string()],
                |row| row.get(0),
            )
            .expect("count preserved unknown outcome");
        assert_eq!(outcome_count, 1);
        let statuses: (String, String) = store
            .connection
            .query_row(
                "SELECT run.status, task.status FROM run \
                 JOIN task ON task.id = run.task_id WHERE run.id = ?1",
                [graph.run_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("load parked statuses");
        assert_eq!(statuses, ("waiting".to_owned(), "waiting".to_owned()));
    }

    #[test]
    fn startup_requeues_run_when_effect_outcome_is_already_terminal() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let (effect_id, attempt_id, dispatch_revision) = start_running_effect(
            &mut store,
            graph,
            descriptor(
                EffectClass::Idempotent,
                IdempotencyClass::Idempotent,
                RecoveryStrategy::Retry,
            ),
        );
        let completed = store
            .record_effect_attempt_outcome(RecordEffectAttemptOutcomeCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: dispatch_revision,
                fence: fence(graph),
                outcome: EffectAttemptOutcome::Succeeded,
                evidence_details: serde_json::json!({"receipt": "terminal-before-crash"}),
                error_class: None,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                completed_at: time(NOW_MS + 30),
            })
            .expect("commit terminal effect before crash");
        let clock = TestClock::new(NOW_MS + 100);
        let ids =
            TestIdGenerator::new(u64::try_from(NOW_MS + 100).expect("positive test ID timestamp"));
        let summary =
            recover_startup(&mut store, &clock, &ids, 8).expect("requeue run with terminal effect");
        assert_eq!(summary.requeued_runs, 1);
        assert_eq!(summary.waiting_runs, 0);
        assert_eq!(
            store
                .effect_attempt_view(graph.ownership, attempt_id)
                .expect("load preserved terminal attempt"),
            completed
        );
        assert_eq!(
            store
                .effect_ledger_view(graph.ownership, effect_id)
                .expect("load terminal effect")
                .status,
            EffectStatus::Succeeded
        );
        let run_status: String = store
            .connection
            .query_row(
                "SELECT status FROM run WHERE id = ?1",
                [graph.run_id.to_string()],
                |row| row.get(0),
            )
            .expect("load requeued run");
        assert_eq!(run_status, "queued");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn startup_retires_safe_running_attempt_and_new_fence_reuses_key() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let (effect_id, attempt_id, dispatch_revision) = start_running_effect(
            &mut store,
            graph,
            descriptor(
                EffectClass::Idempotent,
                IdempotencyClass::Keyed,
                RecoveryStrategy::Retry,
            ),
        );
        let expected_key = derive_effect_idempotency_key(effect_id);
        let clock = TestClock::new(NOW_MS + 100);
        let ids =
            TestIdGenerator::new(u64::try_from(NOW_MS + 100).expect("positive test ID timestamp"));
        let summary =
            recover_startup(&mut store, &clock, &ids, 8).expect("recover safely repeatable effect");
        assert_eq!(summary.requeued_runs, 1);
        assert_eq!(summary.waiting_runs, 0);
        let interrupted = store
            .effect_attempt_view(graph.ownership, attempt_id)
            .expect("load retryable interrupted attempt");
        assert_eq!(interrupted.state, EffectAttemptState::InterruptedRetryable);
        assert_eq!(
            interrupted.error_class.as_deref(),
            Some(INTERRUPTED_EFFECT_RETRY_ERROR_CLASS)
        );
        assert_eq!(interrupted.outcomes.len(), 1);
        assert_eq!(
            interrupted.outcomes[0].evidence["evidence"]["classification"].as_str(),
            Some(INTERRUPTED_EFFECT_RETRY_CLASSIFICATION)
        );
        let effect = store
            .effect_ledger_view(graph.ownership, effect_id)
            .expect("load retry-authorized effect");
        assert_eq!(effect.status, EffectStatus::Authorized);
        assert_eq!(effect.revision, dispatch_revision + 1);
        assert_eq!(
            effect.idempotency_key.as_deref(),
            Some(expected_key.as_str())
        );

        let next_lease = match store
            .claim_next(LeaseClaimCommit {
                owner_id: WorkerId::new(),
                lease_id: LeaseId::new(),
                run_event_id: EventId::new(),
                task_event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                claimed_at: time(NOW_MS + 101),
                expires_at: time(NOW_MS + 1_000),
                concurrency_limits: mealy_application::LeaseConcurrencyLimits::default(),
            })
            .expect("claim safely requeued run")
        {
            LeaseClaimOutcome::Claimed(receipt) => receipt.lease.fence(),
            LeaseClaimOutcome::NoRunnableWork => panic!("safe retry run must be claimable"),
        };
        let retry_attempt = store
            .prepare_effect_attempt(PrepareEffectAttemptCommit {
                effect_id,
                attempt_id: AttemptId::new(),
                expected_effect_revision: effect.revision,
                fence: next_lease,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                prepared_at: time(NOW_MS + 102),
            })
            .expect("prepare new ordinal under new fence");
        assert_eq!(retry_attempt.ordinal, 2);
        assert_eq!(
            retry_attempt.idempotency_key.as_deref(),
            Some(expected_key.as_str())
        );
        assert_ne!(retry_attempt.fence, interrupted.fence);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn startup_retires_undispatched_preparation_without_outcome_and_allows_new_ordinal() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let effect_id = EffectId::new();
        let proposed = store
            .record_effect_proposal(proposal(
                graph,
                effect_id,
                descriptor(
                    EffectClass::NonIdempotent,
                    IdempotencyClass::NonIdempotent,
                    RecoveryStrategy::Reconcile,
                ),
                PolicyDecision::Allow,
            ))
            .expect("record authorized effect");
        let attempt_id = AttemptId::new();
        store
            .prepare_effect_attempt(PrepareEffectAttemptCommit {
                effect_id,
                attempt_id,
                expected_effect_revision: proposed.revision,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                prepared_at: time(NOW_MS + 10),
            })
            .expect("prepare effect before crash");
        let clock = TestClock::new(NOW_MS + 100);
        let ids =
            TestIdGenerator::new(u64::try_from(NOW_MS + 100).expect("positive test ID timestamp"));
        let summary =
            recover_startup(&mut store, &clock, &ids, 8).expect("recover undispatched preparation");
        assert_eq!(summary.requeued_runs, 1);
        assert_eq!(summary.waiting_runs, 0);
        let retired = store
            .effect_attempt_view(graph.ownership, attempt_id)
            .expect("load retired preparation");
        assert_eq!(retired.state, EffectAttemptState::InterruptedUndispatched);
        assert!(retired.started_at.is_none());
        assert!(retired.outcomes.is_empty());
        let effect = store
            .effect_ledger_view(graph.ownership, effect_id)
            .expect("load still-authorized effect");
        assert_eq!(effect.status, EffectStatus::Authorized);
        assert_eq!(effect.revision, proposed.revision + 2);
        let next_fence = match store
            .claim_next(LeaseClaimCommit {
                owner_id: WorkerId::new(),
                lease_id: LeaseId::new(),
                run_event_id: EventId::new(),
                task_event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                claimed_at: time(NOW_MS + 101),
                expires_at: time(NOW_MS + 1_000),
                concurrency_limits: mealy_application::LeaseConcurrencyLimits::default(),
            })
            .expect("claim requeued undispatched work")
        {
            LeaseClaimOutcome::Claimed(receipt) => receipt.lease.fence(),
            LeaseClaimOutcome::NoRunnableWork => {
                panic!("undispatched preparation must be claimable")
            }
        };
        let retry = store
            .prepare_effect_attempt(PrepareEffectAttemptCommit {
                effect_id,
                attempt_id: AttemptId::new(),
                expected_effect_revision: effect.revision,
                fence: next_fence,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                prepared_at: time(NOW_MS + 102),
            })
            .expect("prepare replacement for undispatched work");
        assert_eq!(retry.ordinal, 2);
    }

    fn insert_attempt_event(
        store: &SqliteStore,
        effect_id: EffectId,
        event_id: EventId,
        event_type: &str,
        occurred_at_ms: i64,
    ) {
        let sequence: i64 = store
            .connection
            .query_row(
                "SELECT sequence + 1 FROM aggregate_sequence \
                 WHERE aggregate_kind = 'effect' AND aggregate_id = ?1",
                [effect_id.to_string()],
                |row| row.get(0),
            )
            .expect("load next effect event sequence");
        store
            .connection
            .execute(
                "INSERT INTO journal_event(\
                    event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                    event_version, occurred_at_ms, correlation_id, sensitivity, payload_json\
                 ) VALUES (?1, 'effect', ?2, ?3, ?4, 1, ?5, ?6, 'internal', '{}')",
                params![
                    event_id.to_string(),
                    effect_id.to_string(),
                    sequence,
                    event_type,
                    occurred_at_ms,
                    CorrelationId::new().to_string(),
                ],
            )
            .expect("insert attempt event");
        store
            .connection
            .execute(
                "UPDATE aggregate_sequence SET sequence = ?1 \
                 WHERE aggregate_kind = 'effect' AND aggregate_id = ?2",
                params![sequence, effect_id.to_string()],
            )
            .expect("advance effect aggregate sequence");
    }

    #[allow(clippy::too_many_lines)]
    fn seed_attempt(
        store: &SqliteStore,
        graph: Graph,
        effect_id: EffectId,
        boundary: EffectAttemptBoundary,
        prepared_at_ms: i64,
    ) -> AttemptId {
        let attempt_id = AttemptId::new();
        let prepared_event_id = EventId::new();
        insert_attempt_event(
            store,
            effect_id,
            prepared_event_id,
            "effect.attempt_prepared",
            prepared_at_ms,
        );
        let idempotency_key: Option<String> = store
            .connection
            .query_row(
                "SELECT idempotency_key FROM effect_intent WHERE effect_id = ?1",
                [effect_id.to_string()],
                |row| row.get(0),
            )
            .expect("load effect key");
        store
            .connection
            .execute(
                "INSERT INTO effect_attempt_fence(\
                    lease_id, effect_id, owner_id, fencing_token, run_id\
                 ) VALUES (?1, ?2, ?3, 1, ?4)",
                params![
                    graph.lease_id.to_string(),
                    effect_id.to_string(),
                    graph.worker_id.to_string(),
                    graph.run_id.to_string(),
                ],
            )
            .expect("bind effect attempt fence");
        store
            .connection
            .execute(
                "INSERT INTO effect_attempt(\
                    attempt_id, effect_id, ordinal, state, idempotency_key, prepared_lease_id, \
                    prepared_owner_id, prepared_fencing_token, prepared_event_id, prepared_at_ms\
                 ) VALUES (?1, ?2, 1, 'prepared', ?3, ?4, ?5, 1, ?6, ?7)",
                params![
                    attempt_id.to_string(),
                    effect_id.to_string(),
                    idempotency_key,
                    graph.lease_id.to_string(),
                    graph.worker_id.to_string(),
                    prepared_event_id.to_string(),
                    prepared_at_ms,
                ],
            )
            .expect("insert prepared effect attempt");
        if matches!(
            boundary,
            EffectAttemptBoundary::Running | EffectAttemptBoundary::OutcomeUnknown
        ) {
            let started_event_id = EventId::new();
            insert_attempt_event(
                store,
                effect_id,
                started_event_id,
                "effect.dispatched",
                prepared_at_ms + 1,
            );
            store
                .connection
                .execute(
                    "UPDATE effect SET status = 'dispatching', revision = revision + 1, \
                                       dispatched_at_ms = ?1, updated_at_ms = ?1 \
                     WHERE id = ?2",
                    params![prepared_at_ms + 1, effect_id.to_string()],
                )
                .expect("cross durable dispatch boundary");
            store
                .connection
                .execute(
                    "UPDATE effect_attempt \
                     SET state = 'running', started_event_id = ?1, started_at_ms = ?2 \
                     WHERE attempt_id = ?3",
                    params![
                        started_event_id.to_string(),
                        prepared_at_ms + 1,
                        attempt_id.to_string(),
                    ],
                )
                .expect("start effect attempt");
        }
        if boundary == EffectAttemptBoundary::OutcomeUnknown {
            let terminal_event_id = EventId::new();
            insert_attempt_event(
                store,
                effect_id,
                terminal_event_id,
                "effect.outcome_unknown",
                prepared_at_ms + 2,
            );
            let evidence = effect_outcome_evidence_material(
                effect_id,
                attempt_id,
                0,
                EffectOutcomeKind::OutcomeUnknown,
                &serde_json::json!({"reason": "worker_lost"}),
                Some("worker_lost"),
                prepared_at_ms + 2,
            )
            .expect("build canonical unknown evidence")
            .to_string();
            store
                .connection
                .execute(
                    "INSERT INTO effect_outcome(\
                        attempt_id, effect_id, sequence, outcome_kind, evidence_json, \
                        evidence_digest, event_id, recorded_at_ms\
                     ) VALUES (?1, ?2, 0, 'outcome_unknown', ?3, ?4, ?5, ?6)",
                    params![
                        attempt_id.to_string(),
                        effect_id.to_string(),
                        evidence,
                        sha256_digest(evidence.as_bytes()),
                        terminal_event_id.to_string(),
                        prepared_at_ms + 2,
                    ],
                )
                .expect("record unknown outcome evidence");
            store
                .connection
                .execute(
                    "UPDATE effect SET status = 'outcome_unknown', revision = revision + 1, \
                                       completed_at_ms = ?1, updated_at_ms = ?1 \
                     WHERE id = ?2",
                    params![prepared_at_ms + 2, effect_id.to_string()],
                )
                .expect("mark effect outcome unknown");
            store
                .connection
                .execute(
                    "UPDATE effect_attempt \
                     SET state = 'outcome_unknown', terminal_event_id = ?1, \
                         completed_at_ms = ?2, error_class = 'worker_lost' \
                     WHERE attempt_id = ?3",
                    params![
                        terminal_event_id.to_string(),
                        prepared_at_ms + 2,
                        attempt_id.to_string(),
                    ],
                )
                .expect("settle attempt as unknown");
        }
        attempt_id
    }

    #[test]
    fn recovery_candidates_are_deterministic_and_never_requeue_non_idempotent_unknown_work() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let cases = [
            (
                descriptor(
                    EffectClass::NonIdempotent,
                    IdempotencyClass::NonIdempotent,
                    RecoveryStrategy::Reconcile,
                ),
                EffectAttemptBoundary::Prepared,
                EffectRecoveryDisposition::ResumePrepared,
            ),
            (
                descriptor(
                    EffectClass::NonIdempotent,
                    IdempotencyClass::NonIdempotent,
                    RecoveryStrategy::Reconcile,
                ),
                EffectAttemptBoundary::Running,
                EffectRecoveryDisposition::RequiresReconciliation,
            ),
            (
                descriptor(
                    EffectClass::NonIdempotent,
                    IdempotencyClass::NonIdempotent,
                    RecoveryStrategy::Reconcile,
                ),
                EffectAttemptBoundary::OutcomeUnknown,
                EffectRecoveryDisposition::RequiresReconciliation,
            ),
            (
                descriptor(
                    EffectClass::Idempotent,
                    IdempotencyClass::Keyed,
                    RecoveryStrategy::Retry,
                ),
                EffectAttemptBoundary::Running,
                EffectRecoveryDisposition::RetryWithSameKey,
            ),
            (
                descriptor(
                    EffectClass::Idempotent,
                    IdempotencyClass::Idempotent,
                    RecoveryStrategy::Retry,
                ),
                EffectAttemptBoundary::Running,
                EffectRecoveryDisposition::Retry,
            ),
            (
                descriptor(
                    EffectClass::NonIdempotent,
                    IdempotencyClass::NonIdempotent,
                    RecoveryStrategy::NeverRetry,
                ),
                EffectAttemptBoundary::Running,
                EffectRecoveryDisposition::TerminallyFailed,
            ),
        ];
        let mut expected = Vec::new();
        for (index, (tool, boundary, disposition)) in cases.into_iter().enumerate() {
            let graph = seed_graph(&store);
            let effect_id = EffectId::new();
            store
                .record_effect_proposal(proposal(graph, effect_id, tool, PolicyDecision::Allow))
                .expect("record authorized effect");
            let prepared_at_ms =
                NOW_MS + 100 + i64::try_from(index).expect("small case index") * 10;
            let attempt_id = seed_attempt(&store, graph, effect_id, boundary, prepared_at_ms);
            expected.push((effect_id, attempt_id, boundary, disposition));
        }
        let candidates = store
            .interrupted_effect_recovery_candidates()
            .expect("classify interrupted effects");
        assert_eq!(candidates.len(), expected.len());
        for (candidate, (effect_id, attempt_id, boundary, disposition)) in
            candidates.iter().zip(expected)
        {
            assert_eq!(candidate.effect_id, effect_id);
            assert_eq!(candidate.attempt_id, attempt_id);
            assert_eq!(candidate.boundary, boundary);
            assert_eq!(candidate.disposition, disposition);
            if candidate.idempotency == IdempotencyClass::NonIdempotent
                && matches!(
                    candidate.boundary,
                    EffectAttemptBoundary::Running | EffectAttemptBoundary::OutcomeUnknown
                )
            {
                assert!(!matches!(
                    candidate.disposition,
                    EffectRecoveryDisposition::ResumePrepared
                        | EffectRecoveryDisposition::Retry
                        | EffectRecoveryDisposition::RetryWithSameKey
                ));
            }
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn approval_resolution_receipt_is_exact_scoped_immutable_and_survives_later_revision() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let effect_id = EffectId::new();
        let proposed = store
            .record_effect_proposal(proposal(
                graph,
                effect_id,
                descriptor(
                    EffectClass::NonIdempotent,
                    IdempotencyClass::NonIdempotent,
                    RecoveryStrategy::Reconcile,
                ),
                PolicyDecision::RequireApproval,
            ))
            .expect("record approval effect");
        let approval = proposed.approval.expect("pending approval");
        let command = ResolveApprovalCommit {
            approval_id: approval.approval_id,
            ownership: graph.ownership,
            expected_subject_digest: approval.subject_digest.clone(),
            decision: ApprovalDecision::Approve,
            idempotency_key: "durable-approval-receipt".to_owned(),
            approval_event_id: EventId::new(),
            effect_event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            decided_at: time(NOW_MS + 10),
        };
        let first = store
            .resolve_approval(command.clone())
            .expect("commit approval receipt");
        assert!(!first.duplicate);
        assert_eq!(first.effect_revision, proposed.revision + 1);
        let recorded_cursor: i64 = store
            .connection
            .query_row(
                "SELECT cursor FROM timeline_event WHERE event_id = ?1",
                [first.effect_event_id.to_string()],
                |row| row.get(0),
            )
            .expect("load original approval cursor");
        assert_eq!(
            u64::try_from(recorded_cursor).expect("positive cursor"),
            first.cursor
        );

        store
            .prepare_effect_attempt(PrepareEffectAttemptCommit {
                effect_id,
                attempt_id: AttemptId::new(),
                expected_effect_revision: first.effect_revision,
                fence: fence(graph),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                prepared_at: time(NOW_MS + 20),
            })
            .expect("advance effect after approval receipt");
        assert_eq!(
            store
                .effect_ledger_view(graph.ownership, effect_id)
                .expect("load later effect revision")
                .revision,
            first.effect_revision + 1
        );
        let duplicate = store
            .resolve_approval(ResolveApprovalCommit {
                approval_event_id: EventId::new(),
                effect_event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                decided_at: time(NOW_MS + 5_000),
                ..command.clone()
            })
            .expect("return original approval receipt after later transition");
        assert_eq!(
            duplicate,
            mealy_application::ApprovalResolutionReceipt {
                duplicate: true,
                ..first
            }
        );

        for conflicting in [
            ResolveApprovalCommit {
                decision: ApprovalDecision::Deny,
                ..command.clone()
            },
            ResolveApprovalCommit {
                expected_subject_digest: sha256_digest(b"different subject"),
                ..command.clone()
            },
            ResolveApprovalCommit {
                approval_id: ApprovalId::new(),
                ..command.clone()
            },
        ] {
            assert_eq!(
                store.resolve_approval(conflicting),
                Err(EffectLedgerStoreError::Conflict)
            );
        }
        assert_eq!(
            store.resolve_approval(ResolveApprovalCommit {
                ownership: OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new()),
                ..command.clone()
            }),
            Err(EffectLedgerStoreError::NotFound)
        );
        for invalid_key in [String::new(), "x".repeat(257)] {
            assert!(matches!(
                store.resolve_approval(ResolveApprovalCommit {
                    idempotency_key: invalid_key,
                    ..command.clone()
                }),
                Err(EffectLedgerStoreError::InvalidEvidence(_))
            ));
        }

        store
            .connection
            .execute(
                "UPDATE effect_command_receipt SET cursor = cursor + 1 \
                 WHERE command_kind = 'approval_resolution'",
                [],
            )
            .expect_err("approval receipt update must be rejected");
        store
            .connection
            .execute(
                "DELETE FROM effect_command_receipt WHERE command_kind = 'approval_resolution'",
                [],
            )
            .expect_err("approval receipt delete must be rejected");
        store
            .connection
            .execute_batch("DROP TRIGGER effect_command_receipt_immutable_update")
            .expect("remove immutability guard for corruption test");
        store
            .connection
            .execute(
                "UPDATE effect_command_receipt SET request_digest = ?1 \
                 WHERE command_kind = 'approval_resolution'",
                [sha256_digest(b"forged receipt request")],
            )
            .expect("forge receipt below application boundary");
        assert!(matches!(
            store.resolve_approval(command),
            Err(EffectLedgerStoreError::InvariantViolation(_))
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn reconciliation_receipt_is_exact_owner_scoped_and_command_kind_scoped() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);

        let approval_effect_id = EffectId::new();
        let approval_effect = store
            .record_effect_proposal(proposal(
                graph,
                approval_effect_id,
                descriptor(
                    EffectClass::NonIdempotent,
                    IdempotencyClass::NonIdempotent,
                    RecoveryStrategy::Reconcile,
                ),
                PolicyDecision::RequireApproval,
            ))
            .expect("record approval effect for command-kind scope");
        let approval = approval_effect.approval.expect("pending approval");
        store
            .resolve_approval(ResolveApprovalCommit {
                approval_id: approval.approval_id,
                ownership: graph.ownership,
                expected_subject_digest: approval.subject_digest,
                decision: ApprovalDecision::Deny,
                idempotency_key: "shared-across-command-kinds".to_owned(),
                approval_event_id: EventId::new(),
                effect_event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                decided_at: time(NOW_MS + 5),
            })
            .expect("reserve key for approval command kind");

        let (effect_id, attempt_id, unknown_revision) = start_unknown_effect(&mut store, graph);
        let command = ReconcileEffectOutcomeCommit {
            effect_id,
            attempt_id,
            ownership: graph.ownership,
            expected_effect_revision: unknown_revision,
            outcome: EffectReconciliationOutcome::Succeeded,
            evidence_details: serde_json::json!({"externalReceiptId": "receipt-42"}),
            idempotency_key: "shared-across-command-kinds".to_owned(),
            event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            reconciled_at: time(NOW_MS + 40),
        };
        let first = store
            .reconcile_effect_outcome(command.clone())
            .expect("same key is independent for reconciliation kind");
        assert!(!first.duplicate);
        assert_eq!(first.effect_revision, unknown_revision + 1);
        let duplicate = store
            .reconcile_effect_outcome(ReconcileEffectOutcomeCommit {
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                reconciled_at: time(NOW_MS + 900),
                ..command.clone()
            })
            .expect("return original reconciliation receipt from terminal effect");
        assert_eq!(
            duplicate,
            mealy_application::EffectReconciliationReceipt {
                duplicate: true,
                ..first
            }
        );
        let recorded_cursor: i64 = store
            .connection
            .query_row(
                "SELECT cursor FROM timeline_event WHERE event_id = ?1",
                [first.event_id.to_string()],
                |row| row.get(0),
            )
            .expect("load original reconciliation cursor");
        assert_eq!(
            u64::try_from(recorded_cursor).expect("positive cursor"),
            first.cursor
        );

        for conflicting in [
            ReconcileEffectOutcomeCommit {
                outcome: EffectReconciliationOutcome::Failed,
                ..command.clone()
            },
            ReconcileEffectOutcomeCommit {
                evidence_details: serde_json::json!({"externalReceiptId": "different"}),
                ..command.clone()
            },
            ReconcileEffectOutcomeCommit {
                expected_effect_revision: unknown_revision + 1,
                ..command.clone()
            },
            ReconcileEffectOutcomeCommit {
                effect_id: EffectId::new(),
                ..command.clone()
            },
            ReconcileEffectOutcomeCommit {
                attempt_id: AttemptId::new(),
                ..command.clone()
            },
        ] {
            assert_eq!(
                store.reconcile_effect_outcome(conflicting),
                Err(EffectLedgerStoreError::Conflict)
            );
        }
        assert_eq!(
            store.reconcile_effect_outcome(ReconcileEffectOutcomeCommit {
                ownership: OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new()),
                ..command.clone()
            }),
            Err(EffectLedgerStoreError::NotFound)
        );
        store
            .connection
            .execute(
                "UPDATE effect_command_receipt SET cursor = cursor + 1 \
                 WHERE command_kind = 'effect_reconciliation'",
                [],
            )
            .expect_err("reconciliation receipt update must be rejected");
        store
            .connection
            .execute(
                "DELETE FROM effect_command_receipt \
                 WHERE command_kind = 'effect_reconciliation'",
                [],
            )
            .expect_err("reconciliation receipt delete must be rejected");
        store
            .connection
            .execute_batch("DROP TRIGGER effect_command_receipt_immutable_update")
            .expect("remove immutability guard for corruption test");
        store
            .connection
            .execute(
                "UPDATE effect_command_receipt SET request_digest = ?1 \
                 WHERE command_kind = 'effect_reconciliation'",
                [sha256_digest(b"forged reconciliation request")],
            )
            .expect("forge reconciliation receipt below application boundary");
        assert!(matches!(
            store.reconcile_effect_outcome(command),
            Err(EffectLedgerStoreError::InvariantViolation(_))
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v5_to_v6_upgrade_preserves_effect_graph_history_and_outcomes() {
        let path = std::env::temp_dir().join(format!("mealy-v5-{}.sqlite3", TaskId::new()));
        let (graph, effect_id, attempt_id, journal_count, outcome_count) = {
            let mut connection = Connection::open(&path).expect("create v5 store");
            connection
                .pragma_update(None, "foreign_keys", "ON")
                .expect("enable v5 foreign keys");
            let transaction = connection.transaction().expect("begin v5 setup");
            transaction
                .execute_batch(MIGRATION_0001)
                .expect("install v1 schema");
            ensure_initial_journal_envelope(&transaction).expect("extend journal envelope");
            transaction
                .execute(
                    "INSERT INTO schema_version(version, applied_at_ms) VALUES (1, ?1)",
                    [NOW_MS],
                )
                .expect("record v1 migration");
            transaction
                .execute_batch(MIGRATION_0002)
                .expect("install v2 schema");
            ensure_phase_one_run_columns(&transaction).expect("extend run claim fields");
            transaction
                .execute_batch(
                    "CREATE INDEX IF NOT EXISTS run_claim_order_idx \
                     ON run (status, next_attempt_at_ms, created_at_ms, id);",
                )
                .expect("install v2 run index");
            transaction
                .execute(
                    "INSERT INTO schema_version(version, applied_at_ms) VALUES (2, ?1)",
                    [NOW_MS],
                )
                .expect("record v2 migration");
            transaction
                .execute_batch(MIGRATION_0003)
                .expect("install v3 schema");
            transaction
                .execute(
                    "INSERT INTO schema_version(version, applied_at_ms) VALUES (3, ?1)",
                    [NOW_MS],
                )
                .expect("record v3 migration");
            transaction
                .execute_batch(MIGRATION_0004)
                .expect("install v4 schema");
            transaction
                .execute(
                    "INSERT INTO schema_version(version, applied_at_ms) VALUES (4, ?1)",
                    [NOW_MS],
                )
                .expect("record v4 migration");
            transaction
                .execute_batch(MIGRATION_0005)
                .expect("install v5 schema");
            transaction
                .execute(
                    "INSERT INTO schema_version(version, applied_at_ms) VALUES (5, ?1)",
                    [NOW_MS],
                )
                .expect("record v5 migration");
            transaction.commit().expect("commit exact v5 schema");
            let mut store = SqliteStore { connection };
            let graph = seed_graph(&store);
            let (effect_id, attempt_id, _) = start_unknown_effect(&mut store, graph);
            let journal_count: i64 = store
                .connection
                .query_row("SELECT COUNT(*) FROM journal_event", [], |row| row.get(0))
                .expect("count pre-upgrade journal");
            let outcome_count: i64 = store
                .connection
                .query_row("SELECT COUNT(*) FROM effect_outcome", [], |row| row.get(0))
                .expect("count pre-upgrade outcomes");
            (graph, effect_id, attempt_id, journal_count, outcome_count)
        };

        let store = SqliteStore::open(&path, NOW_MS + 1).expect("upgrade v5 store to v6");
        let effect = store
            .effect_ledger_view(graph.ownership, effect_id)
            .expect("load preserved effect");
        let attempt = store
            .effect_attempt_view(graph.ownership, attempt_id)
            .expect("load preserved attempt");
        assert_eq!(effect.status, EffectStatus::OutcomeUnknown);
        assert_eq!(attempt.state, EffectAttemptState::OutcomeUnknown);
        assert_eq!(attempt.outcomes.len(), 1);
        assert_eq!(attempt.outcomes[0].kind, EffectOutcomeKind::OutcomeUnknown);
        let preserved_counts: (i64, i64) = store
            .connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM journal_event), \
                        (SELECT COUNT(*) FROM effect_outcome)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("count preserved graph history");
        assert_eq!(preserved_counts, (journal_count, outcome_count));
        let version: i64 = store
            .connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .expect("load upgraded schema version");
        assert_eq!(version, LATEST_SCHEMA_VERSION);
        let receipt_table: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema \
                 WHERE type = 'table' AND name = 'effect_command_receipt'",
                [],
                |row| row.get(0),
            )
            .expect("find v6 receipt table");
        assert_eq!(receipt_table, 1);
        let foreign_key_violations: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .expect("check upgraded graph foreign keys");
        assert_eq!(foreign_key_violations, 0);
        drop(store);
        for suffix in ["", "-wal", "-shm"] {
            let mut sidecar = path.as_os_str().to_owned();
            sidecar.push(suffix);
            let _ = fs::remove_file(std::path::PathBuf::from(sidecar));
        }
    }

    #[test]
    fn schema_rejects_dispatch_without_preparation_and_duplicate_unsettled_work() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let graph = seed_graph(&store);
        let effect_id = EffectId::new();
        store
            .record_effect_proposal(proposal(
                graph,
                effect_id,
                descriptor(
                    EffectClass::NonIdempotent,
                    IdempotencyClass::NonIdempotent,
                    RecoveryStrategy::Reconcile,
                ),
                PolicyDecision::Allow,
            ))
            .expect("record authorized effect");
        store
            .connection
            .execute(
                "UPDATE effect SET status = 'dispatching' WHERE id = ?1",
                [effect_id.to_string()],
            )
            .expect_err("dispatching requires a durable prepared attempt");
        seed_attempt(
            &store,
            graph,
            effect_id,
            EffectAttemptBoundary::Running,
            NOW_MS + 100,
        );
        let second_attempt = AttemptId::new();
        let second_event = EventId::new();
        insert_attempt_event(
            &store,
            effect_id,
            second_event,
            "effect.attempt_prepared",
            NOW_MS + 200,
        );
        store
            .connection
            .execute(
                "INSERT INTO effect_attempt(\
                    attempt_id, effect_id, ordinal, state, prepared_lease_id, prepared_owner_id, \
                    prepared_fencing_token, prepared_event_id, prepared_at_ms\
                 ) VALUES (?1, ?2, 2, 'prepared', ?3, ?4, 1, ?5, ?6)",
                params![
                    second_attempt.to_string(),
                    effect_id.to_string(),
                    graph.lease_id.to_string(),
                    graph.worker_id.to_string(),
                    second_event.to_string(),
                    NOW_MS + 200,
                ],
            )
            .expect_err("an interrupted non-idempotent attempt blocks another dispatch");
    }
}
