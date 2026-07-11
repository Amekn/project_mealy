use super::SqliteStore;
use mealy_application::{
    InboxPromotionStore, InterruptionReceipt, OwnershipContext, PromotionCandidate,
    PromotionCommit, PromotionOutcome, PromotionReceipt, PromotionStoreError, SteeringReceipt,
    initial_task_contract, sha256_digest,
};
use mealy_domain::{
    ChannelBindingId, CorrelationId, DeliveryMode, EventId, PrincipalId, RiskClass, SessionId,
};
use rusqlite::{ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::{Value, json};
use std::{str::FromStr, time::SystemTime};

impl InboxPromotionStore for SqliteStore {
    fn pending_sessions(
        &self,
        limit: usize,
    ) -> Result<Vec<PromotionCandidate>, PromotionStoreError> {
        let limit = i64::try_from(limit)
            .map_err(|_| invariant("promotion candidate limit exceeds SQLite range"))?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT s.id, s.principal_id, s.channel_binding_id \
                 FROM session s \
                 JOIN session_inbox head ON head.inbox_entry_id = (\
                    SELECT i.inbox_entry_id FROM session_inbox i \
                    WHERE i.session_id = s.id AND i.state = 'pending' \
                    ORDER BY i.sequence LIMIT 1\
                 ) \
                 WHERE s.active_turn_id IS NULL \
                    OR head.delivery_mode = 'steer_at_boundary' \
                    OR (head.delivery_mode = 'interrupt_then_queue' \
                        AND head.interrupt_requested_at_ms IS NULL) \
                 ORDER BY head.sequence, s.id LIMIT ?1",
            )
            .map_err(map_sqlite_error)?;
        statement
            .query_map([limit], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(map_sqlite_error)?
            .map(|row| {
                let (session, principal, binding) = row.map_err(map_sqlite_error)?;
                Ok(PromotionCandidate {
                    session_id: parse_id::<SessionId>(&session, "session ID")?,
                    ownership: OwnershipContext::new(
                        parse_id::<PrincipalId>(&principal, "principal ID")?,
                        parse_id::<ChannelBindingId>(&binding, "channel binding ID")?,
                    ),
                })
            })
            .collect()
    }

    fn promote_next(
        &mut self,
        commit: PromotionCommit,
    ) -> Result<PromotionOutcome, PromotionStoreError> {
        let promoted_at_ms = epoch_milliseconds(commit.promoted_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let session = load_session(&transaction, commit.session_id)?;
        authorize(&session, &commit)?;
        let Some(pending) = load_pending_head(&transaction, commit.session_id)? else {
            return Ok(PromotionOutcome::InboxEmpty);
        };
        if let Some(active_turn_id) = &session.active_turn_id {
            let mode = parse_delivery_mode(&pending.delivery_mode)?;
            match mode {
                DeliveryMode::Queue => {
                    return Ok(PromotionOutcome::ActiveTurn {
                        turn_id: parse_id(active_turn_id, "active turn ID")?,
                        pending_mode: Some(mode),
                    });
                }
                DeliveryMode::SteerAtBoundary => {
                    let active = load_active(&transaction, active_turn_id)?;
                    let receipt = steer_active(
                        &transaction,
                        &commit,
                        &pending,
                        &session,
                        &active,
                        promoted_at_ms,
                    )?;
                    transaction.commit().map_err(map_sqlite_error)?;
                    return Ok(PromotionOutcome::Steered(receipt));
                }
                DeliveryMode::InterruptThenQueue => {
                    if pending.interrupt_requested_at_ms.is_some() {
                        return Ok(PromotionOutcome::ActiveTurn {
                            turn_id: parse_id(active_turn_id, "active turn ID")?,
                            pending_mode: Some(mode),
                        });
                    }
                    let active = load_active(&transaction, active_turn_id)?;
                    let receipt = interrupt_active(
                        &transaction,
                        &commit,
                        &pending,
                        &session,
                        &active,
                        promoted_at_ms,
                    )?;
                    transaction.commit().map_err(map_sqlite_error)?;
                    return Ok(PromotionOutcome::InterruptRequested(receipt));
                }
            }
        }

        insert_work_graph(&transaction, &commit, &pending, promoted_at_ms)?;
        update_session_and_inbox(&transaction, &commit, &pending, &session, promoted_at_ms)?;
        append_promotion_events(&transaction, &commit, &pending, promoted_at_ms)?;
        append_outbox(&transaction, &commit, &pending, promoted_at_ms)?;
        let cursor = high_cursor(&transaction)?;
        transaction.commit().map_err(map_sqlite_error)?;

        Ok(PromotionOutcome::Promoted(PromotionReceipt {
            session_id: commit.session_id,
            inbox_entry_id: parse_id(&pending.inbox_entry_id, "inbox entry ID")?,
            inbox_sequence: positive_u64(pending.sequence, "inbox sequence")?,
            delivery_mode: parse_delivery_mode(&pending.delivery_mode)?,
            turn_id: commit.turn_id,
            task_id: commit.task_id,
            run_id: commit.run_id,
            cursor,
        }))
    }
}

struct SessionRow {
    principal_id: String,
    channel_binding_id: String,
    active_turn_id: Option<String>,
    revision: i64,
}

struct PendingRow {
    inbox_entry_id: String,
    sequence: i64,
    delivery_mode: String,
    admission_event_id: String,
    correlation_id: String,
    content: String,
    interrupt_requested_at_ms: Option<i64>,
}

struct ActiveRow {
    turn_id: String,
    task_id: String,
    run_id: String,
    turn_revision: i64,
    task_revision: i64,
    run_revision: i64,
    task_status: String,
    run_status: String,
    current_fencing_token: i64,
}

fn load_session(
    transaction: &Transaction<'_>,
    session_id: SessionId,
) -> Result<SessionRow, PromotionStoreError> {
    transaction
        .query_row(
            "SELECT principal_id, channel_binding_id, active_turn_id, revision \
             FROM session WHERE id = ?1",
            [session_id.to_string()],
            |row| {
                Ok(SessionRow {
                    principal_id: row.get(0)?,
                    channel_binding_id: row.get(1)?,
                    active_turn_id: row.get(2)?,
                    revision: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(PromotionStoreError::SessionNotFound)
}

fn authorize(session: &SessionRow, commit: &PromotionCommit) -> Result<(), PromotionStoreError> {
    if session.principal_id == commit.ownership.principal_id().to_string()
        && session.channel_binding_id == commit.ownership.channel_binding_id().to_string()
    {
        Ok(())
    } else {
        Err(PromotionStoreError::Unauthorized)
    }
}

fn load_pending_head(
    transaction: &Transaction<'_>,
    session_id: SessionId,
) -> Result<Option<PendingRow>, PromotionStoreError> {
    transaction
        .query_row(
            "SELECT inbox_entry_id, sequence, delivery_mode, admission_event_id, correlation_id, \
                    content, interrupt_requested_at_ms \
             FROM session_inbox \
             WHERE session_id = ?1 AND state = 'pending' ORDER BY sequence LIMIT 1",
            [session_id.to_string()],
            |row| {
                Ok(PendingRow {
                    inbox_entry_id: row.get(0)?,
                    sequence: row.get(1)?,
                    delivery_mode: row.get(2)?,
                    admission_event_id: row.get(3)?,
                    correlation_id: row.get(4)?,
                    content: row.get(5)?,
                    interrupt_requested_at_ms: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)
}

fn load_active(
    transaction: &Transaction<'_>,
    turn_id: &str,
) -> Result<ActiveRow, PromotionStoreError> {
    transaction
        .query_row(
            "SELECT t.id, t.task_id, t.run_id, t.revision, task.revision, r.revision, \
                    task.status, r.status, r.current_fencing_token \
             FROM turn t \
             JOIN task ON task.id = t.task_id \
             JOIN run r ON r.id = t.run_id AND r.task_id = t.task_id \
             WHERE t.id = ?1 AND t.status = 'active'",
            [turn_id],
            |row| {
                Ok(ActiveRow {
                    turn_id: row.get(0)?,
                    task_id: row.get(1)?,
                    run_id: row.get(2)?,
                    turn_revision: row.get(3)?,
                    task_revision: row.get(4)?,
                    run_revision: row.get(5)?,
                    task_status: row.get(6)?,
                    run_status: row.get(7)?,
                    current_fencing_token: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or_else(|| invariant("session active turn graph is missing or terminal"))
}

#[allow(clippy::too_many_lines)]
fn steer_active(
    transaction: &Transaction<'_>,
    commit: &PromotionCommit,
    pending: &PendingRow,
    session: &SessionRow,
    active: &ActiveRow,
    promoted_at_ms: i64,
) -> Result<SteeringReceipt, PromotionStoreError> {
    if !matches!(active.run_status.as_str(), "queued" | "running" | "waiting") {
        return Err(invariant("steering target run is terminal"));
    }
    transaction
        .execute(
            "INSERT INTO run_input(\
                run_id, inbox_entry_id, inbox_sequence, state, attached_at_ms\
             ) VALUES (?1, ?2, ?3, 'pending', ?4)",
            params![
                active.run_id,
                pending.inbox_entry_id,
                pending.sequence,
                promoted_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    let inbox_changed = transaction
        .execute(
            "UPDATE session_inbox \
             SET state = 'promoted', promoted_at_ms = ?1, promoted_turn_id = ?2 \
             WHERE inbox_entry_id = ?3 AND session_id = ?4 AND state = 'pending'",
            params![
                promoted_at_ms,
                active.turn_id,
                pending.inbox_entry_id,
                commit.session_id.to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    let session_changed = transaction
        .execute(
            "UPDATE session SET revision = revision + 1, updated_at_ms = MAX(updated_at_ms, ?1) \
             WHERE id = ?2 AND active_turn_id = ?3 AND revision = ?4",
            params![
                promoted_at_ms,
                commit.session_id.to_string(),
                active.turn_id,
                session.revision,
            ],
        )
        .map_err(map_sqlite_error)?;
    if inbox_changed != 1 || session_changed != 1 {
        return Err(PromotionStoreError::Conflict);
    }

    let correlation_id: CorrelationId = parse_id(&pending.correlation_id, "correlation ID")?;
    let admission_event_id: EventId = parse_id(&pending.admission_event_id, "admission event ID")?;
    let session_id = commit.session_id.to_string();
    let session_sequence = next_aggregate_sequence(transaction, "session", &session_id)?;
    append_event(
        transaction,
        &EventAppend {
            event_id: commit.promotion_event_id,
            aggregate_kind: "session",
            aggregate_id: session_id.clone(),
            sequence: session_sequence,
            event_type: "input.steered",
            occurred_at_ms: promoted_at_ms,
            actor_principal_id: Some(commit.ownership.principal_id().to_string()),
            correlation_id,
            causation_id: Some(admission_event_id),
            payload: json!({
                "inbox_entry_id": pending.inbox_entry_id,
                "inbox_sequence": pending.sequence,
                "turn_id": active.turn_id,
                "run_id": active.run_id,
                "boundary": "next_safe_boundary",
            }),
        },
    )?;
    set_aggregate_sequence(transaction, "session", &session_id, session_sequence)?;
    let run_sequence = next_aggregate_sequence(transaction, "run", &active.run_id)?;
    append_event(
        transaction,
        &EventAppend {
            event_id: commit.run_event_id,
            aggregate_kind: "run",
            aggregate_id: active.run_id.clone(),
            sequence: run_sequence,
            event_type: "run.input_attached",
            occurred_at_ms: promoted_at_ms,
            actor_principal_id: Some(commit.ownership.principal_id().to_string()),
            correlation_id,
            causation_id: Some(commit.promotion_event_id),
            payload: json!({
                "inbox_entry_id": pending.inbox_entry_id,
                "inbox_sequence": pending.sequence,
            }),
        },
    )?;
    set_aggregate_sequence(transaction, "run", &active.run_id, run_sequence)?;
    append_active_outbox(
        transaction,
        commit,
        pending,
        active,
        "session.input_steered",
        promoted_at_ms,
    )?;
    Ok(SteeringReceipt {
        session_id: commit.session_id,
        inbox_entry_id: parse_id(&pending.inbox_entry_id, "inbox entry ID")?,
        inbox_sequence: positive_u64(pending.sequence, "inbox sequence")?,
        turn_id: parse_id(&active.turn_id, "turn ID")?,
        run_id: parse_id(&active.run_id, "run ID")?,
        cursor: high_cursor(transaction)?,
    })
}

#[allow(clippy::too_many_lines)]
fn interrupt_active(
    transaction: &Transaction<'_>,
    commit: &PromotionCommit,
    pending: &PendingRow,
    session: &SessionRow,
    active: &ActiveRow,
    promoted_at_ms: i64,
) -> Result<InterruptionReceipt, PromotionStoreError> {
    let inbox_changed = transaction
        .execute(
            "UPDATE session_inbox SET interrupt_requested_at_ms = ?1 \
             WHERE inbox_entry_id = ?2 AND session_id = ?3 AND state = 'pending' \
               AND interrupt_requested_at_ms IS NULL",
            params![
                promoted_at_ms,
                pending.inbox_entry_id,
                commit.session_id.to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    if inbox_changed != 1 {
        return Err(PromotionStoreError::Conflict);
    }
    let cancelled_before_claim = match (active.run_status.as_str(), active.task_status.as_str()) {
        ("queued", "queued") => {
            let next_token = active
                .current_fencing_token
                .checked_add(1)
                .ok_or_else(|| invariant("interrupt fencing token overflow"))?;
            let run_changed = transaction
                .execute(
                    "UPDATE run SET status = 'cancelled', revision = revision + 1, \
                                    current_fencing_token = ?1, cancellation_requested_at_ms = ?2, \
                                    updated_at_ms = ?2, completed_at_ms = ?2, \
                                    result_json = json_object('status', 'cancelled', \
                                                              'reason', 'interrupted_before_claim') \
                     WHERE id = ?3 AND status = 'queued' AND revision = ?4 \
                       AND current_fencing_token = ?5",
                    params![
                        next_token,
                        promoted_at_ms,
                        active.run_id,
                        active.run_revision,
                        active.current_fencing_token,
                    ],
                )
                .map_err(map_sqlite_error)?;
            let task_changed = transaction
                .execute(
                    "UPDATE task SET status = 'cancelled', revision = revision + 1 \
                     WHERE id = ?1 AND status = 'queued' AND revision = ?2",
                    params![active.task_id, active.task_revision],
                )
                .map_err(map_sqlite_error)?;
            let session_changed = transaction
                .execute(
                    "UPDATE session SET active_turn_id = NULL, revision = revision + 1, \
                                        updated_at_ms = MAX(updated_at_ms, ?1) \
                     WHERE id = ?2 AND active_turn_id = ?3 AND revision = ?4",
                    params![
                        promoted_at_ms,
                        commit.session_id.to_string(),
                        active.turn_id,
                        session.revision,
                    ],
                )
                .map_err(map_sqlite_error)?;
            let turn_changed = transaction
                .execute(
                    "UPDATE turn SET status = 'cancelled', revision = revision + 1, \
                                     completed_at_ms = ?1 \
                     WHERE id = ?2 AND status = 'active' AND revision = ?3",
                    params![promoted_at_ms, active.turn_id, active.turn_revision],
                )
                .map_err(map_sqlite_error)?;
            if [run_changed, task_changed, session_changed, turn_changed] != [1, 1, 1, 1] {
                return Err(PromotionStoreError::Conflict);
            }
            true
        }
        ("running", "running") => {
            let run_changed = transaction
                .execute(
                    "UPDATE run SET cancellation_requested_at_ms = ?1, revision = revision + 1, \
                                    updated_at_ms = MAX(updated_at_ms, ?1) \
                     WHERE id = ?2 AND status = 'running' AND revision = ?3 \
                       AND cancellation_requested_at_ms IS NULL",
                    params![promoted_at_ms, active.run_id, active.run_revision],
                )
                .map_err(map_sqlite_error)?;
            let task_changed = transaction
                .execute(
                    "UPDATE task SET status = 'cancelling', revision = revision + 1 \
                     WHERE id = ?1 AND status = 'running' AND revision = ?2",
                    params![active.task_id, active.task_revision],
                )
                .map_err(map_sqlite_error)?;
            let session_changed = transaction
                .execute(
                    "UPDATE session SET revision = revision + 1, \
                                        updated_at_ms = MAX(updated_at_ms, ?1) \
                     WHERE id = ?2 AND active_turn_id = ?3 AND revision = ?4",
                    params![
                        promoted_at_ms,
                        commit.session_id.to_string(),
                        active.turn_id,
                        session.revision,
                    ],
                )
                .map_err(map_sqlite_error)?;
            if [run_changed, task_changed, session_changed] != [1, 1, 1] {
                return Err(PromotionStoreError::Conflict);
            }
            false
        }
        _ => {
            return Err(invariant(
                "active turn cannot accept an interrupt in its current state",
            ));
        }
    };

    append_interrupt_events(
        transaction,
        commit,
        pending,
        active,
        promoted_at_ms,
        cancelled_before_claim,
    )?;
    append_active_outbox(
        transaction,
        commit,
        pending,
        active,
        "session.interrupt_requested",
        promoted_at_ms,
    )?;
    Ok(InterruptionReceipt {
        session_id: commit.session_id,
        inbox_entry_id: parse_id(&pending.inbox_entry_id, "inbox entry ID")?,
        inbox_sequence: positive_u64(pending.sequence, "inbox sequence")?,
        turn_id: parse_id(&active.turn_id, "turn ID")?,
        run_id: parse_id(&active.run_id, "run ID")?,
        cancelled_before_claim,
        cursor: high_cursor(transaction)?,
    })
}

fn append_interrupt_events(
    transaction: &Transaction<'_>,
    commit: &PromotionCommit,
    pending: &PendingRow,
    active: &ActiveRow,
    promoted_at_ms: i64,
    cancelled_before_claim: bool,
) -> Result<(), PromotionStoreError> {
    let correlation_id: CorrelationId = parse_id(&pending.correlation_id, "correlation ID")?;
    let admission_event_id: EventId = parse_id(&pending.admission_event_id, "admission event ID")?;
    let session_id = commit.session_id.to_string();
    let facts = [
        (
            commit.promotion_event_id,
            "session",
            session_id.as_str(),
            "input.interrupt_requested",
            Some(admission_event_id),
            json!({
                "inbox_entry_id": pending.inbox_entry_id,
                "inbox_sequence": pending.sequence,
                "turn_id": active.turn_id,
                "run_id": active.run_id,
                "cancelled_before_claim": cancelled_before_claim,
            }),
        ),
        (
            commit.task_event_id,
            "task",
            active.task_id.as_str(),
            if cancelled_before_claim {
                "task.cancelled"
            } else {
                "task.cancelling"
            },
            Some(commit.promotion_event_id),
            json!({ "run_id": active.run_id, "reason": "user_interrupt" }),
        ),
        (
            commit.run_event_id,
            "run",
            active.run_id.as_str(),
            if cancelled_before_claim {
                "run.cancelled"
            } else {
                "run.cancellation_requested"
            },
            Some(commit.task_event_id),
            json!({ "reason": "user_interrupt" }),
        ),
    ];
    for (event_id, kind, id, event_type, causation_id, payload) in facts {
        let sequence = next_aggregate_sequence(transaction, kind, id)?;
        append_event(
            transaction,
            &EventAppend {
                event_id,
                aggregate_kind: kind,
                aggregate_id: id.to_owned(),
                sequence,
                event_type,
                occurred_at_ms: promoted_at_ms,
                actor_principal_id: Some(commit.ownership.principal_id().to_string()),
                correlation_id,
                causation_id,
                payload,
            },
        )?;
        set_aggregate_sequence(transaction, kind, id, sequence)?;
    }
    Ok(())
}

fn append_active_outbox(
    transaction: &Transaction<'_>,
    commit: &PromotionCommit,
    pending: &PendingRow,
    active: &ActiveRow,
    topic: &str,
    created_at_ms: i64,
) -> Result<(), PromotionStoreError> {
    transaction
        .execute(
            "INSERT INTO outbox(outbox_id, topic, payload_json, created_at_ms) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                commit.outbox_id.to_string(),
                topic,
                json!({
                    "session_id": commit.session_id,
                    "inbox_entry_id": pending.inbox_entry_id,
                    "inbox_sequence": pending.sequence,
                    "turn_id": active.turn_id,
                    "task_id": active.task_id,
                    "run_id": active.run_id,
                })
                .to_string(),
                created_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn insert_work_graph(
    transaction: &Transaction<'_>,
    commit: &PromotionCommit,
    pending: &PendingRow,
    promoted_at_ms: i64,
) -> Result<(), PromotionStoreError> {
    let mut contract = initial_task_contract(&pending.content);
    contract.budget = commit.initial_budget;
    contract
        .budget
        .validate()
        .map_err(|_| invariant("initial agent budget is invalid"))?;
    contract
        .capability_ceiling
        .validate()
        .map_err(|_| invariant("initial capability ceiling is invalid"))?;
    contract
        .success_criteria
        .validate()
        .map_err(|_| invariant("initial success criteria are invalid"))?;
    let capability_ceiling_json = serde_json::to_string(&contract.capability_ceiling)
        .map_err(|_| invariant("initial capability ceiling cannot be serialized"))?;
    let budget_json = serde_json::to_string(&contract.budget)
        .map_err(|_| invariant("default agent budget cannot be serialized"))?;
    let criteria_json = serde_json::to_string(&contract.success_criteria.criteria)
        .map_err(|_| invariant("initial task criteria cannot be serialized"))?;
    let context_baseline_version = contract.context_baseline_version.clone();
    let validation_required =
        i64::from(contract.success_criteria.independent_validation_required());
    transaction
        .execute(
            "INSERT INTO task(id, status, revision, validation_required) \
             VALUES (?1, 'queued', 0, ?2)",
            params![commit.task_id.to_string(), validation_required],
        )
        .map_err(map_sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO task_success_criteria(\
                task_id, objective, criteria_json, criteria_digest, \
                no_objective_criteria_reason, risk_class, policy_version, created_at_ms\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                commit.task_id.to_string(),
                contract.success_criteria.objective,
                criteria_json,
                sha256_digest(criteria_json.as_bytes()),
                contract.success_criteria.no_objective_criteria_reason,
                risk_class_text(contract.success_criteria.risk_class),
                contract.success_criteria.policy_version,
                promoted_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO run(\
                id, task_id, status, revision, agent_role, capability_ceiling_json, budget_json, \
                correlation_id, created_at_ms, updated_at_ms, current_fencing_token\
             ) VALUES (?1, ?2, 'queued', 0, ?3, ?4, ?5, ?6, ?7, ?7, 0)",
            params![
                commit.run_id.to_string(),
                commit.task_id.to_string(),
                commit.initial_agent_role,
                capability_ceiling_json,
                budget_json,
                pending.correlation_id,
                promoted_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO run_lineage(\
                run_id, root_run_id, parent_run_id, depth, relation_kind, relation_id\
             ) VALUES (?1, ?1, NULL, 0, 'root', NULL)",
            [commit.run_id.to_string()],
        )
        .map_err(map_sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO turn(\
                id, session_id, inbox_entry_id, task_id, run_id, status, revision, correlation_id, \
                created_at_ms, context_epoch_id\
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'active', 0, ?6, ?7, \
                       (SELECT CASE WHEN epoch.baseline_version = ?8 \
                                    THEN session.current_context_epoch_id ELSE NULL END \
                        FROM session \
                        LEFT JOIN context_epoch epoch \
                          ON epoch.id = session.current_context_epoch_id \
                        WHERE session.id = ?2))",
            params![
                commit.turn_id.to_string(),
                commit.session_id.to_string(),
                pending.inbox_entry_id,
                commit.task_id.to_string(),
                commit.run_id.to_string(),
                pending.correlation_id,
                promoted_at_ms,
                context_baseline_version,
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

const fn risk_class_text(risk: RiskClass) -> &'static str {
    match risk {
        RiskClass::Low => "low",
        RiskClass::Medium => "medium",
        RiskClass::High => "high",
    }
}

fn update_session_and_inbox(
    transaction: &Transaction<'_>,
    commit: &PromotionCommit,
    pending: &PendingRow,
    session: &SessionRow,
    promoted_at_ms: i64,
) -> Result<(), PromotionStoreError> {
    let updated_inbox = transaction
        .execute(
            "UPDATE session_inbox \
             SET state = 'promoted', promoted_at_ms = ?1, promoted_turn_id = ?2 \
             WHERE inbox_entry_id = ?3 AND session_id = ?4 AND state = 'pending'",
            params![
                promoted_at_ms,
                commit.turn_id.to_string(),
                pending.inbox_entry_id,
                commit.session_id.to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    let next_revision = session
        .revision
        .checked_add(1)
        .ok_or_else(|| invariant("session revision overflow"))?;
    let updated_session = transaction
        .execute(
            "UPDATE session SET active_turn_id = ?1, revision = ?2, \
                                updated_at_ms = MAX(updated_at_ms, ?3) \
             WHERE id = ?4 AND active_turn_id IS NULL AND revision = ?5",
            params![
                commit.turn_id.to_string(),
                next_revision,
                promoted_at_ms,
                commit.session_id.to_string(),
                session.revision,
            ],
        )
        .map_err(map_sqlite_error)?;
    if updated_inbox == 1 && updated_session == 1 {
        Ok(())
    } else {
        Err(PromotionStoreError::Conflict)
    }
}

fn append_promotion_events(
    transaction: &Transaction<'_>,
    commit: &PromotionCommit,
    pending: &PendingRow,
    promoted_at_ms: i64,
) -> Result<(), PromotionStoreError> {
    let correlation_id: CorrelationId = parse_id(&pending.correlation_id, "correlation ID")?;
    let admission_event_id: EventId = parse_id(&pending.admission_event_id, "admission event ID")?;
    let session_sequence =
        next_aggregate_sequence(transaction, "session", &commit.session_id.to_string())?;
    append_event(
        transaction,
        &EventAppend {
            event_id: commit.promotion_event_id,
            aggregate_kind: "session",
            aggregate_id: commit.session_id.to_string(),
            sequence: session_sequence,
            event_type: "input.promoted",
            occurred_at_ms: promoted_at_ms,
            actor_principal_id: Some(commit.ownership.principal_id().to_string()),
            correlation_id,
            causation_id: Some(admission_event_id),
            payload: json!({
                "inbox_entry_id": pending.inbox_entry_id,
                "inbox_sequence": pending.sequence,
                "turn_id": commit.turn_id,
            }),
        },
    )?;
    set_aggregate_sequence(
        transaction,
        "session",
        &commit.session_id.to_string(),
        session_sequence,
    )?;

    append_event(
        transaction,
        &EventAppend {
            event_id: commit.task_event_id,
            aggregate_kind: "task",
            aggregate_id: commit.task_id.to_string(),
            sequence: 0,
            event_type: "task.created",
            occurred_at_ms: promoted_at_ms,
            actor_principal_id: Some(commit.ownership.principal_id().to_string()),
            correlation_id,
            causation_id: Some(commit.promotion_event_id),
            payload: json!({ "turn_id": commit.turn_id }),
        },
    )?;
    set_aggregate_sequence(transaction, "task", &commit.task_id.to_string(), 0)?;
    append_event(
        transaction,
        &EventAppend {
            event_id: commit.run_event_id,
            aggregate_kind: "run",
            aggregate_id: commit.run_id.to_string(),
            sequence: 0,
            event_type: "run.created",
            occurred_at_ms: promoted_at_ms,
            actor_principal_id: Some(commit.ownership.principal_id().to_string()),
            correlation_id,
            causation_id: Some(commit.task_event_id),
            payload: json!({
                "task_id": commit.task_id,
                "agent_role": commit.initial_agent_role,
            }),
        },
    )?;
    set_aggregate_sequence(transaction, "run", &commit.run_id.to_string(), 0)
}

struct EventAppend<'a> {
    event_id: EventId,
    aggregate_kind: &'a str,
    aggregate_id: String,
    sequence: i64,
    event_type: &'a str,
    occurred_at_ms: i64,
    actor_principal_id: Option<String>,
    correlation_id: CorrelationId,
    causation_id: Option<EventId>,
    payload: Value,
}

fn append_event(
    transaction: &Transaction<'_>,
    event: &EventAppend<'_>,
) -> Result<(), PromotionStoreError> {
    transaction
        .execute(
            "INSERT INTO journal_event(\
                event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                event_version, occurred_at_ms, actor_principal_id, correlation_id, causation_id, \
                sensitivity, payload_json\
             ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, ?9, 'private', ?10)",
            params![
                event.event_id.to_string(),
                event.aggregate_kind,
                event.aggregate_id,
                event.sequence,
                event.event_type,
                event.occurred_at_ms,
                event.actor_principal_id,
                event.correlation_id.to_string(),
                event.causation_id.map(|id| id.to_string()),
                event.payload.to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn next_aggregate_sequence(
    transaction: &Transaction<'_>,
    kind: &str,
    id: &str,
) -> Result<i64, PromotionStoreError> {
    transaction
        .query_row(
            "SELECT sequence FROM aggregate_sequence WHERE aggregate_kind = ?1 AND aggregate_id = ?2",
            params![kind, id],
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

fn set_aggregate_sequence(
    transaction: &Transaction<'_>,
    kind: &str,
    id: &str,
    sequence: i64,
) -> Result<(), PromotionStoreError> {
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

fn append_outbox(
    transaction: &Transaction<'_>,
    commit: &PromotionCommit,
    pending: &PendingRow,
    promoted_at_ms: i64,
) -> Result<(), PromotionStoreError> {
    transaction
        .execute(
            "INSERT INTO outbox(outbox_id, topic, payload_json, created_at_ms) \
             VALUES (?1, 'session.input_promoted', ?2, ?3)",
            params![
                commit.outbox_id.to_string(),
                json!({
                    "session_id": commit.session_id,
                    "inbox_entry_id": pending.inbox_entry_id,
                    "turn_id": commit.turn_id,
                    "task_id": commit.task_id,
                    "run_id": commit.run_id,
                })
                .to_string(),
                promoted_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn high_cursor(transaction: &Transaction<'_>) -> Result<u64, PromotionStoreError> {
    let value = transaction
        .query_row(
            "SELECT COALESCE(MAX(cursor), 0) FROM timeline_event",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(map_sqlite_error)?;
    u64::try_from(value).map_err(|_| invariant("timeline cursor is negative"))
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, PromotionStoreError> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invariant("application clock returned a time before the Unix epoch"))?;
    i64::try_from(duration.as_millis()).map_err(|_| invariant("timestamp exceeds SQLite range"))
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, PromotionStoreError> {
    value
        .parse()
        .map_err(|_| invariant(format!("stored {field} is invalid")))
}

fn positive_u64(value: i64, field: &str) -> Result<u64, PromotionStoreError> {
    let value =
        u64::try_from(value).map_err(|_| invariant(format!("stored {field} is negative")))?;
    if value == 0 {
        Err(invariant(format!("stored {field} is zero")))
    } else {
        Ok(value)
    }
}

fn parse_delivery_mode(value: &str) -> Result<DeliveryMode, PromotionStoreError> {
    match value {
        "queue" => Ok(DeliveryMode::Queue),
        "steer_at_boundary" => Ok(DeliveryMode::SteerAtBoundary),
        "interrupt_then_queue" => Ok(DeliveryMode::InterruptThenQueue),
        _ => Err(invariant("stored delivery mode is invalid")),
    }
}

fn map_sqlite_error(error: rusqlite::Error) -> PromotionStoreError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation =>
        {
            PromotionStoreError::Conflict
        }
        other => PromotionStoreError::Unavailable(other.to_string()),
    }
}

fn invariant(message: impl Into<String>) -> PromotionStoreError {
    PromotionStoreError::InvariantViolation(message.into())
}
