use super::{SqliteStore, agent};
use mealy_application::{
    AGENT_DELEGATE_TOOL_ID, AcquireResourceClaimCommit, AgentDelegationRequest, AgentLoopLimits,
    AgentStoreError, DELEGATION_CONTRACT_VERSION, DelegationStore, DelegationView,
    LaunchAgentDelegationCommit, OwnershipContext, PrepareDelegationCommit,
    RecordDelegationResultCommit, StartDelegationCommit, sha256_digest, validate_delegation_commit,
};
use mealy_domain::{CapabilityGrant, DelegationId, FencingToken, LeaseFence, RiskClass, RunId};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::{Value, json};
use std::str::FromStr;

impl DelegationStore for SqliteStore {
    fn prepare_delegation(
        &mut self,
        commit: PrepareDelegationCommit,
    ) -> Result<DelegationView, AgentStoreError> {
        validate_delegation_commit(&commit)?;
        let prepared_at_ms = agent::epoch_milliseconds(commit.prepared_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(agent::map_sqlite_error)?;
        let parent = load_parent(&transaction, commit.parent_fence, prepared_at_ms)?;
        insert_delegation_graph(&transaction, &commit, &parent, prepared_at_ms)?;
        let view = load_delegation_view(&transaction, None, commit.delegation_id)?;
        transaction.commit().map_err(agent::map_sqlite_error)?;
        Ok(view)
    }

    #[allow(clippy::too_many_lines)]
    fn launch_agent_delegation(
        &mut self,
        commit: LaunchAgentDelegationCommit,
    ) -> Result<DelegationView, AgentStoreError> {
        validate_delegation_commit(&commit.delegation)?;
        let launched_at_ms = agent::epoch_milliseconds(commit.delegation.prepared_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(agent::map_sqlite_error)?;
        let parent = load_parent(&transaction, commit.delegation.parent_fence, launched_at_ms)?;
        validate_agent_tool_origin(&transaction, &commit)?;
        let package_text = render_agent_child_package(&commit)?;
        insert_delegation_graph(&transaction, &commit.delegation, &parent, launched_at_ms)?;
        insert_delegated_turn(
            &transaction,
            &commit,
            &parent,
            &package_text,
            launched_at_ms,
        )?;
        park_parent_for_child(&transaction, &commit, &parent, launched_at_ms)?;
        let view = load_delegation_view(&transaction, None, commit.delegation.delegation_id)?;
        transaction.commit().map_err(agent::map_sqlite_error)?;
        Ok(view)
    }

    fn start_delegation(
        &mut self,
        commit: StartDelegationCommit,
    ) -> Result<LeaseFence, AgentStoreError> {
        let started_at_ms = agent::epoch_milliseconds(commit.started_at)?;
        let expires_at_ms = agent::epoch_milliseconds(commit.expires_at)?;
        if expires_at_ms <= started_at_ms {
            return Err(AgentStoreError::Conflict);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(agent::map_sqlite_error)?;
        let child = transaction
            .query_row(
                "SELECT child_run_id, child_task_id, run.current_fencing_token \
                 FROM delegation \
                 JOIN run ON run.id = delegation.child_run_id \
                 JOIN task ON task.id = delegation.child_task_id \
                 WHERE delegation.id = ?1 AND delegation.state = 'queued' \
                   AND run.status = 'queued' AND task.status = 'queued'",
                [commit.delegation_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(agent::map_sqlite_error)?
            .ok_or(AgentStoreError::Conflict)?;
        let token = child
            .2
            .checked_add(1)
            .ok_or_else(|| agent::invariant("child fencing token overflow"))?;
        transaction
            .execute(
                "INSERT INTO work_lease(\
                    lease_id, run_id, owner_id, fencing_token, state, acquired_at_ms, \
                    heartbeat_at_ms, expires_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?5, ?6)",
                params![
                    commit.lease_id.to_string(),
                    child.0,
                    commit.owner_id.to_string(),
                    token,
                    started_at_ms,
                    expires_at_ms,
                ],
            )
            .map_err(agent::map_sqlite_error)?;
        let run_changed = transaction
            .execute(
                "UPDATE run SET status = 'running', revision = revision + 1, \
                                current_fencing_token = ?1, updated_at_ms = ?2 \
                 WHERE id = ?3 AND status = 'queued' AND current_fencing_token = ?4",
                params![token, started_at_ms, child.0, child.2],
            )
            .map_err(agent::map_sqlite_error)?;
        let task_changed = transaction
            .execute(
                "UPDATE task SET status = 'running', revision = revision + 1 \
                 WHERE id = ?1 AND status = 'queued'",
                [child.1],
            )
            .map_err(agent::map_sqlite_error)?;
        let delegation_changed = transaction
            .execute(
                "UPDATE delegation SET state = 'running' WHERE id = ?1 AND state = 'queued'",
                [commit.delegation_id.to_string()],
            )
            .map_err(agent::map_sqlite_error)?;
        if [run_changed, task_changed, delegation_changed] != [1, 1, 1] {
            return Err(AgentStoreError::Conflict);
        }
        let run_id: RunId = parse_id(&child.0, "delegated child run ID")?;
        let fencing_token = FencingToken::new(
            u64::try_from(token).map_err(|_| agent::invariant("child token is negative"))?,
        )
        .ok_or_else(|| agent::invariant("child token is zero"))?;
        let fence = LeaseFence::new(commit.lease_id, run_id, commit.owner_id, fencing_token);
        agent::append_agent_event(
            &transaction,
            commit.event_id,
            "delegation",
            &commit.delegation_id.to_string(),
            "delegation.started",
            started_at_ms,
            commit.correlation_id,
            json!({
                "child_run_id": run_id,
                "lease_id": commit.lease_id,
                "owner_id": commit.owner_id,
                "fencing_token": fencing_token,
                "expires_at_ms": expires_at_ms,
            }),
        )?;
        transaction.commit().map_err(agent::map_sqlite_error)?;
        Ok(fence)
    }

    fn acquire_resource_claim(
        &mut self,
        commit: AcquireResourceClaimCommit,
    ) -> Result<(), AgentStoreError> {
        if commit.resource_key.is_empty()
            || commit.resource_key.len() > 1_024
            || commit.resource_key.trim() != commit.resource_key
            || commit.resource_key.chars().any(char::is_control)
        {
            return Err(AgentStoreError::Conflict);
        }
        let acquired_at_ms = agent::epoch_milliseconds(commit.acquired_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(agent::map_sqlite_error)?;
        let child = ensure_child_fence(
            &transaction,
            commit.delegation_id,
            commit.fence,
            acquired_at_ms,
        )?;
        let capabilities = serde_json::from_str::<CapabilityGrant>(&child.capabilities_json)
            .map_err(|_| agent::invariant("delegated child capabilities are invalid"))?;
        capabilities
            .validate()
            .map_err(|_| agent::invariant("delegated child capabilities are non-canonical"))?;
        if !resource_claim_authorized(&capabilities, commit.resource_class, &commit.resource_key) {
            return Err(AgentStoreError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO resource_claim(\
                    claim_id, run_id, delegation_id, resource_class, resource_key, state, \
                    lease_id, owner_id, fencing_token, acquired_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6, ?7, ?8, ?9)",
                params![
                    commit.claim_id.to_string(),
                    commit.fence.run_id().to_string(),
                    commit.delegation_id.to_string(),
                    commit.resource_class.as_str(),
                    commit.resource_key,
                    commit.fence.lease_id().to_string(),
                    commit.fence.owner_id().to_string(),
                    i64::try_from(commit.fence.fencing_token().get())
                        .map_err(|_| agent::invariant("claim token exceeds SQLite range"))?,
                    acquired_at_ms,
                ],
            )
            .map_err(agent::map_sqlite_error)?;
        agent::append_agent_event(
            &transaction,
            commit.event_id,
            "resource_claim",
            &commit.claim_id.to_string(),
            "resource_claim.acquired",
            acquired_at_ms,
            commit.correlation_id,
            json!({
                "delegation_id": commit.delegation_id,
                "run_id": commit.fence.run_id(),
                "resource_class": commit.resource_class,
                "resource_key": commit.resource_key,
                "fencing_token": commit.fence.fencing_token(),
            }),
        )?;
        transaction.commit().map_err(agent::map_sqlite_error)
    }

    #[allow(clippy::too_many_lines)]
    fn record_delegation_result(
        &mut self,
        commit: RecordDelegationResultCommit,
    ) -> Result<DelegationView, AgentStoreError> {
        let result_json = canonical_object(&commit.result, "delegation result")?;
        if result_json.len() > 262_144 {
            return Err(AgentStoreError::Conflict);
        }
        let completed_at_ms = agent::epoch_milliseconds(commit.completed_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(agent::map_sqlite_error)?;
        let child = ensure_child_fence(
            &transaction,
            commit.delegation_id,
            commit.child_fence,
            completed_at_ms,
        )?;
        let status = if commit.succeeded {
            "succeeded"
        } else {
            "failed"
        };
        let token = i64::try_from(commit.child_fence.fencing_token().get())
            .map_err(|_| agent::invariant("child result token exceeds SQLite range"))?;
        transaction
            .execute(
                "UPDATE resource_claim SET state = 'released', released_at_ms = ?1 \
                 WHERE delegation_id = ?2 AND run_id = ?3 AND state = 'active' \
                   AND lease_id = ?4 AND owner_id = ?5 AND fencing_token = ?6",
                params![
                    completed_at_ms,
                    commit.delegation_id.to_string(),
                    commit.child_fence.run_id().to_string(),
                    commit.child_fence.lease_id().to_string(),
                    commit.child_fence.owner_id().to_string(),
                    token,
                ],
            )
            .map_err(agent::map_sqlite_error)?;
        let lease_changed = transaction
            .execute(
                "UPDATE work_lease SET state = 'released', released_at_ms = ?1 \
                 WHERE lease_id = ?2 AND run_id = ?3 AND owner_id = ?4 AND fencing_token = ?5 \
                   AND state = 'active' AND ?1 < expires_at_ms",
                params![
                    completed_at_ms,
                    commit.child_fence.lease_id().to_string(),
                    commit.child_fence.run_id().to_string(),
                    commit.child_fence.owner_id().to_string(),
                    token,
                ],
            )
            .map_err(agent::map_sqlite_error)?;
        let run_changed = transaction
            .execute(
                "UPDATE run SET status = ?1, revision = revision + 1, updated_at_ms = ?2, \
                                completed_at_ms = ?2 \
                 WHERE id = ?3 AND status = 'running' AND current_fencing_token = ?4",
                params![
                    status,
                    completed_at_ms,
                    commit.child_fence.run_id().to_string(),
                    token,
                ],
            )
            .map_err(agent::map_sqlite_error)?;
        let task_changed = transaction
            .execute(
                "UPDATE task SET status = ?1, revision = revision + 1 \
                 WHERE id = (SELECT child_task_id FROM delegation WHERE id = ?2) \
                   AND status = 'running'",
                params![status, commit.delegation_id.to_string()],
            )
            .map_err(agent::map_sqlite_error)?;
        let delegation_changed = transaction
            .execute(
                "UPDATE delegation SET state = ?1, result_json = ?2, result_digest = ?3, \
                                       result_fencing_token = ?4, completed_at_ms = ?5 \
                 WHERE id = ?6 AND state = 'running' AND child_run_id = ?7",
                params![
                    status,
                    result_json,
                    sha256_digest(result_json.as_bytes()),
                    token,
                    completed_at_ms,
                    commit.delegation_id.to_string(),
                    commit.child_fence.run_id().to_string(),
                ],
            )
            .map_err(agent::map_sqlite_error)?;
        let budget_changed = transaction
            .execute(
                "UPDATE run_budget_usage SET revision = revision + 1, \
                    reserved_delegated_runs = reserved_delegated_runs - 1, \
                    used_delegated_runs = used_delegated_runs + 1 \
                 WHERE run_id = ?1 AND reserved_delegated_runs >= 1",
                [child.parent_run_id],
            )
            .map_err(agent::map_sqlite_error)?;
        if [
            lease_changed,
            run_changed,
            task_changed,
            delegation_changed,
            budget_changed,
        ] != [1, 1, 1, 1, 1]
        {
            return Err(AgentStoreError::Conflict);
        }
        agent::append_agent_event(
            &transaction,
            commit.event_id,
            "delegation",
            &commit.delegation_id.to_string(),
            if commit.succeeded {
                "delegation.succeeded"
            } else {
                "delegation.failed"
            },
            completed_at_ms,
            commit.correlation_id,
            json!({
                "child_run_id": commit.child_fence.run_id(),
                "fencing_token": commit.child_fence.fencing_token(),
                "result_digest": sha256_digest(result_json.as_bytes()),
                "status": status,
            }),
        )?;
        let view = load_delegation_view(&transaction, None, commit.delegation_id)?;
        transaction.commit().map_err(agent::map_sqlite_error)?;
        Ok(view)
    }

    fn delegation(
        &self,
        ownership: OwnershipContext,
        delegation_id: DelegationId,
    ) -> Result<DelegationView, AgentStoreError> {
        load_delegation_view(&self.connection, Some(ownership), delegation_id)
    }

    fn delegations(
        &self,
        ownership: OwnershipContext,
        limit: usize,
    ) -> Result<Vec<DelegationView>, AgentStoreError> {
        if !(1..=100).contains(&limit) {
            return Err(agent::invariant(
                "delegation list limit must be between 1 and 100",
            ));
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT delegation.id FROM delegation \
                 JOIN run parent ON parent.id = delegation.parent_run_id \
                 JOIN turn ON turn.run_id = parent.id AND turn.task_id = parent.task_id \
                 JOIN session ON session.id = turn.session_id \
                 WHERE session.principal_id = ?1 AND session.channel_binding_id = ?2 \
                 ORDER BY delegation.created_at_ms DESC, delegation.id DESC LIMIT ?3",
            )
            .map_err(agent::map_sqlite_error)?;
        let ids = statement
            .query_map(
                params![
                    ownership.principal_id().to_string(),
                    ownership.channel_binding_id().to_string(),
                    i64::try_from(limit)
                        .map_err(|_| agent::invariant("delegation list limit exceeds SQLite"))?,
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(agent::map_sqlite_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(agent::map_sqlite_error)?;
        ids.into_iter()
            .map(|id| {
                load_delegation_view(
                    &self.connection,
                    Some(ownership),
                    parse_id(&id, "delegation ID")?,
                )
            })
            .collect()
    }
}

#[allow(clippy::too_many_lines)]
fn insert_delegation_graph(
    transaction: &Transaction<'_>,
    commit: &PrepareDelegationCommit,
    parent: &ParentEvidence,
    prepared_at_ms: i64,
) -> Result<(), AgentStoreError> {
    let parent_capabilities = serde_json::from_str::<CapabilityGrant>(&parent.capabilities_json)
        .map_err(|_| agent::invariant("parent capability ceiling is invalid"))?;
    parent_capabilities
        .validate()
        .map_err(|_| agent::invariant("parent capability ceiling is not canonical"))?;
    if parent_capabilities.maximum_delegated_runs == 0 {
        return Err(AgentStoreError::BudgetExceeded(
            "parent run has no delegation authority".to_owned(),
        ));
    }
    let effective = parent_capabilities
        .intersect_for_child(&commit.requested_capabilities, &commit.policy_capabilities);
    if !parent_capabilities.contains(&effective)
        || !commit.requested_capabilities.contains(&effective)
        || !commit.policy_capabilities.contains(&effective)
    {
        return Err(agent::invariant(
            "effective child capabilities are not a strict intersection",
        ));
    }
    let budget_changed = transaction
        .execute(
            "UPDATE run_budget_usage SET revision = revision + 1, \
                reserved_delegated_runs = reserved_delegated_runs + 1 \
             WHERE run_id = ?1 AND cancellation_requested_at_ms IS NULL \
               AND used_delegated_runs + reserved_delegated_runs + 1 \
                   <= maximum_delegated_runs",
            [commit.parent_fence.run_id().to_string()],
        )
        .map_err(agent::map_sqlite_error)?;
    if budget_changed != 1 {
        return Err(AgentStoreError::BudgetExceeded(
            "delegated run exceeds the effective parent limit".to_owned(),
        ));
    }

    let work_order_json = canonical_object(&commit.work_order, "delegation work order")?;
    let success_criteria_json = serde_json::to_string(&commit.success_criteria)
        .map_err(|_| agent::invariant("delegation criteria cannot be serialized"))?;
    let criteria_items_json = serde_json::to_string(&commit.success_criteria.criteria)
        .map_err(|_| agent::invariant("delegation criteria items cannot be serialized"))?;
    let context_package_json =
        canonical_object(&commit.context_package, "delegation context package")?;
    let requested_capabilities_json = serde_json::to_string(&commit.requested_capabilities)
        .map_err(|_| agent::invariant("requested capabilities cannot be serialized"))?;
    let effective_capabilities_json = serde_json::to_string(&effective)
        .map_err(|_| agent::invariant("effective capabilities cannot be serialized"))?;
    let child_budget_json = serde_json::to_string(&commit.child_budget)
        .map_err(|_| agent::invariant("child budget cannot be serialized"))?;
    let ordinal = transaction
        .query_row(
            "SELECT COALESCE(MAX(ordinal), 0) + 1 FROM delegation WHERE parent_run_id = ?1",
            [commit.parent_fence.run_id().to_string()],
            |row| row.get::<_, i64>(0),
        )
        .map_err(agent::map_sqlite_error)?;
    let validation_required = i64::from(commit.success_criteria.independent_validation_required());
    transaction
        .execute(
            "INSERT INTO task(\
                id, status, revision, validation_required, parent_task_id\
             ) VALUES (?1, 'queued', 0, ?2, ?3)",
            params![
                commit.child_task_id.to_string(),
                validation_required,
                parent.task_id,
            ],
        )
        .map_err(agent::map_sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO task_success_criteria(\
                task_id, objective, criteria_json, criteria_digest, \
                no_objective_criteria_reason, risk_class, policy_version, created_at_ms\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                commit.child_task_id.to_string(),
                commit.success_criteria.objective,
                criteria_items_json,
                sha256_digest(criteria_items_json.as_bytes()),
                commit.success_criteria.no_objective_criteria_reason,
                risk_class_text(commit.success_criteria.risk_class),
                commit.success_criteria.policy_version,
                prepared_at_ms,
            ],
        )
        .map_err(agent::map_sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO run(\
                id, task_id, parent_run_id, status, revision, agent_role, \
                capability_ceiling_json, budget_json, correlation_id, created_at_ms, \
                updated_at_ms, current_fencing_token\
             ) VALUES (?1, ?2, ?3, 'queued', 0, 'delegate', ?4, ?5, ?6, ?7, ?7, 0)",
            params![
                commit.child_run_id.to_string(),
                commit.child_task_id.to_string(),
                commit.parent_fence.run_id().to_string(),
                effective_capabilities_json,
                child_budget_json,
                parent.correlation_id,
                prepared_at_ms,
            ],
        )
        .map_err(agent::map_sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO delegation(\
                id, parent_run_id, child_task_id, child_run_id, ordinal, \
                parent_fencing_token, work_order_json, work_order_digest, \
                success_criteria_json, success_criteria_digest, context_package_json, \
                context_package_digest, requested_capabilities_json, \
                effective_capabilities_json, effective_capabilities_digest, budget_json, \
                budget_digest, state, created_at_ms\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                       ?15, ?16, ?17, 'queued', ?18)",
            params![
                commit.delegation_id.to_string(),
                commit.parent_fence.run_id().to_string(),
                commit.child_task_id.to_string(),
                commit.child_run_id.to_string(),
                ordinal,
                i64::try_from(commit.parent_fence.fencing_token().get()).map_err(|_| {
                    agent::invariant("parent delegation token exceeds SQLite range")
                })?,
                work_order_json,
                sha256_digest(work_order_json.as_bytes()),
                success_criteria_json,
                sha256_digest(success_criteria_json.as_bytes()),
                context_package_json,
                sha256_digest(context_package_json.as_bytes()),
                requested_capabilities_json,
                effective_capabilities_json,
                sha256_digest(effective_capabilities_json.as_bytes()),
                child_budget_json,
                sha256_digest(child_budget_json.as_bytes()),
                prepared_at_ms,
            ],
        )
        .map_err(agent::map_sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO run_lineage(\
                run_id, root_run_id, parent_run_id, depth, relation_kind, relation_id\
             ) VALUES (?1, ?2, ?3, ?4, 'delegation', ?5)",
            params![
                commit.child_run_id.to_string(),
                parent.root_run_id,
                commit.parent_fence.run_id().to_string(),
                parent.depth + 1,
                commit.delegation_id.to_string(),
            ],
        )
        .map_err(agent::map_sqlite_error)?;
    agent::append_agent_event(
        transaction,
        commit.event_id,
        "delegation",
        &commit.delegation_id.to_string(),
        "delegation.prepared",
        prepared_at_ms,
        parse_id(&parent.correlation_id, "delegation correlation ID")?,
        json!({
            "parent_run_id": commit.parent_fence.run_id(),
            "child_task_id": commit.child_task_id,
            "child_run_id": commit.child_run_id,
            "work_order_digest": sha256_digest(work_order_json.as_bytes()),
            "success_criteria_digest": sha256_digest(success_criteria_json.as_bytes()),
            "context_package_digest": sha256_digest(context_package_json.as_bytes()),
            "effective_capabilities_digest": sha256_digest(effective_capabilities_json.as_bytes()),
            "budget_digest": sha256_digest(child_budget_json.as_bytes()),
        }),
    )
}

fn validate_agent_tool_origin(
    transaction: &Transaction<'_>,
    commit: &LaunchAgentDelegationCommit,
) -> Result<(), AgentStoreError> {
    let fence = commit.delegation.parent_fence;
    let token = i64::try_from(fence.fencing_token().get())
        .map_err(|_| agent::invariant("parent tool token exceeds SQLite range"))?;
    let arguments_json = transaction
        .query_row(
            "SELECT tool.arguments_json FROM tool_call tool \
             JOIN run_loop_state loop ON loop.run_id = tool.run_id \
             WHERE tool.tool_call_id = ?1 AND tool.run_id = ?2 \
               AND tool.tool_id = ?3 AND tool.state = 'prepared' \
               AND tool.prepared_lease_id = ?4 AND tool.prepared_owner_id = ?5 \
               AND tool.prepared_fencing_token = ?6 \
               AND loop.next_action = 'dispatch_read_tool' \
               AND loop.current_tool_call_id = tool.tool_call_id",
            params![
                commit.parent_tool_call_id.to_string(),
                fence.run_id().to_string(),
                AGENT_DELEGATE_TOOL_ID,
                fence.lease_id().to_string(),
                fence.owner_id().to_string(),
                token,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(agent::map_sqlite_error)?
        .ok_or(AgentStoreError::Conflict)?;
    let arguments = serde_json::from_str::<Value>(&arguments_json)
        .map_err(|_| agent::invariant("stored delegation arguments are invalid"))?;
    if serde_json::to_string(&arguments).ok().as_deref() != Some(arguments_json.as_str()) {
        return Err(agent::invariant(
            "stored delegation arguments are not canonical",
        ));
    }
    let request = AgentDelegationRequest::from_arguments(&arguments)?;
    let expected_work_order = json!({
        "contractVersion": DELEGATION_CONTRACT_VERSION,
        "objective": request.objective,
        "instructions": request.instructions,
        "parentToolCallId": commit.parent_tool_call_id,
    });
    let expected_context = json!({
        "contractVersion": DELEGATION_CONTRACT_VERSION,
        "parentToolCallId": commit.parent_tool_call_id,
        "context": request.context.unwrap_or_else(|| json!({"provided": false})),
    });
    let criteria_match = commit.delegation.success_criteria.objective
        == expected_work_order["objective"]
            .as_str()
            .unwrap_or_default()
        && commit.delegation.success_criteria.criteria.len() == request.success_criteria.len()
        && commit
            .delegation
            .success_criteria
            .criteria
            .iter()
            .zip(request.success_criteria)
            .all(|(criterion, requirement)| criterion.requirement == requirement);
    if commit.delegation.work_order != expected_work_order
        || commit.delegation.context_package != expected_context
        || !criteria_match
    {
        return Err(agent::invariant(
            "agent delegation contract differs from the committed model tool call",
        ));
    }
    Ok(())
}

fn render_agent_child_package(
    commit: &LaunchAgentDelegationCommit,
) -> Result<String, AgentStoreError> {
    let content = format!(
        "[ISOLATED DELEGATED WORK PACKAGE — use only this explicit package and declared tools; \
         do not infer or request the parent's hidden conversation]\n{}",
        json!({
            "contractVersion": DELEGATION_CONTRACT_VERSION,
            "delegationId": commit.delegation.delegation_id,
            "workOrder": commit.delegation.work_order,
            "successCriteria": commit.delegation.success_criteria,
            "contextPackage": commit.delegation.context_package,
        })
    );
    if content.len() > 240 * 1024 || content.chars().any(|character| character == '\0') {
        return Err(agent::invariant(
            "rendered delegated work package exceeds the isolated context bound",
        ));
    }
    Ok(content)
}

fn insert_delegated_turn(
    transaction: &Transaction<'_>,
    commit: &LaunchAgentDelegationCommit,
    parent: &ParentEvidence,
    package_text: &str,
    launched_at_ms: i64,
) -> Result<(), AgentStoreError> {
    let next_sequence = parent
        .next_inbox_sequence
        .checked_add(1)
        .ok_or_else(|| agent::invariant("delegated inbox sequence overflow"))?;
    transaction
        .execute(
            "INSERT INTO session_inbox(\
                inbox_entry_id, session_id, sequence, dedupe_key, delivery_mode, state, content, \
                admission_event_id, acknowledgement_outbox_id, correlation_id, accepted_at_ms\
             ) VALUES (?1, ?2, ?3, ?4, 'queue', 'pending', ?5, ?6, ?7, ?8, ?9)",
            params![
                commit.child_inbox_entry_id.to_string(),
                parent.session_id,
                parent.next_inbox_sequence,
                format!("delegation:{}", commit.delegation.delegation_id),
                package_text,
                commit.delegation.event_id.to_string(),
                commit.child_acknowledgement_outbox_id.to_string(),
                parent.correlation_id,
                launched_at_ms,
            ],
        )
        .map_err(agent::map_sqlite_error)?;
    let session_changed = transaction
        .execute(
            "UPDATE session SET next_inbox_sequence = ?1, revision = revision + 1, \
                                updated_at_ms = MAX(updated_at_ms, ?2) \
             WHERE id = ?3 AND next_inbox_sequence = ?4 AND active_turn_id = ?5",
            params![
                next_sequence,
                launched_at_ms,
                parent.session_id,
                parent.next_inbox_sequence,
                parent.turn_id,
            ],
        )
        .map_err(agent::map_sqlite_error)?;
    if session_changed != 1 {
        return Err(AgentStoreError::Conflict);
    }
    transaction
        .execute(
            "INSERT INTO turn(\
                id, session_id, inbox_entry_id, task_id, run_id, status, revision, \
                correlation_id, created_at_ms, context_epoch_id, turn_kind\
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'active', 0, ?6, ?7, ?8, 'delegated')",
            params![
                commit.child_turn_id.to_string(),
                parent.session_id,
                commit.child_inbox_entry_id.to_string(),
                commit.delegation.child_task_id.to_string(),
                commit.delegation.child_run_id.to_string(),
                parent.correlation_id,
                launched_at_ms,
                Option::<String>::None,
            ],
        )
        .map_err(agent::map_sqlite_error)?;
    let inbox_changed = transaction
        .execute(
            "UPDATE session_inbox SET state = 'promoted', promoted_at_ms = ?1, \
                                      promoted_turn_id = ?2 \
             WHERE inbox_entry_id = ?3 AND session_id = ?4 AND state = 'pending'",
            params![
                launched_at_ms,
                commit.child_turn_id.to_string(),
                commit.child_inbox_entry_id.to_string(),
                parent.session_id,
            ],
        )
        .map_err(agent::map_sqlite_error)?;
    if inbox_changed != 1 {
        return Err(AgentStoreError::Conflict);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn park_parent_for_child(
    transaction: &Transaction<'_>,
    commit: &LaunchAgentDelegationCommit,
    parent: &ParentEvidence,
    launched_at_ms: i64,
) -> Result<(), AgentStoreError> {
    let fence = commit.delegation.parent_fence;
    let token = i64::try_from(fence.fencing_token().get())
        .map_err(|_| agent::invariant("parent delegation token exceeds SQLite range"))?;
    let next_token = token
        .checked_add(1)
        .ok_or_else(|| agent::invariant("parent delegation token overflow"))?;
    let tool_changed = transaction
        .execute(
            "UPDATE tool_call SET state = 'running', started_at_ms = ?1 \
             WHERE tool_call_id = ?2 AND run_id = ?3 AND state = 'prepared' \
               AND prepared_lease_id = ?4 AND prepared_owner_id = ?5 \
               AND prepared_fencing_token = ?6 \
               AND EXISTS(SELECT 1 FROM run_loop_state \
                          WHERE run_id = ?3 AND next_action = 'dispatch_read_tool' \
                            AND current_tool_call_id = ?2)",
            params![
                launched_at_ms,
                commit.parent_tool_call_id.to_string(),
                fence.run_id().to_string(),
                fence.lease_id().to_string(),
                fence.owner_id().to_string(),
                token,
            ],
        )
        .map_err(agent::map_sqlite_error)?;
    let lease_changed = transaction
        .execute(
            "UPDATE work_lease SET state = 'released', released_at_ms = ?1 \
             WHERE lease_id = ?2 AND run_id = ?3 AND owner_id = ?4 AND fencing_token = ?5 \
               AND state = 'active' AND ?1 < expires_at_ms",
            params![
                launched_at_ms,
                fence.lease_id().to_string(),
                fence.run_id().to_string(),
                fence.owner_id().to_string(),
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
                launched_at_ms,
                fence.run_id().to_string(),
                parent.task_id,
                token,
            ],
        )
        .map_err(agent::map_sqlite_error)?;
    let task_changed = transaction
        .execute(
            "UPDATE task SET status = 'waiting', revision = revision + 1 \
             WHERE id = ?1 AND status = 'running'",
            [parent.task_id.as_str()],
        )
        .map_err(agent::map_sqlite_error)?;
    if [tool_changed, lease_changed, run_changed, task_changed] != [1, 1, 1, 1] {
        return Err(AgentStoreError::StaleFence);
    }
    let correlation_id = parse_id(&parent.correlation_id, "delegation correlation ID")?;
    agent::append_agent_event(
        transaction,
        commit.tool_event_id,
        "tool_call",
        &commit.parent_tool_call_id.to_string(),
        "tool.call.started",
        launched_at_ms,
        correlation_id,
        json!({"run_id": fence.run_id()}),
    )?;
    agent::append_agent_event(
        transaction,
        commit.lease_event_id,
        "lease",
        &fence.lease_id().to_string(),
        "lease.released_for_delegation",
        launched_at_ms,
        correlation_id,
        json!({
            "delegation_id": commit.delegation.delegation_id,
            "invalidated_fencing_token": token,
            "current_fencing_token": next_token,
        }),
    )?;
    agent::append_agent_event(
        transaction,
        commit.parent_run_event_id,
        "run",
        &fence.run_id().to_string(),
        "run.waiting_for_delegation",
        launched_at_ms,
        correlation_id,
        json!({
            "delegation_id": commit.delegation.delegation_id,
            "child_run_id": commit.delegation.child_run_id,
        }),
    )?;
    agent::append_agent_event(
        transaction,
        commit.parent_task_event_id,
        "task",
        &parent.task_id,
        "task.waiting_for_delegation",
        launched_at_ms,
        correlation_id,
        json!({
            "delegation_id": commit.delegation.delegation_id,
            "run_id": fence.run_id(),
        }),
    )
}

struct ParentEvidence {
    task_id: String,
    capabilities_json: String,
    correlation_id: String,
    root_run_id: String,
    depth: i64,
    session_id: String,
    turn_id: String,
    next_inbox_sequence: i64,
}

fn load_parent(
    transaction: &Transaction<'_>,
    fence: LeaseFence,
    observed_at_ms: i64,
) -> Result<ParentEvidence, AgentStoreError> {
    let token = i64::try_from(fence.fencing_token().get())
        .map_err(|_| agent::invariant("parent fencing token exceeds SQLite range"))?;
    transaction
        .query_row(
            "SELECT run.task_id, run.capability_ceiling_json, run.correlation_id, \
                    lineage.root_run_id, lineage.depth, turn.session_id, turn.id, \
                    session.next_inbox_sequence \
             FROM run \
             JOIN task ON task.id = run.task_id \
             JOIN turn ON turn.run_id = run.id AND turn.task_id = run.task_id \
                       AND turn.turn_kind = 'canonical' AND turn.status = 'active' \
             JOIN session ON session.id = turn.session_id AND session.active_turn_id = turn.id \
             JOIN work_lease lease ON lease.run_id = run.id \
             JOIN run_lineage lineage ON lineage.run_id = run.id \
             WHERE run.id = ?1 AND run.status = 'running' AND task.status = 'running' \
               AND run.current_fencing_token = ?2 AND run.cancellation_requested_at_ms IS NULL \
               AND lease.lease_id = ?3 AND lease.owner_id = ?4 AND lease.fencing_token = ?2 \
               AND lease.state = 'active' AND lease.acquired_at_ms <= ?5 AND ?5 < lease.expires_at_ms",
            params![
                fence.run_id().to_string(),
                token,
                fence.lease_id().to_string(),
                fence.owner_id().to_string(),
                observed_at_ms,
            ],
            |row| {
                Ok(ParentEvidence {
                    task_id: row.get(0)?,
                    capabilities_json: row.get(1)?,
                    correlation_id: row.get(2)?,
                    root_run_id: row.get(3)?,
                    depth: row.get(4)?,
                    session_id: row.get(5)?,
                    turn_id: row.get(6)?,
                    next_inbox_sequence: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(agent::map_sqlite_error)?
        .ok_or(AgentStoreError::StaleFence)
}

fn ensure_child_fence(
    transaction: &Transaction<'_>,
    delegation_id: DelegationId,
    fence: LeaseFence,
    observed_at_ms: i64,
) -> Result<ChildFenceEvidence, AgentStoreError> {
    let token = i64::try_from(fence.fencing_token().get())
        .map_err(|_| agent::invariant("child fencing token exceeds SQLite range"))?;
    transaction
        .query_row(
            "SELECT delegation.parent_run_id, run.capability_ceiling_json \
             FROM delegation \
             JOIN run ON run.id = delegation.child_run_id \
             JOIN task ON task.id = delegation.child_task_id \
             JOIN work_lease lease ON lease.run_id = run.id \
             WHERE delegation.id = ?1 AND delegation.child_run_id = ?2 \
               AND delegation.state = 'running' AND run.status = 'running' \
               AND task.status = 'running' AND run.current_fencing_token = ?3 \
               AND lease.lease_id = ?4 AND lease.owner_id = ?5 AND lease.fencing_token = ?3 \
               AND lease.state = 'active' AND lease.acquired_at_ms <= ?6 AND ?6 < lease.expires_at_ms",
            params![
                delegation_id.to_string(),
                fence.run_id().to_string(),
                token,
                fence.lease_id().to_string(),
                fence.owner_id().to_string(),
                observed_at_ms,
            ],
            |row| {
                Ok(ChildFenceEvidence {
                    parent_run_id: row.get(0)?,
                    capabilities_json: row.get(1)?,
                })
            },
        )
        .optional()
        .map_err(agent::map_sqlite_error)?
        .ok_or(AgentStoreError::StaleFence)
}

struct ChildFenceEvidence {
    parent_run_id: String,
    capabilities_json: String,
}

fn resource_claim_authorized(
    capabilities: &CapabilityGrant,
    resource_class: mealy_application::ResourceClass,
    resource_key: &str,
) -> bool {
    let mutating = capabilities
        .effect_classes
        .iter()
        .any(|effect| effect.is_mutating());
    match resource_class {
        mealy_application::ResourceClass::WorkspaceWrite => {
            mutating
                && capabilities
                    .profiles
                    .contains(&mealy_domain::PolicyProfile::WorkspaceWrite)
                && capabilities.workspace_roots.iter().any(|root| {
                    resource_key == root
                        || resource_key
                            .strip_prefix(root)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                })
        }
        mealy_application::ResourceClass::ServiceMutation => {
            mutating
                && capabilities
                    .profiles
                    .contains(&mealy_domain::PolicyProfile::ServiceOperator)
        }
        mealy_application::ResourceClass::MemoryNamespace => mutating,
        mealy_application::ResourceClass::Device => {
            mutating
                && capabilities
                    .profiles
                    .contains(&mealy_domain::PolicyProfile::FullTrust)
        }
    }
}

fn load_delegation_view(
    connection: &rusqlite::Connection,
    ownership: Option<OwnershipContext>,
    delegation_id: DelegationId,
) -> Result<DelegationView, AgentStoreError> {
    let row = connection
        .query_row(
            "SELECT delegation.parent_run_id, delegation.child_task_id, delegation.child_run_id, \
                    delegation.effective_capabilities_json, \
                    delegation.effective_capabilities_digest, delegation.budget_json, \
                    delegation.budget_digest, delegation.state, delegation.result_json, \
                    delegation.result_digest, session.principal_id, session.channel_binding_id \
             FROM delegation \
             JOIN run parent ON parent.id = delegation.parent_run_id \
             JOIN turn ON turn.run_id = parent.id AND turn.task_id = parent.task_id \
             JOIN session ON session.id = turn.session_id \
             WHERE delegation.id = ?1",
            [delegation_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                ))
            },
        )
        .optional()
        .map_err(agent::map_sqlite_error)?
        .ok_or(AgentStoreError::NotFound)?;
    if ownership.is_some_and(|owner| {
        row.10 != owner.principal_id().to_string()
            || row.11 != owner.channel_binding_id().to_string()
    }) {
        return Err(AgentStoreError::NotFound);
    }
    let result_digest_valid = match (&row.8, &row.9) {
        (None, None) => true,
        (Some(result), Some(digest)) => sha256_digest(result.as_bytes()) == *digest,
        _ => false,
    };
    if sha256_digest(row.3.as_bytes()) != row.4
        || sha256_digest(row.5.as_bytes()) != row.6
        || !result_digest_valid
    {
        return Err(agent::invariant("delegation projection digest diverged"));
    }
    let capabilities = serde_json::from_str::<CapabilityGrant>(&row.3)
        .map_err(|_| agent::invariant("delegation capabilities are invalid"))?;
    capabilities
        .validate()
        .map_err(|_| agent::invariant("delegation capabilities are non-canonical"))?;
    let budget = serde_json::from_str::<AgentLoopLimits>(&row.5)
        .map_err(|_| agent::invariant("delegation budget is invalid"))?
        .validate()
        .map_err(|_| agent::invariant("delegation budget is unenforceable"))?;
    Ok(DelegationView {
        delegation_id,
        parent_run_id: parse_id(&row.0, "delegation parent run ID")?,
        child_task_id: parse_id(&row.1, "delegation child task ID")?,
        child_run_id: parse_id(&row.2, "delegation child run ID")?,
        effective_capabilities: capabilities,
        child_budget: budget,
        state: row.7,
        result: row
            .8
            .as_deref()
            .map(|value| {
                serde_json::from_str::<Value>(value)
                    .map_err(|_| agent::invariant("delegation result is invalid"))
            })
            .transpose()?,
    })
}

fn canonical_object(value: &Value, field: &str) -> Result<String, AgentStoreError> {
    if !value.is_object() || value.as_object().is_some_and(serde_json::Map::is_empty) {
        return Err(agent::invariant(format!(
            "{field} is not a nonempty object"
        )));
    }
    serde_json::to_string(value).map_err(|_| agent::invariant(format!("{field} is invalid")))
}

const fn risk_class_text(value: RiskClass) -> &'static str {
    match value {
        RiskClass::Low => "low",
        RiskClass::Medium => "medium",
        RiskClass::High => "high",
    }
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, AgentStoreError> {
    value
        .parse()
        .map_err(|_| agent::invariant(format!("stored {field} is invalid")))
}

#[cfg(test)]
mod tests {
    use super::SqliteStore;
    use mealy_application::{
        AcquireResourceClaimCommit, AgentLoopLimits, AgentStoreError, DelegationStore,
        InboxPromotionStore, InputAdmissionCommit, LeaseClaimCommit, LeaseClaimOutcome,
        OwnershipContext, PrepareDelegationCommit, PromotionCommit, PromotionOutcome,
        RecordDelegationResultCommit, ResourceClass, SchedulerStore, SessionCreationCommit,
        SessionStore, StartDelegationCommit, TimelineQuery, TimelineStore,
        VALIDATION_POLICY_VERSION,
    };
    use mealy_domain::{
        CapabilityGrant, ChannelBindingId, CorrelationId, DelegationId, DeliveryMode, EffectClass,
        EventId, FencingToken, InboxEntryId, LeaseFence, LeaseId, OutboxId, PolicyProfile,
        PrincipalId, RiskClass, RunId, SessionId, SuccessCriterion, TaskId, TaskSuccessCriteria,
        TurnId, WorkerId,
    };
    use rusqlite::params;
    use serde_json::json;
    use std::{collections::BTreeSet, time::Duration, time::SystemTime};

    const NOW_MS: i64 = 1_783_000_000_000;

    struct ParentFixture {
        ownership: OwnershipContext,
        session_id: SessionId,
        fence: LeaseFence,
        task_id: TaskId,
        correlation_id: CorrelationId,
    }

    fn at(offset_ms: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_millis(NOW_MS as u64 + offset_ms)
    }

    fn as_i64(value: u64) -> i64 {
        i64::try_from(value).expect("fixture limit fits SQLite")
    }

    fn running_parent(store: &mut SqliteStore) -> ParentFixture {
        let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
        let session_id = SessionId::new();
        let correlation_id = CorrelationId::new();
        store
            .create_session(SessionCreationCommit {
                session_id,
                ownership,
                event_id: EventId::new(),
                correlation_id,
                created_at: at(0),
            })
            .expect("create session");
        store
            .admit_input(InputAdmissionCommit {
                session_id,
                ownership,
                inbox_entry_id: InboxEntryId::new(),
                delivery_mode: DeliveryMode::Queue,
                dedupe_key: "phase4-parent".to_owned(),
                content: "fixture.write_file {\"operation\":\"write_file\",\"relativePath\":\"delegated.txt\",\"content\":\"parent contract\"}".to_owned(),
                maximum_pending_inputs: 1_024,
                event_id: EventId::new(),
                outbox_id: OutboxId::new(),
                correlation_id,
                accepted_at: at(0),
            })
            .expect("admit parent input");
        let task_id = TaskId::new();
        let run_id = RunId::new();
        assert!(matches!(
            store
                .promote_next(PromotionCommit {
                    session_id,
                    ownership,
                    turn_id: TurnId::new(),
                    task_id,
                    run_id,
                    promotion_event_id: EventId::new(),
                    task_event_id: EventId::new(),
                    run_event_id: EventId::new(),
                    outbox_id: OutboxId::new(),
                    promoted_at: at(1),
                    initial_agent_role: "assistant".to_owned(),
                    initial_budget: AgentLoopLimits::default(),
                    initial_task_profile: mealy_application::InitialTaskProfile::FixtureProof,
                    initial_capability_ceiling: None,
                })
                .expect("promote parent"),
            PromotionOutcome::Promoted(_)
        ));
        let lease_id = LeaseId::new();
        let worker_id = WorkerId::new();
        let LeaseClaimOutcome::Claimed(claim) = store
            .claim_next(LeaseClaimCommit {
                owner_id: worker_id,
                lease_id,
                run_event_id: EventId::new(),
                task_event_id: EventId::new(),
                correlation_id,
                claimed_at: at(2),
                expires_at: at(10_000),
                concurrency_limits: mealy_application::LeaseConcurrencyLimits::default(),
            })
            .expect("claim parent")
        else {
            panic!("parent was not runnable");
        };
        let limits = AgentLoopLimits::default();
        store
            .connection
            .execute(
                "INSERT INTO run_budget_usage(\
                    run_id, maximum_model_calls, maximum_tool_calls, maximum_retries, \
                    maximum_input_tokens, maximum_output_tokens, maximum_cost_microunits, \
                    maximum_output_bytes, maximum_wall_time_ms, maximum_delegated_runs, \
                    started_at_ms, deadline_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    run_id.to_string(),
                    as_i64(limits.maximum_model_calls),
                    as_i64(limits.maximum_tool_calls),
                    as_i64(limits.maximum_retries),
                    as_i64(limits.maximum_input_tokens),
                    as_i64(limits.maximum_output_tokens),
                    as_i64(limits.maximum_cost_microunits),
                    as_i64(limits.maximum_output_bytes),
                    as_i64(limits.maximum_wall_time_ms),
                    as_i64(limits.maximum_delegated_runs),
                    NOW_MS + 2,
                    NOW_MS + 120_002,
                ],
            )
            .expect("initialize parent budget");
        ParentFixture {
            ownership,
            session_id,
            fence: claim.lease.fence(),
            task_id,
            correlation_id,
        }
    }

    fn grant(
        tools: &[&str],
        effects: &[EffectClass],
        profiles: &[PolicyProfile],
        workspace_roots: &[&str],
        maximum_delegated_runs: u64,
    ) -> CapabilityGrant {
        CapabilityGrant {
            tools: tools.iter().map(|value| (*value).to_owned()).collect(),
            effect_classes: effects.iter().copied().collect(),
            profiles: profiles.iter().copied().collect(),
            workspace_roots: workspace_roots
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            maximum_delegated_runs,
            ..CapabilityGrant::default()
        }
    }

    fn criteria() -> TaskSuccessCriteria {
        TaskSuccessCriteria {
            objective: "Return a bounded independent fixture assessment".to_owned(),
            criteria: vec![SuccessCriterion {
                criterion_id: "structured_result".to_owned(),
                requirement: "Return a structured result derived only from the delegated package"
                    .to_owned(),
            }],
            no_objective_criteria_reason: None,
            risk_class: RiskClass::Low,
            policy_version: VALIDATION_POLICY_VERSION.to_owned(),
        }
    }

    fn prepare_child(
        store: &mut SqliteStore,
        parent: &ParentFixture,
        offset_ms: u64,
    ) -> (DelegationId, TaskId, RunId) {
        let delegation_id = DelegationId::new();
        let child_task_id = TaskId::new();
        let child_run_id = RunId::new();
        let requested = grant(
            &["fixture.write_file", "ungranted.admin"],
            &[EffectClass::Idempotent, EffectClass::NonIdempotent],
            &[PolicyProfile::WorkspaceWrite, PolicyProfile::FullTrust],
            &["fixture://phase3/workspace", "fixture://ungranted"],
            2,
        );
        let policy = grant(
            &["fixture.write_file", "unrelated"],
            &[EffectClass::Idempotent],
            &[PolicyProfile::WorkspaceWrite],
            &["fixture://phase3/workspace"],
            1,
        );
        let child_budget = AgentLoopLimits {
            maximum_model_calls: 2,
            maximum_tool_calls: 1,
            maximum_retries: 0,
            maximum_delegated_runs: 0,
            ..AgentLoopLimits::default()
        };
        let view = store
            .prepare_delegation(PrepareDelegationCommit {
                parent_fence: parent.fence,
                delegation_id,
                child_task_id,
                child_run_id,
                work_order: json!({"operation": "assess_fixture", "version": 1}),
                success_criteria: criteria(),
                context_package: json!({
                    "sources": [{"locator": "fixture://phase2/report", "digest": "recorded"}]
                }),
                requested_capabilities: requested,
                policy_capabilities: policy,
                child_budget,
                event_id: EventId::new(),
                prepared_at: at(offset_ms),
            })
            .expect("prepare child delegation");
        assert_eq!(
            view.effective_capabilities.tools,
            BTreeSet::from(["fixture.write_file".to_owned()])
        );
        assert_eq!(
            view.effective_capabilities.effect_classes,
            BTreeSet::from([EffectClass::Idempotent])
        );
        assert_eq!(
            view.effective_capabilities.profiles,
            BTreeSet::from([PolicyProfile::WorkspaceWrite])
        );
        assert_eq!(
            view.effective_capabilities.workspace_roots,
            BTreeSet::from(["fixture://phase3/workspace".to_owned()])
        );
        assert_eq!(view.effective_capabilities.maximum_delegated_runs, 1);
        assert_eq!(view.child_budget, child_budget);
        (delegation_id, child_task_id, child_run_id)
    }

    fn start_child(
        store: &mut SqliteStore,
        parent: &ParentFixture,
        delegation_id: DelegationId,
        offset_ms: u64,
    ) -> LeaseFence {
        store
            .start_delegation(StartDelegationCommit {
                delegation_id,
                lease_id: LeaseId::new(),
                owner_id: WorkerId::new(),
                event_id: EventId::new(),
                correlation_id: parent.correlation_id,
                started_at: at(offset_ms),
                expires_at: at(9_000),
            })
            .expect("start delegated child")
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn capability_intersection_resource_exclusion_and_fenced_results_are_atomic() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let parent = running_parent(&mut store);
        let (first_id, _, _) = prepare_child(&mut store, &parent, 3);
        let (second_id, _, _) = prepare_child(&mut store, &parent, 4);
        let first_fence = start_child(&mut store, &parent, first_id, 5);
        let second_fence = start_child(&mut store, &parent, second_id, 6);

        assert_eq!(
            store.acquire_resource_claim(AcquireResourceClaimCommit {
                fence: first_fence,
                delegation_id: first_id,
                claim_id: EventId::new(),
                resource_class: ResourceClass::WorkspaceWrite,
                resource_key: "fixture://outside-authority/shared-output".to_owned(),
                event_id: EventId::new(),
                correlation_id: parent.correlation_id,
                acquired_at: at(7),
            }),
            Err(AgentStoreError::Conflict)
        );
        store
            .acquire_resource_claim(AcquireResourceClaimCommit {
                fence: first_fence,
                delegation_id: first_id,
                claim_id: EventId::new(),
                resource_class: ResourceClass::WorkspaceWrite,
                resource_key: "fixture://phase3/workspace/shared-output".to_owned(),
                event_id: EventId::new(),
                correlation_id: parent.correlation_id,
                acquired_at: at(8),
            })
            .expect("first child claims resource");
        assert_eq!(
            store.acquire_resource_claim(AcquireResourceClaimCommit {
                fence: second_fence,
                delegation_id: second_id,
                claim_id: EventId::new(),
                resource_class: ResourceClass::WorkspaceWrite,
                resource_key: "fixture://phase3/workspace/shared-output".to_owned(),
                event_id: EventId::new(),
                correlation_id: parent.correlation_id,
                acquired_at: at(9),
            }),
            Err(AgentStoreError::Conflict)
        );

        let stale = LeaseFence::new(
            first_fence.lease_id(),
            first_fence.run_id(),
            first_fence.owner_id(),
            FencingToken::new(first_fence.fencing_token().get() + 1).expect("next token"),
        );
        assert_eq!(
            store.record_delegation_result(RecordDelegationResultCommit {
                child_fence: stale,
                delegation_id: first_id,
                result: json!({"assessment": "must not commit"}),
                succeeded: true,
                event_id: EventId::new(),
                correlation_id: parent.correlation_id,
                completed_at: at(10),
            }),
            Err(AgentStoreError::StaleFence)
        );
        let first = store
            .record_delegation_result(RecordDelegationResultCommit {
                child_fence: first_fence,
                delegation_id: first_id,
                result: json!({"assessment": "bounded", "criterionPassed": true}),
                succeeded: true,
                event_id: EventId::new(),
                correlation_id: parent.correlation_id,
                completed_at: at(11),
            })
            .expect("commit first result");
        assert_eq!(first.state, "succeeded");
        assert_eq!(
            store
                .delegation(parent.ownership, first_id)
                .expect("load owned delegation"),
            first
        );

        store
            .acquire_resource_claim(AcquireResourceClaimCommit {
                fence: second_fence,
                delegation_id: second_id,
                claim_id: EventId::new(),
                resource_class: ResourceClass::WorkspaceWrite,
                resource_key: "fixture://phase3/workspace/shared-output".to_owned(),
                event_id: EventId::new(),
                correlation_id: parent.correlation_id,
                acquired_at: at(12),
            })
            .expect("released claim can be acquired by second child");
        store
            .record_delegation_result(RecordDelegationResultCommit {
                child_fence: second_fence,
                delegation_id: second_id,
                result: json!({"assessment": "unable to establish criterion"}),
                succeeded: false,
                event_id: EventId::new(),
                correlation_id: parent.correlation_id,
                completed_at: at(13),
            })
            .expect("commit second result");

        let usage = store
            .connection
            .query_row(
                "SELECT used_delegated_runs, reserved_delegated_runs \
                 FROM run_budget_usage WHERE run_id = ?1",
                [parent.fence.run_id().to_string()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .expect("parent delegation usage");
        assert_eq!(usage, (2, 0));
        let child_parent: String = store
            .connection
            .query_row(
                "SELECT parent_task_id FROM task WHERE id = (\
                    SELECT child_task_id FROM delegation WHERE id = ?1\
                 )",
                [first_id.to_string()],
                |row| row.get(0),
            )
            .expect("child task parent");
        assert_eq!(child_parent, parent.task_id.to_string());
        let timeline = store
            .timeline_page(TimelineQuery {
                session_id: parent.session_id,
                ownership: parent.ownership,
                after: None,
                limit: 1_000,
            })
            .expect("load delegation timeline");
        for (event_type, expected) in [
            ("delegation.prepared", 2),
            ("delegation.started", 2),
            ("resource_claim.acquired", 2),
            ("delegation.succeeded", 1),
            ("delegation.failed", 1),
        ] {
            assert_eq!(
                timeline
                    .events
                    .iter()
                    .filter(|event| event.event_type == event_type)
                    .count(),
                expected,
                "timeline count for {event_type}"
            );
        }
    }
}
