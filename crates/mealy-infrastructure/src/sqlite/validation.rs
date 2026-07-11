use super::{SqliteStore, agent};
use mealy_application::{
    AgentLoopLimits, AgentStoreError, OwnershipContext, RecordValidationCommit,
    TaskSuccessCriteriaView, ValidationRecordView, ValidationStore, sha256_digest,
    validate_validation_commit,
};
use mealy_domain::{
    RiskClass, RunId, SuccessCriterion, TaskId, TaskSuccessCriteria, ValidationId,
    ValidationMethod, ValidationOutcome,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::{Value, json};
use std::{str::FromStr, time::SystemTime};

impl ValidationStore for SqliteStore {
    fn task_success_criteria(
        &self,
        ownership: OwnershipContext,
        task_id: TaskId,
    ) -> Result<TaskSuccessCriteriaView, AgentStoreError> {
        load_task_criteria(&self.connection, ownership, task_id)
    }

    #[allow(clippy::too_many_lines)]
    fn record_validation(
        &mut self,
        commit: RecordValidationCommit,
    ) -> Result<ValidationRecordView, AgentStoreError> {
        validate_validation_commit(&commit)?;
        let recorded_at_ms = agent::epoch_milliseconds(commit.recorded_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(agent::map_sqlite_error)?;
        let producer = load_validation_producer(
            &transaction,
            commit.producer_fence,
            commit.task_id,
            recorded_at_ms,
        )?;
        let manifest_id = commit.context.manifest_id.to_string();
        if commit.responsible_principal_id.to_string() != producer.principal_id
            || producer.current_context_manifest_id.as_deref() == Some(manifest_id.as_str())
        {
            return Err(AgentStoreError::Conflict);
        }
        let criteria = load_task_criteria_from_row(
            commit.task_id,
            &producer.objective,
            &producer.criteria_json,
            &producer.criteria_digest,
            producer.no_objective_criteria_reason.as_deref(),
            &producer.risk_class,
            &producer.policy_version,
            producer.criteria_created_at_ms,
        )?;
        if commit.context.criteria
            != serde_json::to_value(&criteria.criteria).map_err(|_| {
                agent::invariant("task success criteria cannot be serialized for validation")
            })?
        {
            return Err(AgentStoreError::Conflict);
        }
        let independent_required = criteria.criteria.independent_validation_required();
        if independent_required
            && !matches!(
                commit.method,
                ValidationMethod::FreshContextModel | ValidationMethod::Waiver
            )
        {
            return Err(AgentStoreError::Conflict);
        }

        let request_json = canonical_object(&commit.context.request, "validation request")?;
        let criteria_json = canonical_object(&commit.context.criteria, "validation criteria")?;
        let outputs_json = canonical_object(&commit.context.outputs, "validation outputs")?;
        let context_evidence_json =
            canonical_object(&commit.context.evidence, "validation context evidence")?;
        let capabilities_json = serde_json::to_string(&commit.context.capabilities)
            .map_err(|_| agent::invariant("validator capabilities cannot be serialized"))?;
        let rubric_json = canonical_object(&commit.rubric, "validation rubric")?;
        let evidence_json = canonical_object(&commit.evidence, "validation evidence")?;

        transaction
            .execute(
                "INSERT INTO validation_context_manifest(\
                    id, task_id, producer_run_id, request_json, request_digest, criteria_json, \
                    criteria_digest, outputs_json, outputs_digest, evidence_json, evidence_digest, \
                    capability_grant_json, capability_grant_digest, \
                    producer_hidden_context_included, created_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 0, ?14)",
                params![
                    commit.context.manifest_id.to_string(),
                    commit.task_id.to_string(),
                    commit.producer_fence.run_id().to_string(),
                    request_json,
                    sha256_digest(request_json.as_bytes()),
                    criteria_json,
                    sha256_digest(criteria_json.as_bytes()),
                    outputs_json,
                    sha256_digest(outputs_json.as_bytes()),
                    context_evidence_json,
                    sha256_digest(context_evidence_json.as_bytes()),
                    capabilities_json,
                    sha256_digest(capabilities_json.as_bytes()),
                    recorded_at_ms,
                ],
            )
            .map_err(agent::map_sqlite_error)?;

        if let (Some(validator_task_id), Some(validator_run_id)) =
            (commit.validator_task_id, commit.validator_run_id)
        {
            insert_validator_run(
                &transaction,
                &commit,
                &producer,
                validator_task_id,
                validator_run_id,
                &capabilities_json,
                recorded_at_ms,
            )?;
        }

        agent::append_agent_event(
            &transaction,
            commit.event_id,
            "validation",
            &commit.validation_id.to_string(),
            "validation.completed",
            recorded_at_ms,
            commit.correlation_id,
            json!({
                "task_id": commit.task_id,
                "producer_run_id": commit.producer_fence.run_id(),
                "validator_run_id": commit.validator_run_id,
                "context_manifest_id": commit.context.manifest_id,
                "method": commit.method,
                "outcome": commit.outcome,
                "rubric_digest": sha256_digest(rubric_json.as_bytes()),
                "evidence_digest": sha256_digest(evidence_json.as_bytes()),
                "responsible_principal_id": commit.responsible_principal_id,
                "policy_version": commit.policy_version,
            }),
        )?;
        transaction
            .execute(
                "INSERT INTO validation_record(\
                    id, task_id, producer_run_id, validator_task_id, validator_run_id, \
                    context_manifest_id, method, outcome, rubric_json, rubric_digest, \
                    evidence_json, evidence_digest, responsible_principal_id, policy_version, \
                    event_id, created_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                params![
                    commit.validation_id.to_string(),
                    commit.task_id.to_string(),
                    commit.producer_fence.run_id().to_string(),
                    commit.validator_task_id.map(|id| id.to_string()),
                    commit.validator_run_id.map(|id| id.to_string()),
                    commit.context.manifest_id.to_string(),
                    validation_method_text(commit.method),
                    validation_outcome_text(commit.outcome),
                    rubric_json,
                    sha256_digest(rubric_json.as_bytes()),
                    evidence_json,
                    sha256_digest(evidence_json.as_bytes()),
                    commit.responsible_principal_id.to_string(),
                    commit.policy_version,
                    commit.event_id.to_string(),
                    recorded_at_ms,
                ],
            )
            .map_err(agent::map_sqlite_error)?;
        if let Some(validator_run_id) = commit.validator_run_id {
            let parent_lineage = producer
                .lineage
                .as_ref()
                .ok_or_else(|| agent::invariant("producer run has no durable lineage"))?;
            transaction
                .execute(
                    "INSERT INTO run_lineage(\
                        run_id, root_run_id, parent_run_id, depth, relation_kind, relation_id\
                     ) VALUES (?1, ?2, ?3, ?4, 'validation', ?5)",
                    params![
                        validator_run_id.to_string(),
                        parent_lineage.root_run_id,
                        commit.producer_fence.run_id().to_string(),
                        parent_lineage.depth + 1,
                        commit.validation_id.to_string(),
                    ],
                )
                .map_err(agent::map_sqlite_error)?;
        }
        let task_changed = transaction
            .execute(
                "UPDATE task SET validation_id = ?1, revision = revision + 1 \
                 WHERE id = ?2 AND status = 'running' AND validation_id IS NULL",
                params![commit.validation_id.to_string(), commit.task_id.to_string(),],
            )
            .map_err(agent::map_sqlite_error)?;
        if task_changed != 1 {
            return Err(AgentStoreError::Conflict);
        }
        let view = load_validation_view(&transaction, None, commit.validation_id)?;
        transaction.commit().map_err(agent::map_sqlite_error)?;
        Ok(view)
    }

    fn validation_record(
        &self,
        ownership: OwnershipContext,
        validation_id: ValidationId,
    ) -> Result<ValidationRecordView, AgentStoreError> {
        load_validation_view(&self.connection, Some(ownership), validation_id)
    }

    fn task_validation(
        &self,
        ownership: OwnershipContext,
        task_id: TaskId,
    ) -> Result<Option<ValidationRecordView>, AgentStoreError> {
        let validation_id = self
            .connection
            .query_row(
                "SELECT task.validation_id \
                 FROM task \
                 JOIN run ON run.task_id = task.id AND run.parent_run_id IS NULL \
                 JOIN turn ON turn.run_id = run.id AND turn.task_id = task.id \
                 JOIN session ON session.id = turn.session_id \
                 WHERE task.id = ?1 AND session.principal_id = ?2 \
                   AND session.channel_binding_id = ?3",
                params![
                    task_id.to_string(),
                    ownership.principal_id().to_string(),
                    ownership.channel_binding_id().to_string(),
                ],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(agent::map_sqlite_error)?
            .ok_or(AgentStoreError::NotFound)?;
        validation_id
            .as_deref()
            .map(|value| {
                parse_id(value, "task validation ID").and_then(|validation_id| {
                    load_validation_view(&self.connection, Some(ownership), validation_id)
                })
            })
            .transpose()
    }
}

struct ProducerEvidence {
    principal_id: String,
    objective: String,
    criteria_json: String,
    criteria_digest: String,
    no_objective_criteria_reason: Option<String>,
    risk_class: String,
    policy_version: String,
    criteria_created_at_ms: i64,
    current_context_manifest_id: Option<String>,
    lineage: Option<LineageEvidence>,
}

struct LineageEvidence {
    root_run_id: String,
    depth: i64,
}

fn load_validation_producer(
    transaction: &Transaction<'_>,
    fence: mealy_domain::LeaseFence,
    task_id: TaskId,
    observed_at_ms: i64,
) -> Result<ProducerEvidence, AgentStoreError> {
    let token = i64::try_from(fence.fencing_token().get())
        .map_err(|_| agent::invariant("validation fencing token exceeds SQLite range"))?;
    transaction
        .query_row(
            "SELECT session.principal_id, criteria.objective, criteria.criteria_json, \
                    criteria.criteria_digest, criteria.no_objective_criteria_reason, \
                    criteria.risk_class, criteria.policy_version, criteria.created_at_ms, \
                    loop.current_manifest_id, lineage.root_run_id, lineage.depth \
             FROM run \
             JOIN task ON task.id = run.task_id \
             JOIN turn ON turn.run_id = run.id AND turn.task_id = task.id \
             JOIN session ON session.id = turn.session_id \
             JOIN work_lease lease ON lease.run_id = run.id \
             JOIN run_loop_state loop ON loop.run_id = run.id \
             JOIN task_success_criteria criteria ON criteria.task_id = task.id \
             LEFT JOIN run_lineage lineage ON lineage.run_id = run.id \
             WHERE run.id = ?1 AND task.id = ?2 AND run.status = 'running' \
               AND task.status = 'running' AND run.current_fencing_token = ?3 \
               AND lease.lease_id = ?4 AND lease.owner_id = ?5 AND lease.fencing_token = ?3 \
               AND lease.state = 'active' AND lease.acquired_at_ms <= ?6 AND ?6 < lease.expires_at_ms",
            params![
                fence.run_id().to_string(),
                task_id.to_string(),
                token,
                fence.lease_id().to_string(),
                fence.owner_id().to_string(),
                observed_at_ms,
            ],
            |row| {
                Ok(ProducerEvidence {
                    principal_id: row.get(0)?,
                    objective: row.get(1)?,
                    criteria_json: row.get(2)?,
                    criteria_digest: row.get(3)?,
                    no_objective_criteria_reason: row.get(4)?,
                    risk_class: row.get(5)?,
                    policy_version: row.get(6)?,
                    criteria_created_at_ms: row.get(7)?,
                    current_context_manifest_id: row.get(8)?,
                    lineage: match (row.get::<_, Option<String>>(9)?, row.get::<_, Option<i64>>(10)?) {
                        (Some(root_run_id), Some(depth)) => Some(LineageEvidence { root_run_id, depth }),
                        (None, None) => None,
                        _ => return Err(rusqlite::Error::InvalidQuery),
                    },
                })
            },
        )
        .optional()
        .map_err(agent::map_sqlite_error)?
        .ok_or(AgentStoreError::StaleFence)
}

#[allow(clippy::too_many_arguments)]
fn insert_validator_run(
    transaction: &Transaction<'_>,
    commit: &RecordValidationCommit,
    producer: &ProducerEvidence,
    validator_task_id: TaskId,
    validator_run_id: RunId,
    capabilities_json: &str,
    recorded_at_ms: i64,
) -> Result<(), AgentStoreError> {
    let budget = AgentLoopLimits {
        maximum_model_calls: 1,
        maximum_tool_calls: 0,
        maximum_retries: 0,
        maximum_delegated_runs: 0,
        maximum_input_tokens: 16_384,
        maximum_output_tokens: 1_024,
        maximum_cost_microunits: 100_000,
        maximum_output_bytes: 1024 * 1024,
        maximum_wall_time_ms: 30_000,
        provider_timeout_ms: 10_000,
        tool_timeout_ms: 10_000,
        inline_output_bytes: 1_024,
        maximum_artifact_bytes: 1024 * 1024,
    };
    let budget_json = serde_json::to_string(&budget)
        .map_err(|_| agent::invariant("validator budget cannot be serialized"))?;
    transaction
        .execute(
            "INSERT INTO task(\
                id, status, revision, validation_required, parent_task_id\
             ) VALUES (?1, 'succeeded', 0, 0, ?2)",
            params![validator_task_id.to_string(), commit.task_id.to_string()],
        )
        .map_err(agent::map_sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO task_success_criteria(\
                task_id, objective, criteria_json, criteria_digest, \
                no_objective_criteria_reason, risk_class, policy_version, created_at_ms\
             ) VALUES (?1, 'Independently validate the parent task output', ?2, ?3, NULL, \
                       'low', ?4, ?5)",
            params![
                validator_task_id.to_string(),
                producer.criteria_json,
                producer.criteria_digest,
                producer.policy_version,
                recorded_at_ms,
            ],
        )
        .map_err(agent::map_sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO run(\
                id, task_id, parent_run_id, status, revision, agent_role, \
                capability_ceiling_json, budget_json, correlation_id, created_at_ms, \
                updated_at_ms, completed_at_ms, current_fencing_token\
             ) VALUES (?1, ?2, ?3, 'succeeded', 0, 'validator', ?4, ?5, ?6, ?7, ?7, ?7, 0)",
            params![
                validator_run_id.to_string(),
                validator_task_id.to_string(),
                commit.producer_fence.run_id().to_string(),
                capabilities_json,
                budget_json,
                commit.correlation_id.to_string(),
                recorded_at_ms,
            ],
        )
        .map_err(agent::map_sqlite_error)?;
    Ok(())
}

fn load_task_criteria(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
    task_id: TaskId,
) -> Result<TaskSuccessCriteriaView, AgentStoreError> {
    connection
        .query_row(
            "SELECT criteria.objective, criteria.criteria_json, criteria.criteria_digest, \
                    criteria.no_objective_criteria_reason, criteria.risk_class, \
                    criteria.policy_version, criteria.created_at_ms \
             FROM task_success_criteria criteria \
             JOIN run ON run.task_id = criteria.task_id AND run.parent_run_id IS NULL \
             JOIN turn ON turn.run_id = run.id AND turn.task_id = criteria.task_id \
             JOIN session ON session.id = turn.session_id \
             WHERE criteria.task_id = ?1 AND session.principal_id = ?2 \
               AND session.channel_binding_id = ?3",
            params![
                task_id.to_string(),
                ownership.principal_id().to_string(),
                ownership.channel_binding_id().to_string(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()
        .map_err(agent::map_sqlite_error)?
        .ok_or(AgentStoreError::NotFound)
        .and_then(|row| {
            load_task_criteria_from_row(
                task_id,
                &row.0,
                &row.1,
                &row.2,
                row.3.as_deref(),
                &row.4,
                &row.5,
                row.6,
            )
        })
}

#[allow(clippy::too_many_arguments)]
fn load_task_criteria_from_row(
    task_id: TaskId,
    objective: &str,
    criteria_json: &str,
    criteria_digest: &str,
    reason: Option<&str>,
    risk_class: &str,
    policy_version: &str,
    created_at_ms: i64,
) -> Result<TaskSuccessCriteriaView, AgentStoreError> {
    if sha256_digest(criteria_json.as_bytes()) != criteria_digest {
        return Err(agent::invariant("task criteria digest diverged"));
    }
    let criteria = serde_json::from_str::<Vec<SuccessCriterion>>(criteria_json)
        .map_err(|_| agent::invariant("stored task criteria are invalid"))?;
    let risk_class = parse_risk_class(risk_class)?;
    let contract = TaskSuccessCriteria {
        objective: objective.to_owned(),
        criteria,
        no_objective_criteria_reason: reason.map(str::to_owned),
        risk_class,
        policy_version: policy_version.to_owned(),
    };
    contract
        .validate()
        .map_err(|_| agent::invariant("stored task criteria contract is invalid"))?;
    Ok(TaskSuccessCriteriaView {
        task_id,
        criteria: contract,
        criteria_digest: criteria_digest.to_owned(),
        created_at: system_time(created_at_ms)?,
    })
}

fn load_validation_view(
    connection: &rusqlite::Connection,
    ownership: Option<OwnershipContext>,
    validation_id: ValidationId,
) -> Result<ValidationRecordView, AgentStoreError> {
    let row = connection
        .query_row(
            "SELECT validation.task_id, validation.producer_run_id, validation.validator_run_id, \
                    validation.context_manifest_id, validation.method, validation.outcome, \
                    validation.rubric_json, validation.rubric_digest, validation.evidence_json, \
                    validation.evidence_digest, validation.responsible_principal_id, \
                    validation.policy_version, timeline.cursor, session.principal_id, \
                    session.channel_binding_id \
             FROM validation_record validation \
             JOIN run producer ON producer.id = validation.producer_run_id \
             JOIN turn ON turn.run_id = producer.id AND turn.task_id = validation.task_id \
             JOIN session ON session.id = turn.session_id \
             JOIN timeline_event timeline ON timeline.event_id = validation.event_id \
             WHERE validation.id = ?1",
            [validation_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                ))
            },
        )
        .optional()
        .map_err(agent::map_sqlite_error)?
        .ok_or(AgentStoreError::NotFound)?;
    if ownership.is_some_and(|owner| {
        row.13 != owner.principal_id().to_string()
            || row.14 != owner.channel_binding_id().to_string()
    }) {
        return Err(AgentStoreError::NotFound);
    }
    if sha256_digest(row.6.as_bytes()) != row.7 || sha256_digest(row.8.as_bytes()) != row.9 {
        return Err(agent::invariant("validation record digest diverged"));
    }
    Ok(ValidationRecordView {
        validation_id,
        task_id: parse_id(&row.0, "validation task ID")?,
        producer_run_id: parse_id(&row.1, "validation producer run ID")?,
        validator_run_id: row
            .2
            .as_deref()
            .map(|value| parse_id(value, "validator run ID"))
            .transpose()?,
        context_manifest_id: parse_id(&row.3, "validation context manifest ID")?,
        method: parse_validation_method(&row.4)?,
        outcome: parse_validation_outcome(&row.5)?,
        rubric: serde_json::from_str(&row.6)
            .map_err(|_| agent::invariant("validation rubric is invalid"))?,
        evidence: serde_json::from_str(&row.8)
            .map_err(|_| agent::invariant("validation evidence is invalid"))?,
        responsible_principal_id: parse_id(&row.10, "validation principal ID")?,
        policy_version: row.11,
        cursor: u64::try_from(row.12)
            .map_err(|_| agent::invariant("validation cursor is negative"))?,
    })
}

fn canonical_object(value: &Value, field: &str) -> Result<String, AgentStoreError> {
    if !value.is_object() {
        return Err(agent::invariant(format!("{field} is not an object")));
    }
    serde_json::to_string(value).map_err(|_| agent::invariant(format!("{field} is invalid")))
}

fn validation_method_text(value: ValidationMethod) -> &'static str {
    match value {
        ValidationMethod::Deterministic => "deterministic",
        ValidationMethod::FreshContextModel => "fresh_context_model",
        ValidationMethod::Waiver => "waiver",
    }
}

fn validation_outcome_text(value: ValidationOutcome) -> &'static str {
    match value {
        ValidationOutcome::Passed => "passed",
        ValidationOutcome::NeedsRevision => "needs_revision",
        ValidationOutcome::Failed => "failed",
        ValidationOutcome::Inconclusive => "inconclusive",
        ValidationOutcome::Waived => "waived",
    }
}

fn parse_validation_method(value: &str) -> Result<ValidationMethod, AgentStoreError> {
    match value {
        "deterministic" => Ok(ValidationMethod::Deterministic),
        "fresh_context_model" => Ok(ValidationMethod::FreshContextModel),
        "waiver" => Ok(ValidationMethod::Waiver),
        _ => Err(agent::invariant("stored validation method is invalid")),
    }
}

fn parse_validation_outcome(value: &str) -> Result<ValidationOutcome, AgentStoreError> {
    match value {
        "passed" => Ok(ValidationOutcome::Passed),
        "needs_revision" => Ok(ValidationOutcome::NeedsRevision),
        "failed" => Ok(ValidationOutcome::Failed),
        "inconclusive" => Ok(ValidationOutcome::Inconclusive),
        "waived" => Ok(ValidationOutcome::Waived),
        _ => Err(agent::invariant("stored validation outcome is invalid")),
    }
}

fn parse_risk_class(value: &str) -> Result<RiskClass, AgentStoreError> {
    match value {
        "low" => Ok(RiskClass::Low),
        "medium" => Ok(RiskClass::Medium),
        "high" => Ok(RiskClass::High),
        _ => Err(agent::invariant("stored task risk is invalid")),
    }
}

fn system_time(value: i64) -> Result<SystemTime, AgentStoreError> {
    let millis =
        u64::try_from(value).map_err(|_| agent::invariant("stored validation time is negative"))?;
    SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_millis(millis))
        .ok_or_else(|| agent::invariant("stored validation time exceeds SystemTime"))
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
        AgentLoopLimits, AgentStoreError, FIXTURE_WRITE_INPUT_PREFIX, InboxPromotionStore,
        InputAdmissionCommit, LeaseClaimCommit, LeaseClaimOutcome, OwnershipContext,
        PromotionCommit, PromotionOutcome, RecordValidationCommit, SchedulerStore,
        SessionCreationCommit, SessionStore, VALIDATION_POLICY_VERSION, ValidationContextDraft,
        ValidationStore, sha256_digest,
    };
    use mealy_domain::{
        CapabilityGrant, ChannelBindingId, ContextManifestId, CorrelationId, DeliveryMode,
        EffectClass, EventId, InboxEntryId, LeaseFence, LeaseId, OutboxId, PolicyProfile,
        PrincipalId, RunId, SessionId, TaskId, TaskSuccessCriteria, TurnId, ValidationId,
        ValidationMethod, ValidationOutcome, WorkerId,
    };
    use serde_json::{Value, json};
    use std::{collections::BTreeSet, time::Duration, time::SystemTime};

    const NOW_MS: i64 = 1_783_100_000_000;

    struct ProducerFixture {
        ownership: OwnershipContext,
        fence: LeaseFence,
        task_id: TaskId,
        correlation_id: CorrelationId,
    }

    fn at(offset_ms: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_millis(NOW_MS as u64 + offset_ms)
    }

    fn running_medium_risk_producer(store: &mut SqliteStore) -> ProducerFixture {
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
            .expect("create producer session");
        let write_request = format!(
            "{FIXTURE_WRITE_INPUT_PREFIX}{}",
            json!({
                "operation": "write_file",
                "relativePath": "phase4-validation.txt",
                "content": "fresh validation evidence"
            })
        );
        store
            .admit_input(InputAdmissionCommit {
                session_id,
                ownership,
                inbox_entry_id: InboxEntryId::new(),
                delivery_mode: DeliveryMode::Queue,
                dedupe_key: "phase4-validation".to_owned(),
                content: write_request,
                maximum_pending_inputs: 1_024,
                event_id: EventId::new(),
                outbox_id: OutboxId::new(),
                correlation_id,
                accepted_at: at(0),
            })
            .expect("admit producer input");
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
                })
                .expect("promote producer"),
            PromotionOutcome::Promoted(_)
        ));
        let LeaseClaimOutcome::Claimed(claim) = store
            .claim_next(LeaseClaimCommit {
                owner_id: WorkerId::new(),
                lease_id: LeaseId::new(),
                run_event_id: EventId::new(),
                task_event_id: EventId::new(),
                correlation_id,
                claimed_at: at(2),
                expires_at: at(10_000),
                concurrency_limits: mealy_application::LeaseConcurrencyLimits::default(),
            })
            .expect("claim producer")
        else {
            panic!("producer was not runnable");
        };
        store
            .connection
            .execute(
                "INSERT INTO run_loop_state(\
                    run_id, revision, iteration, next_action, updated_at_ms\
                 ) VALUES (?1, 0, 0, 'compile_context', ?2)",
                rusqlite::params![run_id.to_string(), NOW_MS + 2],
            )
            .expect("seed producer loop boundary");
        ProducerFixture {
            ownership,
            fence: claim.lease.fence(),
            task_id,
            correlation_id,
        }
    }

    fn validator_capabilities() -> CapabilityGrant {
        CapabilityGrant {
            effect_classes: BTreeSet::from([EffectClass::ReadOnly]),
            profiles: BTreeSet::from([PolicyProfile::Observe]),
            maximum_delegated_runs: 0,
            ..CapabilityGrant::default()
        }
    }

    fn validation_commit(
        producer: &ProducerFixture,
        criteria: &TaskSuccessCriteria,
        method: ValidationMethod,
        validator_ids: Option<(TaskId, RunId)>,
        capabilities: CapabilityGrant,
        manifest_id: ContextManifestId,
        offset_ms: u64,
    ) -> RecordValidationCommit {
        RecordValidationCommit {
            producer_fence: producer.fence,
            task_id: producer.task_id,
            validation_id: ValidationId::new(),
            validator_task_id: validator_ids.map(|ids| ids.0),
            validator_run_id: validator_ids.map(|ids| ids.1),
            context: ValidationContextDraft {
                manifest_id,
                request: json!({
                    "objective": criteria.objective,
                    "requestDigest": sha256_digest(b"phase4 fixture-write request")
                }),
                criteria: serde_json::to_value(criteria).expect("serialize criteria"),
                outputs: json!({
                    "finalResponse": "Fixture write reached durable effect state succeeded",
                    "contentDigest": sha256_digest(b"recorded producer output")
                }),
                evidence: json!({
                    "effectStatus": "succeeded",
                    "externalMutationCount": 1,
                    "approvalSubjectMatched": true
                }),
                capabilities,
            },
            method,
            outcome: ValidationOutcome::Passed,
            rubric: json!({
                "decisionRule": "all criteria require direct durable evidence",
                "criterionIds": criteria
                    .criteria
                    .iter()
                    .map(|criterion| criterion.criterion_id.as_str())
                    .collect::<Vec<_>>()
            }),
            evidence: json!({
                "allCriteriaPassed": true,
                "producerHiddenContextUsed": false,
                "findings": [{"criterionId": "effect_outcome", "passed": true}]
            }),
            responsible_principal_id: producer.ownership.principal_id(),
            policy_version: VALIDATION_POLICY_VERSION.to_owned(),
            event_id: EventId::new(),
            correlation_id: producer.correlation_id,
            recorded_at: at(offset_ms),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn medium_risk_success_is_gated_by_fresh_read_only_validation() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let producer = running_medium_risk_producer(&mut store);
        let criteria = store
            .task_success_criteria(producer.ownership, producer.task_id)
            .expect("load explicit task criteria")
            .criteria;
        assert!(criteria.independent_validation_required());

        assert!(
            store
                .connection
                .execute(
                    "UPDATE task SET status = 'succeeded' WHERE id = ?1",
                    [producer.task_id.to_string()],
                )
                .is_err(),
            "schema must reject success before validation"
        );

        let deterministic = validation_commit(
            &producer,
            &criteria,
            ValidationMethod::Deterministic,
            None,
            validator_capabilities(),
            ContextManifestId::new(),
            3,
        );
        assert_eq!(
            store.record_validation(deterministic),
            Err(AgentStoreError::Conflict),
            "medium risk cannot use producer-local deterministic validation"
        );

        let mut widened = validator_capabilities();
        widened.effect_classes.insert(EffectClass::Idempotent);
        widened.profiles.insert(PolicyProfile::WorkspaceWrite);
        let invalid_authority = validation_commit(
            &producer,
            &criteria,
            ValidationMethod::FreshContextModel,
            Some((TaskId::new(), RunId::new())),
            widened,
            ContextManifestId::new(),
            4,
        );
        assert!(matches!(
            store.record_validation(invalid_authority),
            Err(AgentStoreError::InvariantViolation(_))
        ));

        let validator_task_id = TaskId::new();
        let validator_run_id = RunId::new();
        let context_manifest_id = ContextManifestId::new();
        let commit = validation_commit(
            &producer,
            &criteria,
            ValidationMethod::FreshContextModel,
            Some((validator_task_id, validator_run_id)),
            validator_capabilities(),
            context_manifest_id,
            5,
        );
        let validation_id = commit.validation_id;
        let record = store
            .record_validation(commit)
            .expect("record independent validation");
        assert_eq!(record.validation_id, validation_id);
        assert_eq!(record.validator_run_id, Some(validator_run_id));
        assert_eq!(record.context_manifest_id, context_manifest_id);
        assert_eq!(record.outcome, ValidationOutcome::Passed);
        assert_eq!(
            store
                .validation_record(producer.ownership, validation_id)
                .expect("load owned validation"),
            record
        );
        assert_eq!(
            store.validation_record(
                OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new()),
                validation_id,
            ),
            Err(AgentStoreError::NotFound)
        );

        let manifest: (i64, String, String, String) = store
            .connection
            .query_row(
                "SELECT producer_hidden_context_included, capability_grant_json, \
                        producer_run_id, id \
                 FROM validation_context_manifest WHERE id = ?1",
                [context_manifest_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("fresh validation manifest");
        assert_eq!(manifest.0, 0);
        let capabilities: Value =
            serde_json::from_str(&manifest.1).expect("validator capabilities JSON");
        assert_eq!(capabilities["networkDestinations"], json!([]));
        assert_eq!(capabilities["secretReferences"], json!([]));
        assert_eq!(capabilities["effectClasses"], json!(["read_only"]));
        assert_eq!(manifest.2, producer.fence.run_id().to_string());
        assert_eq!(manifest.3, context_manifest_id.to_string());

        let lineage: (String, String, i64, String) = store
            .connection
            .query_row(
                "SELECT parent_run_id, root_run_id, depth, relation_id \
                 FROM run_lineage WHERE run_id = ?1",
                [validator_run_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("validator lineage");
        assert_eq!(lineage.0, producer.fence.run_id().to_string());
        assert_eq!(lineage.1, producer.fence.run_id().to_string());
        assert_eq!(lineage.2, 1);
        assert_eq!(lineage.3, validation_id.to_string());

        assert_eq!(
            store
                .connection
                .execute(
                    "UPDATE task SET status = 'succeeded' WHERE id = ?1",
                    [producer.task_id.to_string()],
                )
                .expect("validation unlocks success"),
            1
        );
    }
}
