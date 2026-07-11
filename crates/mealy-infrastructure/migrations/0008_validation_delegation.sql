ALTER TABLE task ADD COLUMN parent_task_id TEXT REFERENCES task(id) ON DELETE RESTRICT;

ALTER TABLE turn ADD COLUMN turn_kind TEXT NOT NULL DEFAULT 'canonical'
    CHECK (turn_kind IN ('canonical', 'delegated', 'validation'));

DROP INDEX turn_one_active_per_session_idx;
CREATE UNIQUE INDEX turn_one_active_per_session_idx
    ON turn(session_id) WHERE status = 'active' AND turn_kind = 'canonical';

ALTER TABLE run_budget_usage ADD COLUMN maximum_delegated_runs INTEGER NOT NULL DEFAULT 0
    CHECK (maximum_delegated_runs >= 0);
ALTER TABLE run_budget_usage ADD COLUMN used_delegated_runs INTEGER NOT NULL DEFAULT 0
    CHECK (used_delegated_runs >= 0);
ALTER TABLE run_budget_usage ADD COLUMN reserved_delegated_runs INTEGER NOT NULL DEFAULT 0
    CHECK (
        reserved_delegated_runs >= 0
        AND used_delegated_runs + reserved_delegated_runs <= maximum_delegated_runs
    );

CREATE TABLE task_success_criteria (
    task_id TEXT PRIMARY KEY REFERENCES task(id) ON DELETE CASCADE,
    objective TEXT NOT NULL CHECK (length(objective) BETWEEN 1 AND 4096),
    criteria_json TEXT NOT NULL CHECK (
        json_valid(criteria_json) AND json_type(criteria_json) = 'array'
        AND length(criteria_json) BETWEEN 2 AND 65536
    ),
    criteria_digest TEXT NOT NULL CHECK (
        length(criteria_digest) = 64 AND criteria_digest NOT GLOB '*[^0-9a-f]*'
    ),
    no_objective_criteria_reason TEXT
        CHECK (no_objective_criteria_reason IS NULL
               OR length(no_objective_criteria_reason) BETWEEN 1 AND 4096),
    risk_class TEXT NOT NULL CHECK (risk_class IN ('low', 'medium', 'high')),
    policy_version TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 128),
    created_at_ms INTEGER NOT NULL,
    CHECK (
        (json_array_length(criteria_json) > 0 AND no_objective_criteria_reason IS NULL)
        OR
        (json_array_length(criteria_json) = 0 AND no_objective_criteria_reason IS NOT NULL)
    )
) STRICT;

INSERT INTO task_success_criteria(
    task_id, objective, criteria_json, criteria_digest, no_objective_criteria_reason,
    risk_class, policy_version, created_at_ms
)
SELECT task.id, 'Legacy task admitted before explicit success-criteria storage', '[]',
       '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
       'No objective criterion was recorded by the pre-Phase-4 task contract', 'low',
       'mealy.validation.legacy.v1',
       COALESCE((SELECT MIN(run.created_at_ms) FROM run WHERE run.task_id = task.id), 0)
FROM task;

CREATE TABLE run_lineage (
    run_id TEXT PRIMARY KEY REFERENCES run(id) ON DELETE CASCADE,
    root_run_id TEXT NOT NULL REFERENCES run(id) ON DELETE RESTRICT,
    parent_run_id TEXT REFERENCES run(id) ON DELETE RESTRICT,
    depth INTEGER NOT NULL CHECK (depth >= 0 AND depth <= 32),
    relation_kind TEXT NOT NULL CHECK (relation_kind IN ('root', 'delegation', 'validation')),
    relation_id TEXT,
    UNIQUE (relation_kind, relation_id),
    CHECK (
        (depth = 0 AND root_run_id = run_id AND parent_run_id IS NULL
         AND relation_kind = 'root' AND relation_id IS NULL)
        OR
        (depth > 0 AND root_run_id <> run_id AND parent_run_id IS NOT NULL
         AND relation_kind <> 'root' AND relation_id IS NOT NULL)
    )
) STRICT;

INSERT INTO run_lineage(
    run_id, root_run_id, parent_run_id, depth, relation_kind, relation_id
)
SELECT id, id, NULL, 0, 'root', NULL FROM run WHERE parent_run_id IS NULL;

CREATE TABLE delegation (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    parent_run_id TEXT NOT NULL REFERENCES run(id) ON DELETE RESTRICT,
    child_task_id TEXT NOT NULL UNIQUE REFERENCES task(id) ON DELETE RESTRICT,
    child_run_id TEXT NOT NULL UNIQUE REFERENCES run(id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal > 0),
    parent_fencing_token INTEGER NOT NULL CHECK (parent_fencing_token > 0),
    work_order_json TEXT NOT NULL CHECK (
        json_valid(work_order_json) AND json_type(work_order_json) = 'object'
        AND length(work_order_json) BETWEEN 2 AND 65536
    ),
    work_order_digest TEXT NOT NULL CHECK (
        length(work_order_digest) = 64 AND work_order_digest NOT GLOB '*[^0-9a-f]*'
    ),
    success_criteria_json TEXT NOT NULL CHECK (
        json_valid(success_criteria_json) AND json_type(success_criteria_json) = 'object'
        AND length(success_criteria_json) BETWEEN 2 AND 65536
    ),
    success_criteria_digest TEXT NOT NULL CHECK (
        length(success_criteria_digest) = 64
        AND success_criteria_digest NOT GLOB '*[^0-9a-f]*'
    ),
    context_package_json TEXT NOT NULL CHECK (
        json_valid(context_package_json) AND json_type(context_package_json) = 'object'
        AND length(context_package_json) BETWEEN 2 AND 262144
    ),
    context_package_digest TEXT NOT NULL CHECK (
        length(context_package_digest) = 64
        AND context_package_digest NOT GLOB '*[^0-9a-f]*'
    ),
    requested_capabilities_json TEXT NOT NULL CHECK (
        json_valid(requested_capabilities_json) AND json_type(requested_capabilities_json) = 'object'
        AND length(requested_capabilities_json) BETWEEN 2 AND 65536
    ),
    effective_capabilities_json TEXT NOT NULL CHECK (
        json_valid(effective_capabilities_json) AND json_type(effective_capabilities_json) = 'object'
        AND length(effective_capabilities_json) BETWEEN 2 AND 65536
    ),
    effective_capabilities_digest TEXT NOT NULL CHECK (
        length(effective_capabilities_digest) = 64
        AND effective_capabilities_digest NOT GLOB '*[^0-9a-f]*'
    ),
    budget_json TEXT NOT NULL CHECK (
        json_valid(budget_json) AND json_type(budget_json) = 'object'
        AND length(budget_json) BETWEEN 2 AND 65536
    ),
    budget_digest TEXT NOT NULL CHECK (
        length(budget_digest) = 64 AND budget_digest NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL CHECK (
        state IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')
    ),
    result_json TEXT CHECK (
        result_json IS NULL OR (json_valid(result_json) AND json_type(result_json) = 'object'
                                AND length(result_json) BETWEEN 2 AND 262144)
    ),
    result_digest TEXT CHECK (
        result_digest IS NULL OR (length(result_digest) = 64
                                  AND result_digest NOT GLOB '*[^0-9a-f]*')
    ),
    result_fencing_token INTEGER CHECK (result_fencing_token IS NULL OR result_fencing_token > 0),
    created_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER,
    UNIQUE (parent_run_id, ordinal),
    CHECK (
        (state IN ('queued', 'running') AND result_json IS NULL AND result_digest IS NULL
         AND result_fencing_token IS NULL AND completed_at_ms IS NULL)
        OR
        (state IN ('succeeded', 'failed', 'cancelled') AND result_json IS NOT NULL
         AND result_digest IS NOT NULL AND result_fencing_token IS NOT NULL
         AND completed_at_ms IS NOT NULL AND completed_at_ms >= created_at_ms)
    )
) STRICT;

CREATE INDEX delegation_parent_state_idx
    ON delegation(parent_run_id, state, ordinal, id);

CREATE TABLE resource_claim (
    claim_id TEXT PRIMARY KEY CHECK (length(claim_id) > 0),
    run_id TEXT NOT NULL REFERENCES run(id) ON DELETE RESTRICT,
    delegation_id TEXT REFERENCES delegation(id) ON DELETE RESTRICT,
    resource_class TEXT NOT NULL CHECK (
        resource_class IN ('workspace_write', 'service_mutation', 'memory_namespace', 'device')
    ),
    resource_key TEXT NOT NULL CHECK (length(resource_key) BETWEEN 1 AND 1024),
    state TEXT NOT NULL CHECK (state IN ('active', 'released')),
    lease_id TEXT NOT NULL REFERENCES work_lease(lease_id) ON DELETE RESTRICT,
    owner_id TEXT NOT NULL CHECK (length(owner_id) > 0),
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    acquired_at_ms INTEGER NOT NULL,
    released_at_ms INTEGER,
    CHECK (
        (state = 'active' AND released_at_ms IS NULL)
        OR
        (state = 'released' AND released_at_ms IS NOT NULL
         AND released_at_ms >= acquired_at_ms)
    ),
    FOREIGN KEY (lease_id, run_id, owner_id, fencing_token)
        REFERENCES work_lease(lease_id, run_id, owner_id, fencing_token) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX resource_claim_one_active_owner_idx
    ON resource_claim(resource_class, resource_key) WHERE state = 'active';
CREATE INDEX resource_claim_run_idx ON resource_claim(run_id, state, resource_class, resource_key);

CREATE TABLE validation_context_manifest (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    task_id TEXT NOT NULL REFERENCES task(id) ON DELETE RESTRICT,
    producer_run_id TEXT NOT NULL REFERENCES run(id) ON DELETE RESTRICT,
    request_json TEXT NOT NULL CHECK (
        json_valid(request_json) AND json_type(request_json) = 'object'
        AND length(request_json) BETWEEN 2 AND 262144
    ),
    request_digest TEXT NOT NULL CHECK (
        length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'
    ),
    criteria_json TEXT NOT NULL CHECK (
        json_valid(criteria_json) AND json_type(criteria_json) = 'object'
        AND length(criteria_json) BETWEEN 2 AND 65536
    ),
    criteria_digest TEXT NOT NULL CHECK (
        length(criteria_digest) = 64 AND criteria_digest NOT GLOB '*[^0-9a-f]*'
    ),
    outputs_json TEXT NOT NULL CHECK (
        json_valid(outputs_json) AND json_type(outputs_json) = 'object'
        AND length(outputs_json) BETWEEN 2 AND 262144
    ),
    outputs_digest TEXT NOT NULL CHECK (
        length(outputs_digest) = 64 AND outputs_digest NOT GLOB '*[^0-9a-f]*'
    ),
    evidence_json TEXT NOT NULL CHECK (
        json_valid(evidence_json) AND json_type(evidence_json) = 'object'
        AND length(evidence_json) BETWEEN 2 AND 262144
    ),
    evidence_digest TEXT NOT NULL CHECK (
        length(evidence_digest) = 64 AND evidence_digest NOT GLOB '*[^0-9a-f]*'
    ),
    capability_grant_json TEXT NOT NULL CHECK (
        json_valid(capability_grant_json) AND json_type(capability_grant_json) = 'object'
        AND length(capability_grant_json) BETWEEN 2 AND 65536
    ),
    capability_grant_digest TEXT NOT NULL CHECK (
        length(capability_grant_digest) = 64
        AND capability_grant_digest NOT GLOB '*[^0-9a-f]*'
    ),
    producer_hidden_context_included INTEGER NOT NULL DEFAULT 0
        CHECK (producer_hidden_context_included = 0),
    created_at_ms INTEGER NOT NULL,
    UNIQUE (id, task_id, producer_run_id)
) STRICT;

CREATE TABLE validation_record (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    task_id TEXT NOT NULL REFERENCES task(id) ON DELETE RESTRICT,
    producer_run_id TEXT NOT NULL REFERENCES run(id) ON DELETE RESTRICT,
    validator_task_id TEXT REFERENCES task(id) ON DELETE RESTRICT,
    validator_run_id TEXT REFERENCES run(id) ON DELETE RESTRICT,
    context_manifest_id TEXT NOT NULL
        REFERENCES validation_context_manifest(id) ON DELETE RESTRICT,
    method TEXT NOT NULL CHECK (
        method IN ('deterministic', 'fresh_context_model', 'waiver')
    ),
    outcome TEXT NOT NULL CHECK (
        outcome IN ('passed', 'needs_revision', 'failed', 'inconclusive', 'waived')
    ),
    rubric_json TEXT NOT NULL CHECK (
        json_valid(rubric_json) AND json_type(rubric_json) = 'object'
        AND length(rubric_json) BETWEEN 2 AND 65536
    ),
    rubric_digest TEXT NOT NULL CHECK (
        length(rubric_digest) = 64 AND rubric_digest NOT GLOB '*[^0-9a-f]*'
    ),
    evidence_json TEXT NOT NULL CHECK (
        json_valid(evidence_json) AND json_type(evidence_json) = 'object'
        AND length(evidence_json) BETWEEN 2 AND 262144
    ),
    evidence_digest TEXT NOT NULL CHECK (
        length(evidence_digest) = 64 AND evidence_digest NOT GLOB '*[^0-9a-f]*'
    ),
    responsible_principal_id TEXT NOT NULL CHECK (length(responsible_principal_id) > 0),
    policy_version TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 128),
    event_id TEXT NOT NULL UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL,
    UNIQUE (id, task_id),
    CHECK (
        (method = 'fresh_context_model' AND validator_task_id IS NOT NULL
         AND validator_run_id IS NOT NULL AND outcome <> 'waived')
        OR
        (method = 'deterministic' AND validator_task_id IS NULL
         AND validator_run_id IS NULL AND outcome <> 'waived')
        OR
        (method = 'waiver' AND validator_task_id IS NULL
         AND validator_run_id IS NULL AND outcome = 'waived')
    )
) STRICT;

CREATE INDEX validation_task_idx ON validation_record(task_id, created_at_ms, id);

CREATE TRIGGER delegation_graph_insert
BEFORE INSERT ON delegation
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM run child
        JOIN task child_task ON child_task.id = child.task_id
        WHERE child.id = NEW.child_run_id
          AND child.task_id = NEW.child_task_id
          AND child.parent_run_id = NEW.parent_run_id
          AND child_task.parent_task_id = (SELECT task_id FROM run WHERE id = NEW.parent_run_id)
          AND json(child.capability_ceiling_json) = json(NEW.effective_capabilities_json)
          AND json(child.budget_json) = json(NEW.budget_json)
    ) THEN RAISE(ABORT, 'delegated child graph diverged from its contract') END;
END;

CREATE TRIGGER run_lineage_child_insert
BEFORE INSERT ON run_lineage
WHEN NEW.relation_kind = 'delegation'
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM delegation contract
        JOIN run parent ON parent.id = contract.parent_run_id
        JOIN run_lineage parent_lineage ON parent_lineage.run_id = parent.id
        WHERE contract.id = NEW.relation_id
          AND contract.child_run_id = NEW.run_id
          AND contract.parent_run_id = NEW.parent_run_id
          AND parent_lineage.root_run_id = NEW.root_run_id
          AND parent_lineage.depth + 1 = NEW.depth
    ) THEN RAISE(ABORT, 'child run lineage diverged from delegation') END;
END;

CREATE TRIGGER run_lineage_validation_insert
BEFORE INSERT ON run_lineage
WHEN NEW.relation_kind = 'validation'
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM validation_record validation
        JOIN run_lineage parent_lineage ON parent_lineage.run_id = validation.producer_run_id
        WHERE validation.id = NEW.relation_id
          AND validation.validator_run_id = NEW.run_id
          AND validation.producer_run_id = NEW.parent_run_id
          AND parent_lineage.root_run_id = NEW.root_run_id
          AND parent_lineage.depth + 1 = NEW.depth
    ) THEN RAISE(ABORT, 'validator run lineage diverged from validation') END;
END;

CREATE TRIGGER validation_context_read_only_insert
BEFORE INSERT ON validation_context_manifest
BEGIN
    SELECT CASE WHEN EXISTS(
        SELECT 1 FROM json_each(NEW.capability_grant_json, '$.effectClasses')
        WHERE value <> 'read_only'
    ) OR EXISTS(
        SELECT 1 FROM json_each(NEW.capability_grant_json, '$.profiles')
        WHERE value <> 'observe'
    ) OR json_array_length(json_extract(NEW.capability_grant_json, '$.secretReferences')) <> 0
      OR json_array_length(json_extract(NEW.capability_grant_json, '$.networkDestinations')) <> 0
    THEN RAISE(ABORT, 'validator context has effect, secret, or network authority') END;
END;

CREATE TRIGGER validation_record_fresh_context_insert
BEFORE INSERT ON validation_record
WHEN NEW.method = 'fresh_context_model'
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM run validator
        JOIN task validator_task ON validator_task.id = validator.task_id
        JOIN validation_context_manifest manifest ON manifest.id = NEW.context_manifest_id
        WHERE validator.id = NEW.validator_run_id
          AND validator.task_id = NEW.validator_task_id
          AND validator.parent_run_id = NEW.producer_run_id
          AND validator.agent_role = 'validator'
          AND validator_task.parent_task_id = NEW.task_id
          AND manifest.task_id = NEW.task_id
          AND manifest.producer_run_id = NEW.producer_run_id
    ) THEN RAISE(ABORT, 'fresh-context validator lineage is invalid') END;
END;

CREATE TRIGGER task_validation_gate_update
BEFORE UPDATE OF status, validation_id ON task
WHEN NEW.status = 'succeeded' AND NEW.validation_required = 1
BEGIN
    SELECT CASE WHEN NEW.validation_id IS NULL OR NOT EXISTS(
        SELECT 1 FROM validation_record validation
        WHERE validation.id = NEW.validation_id
          AND validation.task_id = NEW.id
          AND validation.outcome IN ('passed', 'waived')
    ) THEN RAISE(ABORT, 'task success requires passing validation or waiver') END;
END;
