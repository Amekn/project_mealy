CREATE TABLE effect_intent (
    effect_id TEXT PRIMARY KEY REFERENCES effect(id) ON DELETE RESTRICT,
    principal_id TEXT NOT NULL CHECK (length(principal_id) > 0),
    channel_binding_id TEXT NOT NULL CHECK (length(channel_binding_id) > 0),
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES task(id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES run(id) ON DELETE RESTRICT,
    intent_json TEXT NOT NULL
        CHECK (json_valid(intent_json) AND length(intent_json) BETWEEN 2 AND 65536),
    intent_digest TEXT NOT NULL CHECK (
        length(intent_digest) = 64 AND intent_digest NOT GLOB '*[^0-9a-f]*'
    ),
    descriptor_json TEXT NOT NULL
        CHECK (json_valid(descriptor_json) AND length(descriptor_json) BETWEEN 2 AND 65536),
    descriptor_digest TEXT NOT NULL CHECK (
        length(descriptor_digest) = 64 AND descriptor_digest NOT GLOB '*[^0-9a-f]*'
    ),
    normalized_arguments_json TEXT NOT NULL
        CHECK (json_valid(normalized_arguments_json) AND length(normalized_arguments_json) <= 65536),
    arguments_digest TEXT NOT NULL CHECK (
        length(arguments_digest) = 64 AND arguments_digest NOT GLOB '*[^0-9a-f]*'
    ),
    capability_scope TEXT NOT NULL CHECK (length(capability_scope) BETWEEN 1 AND 512),
    target_resources_json TEXT NOT NULL CHECK (
        json_valid(target_resources_json)
        AND json_type(target_resources_json) = 'array'
        AND json_array_length(target_resources_json) > 0
        AND length(target_resources_json) <= 32768
    ),
    executable_identity_digest TEXT NOT NULL CHECK (
        length(executable_identity_digest) = 64
        AND executable_identity_digest NOT GLOB '*[^0-9a-f]*'
    ),
    effect_class TEXT NOT NULL
        CHECK (effect_class IN ('read_only', 'reversible', 'idempotent', 'non_idempotent')),
    risk_class TEXT NOT NULL CHECK (risk_class IN ('low', 'medium', 'high')),
    executor_kind TEXT NOT NULL CHECK (length(executor_kind) BETWEEN 1 AND 256),
    idempotency_class TEXT NOT NULL
        CHECK (idempotency_class IN ('pure', 'idempotent', 'keyed', 'non_idempotent')),
    recovery_strategy TEXT NOT NULL
        CHECK (recovery_strategy IN ('retry', 'reconcile', 'compensate', 'never_retry')),
    idempotency_key TEXT CHECK (idempotency_key IS NULL OR length(idempotency_key) <= 256),
    created_at_ms INTEGER NOT NULL,
    UNIQUE (effect_id, run_id),
    CHECK (
        (idempotency_class = 'keyed'
         AND idempotency_key = 'mealy-effect-v1:' || effect_id)
        OR
        (idempotency_class <> 'keyed' AND idempotency_key IS NULL)
    ),
    CHECK (
        (effect_class = 'read_only'
         AND idempotency_class = 'pure' AND recovery_strategy = 'retry')
        OR
        (effect_class IN ('idempotent', 'reversible')
         AND idempotency_class = 'idempotent'
         AND recovery_strategy IN ('retry', 'never_retry'))
        OR
        (effect_class IN ('idempotent', 'reversible')
         AND idempotency_class = 'keyed'
         AND recovery_strategy IN ('retry', 'reconcile', 'never_retry'))
        OR
        (effect_class IN ('non_idempotent', 'reversible')
         AND idempotency_class = 'non_idempotent'
         AND recovery_strategy IN ('reconcile', 'never_retry'))
        OR
        (effect_class = 'reversible'
         AND idempotency_class IN ('idempotent', 'keyed', 'non_idempotent')
         AND recovery_strategy = 'compensate')
    )
) STRICT;

CREATE TABLE effect_policy_evaluation (
    effect_id TEXT PRIMARY KEY REFERENCES effect_intent(effect_id) ON DELETE RESTRICT,
    request_json TEXT NOT NULL
        CHECK (json_valid(request_json) AND length(request_json) BETWEEN 2 AND 131072),
    request_digest TEXT NOT NULL CHECK (
        length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'
    ),
    decision TEXT NOT NULL CHECK (decision IN ('deny', 'allow', 'require_approval')),
    obligations_json TEXT NOT NULL
        CHECK (json_valid(obligations_json) AND length(obligations_json) BETWEEN 2 AND 65536),
    obligations_digest TEXT NOT NULL CHECK (
        length(obligations_digest) = 64 AND obligations_digest NOT GLOB '*[^0-9a-f]*'
    ),
    policy_version TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 512),
    explanation TEXT NOT NULL CHECK (length(explanation) BETWEEN 1 AND 1024),
    evaluated_at_ms INTEGER NOT NULL,
    CHECK (evaluated_at_ms >= 0),
    CHECK (
        decision <> 'deny'
        OR
        (
            json_array_length(obligations_json, '$.readablePaths') = 0
            AND json_array_length(obligations_json, '$.writablePaths') = 0
            AND json_array_length(
                obligations_json, '$.allowedExecutableIdentityDigests'
            ) = 0
            AND json_extract(obligations_json, '$.allowProcessSpawn') = 0
            AND json_array_length(
                obligations_json, '$.allowedEnvironmentVariables'
            ) = 0
            AND json_array_length(obligations_json, '$.networkDestinations') = 0
            AND json_array_length(obligations_json, '$.secretReferences') = 0
            AND json_type(obligations_json, '$.argumentRewrite') = 'null'
            AND json_array_length(obligations_json, '$.redactions') = 0
            AND json_extract(obligations_json, '$.maximumDurationMs') = 0
            AND json_extract(obligations_json, '$.maximumOutputBytes') = 0
            AND json_extract(obligations_json, '$.maximumMemoryBytes') = 0
            AND json_extract(obligations_json, '$.maximumProcesses') = 0
            AND json_extract(obligations_json, '$.validatorRequired') = 0
        )
    )
) STRICT;

CREATE TABLE approval_request (
    approval_id TEXT PRIMARY KEY CHECK (length(approval_id) > 0),
    effect_id TEXT NOT NULL UNIQUE REFERENCES effect_intent(effect_id) ON DELETE RESTRICT,
    principal_id TEXT NOT NULL CHECK (length(principal_id) > 0),
    task_id TEXT NOT NULL REFERENCES task(id) ON DELETE RESTRICT,
    subject_json TEXT NOT NULL
        CHECK (json_valid(subject_json) AND length(subject_json) BETWEEN 2 AND 65536),
    subject_digest TEXT NOT NULL CHECK (
        length(subject_digest) = 64 AND subject_digest NOT GLOB '*[^0-9a-f]*'
    ),
    policy_version TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 512),
    status TEXT NOT NULL
        CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'revoked')),
    decision TEXT CHECK (decision IS NULL OR decision IN ('approve', 'deny')),
    decided_by_principal_id TEXT
        CHECK (decided_by_principal_id IS NULL OR length(decided_by_principal_id) > 0),
    requested_event_id TEXT NOT NULL UNIQUE
        REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    decision_event_id TEXT UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    requested_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    resolved_at_ms INTEGER,
    CHECK (expires_at_ms > requested_at_ms),
    CHECK (
        (status = 'pending' AND decision IS NULL AND decided_by_principal_id IS NULL
         AND decision_event_id IS NULL AND resolved_at_ms IS NULL)
        OR
        (status = 'approved' AND decision = 'approve' AND decided_by_principal_id IS NOT NULL
         AND decision_event_id IS NOT NULL AND resolved_at_ms IS NOT NULL
         AND resolved_at_ms < expires_at_ms)
        OR
        (status = 'denied' AND decision = 'deny' AND decided_by_principal_id IS NOT NULL
         AND decision_event_id IS NOT NULL AND resolved_at_ms IS NOT NULL
         AND resolved_at_ms < expires_at_ms)
        OR
        (status = 'expired' AND decision IS NULL AND decided_by_principal_id IS NULL
         AND decision_event_id IS NOT NULL AND resolved_at_ms IS NOT NULL
         AND resolved_at_ms >= expires_at_ms)
        OR
        (status = 'revoked' AND decision IS NULL AND decided_by_principal_id IS NOT NULL
         AND decision_event_id IS NOT NULL AND resolved_at_ms IS NOT NULL)
    ),
    CHECK (resolved_at_ms IS NULL OR resolved_at_ms >= requested_at_ms)
) STRICT;

CREATE INDEX approval_request_pending_idx
    ON approval_request(status, requested_at_ms, approval_id);

CREATE TABLE effect_attempt (
    attempt_id TEXT PRIMARY KEY CHECK (length(attempt_id) > 0),
    effect_id TEXT NOT NULL REFERENCES effect_intent(effect_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal > 0),
    state TEXT NOT NULL
        CHECK (state IN (
            'prepared', 'running', 'succeeded', 'failed', 'outcome_unknown',
            'interrupted_retryable', 'interrupted_undispatched'
        )),
    idempotency_key TEXT CHECK (idempotency_key IS NULL OR length(idempotency_key) <= 256),
    prepared_lease_id TEXT NOT NULL CHECK (length(prepared_lease_id) > 0),
    prepared_owner_id TEXT NOT NULL CHECK (length(prepared_owner_id) > 0),
    prepared_fencing_token INTEGER NOT NULL CHECK (prepared_fencing_token > 0),
    prepared_event_id TEXT NOT NULL UNIQUE
        REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    started_event_id TEXT UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    terminal_event_id TEXT UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    prepared_at_ms INTEGER NOT NULL,
    started_at_ms INTEGER,
    completed_at_ms INTEGER,
    error_class TEXT CHECK (error_class IS NULL OR length(error_class) BETWEEN 1 AND 128),
    UNIQUE (effect_id, ordinal),
    UNIQUE (attempt_id, effect_id),
    CHECK (started_at_ms IS NULL OR started_at_ms >= prepared_at_ms),
    CHECK (completed_at_ms IS NULL OR completed_at_ms >= COALESCE(started_at_ms, prepared_at_ms)),
    CHECK (
        (state = 'prepared' AND started_event_id IS NULL AND terminal_event_id IS NULL
         AND started_at_ms IS NULL AND completed_at_ms IS NULL AND error_class IS NULL)
        OR
        (state = 'running' AND started_event_id IS NOT NULL AND terminal_event_id IS NULL
         AND started_at_ms IS NOT NULL AND completed_at_ms IS NULL AND error_class IS NULL)
        OR
        (state = 'interrupted_undispatched' AND started_event_id IS NULL
         AND terminal_event_id IS NOT NULL AND started_at_ms IS NULL
         AND completed_at_ms IS NOT NULL AND error_class IS NOT NULL)
        OR
        (state IN ('succeeded', 'failed', 'outcome_unknown', 'interrupted_retryable')
         AND started_event_id IS NOT NULL AND terminal_event_id IS NOT NULL
         AND started_at_ms IS NOT NULL AND completed_at_ms IS NOT NULL
         AND (state = 'succeeded' OR error_class IS NOT NULL))
    ),
    FOREIGN KEY (
        prepared_lease_id, effect_id, prepared_owner_id, prepared_fencing_token
    ) REFERENCES effect_attempt_fence(
        lease_id, effect_id, owner_id, fencing_token
    ) ON DELETE RESTRICT
) STRICT;

-- This table binds an effect attempt to the exact active run lease without weakening the existing
-- lease graph. The fenced prepare transaction populates it before any adapter may be invoked.
CREATE TABLE effect_attempt_fence (
    lease_id TEXT NOT NULL,
    effect_id TEXT NOT NULL REFERENCES effect_intent(effect_id) ON DELETE RESTRICT,
    owner_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    run_id TEXT NOT NULL,
    PRIMARY KEY (lease_id, effect_id, owner_id, fencing_token),
    FOREIGN KEY (lease_id, run_id, owner_id, fencing_token)
        REFERENCES work_lease(lease_id, run_id, owner_id, fencing_token) ON DELETE RESTRICT,
    FOREIGN KEY (effect_id, run_id)
        REFERENCES effect_intent(effect_id, run_id) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX effect_attempt_one_unsettled_idx
    ON effect_attempt(effect_id)
    WHERE state IN ('prepared', 'running', 'outcome_unknown');

CREATE UNIQUE INDEX effect_attempt_one_unsettled_per_lease_idx
    ON effect_attempt(prepared_lease_id, prepared_owner_id, prepared_fencing_token)
    WHERE state IN ('prepared', 'running', 'outcome_unknown');

CREATE INDEX effect_attempt_recovery_idx
    ON effect_attempt(state, prepared_at_ms, effect_id, ordinal);

CREATE TABLE effect_outcome (
    attempt_id TEXT NOT NULL,
    effect_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    outcome_kind TEXT NOT NULL
        CHECK (outcome_kind IN ('succeeded', 'failed', 'outcome_unknown', 'compensated')),
    evidence_json TEXT NOT NULL
        CHECK (json_valid(evidence_json) AND length(evidence_json) BETWEEN 2 AND 65536),
    evidence_digest TEXT NOT NULL CHECK (
        length(evidence_digest) = 64 AND evidence_digest NOT GLOB '*[^0-9a-f]*'
    ),
    event_id TEXT NOT NULL UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    recorded_at_ms INTEGER NOT NULL,
    PRIMARY KEY (attempt_id, sequence),
    FOREIGN KEY (attempt_id, effect_id)
        REFERENCES effect_attempt(attempt_id, effect_id) ON DELETE RESTRICT,
    CHECK (
        (sequence = 0 AND outcome_kind IN ('succeeded', 'failed', 'outcome_unknown'))
        OR
        (sequence > 0 AND outcome_kind IN ('succeeded', 'failed', 'compensated'))
    )
) STRICT;

CREATE TRIGGER effect_intent_graph_insert
BEFORE INSERT ON effect_intent
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM effect e
        JOIN run r ON r.id = e.run_id AND r.task_id = e.task_id
        JOIN turn t ON t.run_id = r.id AND t.task_id = r.task_id
        JOIN session s ON s.id = t.session_id
        WHERE e.id = NEW.effect_id
          AND e.task_id = NEW.task_id
          AND e.run_id = NEW.run_id
          AND e.tool_id = json_extract(NEW.descriptor_json, '$.toolId')
          AND e.tool_version = json_extract(NEW.descriptor_json, '$.version')
          AND e.normalized_arguments_json = NEW.normalized_arguments_json
          AND e.subject_digest = NEW.intent_digest
          AND e.policy_version = json_extract(NEW.intent_json, '$.policyVersion')
          AND e.idempotency_class = NEW.idempotency_class
          AND e.created_at_ms = NEW.created_at_ms
          AND s.id = NEW.session_id
          AND s.principal_id = NEW.principal_id
          AND s.channel_binding_id = NEW.channel_binding_id
    ) THEN RAISE(ABORT, 'effect intent graph or evidence does not match') END;
END;

CREATE TRIGGER effect_intent_immutable_update
BEFORE UPDATE ON effect_intent
BEGIN
    SELECT RAISE(ABORT, 'effect intent is immutable');
END;

CREATE TRIGGER effect_intent_immutable_delete
BEFORE DELETE ON effect_intent
BEGIN
    SELECT RAISE(ABORT, 'effect intent is immutable');
END;

CREATE TRIGGER effect_policy_evaluation_insert
BEFORE INSERT ON effect_policy_evaluation
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM effect e
        JOIN effect_intent intent ON intent.effect_id = e.id
        WHERE e.id = NEW.effect_id
          AND intent.principal_id = json_extract(NEW.request_json, '$.principalId')
          AND intent.channel_binding_id = json_extract(NEW.request_json, '$.channelBindingId')
          AND intent.task_id = json_extract(NEW.request_json, '$.taskId')
          AND intent.run_id = json_extract(NEW.request_json, '$.runId')
          AND intent.descriptor_digest = json_extract(NEW.request_json, '$.tool.descriptorDigest')
          AND intent.normalized_arguments_json = json_extract(NEW.request_json, '$.normalizedArguments')
          AND intent.capability_scope = json_extract(NEW.request_json, '$.requestedCapability')
          AND intent.target_resources_json = json_extract(NEW.request_json, '$.targetResources')
          AND intent.created_at_ms = NEW.evaluated_at_ms
          AND NEW.policy_version = json_extract(NEW.request_json, '$.policyVersion')
          AND e.policy_version = NEW.policy_version
          AND (
              (NEW.decision = 'deny' AND e.status = 'denied')
              OR (NEW.decision = 'allow' AND e.status = 'authorized')
              OR (NEW.decision = 'require_approval' AND e.status = 'awaiting_approval')
          )
    ) THEN RAISE(ABORT, 'policy evidence does not match effect intent') END;
END;

CREATE TRIGGER effect_policy_evaluation_immutable_update
BEFORE UPDATE ON effect_policy_evaluation
BEGIN
    SELECT RAISE(ABORT, 'effect policy evidence is immutable');
END;

CREATE TRIGGER effect_policy_evaluation_immutable_delete
BEFORE DELETE ON effect_policy_evaluation
BEGIN
    SELECT RAISE(ABORT, 'effect policy evidence is immutable');
END;

CREATE TRIGGER approval_request_insert_guard
BEFORE INSERT ON approval_request
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM effect e
        JOIN effect_intent intent ON intent.effect_id = e.id
        JOIN effect_policy_evaluation policy ON policy.effect_id = e.id
        WHERE e.id = NEW.effect_id
          AND e.status = 'awaiting_approval'
          AND policy.decision = 'require_approval'
          AND intent.principal_id = NEW.principal_id
          AND intent.task_id = NEW.task_id
          AND intent.effect_id = json_extract(NEW.subject_json, '$.effectId')
          AND intent.principal_id = json_extract(NEW.subject_json, '$.principalId')
          AND intent.task_id = json_extract(NEW.subject_json, '$.taskId')
          AND json_extract(intent.descriptor_json, '$.toolId') = json_extract(
              NEW.subject_json, '$.toolId'
          )
          AND json_extract(intent.descriptor_json, '$.version') = json_extract(
              NEW.subject_json, '$.toolVersion'
          )
          AND intent.arguments_digest = json_extract(
              NEW.subject_json, '$.canonicalArgumentsDigest'
          )
          AND intent.capability_scope = json_extract(NEW.subject_json, '$.capabilityScope')
          AND intent.target_resources_json = json_extract(NEW.subject_json, '$.targetResources')
          AND intent.executable_identity_digest = json_extract(
              NEW.subject_json, '$.executableIdentityDigest'
          )
          AND policy.policy_version = NEW.policy_version
          AND policy.policy_version = json_extract(NEW.subject_json, '$.policyVersion')
          AND NEW.expires_at_ms = json_extract(NEW.subject_json, '$.expiresAtMs')
    ) THEN RAISE(ABORT, 'approval subject does not match effect intent') END;
END;

CREATE TRIGGER approval_request_subject_immutable
BEFORE UPDATE OF
    approval_id, effect_id, principal_id, task_id, subject_json, subject_digest,
    policy_version, requested_event_id, requested_at_ms, expires_at_ms
ON approval_request
BEGIN
    SELECT RAISE(ABORT, 'approval subject is immutable');
END;

CREATE TRIGGER approval_request_transition_guard
BEFORE UPDATE OF status ON approval_request
WHEN NEW.status <> OLD.status
BEGIN
    SELECT CASE WHEN OLD.status <> 'pending'
        OR NEW.status NOT IN ('approved', 'denied', 'expired', 'revoked')
        THEN RAISE(ABORT, 'invalid approval transition') END;
END;

CREATE TRIGGER approval_request_immutable_delete
BEFORE DELETE ON approval_request
BEGIN
    SELECT RAISE(ABORT, 'approval history is immutable');
END;

CREATE TRIGGER effect_phase3_preparation_immutable
BEFORE UPDATE OF
    id, task_id, run_id, tool_id, tool_version, normalized_arguments_json, subject_digest,
    policy_version, idempotency_class, idempotency_key, recovery_action, created_at_ms
ON effect
WHEN EXISTS(SELECT 1 FROM effect_intent WHERE effect_id = OLD.id)
BEGIN
    SELECT RAISE(ABORT, 'effect preparation is immutable');
END;

CREATE TRIGGER effect_phase3_transition_guard
BEFORE UPDATE OF status ON effect
WHEN NEW.status <> OLD.status
  AND EXISTS(SELECT 1 FROM effect_intent WHERE effect_id = OLD.id)
BEGIN
    SELECT CASE WHEN NOT (
        (OLD.status = 'awaiting_approval' AND NEW.status = 'authorized' AND EXISTS(
            SELECT 1 FROM approval_request
            WHERE effect_id = OLD.id AND status = 'approved'
        ))
        OR
        (OLD.status = 'awaiting_approval' AND NEW.status = 'denied' AND EXISTS(
            SELECT 1 FROM approval_request
            WHERE effect_id = OLD.id AND status IN ('denied', 'expired', 'revoked')
        ))
        OR
        (OLD.status = 'authorized' AND NEW.status = 'dispatching' AND EXISTS(
            SELECT 1 FROM effect_attempt
            WHERE effect_id = OLD.id AND state = 'prepared'
        ))
        OR
        (OLD.status = 'dispatching' AND NEW.status = 'authorized' AND EXISTS(
            SELECT 1
            FROM effect_attempt attempt
            JOIN effect_outcome outcome
              ON outcome.attempt_id = attempt.attempt_id AND outcome.effect_id = attempt.effect_id
            JOIN journal_event event ON event.event_id = outcome.event_id
            JOIN effect_intent intent ON intent.effect_id = attempt.effect_id
            WHERE attempt.effect_id = OLD.id AND attempt.state = 'running'
              AND outcome.sequence = 0 AND outcome.outcome_kind = 'outcome_unknown'
              AND event.event_type = 'effect.retry_authorized'
              AND intent.recovery_strategy = 'retry'
              AND intent.idempotency_class IN ('pure', 'idempotent', 'keyed')
        ))
        OR
        (OLD.status = 'dispatching' AND NEW.status IN ('succeeded', 'failed', 'outcome_unknown')
         AND EXISTS(
            SELECT 1 FROM effect_attempt attempt
            JOIN effect_outcome outcome
              ON outcome.attempt_id = attempt.attempt_id AND outcome.effect_id = attempt.effect_id
            WHERE attempt.effect_id = OLD.id AND attempt.state = 'running'
              AND outcome.sequence = 0 AND outcome.outcome_kind = NEW.status
         ))
        OR
        (OLD.status = 'outcome_unknown' AND NEW.status IN ('succeeded', 'failed', 'compensated')
         AND EXISTS(
            SELECT 1 FROM effect_attempt attempt
            JOIN effect_outcome outcome
              ON outcome.attempt_id = attempt.attempt_id AND outcome.effect_id = attempt.effect_id
            WHERE attempt.effect_id = OLD.id AND attempt.state = 'outcome_unknown'
              AND outcome.sequence > 0 AND outcome.outcome_kind = NEW.status
         ))
    ) THEN RAISE(ABORT, 'invalid or unsupported effect transition') END;
END;

CREATE TRIGGER effect_phase3_revision_guard
BEFORE UPDATE ON effect
WHEN EXISTS(SELECT 1 FROM effect_intent WHERE effect_id = OLD.id)
BEGIN
    SELECT CASE WHEN NEW.revision <> OLD.revision + 1
        THEN RAISE(ABORT, 'effect revision must advance exactly once') END;
    SELECT CASE WHEN NEW.updated_at_ms < OLD.updated_at_ms
        THEN RAISE(ABORT, 'effect update time cannot move backwards') END;
    SELECT CASE WHEN OLD.status = 'authorized' AND NEW.status = 'authorized'
        AND (
            NEW.dispatched_at_ms IS NOT OLD.dispatched_at_ms
            OR NEW.completed_at_ms IS NOT OLD.completed_at_ms
        )
        THEN RAISE(ABORT, 'effect preparation cannot cross dispatch') END;
    SELECT CASE WHEN OLD.status = 'authorized' AND NEW.status = 'dispatching'
        AND (
            NEW.dispatched_at_ms IS NULL
            OR NEW.dispatched_at_ms <> NEW.updated_at_ms
            OR NEW.completed_at_ms IS NOT NULL
        )
        THEN RAISE(ABORT, 'effect dispatch timestamps are invalid') END;
    SELECT CASE WHEN OLD.status = 'dispatching'
        AND NEW.status = 'authorized'
        AND (
            NEW.dispatched_at_ms IS NOT OLD.dispatched_at_ms
            OR NEW.completed_at_ms IS NOT OLD.completed_at_ms
        )
        THEN RAISE(ABORT, 'retry authorization cannot rewrite dispatch history') END;
    SELECT CASE WHEN OLD.status = 'dispatching'
        AND NEW.status IN ('succeeded', 'failed', 'outcome_unknown')
        AND (
            NEW.dispatched_at_ms IS NOT OLD.dispatched_at_ms
            OR NEW.completed_at_ms IS NULL
            OR NEW.completed_at_ms <> NEW.updated_at_ms
        )
        THEN RAISE(ABORT, 'effect outcome timestamps are invalid') END;
    SELECT CASE WHEN OLD.status = 'outcome_unknown'
        AND NEW.status IN ('succeeded', 'failed', 'compensated')
        AND (
            NEW.dispatched_at_ms IS NOT OLD.dispatched_at_ms
            OR NEW.completed_at_ms IS NOT OLD.completed_at_ms
        )
        THEN RAISE(ABORT, 'reconciliation cannot rewrite dispatch history') END;
END;

CREATE TRIGGER effect_attempt_fence_insert_guard
BEFORE INSERT ON effect_attempt_fence
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM effect_intent intent
        WHERE intent.effect_id = NEW.effect_id AND intent.run_id = NEW.run_id
    ) THEN RAISE(ABORT, 'effect attempt fence uses the wrong run') END;
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM work_lease lease
        JOIN run ON run.id = lease.run_id
        WHERE lease.lease_id = NEW.lease_id
          AND lease.run_id = NEW.run_id
          AND lease.owner_id = NEW.owner_id
          AND lease.fencing_token = NEW.fencing_token
          AND lease.state = 'active'
          AND run.status = 'running'
          AND run.current_fencing_token = NEW.fencing_token
    ) THEN RAISE(ABORT, 'effect attempt fence is not active and current') END;
END;

CREATE TRIGGER effect_attempt_fence_immutable_update
BEFORE UPDATE ON effect_attempt_fence
BEGIN
    SELECT RAISE(ABORT, 'effect attempt fence is immutable');
END;

CREATE TRIGGER effect_attempt_fence_immutable_delete
BEFORE DELETE ON effect_attempt_fence
BEGIN
    SELECT RAISE(ABORT, 'effect attempt fence history is immutable');
END;

CREATE TRIGGER effect_attempt_insert_guard
BEFORE INSERT ON effect_attempt
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM effect e
        JOIN effect_intent intent ON intent.effect_id = e.id
        WHERE e.id = NEW.effect_id
          AND e.status = 'authorized'
          AND NEW.idempotency_key IS intent.idempotency_key
    ) THEN RAISE(ABORT, 'effect attempt is not exactly authorized') END;
    SELECT CASE WHEN EXISTS(
        SELECT 1 FROM effect_attempt
        WHERE effect_id = NEW.effect_id AND state IN ('prepared', 'running', 'outcome_unknown')
    ) THEN RAISE(ABORT, 'effect already has unsettled external work') END;
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM effect_attempt_fence fence
        JOIN work_lease lease
          ON lease.lease_id = fence.lease_id
         AND lease.run_id = fence.run_id
         AND lease.owner_id = fence.owner_id
         AND lease.fencing_token = fence.fencing_token
        WHERE fence.lease_id = NEW.prepared_lease_id
          AND fence.effect_id = NEW.effect_id
          AND fence.owner_id = NEW.prepared_owner_id
          AND fence.fencing_token = NEW.prepared_fencing_token
          AND lease.state = 'active'
          AND lease.acquired_at_ms <= NEW.prepared_at_ms
          AND NEW.prepared_at_ms < lease.expires_at_ms
    ) THEN RAISE(ABORT, 'effect attempt preparation is outside its active fence') END;
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM journal_event event
        JOIN timeline_event timeline ON timeline.event_id = event.event_id
        WHERE event.event_id = NEW.prepared_event_id
          AND event.aggregate_kind = 'effect'
          AND event.aggregate_id = NEW.effect_id
          AND event.event_type = 'effect.attempt_prepared'
          AND event.event_version = 1
          AND event.occurred_at_ms = NEW.prepared_at_ms
          AND event.sensitivity = 'internal'
    ) THEN RAISE(ABORT, 'effect attempt preparation event is invalid') END;
END;

CREATE TRIGGER effect_attempt_state_guard
BEFORE UPDATE OF state ON effect_attempt
WHEN NEW.state <> OLD.state
BEGIN
    SELECT CASE WHEN NOT (
        (OLD.state = 'prepared' AND NEW.state = 'running'
         AND EXISTS(SELECT 1 FROM effect WHERE id = OLD.effect_id AND status = 'dispatching'))
        OR
        (OLD.state = 'prepared' AND NEW.state = 'interrupted_undispatched'
         AND EXISTS(SELECT 1 FROM effect WHERE id = OLD.effect_id AND status = 'authorized'))
        OR
        (OLD.state = 'running' AND NEW.state = 'interrupted_retryable'
         AND EXISTS(SELECT 1 FROM effect WHERE id = OLD.effect_id AND status = 'authorized'))
        OR
        (OLD.state = 'running' AND NEW.state IN ('succeeded', 'failed', 'outcome_unknown')
         AND EXISTS(
            SELECT 1 FROM effect
            WHERE id = OLD.effect_id AND status = NEW.state
         ))
    ) THEN RAISE(ABORT, 'invalid effect attempt transition') END;
    SELECT CASE WHEN OLD.state = 'prepared' AND NEW.state = 'running' AND NOT EXISTS(
        SELECT 1
        FROM journal_event event
        JOIN timeline_event timeline ON timeline.event_id = event.event_id
        WHERE event.event_id = NEW.started_event_id
          AND event.aggregate_kind = 'effect'
          AND event.aggregate_id = OLD.effect_id
          AND event.event_type = 'effect.dispatched'
          AND event.event_version = 1
          AND event.occurred_at_ms = NEW.started_at_ms
          AND event.sensitivity = 'internal'
    ) THEN RAISE(ABORT, 'effect dispatch event is invalid') END;
    SELECT CASE WHEN OLD.state = 'prepared' AND NEW.state = 'interrupted_undispatched'
        AND NOT EXISTS(
            SELECT 1
            FROM journal_event event
            JOIN timeline_event timeline ON timeline.event_id = event.event_id
            WHERE event.event_id = NEW.terminal_event_id
              AND event.aggregate_kind = 'effect'
              AND event.aggregate_id = OLD.effect_id
              AND event.event_type = 'effect.preparation_interrupted'
              AND event.event_version = 1
              AND event.occurred_at_ms = NEW.completed_at_ms
              AND event.sensitivity = 'internal'
        ) THEN RAISE(ABORT, 'interrupted effect preparation event is invalid') END;
    SELECT CASE WHEN OLD.state = 'running'
        AND NEW.state IN ('succeeded', 'failed', 'outcome_unknown', 'interrupted_retryable')
        AND NOT EXISTS(
            SELECT 1
            FROM effect_outcome outcome
            JOIN journal_event event ON event.event_id = outcome.event_id
            JOIN timeline_event timeline ON timeline.event_id = event.event_id
            WHERE outcome.attempt_id = OLD.attempt_id
              AND outcome.effect_id = OLD.effect_id
              AND outcome.sequence = 0
              AND outcome.outcome_kind = CASE NEW.state
                  WHEN 'interrupted_retryable' THEN 'outcome_unknown'
                  ELSE NEW.state
              END
              AND event.event_id = NEW.terminal_event_id
              AND event.aggregate_kind = 'effect'
              AND event.aggregate_id = OLD.effect_id
              AND event.event_type = CASE NEW.state
                  WHEN 'succeeded' THEN 'effect.succeeded'
                  WHEN 'failed' THEN 'effect.failed'
                  WHEN 'interrupted_retryable' THEN 'effect.retry_authorized'
                  ELSE 'effect.outcome_unknown'
              END
              AND event.event_version = 1
              AND event.occurred_at_ms = NEW.completed_at_ms
              AND event.sensitivity = 'internal'
        ) THEN RAISE(ABORT, 'effect terminal event is invalid') END;
END;

CREATE TRIGGER effect_attempt_preparation_immutable
BEFORE UPDATE OF
    attempt_id, effect_id, ordinal, idempotency_key, prepared_lease_id, prepared_owner_id,
    prepared_fencing_token, prepared_event_id, prepared_at_ms
ON effect_attempt
BEGIN
    SELECT RAISE(ABORT, 'effect attempt preparation is immutable');
END;

CREATE TRIGGER effect_attempt_immutable_delete
BEFORE DELETE ON effect_attempt
BEGIN
    SELECT RAISE(ABORT, 'effect attempt history is immutable');
END;

CREATE TRIGGER effect_outcome_immutable_update
BEFORE UPDATE ON effect_outcome
BEGIN
    SELECT RAISE(ABORT, 'effect outcome evidence is immutable');
END;

CREATE TRIGGER effect_outcome_insert_guard
BEFORE INSERT ON effect_outcome
BEGIN
    SELECT CASE WHEN NOT (
        (NEW.sequence = 0 AND EXISTS(
            SELECT 1
            FROM effect_attempt attempt
            JOIN effect ON effect.id = attempt.effect_id
            WHERE attempt.attempt_id = NEW.attempt_id
              AND attempt.effect_id = NEW.effect_id
              AND attempt.state = 'running'
              AND effect.status = 'dispatching'
        ))
        OR
        (NEW.sequence = 1 AND NEW.outcome_kind IN ('succeeded', 'failed', 'compensated')
         AND EXISTS(
            SELECT 1
            FROM effect_attempt attempt
            JOIN effect ON effect.id = attempt.effect_id
            JOIN effect_outcome initial
              ON initial.attempt_id = attempt.attempt_id
             AND initial.effect_id = attempt.effect_id
             AND initial.sequence = 0
            WHERE attempt.attempt_id = NEW.attempt_id
              AND attempt.effect_id = NEW.effect_id
              AND attempt.state = 'outcome_unknown'
              AND effect.status = 'outcome_unknown'
              AND initial.outcome_kind = 'outcome_unknown'
        ))
    ) THEN RAISE(ABORT, 'effect outcome is outside its exact lifecycle boundary') END;
    SELECT CASE WHEN json_extract(NEW.evidence_json, '$.contractVersion')
            IS NOT 'mealy.effect-outcome-evidence.v1'
        OR json_extract(NEW.evidence_json, '$.attemptId') IS NOT NEW.attempt_id
        OR json_extract(NEW.evidence_json, '$.effectId') IS NOT NEW.effect_id
        OR json_extract(NEW.evidence_json, '$.sequence') IS NOT NEW.sequence
        OR json_extract(NEW.evidence_json, '$.outcomeKind') IS NOT NEW.outcome_kind
        OR json_extract(NEW.evidence_json, '$.recordedAtMs') IS NOT NEW.recorded_at_ms
        OR json_type(NEW.evidence_json, '$.evidence') IS NOT 'object'
        OR NOT EXISTS(SELECT 1 FROM json_each(NEW.evidence_json, '$.evidence'))
        THEN RAISE(ABORT, 'effect outcome evidence envelope is invalid') END;
    SELECT CASE WHEN NOT (
        (NEW.sequence = 0 AND NEW.outcome_kind = 'succeeded'
         AND json_type(NEW.evidence_json, '$.errorClass') IS 'null')
        OR
        (NEW.sequence = 0 AND NEW.outcome_kind IN ('failed', 'outcome_unknown')
         AND json_type(NEW.evidence_json, '$.errorClass') IS 'text'
         AND length(json_extract(NEW.evidence_json, '$.errorClass')) BETWEEN 1 AND 128)
        OR
        (NEW.sequence = 1 AND json_type(NEW.evidence_json, '$.errorClass') IS 'null')
    ) THEN RAISE(ABORT, 'effect outcome error classification is invalid') END;
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM journal_event event
        JOIN timeline_event timeline ON timeline.event_id = event.event_id
        WHERE event.event_id = NEW.event_id
          AND event.aggregate_kind = 'effect'
          AND event.aggregate_id = NEW.effect_id
          AND event.event_version = 1
          AND event.occurred_at_ms = NEW.recorded_at_ms
          AND event.sensitivity = 'internal'
          AND (
              (NEW.sequence > 0 AND event.event_type = 'effect.reconciled')
              OR (NEW.sequence = 0 AND NEW.outcome_kind = 'succeeded'
                  AND event.event_type = 'effect.succeeded')
              OR (NEW.sequence = 0 AND NEW.outcome_kind = 'failed'
                  AND event.event_type = 'effect.failed')
              OR (NEW.sequence = 0 AND NEW.outcome_kind = 'outcome_unknown'
                  AND event.event_type IN ('effect.outcome_unknown', 'effect.retry_authorized'))
          )
    ) THEN RAISE(ABORT, 'effect outcome journal event is invalid') END;
END;

CREATE TRIGGER effect_outcome_immutable_delete
BEFORE DELETE ON effect_outcome
BEGIN
    SELECT RAISE(ABORT, 'effect outcome evidence is immutable');
END;

CREATE VIEW effect_recovery_candidate AS
SELECT
    attempt.attempt_id,
    attempt.effect_id,
    attempt.ordinal,
    attempt.state AS boundary,
    intent.idempotency_class,
    intent.recovery_strategy,
    intent.idempotency_key,
    attempt.prepared_at_ms,
    CASE
        WHEN attempt.state = 'prepared' THEN 'resume_prepared'
        WHEN attempt.state = 'outcome_unknown' AND intent.recovery_strategy = 'compensate'
            THEN 'requires_compensation'
        WHEN attempt.state = 'outcome_unknown' AND intent.recovery_strategy = 'never_retry'
            THEN 'terminally_failed'
        WHEN attempt.state = 'outcome_unknown' THEN 'requires_reconciliation'
        WHEN intent.recovery_strategy = 'compensate' THEN 'requires_compensation'
        WHEN intent.recovery_strategy = 'never_retry' THEN 'terminally_failed'
        WHEN intent.idempotency_class = 'keyed' AND intent.recovery_strategy = 'retry'
            THEN 'retry_with_same_key'
        WHEN intent.idempotency_class IN ('pure', 'idempotent')
             AND intent.recovery_strategy = 'retry' THEN 'retry'
        ELSE 'requires_reconciliation'
    END AS disposition
FROM effect_attempt attempt
JOIN effect_intent intent ON intent.effect_id = attempt.effect_id
JOIN effect ON effect.id = attempt.effect_id
WHERE (attempt.state = 'prepared' AND effect.status = 'authorized')
   OR (attempt.state = 'running' AND effect.status = 'dispatching')
   OR (attempt.state = 'outcome_unknown' AND effect.status = 'outcome_unknown');
