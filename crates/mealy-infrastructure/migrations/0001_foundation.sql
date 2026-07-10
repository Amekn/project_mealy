PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS session (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    principal_id TEXT NOT NULL CHECK (length(principal_id) > 0),
    channel_binding_id TEXT NOT NULL CHECK (length(channel_binding_id) > 0),
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'paused', 'closed')),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    inbox_mode TEXT NOT NULL DEFAULT 'queue'
        CHECK (inbox_mode IN ('queue', 'steer_at_boundary', 'interrupt_then_queue')),
    next_inbox_sequence INTEGER NOT NULL DEFAULT 1 CHECK (next_inbox_sequence > 0),
    active_turn_id TEXT,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    CHECK (updated_at_ms >= created_at_ms)
) STRICT;

CREATE TABLE IF NOT EXISTS session_inbox (
    inbox_entry_id TEXT PRIMARY KEY CHECK (length(inbox_entry_id) > 0),
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    dedupe_key TEXT NOT NULL CHECK (length(dedupe_key) > 0),
    delivery_mode TEXT NOT NULL
        CHECK (delivery_mode IN ('queue', 'steer_at_boundary', 'interrupt_then_queue')),
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'promoted')),
    content TEXT NOT NULL CHECK (length(content) > 0),
    admission_event_id TEXT NOT NULL UNIQUE CHECK (length(admission_event_id) > 0),
    acknowledgement_outbox_id TEXT NOT NULL UNIQUE
        CHECK (length(acknowledgement_outbox_id) > 0),
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) > 0),
    accepted_at_ms INTEGER NOT NULL,
    promoted_at_ms INTEGER,
    promoted_turn_id TEXT,
    UNIQUE (session_id, sequence),
    UNIQUE (session_id, dedupe_key),
    CHECK (
        (state = 'pending' AND promoted_at_ms IS NULL AND promoted_turn_id IS NULL)
        OR
        (state = 'promoted' AND promoted_at_ms IS NOT NULL AND promoted_turn_id IS NOT NULL)
    )
) STRICT;

CREATE TABLE IF NOT EXISTS task (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    status TEXT NOT NULL
        CHECK (status IN (
            'queued', 'running', 'waiting', 'paused', 'cancelling',
            'succeeded', 'failed', 'cancelled'
        )),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    validation_required INTEGER NOT NULL CHECK (validation_required IN (0, 1)),
    validation_id TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS run (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    task_id TEXT NOT NULL REFERENCES task(id) ON DELETE CASCADE,
    parent_run_id TEXT REFERENCES run(id) ON DELETE RESTRICT,
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN (
            'queued', 'running', 'waiting', 'succeeded', 'failed', 'cancelled'
        )),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    agent_role TEXT NOT NULL CHECK (length(agent_role) > 0),
    capability_ceiling_json TEXT NOT NULL CHECK (json_valid(capability_ceiling_json)),
    budget_json TEXT NOT NULL CHECK (json_valid(budget_json)),
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) > 0),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER,
    CHECK (parent_run_id IS NULL OR parent_run_id <> id),
    CHECK (updated_at_ms >= created_at_ms),
    CHECK (completed_at_ms IS NULL OR completed_at_ms >= created_at_ms),
    CHECK (
        (status IN ('succeeded', 'failed', 'cancelled') AND completed_at_ms IS NOT NULL)
        OR
        (status NOT IN ('succeeded', 'failed', 'cancelled') AND completed_at_ms IS NULL)
    )
) STRICT;

CREATE TABLE IF NOT EXISTS work_lease (
    lease_id TEXT PRIMARY KEY CHECK (length(lease_id) > 0),
    run_id TEXT NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    owner_id TEXT NOT NULL CHECK (length(owner_id) > 0),
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    state TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'released', 'expired')),
    acquired_at_ms INTEGER NOT NULL,
    heartbeat_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    released_at_ms INTEGER,
    UNIQUE (run_id, fencing_token),
    CHECK (heartbeat_at_ms >= acquired_at_ms),
    CHECK (expires_at_ms > heartbeat_at_ms),
    CHECK (
        (state = 'active' AND released_at_ms IS NULL)
        OR
        (state IN ('released', 'expired') AND released_at_ms IS NOT NULL)
    ),
    CHECK (released_at_ms IS NULL OR released_at_ms >= acquired_at_ms)
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS work_lease_one_active_per_run_idx
    ON work_lease (run_id)
    WHERE state = 'active';

CREATE INDEX IF NOT EXISTS work_lease_expiry_idx
    ON work_lease (state, expires_at_ms);

CREATE INDEX IF NOT EXISTS work_lease_owner_idx
    ON work_lease (owner_id, state, expires_at_ms);

CREATE TABLE IF NOT EXISTS effect (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    task_id TEXT NOT NULL REFERENCES task(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'proposed'
        CHECK (status IN (
            'proposed', 'awaiting_approval', 'authorized', 'dispatching',
            'succeeded', 'failed', 'outcome_unknown', 'compensated', 'denied'
        )),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    tool_id TEXT NOT NULL CHECK (length(tool_id) > 0),
    tool_version TEXT NOT NULL CHECK (length(tool_version) > 0),
    normalized_arguments_json TEXT NOT NULL CHECK (json_valid(normalized_arguments_json)),
    subject_digest TEXT NOT NULL CHECK (length(subject_digest) > 0),
    policy_version TEXT,
    idempotency_class TEXT NOT NULL
        CHECK (idempotency_class IN ('pure', 'idempotent', 'keyed', 'non_idempotent')),
    idempotency_key TEXT,
    recovery_action TEXT NOT NULL
        CHECK (recovery_action IN ('retry', 'retry_with_same_key', 'reconcile')),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    dispatched_at_ms INTEGER,
    completed_at_ms INTEGER,
    CHECK (policy_version IS NULL OR length(policy_version) > 0),
    CHECK (idempotency_key IS NULL OR length(idempotency_key) > 0),
    CHECK (idempotency_class <> 'keyed' OR idempotency_key IS NOT NULL),
    CHECK (recovery_action <> 'retry_with_same_key' OR idempotency_class = 'keyed'),
    CHECK (
        idempotency_class <> 'keyed'
        OR recovery_action IN ('retry_with_same_key', 'reconcile')
    ),
    CHECK (idempotency_class <> 'non_idempotent' OR recovery_action = 'reconcile'),
    CHECK (updated_at_ms >= created_at_ms),
    CHECK (dispatched_at_ms IS NULL OR dispatched_at_ms >= created_at_ms),
    CHECK (completed_at_ms IS NULL OR completed_at_ms >= created_at_ms)
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS effect_idempotency_key_idx
    ON effect (idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS effect_recovery_idx
    ON effect (status, idempotency_class, updated_at_ms);

CREATE TABLE IF NOT EXISTS aggregate_sequence (
    aggregate_kind TEXT NOT NULL CHECK (length(aggregate_kind) > 0),
    aggregate_id TEXT NOT NULL CHECK (length(aggregate_id) > 0),
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    PRIMARY KEY (aggregate_kind, aggregate_id)
) STRICT;

CREATE TABLE IF NOT EXISTS journal_event (
    event_id TEXT PRIMARY KEY CHECK (length(event_id) > 0),
    aggregate_kind TEXT NOT NULL CHECK (length(aggregate_kind) > 0),
    aggregate_id TEXT NOT NULL CHECK (length(aggregate_id) > 0),
    aggregate_sequence INTEGER NOT NULL CHECK (aggregate_sequence >= 0),
    event_type TEXT NOT NULL CHECK (length(event_type) > 0),
    event_version INTEGER NOT NULL CHECK (event_version > 0),
    occurred_at_ms INTEGER NOT NULL,
    actor_principal_id TEXT,
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) > 0),
    causation_id TEXT CHECK (causation_id IS NULL OR length(causation_id) > 0),
    policy_version TEXT CHECK (policy_version IS NULL OR length(policy_version) > 0),
    sensitivity TEXT NOT NULL DEFAULT 'internal' CHECK (length(sensitivity) > 0),
    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
    UNIQUE (aggregate_kind, aggregate_id, aggregate_sequence)
) STRICT;

CREATE TABLE IF NOT EXISTS outbox (
    outbox_id TEXT PRIMARY KEY CHECK (length(outbox_id) > 0),
    topic TEXT NOT NULL CHECK (length(topic) > 0),
    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
    created_at_ms INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'delivering', 'delivered', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at_ms INTEGER
) STRICT;

CREATE INDEX IF NOT EXISTS session_inbox_pending_idx
    ON session_inbox (session_id, state, sequence);

CREATE INDEX IF NOT EXISTS run_runnable_idx
    ON run (status, updated_at_ms);

CREATE INDEX IF NOT EXISTS journal_event_aggregate_idx
    ON journal_event (aggregate_kind, aggregate_id, aggregate_sequence);

CREATE INDEX IF NOT EXISTS journal_event_timeline_idx
    ON journal_event (occurred_at_ms, event_id);

CREATE INDEX IF NOT EXISTS outbox_pending_idx
    ON outbox (state, next_attempt_at_ms, created_at_ms);
