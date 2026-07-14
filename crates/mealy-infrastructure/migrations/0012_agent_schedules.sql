PRAGMA foreign_keys = ON;

CREATE TABLE agent_schedule (
    schedule_id TEXT PRIMARY KEY CHECK (length(schedule_id) > 0),
    principal_id TEXT NOT NULL REFERENCES principal_registry(principal_id) ON DELETE RESTRICT,
    channel_binding_id TEXT NOT NULL CHECK (length(channel_binding_id) > 0),
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128 AND trim(name) = name),
    prompt TEXT NOT NULL CHECK (length(prompt) BETWEEN 1 AND 65536),
    cron_expression TEXT NOT NULL CHECK (length(cron_expression) BETWEEN 1 AND 256),
    timezone TEXT NOT NULL CHECK (length(timezone) BETWEEN 1 AND 128),
    missed_run_policy TEXT NOT NULL CHECK (missed_run_policy IN ('skip', 'latest')),
    overlap_policy TEXT NOT NULL CHECK (overlap_policy IN ('queue', 'skip_if_running')),
    misfire_grace_ms INTEGER NOT NULL CHECK (misfire_grace_ms BETWEEN 0 AND 86400000),
    approval_required_actions_allowed INTEGER NOT NULL
        CHECK (approval_required_actions_allowed IN (0, 1)),
    status TEXT NOT NULL CHECK (status IN ('active', 'paused', 'cancelled')),
    next_due_at_ms INTEGER,
    revision INTEGER NOT NULL CHECK (revision >= 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    CHECK (
        (status = 'cancelled' AND next_due_at_ms IS NULL)
        OR (status IN ('active', 'paused') AND next_due_at_ms IS NOT NULL AND next_due_at_ms >= 0)
    )
) STRICT;

CREATE INDEX agent_schedule_due_idx
    ON agent_schedule(status, next_due_at_ms, created_at_ms, schedule_id);
CREATE INDEX agent_schedule_owner_idx
    ON agent_schedule(principal_id, channel_binding_id, created_at_ms, schedule_id);

CREATE TRIGGER agent_schedule_session_owner_insert
BEFORE INSERT ON agent_schedule
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM session
        WHERE id = NEW.session_id
          AND principal_id = NEW.principal_id
          AND channel_binding_id = NEW.channel_binding_id
          AND status <> 'closed'
    ) THEN RAISE(ABORT, 'schedule session ownership is invalid') END;
END;

CREATE TRIGGER agent_schedule_definition_immutable
BEFORE UPDATE ON agent_schedule
BEGIN
    SELECT CASE WHEN NEW.schedule_id <> OLD.schedule_id
        OR NEW.principal_id <> OLD.principal_id
        OR NEW.channel_binding_id <> OLD.channel_binding_id
        OR NEW.session_id <> OLD.session_id
        OR NEW.name <> OLD.name
        OR NEW.prompt <> OLD.prompt
        OR NEW.cron_expression <> OLD.cron_expression
        OR NEW.timezone <> OLD.timezone
        OR NEW.missed_run_policy <> OLD.missed_run_policy
        OR NEW.overlap_policy <> OLD.overlap_policy
        OR NEW.misfire_grace_ms <> OLD.misfire_grace_ms
        OR NEW.approval_required_actions_allowed <> OLD.approval_required_actions_allowed
        OR NEW.created_at_ms <> OLD.created_at_ms
        OR NEW.revision <> OLD.revision + 1
        OR NEW.updated_at_ms < OLD.updated_at_ms
        OR OLD.status = 'cancelled'
    THEN RAISE(ABORT, 'invalid schedule transition') END;
END;

CREATE TRIGGER agent_schedule_immutable_delete
BEFORE DELETE ON agent_schedule
BEGIN
    SELECT RAISE(ABORT, 'schedule audit history cannot be removed');
END;

CREATE TABLE agent_schedule_run (
    schedule_run_id TEXT PRIMARY KEY CHECK (length(schedule_run_id) > 0),
    schedule_id TEXT NOT NULL REFERENCES agent_schedule(schedule_id) ON DELETE RESTRICT,
    scheduled_for_ms INTEGER NOT NULL CHECK (scheduled_for_ms >= 0),
    coalesced INTEGER NOT NULL CHECK (coalesced IN (0, 1)),
    intent TEXT NOT NULL CHECK (intent IN ('fire', 'skip_misfire', 'skip_overlap')),
    status TEXT NOT NULL CHECK (status IN ('claimed', 'admitted', 'skipped', 'failed')),
    claim_owner_id TEXT NOT NULL CHECK (length(claim_owner_id) > 0),
    claim_expires_at_ms INTEGER NOT NULL,
    inbox_entry_id TEXT REFERENCES session_inbox(inbox_entry_id) ON DELETE RESTRICT,
    reason TEXT CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 4096),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    completed_at_ms INTEGER,
    UNIQUE(schedule_id, scheduled_for_ms),
    CHECK (claim_expires_at_ms > created_at_ms),
    CHECK (
        (status = 'claimed' AND inbox_entry_id IS NULL AND reason IS NULL AND completed_at_ms IS NULL)
        OR (status = 'admitted' AND inbox_entry_id IS NOT NULL AND reason IS NULL
            AND completed_at_ms IS NOT NULL AND completed_at_ms >= created_at_ms)
        OR (status IN ('skipped', 'failed') AND inbox_entry_id IS NULL AND reason IS NOT NULL
            AND completed_at_ms IS NOT NULL AND completed_at_ms >= created_at_ms)
    )
) STRICT;

CREATE INDEX agent_schedule_run_history_idx
    ON agent_schedule_run(schedule_id, scheduled_for_ms DESC, schedule_run_id DESC);
CREATE INDEX agent_schedule_run_claim_idx
    ON agent_schedule_run(status, claim_expires_at_ms, schedule_run_id);

CREATE TRIGGER agent_schedule_run_transition
BEFORE UPDATE ON agent_schedule_run
BEGIN
    SELECT CASE WHEN NEW.schedule_run_id <> OLD.schedule_run_id
        OR NEW.schedule_id <> OLD.schedule_id
        OR NEW.scheduled_for_ms <> OLD.scheduled_for_ms
        OR NEW.coalesced < OLD.coalesced
        OR NEW.intent <> OLD.intent
        OR NEW.created_at_ms <> OLD.created_at_ms
        OR OLD.status <> 'claimed'
        OR NEW.status NOT IN ('claimed', 'admitted', 'skipped', 'failed')
    THEN RAISE(ABORT, 'invalid schedule run transition') END;
END;

CREATE TRIGGER agent_schedule_run_immutable_delete
BEFORE DELETE ON agent_schedule_run
BEGIN
    SELECT RAISE(ABORT, 'schedule run history cannot be removed');
END;
