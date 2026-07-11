PRAGMA foreign_keys = ON;

-- Each process lifetime records the exact non-secret configuration/policy identity and recovery
-- result before readiness. A missing terminal update is classified as unclean by the next start.
CREATE TABLE daemon_run_record (
    start_id TEXT PRIMARY KEY CHECK (length(start_id) > 0),
    principal_id TEXT NOT NULL REFERENCES principal_registry(principal_id) ON DELETE RESTRICT,
    config_digest TEXT NOT NULL CHECK (
        length(config_digest) = 64 AND config_digest NOT GLOB '*[^0-9a-f]*'
    ),
    policy_bundle_digest TEXT NOT NULL CHECK (
        length(policy_bundle_digest) = 64 AND policy_bundle_digest NOT GLOB '*[^0-9a-f]*'
    ),
    safe_mode INTEGER NOT NULL CHECK (safe_mode IN (0, 1)),
    recovery_counts_json TEXT NOT NULL CHECK (
        json_valid(recovery_counts_json) AND json_type(recovery_counts_json) = 'object'
    ),
    status TEXT NOT NULL CHECK (status IN ('running', 'clean', 'forced', 'unclean')),
    started_at_ms INTEGER NOT NULL CHECK (started_at_ms >= 0),
    ready_at_ms INTEGER NOT NULL CHECK (ready_at_ms >= started_at_ms),
    completed_at_ms INTEGER,
    completion_reason TEXT CHECK (
        completion_reason IS NULL OR length(completion_reason) BETWEEN 1 AND 4096
    ),
    CHECK (
        (status = 'running' AND completed_at_ms IS NULL AND completion_reason IS NULL)
        OR
        (status IN ('clean', 'forced', 'unclean')
         AND completed_at_ms IS NOT NULL AND completed_at_ms >= ready_at_ms
         AND completion_reason IS NOT NULL)
    )
) STRICT;

CREATE INDEX daemon_run_recent_idx ON daemon_run_record(started_at_ms DESC, start_id DESC);
CREATE UNIQUE INDEX daemon_run_one_active_idx ON daemon_run_record(status) WHERE status = 'running';

CREATE TRIGGER daemon_run_terminal_transition
BEFORE UPDATE ON daemon_run_record
BEGIN
    SELECT CASE WHEN NEW.start_id <> OLD.start_id
        OR NEW.principal_id <> OLD.principal_id
        OR NEW.config_digest <> OLD.config_digest
        OR NEW.policy_bundle_digest <> OLD.policy_bundle_digest
        OR NEW.safe_mode <> OLD.safe_mode
        OR NEW.recovery_counts_json <> OLD.recovery_counts_json
        OR NEW.started_at_ms <> OLD.started_at_ms
        OR NEW.ready_at_ms <> OLD.ready_at_ms
        OR OLD.status <> 'running'
        OR NEW.status NOT IN ('clean', 'forced', 'unclean')
    THEN RAISE(ABORT, 'invalid daemon run terminal transition') END;
END;

CREATE TRIGGER daemon_run_immutable_delete
BEFORE DELETE ON daemon_run_record
BEGIN
    SELECT RAISE(ABORT, 'daemon run evidence cannot be removed');
END;
