CREATE TABLE IF NOT EXISTS turn (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    inbox_entry_id TEXT NOT NULL UNIQUE
        REFERENCES session_inbox(inbox_entry_id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL UNIQUE REFERENCES task(id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL UNIQUE REFERENCES run(id) ON DELETE RESTRICT,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'completed', 'failed', 'cancelled')),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) > 0),
    created_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER,
    CHECK (
        (status = 'active' AND completed_at_ms IS NULL)
        OR
        (status IN ('completed', 'failed', 'cancelled') AND completed_at_ms IS NOT NULL)
    ),
    CHECK (completed_at_ms IS NULL OR completed_at_ms >= created_at_ms)
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS turn_one_active_per_session_idx
    ON turn (session_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS timeline_event (
    cursor INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE
        REFERENCES journal_event(event_id) ON DELETE RESTRICT
) STRICT;

INSERT OR IGNORE INTO timeline_event(event_id)
SELECT event_id
FROM journal_event
-- A v1 journal has no explicit global commit sequence. SQLite rowid is the only persisted
-- insertion order and therefore the least surprising deterministic upgrade order.
ORDER BY rowid;

CREATE TRIGGER IF NOT EXISTS journal_event_timeline_insert
AFTER INSERT ON journal_event
BEGIN
    INSERT INTO timeline_event(event_id) VALUES (NEW.event_id);
END;

CREATE INDEX IF NOT EXISTS timeline_event_event_idx
    ON timeline_event (event_id);
