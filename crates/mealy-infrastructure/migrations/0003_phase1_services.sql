CREATE TABLE timeline_retention (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    earliest_available_cursor INTEGER NOT NULL CHECK (earliest_available_cursor > 0),
    updated_at_ms INTEGER NOT NULL
) STRICT;

INSERT INTO timeline_retention(singleton, earliest_available_cursor, updated_at_ms)
VALUES (1, 1, 0);

ALTER TABLE outbox ADD COLUMN delivery_owner_id TEXT
    CHECK (delivery_owner_id IS NULL OR length(delivery_owner_id) > 0);
ALTER TABLE outbox ADD COLUMN delivery_started_at_ms INTEGER;
ALTER TABLE outbox ADD COLUMN delivered_at_ms INTEGER;
ALTER TABLE outbox ADD COLUMN last_error TEXT
    CHECK (last_error IS NULL OR length(last_error) > 0);

CREATE INDEX outbox_delivery_recovery_idx
    ON outbox (state, delivery_started_at_ms, outbox_id);

ALTER TABLE run ADD COLUMN cancellation_requested_at_ms INTEGER;
ALTER TABLE run ADD COLUMN result_json TEXT CHECK (result_json IS NULL OR json_valid(result_json));
ALTER TABLE session_inbox ADD COLUMN interrupt_requested_at_ms INTEGER;

CREATE TABLE run_input (
    run_id TEXT NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    inbox_entry_id TEXT NOT NULL UNIQUE
        REFERENCES session_inbox(inbox_entry_id) ON DELETE RESTRICT,
    inbox_sequence INTEGER NOT NULL CHECK (inbox_sequence > 0),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'consumed')),
    attached_at_ms INTEGER NOT NULL,
    consumed_at_ms INTEGER,
    PRIMARY KEY (run_id, inbox_sequence),
    CHECK (
        (state = 'pending' AND consumed_at_ms IS NULL)
        OR
        (state = 'consumed' AND consumed_at_ms IS NOT NULL)
    ),
    CHECK (consumed_at_ms IS NULL OR consumed_at_ms >= attached_at_ms)
) STRICT;

CREATE INDEX run_input_pending_idx ON run_input (run_id, state, inbox_sequence);

CREATE TRIGGER session_active_turn_reference_insert
BEFORE INSERT ON session
WHEN NEW.active_turn_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM turn
        WHERE id = NEW.active_turn_id AND session_id = NEW.id AND status = 'active'
    ) THEN RAISE(ABORT, 'session active turn is invalid') END;
END;

CREATE TRIGGER session_active_turn_reference_update
BEFORE UPDATE OF active_turn_id ON session
WHEN NEW.active_turn_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM turn
        WHERE id = NEW.active_turn_id AND session_id = NEW.id AND status = 'active'
    ) THEN RAISE(ABORT, 'session active turn is invalid') END;
END;

CREATE TRIGGER inbox_promoted_turn_reference
BEFORE UPDATE OF state, promoted_turn_id ON session_inbox
WHEN NEW.state = 'promoted'
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM turn
        WHERE id = NEW.promoted_turn_id
          AND session_id = NEW.session_id
          AND inbox_entry_id = NEW.inbox_entry_id
        UNION ALL
        SELECT 1 FROM run_input ri
        JOIN turn t ON t.run_id = ri.run_id
        WHERE ri.inbox_entry_id = NEW.inbox_entry_id
          AND t.id = NEW.promoted_turn_id
          AND t.session_id = NEW.session_id
    ) THEN RAISE(ABORT, 'inbox promoted turn is invalid') END;
END;

CREATE TRIGGER turn_graph_reference_insert
BEFORE INSERT ON turn
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM session_inbox i
        WHERE i.inbox_entry_id = NEW.inbox_entry_id AND i.session_id = NEW.session_id
    ) THEN RAISE(ABORT, 'turn inbox/session graph is invalid') END;
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM run r WHERE r.id = NEW.run_id AND r.task_id = NEW.task_id
    ) THEN RAISE(ABORT, 'turn run/task graph is invalid') END;
END;

CREATE TRIGGER turn_reference_delete
BEFORE DELETE ON turn
WHEN EXISTS(SELECT 1 FROM session WHERE active_turn_id = OLD.id)
  OR EXISTS(SELECT 1 FROM session_inbox WHERE promoted_turn_id = OLD.id)
BEGIN
    SELECT RAISE(ABORT, 'turn is still referenced');
END;
