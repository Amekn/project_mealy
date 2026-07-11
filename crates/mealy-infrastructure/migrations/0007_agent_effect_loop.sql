CREATE UNIQUE INDEX agent_effect_run_task_reference_idx ON run(id, task_id);

CREATE TABLE agent_effect_invocation (
    effect_id TEXT PRIMARY KEY REFERENCES effect_intent(effect_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES run(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES task(id) ON DELETE RESTRICT,
    model_attempt_id TEXT NOT NULL UNIQUE REFERENCES model_attempt(attempt_id) ON DELETE RESTRICT,
    tool_call_id TEXT NOT NULL UNIQUE CHECK (length(tool_call_id) > 0),
    created_at_ms INTEGER NOT NULL,
    UNIQUE (effect_id, run_id),
    FOREIGN KEY (effect_id, run_id)
        REFERENCES effect_intent(effect_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (model_attempt_id, run_id)
        REFERENCES model_attempt(attempt_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, task_id)
        REFERENCES run(id, task_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX agent_effect_invocation_resume_idx
    ON agent_effect_invocation(run_id, created_at_ms, effect_id);

ALTER TABLE message ADD COLUMN source_effect_id TEXT REFERENCES effect(id) ON DELETE RESTRICT;

CREATE TABLE agent_effect_observation (
    effect_id TEXT PRIMARY KEY
        REFERENCES agent_effect_invocation(effect_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES run(id) ON DELETE RESTRICT,
    model_attempt_id TEXT NOT NULL UNIQUE
        REFERENCES model_attempt(attempt_id) ON DELETE RESTRICT,
    tool_call_id TEXT NOT NULL UNIQUE CHECK (length(tool_call_id) > 0),
    message_id TEXT NOT NULL UNIQUE REFERENCES message(id) ON DELETE RESTRICT,
    effect_revision INTEGER NOT NULL CHECK (effect_revision >= 0),
    content_json TEXT NOT NULL CHECK (
        json_valid(content_json)
        AND json_type(content_json) = 'object'
        AND length(content_json) BETWEEN 2 AND 65536
    ),
    content_digest TEXT NOT NULL CHECK (
        length(content_digest) = 64 AND content_digest NOT GLOB '*[^0-9a-f]*'
    ),
    created_at_ms INTEGER NOT NULL,
    UNIQUE (effect_id, run_id),
    FOREIGN KEY (effect_id, run_id)
        REFERENCES agent_effect_invocation(effect_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (model_attempt_id, run_id)
        REFERENCES model_attempt(attempt_id, run_id) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER agent_effect_invocation_origin_insert
BEFORE INSERT ON agent_effect_invocation
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM effect_intent intent
        JOIN effect ON effect.id = intent.effect_id
        JOIN model_attempt attempt ON attempt.attempt_id = NEW.model_attempt_id
        WHERE intent.effect_id = NEW.effect_id
          AND intent.run_id = NEW.run_id
          AND intent.task_id = NEW.task_id
          AND effect.task_id = NEW.task_id
          AND effect.run_id = NEW.run_id
          AND attempt.run_id = NEW.run_id
          AND attempt.state = 'completed'
          AND attempt.response_kind = 'tool_call'
          AND json_extract(attempt.response_json, '$.kind') = 'tool_call'
          AND json_extract(attempt.response_json, '$.tool_id') = effect.tool_id
          AND json(json_extract(attempt.response_json, '$.arguments'))
              = json(intent.normalized_arguments_json)
    ) THEN RAISE(ABORT, 'agent effect origin does not match normalized model result') END;
END;

CREATE TRIGGER agent_effect_invocation_immutable
BEFORE UPDATE ON agent_effect_invocation
BEGIN
    SELECT RAISE(ABORT, 'agent effect invocation is immutable');
END;

CREATE TRIGGER message_effect_source_insert
BEFORE INSERT ON message
WHEN NEW.source_effect_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NEW.role <> 'tool'
        OR NEW.source_attempt_id IS NOT NULL
        OR NEW.source_tool_call_id IS NOT NULL
        OR NOT EXISTS(
            SELECT 1 FROM agent_effect_invocation invocation
            WHERE invocation.effect_id = NEW.source_effect_id
              AND invocation.run_id = NEW.run_id
        )
    THEN RAISE(ABORT, 'message effect source is invalid') END;
END;

CREATE TRIGGER message_effect_source_update
BEFORE UPDATE OF source_effect_id, source_attempt_id, source_tool_call_id, role, run_id ON message
WHEN OLD.source_effect_id IS NOT NULL OR NEW.source_effect_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'message effect source is immutable');
END;

CREATE TRIGGER agent_effect_observation_insert
BEFORE INSERT ON agent_effect_observation
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM agent_effect_invocation invocation
        JOIN message ON message.id = NEW.message_id
        WHERE invocation.effect_id = NEW.effect_id
          AND invocation.run_id = NEW.run_id
          AND invocation.model_attempt_id = NEW.model_attempt_id
          AND invocation.tool_call_id = NEW.tool_call_id
          AND message.run_id = NEW.run_id
          AND message.source_effect_id = NEW.effect_id
          AND message.role = 'tool'
          AND message.content_inline = NEW.content_json
          AND message.content_digest = NEW.content_digest
    ) THEN RAISE(ABORT, 'agent effect observation provenance mismatch') END;
END;

CREATE TRIGGER agent_effect_observation_update_immutable
BEFORE UPDATE ON agent_effect_observation
BEGIN
    SELECT RAISE(ABORT, 'agent effect observation is immutable');
END;

CREATE TRIGGER agent_effect_observation_delete_immutable
BEFORE DELETE ON agent_effect_observation
BEGIN
    SELECT RAISE(ABORT, 'agent effect observation is immutable');
END;
