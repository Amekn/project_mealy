CREATE UNIQUE INDEX session_identity_reference_idx ON session(id, principal_id);
CREATE UNIQUE INDEX turn_context_graph_reference_idx
    ON turn(id, session_id, task_id, run_id);
CREATE UNIQUE INDEX turn_manifest_graph_reference_idx ON turn(id, session_id, run_id);
CREATE UNIQUE INDEX work_lease_fence_reference_idx
    ON work_lease(lease_id, run_id, owner_id, fencing_token);

CREATE TABLE context_epoch (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    epoch_number INTEGER NOT NULL CHECK (epoch_number > 0),
    baseline_version TEXT NOT NULL CHECK (length(baseline_version) BETWEEN 1 AND 128),
    baseline_digest TEXT NOT NULL CHECK (length(baseline_digest) = 64),
    baseline_text TEXT NOT NULL CHECK (length(baseline_text) BETWEEN 1 AND 65536),
    agent_profile_json TEXT NOT NULL
        CHECK (json_valid(agent_profile_json) AND length(agent_profile_json) <= 65536),
    workspace_identity TEXT NOT NULL CHECK (length(workspace_identity) BETWEEN 1 AND 2048),
    config_digest TEXT NOT NULL CHECK (length(config_digest) = 64),
    policy_digest TEXT NOT NULL CHECK (length(policy_digest) = 64),
    created_at_ms INTEGER NOT NULL,
    retired_at_ms INTEGER,
    UNIQUE (session_id, epoch_number),
    UNIQUE (id, session_id),
    CHECK (retired_at_ms IS NULL OR retired_at_ms >= created_at_ms)
) STRICT;

CREATE UNIQUE INDEX context_epoch_one_active_per_session_idx
    ON context_epoch(session_id) WHERE retired_at_ms IS NULL;

ALTER TABLE session ADD COLUMN current_context_epoch_id TEXT
    REFERENCES context_epoch(id) ON DELETE RESTRICT;
ALTER TABLE turn ADD COLUMN context_epoch_id TEXT
    REFERENCES context_epoch(id) ON DELETE RESTRICT;

CREATE TABLE artifact_blob (
    algorithm TEXT NOT NULL CHECK (algorithm = 'sha256'),
    digest TEXT NOT NULL CHECK (
        length(digest) = 64 AND digest NOT GLOB '*[^0-9a-f]*'
    ),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    relative_path TEXT NOT NULL CHECK (
        length(relative_path) BETWEEN 1 AND 256
        AND relative_path = algorithm || '/' || digest
        AND substr(relative_path, 1, 1) <> '/'
        AND instr(relative_path, char(92)) = 0
        AND relative_path <> '..'
        AND relative_path NOT LIKE '../%'
        AND relative_path NOT LIKE '%/../%'
        AND relative_path NOT LIKE '%/..'
        AND relative_path NOT LIKE '%//%'
    ),
    committed_at_ms INTEGER NOT NULL,
    PRIMARY KEY (algorithm, digest)
) STRICT;

CREATE TABLE artifact (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    blob_algorithm TEXT NOT NULL,
    blob_digest TEXT NOT NULL,
    principal_id TEXT NOT NULL CHECK (length(principal_id) > 0),
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE RESTRICT,
    media_type TEXT NOT NULL CHECK (length(media_type) BETWEEN 1 AND 255),
    origin_kind TEXT NOT NULL CHECK (length(origin_kind) BETWEEN 1 AND 64),
    origin_id TEXT NOT NULL CHECK (length(origin_id) BETWEEN 1 AND 255),
    producer_kind TEXT NOT NULL CHECK (length(producer_kind) BETWEEN 1 AND 64),
    producer_id TEXT NOT NULL CHECK (length(producer_id) BETWEEN 1 AND 255),
    sensitivity TEXT NOT NULL CHECK (length(sensitivity) BETWEEN 1 AND 64),
    retention_class TEXT NOT NULL CHECK (length(retention_class) BETWEEN 1 AND 64),
    access_policy_json TEXT NOT NULL
        CHECK (json_valid(access_policy_json) AND length(access_policy_json) <= 16384),
    access_policy_digest TEXT NOT NULL CHECK (length(access_policy_digest) = 64),
    created_at_ms INTEGER NOT NULL,
    UNIQUE (id, principal_id, session_id),
    FOREIGN KEY (session_id, principal_id)
        REFERENCES session(id, principal_id) ON DELETE RESTRICT,
    FOREIGN KEY (blob_algorithm, blob_digest)
        REFERENCES artifact_blob(algorithm, digest) ON DELETE RESTRICT
) STRICT;

CREATE INDEX artifact_owner_idx ON artifact(principal_id, session_id, created_at_ms, id);

CREATE TABLE artifact_reference (
    artifact_id TEXT NOT NULL REFERENCES artifact(id) ON DELETE RESTRICT,
    principal_id TEXT NOT NULL CHECK (length(principal_id) > 0),
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE RESTRICT,
    owner_kind TEXT NOT NULL CHECK (length(owner_kind) BETWEEN 1 AND 64),
    owner_id TEXT NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    relation TEXT NOT NULL CHECK (length(relation) BETWEEN 1 AND 64),
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (artifact_id, owner_kind, owner_id, relation),
    FOREIGN KEY (artifact_id, principal_id, session_id)
        REFERENCES artifact(id, principal_id, session_id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, principal_id)
        REFERENCES session(id, principal_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX artifact_reference_owner_idx
    ON artifact_reference(principal_id, session_id, owner_kind, owner_id, relation);

CREATE TABLE context_manifest (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    run_id TEXT NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE RESTRICT,
    turn_id TEXT NOT NULL REFERENCES turn(id) ON DELETE RESTRICT,
    epoch_id TEXT NOT NULL REFERENCES context_epoch(id) ON DELETE RESTRICT,
    iteration INTEGER NOT NULL CHECK (iteration > 0),
    compiler_version TEXT NOT NULL CHECK (length(compiler_version) BETWEEN 1 AND 128),
    provider_residency TEXT NOT NULL CHECK (length(provider_residency) BETWEEN 1 AND 128),
    token_budget INTEGER NOT NULL CHECK (token_budget > 0),
    total_token_estimate INTEGER NOT NULL CHECK (total_token_estimate >= 0),
    tool_schema_set_digest TEXT NOT NULL CHECK (length(tool_schema_set_digest) = 64),
    policy_version TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 128),
    projection_digest TEXT NOT NULL CHECK (length(projection_digest) = 64),
    created_at_ms INTEGER NOT NULL,
    UNIQUE (run_id, iteration),
    UNIQUE (id, run_id),
    CHECK (total_token_estimate <= token_budget),
    FOREIGN KEY (turn_id, session_id, run_id)
        REFERENCES turn(id, session_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (epoch_id, session_id)
        REFERENCES context_epoch(id, session_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE context_manifest_item (
    manifest_id TEXT NOT NULL REFERENCES context_manifest(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    item_id TEXT NOT NULL CHECK (length(item_id) BETWEEN 1 AND 255),
    disposition TEXT NOT NULL CHECK (disposition IN ('included', 'excluded', 'redacted')),
    source_type TEXT NOT NULL CHECK (length(source_type) BETWEEN 1 AND 64),
    source_locator TEXT NOT NULL CHECK (length(source_locator) BETWEEN 1 AND 1024),
    source_content_digest TEXT NOT NULL CHECK (length(source_content_digest) = 64),
    rendered_content_digest TEXT NOT NULL CHECK (length(rendered_content_digest) = 64),
    inclusion_reason TEXT NOT NULL CHECK (length(inclusion_reason) BETWEEN 1 AND 1024),
    sensitivity TEXT NOT NULL CHECK (length(sensitivity) BETWEEN 1 AND 64),
    token_estimate INTEGER NOT NULL CHECK (token_estimate >= 0),
    transformation TEXT NOT NULL CHECK (length(transformation) BETWEEN 1 AND 255),
    policy_decision TEXT NOT NULL CHECK (length(policy_decision) BETWEEN 1 AND 1024),
    content_text TEXT CHECK (content_text IS NULL OR length(content_text) <= 262144),
    content_artifact_id TEXT REFERENCES artifact(id) ON DELETE RESTRICT,
    PRIMARY KEY (manifest_id, ordinal),
    UNIQUE (manifest_id, item_id),
    CHECK (
        (disposition = 'included'
         AND ((content_text IS NOT NULL) <> (content_artifact_id IS NOT NULL)))
        OR
        (disposition IN ('excluded', 'redacted')
         AND content_text IS NULL AND content_artifact_id IS NULL)
    )
) STRICT;

CREATE TABLE message (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    principal_id TEXT NOT NULL CHECK (length(principal_id) > 0),
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    turn_id TEXT NOT NULL REFERENCES turn(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES task(id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES run(id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal > 0),
    role TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'tool', 'system')),
    media_type TEXT NOT NULL CHECK (length(media_type) BETWEEN 1 AND 255),
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
    content_inline TEXT CHECK (content_inline IS NULL OR length(content_inline) <= 65536),
    content_artifact_id TEXT REFERENCES artifact(id) ON DELETE RESTRICT,
    sensitivity TEXT NOT NULL CHECK (length(sensitivity) BETWEEN 1 AND 64),
    source_attempt_id TEXT REFERENCES model_attempt(attempt_id) ON DELETE RESTRICT,
    source_tool_call_id TEXT REFERENCES tool_call(tool_call_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL,
    UNIQUE (turn_id, ordinal),
    UNIQUE (id, run_id),
    CHECK ((content_inline IS NOT NULL) <> (content_artifact_id IS NOT NULL)),
    CHECK (NOT (source_attempt_id IS NOT NULL AND source_tool_call_id IS NOT NULL)),
    FOREIGN KEY (session_id, principal_id)
        REFERENCES session(id, principal_id) ON DELETE RESTRICT,
    FOREIGN KEY (content_artifact_id, principal_id, session_id)
        REFERENCES artifact(id, principal_id, session_id) ON DELETE RESTRICT,
    FOREIGN KEY (turn_id, session_id, task_id, run_id)
        REFERENCES turn(id, session_id, task_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (source_attempt_id, run_id)
        REFERENCES model_attempt(attempt_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (source_tool_call_id, run_id)
        REFERENCES tool_call(tool_call_id, run_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE model_attempt (
    attempt_id TEXT PRIMARY KEY CHECK (length(attempt_id) > 0),
    run_id TEXT NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal > 0),
    state TEXT NOT NULL
        CHECK (state IN ('prepared', 'dispatching', 'completed', 'failed', 'cancelled', 'interrupted')),
    retry_of_attempt_id TEXT REFERENCES model_attempt(attempt_id) ON DELETE RESTRICT,
    provider_id TEXT NOT NULL CHECK (length(provider_id) BETWEEN 1 AND 128),
    adapter_version TEXT NOT NULL CHECK (length(adapter_version) BETWEEN 1 AND 128),
    model_id TEXT NOT NULL CHECK (length(model_id) BETWEEN 1 AND 128),
    capability_snapshot_json TEXT NOT NULL
        CHECK (json_valid(capability_snapshot_json) AND length(capability_snapshot_json) <= 65536),
    capability_digest TEXT NOT NULL CHECK (length(capability_digest) = 64),
    context_manifest_id TEXT NOT NULL REFERENCES context_manifest(id) ON DELETE RESTRICT,
    routing_decision_json TEXT NOT NULL
        CHECK (json_valid(routing_decision_json) AND length(routing_decision_json) <= 16384),
    tool_schema_digests_json TEXT NOT NULL
        CHECK (json_valid(tool_schema_digests_json) AND length(tool_schema_digests_json) <= 16384),
    budget_reservation_json TEXT NOT NULL
        CHECK (json_valid(budget_reservation_json) AND length(budget_reservation_json) <= 16384),
    request_json TEXT NOT NULL CHECK (json_valid(request_json) AND length(request_json) <= 262144),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
    timeout_ms INTEGER NOT NULL CHECK (timeout_ms > 0),
    prepared_at_ms INTEGER NOT NULL,
    dispatched_at_ms INTEGER,
    deadline_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER,
    response_kind TEXT CHECK (response_kind IN ('final', 'tool_call')),
    response_json TEXT CHECK (
        response_json IS NULL OR (json_valid(response_json) AND length(response_json) <= 262144)
    ),
    response_artifact_id TEXT REFERENCES artifact(id) ON DELETE RESTRICT,
    response_digest TEXT CHECK (response_digest IS NULL OR length(response_digest) = 64),
    finish_reason TEXT CHECK (finish_reason IS NULL OR length(finish_reason) <= 128),
    error_class TEXT CHECK (error_class IS NULL OR length(error_class) <= 128),
    error_message TEXT CHECK (error_message IS NULL OR length(error_message) <= 4096),
    retryable INTEGER CHECK (retryable IS NULL OR retryable IN (0, 1)),
    retry_after_ms INTEGER,
    input_tokens INTEGER CHECK (input_tokens IS NULL OR input_tokens >= 0),
    output_tokens INTEGER CHECK (output_tokens IS NULL OR output_tokens >= 0),
    total_tokens INTEGER CHECK (total_tokens IS NULL OR total_tokens >= 0),
    cost_microunits INTEGER CHECK (cost_microunits IS NULL OR cost_microunits >= 0),
    provider_request_id TEXT CHECK (provider_request_id IS NULL OR length(provider_request_id) <= 255),
    prepared_lease_id TEXT NOT NULL CHECK (length(prepared_lease_id) > 0),
    prepared_owner_id TEXT NOT NULL CHECK (length(prepared_owner_id) > 0),
    prepared_fencing_token INTEGER NOT NULL CHECK (prepared_fencing_token > 0),
    UNIQUE (run_id, ordinal),
    UNIQUE (attempt_id, run_id),
    CHECK (deadline_at_ms > prepared_at_ms),
    CHECK (dispatched_at_ms IS NULL OR dispatched_at_ms >= prepared_at_ms),
    CHECK (dispatched_at_ms IS NULL OR dispatched_at_ms < deadline_at_ms),
    CHECK (completed_at_ms IS NULL OR completed_at_ms >= prepared_at_ms),
    CHECK (retry_after_ms IS NULL OR retry_after_ms >= 0),
    CHECK (retry_of_attempt_id IS NULL OR retry_of_attempt_id <> attempt_id),
    CHECK (
        (state = 'prepared' AND dispatched_at_ms IS NULL AND completed_at_ms IS NULL)
        OR
        (state = 'dispatching' AND dispatched_at_ms IS NOT NULL AND completed_at_ms IS NULL)
        OR
        (state = 'completed' AND completed_at_ms IS NOT NULL AND response_kind IS NOT NULL
         AND response_json IS NOT NULL AND response_digest IS NOT NULL
         AND input_tokens IS NOT NULL AND output_tokens IS NOT NULL
         AND total_tokens IS NOT NULL AND cost_microunits IS NOT NULL)
        OR
        (state = 'cancelled' AND completed_at_ms IS NOT NULL)
        OR
        (state IN ('failed', 'interrupted') AND completed_at_ms IS NOT NULL
         AND error_class IS NOT NULL)
    ),
    FOREIGN KEY (context_manifest_id, run_id)
        REFERENCES context_manifest(id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (retry_of_attempt_id, run_id)
        REFERENCES model_attempt(attempt_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (prepared_lease_id, run_id, prepared_owner_id, prepared_fencing_token)
        REFERENCES work_lease(lease_id, run_id, owner_id, fencing_token) ON DELETE RESTRICT
) STRICT;

CREATE INDEX model_attempt_recovery_idx
    ON model_attempt(state, dispatched_at_ms, prepared_at_ms, attempt_id);

CREATE TABLE tool_call (
    tool_call_id TEXT PRIMARY KEY CHECK (length(tool_call_id) > 0),
    tool_attempt_id TEXT NOT NULL UNIQUE CHECK (length(tool_attempt_id) > 0),
    run_id TEXT NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    model_attempt_id TEXT NOT NULL REFERENCES model_attempt(attempt_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal > 0),
    tool_id TEXT NOT NULL CHECK (length(tool_id) BETWEEN 1 AND 128),
    tool_version TEXT NOT NULL CHECK (length(tool_version) BETWEEN 1 AND 128),
    descriptor_digest TEXT NOT NULL CHECK (length(descriptor_digest) = 64),
    descriptor_json TEXT NOT NULL
        CHECK (json_valid(descriptor_json) AND length(descriptor_json) <= 65536),
    schema_digest TEXT NOT NULL CHECK (length(schema_digest) = 64),
    effect_class TEXT NOT NULL CHECK (effect_class = 'read_only'),
    risk_class TEXT NOT NULL CHECK (risk_class IN ('low', 'medium', 'high')),
    policy_version TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 128),
    policy_decision TEXT NOT NULL CHECK (length(policy_decision) BETWEEN 1 AND 1024),
    arguments_json TEXT NOT NULL
        CHECK (json_valid(arguments_json) AND length(arguments_json) <= 65536),
    arguments_digest TEXT NOT NULL CHECK (length(arguments_digest) = 64),
    state TEXT NOT NULL
        CHECK (state IN ('prepared', 'running', 'succeeded', 'failed', 'cancelled', 'interrupted')),
    timeout_ms INTEGER NOT NULL CHECK (timeout_ms > 0),
    prepared_at_ms INTEGER NOT NULL,
    started_at_ms INTEGER,
    completed_at_ms INTEGER,
    output_inline TEXT CHECK (output_inline IS NULL OR length(output_inline) <= 65536),
    output_artifact_id TEXT REFERENCES artifact(id) ON DELETE RESTRICT,
    output_digest TEXT CHECK (output_digest IS NULL OR length(output_digest) = 64),
    output_size_bytes INTEGER CHECK (output_size_bytes IS NULL OR output_size_bytes >= 0),
    output_media_type TEXT CHECK (output_media_type IS NULL OR length(output_media_type) <= 255),
    output_source_locator TEXT CHECK (
        output_source_locator IS NULL OR length(output_source_locator) BETWEEN 1 AND 2048
    ),
    error_class TEXT CHECK (error_class IS NULL OR length(error_class) <= 128),
    error_message TEXT CHECK (error_message IS NULL OR length(error_message) <= 4096),
    prepared_lease_id TEXT NOT NULL CHECK (length(prepared_lease_id) > 0),
    prepared_owner_id TEXT NOT NULL CHECK (length(prepared_owner_id) > 0),
    prepared_fencing_token INTEGER NOT NULL CHECK (prepared_fencing_token > 0),
    UNIQUE (run_id, ordinal),
    UNIQUE (tool_call_id, run_id),
    CHECK (started_at_ms IS NULL OR started_at_ms >= prepared_at_ms),
    CHECK (completed_at_ms IS NULL OR completed_at_ms >= COALESCE(started_at_ms, prepared_at_ms)),
    CHECK (
        (state = 'prepared' AND started_at_ms IS NULL AND completed_at_ms IS NULL)
        OR
        (state = 'running' AND started_at_ms IS NOT NULL AND completed_at_ms IS NULL)
        OR
        (state IN ('succeeded', 'failed', 'cancelled', 'interrupted')
         AND completed_at_ms IS NOT NULL)
    ),
    CHECK (
        (state <> 'succeeded' AND output_inline IS NULL AND output_artifact_id IS NULL
         AND output_digest IS NULL AND output_size_bytes IS NULL AND output_media_type IS NULL
         AND output_source_locator IS NULL)
        OR
        (state = 'succeeded'
         AND ((output_inline IS NOT NULL) <> (output_artifact_id IS NOT NULL))
         AND output_digest IS NOT NULL AND output_size_bytes IS NOT NULL
         AND output_media_type IS NOT NULL AND output_source_locator IS NOT NULL)
    ),
    FOREIGN KEY (model_attempt_id, run_id)
        REFERENCES model_attempt(attempt_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (prepared_lease_id, run_id, prepared_owner_id, prepared_fencing_token)
        REFERENCES work_lease(lease_id, run_id, owner_id, fencing_token) ON DELETE RESTRICT
) STRICT;

CREATE INDEX tool_call_recovery_idx ON tool_call(state, started_at_ms, prepared_at_ms, tool_call_id);

CREATE TABLE run_budget_usage (
    run_id TEXT PRIMARY KEY REFERENCES run(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    maximum_model_calls INTEGER NOT NULL CHECK (maximum_model_calls > 0),
    maximum_tool_calls INTEGER NOT NULL CHECK (maximum_tool_calls >= 0),
    maximum_retries INTEGER NOT NULL CHECK (maximum_retries >= 0),
    maximum_input_tokens INTEGER NOT NULL CHECK (maximum_input_tokens > 0),
    maximum_output_tokens INTEGER NOT NULL CHECK (maximum_output_tokens > 0),
    maximum_cost_microunits INTEGER NOT NULL CHECK (maximum_cost_microunits >= 0),
    maximum_output_bytes INTEGER NOT NULL CHECK (maximum_output_bytes > 0),
    maximum_wall_time_ms INTEGER NOT NULL CHECK (maximum_wall_time_ms > 0),
    used_model_calls INTEGER NOT NULL DEFAULT 0 CHECK (used_model_calls >= 0),
    reserved_model_calls INTEGER NOT NULL DEFAULT 0 CHECK (reserved_model_calls >= 0),
    used_tool_calls INTEGER NOT NULL DEFAULT 0 CHECK (used_tool_calls >= 0),
    reserved_tool_calls INTEGER NOT NULL DEFAULT 0 CHECK (reserved_tool_calls >= 0),
    used_retries INTEGER NOT NULL DEFAULT 0 CHECK (used_retries >= 0),
    used_input_tokens INTEGER NOT NULL DEFAULT 0 CHECK (used_input_tokens >= 0),
    reserved_input_tokens INTEGER NOT NULL DEFAULT 0 CHECK (reserved_input_tokens >= 0),
    used_output_tokens INTEGER NOT NULL DEFAULT 0 CHECK (used_output_tokens >= 0),
    reserved_output_tokens INTEGER NOT NULL DEFAULT 0 CHECK (reserved_output_tokens >= 0),
    used_cost_microunits INTEGER NOT NULL DEFAULT 0 CHECK (used_cost_microunits >= 0),
    reserved_cost_microunits INTEGER NOT NULL DEFAULT 0 CHECK (reserved_cost_microunits >= 0),
    used_output_bytes INTEGER NOT NULL DEFAULT 0 CHECK (used_output_bytes >= 0),
    reserved_output_bytes INTEGER NOT NULL DEFAULT 0 CHECK (reserved_output_bytes >= 0),
    started_at_ms INTEGER NOT NULL,
    deadline_at_ms INTEGER NOT NULL,
    cancellation_requested_at_ms INTEGER,
    cancellation_reason TEXT CHECK (cancellation_reason IS NULL OR length(cancellation_reason) <= 1024),
    CHECK (deadline_at_ms > started_at_ms),
    CHECK (used_model_calls + reserved_model_calls <= maximum_model_calls),
    CHECK (used_tool_calls + reserved_tool_calls <= maximum_tool_calls),
    CHECK (used_retries <= maximum_retries),
    CHECK (used_input_tokens + reserved_input_tokens <= maximum_input_tokens),
    CHECK (used_output_tokens + reserved_output_tokens <= maximum_output_tokens),
    CHECK (used_cost_microunits + reserved_cost_microunits <= maximum_cost_microunits),
    CHECK (used_output_bytes + reserved_output_bytes <= maximum_output_bytes),
    CHECK (cancellation_requested_at_ms IS NULL OR cancellation_requested_at_ms >= started_at_ms),
    CHECK (
        (cancellation_requested_at_ms IS NULL AND cancellation_reason IS NULL)
        OR
        (cancellation_requested_at_ms IS NOT NULL AND cancellation_reason IS NOT NULL
         AND length(cancellation_reason) > 0)
    )
) STRICT;

CREATE TABLE budget_reservation (
    attempt_id TEXT PRIMARY KEY REFERENCES model_attempt(attempt_id) ON DELETE RESTRICT,
    model_calls INTEGER NOT NULL CHECK (model_calls = 1),
    input_tokens INTEGER NOT NULL CHECK (input_tokens >= 0),
    output_tokens INTEGER NOT NULL CHECK (output_tokens >= 0),
    cost_microunits INTEGER NOT NULL CHECK (cost_microunits >= 0),
    output_bytes INTEGER NOT NULL CHECK (output_bytes >= 0),
    state TEXT NOT NULL CHECK (state IN ('active', 'settled', 'charged_unknown', 'released')),
    created_at_ms INTEGER NOT NULL,
    settled_at_ms INTEGER,
    CHECK (
        (state = 'active' AND settled_at_ms IS NULL)
        OR
        (state <> 'active' AND settled_at_ms IS NOT NULL)
    ),
    CHECK (settled_at_ms IS NULL OR settled_at_ms >= created_at_ms)
) STRICT;

CREATE TABLE run_loop_state (
    run_id TEXT PRIMARY KEY REFERENCES run(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    iteration INTEGER NOT NULL DEFAULT 0 CHECK (iteration >= 0),
    next_action TEXT NOT NULL CHECK (next_action IN (
        'compile_context', 'dispatch_model', 'consume_model_result', 'dispatch_read_tool',
        'compile_after_tool', 'commit_final', 'terminal'
    )),
    current_manifest_id TEXT REFERENCES context_manifest(id) ON DELETE RESTRICT,
    current_attempt_id TEXT REFERENCES model_attempt(attempt_id) ON DELETE RESTRICT,
    current_tool_call_id TEXT REFERENCES tool_call(tool_call_id) ON DELETE RESTRICT,
    final_message_id TEXT REFERENCES message(id) ON DELETE RESTRICT,
    updated_at_ms INTEGER NOT NULL,
    CHECK (next_action <> 'dispatch_model'
           OR (current_manifest_id IS NOT NULL AND current_attempt_id IS NOT NULL)),
    CHECK (next_action <> 'consume_model_result' OR current_attempt_id IS NOT NULL),
    CHECK (next_action <> 'dispatch_read_tool' OR current_tool_call_id IS NOT NULL),
    CHECK (next_action <> 'compile_after_tool' OR current_tool_call_id IS NOT NULL),
    CHECK (next_action <> 'commit_final' OR current_attempt_id IS NOT NULL),
    CHECK (next_action <> 'terminal' OR final_message_id IS NOT NULL),
    FOREIGN KEY (current_manifest_id, run_id)
        REFERENCES context_manifest(id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (current_attempt_id, run_id)
        REFERENCES model_attempt(attempt_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (current_tool_call_id, run_id)
        REFERENCES tool_call(tool_call_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (final_message_id, run_id)
        REFERENCES message(id, run_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE loop_checkpoint (
    run_id TEXT NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    prior_sequence INTEGER,
    loop_version TEXT NOT NULL CHECK (length(loop_version) BETWEEN 1 AND 128),
    next_action TEXT NOT NULL CHECK (next_action IN (
        'compile_context', 'dispatch_model', 'consume_model_result', 'dispatch_read_tool',
        'compile_after_tool', 'commit_final', 'terminal'
    )),
    manifest_id TEXT REFERENCES context_manifest(id) ON DELETE RESTRICT,
    attempt_id TEXT REFERENCES model_attempt(attempt_id) ON DELETE RESTRICT,
    tool_call_id TEXT REFERENCES tool_call(tool_call_id) ON DELETE RESTRICT,
    decision_json TEXT NOT NULL CHECK (json_valid(decision_json) AND length(decision_json) <= 16384),
    prior_checkpoint_digest TEXT CHECK (
        prior_checkpoint_digest IS NULL OR length(prior_checkpoint_digest) = 64
    ),
    checkpoint_digest TEXT NOT NULL CHECK (length(checkpoint_digest) = 64),
    event_id TEXT NOT NULL UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (run_id, sequence),
    CHECK (
        (sequence = 0 AND prior_sequence IS NULL AND prior_checkpoint_digest IS NULL)
        OR
        (sequence > 0 AND prior_sequence = sequence - 1 AND prior_checkpoint_digest IS NOT NULL)
    ),
    FOREIGN KEY (run_id, prior_sequence)
        REFERENCES loop_checkpoint(run_id, sequence) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (manifest_id, run_id)
        REFERENCES context_manifest(id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (attempt_id, run_id)
        REFERENCES model_attempt(attempt_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (tool_call_id, run_id)
        REFERENCES tool_call(tool_call_id, run_id) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER loop_checkpoint_prior_digest_insert
BEFORE INSERT ON loop_checkpoint
WHEN NEW.sequence > 0
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM loop_checkpoint prior
        WHERE prior.run_id = NEW.run_id
          AND prior.sequence = NEW.prior_sequence
          AND prior.checkpoint_digest = NEW.prior_checkpoint_digest
    ) THEN RAISE(ABORT, 'loop checkpoint predecessor digest mismatch') END;
END;

CREATE TRIGGER session_context_epoch_reference_update
BEFORE UPDATE OF current_context_epoch_id ON session
WHEN NEW.current_context_epoch_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM context_epoch epoch
        WHERE epoch.id = NEW.current_context_epoch_id
          AND epoch.session_id = NEW.id
          AND epoch.retired_at_ms IS NULL
    ) THEN RAISE(ABORT, 'session context epoch is invalid') END;
END;

CREATE TRIGGER session_context_epoch_reference_insert
BEFORE INSERT ON session
WHEN NEW.current_context_epoch_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM context_epoch epoch
        WHERE epoch.id = NEW.current_context_epoch_id
          AND epoch.session_id = NEW.id
          AND epoch.retired_at_ms IS NULL
    ) THEN RAISE(ABORT, 'session context epoch is invalid') END;
END;

CREATE TRIGGER context_epoch_current_retirement
BEFORE UPDATE OF retired_at_ms ON context_epoch
WHEN NEW.retired_at_ms IS NOT NULL
  AND EXISTS(
      SELECT 1 FROM session WHERE current_context_epoch_id = OLD.id
  )
BEGIN
    SELECT RAISE(ABORT, 'current context epoch cannot be retired');
END;

CREATE TRIGGER context_epoch_baseline_immutable
BEFORE UPDATE OF
    id, session_id, epoch_number, baseline_version, baseline_digest, baseline_text,
    agent_profile_json, workspace_identity, config_digest, policy_digest, created_at_ms
ON context_epoch
BEGIN
    SELECT RAISE(ABORT, 'context epoch baseline is immutable');
END;

CREATE TRIGGER turn_context_epoch_reference_insert
BEFORE INSERT ON turn
WHEN NEW.context_epoch_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM context_epoch epoch
        WHERE epoch.id = NEW.context_epoch_id AND epoch.session_id = NEW.session_id
    ) THEN RAISE(ABORT, 'turn context epoch is invalid') END;
END;

CREATE TRIGGER turn_context_epoch_reference_update
BEFORE UPDATE OF context_epoch_id ON turn
WHEN NEW.context_epoch_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM context_epoch epoch
        WHERE epoch.id = NEW.context_epoch_id AND epoch.session_id = NEW.session_id
    ) THEN RAISE(ABORT, 'turn context epoch is invalid') END;
END;

CREATE TRIGGER turn_context_epoch_immutable
BEFORE UPDATE OF context_epoch_id ON turn
WHEN OLD.context_epoch_id IS NOT NULL
  AND NEW.context_epoch_id IS NOT OLD.context_epoch_id
BEGIN
    SELECT RAISE(ABORT, 'turn context epoch is immutable');
END;

CREATE TRIGGER context_manifest_turn_epoch_insert
BEFORE INSERT ON context_manifest
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM turn
        WHERE id = NEW.turn_id
          AND session_id = NEW.session_id
          AND run_id = NEW.run_id
          AND context_epoch_id = NEW.epoch_id
    ) THEN RAISE(ABORT, 'manifest does not use the turn context epoch') END;
END;

CREATE TRIGGER context_manifest_turn_epoch_update
BEFORE UPDATE OF run_id, session_id, turn_id, epoch_id ON context_manifest
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM turn
        WHERE id = NEW.turn_id
          AND session_id = NEW.session_id
          AND run_id = NEW.run_id
          AND context_epoch_id = NEW.epoch_id
    ) THEN RAISE(ABORT, 'manifest does not use the turn context epoch') END;
END;

CREATE TRIGGER artifact_access_policy_insert
BEFORE INSERT ON artifact
WHEN NEW.access_policy_json <> json_object(
    'principalId', NEW.principal_id,
    'sessionId', NEW.session_id
)
BEGIN
    SELECT RAISE(ABORT, 'artifact access policy does not match its owner');
END;

CREATE TRIGGER artifact_ownership_immutable
BEFORE UPDATE OF principal_id, session_id, access_policy_json, access_policy_digest ON artifact
WHEN NEW.principal_id <> OLD.principal_id
  OR NEW.session_id <> OLD.session_id
  OR NEW.access_policy_json <> OLD.access_policy_json
  OR NEW.access_policy_digest <> OLD.access_policy_digest
BEGIN
    SELECT RAISE(ABORT, 'artifact ownership and access policy are immutable');
END;

CREATE TRIGGER context_manifest_item_artifact_scope_insert
BEFORE INSERT ON context_manifest_item
WHEN NEW.content_artifact_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM context_manifest manifest
        JOIN artifact artifact ON artifact.id = NEW.content_artifact_id
        WHERE manifest.id = NEW.manifest_id
          AND artifact.session_id = manifest.session_id
    ) THEN RAISE(ABORT, 'context artifact is outside the owning session') END;
END;

CREATE TRIGGER context_manifest_immutable_update
BEFORE UPDATE ON context_manifest
WHEN EXISTS(
    SELECT 1 FROM model_attempt WHERE context_manifest_id = OLD.id
)
BEGIN
    SELECT RAISE(ABORT, 'bound context manifest is immutable');
END;

CREATE TRIGGER context_manifest_item_late_insert
BEFORE INSERT ON context_manifest_item
WHEN EXISTS(
    SELECT 1 FROM model_attempt WHERE context_manifest_id = NEW.manifest_id
)
BEGIN
    SELECT RAISE(ABORT, 'context manifest is already bound to an attempt');
END;

CREATE TRIGGER context_manifest_item_immutable_update
BEFORE UPDATE ON context_manifest_item
WHEN EXISTS(
    SELECT 1 FROM model_attempt WHERE context_manifest_id = OLD.manifest_id
)
BEGIN
    SELECT RAISE(ABORT, 'bound context manifest item is immutable');
END;

CREATE TRIGGER context_manifest_item_immutable_delete
BEFORE DELETE ON context_manifest_item
WHEN EXISTS(
    SELECT 1 FROM model_attempt WHERE context_manifest_id = OLD.manifest_id
)
BEGIN
    SELECT RAISE(ABORT, 'bound context manifest item is immutable');
END;

CREATE TRIGGER model_attempt_response_artifact_scope_insert
BEFORE INSERT ON model_attempt
WHEN NEW.response_artifact_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM context_manifest manifest
        JOIN artifact artifact ON artifact.id = NEW.response_artifact_id
        WHERE manifest.id = NEW.context_manifest_id
          AND manifest.run_id = NEW.run_id
          AND artifact.session_id = manifest.session_id
    ) THEN RAISE(ABORT, 'model response artifact is outside the owning session') END;
END;

CREATE TRIGGER model_attempt_manifest_token_total_insert
BEFORE INSERT ON model_attempt
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM context_manifest manifest
        WHERE manifest.id = NEW.context_manifest_id
          AND manifest.run_id = NEW.run_id
          AND manifest.total_token_estimate = COALESCE((
              SELECT SUM(item.token_estimate)
              FROM context_manifest_item item
              WHERE item.manifest_id = manifest.id
                AND item.disposition = 'included'
          ), 0)
    ) THEN RAISE(ABORT, 'context manifest token total is inconsistent') END;
END;

CREATE TRIGGER model_attempt_response_artifact_scope_update
BEFORE UPDATE OF run_id, context_manifest_id, response_artifact_id ON model_attempt
WHEN NEW.response_artifact_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM context_manifest manifest
        JOIN artifact artifact ON artifact.id = NEW.response_artifact_id
        WHERE manifest.id = NEW.context_manifest_id
          AND manifest.run_id = NEW.run_id
          AND artifact.session_id = manifest.session_id
    ) THEN RAISE(ABORT, 'model response artifact is outside the owning session') END;
END;

CREATE TRIGGER model_attempt_preparation_immutable
BEFORE UPDATE OF
    attempt_id, run_id, ordinal, retry_of_attempt_id, provider_id, adapter_version, model_id,
    capability_snapshot_json, capability_digest, context_manifest_id, routing_decision_json,
    tool_schema_digests_json, budget_reservation_json, request_json, request_digest, timeout_ms,
    prepared_at_ms, deadline_at_ms, prepared_lease_id, prepared_owner_id, prepared_fencing_token
ON model_attempt
BEGIN
    SELECT RAISE(ABORT, 'model attempt preparation is immutable');
END;

CREATE TRIGGER tool_call_output_artifact_scope_insert
BEFORE INSERT ON tool_call
WHEN NEW.output_artifact_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM model_attempt attempt
        JOIN context_manifest manifest ON manifest.id = attempt.context_manifest_id
        JOIN artifact artifact ON artifact.id = NEW.output_artifact_id
        WHERE attempt.attempt_id = NEW.model_attempt_id
          AND attempt.run_id = NEW.run_id
          AND artifact.session_id = manifest.session_id
    ) THEN RAISE(ABORT, 'tool output artifact is outside the owning session') END;
END;

CREATE TRIGGER tool_call_output_artifact_scope_update
BEFORE UPDATE OF run_id, model_attempt_id, output_artifact_id ON tool_call
WHEN NEW.output_artifact_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM model_attempt attempt
        JOIN context_manifest manifest ON manifest.id = attempt.context_manifest_id
        JOIN artifact artifact ON artifact.id = NEW.output_artifact_id
        WHERE attempt.attempt_id = NEW.model_attempt_id
          AND attempt.run_id = NEW.run_id
          AND artifact.session_id = manifest.session_id
    ) THEN RAISE(ABORT, 'tool output artifact is outside the owning session') END;
END;

CREATE TABLE session_creation (
    principal_id TEXT NOT NULL CHECK (length(principal_id) > 0),
    channel_binding_id TEXT NOT NULL CHECK (length(channel_binding_id) > 0),
    dedupe_key TEXT NOT NULL CHECK (length(dedupe_key) BETWEEN 1 AND 256),
    session_id TEXT NOT NULL UNIQUE REFERENCES session(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (principal_id, channel_binding_id, dedupe_key)
) STRICT;

CREATE TABLE task_cancellation (
    principal_id TEXT NOT NULL CHECK (length(principal_id) > 0),
    channel_binding_id TEXT NOT NULL CHECK (length(channel_binding_id) > 0),
    dedupe_key TEXT NOT NULL CHECK (length(dedupe_key) BETWEEN 1 AND 256),
    task_id TEXT NOT NULL REFERENCES task(id) ON DELETE RESTRICT,
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
    status TEXT NOT NULL CHECK (status = 'cancelling'),
    task_revision INTEGER NOT NULL CHECK (task_revision > 0),
    event_id TEXT NOT NULL UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    requested_at_ms INTEGER NOT NULL,
    PRIMARY KEY (principal_id, channel_binding_id, dedupe_key)
) STRICT;
