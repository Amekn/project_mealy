CREATE TABLE session_compaction (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    principal_id TEXT NOT NULL CHECK (length(principal_id) > 0),
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE RESTRICT,
    artifact_id TEXT NOT NULL REFERENCES artifact(id) ON DELETE RESTRICT,
    source_first_cursor INTEGER NOT NULL CHECK (source_first_cursor > 0),
    source_last_cursor INTEGER NOT NULL CHECK (source_last_cursor >= source_first_cursor),
    source_first_event_id TEXT NOT NULL REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    source_last_event_id TEXT NOT NULL REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    prompt_version TEXT NOT NULL CHECK (length(prompt_version) BETWEEN 1 AND 1024),
    config_digest TEXT NOT NULL CHECK (
        length(config_digest) = 64 AND config_digest NOT GLOB '*[^0-9a-f]*'
    ),
    artifact_digest TEXT NOT NULL CHECK (
        length(artifact_digest) = 64 AND artifact_digest NOT GLOB '*[^0-9a-f]*'
    ),
    summary_text TEXT NOT NULL CHECK (length(summary_text) BETWEEN 1 AND 262144),
    carry_forward_json TEXT NOT NULL CHECK (
        json_valid(carry_forward_json) AND json_type(carry_forward_json) = 'object'
        AND length(carry_forward_json) BETWEEN 2 AND 262144
    ),
    carry_forward_digest TEXT NOT NULL CHECK (
        length(carry_forward_digest) = 64
        AND carry_forward_digest NOT GLOB '*[^0-9a-f]*'
    ),
    event_id TEXT NOT NULL UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE (id, principal_id, session_id),
    FOREIGN KEY (session_id, principal_id)
        REFERENCES session(id, principal_id) ON DELETE RESTRICT,
    FOREIGN KEY (artifact_id, principal_id, session_id)
        REFERENCES artifact(id, principal_id, session_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX session_compaction_owner_idx
    ON session_compaction(principal_id, session_id, source_last_cursor DESC, id);

CREATE UNIQUE INDEX timeline_event_cursor_event_reference_idx
    ON timeline_event(cursor, event_id);

CREATE TABLE session_compaction_citation (
    compaction_id TEXT NOT NULL REFERENCES session_compaction(id) ON DELETE RESTRICT,
    item_kind TEXT NOT NULL CHECK (
        item_kind IN (
            'current_goal', 'safety_constraint', 'decision', 'unresolved_work',
            'unresolved_approval', 'effect_outcome'
        )
    ),
    item_key TEXT NOT NULL CHECK (length(item_key) BETWEEN 1 AND 256),
    citation_ordinal INTEGER NOT NULL CHECK (citation_ordinal > 0),
    event_id TEXT NOT NULL REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    cursor INTEGER NOT NULL REFERENCES timeline_event(cursor) ON DELETE RESTRICT,
    event_digest TEXT NOT NULL CHECK (
        length(event_digest) = 64 AND event_digest NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (compaction_id, item_kind, item_key, citation_ordinal),
    UNIQUE (compaction_id, item_kind, item_key, event_id, cursor),
    FOREIGN KEY (cursor, event_id)
        REFERENCES timeline_event(cursor, event_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX session_compaction_citation_event_idx
    ON session_compaction_citation(event_id, compaction_id);

CREATE TRIGGER session_compaction_range_insert
BEFORE INSERT ON session_compaction
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM timeline_event first_event
        JOIN timeline_event last_event
          ON last_event.cursor = NEW.source_last_cursor
         AND last_event.event_id = NEW.source_last_event_id
        WHERE first_event.cursor = NEW.source_first_cursor
          AND first_event.event_id = NEW.source_first_event_id
    ) THEN RAISE(ABORT, 'compaction source range does not match canonical timeline') END;
END;

CREATE TRIGGER session_compaction_immutable_update
BEFORE UPDATE ON session_compaction
BEGIN
    SELECT RAISE(ABORT, 'compaction provenance is immutable');
END;

CREATE TRIGGER session_compaction_immutable_delete
BEFORE DELETE ON session_compaction
BEGIN
    SELECT RAISE(ABORT, 'compaction provenance cannot delete canonical history links');
END;

CREATE TRIGGER session_compaction_citation_insert
BEFORE INSERT ON session_compaction_citation
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM session_compaction compaction
        JOIN timeline_event timeline
          ON timeline.cursor = NEW.cursor AND timeline.event_id = NEW.event_id
        WHERE compaction.id = NEW.compaction_id
          AND NEW.cursor BETWEEN compaction.source_first_cursor AND compaction.source_last_cursor
    ) THEN RAISE(ABORT, 'compaction citation is outside its canonical source range') END;
END;

CREATE TRIGGER session_compaction_citation_immutable_update
BEFORE UPDATE ON session_compaction_citation
BEGIN
    SELECT RAISE(ABORT, 'compaction citations are immutable');
END;

CREATE TRIGGER session_compaction_citation_immutable_delete
BEFORE DELETE ON session_compaction_citation
BEGIN
    SELECT RAISE(ABORT, 'compaction citations cannot be removed');
END;

CREATE TABLE memory (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    principal_id TEXT NOT NULL CHECK (length(principal_id) > 0),
    workspace_identity TEXT NOT NULL CHECK (length(workspace_identity) BETWEEN 1 AND 1024),
    status TEXT NOT NULL CHECK (
        status IN ('proposed', 'active', 'superseded', 'expired', 'rejected', 'deleted')
    ),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    category TEXT NOT NULL CHECK (
        category IN (
            'preference', 'fact', 'goal', 'decision', 'constraint', 'identity',
            'credential', 'health', 'financial', 'third_party_private'
        )
    ),
    confidence_basis_points INTEGER NOT NULL
        CHECK (confidence_basis_points BETWEEN 0 AND 10000),
    sensitivity TEXT NOT NULL CHECK (
        sensitivity IN ('public', 'internal', 'private', 'restricted')
    ),
    retention_class TEXT NOT NULL CHECK (
        retention_class IN ('session', 'standard', 'pinned', 'policy_hold')
    ),
    proposed_by_principal_id TEXT NOT NULL CHECK (length(proposed_by_principal_id) > 0),
    created_event_id TEXT NOT NULL UNIQUE
        REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    updated_event_id TEXT NOT NULL REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    last_verified_at_ms INTEGER NOT NULL CHECK (last_verified_at_ms >= created_at_ms),
    deleted_at_ms INTEGER,
    UNIQUE (id, principal_id, workspace_identity),
    CHECK (
        (status = 'deleted' AND deleted_at_ms IS NOT NULL
         AND deleted_at_ms >= created_at_ms)
        OR
        (status <> 'deleted' AND deleted_at_ms IS NULL)
    )
) STRICT;

CREATE INDEX memory_namespace_status_idx
    ON memory(principal_id, workspace_identity, status, updated_event_id, id);

CREATE TABLE memory_revision (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    memory_id TEXT NOT NULL REFERENCES memory(id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal > 0),
    status TEXT NOT NULL CHECK (
        status IN ('proposed', 'active', 'superseded', 'expired', 'rejected', 'deleted')
    ),
    content_text TEXT CHECK (content_text IS NULL OR length(content_text) BETWEEN 1 AND 65536),
    content_digest TEXT NOT NULL CHECK (
        length(content_digest) = 64 AND content_digest NOT GLOB '*[^0-9a-f]*'
    ),
    confidence_basis_points INTEGER NOT NULL
        CHECK (confidence_basis_points BETWEEN 0 AND 10000),
    sensitivity TEXT NOT NULL CHECK (
        sensitivity IN ('public', 'internal', 'private', 'restricted')
    ),
    retention_class TEXT NOT NULL CHECK (
        retention_class IN ('session', 'standard', 'pinned', 'policy_hold')
    ),
    supersedes_revision_id TEXT REFERENCES memory_revision(id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    created_event_id TEXT NOT NULL UNIQUE
        REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    status_event_id TEXT NOT NULL REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    last_verified_at_ms INTEGER NOT NULL CHECK (last_verified_at_ms >= created_at_ms),
    deleted_at_ms INTEGER,
    UNIQUE (memory_id, ordinal),
    UNIQUE (id, memory_id),
    CHECK (supersedes_revision_id IS NULL OR supersedes_revision_id <> id),
    CHECK (
        (status = 'deleted' AND content_text IS NULL AND deleted_at_ms IS NOT NULL
         AND deleted_at_ms >= created_at_ms)
        OR
        (status <> 'deleted' AND content_text IS NOT NULL AND deleted_at_ms IS NULL)
    )
) STRICT;

CREATE UNIQUE INDEX memory_revision_one_active_idx
    ON memory_revision(memory_id) WHERE status = 'active';
CREATE UNIQUE INDEX memory_revision_one_proposed_idx
    ON memory_revision(memory_id) WHERE status = 'proposed';
CREATE INDEX memory_revision_history_idx
    ON memory_revision(memory_id, ordinal DESC, id);

CREATE TABLE memory_source (
    revision_id TEXT NOT NULL REFERENCES memory_revision(id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal > 0),
    source_locator TEXT NOT NULL CHECK (length(source_locator) BETWEEN 1 AND 4096),
    source_digest TEXT NOT NULL CHECK (
        length(source_digest) = 64 AND source_digest NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (revision_id, ordinal),
    UNIQUE (revision_id, source_locator, source_digest),
    UNIQUE (revision_id, ordinal, source_digest)
) STRICT;

CREATE INDEX memory_source_digest_idx ON memory_source(source_digest, revision_id);

CREATE TABLE memory_promotion_authorization (
    revision_id TEXT PRIMARY KEY REFERENCES memory_revision(id) ON DELETE RESTRICT,
    memory_id TEXT NOT NULL REFERENCES memory(id) ON DELETE RESTRICT,
    authorization_kind TEXT NOT NULL CHECK (
        authorization_kind IN ('owner_policy', 'owner_approval')
    ),
    authorization_id TEXT CHECK (
        authorization_id IS NULL OR length(authorization_id) BETWEEN 1 AND 255
    ),
    subject_digest TEXT NOT NULL CHECK (
        length(subject_digest) = 64 AND subject_digest NOT GLOB '*[^0-9a-f]*'
    ),
    policy_version TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 1024),
    actor_principal_id TEXT NOT NULL CHECK (length(actor_principal_id) > 0),
    event_id TEXT NOT NULL UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    authorized_at_ms INTEGER NOT NULL CHECK (authorized_at_ms >= 0),
    UNIQUE (revision_id, memory_id),
    CHECK (
        (authorization_kind = 'owner_policy' AND authorization_id IS NULL)
        OR
        (authorization_kind = 'owner_approval' AND authorization_id IS NOT NULL)
    ),
    FOREIGN KEY (revision_id, memory_id)
        REFERENCES memory_revision(id, memory_id) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER memory_transition_update
BEFORE UPDATE ON memory
BEGIN
    SELECT CASE WHEN NEW.id <> OLD.id
        OR NEW.principal_id <> OLD.principal_id
        OR NEW.workspace_identity <> OLD.workspace_identity
        OR NEW.category <> OLD.category
        OR NEW.proposed_by_principal_id <> OLD.proposed_by_principal_id
        OR NEW.created_event_id <> OLD.created_event_id
        OR NEW.created_at_ms <> OLD.created_at_ms
    THEN RAISE(ABORT, 'memory namespace and creation provenance are immutable') END;
    SELECT CASE WHEN NEW.revision <> OLD.revision + 1
        OR NEW.updated_event_id = OLD.updated_event_id
        OR NOT (
            (OLD.status = 'proposed' AND NEW.status IN ('active', 'rejected', 'deleted'))
            OR (OLD.status = 'active' AND NEW.status IN ('active', 'superseded', 'expired', 'deleted'))
            OR (OLD.status IN ('superseded', 'expired', 'rejected') AND NEW.status = 'deleted')
        )
    THEN RAISE(ABORT, 'invalid memory transition or revision') END;
END;

CREATE TRIGGER memory_revision_insert
BEFORE INSERT ON memory_revision
BEGIN
    SELECT CASE WHEN NEW.status <> 'proposed'
        OR NOT EXISTS(
            SELECT 1 FROM memory owner
            WHERE owner.id = NEW.memory_id AND owner.status = 'proposed'
              AND NEW.ordinal = 1
        ) AND NOT EXISTS(
            SELECT 1 FROM memory owner
            JOIN memory_revision previous
              ON previous.id = NEW.supersedes_revision_id
             AND previous.memory_id = owner.id
            WHERE owner.id = NEW.memory_id AND owner.status = 'active'
              AND previous.status = 'active'
              AND NEW.ordinal = previous.ordinal + 1
        )
    THEN RAISE(ABORT, 'memory revision must be a correctly ordered proposal') END;
END;

CREATE TRIGGER memory_revision_transition_update
BEFORE UPDATE ON memory_revision
BEGIN
    SELECT CASE WHEN NEW.id <> OLD.id
        OR NEW.memory_id <> OLD.memory_id
        OR NEW.ordinal <> OLD.ordinal
        OR NEW.content_digest <> OLD.content_digest
        OR NEW.confidence_basis_points <> OLD.confidence_basis_points
        OR NEW.sensitivity <> OLD.sensitivity
        OR NEW.retention_class <> OLD.retention_class
        OR NEW.supersedes_revision_id IS NOT OLD.supersedes_revision_id
        OR NEW.created_event_id <> OLD.created_event_id
        OR NEW.created_at_ms <> OLD.created_at_ms
        OR NEW.last_verified_at_ms <> OLD.last_verified_at_ms
    THEN RAISE(ABORT, 'memory revision evidence is immutable') END;
    SELECT CASE WHEN NOT (
        (OLD.status = 'proposed' AND NEW.status IN ('active', 'rejected', 'deleted'))
        OR (OLD.status = 'active' AND NEW.status IN ('superseded', 'expired', 'deleted'))
        OR (OLD.status IN ('superseded', 'expired', 'rejected') AND NEW.status = 'deleted')
    ) THEN RAISE(ABORT, 'invalid memory revision transition') END;
    SELECT CASE WHEN NEW.status <> 'deleted' AND NEW.content_text IS NOT OLD.content_text
        THEN RAISE(ABORT, 'memory revision content is immutable') END;
END;

CREATE TRIGGER memory_source_immutable_update
BEFORE UPDATE ON memory_source
BEGIN
    SELECT RAISE(ABORT, 'memory source provenance is immutable');
END;

CREATE TRIGGER memory_source_immutable_delete
BEFORE DELETE ON memory_source
BEGIN
    SELECT RAISE(ABORT, 'memory source provenance cannot be removed');
END;

CREATE TRIGGER memory_promotion_authorization_insert
BEFORE INSERT ON memory_promotion_authorization
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM memory_revision revision
        JOIN memory owner ON owner.id = revision.memory_id
        WHERE revision.id = NEW.revision_id
          AND revision.memory_id = NEW.memory_id
          AND revision.status = 'proposed'
          AND revision.content_digest = NEW.subject_digest
          AND owner.principal_id = NEW.actor_principal_id
    ) THEN RAISE(ABORT, 'memory promotion authorization is not owner-bound') END;
END;

CREATE TRIGGER memory_promotion_authorization_immutable_update
BEFORE UPDATE ON memory_promotion_authorization
BEGIN
    SELECT RAISE(ABORT, 'memory promotion authorization is immutable');
END;

CREATE TRIGGER memory_promotion_authorization_immutable_delete
BEFORE DELETE ON memory_promotion_authorization
BEGIN
    SELECT RAISE(ABORT, 'memory promotion authorization cannot be removed');
END;

CREATE TRIGGER memory_revision_activation_update
BEFORE UPDATE OF status ON memory_revision
WHEN NEW.status = 'active'
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM memory_source source WHERE source.revision_id = NEW.id
    ) THEN RAISE(ABORT, 'active memory revision requires immutable source provenance') END;
    SELECT CASE WHEN EXISTS(
        SELECT 1 FROM memory owner
        WHERE owner.id = NEW.memory_id
          AND (owner.category IN (
              'identity', 'credential', 'health', 'financial', 'third_party_private'
          ) OR NEW.sensitivity = 'restricted')
    ) AND NOT EXISTS(
        SELECT 1 FROM memory_promotion_authorization authorization
        JOIN memory owner ON owner.id = authorization.memory_id
        WHERE authorization.revision_id = NEW.id
          AND authorization.memory_id = NEW.memory_id
          AND authorization.subject_digest = NEW.content_digest
          AND authorization.actor_principal_id = owner.principal_id
    ) THEN RAISE(ABORT, 'sensitive memory promotion requires owner authorization') END;
END;

CREATE VIRTUAL TABLE memory_fts USING fts5(
    memory_id UNINDEXED,
    revision_id UNINDEXED,
    principal_id UNINDEXED,
    workspace_identity UNINDEXED,
    content,
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TABLE memory_index_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    lexical_status TEXT NOT NULL CHECK (
        lexical_status IN ('healthy', 'degraded', 'rebuilding')
    ),
    indexed_revision_count INTEGER NOT NULL CHECK (indexed_revision_count >= 0),
    last_rebuilt_at_ms INTEGER,
    last_error TEXT CHECK (last_error IS NULL OR length(last_error) BETWEEN 1 AND 4096),
    CHECK (
        (lexical_status = 'degraded' AND last_error IS NOT NULL)
        OR (lexical_status <> 'degraded' AND last_error IS NULL)
    )
) STRICT;

INSERT INTO memory_index_state(
    singleton, lexical_status, indexed_revision_count, last_rebuilt_at_ms, last_error
) VALUES (1, 'healthy', 0, NULL, NULL);

CREATE TRIGGER memory_revision_fts_update
AFTER UPDATE OF status, content_text ON memory_revision
BEGIN
    DELETE FROM memory_fts WHERE revision_id = OLD.id;
    INSERT INTO memory_fts(
        memory_id, revision_id, principal_id, workspace_identity, content
    )
    SELECT owner.id, NEW.id, owner.principal_id, owner.workspace_identity, NEW.content_text
    FROM memory owner
    WHERE owner.id = NEW.memory_id AND NEW.status = 'active';
    UPDATE memory_index_state
       SET indexed_revision_count = (SELECT COUNT(*) FROM memory_fts)
     WHERE singleton = 1;
END;

CREATE TABLE context_compaction_use (
    manifest_id TEXT NOT NULL,
    item_ordinal INTEGER NOT NULL,
    compaction_id TEXT NOT NULL REFERENCES session_compaction(id) ON DELETE RESTRICT,
    PRIMARY KEY (manifest_id, item_ordinal),
    FOREIGN KEY (manifest_id, item_ordinal)
        REFERENCES context_manifest_item(manifest_id, ordinal) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER context_compaction_use_insert
BEFORE INSERT ON context_compaction_use
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM context_manifest_item item
        JOIN context_manifest manifest ON manifest.id = item.manifest_id
        JOIN session_compaction compaction ON compaction.id = NEW.compaction_id
        WHERE item.manifest_id = NEW.manifest_id
          AND item.ordinal = NEW.item_ordinal
          AND item.disposition = 'included'
          AND item.source_type = 'compaction'
          AND item.source_content_digest = compaction.artifact_digest
          AND manifest.session_id = compaction.session_id
    ) THEN RAISE(ABORT, 'context compaction is outside its manifest session') END;
END;

CREATE TABLE context_memory_citation (
    manifest_id TEXT NOT NULL,
    item_ordinal INTEGER NOT NULL,
    memory_id TEXT NOT NULL REFERENCES memory(id) ON DELETE RESTRICT,
    revision_id TEXT NOT NULL REFERENCES memory_revision(id) ON DELETE RESTRICT,
    source_ordinal INTEGER NOT NULL,
    source_digest TEXT NOT NULL CHECK (
        length(source_digest) = 64 AND source_digest NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (manifest_id, item_ordinal, revision_id, source_ordinal),
    FOREIGN KEY (manifest_id, item_ordinal)
        REFERENCES context_manifest_item(manifest_id, ordinal) ON DELETE RESTRICT,
    FOREIGN KEY (revision_id, memory_id)
        REFERENCES memory_revision(id, memory_id) ON DELETE RESTRICT,
    FOREIGN KEY (revision_id, source_ordinal, source_digest)
        REFERENCES memory_source(revision_id, ordinal, source_digest) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER context_memory_citation_insert
BEFORE INSERT ON context_memory_citation
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM context_manifest_item item
        JOIN context_manifest manifest ON manifest.id = item.manifest_id
        JOIN session owner_session ON owner_session.id = manifest.session_id
        JOIN context_epoch epoch ON epoch.id = manifest.epoch_id
        JOIN memory owner ON owner.id = NEW.memory_id
        JOIN memory_revision revision
          ON revision.id = NEW.revision_id AND revision.memory_id = owner.id
        WHERE item.manifest_id = NEW.manifest_id
          AND item.ordinal = NEW.item_ordinal
          AND item.disposition = 'included'
          AND item.source_type = 'memory'
          AND item.source_content_digest = revision.content_digest
          AND owner.status = 'active'
          AND revision.status = 'active'
          AND owner.principal_id = owner_session.principal_id
          AND owner.workspace_identity = epoch.workspace_identity
    ) THEN RAISE(ABORT, 'context memory citation violates namespace or lifecycle policy') END;
END;

CREATE TRIGGER context_compaction_use_late_insert
BEFORE INSERT ON context_compaction_use
WHEN EXISTS(
    SELECT 1 FROM model_attempt WHERE context_manifest_id = NEW.manifest_id
)
BEGIN
    SELECT RAISE(ABORT, 'attempt context compaction evidence is immutable');
END;

CREATE TRIGGER context_memory_citation_late_insert
BEFORE INSERT ON context_memory_citation
WHEN EXISTS(
    SELECT 1 FROM model_attempt WHERE context_manifest_id = NEW.manifest_id
)
BEGIN
    SELECT RAISE(ABORT, 'attempt context memory evidence is immutable');
END;

CREATE TRIGGER context_compaction_use_immutable_update
BEFORE UPDATE ON context_compaction_use
BEGIN
    SELECT RAISE(ABORT, 'context compaction evidence is immutable');
END;

CREATE TRIGGER context_compaction_use_immutable_delete
BEFORE DELETE ON context_compaction_use
BEGIN
    SELECT RAISE(ABORT, 'context compaction evidence is immutable');
END;

CREATE TRIGGER context_memory_citation_immutable_update
BEFORE UPDATE ON context_memory_citation
BEGIN
    SELECT RAISE(ABORT, 'context memory evidence is immutable');
END;

CREATE TRIGGER context_memory_citation_immutable_delete
BEFORE DELETE ON context_memory_citation
BEGIN
    SELECT RAISE(ABORT, 'context memory evidence is immutable');
END;

CREATE TRIGGER model_attempt_phase_five_context_insert
BEFORE INSERT ON model_attempt
BEGIN
    SELECT CASE WHEN EXISTS(
        SELECT 1 FROM context_manifest_item item
        WHERE item.manifest_id = NEW.context_manifest_id
          AND item.disposition = 'included'
          AND item.source_type = 'compaction'
          AND NOT EXISTS(
              SELECT 1 FROM context_compaction_use use_record
              WHERE use_record.manifest_id = item.manifest_id
                AND use_record.item_ordinal = item.ordinal
          )
    ) THEN RAISE(ABORT, 'included compaction lacks durable context provenance') END;
    SELECT CASE WHEN EXISTS(
        SELECT 1 FROM context_manifest_item item
        WHERE item.manifest_id = NEW.context_manifest_id
          AND item.disposition = 'included'
          AND item.source_type = 'memory'
          AND NOT EXISTS(
              SELECT 1 FROM context_memory_citation citation
              WHERE citation.manifest_id = item.manifest_id
                AND citation.item_ordinal = item.ordinal
          )
    ) THEN RAISE(ABORT, 'included memory lacks durable source citations') END;
END;
