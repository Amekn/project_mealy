PRAGMA foreign_keys = ON;

-- Phase 6 gives authenticated channels a durable revocation registry. Existing sessions seed the
-- registry without rewriting their historical identity evidence; future sessions maintain it.
CREATE TABLE principal_registry (
    principal_id TEXT PRIMARY KEY CHECK (length(principal_id) > 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    revoked_at_ms INTEGER,
    CHECK (
        (status = 'active' AND revoked_at_ms IS NULL)
        OR (status = 'revoked' AND revoked_at_ms IS NOT NULL)
    )
) STRICT;

CREATE TABLE channel_binding_registry (
    binding_id TEXT PRIMARY KEY CHECK (length(binding_id) > 0),
    principal_id TEXT NOT NULL REFERENCES principal_registry(principal_id) ON DELETE RESTRICT,
    channel_kind TEXT NOT NULL CHECK (
        channel_kind IN ('local_cli', 'legacy_session', 'signed_webhook', 'extension_channel')
    ),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    installation_id TEXT,
    external_subject TEXT,
    external_subject_digest TEXT CHECK (
        external_subject_digest IS NULL OR (
            length(external_subject_digest) = 64
            AND external_subject_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    revoked_at_ms INTEGER,
    UNIQUE (binding_id, principal_id),
    CHECK (
        (channel_kind IN ('local_cli', 'legacy_session')
         AND installation_id IS NULL AND external_subject IS NULL
         AND external_subject_digest IS NULL)
        OR
        (channel_kind IN ('signed_webhook', 'extension_channel')
         AND installation_id IS NOT NULL AND length(installation_id) > 0
         AND external_subject IS NOT NULL AND length(external_subject) BETWEEN 1 AND 1024
         AND external_subject_digest IS NOT NULL)
    ),
    CHECK (
        (status = 'active' AND revoked_at_ms IS NULL)
        OR (status = 'revoked' AND revoked_at_ms IS NOT NULL)
    )
) STRICT;

CREATE INDEX channel_binding_principal_status_idx
    ON channel_binding_registry(principal_id, status, channel_kind, binding_id);
CREATE UNIQUE INDEX channel_binding_external_identity_idx
    ON channel_binding_registry(channel_kind, installation_id, external_subject_digest)
    WHERE external_subject_digest IS NOT NULL;

INSERT OR IGNORE INTO principal_registry(
    principal_id, status, revision, created_at_ms, updated_at_ms
)
SELECT principal_id, 'active', 0, MIN(created_at_ms), MIN(created_at_ms)
FROM session GROUP BY principal_id;

INSERT OR IGNORE INTO channel_binding_registry(
    binding_id, principal_id, channel_kind, status, revision, created_at_ms, updated_at_ms
)
SELECT channel_binding_id, principal_id, 'legacy_session', 'active', 0,
       MIN(created_at_ms), MIN(created_at_ms)
FROM session GROUP BY channel_binding_id, principal_id;

CREATE TRIGGER session_identity_registry
AFTER INSERT ON session
BEGIN
    INSERT OR IGNORE INTO principal_registry(
        principal_id, status, revision, created_at_ms, updated_at_ms
    ) VALUES (NEW.principal_id, 'active', 0, NEW.created_at_ms, NEW.created_at_ms);
    INSERT OR IGNORE INTO channel_binding_registry(
        binding_id, principal_id, channel_kind, status, revision, created_at_ms, updated_at_ms
    ) VALUES (
        NEW.channel_binding_id, NEW.principal_id, 'legacy_session', 'active', 0,
        NEW.created_at_ms, NEW.created_at_ms
    );
END;

CREATE TRIGGER principal_registry_transition
BEFORE UPDATE ON principal_registry
BEGIN
    SELECT CASE WHEN NEW.principal_id <> OLD.principal_id
        OR NEW.created_at_ms <> OLD.created_at_ms
        OR NEW.revision <> OLD.revision + 1
        OR OLD.status <> 'active' OR NEW.status <> 'revoked'
    THEN RAISE(ABORT, 'invalid principal revocation transition') END;
END;

CREATE TRIGGER channel_binding_registry_transition
BEFORE UPDATE ON channel_binding_registry
BEGIN
    SELECT CASE WHEN NEW.binding_id <> OLD.binding_id
        OR NEW.principal_id <> OLD.principal_id
        OR NEW.channel_kind <> OLD.channel_kind
        OR NEW.installation_id IS NOT OLD.installation_id
        OR NEW.external_subject IS NOT OLD.external_subject
        OR NEW.external_subject_digest IS NOT OLD.external_subject_digest
        OR NEW.created_at_ms <> OLD.created_at_ms
        OR NEW.revision <> OLD.revision + 1
        OR OLD.status <> 'active' OR NEW.status <> 'revoked'
    THEN RAISE(ABORT, 'invalid channel binding revocation transition') END;
END;

CREATE TABLE extension_installation (
    extension_id TEXT PRIMARY KEY CHECK (length(extension_id) > 0),
    principal_id TEXT NOT NULL REFERENCES principal_registry(principal_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (
        status IN ('installed', 'enabled', 'disabled', 'failed', 'revoked')
    ),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    publisher TEXT NOT NULL CHECK (length(publisher) BETWEEN 1 AND 255),
    current_manifest_ordinal INTEGER NOT NULL CHECK (current_manifest_ordinal > 0),
    current_manifest_digest TEXT NOT NULL CHECK (
        length(current_manifest_digest) = 64
        AND current_manifest_digest NOT GLOB '*[^0-9a-f]*'
    ),
    current_version TEXT NOT NULL CHECK (length(current_version) BETWEEN 1 AND 128),
    active_grant_id TEXT,
    active_grant_digest TEXT CHECK (
        active_grant_digest IS NULL OR (
            length(active_grant_digest) = 64
            AND active_grant_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    created_event_id TEXT NOT NULL UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    updated_event_id TEXT NOT NULL REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    last_healthy_at_ms INTEGER,
    last_failure_at_ms INTEGER,
    UNIQUE (extension_id, principal_id),
    CHECK (
        (status = 'enabled' AND active_grant_id IS NOT NULL AND active_grant_digest IS NOT NULL)
        OR (status <> 'enabled' AND active_grant_id IS NULL AND active_grant_digest IS NULL)
    ),
    CHECK (last_healthy_at_ms IS NULL OR last_healthy_at_ms >= created_at_ms),
    CHECK (last_failure_at_ms IS NULL OR last_failure_at_ms >= created_at_ms),
    FOREIGN KEY (extension_id, current_manifest_ordinal)
        REFERENCES extension_manifest_revision(extension_id, ordinal)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE extension_manifest_revision (
    extension_id TEXT NOT NULL REFERENCES extension_installation(extension_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal > 0),
    manifest_digest TEXT NOT NULL CHECK (
        length(manifest_digest) = 64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'
    ),
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 128),
    manifest_json TEXT NOT NULL CHECK (json_valid(manifest_json)),
    installation_root TEXT NOT NULL CHECK (
        length(installation_root) BETWEEN 2 AND 4096 AND substr(installation_root, 1, 1) = '/'
    ),
    installed_event_id TEXT NOT NULL UNIQUE
        REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    installed_at_ms INTEGER NOT NULL CHECK (installed_at_ms >= 0),
    PRIMARY KEY (extension_id, ordinal),
    UNIQUE (extension_id, ordinal, manifest_digest)
) STRICT;

CREATE INDEX extension_manifest_digest_idx
    ON extension_manifest_revision(extension_id, manifest_digest, ordinal DESC);

CREATE TABLE extension_grant (
    grant_id TEXT PRIMARY KEY CHECK (length(grant_id) > 0),
    extension_id TEXT NOT NULL REFERENCES extension_installation(extension_id) ON DELETE RESTRICT,
    manifest_ordinal INTEGER NOT NULL CHECK (manifest_ordinal > 0),
    manifest_digest TEXT NOT NULL CHECK (
        length(manifest_digest) = 64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'
    ),
    grant_json TEXT NOT NULL CHECK (json_valid(grant_json)),
    grant_digest TEXT NOT NULL CHECK (
        length(grant_digest) = 64 AND grant_digest NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'superseded')),
    issued_by_principal_id TEXT NOT NULL CHECK (length(issued_by_principal_id) > 0),
    issued_event_id TEXT NOT NULL UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms >= 0),
    terminal_event_id TEXT REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    terminal_at_ms INTEGER,
    UNIQUE (grant_id, extension_id),
    FOREIGN KEY (extension_id, manifest_ordinal, manifest_digest)
        REFERENCES extension_manifest_revision(extension_id, ordinal, manifest_digest)
        ON DELETE RESTRICT,
    CHECK (
        (status = 'active' AND terminal_event_id IS NULL AND terminal_at_ms IS NULL)
        OR
        (status IN ('revoked', 'superseded')
         AND terminal_event_id IS NOT NULL AND terminal_at_ms IS NOT NULL
         AND terminal_at_ms >= issued_at_ms)
    )
) STRICT;

CREATE UNIQUE INDEX extension_one_active_grant_idx
    ON extension_grant(extension_id) WHERE status = 'active';

CREATE TABLE extension_invocation (
    invocation_id TEXT PRIMARY KEY CHECK (length(invocation_id) > 0),
    extension_id TEXT NOT NULL REFERENCES extension_installation(extension_id) ON DELETE RESTRICT,
    principal_id TEXT NOT NULL REFERENCES principal_registry(principal_id) ON DELETE RESTRICT,
    channel_binding_id TEXT NOT NULL CHECK (length(channel_binding_id) > 0),
    manifest_ordinal INTEGER NOT NULL CHECK (manifest_ordinal > 0),
    manifest_digest TEXT NOT NULL CHECK (
        length(manifest_digest) = 64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'
    ),
    grant_id TEXT NOT NULL REFERENCES extension_grant(grant_id) ON DELETE RESTRICT,
    grant_digest TEXT NOT NULL CHECK (
        length(grant_digest) = 64 AND grant_digest NOT GLOB '*[^0-9a-f]*'
    ),
    capability_id TEXT NOT NULL CHECK (length(capability_id) BETWEEN 1 AND 255),
    input_digest TEXT NOT NULL CHECK (
        length(input_digest) = 64 AND input_digest NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (status IN ('dispatching', 'succeeded', 'failed', 'abandoned')),
    response_json TEXT CHECK (response_json IS NULL OR json_valid(response_json)),
    output_digest TEXT CHECK (
        output_digest IS NULL OR (
            length(output_digest) = 64 AND output_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    error_class TEXT CHECK (error_class IS NULL OR length(error_class) BETWEEN 1 AND 255),
    error_message TEXT CHECK (error_message IS NULL OR length(error_message) BETWEEN 1 AND 4096),
    duration_ms INTEGER CHECK (duration_ms IS NULL OR duration_ms >= 0),
    started_event_id TEXT NOT NULL UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    completed_event_id TEXT UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    started_at_ms INTEGER NOT NULL CHECK (started_at_ms >= 0),
    completed_at_ms INTEGER,
    FOREIGN KEY (extension_id, manifest_ordinal, manifest_digest)
        REFERENCES extension_manifest_revision(extension_id, ordinal, manifest_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (grant_id, extension_id)
        REFERENCES extension_grant(grant_id, extension_id) ON DELETE RESTRICT,
    CHECK (
        (status = 'dispatching'
         AND response_json IS NULL AND output_digest IS NULL
         AND error_class IS NULL AND error_message IS NULL AND duration_ms IS NULL
         AND completed_event_id IS NULL AND completed_at_ms IS NULL)
        OR
        (status = 'succeeded'
         AND response_json IS NOT NULL AND output_digest IS NOT NULL
         AND error_class IS NULL AND error_message IS NULL AND duration_ms IS NOT NULL
         AND completed_event_id IS NOT NULL AND completed_at_ms IS NOT NULL)
        OR
        (status IN ('failed', 'abandoned')
         AND response_json IS NULL AND output_digest IS NULL
         AND error_class IS NOT NULL AND error_message IS NOT NULL AND duration_ms IS NOT NULL
         AND completed_event_id IS NOT NULL AND completed_at_ms IS NOT NULL)
    ),
    CHECK (completed_at_ms IS NULL OR completed_at_ms >= started_at_ms)
) STRICT;

CREATE INDEX extension_invocation_recovery_idx
    ON extension_invocation(status, started_at_ms, invocation_id);
CREATE INDEX extension_invocation_owner_idx
    ON extension_invocation(principal_id, extension_id, started_at_ms, invocation_id);

CREATE TRIGGER extension_installation_transition
BEFORE UPDATE ON extension_installation
BEGIN
    SELECT CASE WHEN NEW.extension_id <> OLD.extension_id
        OR NEW.principal_id <> OLD.principal_id
        OR NEW.name <> OLD.name
        OR NEW.publisher <> OLD.publisher
        OR NEW.created_event_id <> OLD.created_event_id
        OR NEW.created_at_ms <> OLD.created_at_ms
        OR NEW.revision <> OLD.revision + 1
        OR NEW.updated_event_id = OLD.updated_event_id
        OR NOT (
            (OLD.status = 'installed' AND NEW.status IN ('installed', 'enabled', 'revoked'))
            OR (OLD.status = 'enabled'
                AND NEW.status IN ('installed', 'disabled', 'failed', 'revoked'))
            OR (OLD.status IN ('disabled', 'failed')
                AND NEW.status IN ('installed', 'enabled', 'revoked'))
        )
    THEN RAISE(ABORT, 'invalid extension transition or revision') END;
END;

CREATE TRIGGER extension_manifest_revision_immutable_update
BEFORE UPDATE ON extension_manifest_revision
BEGIN
    SELECT RAISE(ABORT, 'extension manifest history is immutable');
END;

CREATE TRIGGER extension_manifest_revision_immutable_delete
BEFORE DELETE ON extension_manifest_revision
BEGIN
    SELECT RAISE(ABORT, 'extension manifest history cannot be removed');
END;

CREATE TRIGGER extension_grant_insert_guard
BEFORE INSERT ON extension_grant
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM extension_installation installation
        WHERE installation.extension_id = NEW.extension_id
          AND installation.current_manifest_ordinal = NEW.manifest_ordinal
          AND installation.current_manifest_digest = NEW.manifest_digest
          AND installation.status IN ('installed', 'disabled', 'failed')
          AND installation.principal_id = NEW.issued_by_principal_id
    ) THEN RAISE(ABORT, 'extension grant does not bind the staged owner manifest') END;
END;

CREATE TRIGGER extension_grant_transition
BEFORE UPDATE ON extension_grant
BEGIN
    SELECT CASE WHEN NEW.grant_id <> OLD.grant_id
        OR NEW.extension_id <> OLD.extension_id
        OR NEW.manifest_ordinal <> OLD.manifest_ordinal
        OR NEW.manifest_digest <> OLD.manifest_digest
        OR NEW.grant_json <> OLD.grant_json
        OR NEW.grant_digest <> OLD.grant_digest
        OR NEW.issued_by_principal_id <> OLD.issued_by_principal_id
        OR NEW.issued_event_id <> OLD.issued_event_id
        OR NEW.issued_at_ms <> OLD.issued_at_ms
        OR OLD.status <> 'active' OR NEW.status NOT IN ('revoked', 'superseded')
    THEN RAISE(ABORT, 'invalid extension grant transition') END;
END;

CREATE TRIGGER extension_grant_immutable_delete
BEFORE DELETE ON extension_grant
BEGIN
    SELECT RAISE(ABORT, 'extension grants cannot be removed');
END;

CREATE TRIGGER extension_invocation_insert_guard
BEFORE INSERT ON extension_invocation
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM extension_installation installation
        JOIN extension_grant grant ON grant.grant_id = NEW.grant_id
        WHERE installation.extension_id = NEW.extension_id
          AND installation.principal_id = NEW.principal_id
          AND installation.status = 'enabled'
          AND installation.current_manifest_ordinal = NEW.manifest_ordinal
          AND installation.current_manifest_digest = NEW.manifest_digest
          AND installation.active_grant_id = NEW.grant_id
          AND installation.active_grant_digest = NEW.grant_digest
          AND grant.extension_id = NEW.extension_id
          AND grant.manifest_ordinal = NEW.manifest_ordinal
          AND grant.manifest_digest = NEW.manifest_digest
          AND grant.grant_digest = NEW.grant_digest
          AND grant.status = 'active'
          AND EXISTS(
              SELECT 1 FROM json_each(grant.grant_json, '$.capabilityIds') capability
              WHERE capability.value = NEW.capability_id
          )
    ) THEN RAISE(ABORT, 'extension invocation lacks exact active grant authority') END;
END;

CREATE TRIGGER extension_invocation_transition
BEFORE UPDATE ON extension_invocation
BEGIN
    SELECT CASE WHEN NEW.invocation_id <> OLD.invocation_id
        OR NEW.extension_id <> OLD.extension_id
        OR NEW.principal_id <> OLD.principal_id
        OR NEW.channel_binding_id <> OLD.channel_binding_id
        OR NEW.manifest_ordinal <> OLD.manifest_ordinal
        OR NEW.manifest_digest <> OLD.manifest_digest
        OR NEW.grant_id <> OLD.grant_id
        OR NEW.grant_digest <> OLD.grant_digest
        OR NEW.capability_id <> OLD.capability_id
        OR NEW.input_digest <> OLD.input_digest
        OR NEW.started_event_id <> OLD.started_event_id
        OR NEW.started_at_ms <> OLD.started_at_ms
        OR OLD.status <> 'dispatching'
        OR NEW.status NOT IN ('succeeded', 'failed', 'abandoned')
    THEN RAISE(ABORT, 'invalid extension invocation transition') END;
END;

CREATE TRIGGER extension_invocation_immutable_delete
BEFORE DELETE ON extension_invocation
BEGIN
    SELECT RAISE(ABORT, 'extension invocation evidence cannot be removed');
END;

-- One built-in external channel proof: a verified platform subject owns a dedicated session,
-- while signing material remains in the filesystem secret broker rather than SQLite.
CREATE TABLE webhook_channel_binding (
    binding_id TEXT PRIMARY KEY
        REFERENCES channel_binding_registry(binding_id) ON DELETE RESTRICT,
    principal_id TEXT NOT NULL REFERENCES principal_registry(principal_id) ON DELETE RESTRICT,
    session_id TEXT NOT NULL UNIQUE REFERENCES session(id) ON DELETE RESTRICT,
    external_subject TEXT NOT NULL CHECK (length(external_subject) BETWEEN 1 AND 1024),
    callback_url TEXT NOT NULL CHECK (length(callback_url) BETWEEN 1 AND 2048),
    secret_digest TEXT NOT NULL CHECK (
        length(secret_digest) = 64 AND secret_digest NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    created_event_id TEXT NOT NULL REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    revoked_at_ms INTEGER,
    UNIQUE(binding_id, principal_id),
    CHECK (
        (status = 'active' AND revoked_at_ms IS NULL)
        OR (status = 'revoked' AND revoked_at_ms IS NOT NULL)
    )
) STRICT;

CREATE INDEX webhook_channel_owner_idx
    ON webhook_channel_binding(principal_id, created_at_ms, binding_id);

CREATE TRIGGER webhook_channel_binding_insert_guard
BEFORE INSERT ON webhook_channel_binding
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM channel_binding_registry binding
        JOIN session ON session.id = NEW.session_id
        WHERE binding.binding_id = NEW.binding_id
          AND binding.principal_id = NEW.principal_id
          AND binding.channel_kind = 'signed_webhook'
          AND binding.status = 'active'
          AND binding.external_subject = NEW.external_subject
          AND session.principal_id = NEW.principal_id
          AND session.channel_binding_id = NEW.binding_id
    ) THEN RAISE(ABORT, 'webhook binding lacks exact registry and session identity') END;
END;

CREATE TRIGGER webhook_channel_binding_transition
BEFORE UPDATE ON webhook_channel_binding
BEGIN
    SELECT CASE WHEN NEW.binding_id <> OLD.binding_id
        OR NEW.principal_id <> OLD.principal_id
        OR NEW.session_id <> OLD.session_id
        OR NEW.external_subject <> OLD.external_subject
        OR NEW.callback_url <> OLD.callback_url
        OR NEW.secret_digest <> OLD.secret_digest
        OR NEW.created_event_id <> OLD.created_event_id
        OR NEW.created_at_ms <> OLD.created_at_ms
        OR NEW.revision <> OLD.revision + 1
        OR OLD.status <> 'active' OR NEW.status <> 'revoked'
    THEN RAISE(ABORT, 'invalid webhook channel revocation transition') END;
END;

CREATE TRIGGER webhook_channel_binding_immutable_delete
BEFORE DELETE ON webhook_channel_binding
BEGIN
    SELECT RAISE(ABORT, 'webhook channel evidence cannot be removed');
END;

-- Reservation precedes session admission. Re-running the exact delivery after a crash resumes the
-- idempotent admission; reusing a nonce for another delivery fails before it reaches the inbox.
CREATE TABLE webhook_delivery_receipt (
    binding_id TEXT NOT NULL
        REFERENCES webhook_channel_binding(binding_id) ON DELETE RESTRICT,
    delivery_id TEXT NOT NULL CHECK (length(delivery_id) BETWEEN 1 AND 128),
    nonce TEXT NOT NULL CHECK (length(nonce) BETWEEN 1 AND 128),
    body_digest TEXT NOT NULL CHECK (
        length(body_digest) = 64 AND body_digest NOT GLOB '*[^0-9a-f]*'
    ),
    signature_digest TEXT NOT NULL CHECK (
        length(signature_digest) = 64 AND signature_digest NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'completed')),
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE RESTRICT,
    inbox_entry_id TEXT REFERENCES session_inbox(inbox_entry_id) ON DELETE RESTRICT,
    acknowledgement_outbox_id TEXT REFERENCES outbox(outbox_id) ON DELETE RESTRICT,
    received_at_ms INTEGER NOT NULL CHECK (received_at_ms >= 0),
    completed_at_ms INTEGER,
    PRIMARY KEY(binding_id, delivery_id),
    UNIQUE(binding_id, nonce),
    CHECK (
        (state = 'reserved' AND inbox_entry_id IS NULL
         AND acknowledgement_outbox_id IS NULL AND completed_at_ms IS NULL)
        OR
        (state = 'completed' AND inbox_entry_id IS NOT NULL
         AND acknowledgement_outbox_id IS NOT NULL AND completed_at_ms IS NOT NULL)
    ),
    CHECK (completed_at_ms IS NULL OR completed_at_ms >= received_at_ms)
) STRICT;

CREATE INDEX webhook_delivery_recovery_idx
    ON webhook_delivery_receipt(state, received_at_ms, binding_id, delivery_id);

CREATE TRIGGER webhook_delivery_insert_guard
BEFORE INSERT ON webhook_delivery_receipt
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM webhook_channel_binding binding
        JOIN channel_binding_registry registry ON registry.binding_id = binding.binding_id
        WHERE binding.binding_id = NEW.binding_id
          AND binding.session_id = NEW.session_id
          AND binding.status = 'active'
          AND registry.status = 'active'
    ) THEN RAISE(ABORT, 'webhook delivery lacks active binding authority') END;
END;

CREATE TRIGGER webhook_delivery_transition
BEFORE UPDATE ON webhook_delivery_receipt
BEGIN
    SELECT CASE WHEN NEW.binding_id <> OLD.binding_id
        OR NEW.delivery_id <> OLD.delivery_id
        OR NEW.nonce <> OLD.nonce
        OR NEW.body_digest <> OLD.body_digest
        OR NEW.signature_digest <> OLD.signature_digest
        OR NEW.session_id <> OLD.session_id
        OR NEW.received_at_ms <> OLD.received_at_ms
        OR OLD.state <> 'reserved' OR NEW.state <> 'completed'
    THEN RAISE(ABORT, 'invalid webhook delivery completion transition') END;
END;

CREATE TRIGGER webhook_delivery_immutable_delete
BEFORE DELETE ON webhook_delivery_receipt
BEGIN
    SELECT RAISE(ABORT, 'webhook delivery evidence cannot be removed');
END;
