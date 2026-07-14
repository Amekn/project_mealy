PRAGMA foreign_keys = ON;

-- Discord snowflakes are canonical decimal strings so no unsigned 64-bit identity is narrowed
-- through SQLite's signed INTEGER type. Each binding is one exact human in one one-to-one DM.
CREATE TABLE discord_channel_binding (
    binding_id TEXT PRIMARY KEY
        REFERENCES channel_binding_registry(binding_id) ON DELETE RESTRICT,
    principal_id TEXT NOT NULL REFERENCES principal_registry(principal_id) ON DELETE RESTRICT,
    session_id TEXT NOT NULL UNIQUE REFERENCES session(id) ON DELETE RESTRICT,
    discord_user_id TEXT NOT NULL CHECK (
        length(discord_user_id) BETWEEN 1 AND 20
        AND discord_user_id NOT GLOB '*[^0-9]*'
        AND substr(discord_user_id, 1, 1) <> '0'
    ),
    discord_channel_id TEXT NOT NULL UNIQUE CHECK (
        length(discord_channel_id) BETWEEN 1 AND 20
        AND discord_channel_id NOT GLOB '*[^0-9]*'
        AND substr(discord_channel_id, 1, 1) <> '0'
    ),
    bot_user_id TEXT NOT NULL CHECK (
        length(bot_user_id) BETWEEN 1 AND 20
        AND bot_user_id NOT GLOB '*[^0-9]*'
        AND substr(bot_user_id, 1, 1) <> '0'
        AND bot_user_id <> discord_user_id
    ),
    bot_username TEXT NOT NULL CHECK (length(bot_username) BETWEEN 1 AND 64),
    token_secret_id TEXT NOT NULL CHECK (length(token_secret_id) BETWEEN 1 AND 128),
    token_digest TEXT NOT NULL CHECK (
        length(token_digest) = 64 AND token_digest NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    created_event_id TEXT NOT NULL UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    revoked_at_ms INTEGER,
    UNIQUE(binding_id, principal_id),
    CHECK (
        (status = 'active' AND revoked_at_ms IS NULL)
        OR (status = 'revoked' AND revoked_at_ms IS NOT NULL)
    )
) STRICT;

CREATE INDEX discord_channel_owner_idx
    ON discord_channel_binding(principal_id, created_at_ms, binding_id);

CREATE TRIGGER discord_channel_binding_insert_guard
BEFORE INSERT ON discord_channel_binding
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM channel_binding_registry binding
        JOIN session ON session.id = NEW.session_id
        WHERE binding.binding_id = NEW.binding_id
          AND binding.principal_id = NEW.principal_id
          AND binding.channel_kind = 'extension_channel'
          AND binding.installation_id = 'builtin.discord.dm.v1'
          AND binding.status = 'active'
          AND session.principal_id = NEW.principal_id
          AND session.channel_binding_id = NEW.binding_id
    ) THEN RAISE(ABORT, 'Discord binding lacks exact registry and session identity') END;
END;

CREATE TRIGGER discord_channel_binding_transition
BEFORE UPDATE ON discord_channel_binding
BEGIN
    SELECT CASE WHEN NEW.binding_id <> OLD.binding_id
        OR NEW.principal_id <> OLD.principal_id
        OR NEW.session_id <> OLD.session_id
        OR NEW.discord_user_id <> OLD.discord_user_id
        OR NEW.discord_channel_id <> OLD.discord_channel_id
        OR NEW.bot_user_id <> OLD.bot_user_id
        OR NEW.bot_username <> OLD.bot_username
        OR NEW.token_secret_id <> OLD.token_secret_id
        OR NEW.token_digest <> OLD.token_digest
        OR NEW.created_event_id <> OLD.created_event_id
        OR NEW.created_at_ms <> OLD.created_at_ms
        OR NEW.revision <> OLD.revision + 1
        OR OLD.status <> 'active' OR NEW.status <> 'revoked'
    THEN RAISE(ABORT, 'invalid Discord channel revocation transition') END;
END;

CREATE TRIGGER discord_channel_binding_immutable_delete
BEFORE DELETE ON discord_channel_binding
BEGIN
    SELECT RAISE(ABORT, 'Discord channel evidence cannot be removed');
END;

CREATE TABLE discord_channel_cursor (
    binding_id TEXT PRIMARY KEY
        REFERENCES discord_channel_binding(binding_id) ON DELETE RESTRICT,
    after_message_id TEXT CHECK (
        after_message_id IS NULL OR (
            length(after_message_id) BETWEEN 1 AND 20
            AND after_message_id NOT GLOB '*[^0-9]*'
            AND substr(after_message_id, 1, 1) <> '0'
        )
    ),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
) STRICT;

CREATE TRIGGER discord_channel_cursor_transition
BEFORE UPDATE ON discord_channel_cursor
BEGIN
    SELECT CASE WHEN NEW.binding_id <> OLD.binding_id
        OR NEW.after_message_id IS NULL
        OR NOT (
            OLD.after_message_id IS NULL
            OR length(NEW.after_message_id) > length(OLD.after_message_id)
            OR (
                length(NEW.after_message_id) = length(OLD.after_message_id)
                AND NEW.after_message_id > OLD.after_message_id
            )
        )
        OR NEW.revision <> OLD.revision + 1
        OR NEW.updated_at_ms < OLD.updated_at_ms
    THEN RAISE(ABORT, 'invalid Discord message cursor transition') END;
END;

CREATE TRIGGER discord_channel_cursor_immutable_delete
BEFORE DELETE ON discord_channel_cursor
BEGIN
    SELECT RAISE(ABORT, 'Discord cursor evidence cannot be removed');
END;

CREATE TABLE discord_channel_health (
    binding_id TEXT PRIMARY KEY
        REFERENCES discord_channel_binding(binding_id) ON DELETE RESTRICT,
    last_success_at_ms INTEGER,
    last_failure_at_ms INTEGER,
    consecutive_failures INTEGER NOT NULL CHECK (consecutive_failures >= 0),
    last_error_code TEXT CHECK (last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 128),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    CHECK (
        (consecutive_failures = 0 AND last_error_code IS NULL)
        OR (consecutive_failures > 0 AND last_failure_at_ms IS NOT NULL
            AND last_error_code IS NOT NULL)
    )
) STRICT;

CREATE TRIGGER discord_channel_health_transition
BEFORE UPDATE ON discord_channel_health
BEGIN
    SELECT CASE WHEN NEW.binding_id <> OLD.binding_id
        OR NEW.revision <> OLD.revision + 1
        OR NEW.updated_at_ms < OLD.updated_at_ms
        OR NEW.last_success_at_ms IS NOT NULL
           AND OLD.last_success_at_ms IS NOT NULL
           AND NEW.last_success_at_ms < OLD.last_success_at_ms
        OR NEW.last_failure_at_ms IS NOT NULL
           AND OLD.last_failure_at_ms IS NOT NULL
           AND NEW.last_failure_at_ms < OLD.last_failure_at_ms
    THEN RAISE(ABORT, 'invalid Discord channel health transition') END;
END;

CREATE TRIGGER discord_channel_health_immutable_delete
BEFORE DELETE ON discord_channel_health
BEGIN
    SELECT RAISE(ABORT, 'Discord channel health cannot be removed');
END;

-- Reservation precedes session admission. Completion and cursor advancement share one transaction,
-- so a crash replays the same idempotent message rather than silently advancing past it.
CREATE TABLE discord_message_receipt (
    binding_id TEXT NOT NULL
        REFERENCES discord_channel_binding(binding_id) ON DELETE RESTRICT,
    message_id TEXT NOT NULL CHECK (
        length(message_id) BETWEEN 1 AND 20
        AND message_id NOT GLOB '*[^0-9]*'
        AND substr(message_id, 1, 1) <> '0'
    ),
    body_digest TEXT NOT NULL CHECK (
        length(body_digest) = 64 AND body_digest NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'admitted', 'ignored')),
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE RESTRICT,
    inbox_entry_id TEXT REFERENCES session_inbox(inbox_entry_id) ON DELETE RESTRICT,
    acknowledgement_outbox_id TEXT REFERENCES outbox(outbox_id) ON DELETE RESTRICT,
    ignore_reason TEXT CHECK (ignore_reason IS NULL OR length(ignore_reason) BETWEEN 1 AND 256),
    received_at_ms INTEGER NOT NULL CHECK (received_at_ms >= 0),
    completed_at_ms INTEGER,
    PRIMARY KEY(binding_id, message_id),
    CHECK (
        (state = 'reserved' AND inbox_entry_id IS NULL
         AND acknowledgement_outbox_id IS NULL AND ignore_reason IS NULL
         AND completed_at_ms IS NULL)
        OR (state = 'admitted' AND inbox_entry_id IS NOT NULL
            AND acknowledgement_outbox_id IS NOT NULL AND ignore_reason IS NULL
            AND completed_at_ms IS NOT NULL AND completed_at_ms >= received_at_ms)
        OR (state = 'ignored' AND inbox_entry_id IS NULL
            AND acknowledgement_outbox_id IS NULL AND ignore_reason IS NOT NULL
            AND completed_at_ms IS NOT NULL AND completed_at_ms >= received_at_ms)
    )
) STRICT;

CREATE INDEX discord_message_recovery_idx
    ON discord_message_receipt(state, received_at_ms, binding_id, message_id);

CREATE TRIGGER discord_message_insert_guard
BEFORE INSERT ON discord_message_receipt
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM discord_channel_binding binding
        JOIN channel_binding_registry registry ON registry.binding_id = binding.binding_id
        WHERE binding.binding_id = NEW.binding_id
          AND binding.session_id = NEW.session_id
          AND binding.status = 'active'
          AND registry.status = 'active'
    ) THEN RAISE(ABORT, 'Discord message lacks active binding authority') END;
END;

CREATE TRIGGER discord_message_transition
BEFORE UPDATE ON discord_message_receipt
BEGIN
    SELECT CASE WHEN NEW.binding_id <> OLD.binding_id
        OR NEW.message_id <> OLD.message_id
        OR NEW.body_digest <> OLD.body_digest
        OR NEW.session_id <> OLD.session_id
        OR NEW.received_at_ms <> OLD.received_at_ms
        OR OLD.state <> 'reserved' OR NEW.state NOT IN ('admitted', 'ignored')
    THEN RAISE(ABORT, 'invalid Discord message completion transition') END;
END;

CREATE TRIGGER discord_message_immutable_delete
BEFORE DELETE ON discord_message_receipt
BEGIN
    SELECT RAISE(ABORT, 'Discord message evidence cannot be removed');
END;
