-- Durable authenticated-command receipts. The semantic request is scoped by owner, verified
-- channel, and command kind; delivery metadata is deliberately not part of request_json.
CREATE TABLE effect_command_receipt (
    principal_id TEXT NOT NULL CHECK (length(principal_id) > 0),
    channel_binding_id TEXT NOT NULL CHECK (length(channel_binding_id) > 0),
    command_kind TEXT NOT NULL
        CHECK (command_kind IN ('approval_resolution', 'effect_reconciliation')),
    idempotency_key TEXT NOT NULL CHECK (
        length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND 256
    ),
    request_json TEXT NOT NULL CHECK (
        json_valid(request_json)
        AND json_type(request_json) = 'object'
        AND length(CAST(request_json AS BLOB)) BETWEEN 2 AND 65536
    ),
    request_digest TEXT NOT NULL CHECK (
        length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'
    ),
    effect_id TEXT NOT NULL REFERENCES effect_intent(effect_id) ON DELETE RESTRICT,
    approval_id TEXT REFERENCES approval_request(approval_id) ON DELETE RESTRICT,
    attempt_id TEXT,
    result_kind TEXT NOT NULL CHECK (result_kind IN ('approve', 'deny', 'succeeded', 'failed')),
    effect_revision INTEGER NOT NULL CHECK (effect_revision > 0),
    approval_event_id TEXT UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    effect_event_id TEXT NOT NULL UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    cursor INTEGER NOT NULL REFERENCES timeline_event(cursor) ON DELETE RESTRICT,
    committed_at_ms INTEGER NOT NULL CHECK (committed_at_ms >= 0),
    PRIMARY KEY (principal_id, channel_binding_id, command_kind, idempotency_key),
    FOREIGN KEY (attempt_id, effect_id)
        REFERENCES effect_attempt(attempt_id, effect_id) ON DELETE RESTRICT,
    CHECK (
        (command_kind = 'approval_resolution'
         AND approval_id IS NOT NULL AND attempt_id IS NULL
         AND result_kind IN ('approve', 'deny') AND approval_event_id IS NOT NULL)
        OR
        (command_kind = 'effect_reconciliation'
         AND approval_id IS NULL AND attempt_id IS NOT NULL
         AND result_kind IN ('succeeded', 'failed') AND approval_event_id IS NULL)
    )
) STRICT;

CREATE TRIGGER effect_command_receipt_insert_guard
BEFORE INSERT ON effect_command_receipt
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM effect_intent intent
        JOIN session owner_session ON owner_session.id = intent.session_id
        WHERE intent.effect_id = NEW.effect_id
          AND intent.principal_id = NEW.principal_id
          AND intent.channel_binding_id = NEW.channel_binding_id
          AND owner_session.principal_id = NEW.principal_id
          AND owner_session.channel_binding_id = NEW.channel_binding_id
    ) THEN RAISE(ABORT, 'effect command receipt is outside the owning channel') END;

    SELECT CASE WHEN json_extract(NEW.request_json, '$.principalId') IS NOT NEW.principal_id
        OR json_extract(NEW.request_json, '$.channelBindingId') IS NOT NEW.channel_binding_id
        OR json_extract(NEW.request_json, '$.idempotencyKey') IS NOT NEW.idempotency_key
    THEN RAISE(ABORT, 'effect command receipt request scope is inconsistent') END;

    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM timeline_event timeline
        WHERE timeline.cursor = NEW.cursor AND timeline.event_id = NEW.effect_event_id
    ) THEN RAISE(ABORT, 'effect command receipt cursor is inconsistent') END;

    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM effect
        WHERE effect.id = NEW.effect_id
          AND effect.revision = NEW.effect_revision
          AND effect.updated_at_ms = NEW.committed_at_ms
          AND effect.status = CASE NEW.result_kind
              WHEN 'approve' THEN 'authorized'
              WHEN 'deny' THEN 'denied'
              WHEN 'succeeded' THEN 'succeeded'
              WHEN 'failed' THEN 'failed'
          END
    ) THEN RAISE(ABORT, 'effect command receipt revision is inconsistent') END;

    SELECT CASE WHEN NEW.command_kind = 'approval_resolution' AND (
        (SELECT COUNT(*) FROM json_each(NEW.request_json)) <> 7
        OR json_extract(NEW.request_json, '$.contractVersion')
            IS NOT 'mealy.approval-resolution-request.v1'
        OR json_extract(NEW.request_json, '$.approvalId') IS NOT NEW.approval_id
        OR json_extract(NEW.request_json, '$.decision') IS NOT NEW.result_kind
        OR NOT EXISTS(
            SELECT 1
            FROM approval_request approval
            WHERE approval.approval_id = NEW.approval_id
              AND approval.effect_id = NEW.effect_id
              AND approval.principal_id = NEW.principal_id
              AND approval.subject_digest = json_extract(
                  NEW.request_json, '$.expectedSubjectDigest'
              )
              AND approval.decision = NEW.result_kind
              AND approval.decision_event_id = NEW.approval_event_id
              AND approval.resolved_at_ms = NEW.committed_at_ms
              AND approval.status = CASE NEW.result_kind
                  WHEN 'approve' THEN 'approved'
                  WHEN 'deny' THEN 'denied'
              END
        )
        OR NOT EXISTS(
            SELECT 1 FROM journal_event approval_event
            WHERE approval_event.event_id = NEW.approval_event_id
              AND approval_event.aggregate_kind = 'approval'
              AND approval_event.aggregate_id = NEW.approval_id
              AND approval_event.event_type = CASE NEW.result_kind
                  WHEN 'approve' THEN 'approval.approved'
                  WHEN 'deny' THEN 'approval.denied'
              END
              AND approval_event.actor_principal_id = NEW.principal_id
              AND approval_event.occurred_at_ms = NEW.committed_at_ms
        )
        OR NOT EXISTS(
            SELECT 1 FROM journal_event effect_event
            WHERE effect_event.event_id = NEW.effect_event_id
              AND effect_event.aggregate_kind = 'effect'
              AND effect_event.aggregate_id = NEW.effect_id
              AND effect_event.event_type = CASE NEW.result_kind
                  WHEN 'approve' THEN 'effect.authorized'
                  WHEN 'deny' THEN 'effect.denied'
              END
              AND effect_event.actor_principal_id = NEW.principal_id
              AND effect_event.occurred_at_ms = NEW.committed_at_ms
        )
    ) THEN RAISE(ABORT, 'approval resolution receipt graph is inconsistent') END;

    SELECT CASE WHEN NEW.command_kind = 'effect_reconciliation' AND (
        (SELECT COUNT(*) FROM json_each(NEW.request_json)) <> 9
        OR json_extract(NEW.request_json, '$.contractVersion')
            IS NOT 'mealy.effect-reconciliation-request.v1'
        OR json_extract(NEW.request_json, '$.effectId') IS NOT NEW.effect_id
        OR json_extract(NEW.request_json, '$.attemptId') IS NOT NEW.attempt_id
        OR json_extract(NEW.request_json, '$.outcome') IS NOT NEW.result_kind
        OR json_extract(NEW.request_json, '$.expectedEffectRevision')
            IS NOT NEW.effect_revision - 1
        OR NOT EXISTS(
            SELECT 1
            FROM effect_attempt attempt
            JOIN effect_outcome outcome
              ON outcome.attempt_id = attempt.attempt_id
             AND outcome.effect_id = attempt.effect_id
             AND outcome.sequence = 1
            WHERE attempt.attempt_id = NEW.attempt_id
              AND attempt.effect_id = NEW.effect_id
              AND attempt.state = 'outcome_unknown'
              AND outcome.outcome_kind = NEW.result_kind
              AND outcome.event_id = NEW.effect_event_id
              AND outcome.recorded_at_ms = NEW.committed_at_ms
              AND json(json_extract(outcome.evidence_json, '$.evidence'))
                  = json(json_extract(NEW.request_json, '$.evidenceDetails'))
        )
        OR NOT EXISTS(
            SELECT 1 FROM journal_event effect_event
            WHERE effect_event.event_id = NEW.effect_event_id
              AND effect_event.aggregate_kind = 'effect'
              AND effect_event.aggregate_id = NEW.effect_id
              AND effect_event.event_type = 'effect.reconciled'
              AND effect_event.actor_principal_id = NEW.principal_id
              AND effect_event.occurred_at_ms = NEW.committed_at_ms
        )
    ) THEN RAISE(ABORT, 'effect reconciliation receipt graph is inconsistent') END;
END;

CREATE TRIGGER effect_command_receipt_immutable_update
BEFORE UPDATE ON effect_command_receipt
BEGIN
    SELECT RAISE(ABORT, 'effect command receipt is immutable');
END;

CREATE TRIGGER effect_command_receipt_immutable_delete
BEFORE DELETE ON effect_command_receipt
BEGIN
    SELECT RAISE(ABORT, 'effect command receipt is immutable');
END;
