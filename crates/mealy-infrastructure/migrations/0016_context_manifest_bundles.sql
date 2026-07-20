-- Context manifests are immutable evidence, but the legacy row-per-item representation rewrites
-- the complete conversation prefix for every model attempt. Retain legacy rows for replay while
-- storing all new manifests as one bounded, digest-bound compressed bundle plus sparse relational
-- references for artifacts, compactions, and governed-memory citations.
CREATE TABLE context_manifest_bundle (
    manifest_id TEXT PRIMARY KEY REFERENCES context_manifest(id) ON DELETE CASCADE,
    items_json TEXT NOT NULL CHECK (
        json_valid(items_json)
        AND json_type(items_json) = 'object'
        AND length(CAST(items_json AS BLOB)) BETWEEN 2 AND 2097152
    ),
    items_digest TEXT NOT NULL CHECK (
        length(items_digest) = 64 AND items_digest NOT GLOB '*[^0-9a-f]*'
    ),
    logical_size_bytes INTEGER NOT NULL CHECK (logical_size_bytes BETWEEN 2 AND 2097152),
    item_count INTEGER NOT NULL CHECK (item_count BETWEEN 1 AND 4096),
    included_item_count INTEGER NOT NULL CHECK (included_item_count BETWEEN 0 AND item_count),
    withheld_item_count INTEGER NOT NULL CHECK (
        withheld_item_count BETWEEN 0 AND item_count
        AND included_item_count + withheld_item_count = item_count
    ),
    included_token_total INTEGER NOT NULL CHECK (included_token_total >= 0),
    inline_content_count INTEGER NOT NULL CHECK (
        inline_content_count BETWEEN 0 AND included_item_count
    ),
    inline_content_bytes INTEGER NOT NULL CHECK (inline_content_bytes >= 0),
    maximum_inline_content_bytes INTEGER NOT NULL CHECK (
        maximum_inline_content_bytes BETWEEN 0 AND 262144
    ),
    source_type_counts_json TEXT NOT NULL CHECK (
        json_valid(source_type_counts_json)
        AND json_type(source_type_counts_json) = 'object'
        AND length(CAST(source_type_counts_json AS BLOB)) BETWEEN 2 AND 65536
    ),
    artifact_count INTEGER NOT NULL CHECK (artifact_count BETWEEN 0 AND item_count),
    compaction_count INTEGER NOT NULL CHECK (compaction_count BETWEEN 0 AND item_count),
    memory_citation_count INTEGER NOT NULL CHECK (memory_citation_count >= 0)
) STRICT;

CREATE TABLE context_manifest_bundle_artifact (
    manifest_id TEXT NOT NULL REFERENCES context_manifest_bundle(manifest_id) ON DELETE CASCADE,
    item_ordinal INTEGER NOT NULL CHECK (item_ordinal >= 0),
    artifact_id TEXT NOT NULL REFERENCES artifact(id) ON DELETE RESTRICT,
    PRIMARY KEY (manifest_id, item_ordinal)
) STRICT, WITHOUT ROWID;

CREATE TABLE context_manifest_bundle_compaction (
    manifest_id TEXT NOT NULL REFERENCES context_manifest_bundle(manifest_id) ON DELETE CASCADE,
    item_ordinal INTEGER NOT NULL CHECK (item_ordinal >= 0),
    compaction_id TEXT NOT NULL REFERENCES session_compaction(id) ON DELETE RESTRICT,
    PRIMARY KEY (manifest_id, item_ordinal)
) STRICT, WITHOUT ROWID;

CREATE TABLE context_manifest_bundle_memory_citation (
    manifest_id TEXT NOT NULL REFERENCES context_manifest_bundle(manifest_id) ON DELETE CASCADE,
    item_ordinal INTEGER NOT NULL CHECK (item_ordinal >= 0),
    memory_id TEXT NOT NULL REFERENCES memory(id) ON DELETE RESTRICT,
    revision_id TEXT NOT NULL REFERENCES memory_revision(id) ON DELETE RESTRICT,
    source_ordinal INTEGER NOT NULL CHECK (source_ordinal > 0),
    source_digest TEXT NOT NULL CHECK (
        length(source_digest) = 64 AND source_digest NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (manifest_id, item_ordinal, revision_id, source_ordinal),
    FOREIGN KEY (revision_id, memory_id)
        REFERENCES memory_revision(id, memory_id) ON DELETE RESTRICT,
    FOREIGN KEY (revision_id, source_ordinal, source_digest)
        REFERENCES memory_source(revision_id, ordinal, source_digest) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TRIGGER context_manifest_bundle_late_insert
BEFORE INSERT ON context_manifest_bundle
WHEN EXISTS(SELECT 1 FROM model_attempt WHERE context_manifest_id = NEW.manifest_id)
BEGIN
    SELECT RAISE(ABORT, 'context manifest is already bound to an attempt');
END;

CREATE TRIGGER context_manifest_bundle_immutable_update
BEFORE UPDATE ON context_manifest_bundle
BEGIN
    SELECT RAISE(ABORT, 'context manifest bundle is immutable');
END;

CREATE TRIGGER context_manifest_bundle_immutable_delete
BEFORE DELETE ON context_manifest_bundle
WHEN EXISTS(SELECT 1 FROM model_attempt WHERE context_manifest_id = OLD.manifest_id)
BEGIN
    SELECT RAISE(ABORT, 'bound context manifest bundle is immutable');
END;

CREATE TRIGGER context_manifest_bundle_artifact_insert
BEFORE INSERT ON context_manifest_bundle_artifact
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM context_manifest_bundle bundle
        JOIN context_manifest manifest ON manifest.id = bundle.manifest_id
        JOIN artifact artifact ON artifact.id = NEW.artifact_id
        WHERE bundle.manifest_id = NEW.manifest_id
          AND NEW.item_ordinal < bundle.item_count
          AND artifact.session_id = manifest.session_id
    ) THEN RAISE(ABORT, 'bundled context artifact is outside the owning session') END;
    SELECT CASE WHEN EXISTS(
        SELECT 1 FROM model_attempt WHERE context_manifest_id = NEW.manifest_id
    ) THEN RAISE(ABORT, 'attempt context artifact evidence is immutable') END;
END;

CREATE TRIGGER context_manifest_bundle_compaction_insert
BEFORE INSERT ON context_manifest_bundle_compaction
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM context_manifest_bundle bundle
        JOIN context_manifest manifest ON manifest.id = bundle.manifest_id
        JOIN session_compaction compaction ON compaction.id = NEW.compaction_id
        WHERE bundle.manifest_id = NEW.manifest_id
          AND NEW.item_ordinal < bundle.item_count
          AND compaction.session_id = manifest.session_id
    ) THEN RAISE(ABORT, 'bundled context compaction is outside the owning session') END;
    SELECT CASE WHEN EXISTS(
        SELECT 1 FROM model_attempt WHERE context_manifest_id = NEW.manifest_id
    ) THEN RAISE(ABORT, 'attempt context compaction evidence is immutable') END;
END;

CREATE TRIGGER context_manifest_bundle_memory_citation_insert
BEFORE INSERT ON context_manifest_bundle_memory_citation
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM context_manifest_bundle bundle
        JOIN context_manifest manifest ON manifest.id = bundle.manifest_id
        JOIN session owner_session ON owner_session.id = manifest.session_id
        JOIN context_epoch epoch ON epoch.id = manifest.epoch_id
        JOIN memory owner ON owner.id = NEW.memory_id
        JOIN memory_revision revision
          ON revision.id = NEW.revision_id AND revision.memory_id = owner.id
        WHERE bundle.manifest_id = NEW.manifest_id
          AND NEW.item_ordinal < bundle.item_count
          AND owner.status = 'active'
          AND revision.status = 'active'
          AND owner.principal_id = owner_session.principal_id
          AND owner.workspace_identity = epoch.workspace_identity
    ) THEN RAISE(ABORT, 'bundled context memory citation violates namespace or lifecycle policy') END;
    SELECT CASE WHEN EXISTS(
        SELECT 1 FROM model_attempt WHERE context_manifest_id = NEW.manifest_id
    ) THEN RAISE(ABORT, 'attempt context memory evidence is immutable') END;
END;

CREATE TRIGGER context_manifest_bundle_artifact_immutable_update
BEFORE UPDATE ON context_manifest_bundle_artifact
BEGIN SELECT RAISE(ABORT, 'bundled context artifact evidence is immutable'); END;
CREATE TRIGGER context_manifest_bundle_artifact_immutable_delete
BEFORE DELETE ON context_manifest_bundle_artifact
BEGIN SELECT RAISE(ABORT, 'bundled context artifact evidence is immutable'); END;
CREATE TRIGGER context_manifest_bundle_compaction_immutable_update
BEFORE UPDATE ON context_manifest_bundle_compaction
BEGIN SELECT RAISE(ABORT, 'bundled context compaction evidence is immutable'); END;
CREATE TRIGGER context_manifest_bundle_compaction_immutable_delete
BEFORE DELETE ON context_manifest_bundle_compaction
BEGIN SELECT RAISE(ABORT, 'bundled context compaction evidence is immutable'); END;
CREATE TRIGGER context_manifest_bundle_memory_immutable_update
BEFORE UPDATE ON context_manifest_bundle_memory_citation
BEGIN SELECT RAISE(ABORT, 'bundled context memory evidence is immutable'); END;
CREATE TRIGGER context_manifest_bundle_memory_immutable_delete
BEFORE DELETE ON context_manifest_bundle_memory_citation
BEGIN SELECT RAISE(ABORT, 'bundled context memory evidence is immutable'); END;

DROP TRIGGER IF EXISTS model_attempt_manifest_token_total_insert;
CREATE TRIGGER model_attempt_manifest_token_total_insert
BEFORE INSERT ON model_attempt
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM context_manifest manifest
        WHERE manifest.id = NEW.context_manifest_id
          AND manifest.run_id = NEW.run_id
          AND (
            (
              EXISTS(SELECT 1 FROM context_manifest_bundle bundle
                     WHERE bundle.manifest_id = manifest.id)
              AND NOT EXISTS(SELECT 1 FROM context_manifest_item item
                             WHERE item.manifest_id = manifest.id)
              AND manifest.total_token_estimate = (
                  SELECT bundle.included_token_total FROM context_manifest_bundle bundle
                  WHERE bundle.manifest_id = manifest.id
              )
              AND (SELECT artifact_count FROM context_manifest_bundle
                   WHERE manifest_id = manifest.id) = (
                  SELECT COUNT(*) FROM context_manifest_bundle_artifact
                  WHERE manifest_id = manifest.id
              )
              AND (SELECT compaction_count FROM context_manifest_bundle
                   WHERE manifest_id = manifest.id) = (
                  SELECT COUNT(*) FROM context_manifest_bundle_compaction
                  WHERE manifest_id = manifest.id
              )
              AND (SELECT memory_citation_count FROM context_manifest_bundle
                   WHERE manifest_id = manifest.id) = (
                  SELECT COUNT(*) FROM context_manifest_bundle_memory_citation
                  WHERE manifest_id = manifest.id
              )
            )
            OR
            (
              NOT EXISTS(SELECT 1 FROM context_manifest_bundle bundle
                         WHERE bundle.manifest_id = manifest.id)
              AND manifest.total_token_estimate = COALESCE((
                  SELECT SUM(item.token_estimate)
                  FROM context_manifest_item item
                  WHERE item.manifest_id = manifest.id
                    AND item.disposition = 'included'
              ), 0)
            )
          )
    ) THEN RAISE(ABORT, 'context manifest token total or storage representation is inconsistent') END;
END;
