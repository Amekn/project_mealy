use super::{SqliteStore, agent};
use mealy_application::{
    AgentStoreError, ContextDisposition, ContextManifestEvidence, ContextManifestEvidenceItem,
    ContextManifestEvidenceStore, ContextManifestEvidenceStoreError, ContextMemoryEvidence,
    ContextMemorySourceCitation, OwnershipContext, validate_context_manifest_evidence,
};
use mealy_domain::{CompactionId, ContextManifestId, MemoryId, MemoryRevisionId};
use rusqlite::{OptionalExtension, params};
use std::str::FromStr;

impl ContextManifestEvidenceStore for SqliteStore {
    fn context_manifest_evidence(
        &self,
        ownership: OwnershipContext,
        manifest_id: ContextManifestId,
    ) -> Result<ContextManifestEvidence, ContextManifestEvidenceStoreError> {
        let row = load_authorized_manifest(&self.connection, ownership, manifest_id)?;
        let items = load_manifest_items(&self.connection, ownership, manifest_id)?;
        let evidence = row.into_evidence(manifest_id, items)?;
        validate_context_manifest_evidence(&evidence)?;
        Ok(evidence)
    }
}

fn load_authorized_manifest(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
    manifest_id: ContextManifestId,
) -> Result<StoredManifest, ContextManifestEvidenceStoreError> {
    connection
        .query_row(
            "SELECT manifest.run_id, manifest.turn_id, manifest.epoch_id, manifest.iteration, \
                    manifest.compiler_version, manifest.provider_residency, \
                    manifest.token_budget, manifest.total_token_estimate, \
                    manifest.tool_schema_set_digest, manifest.policy_version, \
                    manifest.projection_digest, manifest.created_at_ms \
             FROM context_manifest manifest \
             JOIN session owner_session ON owner_session.id = manifest.session_id \
             WHERE manifest.id = ?1 AND owner_session.principal_id = ?2 \
               AND owner_session.channel_binding_id = ?3",
            params![
                manifest_id.to_string(),
                ownership.principal_id().to_string(),
                ownership.channel_binding_id().to_string(),
            ],
            |result| {
                Ok(StoredManifest {
                    run_id: result.get(0)?,
                    turn_id: result.get(1)?,
                    epoch_id: result.get(2)?,
                    iteration: result.get(3)?,
                    compiler_version: result.get(4)?,
                    provider_residency: result.get(5)?,
                    token_budget: result.get(6)?,
                    total_token_estimate: result.get(7)?,
                    tool_schema_set_digest: result.get(8)?,
                    policy_version: result.get(9)?,
                    projection_digest: result.get(10)?,
                    created_at_ms: result.get(11)?,
                })
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?
        .ok_or(ContextManifestEvidenceStoreError::NotFound)
}

fn load_manifest_items(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
    manifest_id: ContextManifestId,
) -> Result<Vec<ContextManifestEvidenceItem>, ContextManifestEvidenceStoreError> {
    if let Some(items) =
        agent::load_context_manifest_item_bundle(connection, &manifest_id.to_string())
            .map_err(map_bundle_error)?
    {
        return Ok(items
            .into_iter()
            .map(|item| ContextManifestEvidenceItem {
                item_id: item.item_id,
                ordinal: item.ordinal,
                disposition: item.disposition,
                source_type: item.source_type,
                source_locator: item.source_locator,
                source_content_digest: item.source_content_digest,
                rendered_content_digest: item.rendered_content_digest,
                inclusion_reason: item.inclusion_reason,
                sensitivity: item.sensitivity,
                token_estimate: item.token_estimate,
                transformation: item.transformation,
                policy_decision: item.policy_decision,
                content: item.content,
                content_artifact_id: item.content_artifact_id,
                memory_evidence: item.memory_evidence,
                compaction_id: item.compaction_id,
            })
            .collect());
    }
    let mut statement = connection
        .prepare(
            "SELECT item.ordinal, item.item_id, item.disposition, item.source_type, \
                    item.source_locator, item.source_content_digest, item.rendered_content_digest, \
                    item.inclusion_reason, item.sensitivity, item.token_estimate, \
                    item.transformation, item.policy_decision, \
                    CASE WHEN item.disposition = 'included' THEN item.content_text ELSE NULL END, \
                    CASE WHEN item.disposition = 'included' AND artifact.id IS NOT NULL \
                         THEN item.content_artifact_id ELSE NULL END, \
                    CASE WHEN item.disposition <> 'included' \
                              AND (item.content_text IS NOT NULL \
                                   OR item.content_artifact_id IS NOT NULL) \
                         THEN 1 ELSE 0 END, \
                    CASE WHEN item.content_artifact_id IS NOT NULL AND artifact.id IS NULL \
                         THEN 1 ELSE 0 END \
             FROM context_manifest_item item \
             JOIN context_manifest manifest ON manifest.id = item.manifest_id \
             JOIN session owner_session ON owner_session.id = manifest.session_id \
             LEFT JOIN artifact artifact \
               ON artifact.id = item.content_artifact_id \
              AND artifact.session_id = manifest.session_id \
             WHERE item.manifest_id = ?1 AND owner_session.principal_id = ?2 \
               AND owner_session.channel_binding_id = ?3 \
             ORDER BY item.ordinal",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                manifest_id.to_string(),
                ownership.principal_id().to_string(),
                ownership.channel_binding_id().to_string(),
            ],
            |result| {
                Ok(StoredItem {
                    ordinal: result.get(0)?,
                    item_id: result.get(1)?,
                    disposition: result.get(2)?,
                    source_type: result.get(3)?,
                    source_locator: result.get(4)?,
                    source_content_digest: result.get(5)?,
                    rendered_content_digest: result.get(6)?,
                    inclusion_reason: result.get(7)?,
                    sensitivity: result.get(8)?,
                    token_estimate: result.get(9)?,
                    transformation: result.get(10)?,
                    policy_decision: result.get(11)?,
                    content: result.get(12)?,
                    content_artifact_id: result.get(13)?,
                    withheld_content_present: result.get(14)?,
                    unauthorized_artifact_present: result.get(15)?,
                })
            },
        )
        .map_err(|error| map_sqlite_error(&error))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|error| map_sqlite_error(&error))?;
    rows.into_iter()
        .map(|row| {
            let (memory_evidence, compaction_id) =
                load_phase_five_provenance(connection, manifest_id, row.ordinal, &row.source_type)?;
            row.into_evidence(memory_evidence, compaction_id)
        })
        .collect()
}

fn load_phase_five_provenance(
    connection: &rusqlite::Connection,
    manifest_id: ContextManifestId,
    ordinal: i64,
    source_type: &str,
) -> Result<(Option<ContextMemoryEvidence>, Option<CompactionId>), ContextManifestEvidenceStoreError>
{
    match source_type {
        "memory" => {
            let mut statement = connection
                .prepare(
                    "SELECT memory_id, revision_id, source_ordinal, source_digest \
                     FROM context_memory_citation \
                     WHERE manifest_id = ?1 AND item_ordinal = ?2 ORDER BY source_ordinal",
                )
                .map_err(|error| map_sqlite_error(&error))?;
            let rows = statement
                .query_map(params![manifest_id.to_string(), ordinal], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(|error| map_sqlite_error(&error))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|error| map_sqlite_error(&error))?;
            let Some((first_memory_id, first_revision_id, _, _)) = rows.first() else {
                return Ok((None, None));
            };
            if rows.iter().any(|(memory_id, revision_id, _, _)| {
                memory_id != first_memory_id || revision_id != first_revision_id
            }) {
                return Err(invariant(
                    "context memory citations mix logical memories or revisions",
                ));
            }
            let memory_id = parse_id::<MemoryId>(first_memory_id, "memory ID")?;
            let revision_id =
                parse_id::<MemoryRevisionId>(first_revision_id, "memory revision ID")?;
            let sources = rows
                .into_iter()
                .map(|(_, _, source_ordinal, source_digest)| {
                    Ok(ContextMemorySourceCitation {
                        source_ordinal: nonnegative(source_ordinal, "memory source ordinal")?,
                        source_digest,
                    })
                })
                .collect::<Result<Vec<_>, ContextManifestEvidenceStoreError>>()?;
            Ok((
                Some(ContextMemoryEvidence {
                    memory_id,
                    revision_id,
                    sources,
                }),
                None,
            ))
        }
        "compaction" => {
            let compaction_id = connection
                .query_row(
                    "SELECT compaction_id FROM context_compaction_use \
                     WHERE manifest_id = ?1 AND item_ordinal = ?2",
                    params![manifest_id.to_string(), ordinal],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|error| map_sqlite_error(&error))?
                .as_deref()
                .map(|value| parse_id(value, "compaction ID"))
                .transpose()?;
            Ok((None, compaction_id))
        }
        _ => Ok((None, None)),
    }
}

struct StoredManifest {
    run_id: String,
    turn_id: String,
    epoch_id: String,
    iteration: i64,
    compiler_version: String,
    provider_residency: String,
    token_budget: i64,
    total_token_estimate: i64,
    tool_schema_set_digest: String,
    policy_version: String,
    projection_digest: String,
    created_at_ms: i64,
}

impl StoredManifest {
    fn into_evidence(
        self,
        manifest_id: ContextManifestId,
        items: Vec<ContextManifestEvidenceItem>,
    ) -> Result<ContextManifestEvidence, ContextManifestEvidenceStoreError> {
        Ok(ContextManifestEvidence {
            manifest_id,
            run_id: parse_id(&self.run_id, "run ID")?,
            turn_id: parse_id(&self.turn_id, "turn ID")?,
            epoch_id: parse_id(&self.epoch_id, "context epoch ID")?,
            iteration: nonnegative(self.iteration, "manifest iteration")?,
            compiler_version: self.compiler_version,
            provider_residency: self.provider_residency,
            token_budget: nonnegative(self.token_budget, "manifest token budget")?,
            total_token_estimate: nonnegative(
                self.total_token_estimate,
                "manifest token estimate",
            )?,
            tool_schema_set_digest: self.tool_schema_set_digest,
            policy_version: self.policy_version,
            projection_digest: self.projection_digest,
            items,
            created_at_ms: self.created_at_ms,
        })
    }
}

struct StoredItem {
    ordinal: i64,
    item_id: String,
    disposition: String,
    source_type: String,
    source_locator: String,
    source_content_digest: String,
    rendered_content_digest: String,
    inclusion_reason: String,
    sensitivity: String,
    token_estimate: i64,
    transformation: String,
    policy_decision: String,
    content: Option<String>,
    content_artifact_id: Option<String>,
    withheld_content_present: bool,
    unauthorized_artifact_present: bool,
}

impl StoredItem {
    fn into_evidence(
        self,
        memory_evidence: Option<ContextMemoryEvidence>,
        compaction_id: Option<CompactionId>,
    ) -> Result<ContextManifestEvidenceItem, ContextManifestEvidenceStoreError> {
        if self.withheld_content_present {
            return Err(invariant("withheld context item persisted content"));
        }
        if self.unauthorized_artifact_present {
            return Err(invariant(
                "context item referenced content outside its authorized session",
            ));
        }
        Ok(ContextManifestEvidenceItem {
            item_id: parse_id(&self.item_id, "context item ID")?,
            ordinal: nonnegative(self.ordinal, "context item ordinal")?,
            disposition: parse_disposition(&self.disposition)?,
            source_type: self.source_type,
            source_locator: self.source_locator,
            source_content_digest: self.source_content_digest,
            rendered_content_digest: self.rendered_content_digest,
            inclusion_reason: self.inclusion_reason,
            sensitivity: self.sensitivity,
            token_estimate: nonnegative(self.token_estimate, "context item token estimate")?,
            transformation: self.transformation,
            policy_decision: self.policy_decision,
            content: self.content,
            content_artifact_id: self
                .content_artifact_id
                .as_deref()
                .map(|value| parse_id(value, "content artifact ID"))
                .transpose()?,
            memory_evidence,
            compaction_id,
        })
    }
}

fn parse_disposition(value: &str) -> Result<ContextDisposition, ContextManifestEvidenceStoreError> {
    match value {
        "included" => Ok(ContextDisposition::Included),
        "excluded" => Ok(ContextDisposition::Excluded),
        "redacted" => Ok(ContextDisposition::Redacted),
        _ => Err(invariant("stored context disposition is invalid")),
    }
}

fn nonnegative(value: i64, field: &str) -> Result<u64, ContextManifestEvidenceStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("stored {field} is negative")))
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, ContextManifestEvidenceStoreError> {
    value
        .parse()
        .map_err(|_| invariant(format!("stored {field} is invalid")))
}

fn map_sqlite_error(error: &rusqlite::Error) -> ContextManifestEvidenceStoreError {
    ContextManifestEvidenceStoreError::Unavailable(error.to_string())
}

fn map_bundle_error(error: AgentStoreError) -> ContextManifestEvidenceStoreError {
    match error {
        AgentStoreError::InvariantViolation(message) => invariant(message),
        other => ContextManifestEvidenceStoreError::Unavailable(other.to_string()),
    }
}

fn invariant(message: impl Into<String>) -> ContextManifestEvidenceStoreError {
    ContextManifestEvidenceStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::SqliteStore;
    use mealy_application::{
        ContextDisposition, ContextManifestEvidenceStore, ContextManifestEvidenceStoreError,
        OwnershipContext, estimate_tokens, sha256_digest,
    };
    use mealy_domain::{
        ChannelBindingId, ContextEpochId, ContextItemId, ContextManifestId, CorrelationId, EventId,
        InboxEntryId, OutboxId, PrincipalId, RunId, SessionId, TaskId, TurnId,
    };
    use rusqlite::params;

    #[test]
    fn authorized_projection_is_ordered_and_withholds_excluded_and_redacted_content() {
        let fixture = Fixture::new();
        let evidence = fixture
            .store
            .context_manifest_evidence(fixture.ownership, fixture.manifest_id)
            .expect("authorized context evidence");

        assert_eq!(evidence.manifest_id, fixture.manifest_id);
        assert_eq!(evidence.items.len(), 3);
        assert_eq!(evidence.items[0].ordinal, 0);
        assert_eq!(evidence.items[0].disposition, ContextDisposition::Included);
        assert_eq!(evidence.items[0].content.as_deref(), Some("baseline"));
        assert_eq!(evidence.items[1].ordinal, 1);
        assert_eq!(evidence.items[1].disposition, ContextDisposition::Excluded);
        assert!(evidence.items[1].content.is_none());
        assert!(evidence.items[1].content_artifact_id.is_none());
        assert_eq!(evidence.items[2].ordinal, 2);
        assert_eq!(evidence.items[2].disposition, ContextDisposition::Redacted);
        assert!(evidence.items[2].content.is_none());
        assert!(evidence.items[2].content_artifact_id.is_none());
    }

    #[test]
    fn wrong_principal_or_channel_cannot_enumerate_context_manifests() {
        let fixture = Fixture::new();
        let ownerships = [
            OwnershipContext::new(PrincipalId::new(), fixture.ownership.channel_binding_id()),
            OwnershipContext::new(fixture.ownership.principal_id(), ChannelBindingId::new()),
        ];
        for ownership in ownerships {
            assert_eq!(
                fixture
                    .store
                    .context_manifest_evidence(ownership, fixture.manifest_id),
                Err(ContextManifestEvidenceStoreError::NotFound)
            );
        }
    }

    #[test]
    fn corrupt_withheld_content_is_never_projected() {
        let fixture = Fixture::new();
        fixture
            .store
            .connection
            .pragma_update(None, "ignore_check_constraints", true)
            .expect("disable checks for corruption fixture");
        fixture
            .store
            .connection
            .execute(
                "UPDATE context_manifest_item SET content_text = 'secret leak' \
                 WHERE manifest_id = ?1 AND disposition = 'excluded'",
                [fixture.manifest_id.to_string()],
            )
            .expect("inject corrupt withheld content");
        assert!(matches!(
            fixture
                .store
                .context_manifest_evidence(fixture.ownership, fixture.manifest_id),
            Err(ContextManifestEvidenceStoreError::InvariantViolation(message))
                if message.contains("withheld")
        ));
    }

    struct Fixture {
        store: SqliteStore,
        ownership: OwnershipContext,
        manifest_id: ContextManifestId,
    }

    impl Fixture {
        #[allow(clippy::too_many_lines)]
        fn new() -> Self {
            let store = SqliteStore::open_in_memory(0).expect("open store");
            let principal_id = PrincipalId::new();
            let channel_binding_id = ChannelBindingId::new();
            let session_id = SessionId::new();
            let inbox_id = InboxEntryId::new();
            let task_id = TaskId::new();
            let run_id = RunId::new();
            let turn_id = TurnId::new();
            let epoch_id = ContextEpochId::new();
            let manifest_id = ContextManifestId::new();
            let correlation_id = CorrelationId::new();
            store
                .connection
                .execute(
                    "INSERT INTO session(\
                        id, principal_id, channel_binding_id, created_at_ms, updated_at_ms\
                     ) VALUES (?1, ?2, ?3, 0, 0)",
                    params![
                        session_id.to_string(),
                        principal_id.to_string(),
                        channel_binding_id.to_string()
                    ],
                )
                .expect("seed session");
            store
                .connection
                .execute(
                    "INSERT INTO session_inbox(\
                        inbox_entry_id, session_id, sequence, dedupe_key, delivery_mode, content, \
                        admission_event_id, acknowledgement_outbox_id, correlation_id, accepted_at_ms\
                     ) VALUES (?1, ?2, 1, 'delivery', 'queue', 'hello', ?3, ?4, ?5, 0)",
                    params![
                        inbox_id.to_string(),
                        session_id.to_string(),
                        EventId::new().to_string(),
                        OutboxId::new().to_string(),
                        correlation_id.to_string(),
                    ],
                )
                .expect("seed inbox");
            store
                .connection
                .execute(
                    "INSERT INTO task(id, status, revision, validation_required) \
                     VALUES (?1, 'running', 0, 0)",
                    [task_id.to_string()],
                )
                .expect("seed task");
            store
                .connection
                .execute(
                    "INSERT INTO run(\
                        id, task_id, status, agent_role, capability_ceiling_json, budget_json, \
                        correlation_id, created_at_ms, updated_at_ms\
                     ) VALUES (?1, ?2, 'running', 'assistant', '{}', '{}', ?3, 0, 0)",
                    params![
                        run_id.to_string(),
                        task_id.to_string(),
                        correlation_id.to_string()
                    ],
                )
                .expect("seed run");
            store
                .connection
                .execute(
                    "INSERT INTO turn(\
                        id, session_id, inbox_entry_id, task_id, run_id, correlation_id, created_at_ms\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
                    params![
                        turn_id.to_string(),
                        session_id.to_string(),
                        inbox_id.to_string(),
                        task_id.to_string(),
                        run_id.to_string(),
                        correlation_id.to_string(),
                    ],
                )
                .expect("seed turn");
            let baseline_digest = sha256_digest(b"baseline");
            store
                .connection
                .execute(
                    "INSERT INTO context_epoch(\
                        id, session_id, epoch_number, baseline_version, baseline_digest, baseline_text, \
                        agent_profile_json, workspace_identity, config_digest, policy_digest, created_at_ms\
                     ) VALUES (?1, ?2, 1, 'v1', ?3, 'baseline', '{}', 'workspace', ?4, ?5, 0)",
                    params![
                        epoch_id.to_string(),
                        session_id.to_string(),
                        baseline_digest,
                        sha256_digest(b"config"),
                        sha256_digest(b"policy"),
                    ],
                )
                .expect("seed epoch");
            store
                .connection
                .execute(
                    "UPDATE session SET current_context_epoch_id = ?1 WHERE id = ?2",
                    params![epoch_id.to_string(), session_id.to_string()],
                )
                .expect("pin session epoch");
            store
                .connection
                .execute(
                    "UPDATE turn SET context_epoch_id = ?1 WHERE id = ?2",
                    params![epoch_id.to_string(), turn_id.to_string()],
                )
                .expect("pin turn epoch");
            let baseline_tokens = estimate_tokens("baseline");
            store
                .connection
                .execute(
                    "INSERT INTO context_manifest(\
                        id, run_id, session_id, turn_id, epoch_id, iteration, compiler_version, \
                        provider_residency, token_budget, total_token_estimate, \
                        tool_schema_set_digest, policy_version, projection_digest, created_at_ms\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 'v1', 'local', 100, ?6, ?7, 'v1', ?8, 1)",
                    params![
                        manifest_id.to_string(),
                        run_id.to_string(),
                        session_id.to_string(),
                        turn_id.to_string(),
                        epoch_id.to_string(),
                        i64::try_from(baseline_tokens).expect("token estimate fits SQLite"),
                        sha256_digest(b"tools"),
                        sha256_digest(b"projection"),
                    ],
                )
                .expect("seed manifest");
            let items = [
                (
                    ContextItemId::new(),
                    0_i64,
                    "included",
                    "baseline",
                    "baseline://v1",
                    "baseline",
                    baseline_tokens,
                    Some("baseline"),
                ),
                (
                    ContextItemId::new(),
                    1_i64,
                    "excluded",
                    "user",
                    "inbox://entry",
                    "excluded secret",
                    10,
                    None,
                ),
                (
                    ContextItemId::new(),
                    2_i64,
                    "redacted",
                    "memory",
                    "memory://private",
                    "redacted secret",
                    10,
                    None,
                ),
            ];
            for (
                item_id,
                ordinal,
                disposition,
                source_type,
                locator,
                digest_source,
                tokens,
                content,
            ) in items
            {
                let digest = sha256_digest(digest_source.as_bytes());
                store
                    .connection
                    .execute(
                        "INSERT INTO context_manifest_item(\
                            manifest_id, ordinal, item_id, disposition, source_type, source_locator, \
                            source_content_digest, rendered_content_digest, inclusion_reason, \
                            sensitivity, token_estimate, transformation, policy_decision, content_text\
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 'fixture decision', \
                                   'private', ?8, 'identity', 'fixture policy', ?9)",
                        params![
                            manifest_id.to_string(),
                            ordinal,
                            item_id.to_string(),
                            disposition,
                            source_type,
                            locator,
                            digest,
                            i64::try_from(tokens).expect("token estimate fits SQLite"),
                            content,
                        ],
                    )
                    .expect("seed manifest item");
            }
            Self {
                store,
                ownership: OwnershipContext::new(principal_id, channel_binding_id),
                manifest_id,
            }
        }
    }
}
