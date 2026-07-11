use super::{SqliteStore, agent};
use mealy_application::{
    BeginExtensionInvocationCommit, CompleteExtensionInvocationCommit, DisableExtensionCommit,
    EnableExtensionCommit, ExtensionGrant, ExtensionInvocationStatus, ExtensionInvocationTerminal,
    ExtensionInvocationView, ExtensionManifestRevisionView, ExtensionStore, ExtensionStoreError,
    ExtensionView, InstallExtensionCommit, OwnershipContext, RevokeExtensionCommit,
    StageExtensionManifestCommit, extension_grant_digest, is_sha256_digest, sha256_digest,
    validate_extension_object,
};
use mealy_domain::{
    CorrelationId, EventId, ExtensionId, ExtensionInvocationId, ExtensionManifest, ExtensionStatus,
    PrincipalId,
};
use rusqlite::{ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use std::{str::FromStr, time::SystemTime};

impl SqliteStore {
    /// Idempotently registers the trusted local principal/channel loaded from owner-only config.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionStoreError`] if the identity conflicts with a revoked or differently
    /// owned binding, or persistence is unavailable.
    pub fn register_local_identity(
        &mut self,
        ownership: OwnershipContext,
        registered_at_ms: i64,
    ) -> Result<(), ExtensionStoreError> {
        if registered_at_ms < 0 {
            return Err(invalid_contract("identity registration time is invalid"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO principal_registry(\
                    principal_id, status, revision, created_at_ms, updated_at_ms\
                 ) VALUES (?1, 'active', 0, ?2, ?2) ON CONFLICT(principal_id) DO NOTHING",
                params![ownership.principal_id().to_string(), registered_at_ms],
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO channel_binding_registry(\
                    binding_id, principal_id, channel_kind, status, revision, \
                    created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, 'local_cli', 'active', 0, ?3, ?3) \
                 ON CONFLICT(binding_id) DO NOTHING",
                params![
                    ownership.channel_binding_id().to_string(),
                    ownership.principal_id().to_string(),
                    registered_at_ms,
                ],
            )
            .map_err(map_sqlite_error)?;
        authorize_identity(&transaction, ownership)?;
        transaction.commit().map_err(map_sqlite_error)
    }
}

impl ExtensionStore for SqliteStore {
    fn install_extension(
        &mut self,
        commit: InstallExtensionCommit,
    ) -> Result<ExtensionView, ExtensionStoreError> {
        validate_inspection(
            &commit.inspection.manifest,
            &commit.inspection.manifest_json,
            &commit.inspection.manifest_digest,
            &commit.installation_root,
        )?;
        let installed_at_ms = epoch_milliseconds(commit.installed_at)?;
        let extension_id = commit.inspection.manifest.extension_id;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        authorize_identity(&transaction, commit.ownership)?;
        append_event(
            &transaction,
            "extension",
            &extension_id.to_string(),
            commit.event_id,
            "extension.installed",
            installed_at_ms,
            commit.ownership.principal_id(),
            commit.correlation_id,
            &json!({
                "extension_id": extension_id,
                "manifest_digest": commit.inspection.manifest_digest,
                "version": commit.inspection.manifest.version,
            }),
        )?;
        transaction
            .execute(
                "INSERT INTO extension_installation(\
                    extension_id, principal_id, status, revision, name, publisher, \
                    current_manifest_ordinal, current_manifest_digest, current_version, \
                    created_event_id, updated_event_id, created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, 'installed', 0, ?3, ?4, 1, ?5, ?6, ?7, ?7, ?8, ?8)",
                params![
                    extension_id.to_string(),
                    commit.ownership.principal_id().to_string(),
                    commit.inspection.manifest.name,
                    commit.inspection.manifest.publisher,
                    commit.inspection.manifest_digest,
                    commit.inspection.manifest.version,
                    commit.event_id.to_string(),
                    installed_at_ms,
                ],
            )
            .map_err(map_sqlite_error)?;
        insert_manifest_revision(
            &transaction,
            extension_id,
            1,
            &commit.inspection.manifest_digest,
            &commit.inspection.manifest.version,
            &commit.inspection.manifest_json,
            &commit.installation_root,
            commit.event_id,
            installed_at_ms,
        )?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_extension(&self.connection, commit.ownership, extension_id)
    }

    fn stage_extension_manifest(
        &mut self,
        commit: StageExtensionManifestCommit,
    ) -> Result<ExtensionView, ExtensionStoreError> {
        if commit.extension_id != commit.inspection.manifest.extension_id {
            return Err(invalid_contract(
                "staged manifest extension identity changed",
            ));
        }
        validate_inspection(
            &commit.inspection.manifest,
            &commit.inspection.manifest_json,
            &commit.inspection.manifest_digest,
            &commit.installation_root,
        )?;
        let staged_at_ms = epoch_milliseconds(commit.staged_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        authorize_identity(&transaction, commit.ownership)?;
        let current = load_current_for_mutation(
            &transaction,
            commit.ownership,
            commit.extension_id,
            commit.expected_revision,
        )?;
        if current.status == "revoked"
            || current.name != commit.inspection.manifest.name
            || current.publisher != commit.inspection.manifest.publisher
            || current.manifest_digest == commit.inspection.manifest_digest
        {
            return Err(ExtensionStoreError::Conflict);
        }
        let ordinal = current
            .manifest_ordinal
            .checked_add(1)
            .ok_or_else(|| invariant("extension manifest ordinal overflowed"))?;
        append_event(
            &transaction,
            "extension",
            &commit.extension_id.to_string(),
            commit.event_id,
            "extension.manifest_staged",
            staged_at_ms,
            commit.ownership.principal_id(),
            commit.correlation_id,
            &json!({
                "extension_id": commit.extension_id,
                "previous_manifest_digest": current.manifest_digest,
                "manifest_digest": commit.inspection.manifest_digest,
                "version": commit.inspection.manifest.version,
                "authority_reset": true,
            }),
        )?;
        terminalize_active_grant(
            &transaction,
            current.active_grant_id.as_deref(),
            "superseded",
            commit.event_id,
            staged_at_ms,
        )?;
        insert_manifest_revision(
            &transaction,
            commit.extension_id,
            ordinal,
            &commit.inspection.manifest_digest,
            &commit.inspection.manifest.version,
            &commit.inspection.manifest_json,
            &commit.installation_root,
            commit.event_id,
            staged_at_ms,
        )?;
        let changed = transaction
            .execute(
                "UPDATE extension_installation SET status = 'installed', revision = revision + 1, \
                    current_manifest_ordinal = ?1, current_manifest_digest = ?2, \
                    current_version = ?3, active_grant_id = NULL, active_grant_digest = NULL, \
                    updated_event_id = ?4, updated_at_ms = ?5 \
                 WHERE extension_id = ?6 AND principal_id = ?7 AND revision = ?8 \
                   AND status <> 'revoked'",
                params![
                    ordinal,
                    commit.inspection.manifest_digest,
                    commit.inspection.manifest.version,
                    commit.event_id.to_string(),
                    staged_at_ms,
                    commit.extension_id.to_string(),
                    commit.ownership.principal_id().to_string(),
                    to_i64(commit.expected_revision, "expected extension revision")?,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(ExtensionStoreError::Conflict);
        }
        transaction.commit().map_err(map_sqlite_error)?;
        load_extension(&self.connection, commit.ownership, commit.extension_id)
    }

    fn enable_extension(
        &mut self,
        commit: EnableExtensionCommit,
    ) -> Result<ExtensionView, ExtensionStoreError> {
        let enabled_at_ms = epoch_milliseconds(commit.enabled_at)?;
        if commit.grant.issued_at_ms > enabled_at_ms
            || !is_sha256_digest(&commit.health_output_digest)
        {
            return Err(invalid_contract(
                "extension grant issue time or health evidence is invalid",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        authorize_identity(&transaction, commit.ownership)?;
        let current = load_current_for_mutation(
            &transaction,
            commit.ownership,
            commit.extension_id,
            commit.expected_revision,
        )?;
        if !matches!(current.status.as_str(), "installed" | "disabled" | "failed") {
            return Err(ExtensionStoreError::Conflict);
        }
        let manifest = load_manifest_at(
            &transaction,
            commit.extension_id,
            current.manifest_ordinal,
            &current.manifest_digest,
        )?;
        commit
            .grant
            .validate(&manifest.manifest, commit.ownership)
            .map_err(|error| invalid_contract(error.to_string()))?;
        if commit.grant.manifest_digest != current.manifest_digest {
            return Err(ExtensionStoreError::Conflict);
        }
        let grant_digest = extension_grant_digest(&commit.grant)
            .map_err(|error| invalid_contract(error.to_string()))?;
        let grant_json = serde_json::to_string(&commit.grant)
            .map_err(|error| invalid_contract(error.to_string()))?;
        append_event(
            &transaction,
            "extension",
            &commit.extension_id.to_string(),
            commit.event_id,
            "extension.enabled",
            enabled_at_ms,
            commit.ownership.principal_id(),
            commit.correlation_id,
            &json!({
                "extension_id": commit.extension_id,
                "manifest_digest": current.manifest_digest,
                "grant_id": commit.grant.grant_id,
                "grant_digest": grant_digest,
                "capability_ids": commit.grant.capability_ids,
                "health_output_digest": commit.health_output_digest,
            }),
        )?;
        transaction
            .execute(
                "INSERT INTO extension_grant(\
                    grant_id, extension_id, manifest_ordinal, manifest_digest, grant_json, \
                    grant_digest, status, issued_by_principal_id, issued_event_id, issued_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', ?7, ?8, ?9)",
                params![
                    commit.grant.grant_id.to_string(),
                    commit.extension_id.to_string(),
                    current.manifest_ordinal,
                    current.manifest_digest,
                    grant_json,
                    grant_digest,
                    commit.ownership.principal_id().to_string(),
                    commit.event_id.to_string(),
                    commit.grant.issued_at_ms,
                ],
            )
            .map_err(map_sqlite_error)?;
        let changed = transaction
            .execute(
                "UPDATE extension_installation SET status = 'enabled', revision = revision + 1, \
                    active_grant_id = ?1, active_grant_digest = ?2, updated_event_id = ?3, \
                    updated_at_ms = ?4, last_healthy_at_ms = ?4 \
                 WHERE extension_id = ?5 AND principal_id = ?6 AND revision = ?7 \
                   AND status IN ('installed', 'disabled', 'failed')",
                params![
                    commit.grant.grant_id.to_string(),
                    grant_digest,
                    commit.event_id.to_string(),
                    enabled_at_ms,
                    commit.extension_id.to_string(),
                    commit.ownership.principal_id().to_string(),
                    to_i64(commit.expected_revision, "expected extension revision")?,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(ExtensionStoreError::Conflict);
        }
        transaction.commit().map_err(map_sqlite_error)?;
        load_extension(&self.connection, commit.ownership, commit.extension_id)
    }

    fn disable_extension(
        &mut self,
        commit: DisableExtensionCommit,
    ) -> Result<ExtensionView, ExtensionStoreError> {
        transition_out_of_enabled(
            &mut self.connection,
            commit.ownership,
            commit.extension_id,
            commit.expected_revision,
            "disabled",
            "extension.disabled",
            commit.event_id,
            commit.correlation_id,
            epoch_milliseconds(commit.disabled_at)?,
        )
    }

    fn revoke_extension(
        &mut self,
        commit: RevokeExtensionCommit,
    ) -> Result<ExtensionView, ExtensionStoreError> {
        let revoked_at_ms = epoch_milliseconds(commit.revoked_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        authorize_identity(&transaction, commit.ownership)?;
        let current = load_current_for_mutation(
            &transaction,
            commit.ownership,
            commit.extension_id,
            commit.expected_revision,
        )?;
        if current.status == "revoked" {
            return Err(ExtensionStoreError::Conflict);
        }
        append_event(
            &transaction,
            "extension",
            &commit.extension_id.to_string(),
            commit.event_id,
            "extension.revoked",
            revoked_at_ms,
            commit.ownership.principal_id(),
            commit.correlation_id,
            &json!({
                "extension_id": commit.extension_id,
                "manifest_digest": current.manifest_digest,
            }),
        )?;
        terminalize_active_grant(
            &transaction,
            current.active_grant_id.as_deref(),
            "revoked",
            commit.event_id,
            revoked_at_ms,
        )?;
        let changed = transaction
            .execute(
                "UPDATE extension_installation SET status = 'revoked', revision = revision + 1, \
                    active_grant_id = NULL, active_grant_digest = NULL, updated_event_id = ?1, \
                    updated_at_ms = ?2 \
                 WHERE extension_id = ?3 AND principal_id = ?4 AND revision = ?5 \
                   AND status <> 'revoked'",
                params![
                    commit.event_id.to_string(),
                    revoked_at_ms,
                    commit.extension_id.to_string(),
                    commit.ownership.principal_id().to_string(),
                    to_i64(commit.expected_revision, "expected extension revision")?,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(ExtensionStoreError::Conflict);
        }
        transaction.commit().map_err(map_sqlite_error)?;
        load_extension(&self.connection, commit.ownership, commit.extension_id)
    }

    fn extension(
        &self,
        ownership: OwnershipContext,
        extension_id: ExtensionId,
    ) -> Result<ExtensionView, ExtensionStoreError> {
        load_extension(&self.connection, ownership, extension_id)
    }

    fn extensions(
        &self,
        ownership: OwnershipContext,
    ) -> Result<Vec<ExtensionView>, ExtensionStoreError> {
        authorize_identity(&self.connection, ownership)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT extension_id FROM extension_installation WHERE principal_id = ?1 \
                 ORDER BY created_at_ms, extension_id",
            )
            .map_err(map_sqlite_error)?;
        let ids = statement
            .query_map([ownership.principal_id().to_string()], |row| {
                row.get::<_, String>(0)
            })
            .map_err(map_sqlite_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_sqlite_error)?;
        ids.into_iter()
            .map(|id| load_extension(&self.connection, ownership, parse_id(&id, "extension ID")?))
            .collect()
    }

    fn begin_extension_invocation(
        &mut self,
        commit: BeginExtensionInvocationCommit,
    ) -> Result<ExtensionInvocationView, ExtensionStoreError> {
        if !is_sha256_digest(&commit.manifest_digest)
            || !is_sha256_digest(&commit.grant_digest)
            || !is_sha256_digest(&commit.input_digest)
            || !valid_field(&commit.capability_id, 255)
        {
            return Err(invalid_contract("extension invocation identity is invalid"));
        }
        let started_at_ms = epoch_milliseconds(commit.started_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        authorize_identity(&transaction, commit.ownership)?;
        let view = load_extension(&transaction, commit.ownership, commit.extension_id)?;
        let grant = view
            .active_grant
            .as_ref()
            .ok_or(ExtensionStoreError::Conflict)?;
        if view.status != ExtensionStatus::Enabled
            || view.revision != commit.expected_extension_revision
            || view.current_manifest_digest != commit.manifest_digest
            || grant.grant_id != commit.grant_id
            || view.active_grant_digest.as_deref() != Some(commit.grant_digest.as_str())
            || !grant.capability_ids.contains(&commit.capability_id)
        {
            return Err(ExtensionStoreError::Conflict);
        }
        let manifest_ordinal = i64::try_from(view.manifest_history.len())
            .map_err(|_| invariant("extension manifest ordinal overflowed"))?;
        append_event(
            &transaction,
            "extension_invocation",
            &commit.invocation_id.to_string(),
            commit.event_id,
            "extension.invocation_dispatching",
            started_at_ms,
            commit.ownership.principal_id(),
            commit.correlation_id,
            &json!({
                "extension_id": commit.extension_id,
                "invocation_id": commit.invocation_id,
                "manifest_digest": commit.manifest_digest,
                "grant_id": commit.grant_id,
                "grant_digest": commit.grant_digest,
                "capability_id": commit.capability_id,
                "input_digest": commit.input_digest,
            }),
        )?;
        transaction
            .execute(
                "INSERT INTO extension_invocation(\
                    invocation_id, extension_id, principal_id, channel_binding_id, \
                    manifest_ordinal, manifest_digest, grant_id, grant_digest, capability_id, \
                    input_digest, status, started_event_id, started_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'dispatching', ?11, ?12)",
                params![
                    commit.invocation_id.to_string(),
                    commit.extension_id.to_string(),
                    commit.ownership.principal_id().to_string(),
                    commit.ownership.channel_binding_id().to_string(),
                    manifest_ordinal,
                    commit.manifest_digest,
                    commit.grant_id.to_string(),
                    commit.grant_digest,
                    commit.capability_id,
                    commit.input_digest,
                    commit.event_id.to_string(),
                    started_at_ms,
                ],
            )
            .map_err(map_sqlite_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_invocation(&self.connection, commit.ownership, commit.invocation_id)
    }

    fn complete_extension_invocation(
        &mut self,
        commit: CompleteExtensionInvocationCommit,
    ) -> Result<ExtensionInvocationView, ExtensionStoreError> {
        let completed_at_ms = epoch_milliseconds(commit.completed_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let current = load_invocation_unchecked(&transaction, commit.invocation_id)?;
        if current.principal_id != commit.ownership.principal_id()
            || current.channel_binding_id != commit.ownership.channel_binding_id()
            || current.status != ExtensionInvocationStatus::Dispatching
        {
            return Err(ExtensionStoreError::Conflict);
        }
        if !matches!(commit.terminal, ExtensionInvocationTerminal::Abandoned) {
            authorize_identity(&transaction, commit.ownership)?;
        }
        let (status, response_json, output_digest, error_class, error_message, event_type) =
            terminal_material(&transaction, &current, &commit.terminal)?;
        append_event(
            &transaction,
            "extension_invocation",
            &commit.invocation_id.to_string(),
            commit.event_id,
            event_type,
            completed_at_ms,
            commit.ownership.principal_id(),
            commit.correlation_id,
            &json!({
                "extension_id": current.extension_id,
                "invocation_id": commit.invocation_id,
                "status": status,
                "output_digest": output_digest,
                "error_class": error_class,
                "duration_ms": commit.duration_ms,
            }),
        )?;
        let changed = transaction
            .execute(
                "UPDATE extension_invocation SET status = ?1, response_json = ?2, \
                    output_digest = ?3, error_class = ?4, error_message = ?5, duration_ms = ?6, \
                    completed_event_id = ?7, completed_at_ms = ?8 \
                 WHERE invocation_id = ?9 AND status = 'dispatching'",
                params![
                    status,
                    response_json,
                    output_digest,
                    error_class,
                    error_message,
                    to_i64(commit.duration_ms, "extension invocation duration")?,
                    commit.event_id.to_string(),
                    completed_at_ms,
                    commit.invocation_id.to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(ExtensionStoreError::Conflict);
        }
        transaction.commit().map_err(map_sqlite_error)?;
        load_invocation(&self.connection, commit.ownership, commit.invocation_id)
    }

    fn incomplete_extension_invocations(
        &self,
        limit: usize,
    ) -> Result<Vec<ExtensionInvocationView>, ExtensionStoreError> {
        if !(1..=1_000).contains(&limit) {
            return Err(invalid_contract(
                "extension recovery limit must be between 1 and 1000",
            ));
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT invocation_id FROM extension_invocation WHERE status = 'dispatching' \
                 ORDER BY started_at_ms, invocation_id LIMIT ?1",
            )
            .map_err(map_sqlite_error)?;
        let ids = statement
            .query_map(
                [i64::try_from(limit)
                    .map_err(|_| invalid_contract("extension recovery limit overflowed"))?],
                |row| row.get::<_, String>(0),
            )
            .map_err(map_sqlite_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_sqlite_error)?;
        ids.into_iter()
            .map(|id| {
                load_invocation_unchecked(
                    &self.connection,
                    parse_id(&id, "extension invocation ID")?,
                )
            })
            .collect()
    }
}

#[allow(clippy::too_many_arguments)]
fn transition_out_of_enabled(
    connection: &mut rusqlite::Connection,
    ownership: OwnershipContext,
    extension_id: ExtensionId,
    expected_revision: u64,
    status: &str,
    event_type: &str,
    event_id: EventId,
    correlation_id: CorrelationId,
    occurred_at_ms: i64,
) -> Result<ExtensionView, ExtensionStoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sqlite_error)?;
    authorize_identity(&transaction, ownership)?;
    let current =
        load_current_for_mutation(&transaction, ownership, extension_id, expected_revision)?;
    if current.status != "enabled" || current.active_grant_id.is_none() {
        return Err(ExtensionStoreError::Conflict);
    }
    append_event(
        &transaction,
        "extension",
        &extension_id.to_string(),
        event_id,
        event_type,
        occurred_at_ms,
        ownership.principal_id(),
        correlation_id,
        &json!({
            "extension_id": extension_id,
            "manifest_digest": current.manifest_digest,
            "status": status,
        }),
    )?;
    terminalize_active_grant(
        &transaction,
        current.active_grant_id.as_deref(),
        "revoked",
        event_id,
        occurred_at_ms,
    )?;
    let changed = transaction
        .execute(
            "UPDATE extension_installation SET status = ?1, revision = revision + 1, \
                active_grant_id = NULL, active_grant_digest = NULL, updated_event_id = ?2, \
                updated_at_ms = ?3 \
             WHERE extension_id = ?4 AND principal_id = ?5 AND revision = ?6 \
               AND status = 'enabled'",
            params![
                status,
                event_id.to_string(),
                occurred_at_ms,
                extension_id.to_string(),
                ownership.principal_id().to_string(),
                to_i64(expected_revision, "expected extension revision")?,
            ],
        )
        .map_err(map_sqlite_error)?;
    if changed != 1 {
        return Err(ExtensionStoreError::Conflict);
    }
    transaction.commit().map_err(map_sqlite_error)?;
    load_extension(connection, ownership, extension_id)
}

struct CurrentExtension {
    status: String,
    name: String,
    publisher: String,
    manifest_ordinal: i64,
    manifest_digest: String,
    active_grant_id: Option<String>,
}

fn load_current_for_mutation(
    transaction: &Transaction<'_>,
    ownership: OwnershipContext,
    extension_id: ExtensionId,
    expected_revision: u64,
) -> Result<CurrentExtension, ExtensionStoreError> {
    transaction
        .query_row(
            "SELECT status, name, publisher, current_manifest_ordinal, \
                    current_manifest_digest, active_grant_id \
             FROM extension_installation \
             WHERE extension_id = ?1 AND principal_id = ?2 AND revision = ?3",
            params![
                extension_id.to_string(),
                ownership.principal_id().to_string(),
                to_i64(expected_revision, "expected extension revision")?,
            ],
            |row| {
                Ok(CurrentExtension {
                    status: row.get(0)?,
                    name: row.get(1)?,
                    publisher: row.get(2)?,
                    manifest_ordinal: row.get(3)?,
                    manifest_digest: row.get(4)?,
                    active_grant_id: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(ExtensionStoreError::NotFound)
}

#[allow(clippy::too_many_arguments)]
fn insert_manifest_revision(
    transaction: &Transaction<'_>,
    extension_id: ExtensionId,
    ordinal: i64,
    manifest_digest: &str,
    version: &str,
    manifest_json: &str,
    installation_root: &str,
    event_id: EventId,
    installed_at_ms: i64,
) -> Result<(), ExtensionStoreError> {
    transaction
        .execute(
            "INSERT INTO extension_manifest_revision(\
                extension_id, ordinal, manifest_digest, version, manifest_json, \
                installation_root, installed_event_id, installed_at_ms\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                extension_id.to_string(),
                ordinal,
                manifest_digest,
                version,
                manifest_json,
                installation_root,
                event_id.to_string(),
                installed_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn terminalize_active_grant(
    transaction: &Transaction<'_>,
    grant_id: Option<&str>,
    status: &str,
    event_id: EventId,
    terminal_at_ms: i64,
) -> Result<(), ExtensionStoreError> {
    if let Some(grant_id) = grant_id {
        let changed = transaction
            .execute(
                "UPDATE extension_grant SET status = ?1, terminal_event_id = ?2, \
                    terminal_at_ms = ?3 WHERE grant_id = ?4 AND status = 'active'",
                params![status, event_id.to_string(), terminal_at_ms, grant_id],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(ExtensionStoreError::Conflict);
        }
    }
    Ok(())
}

fn load_extension(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
    extension_id: ExtensionId,
) -> Result<ExtensionView, ExtensionStoreError> {
    authorize_identity(connection, ownership)?;
    let row = connection
        .query_row(
            "SELECT principal_id, status, revision, current_manifest_ordinal, \
                    current_manifest_digest, active_grant_id, active_grant_digest, \
                    last_healthy_at_ms, last_failure_at_ms \
             FROM extension_installation WHERE extension_id = ?1 AND principal_id = ?2",
            params![
                extension_id.to_string(),
                ownership.principal_id().to_string(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(ExtensionStoreError::NotFound)?;
    let history = load_manifest_history(connection, extension_id)?;
    let current_index = usize::try_from(row.3)
        .ok()
        .and_then(|ordinal| ordinal.checked_sub(1))
        .ok_or_else(|| invariant("stored extension manifest ordinal is invalid"))?;
    let current = history
        .get(current_index)
        .ok_or_else(|| invariant("current extension manifest history is absent"))?;
    if current.manifest_digest != row.4 {
        return Err(invariant("current extension manifest digest diverged"));
    }
    let status = parse_extension_status(&row.1)?;
    let (active_grant, active_grant_digest) = match (row.5, row.6) {
        (Some(grant_id), Some(digest)) if status == ExtensionStatus::Enabled => {
            let grant_json = connection
                .query_row(
                    "SELECT grant_json FROM extension_grant \
                     WHERE grant_id = ?1 AND extension_id = ?2 AND grant_digest = ?3 \
                       AND status = 'active'",
                    params![grant_id, extension_id.to_string(), digest],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(map_sqlite_error)?
                .ok_or_else(|| invariant("active extension grant is absent"))?;
            let grant = serde_json::from_str::<ExtensionGrant>(&grant_json)
                .map_err(|error| invariant(error.to_string()))?;
            if extension_grant_digest(&grant).map_err(|error| invariant(error.to_string()))?
                != digest
            {
                return Err(invariant("active extension grant digest diverged"));
            }
            grant
                .validate(&current.manifest, ownership)
                .map_err(|error| invariant(error.to_string()))?;
            (Some(grant), Some(digest))
        }
        (None, None) if status != ExtensionStatus::Enabled => (None, None),
        _ => return Err(invariant("extension lifecycle and active grant diverged")),
    };
    Ok(ExtensionView {
        extension_id,
        principal_id: parse_id(&row.0, "extension principal ID")?,
        status,
        revision: nonnegative(row.2, "extension revision")?,
        current_manifest_digest: row.4,
        manifest: current.manifest.clone(),
        active_grant,
        active_grant_digest,
        manifest_history: history,
        last_healthy_at_ms: row.7,
        last_failure_at_ms: row.8,
    })
}

fn load_manifest_history(
    connection: &rusqlite::Connection,
    extension_id: ExtensionId,
) -> Result<Vec<ExtensionManifestRevisionView>, ExtensionStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT ordinal, manifest_digest, manifest_json, installation_root, installed_at_ms \
             FROM extension_manifest_revision WHERE extension_id = ?1 ORDER BY ordinal",
        )
        .map_err(map_sqlite_error)?;
    let rows = statement
        .query_map([extension_id.to_string()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(map_sqlite_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_sqlite_error)?;
    rows.into_iter()
        .enumerate()
        .map(
            |(index, (ordinal, digest, manifest_json, installation_root, installed_at_ms))| {
                if usize::try_from(ordinal).ok() != index.checked_add(1)
                    || sha256_digest(manifest_json.as_bytes()) != digest
                {
                    return Err(invariant("extension manifest history is inconsistent"));
                }
                let manifest = serde_json::from_str::<ExtensionManifest>(&manifest_json)
                    .map_err(|error| invariant(error.to_string()))?;
                manifest
                    .validate()
                    .map_err(|error| invariant(error.to_string()))?;
                if manifest.extension_id != extension_id {
                    return Err(invariant("extension manifest history identity diverged"));
                }
                Ok(ExtensionManifestRevisionView {
                    manifest_digest: digest,
                    manifest,
                    manifest_json,
                    installation_root,
                    installed_at_ms,
                })
            },
        )
        .collect()
}

fn load_manifest_at(
    connection: &rusqlite::Connection,
    extension_id: ExtensionId,
    ordinal: i64,
    digest: &str,
) -> Result<ExtensionManifestRevisionView, ExtensionStoreError> {
    let history = load_manifest_history(connection, extension_id)?;
    let index = usize::try_from(ordinal)
        .ok()
        .and_then(|ordinal| ordinal.checked_sub(1))
        .ok_or_else(|| invariant("extension manifest ordinal is invalid"))?;
    let manifest = history
        .into_iter()
        .nth(index)
        .ok_or_else(|| invariant("extension manifest revision is absent"))?;
    if manifest.manifest_digest != digest {
        return Err(invariant("extension manifest revision digest diverged"));
    }
    Ok(manifest)
}

type TerminalMaterial = (
    &'static str,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    &'static str,
);

fn terminal_material(
    connection: &rusqlite::Connection,
    invocation: &ExtensionInvocationView,
    terminal: &ExtensionInvocationTerminal,
) -> Result<TerminalMaterial, ExtensionStoreError> {
    match terminal {
        ExtensionInvocationTerminal::Succeeded(response) => {
            if response.invocation_id != invocation.invocation_id
                || response.extension_id != invocation.extension_id
                || response.manifest_digest != invocation.manifest_digest
                || response.grant_digest != invocation.grant_digest
                || response.capability_id != invocation.capability_id
                || !is_sha256_digest(&response.output_digest)
                || sha256_digest(
                    &serde_json::to_vec(&response.output)
                        .map_err(|error| invalid_contract(error.to_string()))?,
                ) != response.output_digest
            {
                return Err(invalid_contract(
                    "extension response does not bind the dispatch",
                ));
            }
            let manifest_ordinal = connection
                .query_row(
                    "SELECT manifest_ordinal FROM extension_invocation WHERE invocation_id = ?1",
                    [invocation.invocation_id.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(map_sqlite_error)?;
            let manifest = load_manifest_at(
                connection,
                invocation.extension_id,
                manifest_ordinal,
                &invocation.manifest_digest,
            )?;
            let capability = manifest
                .manifest
                .capability(&invocation.capability_id)
                .ok_or_else(|| invariant("stored extension capability is absent"))?;
            validate_extension_object(&response.output, &capability.output_schema)
                .map_err(|error| invalid_contract(error.to_string()))?;
            Ok((
                "succeeded",
                Some(
                    serde_json::to_string(response)
                        .map_err(|error| invalid_contract(error.to_string()))?,
                ),
                Some(response.output_digest.clone()),
                None,
                None,
                "extension.invocation_succeeded",
            ))
        }
        ExtensionInvocationTerminal::Failed {
            error_class,
            error_message,
        } => {
            if !valid_field(error_class, 255) || !valid_field(error_message, 4_096) {
                return Err(invalid_contract("extension failure evidence is invalid"));
            }
            Ok((
                "failed",
                None,
                None,
                Some(error_class.clone()),
                Some(error_message.clone()),
                "extension.invocation_failed",
            ))
        }
        ExtensionInvocationTerminal::Abandoned => Ok((
            "abandoned",
            None,
            None,
            Some("daemon_restart".to_owned()),
            Some("invocation had no terminal evidence at startup recovery".to_owned()),
            "extension.invocation_abandoned",
        )),
    }
}

fn load_invocation(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
    invocation_id: ExtensionInvocationId,
) -> Result<ExtensionInvocationView, ExtensionStoreError> {
    authorize_identity(connection, ownership)?;
    let view = load_invocation_unchecked(connection, invocation_id)?;
    if view.principal_id != ownership.principal_id()
        || view.channel_binding_id != ownership.channel_binding_id()
    {
        return Err(ExtensionStoreError::NotFound);
    }
    Ok(view)
}

fn load_invocation_unchecked(
    connection: &rusqlite::Connection,
    invocation_id: ExtensionInvocationId,
) -> Result<ExtensionInvocationView, ExtensionStoreError> {
    let row = connection
        .query_row(
            "SELECT extension_id, principal_id, channel_binding_id, manifest_digest, grant_id, \
                    grant_digest, capability_id, input_digest, status, response_json, \
                    output_digest, error_class, error_message, duration_ms, started_at_ms, \
                    completed_at_ms \
             FROM extension_invocation WHERE invocation_id = ?1",
            [invocation_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, Option<i64>>(15)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(ExtensionStoreError::NotFound)?;
    let response = row
        .9
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|error| invariant(error.to_string()))?;
    let status = parse_invocation_status(&row.8)?;
    let view = ExtensionInvocationView {
        invocation_id,
        extension_id: parse_id(&row.0, "invocation extension ID")?,
        principal_id: parse_id(&row.1, "invocation principal ID")?,
        channel_binding_id: parse_id(&row.2, "invocation channel binding ID")?,
        manifest_digest: row.3,
        grant_id: parse_id(&row.4, "invocation grant ID")?,
        grant_digest: row.5,
        capability_id: row.6,
        input_digest: row.7,
        status,
        output_digest: row.10,
        response,
        error_class: row.11,
        error_message: row.12,
        duration_ms: row
            .13
            .map(|value| nonnegative(value, "invocation duration"))
            .transpose()?,
        started_at_ms: row.14,
        completed_at_ms: row.15,
    };
    validate_invocation_view(&view)?;
    Ok(view)
}

fn validate_invocation_view(view: &ExtensionInvocationView) -> Result<(), ExtensionStoreError> {
    if !is_sha256_digest(&view.manifest_digest)
        || !is_sha256_digest(&view.grant_digest)
        || !is_sha256_digest(&view.input_digest)
        || view.started_at_ms < 0
        || view
            .completed_at_ms
            .is_some_and(|completed| completed < view.started_at_ms)
    {
        return Err(invariant("stored extension invocation is invalid"));
    }
    if let Some(response) = &view.response
        && (response.invocation_id != view.invocation_id
            || response.extension_id != view.extension_id
            || response.manifest_digest != view.manifest_digest
            || response.grant_digest != view.grant_digest
            || response.capability_id != view.capability_id
            || view.output_digest.as_deref() != Some(response.output_digest.as_str()))
    {
        return Err(invariant("stored extension response identity diverged"));
    }
    Ok(())
}

fn validate_inspection(
    manifest: &ExtensionManifest,
    manifest_json: &str,
    manifest_digest: &str,
    installation_root: &str,
) -> Result<(), ExtensionStoreError> {
    manifest
        .validate()
        .map_err(|error| invalid_contract(error.to_string()))?;
    let decoded = serde_json::from_str::<ExtensionManifest>(manifest_json)
        .map_err(|error| invalid_contract(error.to_string()))?;
    if &decoded != manifest
        || !is_sha256_digest(manifest_digest)
        || sha256_digest(manifest_json.as_bytes()) != manifest_digest
        || !valid_absolute_path(installation_root)
    {
        return Err(invalid_contract(
            "extension inspection or installation root is invalid",
        ));
    }
    Ok(())
}

fn authorize_identity(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
) -> Result<(), ExtensionStoreError> {
    let authorized = connection
        .query_row(
            "SELECT EXISTS(\
                SELECT 1 FROM principal_registry principal \
                JOIN channel_binding_registry binding \
                  ON binding.principal_id = principal.principal_id \
                WHERE principal.principal_id = ?1 AND principal.status = 'active' \
                  AND binding.binding_id = ?2 AND binding.status = 'active'\
             )",
            params![
                ownership.principal_id().to_string(),
                ownership.channel_binding_id().to_string(),
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(map_sqlite_error)?;
    if authorized {
        Ok(())
    } else {
        Err(ExtensionStoreError::NotFound)
    }
}

#[allow(clippy::too_many_arguments)]
fn append_event(
    transaction: &Transaction<'_>,
    aggregate_kind: &str,
    aggregate_id: &str,
    event_id: EventId,
    event_type: &str,
    occurred_at_ms: i64,
    principal_id: PrincipalId,
    correlation_id: CorrelationId,
    payload: &serde_json::Value,
) -> Result<(), ExtensionStoreError> {
    let sequence =
        agent::next_sequence(transaction, aggregate_kind, aggregate_id).map_err(map_agent_error)?;
    transaction
        .execute(
            "INSERT INTO journal_event(\
                event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                event_version, occurred_at_ms, actor_principal_id, correlation_id, sensitivity, \
                payload_json\
             ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, 'private', ?9)",
            params![
                event_id.to_string(),
                aggregate_kind,
                aggregate_id,
                sequence,
                event_type,
                occurred_at_ms,
                principal_id.to_string(),
                correlation_id.to_string(),
                payload.to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO aggregate_sequence(aggregate_kind, aggregate_id, sequence) \
             VALUES (?1, ?2, ?3) ON CONFLICT(aggregate_kind, aggregate_id) \
             DO UPDATE SET sequence = excluded.sequence",
            params![aggregate_kind, aggregate_id, sequence],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn parse_extension_status(value: &str) -> Result<ExtensionStatus, ExtensionStoreError> {
    match value {
        "installed" => Ok(ExtensionStatus::Installed),
        "enabled" => Ok(ExtensionStatus::Enabled),
        "disabled" => Ok(ExtensionStatus::Disabled),
        "failed" => Ok(ExtensionStatus::Failed),
        "revoked" => Ok(ExtensionStatus::Revoked),
        _ => Err(invariant("stored extension status is invalid")),
    }
}

fn parse_invocation_status(value: &str) -> Result<ExtensionInvocationStatus, ExtensionStoreError> {
    match value {
        "dispatching" => Ok(ExtensionInvocationStatus::Dispatching),
        "succeeded" => Ok(ExtensionInvocationStatus::Succeeded),
        "failed" => Ok(ExtensionInvocationStatus::Failed),
        "abandoned" => Ok(ExtensionInvocationStatus::Abandoned),
        _ => Err(invariant("stored extension invocation status is invalid")),
    }
}

fn valid_field(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 4_096
        && !value.contains('\\')
        && value
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
        && !value.chars().any(char::is_control)
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, ExtensionStoreError> {
    agent::epoch_milliseconds(time).map_err(map_agent_error)
}

fn to_i64(value: u64, field: &str) -> Result<i64, ExtensionStoreError> {
    i64::try_from(value).map_err(|_| invalid_contract(format!("{field} exceeds SQLite range")))
}

fn nonnegative(value: i64, field: &str) -> Result<u64, ExtensionStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("stored {field} is negative")))
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, ExtensionStoreError> {
    value
        .parse()
        .map_err(|_| invariant(format!("stored {field} is invalid")))
}

fn map_agent_error(error: mealy_application::AgentStoreError) -> ExtensionStoreError {
    match error {
        mealy_application::AgentStoreError::Conflict => ExtensionStoreError::Conflict,
        mealy_application::AgentStoreError::Unavailable(message) => {
            ExtensionStoreError::Unavailable(message)
        }
        other => ExtensionStoreError::InvariantViolation(other.to_string()),
    }
}

fn map_sqlite_error(error: rusqlite::Error) -> ExtensionStoreError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation =>
        {
            ExtensionStoreError::Conflict
        }
        other => ExtensionStoreError::Unavailable(other.to_string()),
    }
}

fn invalid_contract(message: impl Into<String>) -> ExtensionStoreError {
    ExtensionStoreError::InvalidContract(message.into())
}

fn invariant(message: impl Into<String>) -> ExtensionStoreError {
    ExtensionStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::SqliteStore;
    use mealy_application::{
        BeginExtensionInvocationCommit, CompleteExtensionInvocationCommit, EnableExtensionCommit,
        ExtensionGrant, ExtensionInvocationStatus, ExtensionInvocationTerminal, ExtensionStore,
        ExtensionStoreError, InstallExtensionCommit, OwnershipContext, RevokeExtensionCommit,
        StageExtensionManifestCommit, extension_grant_digest, inspect_extension_manifest,
        sha256_digest,
    };
    use mealy_domain::{
        ChannelBindingId, CorrelationId, EXTENSION_MANIFEST_SCHEMA_VERSION, EffectClass, EventId,
        ExtensionCapabilityKind, ExtensionCapabilityManifest, ExtensionCompatibility,
        ExtensionEntryPoint, ExtensionGrantId, ExtensionHealthCheck, ExtensionId,
        ExtensionInvocationId, ExtensionKind, ExtensionManifest, ExtensionObjectSchema,
        ExtensionPermissions, ExtensionShutdownBehavior, ExtensionShutdownMode, ExtensionStatus,
        PrincipalId, RiskClass, SessionId,
    };
    use rusqlite::params;
    use serde_json::json;
    use std::{
        collections::{BTreeMap, BTreeSet},
        time::{Duration, SystemTime},
    };

    const NOW: i64 = 1_783_209_600_000;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn lifecycle_resets_grants_on_upgrade_revokes_terminally_and_records_invocations() {
        let mut store = SqliteStore::open_in_memory(NOW).expect("open extension store");
        let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
        let other = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
        seed_session(&store, ownership, "owner");
        seed_session(&store, other, "other");
        let extension_id = ExtensionId::new();
        let first = inspection(&manifest(extension_id, "1.0.0"));
        let installed = store
            .install_extension(InstallExtensionCommit {
                ownership,
                inspection: first.clone(),
                installation_root: "/opt/mealy/extensions/sample".to_owned(),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                installed_at: at(NOW + 1),
            })
            .expect("install inert extension");
        assert_eq!(installed.status, ExtensionStatus::Installed);
        assert_eq!(installed.revision, 0);
        assert!(installed.active_grant.is_none());
        assert_eq!(
            store.extension(other, extension_id),
            Err(ExtensionStoreError::NotFound)
        );

        let first_grant = grant(ownership, extension_id, &first.manifest_digest, NOW + 2);
        let enabled = store
            .enable_extension(EnableExtensionCommit {
                ownership,
                extension_id,
                expected_revision: installed.revision,
                grant: first_grant.clone(),
                health_output_digest: "a".repeat(64),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                enabled_at: at(NOW + 2),
            })
            .expect("enable reviewed extension");
        assert_eq!(enabled.status, ExtensionStatus::Enabled);
        assert_eq!(enabled.revision, 1);

        let invocation_id = ExtensionInvocationId::new();
        let grant_digest = extension_grant_digest(&first_grant).expect("grant digest");
        let input = json!({});
        let input_digest = sha256_digest(&serde_json::to_vec(&input).expect("input JSON"));
        let dispatching = store
            .begin_extension_invocation(BeginExtensionInvocationCommit {
                ownership,
                extension_id,
                expected_extension_revision: enabled.revision,
                invocation_id,
                manifest_digest: first.manifest_digest.clone(),
                grant_id: first_grant.grant_id,
                grant_digest: grant_digest.clone(),
                capability_id: "health".to_owned(),
                input_digest,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                started_at: at(NOW + 3),
            })
            .expect("commit dispatch boundary");
        assert_eq!(dispatching.status, ExtensionInvocationStatus::Dispatching);
        let output = json!({"status": "ok"});
        let response = mealy_application::ExtensionRpcResponse {
            protocol_version: mealy_application::EXTENSION_RPC_VERSION.to_owned(),
            invocation_id,
            extension_id,
            manifest_digest: first.manifest_digest.clone(),
            grant_digest: grant_digest.clone(),
            capability_id: "health".to_owned(),
            output_digest: sha256_digest(&serde_json::to_vec(&output).expect("output JSON")),
            output,
        };
        let completed = store
            .complete_extension_invocation(CompleteExtensionInvocationCommit {
                ownership,
                invocation_id,
                terminal: ExtensionInvocationTerminal::Succeeded(response.clone()),
                duration_ms: 7,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                completed_at: at(NOW + 4),
            })
            .expect("commit terminal response");
        assert_eq!(completed.status, ExtensionInvocationStatus::Succeeded);
        assert_eq!(completed.response, Some(response));

        let abandoned_id = ExtensionInvocationId::new();
        store
            .begin_extension_invocation(BeginExtensionInvocationCommit {
                ownership,
                extension_id,
                expected_extension_revision: enabled.revision,
                invocation_id: abandoned_id,
                manifest_digest: first.manifest_digest.clone(),
                grant_id: first_grant.grant_id,
                grant_digest,
                capability_id: "health".to_owned(),
                input_digest: "d".repeat(64),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                started_at: at(NOW + 5),
            })
            .expect("second dispatch");
        assert_eq!(
            store
                .incomplete_extension_invocations(16)
                .expect("incomplete invocations")
                .len(),
            1
        );
        let abandoned = store
            .complete_extension_invocation(CompleteExtensionInvocationCommit {
                ownership,
                invocation_id: abandoned_id,
                terminal: ExtensionInvocationTerminal::Abandoned,
                duration_ms: 0,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                completed_at: at(NOW + 6),
            })
            .expect("startup abandonment");
        assert_eq!(abandoned.status, ExtensionInvocationStatus::Abandoned);

        let second = inspection(&manifest(extension_id, "2.0.0"));
        let staged = store
            .stage_extension_manifest(StageExtensionManifestCommit {
                ownership,
                extension_id,
                expected_revision: enabled.revision,
                inspection: second.clone(),
                installation_root: "/opt/mealy/extensions/sample-v2".to_owned(),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                staged_at: at(NOW + 7),
            })
            .expect("stage authority-resetting upgrade");
        assert_eq!(staged.status, ExtensionStatus::Installed);
        assert_eq!(staged.manifest_history.len(), 2);
        assert!(staged.active_grant.is_none());
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT status FROM extension_grant WHERE grant_id = ?1",
                    [first_grant.grant_id.to_string()],
                    |row| row.get::<_, String>(0),
                )
                .expect("old grant status"),
            "superseded"
        );

        let second_grant = grant(ownership, extension_id, &second.manifest_digest, NOW + 8);
        let reenabled = store
            .enable_extension(EnableExtensionCommit {
                ownership,
                extension_id,
                expected_revision: staged.revision,
                grant: second_grant,
                health_output_digest: "b".repeat(64),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                enabled_at: at(NOW + 8),
            })
            .expect("fresh post-upgrade grant");
        let revoked = store
            .revoke_extension(RevokeExtensionCommit {
                ownership,
                extension_id,
                expected_revision: reenabled.revision,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                revoked_at: at(NOW + 9),
            })
            .expect("terminal revocation");
        assert_eq!(revoked.status, ExtensionStatus::Revoked);
        assert!(revoked.active_grant.is_none());
        assert!(
            store
                .connection
                .execute(
                    "DELETE FROM extension_manifest_revision WHERE extension_id = ?1",
                    [extension_id.to_string()],
                )
                .is_err()
        );
    }

    fn seed_session(store: &SqliteStore, ownership: OwnershipContext, suffix: &str) {
        store
            .connection
            .execute(
                "INSERT INTO session(id, principal_id, channel_binding_id, created_at_ms, updated_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?4)",
                params![
                    SessionId::new().to_string(),
                    ownership.principal_id().to_string(),
                    ownership.channel_binding_id().to_string(),
                    NOW,
                ],
            )
            .unwrap_or_else(|error| panic!("seed {suffix} session: {error}"));
    }

    fn inspection(manifest: &ExtensionManifest) -> mealy_application::ExtensionManifestInspection {
        let bytes = serde_json::to_vec(manifest).expect("manifest JSON");
        inspect_extension_manifest(&bytes, &sha256_digest(&bytes)).expect("manifest inspection")
    }

    fn grant(
        ownership: OwnershipContext,
        extension_id: ExtensionId,
        manifest_digest: &str,
        issued_at_ms: i64,
    ) -> ExtensionGrant {
        ExtensionGrant {
            grant_id: ExtensionGrantId::new(),
            extension_id,
            manifest_digest: manifest_digest.to_owned(),
            capability_ids: BTreeSet::from(["health".to_owned()]),
            mounts: Vec::new(),
            network_destinations: BTreeSet::new(),
            secret_references: BTreeSet::new(),
            allow_process_spawn: false,
            policy_version: mealy_application::EXTENSION_POLICY_VERSION.to_owned(),
            issued_by_principal_id: ownership.principal_id(),
            issued_at_ms,
        }
    }

    fn manifest(extension_id: ExtensionId, version: &str) -> ExtensionManifest {
        ExtensionManifest {
            schema_version: EXTENSION_MANIFEST_SCHEMA_VERSION,
            extension_id,
            name: "dev.mealy.sqlite-extension".to_owned(),
            publisher: "dev.mealy".to_owned(),
            version: version.to_owned(),
            kinds: BTreeSet::from([ExtensionKind::ToolService]),
            compatibility: ExtensionCompatibility {
                minimum_host_api: 1,
                maximum_host_api: 1,
            },
            entry_point: ExtensionEntryPoint {
                executable: "extension-worker".to_owned(),
                executable_digest: sha256_digest(version.as_bytes()),
                runtime_files: Vec::new(),
            },
            capabilities: vec![ExtensionCapabilityManifest {
                capability_id: "health".to_owned(),
                kind: ExtensionCapabilityKind::Health,
                effect_class: EffectClass::ReadOnly,
                risk_class: RiskClass::Low,
                input_schema: empty_schema(),
                output_schema: ExtensionObjectSchema {
                    properties: BTreeMap::from([(
                        "status".to_owned(),
                        mealy_domain::ExtensionFieldSchema {
                            value_type: mealy_domain::ExtensionScalarType::String,
                            maximum_length: Some(32),
                            minimum_integer: None,
                            maximum_integer: None,
                        },
                    )]),
                    required: BTreeSet::from(["status".to_owned()]),
                    additional_properties: false,
                    maximum_serialized_bytes: 64,
                },
                timeout_ms: 1_000,
                maximum_output_bytes: 1_024,
            }],
            permissions: ExtensionPermissions::default(),
            health_check: ExtensionHealthCheck {
                capability_id: "health".to_owned(),
                timeout_ms: 500,
                interval_ms: 1_000,
            },
            migrations: Vec::new(),
            shutdown: ExtensionShutdownBehavior {
                mode: ExtensionShutdownMode::Terminate,
                capability_id: None,
                grace_period_ms: 1_000,
            },
        }
    }

    fn empty_schema() -> ExtensionObjectSchema {
        ExtensionObjectSchema {
            properties: BTreeMap::new(),
            required: BTreeSet::new(),
            additional_properties: false,
            maximum_serialized_bytes: 2,
        }
    }

    fn at(milliseconds: i64) -> SystemTime {
        SystemTime::UNIX_EPOCH
            + Duration::from_millis(u64::try_from(milliseconds).expect("positive time"))
    }
}
