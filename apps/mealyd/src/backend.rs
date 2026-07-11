use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mealy_api::{
    ApiBackend, ArtifactContent, AuthenticatedIdentity, BackendError, SignedWebhookEnvelope,
};
use mealy_application::{
    AdmitInputCommand, AgentEvidenceStore, AgentExecutionStore, AgentStoreError,
    ApprovalRequestView, ArtifactBlobStore, ArtifactBlobStoreError, ArtifactEvidenceStore,
    ArtifactEvidenceStoreError, ArtifactMetadata, COMPACTION_PROMPT_VERSION, CancellationProbe,
    CapabilityRequirement, Clock, CommitCompaction, CompactionStore, CompactionStoreError,
    CompactionView, CompleteExtensionInvocationCommit, CompleteWebhookDeliveryCommit,
    ContextDisposition, ContextManifestEvidence, ContextManifestEvidenceStore,
    ContextManifestEvidenceStoreError, DisableExtensionCommit, EXTENSION_POLICY_VERSION,
    EXTENSION_RPC_VERSION, EffectAttemptState, EffectAttemptView, EffectLedgerStore,
    EffectLedgerStoreError, EffectLedgerView, EffectOutcomeKind, EffectReconciliationOutcome,
    EnableExtensionCommit, ExtensionDispatchRequest, ExtensionGrant, ExtensionHost,
    ExtensionHostError, ExtensionInvocationStatus, ExtensionInvocationTerminal,
    ExtensionInvocationView, ExtensionManifestInspection, ExtensionMountGrant, ExtensionRpcRequest,
    ExtensionStore, ExtensionStoreError, ExtensionView, IdGenerator, InputAdmissionLimits,
    InputAdmissionOutcome, InputAdmissionReceipt, InstallExtensionCommit, MEMORY_POLICY_VERSION,
    MemorySearchQuery, MemorySource, MemoryStore, MemoryStoreError, MemoryView, OperationalStore,
    OperationalStoreError, OwnershipContext, ProviderCapabilities, ProviderFallbackPolicy,
    ProviderLocality, ProviderPricing, ProviderRouteCandidate, ProviderRoutingPolicy,
    ReconcileEffectOutcomeCommit, RegisterWebhookChannelCommit, RequestTaskCancellationCommit,
    ReserveWebhookDeliveryCommit, ResolveApprovalCommit, RevokeExtensionCommit,
    RevokeWebhookChannelCommit, SessionStoreError, SessionUseCaseError,
    StageExtensionManifestCommit, TaskControlAction, TaskControlCommit, TimelineQuery,
    TimelineStoreError, TimelineUseCaseError, ValidationStore, WEBHOOK_MAXIMUM_CLOCK_SKEW,
    WEBHOOK_SIGNATURE_ALGORITHM, WEBHOOK_SIGNATURE_VERSION, WebhookChannelBindingView,
    WebhookChannelStatus, WebhookChannelStore, WebhookChannelStoreError, admit_input,
    canonical_arguments_digest, compaction_source_event_digest, create_session,
    extension_grant_digest, inspect_extension_manifest, query_session_status, query_timeline,
    route_provider, sha256_digest, validate_webhook_binding_fields, validate_webhook_timestamp,
    verify_webhook_signature, webhook_input_dedupe_key, webhook_signature_digest,
};
use mealy_domain::{
    ApprovalDecision, ApprovalId, ApprovalStatus, ArtifactId, AttemptId, ChannelBindingId,
    CompactionCarryForward, CompactionId, CompactionRecord, CompactionSourceRange,
    ContextManifestId, CorrelationId, EffectId, EffectStatus, ExtensionFilesystemAccess,
    ExtensionGrantId, ExtensionId, ExtensionInvocationId, ExtensionStatus, MemoryCategory,
    MemoryConfidence, MemoryId, MemoryMetadata, MemoryNamespace, MemoryPromotionAuthorization,
    MemoryProvenance, MemoryRetention, MemoryRevisionId, MemorySensitivity, PrincipalId, SessionId,
    TaskId, ValidationMethod, ValidationOutcome,
};
use mealy_infrastructure::{
    ChannelSecretStoreError, FileArtifactBlobStore, FileChannelSecretStore,
    InstalledExtensionPackage, LinuxBubblewrapExtensionHost, MaintenanceError, SqliteStore,
    SystemClock, SystemIdGenerator, create_backup as create_complete_backup,
    create_complete_export, inspect_extension_package, publish_export,
    verify_backup as verify_complete_backup,
};

const BUBBLEWRAP_PATH: &str = "/usr/bin/bwrap";
use mealy_protocol::{
    API_VERSION, AdminMetricsResponse, AdminStatusResponse, ApprovalDecisionCommand,
    ApprovalResolutionReceipt, ApprovalResponse, ApprovalStatusResponse, ApprovalSubjectResponse,
    ArtifactMetadataResponse, BackupResponse, BackupVerificationResponse, CancelTaskRequest,
    CompactionResponse, ContextItemDisposition, ContextManifestEvidenceItemResponse,
    ContextManifestEvidenceResponse, ContextMemoryEvidenceResponse,
    ContextMemorySourceCitationResponse, ControlTaskRequest, CorrectMemoryRequest,
    CreateBackupRequest, CreateCompactionRequest, CreateExportRequest, CreateSessionResponse,
    CreateWebhookChannelRequest, CreateWebhookChannelResponse, DaemonRunStatusResponse,
    DoctorResponse, DrainDaemonRequest, DrainDaemonResponse, EffectAttemptResponse,
    EffectAttemptStatusResponse, EffectOutcomeEvidenceResponse, EffectOutcomeResponse,
    EffectReconciliationReceipt, EffectResponse, EffectStatusResponse, EnableExtensionRequest,
    ExportKindRequest, ExportResponse, ExtensionFilesystemAccessCommand, ExtensionGrantResponse,
    ExtensionInvocationResponse, ExtensionInvocationStatusResponse, ExtensionLifecycleRequest,
    ExtensionManifestRevisionResponse, ExtensionMountGrantCommand, ExtensionResponse,
    ExtensionStatusResponse, ExtensionsResponse, GarbageCollectionResponse, InputAdmissionResponse,
    InstallExtensionRequest, InvokeExtensionRequest, MemoriesResponse, MemoryCategoryCommand,
    MemoryIndexRebuildResponse, MemoryLifecycleRequest, MemoryPromotionAuthorizationCommand,
    MemoryResponse, MemoryRetentionCommand, MemoryRevisionResponse, MemorySearchHitResponse,
    MemorySearchResponse, MemorySensitivityCommand, MemorySourceResponse, MemoryStatusResponse,
    OperationalFailureResponse, PendingApprovalsResponse, PromoteMemoryRequest,
    ProposeMemoryRequest, RebuildMemoryIndexRequest, ReconcileEffectRequest,
    ReconciliationOutcomeCommand, ResolveApprovalRequest, RevokeWebhookChannelRequest,
    RunGarbageCollectionRequest, SandboxProfileResponse, SandboxProfileStatusResponse,
    SessionStatusResponse, SetMemoryPinRequest, SignedWebhookInputRequest,
    StageExtensionManifestRequest, SubmitInputRequest, SuccessCriterionResponse, TaskBudgetUsage,
    TaskCancellationReceipt, TaskControlReceipt, TaskReplayResponse, TaskResponse, TaskRiskClass,
    TaskStatus, TaskSuccessCriteriaResponse, TaskValidationResponse, TimelineCursor, TimelineEvent,
    TimelinePageResponse, ValidationMethodResponse, ValidationOutcomeResponse, VerifyBackupRequest,
    WebhookChannelResponse, WebhookChannelStatusResponse, WebhookChannelsResponse,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::PathBuf,
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::watch;

/// Thread-safe synchronous backend invoked on the API's bounded blocking pool.
pub struct RuntimeBackend {
    store: Arc<Mutex<SqliteStore>>,
    artifacts: Arc<FileArtifactBlobStore>,
    channel_secrets: Arc<FileChannelSecretStore>,
    home: PathBuf,
    artifact_gc_minimum_age_hours: u64,
    maximum_pending_inputs_per_session: u64,
    extension_invocations: KeyedConcurrencyLimiter,
    sandbox_available: bool,
    safe_mode: bool,
    drain: Arc<DrainController>,
    clock: SystemClock,
    ids: SystemIdGenerator,
}

/// Process-local operational settings consumed by the authenticated backend.
pub struct RuntimeOperationalConfig {
    /// Private daemon home containing backup and verification roots.
    pub home: PathBuf,
    /// Minimum physical-erasure age for unreferenced artifacts.
    pub artifact_gc_minimum_age_hours: u64,
    /// Maximum durable pending input records admitted to one session.
    pub maximum_pending_inputs_per_session: u64,
    /// Maximum simultaneous invocations for one extension identity.
    pub maximum_extension_invocations: u32,
    /// Whether the installed host sandbox passed its startup probe.
    pub sandbox_available: bool,
    /// Whether mutation and dispatch must fail closed.
    pub safe_mode: bool,
}

/// Idempotent bridge from an authenticated admin command to daemon graceful shutdown.
pub struct DrainController {
    sender: watch::Sender<bool>,
    requested: AtomicBool,
    start_id: CorrelationId,
    deadline_ms: u64,
}

impl DrainController {
    /// Creates a controller for one exact daemon lifetime.
    #[must_use]
    pub fn new(sender: watch::Sender<bool>, start_id: CorrelationId, deadline_ms: u64) -> Self {
        Self {
            sender,
            requested: AtomicBool::new(false),
            start_id,
            deadline_ms,
        }
    }

    fn request(&self) -> bool {
        let newly_requested = !self.requested.swap(true, Ordering::SeqCst);
        let _ = self.sender.send(true);
        newly_requested
    }

    fn admission_open(&self) -> bool {
        !self.requested.load(Ordering::SeqCst)
    }
}

impl RuntimeBackend {
    /// Creates a backend over the daemon's single transactional store.
    #[must_use]
    pub fn new(
        store: Arc<Mutex<SqliteStore>>,
        artifacts: Arc<FileArtifactBlobStore>,
        channel_secrets: Arc<FileChannelSecretStore>,
        operations: RuntimeOperationalConfig,
        drain: Arc<DrainController>,
    ) -> Self {
        Self {
            store,
            artifacts,
            channel_secrets,
            home: operations.home,
            artifact_gc_minimum_age_hours: operations.artifact_gc_minimum_age_hours,
            maximum_pending_inputs_per_session: operations.maximum_pending_inputs_per_session,
            extension_invocations: KeyedConcurrencyLimiter::new(
                operations.maximum_extension_invocations,
            ),
            sandbox_available: operations.sandbox_available,
            safe_mode: operations.safe_mode,
            drain,
            clock: SystemClock,
            ids: SystemIdGenerator,
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, SqliteStore>, BackendError> {
        self.store.lock().map_err(|_| BackendError::Internal)
    }

    fn control_task(
        &self,
        identity: &AuthenticatedIdentity,
        task_id: &str,
        request: &ControlTaskRequest,
        action: TaskControlAction,
    ) -> Result<TaskControlReceipt, BackendError> {
        let ownership = parse_ownership(identity)?;
        let task_id = parse_task(task_id)?;
        let receipt = self
            .lock()?
            .control_task(TaskControlCommit {
                ownership,
                task_id,
                expected_revision: request.expected_revision,
                action,
                event_id: self.ids.generate_event_id(),
                recovery_event_ids: mealy_application::LeaseRecoveryEventIds {
                    lease_expired: self.ids.generate_event_id(),
                    run_requeued: self.ids.generate_event_id(),
                    effect_recovered: self.ids.generate_event_id(),
                    task_waiting: self.ids.generate_event_id(),
                    agent_boundary_recovered: self.ids.generate_event_id(),
                },
                controlled_at: self.clock.now(),
            })
            .map_err(|error| map_agent_error(&error))?;
        Ok(TaskControlReceipt {
            api_version: API_VERSION.to_owned(),
            task_id: receipt.task_id.to_string(),
            status: parse_task_status(&receipt.status)?,
            revision: receipt.revision,
            event_id: receipt.event_id.to_string(),
            cursor: TimelineCursor(receipt.cursor),
        })
    }
}

struct KeyedConcurrencyLimiter {
    maximum: u32,
    in_flight: Mutex<BTreeMap<String, u32>>,
}

impl KeyedConcurrencyLimiter {
    const fn new(maximum: u32) -> Self {
        Self {
            maximum,
            in_flight: Mutex::new(BTreeMap::new()),
        }
    }

    fn try_acquire(&self, key: String) -> Option<KeyedConcurrencyGuard<'_>> {
        let mut counts = self.in_flight.lock().ok()?;
        let current = counts.entry(key.clone()).or_default();
        if *current >= self.maximum {
            return None;
        }
        *current += 1;
        Some(KeyedConcurrencyGuard { limiter: self, key })
    }
}

struct KeyedConcurrencyGuard<'a> {
    limiter: &'a KeyedConcurrencyLimiter,
    key: String,
}

impl Drop for KeyedConcurrencyGuard<'_> {
    fn drop(&mut self) {
        let Ok(mut counts) = self.limiter.in_flight.lock() else {
            return;
        };
        let Some(current) = counts.get_mut(&self.key) else {
            return;
        };
        *current = current.saturating_sub(1);
        if *current == 0 {
            counts.remove(&self.key);
        }
    }
}

impl ApiBackend for RuntimeBackend {
    fn readiness(&self) -> Result<(), BackendError> {
        self.lock()?
            .readiness_check()
            .map_err(|_| BackendError::Unavailable)
    }

    fn safe_mode(&self) -> bool {
        self.safe_mode
    }

    fn admission_open(&self) -> bool {
        self.drain.admission_open()
    }

    fn admin_status(
        &self,
        identity: AuthenticatedIdentity,
    ) -> Result<AdminStatusResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let (snapshot, database_bytes) = {
            let store = self.lock()?;
            (
                store
                    .operational_snapshot(ownership)
                    .map_err(map_operational_store_error)?,
                store
                    .database_storage_bytes()
                    .map_err(map_operational_store_error)?,
            )
        };
        let artifacts = self
            .artifacts
            .storage_usage()
            .map_err(|error| map_artifact_blob_error(&error))?;
        Ok(AdminStatusResponse {
            api_version: API_VERSION.to_owned(),
            start_id: snapshot.start_id.to_string(),
            run_status: match snapshot.run_status {
                mealy_application::DaemonRunStatus::Running => DaemonRunStatusResponse::Running,
                mealy_application::DaemonRunStatus::Clean => DaemonRunStatusResponse::Clean,
                mealy_application::DaemonRunStatus::Forced => DaemonRunStatusResponse::Forced,
                mealy_application::DaemonRunStatus::Unclean => DaemonRunStatusResponse::Unclean,
            },
            safe_mode: snapshot.safe_mode,
            admission_open: self.admission_open(),
            config_digest: snapshot.config_digest,
            policy_bundle_digest: snapshot.policy_bundle_digest,
            schema_version: snapshot.schema_version,
            pending_inputs: snapshot.pending_inputs,
            nonterminal_runs: snapshot.nonterminal_runs,
            active_leases: snapshot.active_leases,
            pending_approvals: snapshot.pending_approvals,
            unknown_effects: snapshot.unknown_effects,
            pending_outbox: snapshot.pending_outbox,
            failed_outbox: snapshot.failed_outbox,
            enabled_extensions: snapshot.enabled_extensions,
            failed_extensions: snapshot.failed_extensions,
            provider_health: "healthy".to_owned(),
            extension_host_health: if self.sandbox_available {
                "healthy".to_owned()
            } else {
                "unavailable_fail_closed".to_owned()
            },
            active_channels: snapshot.active_channels,
            database_bytes,
            artifact_bytes: artifacts.total_bytes,
            artifact_count: artifacts.blob_count,
            recent_failures: snapshot
                .recent_failures
                .into_iter()
                .map(|failure| OperationalFailureResponse {
                    cursor: TimelineCursor(failure.cursor),
                    event_type: failure.event_type,
                    aggregate_kind: failure.aggregate_kind,
                    aggregate_id: failure.aggregate_id,
                    correlation_id: failure.correlation_id,
                    occurred_at_ms: failure.occurred_at_ms,
                })
                .collect(),
            started_at_ms: snapshot.started_at_ms,
            ready_at_ms: snapshot.ready_at_ms,
            completed_at_ms: snapshot.completed_at_ms,
            completion_reason: snapshot.completion_reason,
        })
    }

    fn admin_metrics(
        &self,
        identity: AuthenticatedIdentity,
    ) -> Result<AdminMetricsResponse, BackendError> {
        let status = self.admin_status(identity)?;
        let gauges = BTreeMap::from([
            ("active_channels".to_owned(), status.active_channels),
            ("active_leases".to_owned(), status.active_leases),
            ("artifact_bytes".to_owned(), status.artifact_bytes),
            ("artifact_count".to_owned(), status.artifact_count),
            ("database_bytes".to_owned(), status.database_bytes),
            ("enabled_extensions".to_owned(), status.enabled_extensions),
            ("failed_extensions".to_owned(), status.failed_extensions),
            ("failed_outbox".to_owned(), status.failed_outbox),
            ("nonterminal_runs".to_owned(), status.nonterminal_runs),
            ("pending_approvals".to_owned(), status.pending_approvals),
            ("pending_inputs".to_owned(), status.pending_inputs),
            ("pending_outbox".to_owned(), status.pending_outbox),
            ("provider_healthy".to_owned(), 1),
            (
                "extension_host_healthy".to_owned(),
                u64::from(status.extension_host_health == "healthy"),
            ),
            ("unknown_effects".to_owned(), status.unknown_effects),
        ]);
        Ok(AdminMetricsResponse {
            api_version: API_VERSION.to_owned(),
            gauges,
        })
    }

    fn drain_daemon(
        &self,
        identity: AuthenticatedIdentity,
        _request: DrainDaemonRequest,
    ) -> Result<DrainDaemonResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        self.lock()?
            .operational_snapshot(ownership)
            .map_err(map_operational_store_error)?;
        Ok(DrainDaemonResponse {
            api_version: API_VERSION.to_owned(),
            start_id: self.drain.start_id.to_string(),
            deadline_ms: self.drain.deadline_ms,
            newly_requested: self.drain.request(),
        })
    }

    fn doctor(&self, identity: AuthenticatedIdentity) -> Result<DoctorResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let store = self.lock()?;
        store
            .operational_snapshot(ownership)
            .map_err(map_operational_store_error)?;
        store
            .verify_storage_integrity()
            .map_err(|_| BackendError::Unavailable)?;
        let usage = self
            .artifacts
            .storage_usage()
            .map_err(|error| map_artifact_blob_error(&error))?;
        let config_path = self.home.join("config.json");
        let config_ready = config_path.is_file();
        let home_private = private_home_permissions(&self.home);
        let mut checks = BTreeMap::from([
            (
                "artifact_store".to_owned(),
                format!(
                    "ok: {} committed blob(s), {} byte(s), {} temporary file(s)",
                    usage.blob_count, usage.total_bytes, usage.temporary_file_count
                ),
            ),
            (
                "configuration".to_owned(),
                if config_ready {
                    "ok: schema-versioned non-secret configuration loaded".to_owned()
                } else {
                    "failed: config.json is missing".to_owned()
                },
            ),
            (
                "home_permissions".to_owned(),
                if home_private {
                    "ok: state directory is owner-private".to_owned()
                } else {
                    "failed: state directory permissions are not owner-private".to_owned()
                },
            ),
            (
                "sqlite".to_owned(),
                format!(
                    "ok: schema {} passed full integrity and foreign-key checks",
                    store
                        .schema_version()
                        .map_err(|_| BackendError::Unavailable)?
                ),
            ),
        ]);
        checks.insert(
            "sandbox".to_owned(),
            if self.sandbox_available {
                "ok: Linux Bubblewrap observe/workspace-write proof passed".to_owned()
            } else {
                "degraded: sandbox profiles fail closed on this host/install".to_owned()
            },
        );
        checks.insert("provider_routing".to_owned(), provider_routing_check()?);
        let enforceable = if self.sandbox_available {
            SandboxProfileStatusResponse::Enforceable
        } else {
            SandboxProfileStatusResponse::Denied
        };
        let enforceable_detail = if self.sandbox_available {
            "Bubblewrap namespace probe and exact worker identity passed"
        } else {
            "required local sandbox adapter is unavailable; execution is omitted"
        };
        Ok(DoctorResponse {
            api_version: API_VERSION.to_owned(),
            operating_system: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            control_plane_ready: config_ready && home_private,
            sandbox_available: self.sandbox_available,
            sandbox_profiles: vec![
                SandboxProfileResponse {
                    profile: "observe".to_owned(),
                    status: enforceable,
                    detail: enforceable_detail.to_owned(),
                },
                SandboxProfileResponse {
                    profile: "workspace_write".to_owned(),
                    status: enforceable,
                    detail: enforceable_detail.to_owned(),
                },
                denied_sandbox_profile(
                    "networked",
                    "destination-level network enforcement is not implemented",
                ),
                denied_sandbox_profile(
                    "service_operator",
                    "service-manager authority is not delegated to workers",
                ),
                denied_sandbox_profile(
                    "full_trust",
                    "release one never grants unsandboxed full-trust execution",
                ),
            ],
            checks,
        })
    }

    fn create_backup(
        &self,
        identity: AuthenticatedIdentity,
        request: CreateBackupRequest,
    ) -> Result<BackupResponse, BackendError> {
        if request.include_secrets != request.secret_passphrase.is_some() {
            return Err(BackendError::InvalidRequest(
                "secret backup requires both explicit opt-in and one passphrase".to_owned(),
            ));
        }
        let ownership = parse_ownership(&identity)?;
        let store = self.lock()?;
        store
            .operational_snapshot(ownership)
            .map_err(map_operational_store_error)?;
        let report = create_complete_backup(
            &self.home,
            &store,
            &self.artifacts,
            &request.name,
            request.secret_passphrase.as_deref(),
            SystemTime::now(),
        )
        .map_err(|error| map_maintenance_error(&error))?;
        Ok(BackupResponse {
            api_version: API_VERSION.to_owned(),
            name: request.name,
            path: report.path.display().to_string(),
            manifest_digest: report.manifest_digest,
            file_count: report.file_count,
            total_bytes: report.total_bytes,
            schema_version: report.schema_version,
            artifact_count: report.artifact_count,
            secrets_included: report.secrets_included,
        })
    }

    fn verify_backup(
        &self,
        identity: AuthenticatedIdentity,
        request: VerifyBackupRequest,
    ) -> Result<BackupVerificationResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        self.lock()?
            .operational_snapshot(ownership)
            .map_err(map_operational_store_error)?;
        let report = verify_complete_backup(
            &self.home,
            &request.name,
            request.secret_passphrase.as_deref(),
            SystemTime::now(),
        )
        .map_err(|error| map_maintenance_error(&error))?;
        Ok(BackupVerificationResponse {
            api_version: API_VERSION.to_owned(),
            name: request.name,
            path: report.path.display().to_string(),
            manifest_digest: report.manifest_digest,
            verified_at_ms: report.verified_at_ms,
            schema_version: report.schema_version,
            file_count: report.file_count,
            total_bytes: report.total_bytes,
            artifact_count: report.artifact_count,
            secrets_included: report.secrets_included,
            identity_verified: report.identity_verified,
        })
    }

    fn run_garbage_collection(
        &self,
        identity: AuthenticatedIdentity,
        _request: RunGarbageCollectionRequest,
    ) -> Result<GarbageCollectionResponse, BackendError> {
        if self.safe_mode {
            return Err(BackendError::Unavailable);
        }
        let ownership = parse_ownership(&identity)?;
        let store = self.lock()?;
        store
            .operational_snapshot(ownership)
            .map_err(map_operational_store_error)?;
        let referenced = store
            .referenced_artifact_digests()
            .map_err(|_| BackendError::Unavailable)?;
        let seconds = self
            .artifact_gc_minimum_age_hours
            .checked_mul(60 * 60)
            .ok_or(BackendError::Internal)?;
        let report = self
            .artifacts
            .garbage_collect(&referenced, Duration::from_secs(seconds), SystemTime::now())
            .map_err(|error| map_artifact_blob_error(&error))?;
        drop(store);
        Ok(GarbageCollectionResponse {
            api_version: API_VERSION.to_owned(),
            minimum_age_hours: self.artifact_gc_minimum_age_hours,
            removed_blob_count: report.removed_blob_count,
            removed_blob_bytes: report.removed_blob_bytes,
            removed_temporary_file_count: report.removed_temporary_file_count,
            retained_young_file_count: report.retained_young_file_count,
            retained_referenced_blob_count: report.retained_referenced_blob_count,
        })
    }

    fn create_export(
        &self,
        identity: AuthenticatedIdentity,
        request: CreateExportRequest,
    ) -> Result<ExportResponse, BackendError> {
        let kind = request.kind;
        let selector = validated_export_selector(kind, request.selector)?;
        let payload = match kind {
            ExportKindRequest::Complete => {
                let ownership = parse_ownership(&identity)?;
                let exported_at_ms = epoch_milliseconds(SystemTime::now())?;
                let report = {
                    let store = self.lock()?;
                    store
                        .operational_snapshot(ownership)
                        .map_err(map_operational_store_error)?;
                    create_complete_export(
                        &self.home,
                        &store,
                        &self.artifacts,
                        &request.name,
                        SystemTime::now(),
                    )
                    .map_err(|error| map_maintenance_error(&error))?
                };
                return Ok(ExportResponse {
                    api_version: API_VERSION.to_owned(),
                    name: request.name,
                    kind,
                    selector: None,
                    path: report.path.display().to_string(),
                    digest: report.manifest_digest,
                    size_bytes: report.total_bytes,
                    exported_at_ms,
                });
            }
            ExportKindRequest::Audit => audit_export_payload(self, identity.clone())?,
            ExportKindRequest::Task => serde_json::to_value(self.task_replay(
                identity.clone(),
                selector.clone().ok_or(BackendError::Internal)?,
            )?)
            .map_err(|_| BackendError::Internal)?,
            ExportKindRequest::Artifact => {
                let artifact_id = selector.clone().ok_or(BackendError::Internal)?;
                let metadata = self.artifact_metadata(identity.clone(), artifact_id.clone())?;
                let content = self.artifact_content(identity.clone(), artifact_id)?;
                serde_json::json!({
                    "metadata": metadata,
                    "contentEncoding": "base64url_no_pad",
                    "contentMediaType": content.media_type,
                    "content": URL_SAFE_NO_PAD.encode(content.bytes),
                })
            }
            ExportKindRequest::Memory => serde_json::to_value(self.memories(
                identity.clone(),
                selector.clone().ok_or(BackendError::Internal)?,
                true,
            )?)
            .map_err(|_| BackendError::Internal)?,
        };
        let exported_at_ms = epoch_milliseconds(SystemTime::now())?;
        let bundle = serde_json::json!({
            "formatVersion": 1,
            "apiVersion": API_VERSION,
            "exportedAtMs": exported_at_ms,
            "kind": kind,
            "selector": selector,
            "payload": payload,
        });
        let report = publish_export(&self.home, &request.name, &bundle)
            .map_err(|error| map_maintenance_error(&error))?;
        Ok(ExportResponse {
            api_version: API_VERSION.to_owned(),
            name: request.name,
            kind,
            selector,
            path: report.path.display().to_string(),
            digest: report.digest,
            size_bytes: report.size_bytes,
            exported_at_ms,
        })
    }

    fn create_session(
        &self,
        identity: AuthenticatedIdentity,
    ) -> Result<CreateSessionResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let session_id = create_session(&mut *self.lock()?, &self.clock, &self.ids, ownership)
            .map_err(map_session_error)?;
        Ok(CreateSessionResponse {
            api_version: API_VERSION.to_owned(),
            session_id: session_id.to_string(),
        })
    }

    fn submit_input(
        &self,
        identity: AuthenticatedIdentity,
        session_id: String,
        request: SubmitInputRequest,
    ) -> Result<InputAdmissionResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let session_id = parse_session(&session_id)?;
        let mut store = self.lock()?;
        let outcome = admit_input(
            &mut *store,
            &self.clock,
            &self.ids,
            InputAdmissionLimits::new(256, 1024 * 1024, self.maximum_pending_inputs_per_session),
            AdmitInputCommand {
                session_id,
                ownership,
                dedupe_key: request.idempotency_key,
                delivery_mode: request.delivery_mode.into(),
                content: request.content,
            },
        )
        .map_err(map_session_error)?;
        let receipt = outcome.receipt();
        Ok(InputAdmissionResponse {
            api_version: API_VERSION.to_owned(),
            session_id: receipt.session_id.to_string(),
            inbox_entry_id: receipt.inbox_entry_id.to_string(),
            inbox_sequence: receipt.inbox_sequence,
            delivery_mode: receipt.delivery_mode.into(),
            event_id: receipt.event_id.to_string(),
            outbox_id: receipt.outbox_id.to_string(),
            accepted_at_ms: epoch_milliseconds(receipt.accepted_at)?,
            duplicate: matches!(outcome, InputAdmissionOutcome::Duplicate(_)),
            cursor: TimelineCursor(receipt.timeline_cursor),
        })
    }

    fn session_status(
        &self,
        identity: AuthenticatedIdentity,
        session_id: String,
    ) -> Result<SessionStatusResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let session_id = parse_session(&session_id)?;
        let status = query_session_status(&*self.lock()?, session_id, ownership)
            .map_err(|error| map_timeline_error(&error))?;
        Ok(SessionStatusResponse {
            api_version: API_VERSION.to_owned(),
            session_id: status.session_id.to_string(),
            revision: status.revision,
            pending_inputs: status.pending_inputs,
            active_turn_id: status.active_turn_id.map(|id| id.to_string()),
            latest_cursor: TimelineCursor(status.latest_cursor.0),
        })
    }

    fn timeline_page(
        &self,
        identity: AuthenticatedIdentity,
        session_id: String,
        after: Option<TimelineCursor>,
        limit: usize,
    ) -> Result<TimelinePageResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let session_id = parse_session(&session_id)?;
        let page = query_timeline(
            &*self.lock()?,
            TimelineQuery {
                session_id,
                ownership,
                after: after.map(|cursor| mealy_application::TimelineCursor(cursor.0)),
                limit,
            },
        )
        .map_err(|error| map_timeline_error(&error))?;
        let events = page
            .events
            .into_iter()
            .map(|event| {
                let event_digest =
                    compaction_source_event_digest(&event).map_err(|_| BackendError::Internal)?;
                Ok(TimelineEvent {
                    cursor: TimelineCursor(event.cursor.0),
                    event_id: event.event_id.to_string(),
                    aggregate_kind: event.aggregate_kind,
                    aggregate_id: event.aggregate_id,
                    aggregate_sequence: event.aggregate_sequence,
                    event_type: event.event_type,
                    event_version: event.event_version,
                    occurred_at_ms: epoch_milliseconds(event.occurred_at)?,
                    correlation_id: event.correlation_id.to_string(),
                    causation_id: event.causation_id.map(|id| id.to_string()),
                    payload: serde_json::from_str(&event.payload_json)
                        .map_err(|_| BackendError::Internal)?,
                    event_digest,
                })
            })
            .collect::<Result<Vec<_>, BackendError>>()?;
        Ok(TimelinePageResponse {
            api_version: API_VERSION.to_owned(),
            events,
            high_watermark: TimelineCursor(page.high_watermark.0),
            has_more: page.has_more,
        })
    }

    fn artifact_metadata(
        &self,
        identity: AuthenticatedIdentity,
        artifact_id: String,
    ) -> Result<ArtifactMetadataResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let artifact_id = parse_artifact(&artifact_id)?;
        let metadata = self
            .lock()?
            .artifact_metadata(ownership, artifact_id)
            .map_err(|error| map_artifact_evidence_error(&error))?;
        artifact_metadata_response(metadata)
    }

    fn artifact_content(
        &self,
        identity: AuthenticatedIdentity,
        artifact_id: String,
    ) -> Result<ArtifactContent, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let artifact_id = parse_artifact(&artifact_id)?;
        let descriptor = {
            self.lock()?
                .artifact_content_descriptor(ownership, artifact_id)
                .map_err(|error| map_artifact_evidence_error(&error))?
        };
        let (metadata, committed_blob) = descriptor.into_parts();
        let bytes = self
            .artifacts
            .read(&committed_blob)
            .map_err(|error| map_artifact_blob_error(&error))?;
        Ok(ArtifactContent {
            media_type: metadata.media_type,
            bytes,
        })
    }

    fn context_manifest(
        &self,
        identity: AuthenticatedIdentity,
        manifest_id: String,
    ) -> Result<ContextManifestEvidenceResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let manifest_id = parse_context_manifest(&manifest_id)?;
        let evidence = self
            .lock()?
            .context_manifest_evidence(ownership, manifest_id)
            .map_err(|error| map_context_evidence_error(&error))?;
        Ok(context_manifest_response(evidence))
    }

    fn propose_memory(
        &self,
        identity: AuthenticatedIdentity,
        request: ProposeMemoryRequest,
    ) -> Result<MemoryResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let now = self.clock.now();
        let now_ms = epoch_milliseconds(now)?;
        let sources = request
            .sources
            .into_iter()
            .map(|source| MemorySource {
                locator: source.locator,
                digest: source.digest,
            })
            .collect::<Vec<_>>();
        let source_locators = sources
            .iter()
            .map(|source| source.locator.clone())
            .collect::<BTreeSet<_>>();
        let source_digests = sources
            .iter()
            .map(|source| source.digest.clone())
            .collect::<BTreeSet<_>>();
        let view = self
            .lock()?
            .propose_memory(mealy_application::ProposeMemoryCommit {
                ownership,
                memory_id: self.ids.generate_memory_id(),
                revision_id: self.ids.generate_memory_revision_id(),
                content: request.content,
                metadata: MemoryMetadata {
                    namespace: MemoryNamespace {
                        principal_id: ownership.principal_id(),
                        workspace_identity: request.workspace_identity,
                    },
                    category: memory_category(request.category),
                    provenance: MemoryProvenance {
                        proposed_by_principal_id: ownership.principal_id(),
                        source_locators,
                        source_digests,
                    },
                    confidence: MemoryConfidence::new(request.confidence_basis_points)
                        .map_err(|error| BackendError::InvalidRequest(error.to_string()))?,
                    sensitivity: memory_sensitivity(request.sensitivity),
                    retention: memory_retention(request.retention),
                    created_at_ms: now_ms,
                    last_verified_at_ms: now_ms,
                },
                sources,
                event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                proposed_at: now,
            })
            .map_err(map_memory_error)?;
        Ok(memory_response(view))
    }

    fn promote_memory(
        &self,
        identity: AuthenticatedIdentity,
        memory_id: String,
        request: PromoteMemoryRequest,
    ) -> Result<MemoryResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let memory_id = parse_memory(&memory_id)?;
        let revision_id = parse_memory_revision(&request.revision_id)?;
        let authorization = memory_authorization(request.authorization, &self.ids);
        let view = self
            .lock()?
            .promote_memory(mealy_application::PromoteMemoryCommit {
                ownership,
                memory_id,
                revision_id,
                authorization_event_id: authorization
                    .as_ref()
                    .map(|_| self.ids.generate_event_id()),
                authorization,
                activation_event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                activated_at: self.clock.now(),
            })
            .map_err(map_memory_error)?;
        Ok(memory_response(view))
    }

    fn memory(
        &self,
        identity: AuthenticatedIdentity,
        workspace_identity: String,
        memory_id: String,
    ) -> Result<MemoryResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let view = self
            .lock()?
            .memory(ownership, &workspace_identity, parse_memory(&memory_id)?)
            .map_err(map_memory_error)?;
        Ok(memory_response(view))
    }

    fn memories(
        &self,
        identity: AuthenticatedIdentity,
        workspace_identity: String,
        include_deleted: bool,
    ) -> Result<MemoriesResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let memories = self
            .lock()?
            .memories(ownership, &workspace_identity, include_deleted)
            .map_err(map_memory_error)?
            .into_iter()
            .map(memory_response)
            .collect();
        Ok(MemoriesResponse {
            api_version: API_VERSION.to_owned(),
            memories,
        })
    }

    fn search_memories(
        &self,
        identity: AuthenticatedIdentity,
        workspace_identity: String,
        query: String,
        maximum_sensitivity: MemorySensitivityCommand,
        limit: usize,
    ) -> Result<MemorySearchResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let hits = self
            .lock()?
            .search_memories(MemorySearchQuery {
                ownership,
                workspace_identity,
                query,
                maximum_sensitivity: memory_sensitivity(maximum_sensitivity),
                limit,
            })
            .map_err(map_memory_error)?
            .into_iter()
            .map(|hit| MemorySearchHitResponse {
                memory: memory_response(hit.memory),
                lexical_rank: hit.lexical_rank,
            })
            .collect();
        Ok(MemorySearchResponse {
            api_version: API_VERSION.to_owned(),
            hits,
        })
    }

    fn correct_memory(
        &self,
        identity: AuthenticatedIdentity,
        memory_id: String,
        request: CorrectMemoryRequest,
    ) -> Result<MemoryResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let authorization = memory_authorization(request.authorization, &self.ids);
        let view = self
            .lock()?
            .correct_memory(mealy_application::CorrectMemoryCommit {
                ownership,
                memory_id: parse_memory(&memory_id)?,
                expected_revision: request.expected_revision,
                revision_id: self.ids.generate_memory_revision_id(),
                content: request.content,
                confidence: MemoryConfidence::new(request.confidence_basis_points)
                    .map_err(|error| BackendError::InvalidRequest(error.to_string()))?,
                sensitivity: memory_sensitivity(request.sensitivity),
                retention: memory_retention(request.retention),
                sources: request
                    .sources
                    .into_iter()
                    .map(|source| MemorySource {
                        locator: source.locator,
                        digest: source.digest,
                    })
                    .collect(),
                authorization_event_id: authorization
                    .as_ref()
                    .map(|_| self.ids.generate_event_id()),
                authorization,
                revision_event_id: self.ids.generate_event_id(),
                corrected_event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                corrected_at: self.clock.now(),
            })
            .map_err(map_memory_error)?;
        Ok(memory_response(view))
    }

    fn set_memory_pin(
        &self,
        identity: AuthenticatedIdentity,
        memory_id: String,
        request: SetMemoryPinRequest,
    ) -> Result<MemoryResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let view = self
            .lock()?
            .set_memory_pin(mealy_application::SetMemoryPinCommit {
                ownership,
                memory_id: parse_memory(&memory_id)?,
                expected_revision: request.expected_revision,
                pinned: request.pinned,
                event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                updated_at: self.clock.now(),
            })
            .map_err(map_memory_error)?;
        Ok(memory_response(view))
    }

    fn expire_memory(
        &self,
        identity: AuthenticatedIdentity,
        memory_id: String,
        request: MemoryLifecycleRequest,
    ) -> Result<MemoryResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let view = self
            .lock()?
            .expire_memory(mealy_application::ExpireMemoryCommit {
                ownership,
                memory_id: parse_memory(&memory_id)?,
                expected_revision: request.expected_revision,
                event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                expired_at: self.clock.now(),
            })
            .map_err(map_memory_error)?;
        Ok(memory_response(view))
    }

    fn reject_memory(
        &self,
        identity: AuthenticatedIdentity,
        memory_id: String,
        request: MemoryLifecycleRequest,
    ) -> Result<MemoryResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let view = self
            .lock()?
            .reject_memory(mealy_application::RejectMemoryCommit {
                ownership,
                memory_id: parse_memory(&memory_id)?,
                expected_revision: request.expected_revision,
                event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                rejected_at: self.clock.now(),
            })
            .map_err(map_memory_error)?;
        Ok(memory_response(view))
    }

    fn delete_memory(
        &self,
        identity: AuthenticatedIdentity,
        memory_id: String,
        request: MemoryLifecycleRequest,
    ) -> Result<MemoryResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let view = self
            .lock()?
            .delete_memory(mealy_application::DeleteMemoryCommit {
                ownership,
                memory_id: parse_memory(&memory_id)?,
                expected_revision: request.expected_revision,
                event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                deleted_at: self.clock.now(),
            })
            .map_err(map_memory_error)?;
        Ok(memory_response(view))
    }

    fn rebuild_memory_index(
        &self,
        identity: AuthenticatedIdentity,
        _request: RebuildMemoryIndexRequest,
    ) -> Result<MemoryIndexRebuildResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let receipt = self
            .lock()?
            .rebuild_memory_index(ownership, self.clock.now())
            .map_err(map_memory_error)?;
        Ok(MemoryIndexRebuildResponse {
            api_version: API_VERSION.to_owned(),
            indexed_revision_count: receipt.indexed_revision_count,
            rebuilt_at_ms: receipt.rebuilt_at_ms,
        })
    }

    fn create_compaction(
        &self,
        identity: AuthenticatedIdentity,
        session_id: String,
        request: CreateCompactionRequest,
    ) -> Result<CompactionResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let session_id = parse_session(&session_id)?;
        let carry_forward = serde_json::from_value::<CompactionCarryForward>(request.carry_forward)
            .map_err(|error| {
                BackendError::InvalidRequest(format!("invalid typed carryForward: {error}"))
            })?;
        let artifact_blob = self
            .artifacts
            .commit(request.summary_text.as_bytes())
            .map_err(|error| map_artifact_blob_error(&error))?;
        let view = self
            .lock()?
            .commit_compaction(CommitCompaction {
                ownership,
                session_id,
                record: CompactionRecord {
                    compaction_id: self.ids.generate_compaction_id(),
                    artifact_id: self.ids.generate_artifact_id(),
                    source_range: CompactionSourceRange {
                        first_cursor: request.source_first_cursor,
                        last_cursor: request.source_last_cursor,
                    },
                    prompt_version: COMPACTION_PROMPT_VERSION.to_owned(),
                    config_digest: mealy_application::sha256_digest(b"mealy.compaction.config.v1"),
                    artifact_digest: artifact_blob.digest.clone(),
                    carry_forward,
                },
                summary_text: request.summary_text,
                artifact_blob,
                event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                created_at: self.clock.now(),
            })
            .map_err(map_compaction_error)?;
        compaction_response(view)
    }

    fn compaction(
        &self,
        identity: AuthenticatedIdentity,
        compaction_id: String,
    ) -> Result<CompactionResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let view = self
            .lock()?
            .compaction(ownership, parse_compaction(&compaction_id)?)
            .map_err(map_compaction_error)?;
        compaction_response(view)
    }

    fn install_extension(
        &self,
        identity: AuthenticatedIdentity,
        request: InstallExtensionRequest,
    ) -> Result<ExtensionResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let inspection =
            inspect_manifest_request(&request.manifest_json, &request.manifest_digest)?;
        let package = inspect_extension_package(inspection.clone(), &request.installation_root)
            .map_err(map_extension_package_error)?;
        let installation_root = canonical_extension_root(&package)?;
        let view = self
            .lock()?
            .install_extension(InstallExtensionCommit {
                ownership,
                inspection,
                installation_root,
                event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                installed_at: self.clock.now(),
            })
            .map_err(map_extension_store_error)?;
        extension_response(view)
    }

    fn extensions(
        &self,
        identity: AuthenticatedIdentity,
    ) -> Result<ExtensionsResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let extensions = self
            .lock()?
            .extensions(ownership)
            .map_err(map_extension_store_error)?
            .into_iter()
            .map(extension_response)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ExtensionsResponse {
            api_version: API_VERSION.to_owned(),
            extensions,
        })
    }

    fn extension(
        &self,
        identity: AuthenticatedIdentity,
        extension_id: String,
    ) -> Result<ExtensionResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let extension_id = parse_extension(&extension_id)?;
        let _capacity = self
            .extension_invocations
            .try_acquire(extension_id.to_string())
            .ok_or(BackendError::Busy)?;
        let view = self
            .lock()?
            .extension(ownership, extension_id)
            .map_err(map_extension_store_error)?;
        extension_response(view)
    }

    fn stage_extension_manifest(
        &self,
        identity: AuthenticatedIdentity,
        extension_id: String,
        request: StageExtensionManifestRequest,
    ) -> Result<ExtensionResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let extension_id = parse_extension(&extension_id)?;
        let inspection =
            inspect_manifest_request(&request.manifest_json, &request.manifest_digest)?;
        if inspection.manifest.extension_id != extension_id {
            return Err(BackendError::InvalidRequest(
                "staged manifest changes the extension identity".to_owned(),
            ));
        }
        let package = inspect_extension_package(inspection.clone(), &request.installation_root)
            .map_err(map_extension_package_error)?;
        let installation_root = canonical_extension_root(&package)?;
        let view = self
            .lock()?
            .stage_extension_manifest(StageExtensionManifestCommit {
                ownership,
                extension_id,
                expected_revision: request.expected_revision,
                inspection,
                installation_root,
                event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                staged_at: self.clock.now(),
            })
            .map_err(map_extension_store_error)?;
        extension_response(view)
    }

    fn enable_extension(
        &self,
        identity: AuthenticatedIdentity,
        extension_id: String,
        request: EnableExtensionRequest,
    ) -> Result<ExtensionResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let extension_id = parse_extension(&extension_id)?;
        let view = self
            .lock()?
            .extension(ownership, extension_id)
            .map_err(map_extension_store_error)?;
        if view.revision != request.expected_revision {
            return Err(BackendError::Conflict);
        }
        let package = inspect_current_extension_package(&view)?;
        let issued_at = self.clock.now();
        let grant = build_extension_grant(
            ownership,
            extension_id,
            &view.current_manifest_digest,
            request,
            self.ids.generate_extension_grant_id(),
            epoch_milliseconds(issued_at)?,
        )?;
        grant
            .validate(&view.manifest, ownership)
            .map_err(|error| BackendError::InvalidRequest(error.to_string()))?;
        let health_capability = view.manifest.health_check.capability_id.clone();
        if !grant.capability_ids.contains(&health_capability) {
            return Err(BackendError::InvalidRequest(
                "the explicit grant must include the manifest health capability".to_owned(),
            ));
        }
        let health_request = extension_rpc_request(
            self.ids.generate_extension_invocation_id(),
            extension_id,
            &view.current_manifest_digest,
            &grant,
            health_capability,
            serde_json::json!({}),
        )?;
        health_request
            .validate(
                &view.manifest,
                &view.current_manifest_digest,
                &grant,
                ownership,
            )
            .map_err(|error| BackendError::InvalidRequest(error.to_string()))?;
        let dispatch = ExtensionDispatchRequest {
            ownership,
            manifest: view.manifest.clone(),
            manifest_digest: view.current_manifest_digest.clone(),
            grant: grant.clone(),
            capability_token: extension_capability_token(health_request.invocation_id),
            rpc_request: health_request,
        };
        let host = LinuxBubblewrapExtensionHost::new(BUBBLEWRAP_PATH, package)
            .map_err(|error| map_extension_host_boundary_error(&error))?;
        let health = host
            .invoke(&dispatch, &NeverCancelled)
            .map_err(|error| map_extension_host_boundary_error(&error))?;
        let enabled = self
            .lock()?
            .enable_extension(EnableExtensionCommit {
                ownership,
                extension_id,
                expected_revision: view.revision,
                grant,
                health_output_digest: health.output_digest,
                event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                enabled_at: self.clock.now(),
            })
            .map_err(map_extension_store_error)?;
        extension_response(enabled)
    }

    fn disable_extension(
        &self,
        identity: AuthenticatedIdentity,
        extension_id: String,
        request: ExtensionLifecycleRequest,
    ) -> Result<ExtensionResponse, BackendError> {
        let view = self
            .lock()?
            .disable_extension(DisableExtensionCommit {
                ownership: parse_ownership(&identity)?,
                extension_id: parse_extension(&extension_id)?,
                expected_revision: request.expected_revision,
                event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                disabled_at: self.clock.now(),
            })
            .map_err(map_extension_store_error)?;
        extension_response(view)
    }

    fn revoke_extension(
        &self,
        identity: AuthenticatedIdentity,
        extension_id: String,
        request: ExtensionLifecycleRequest,
    ) -> Result<ExtensionResponse, BackendError> {
        let view = self
            .lock()?
            .revoke_extension(RevokeExtensionCommit {
                ownership: parse_ownership(&identity)?,
                extension_id: parse_extension(&extension_id)?,
                expected_revision: request.expected_revision,
                event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                revoked_at: self.clock.now(),
            })
            .map_err(map_extension_store_error)?;
        extension_response(view)
    }

    fn invoke_extension(
        &self,
        identity: AuthenticatedIdentity,
        extension_id: String,
        request: InvokeExtensionRequest,
    ) -> Result<ExtensionInvocationResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let extension_id = parse_extension(&extension_id)?;
        let view = self
            .lock()?
            .extension(ownership, extension_id)
            .map_err(map_extension_store_error)?;
        if view.status != ExtensionStatus::Enabled {
            return Err(BackendError::Conflict);
        }
        let grant = view.active_grant.clone().ok_or(BackendError::Internal)?;
        let grant_digest = view
            .active_grant_digest
            .clone()
            .ok_or(BackendError::Internal)?;
        let package = inspect_current_extension_package(&view)?;
        let invocation_id = self.ids.generate_extension_invocation_id();
        let rpc_request = extension_rpc_request(
            invocation_id,
            extension_id,
            &view.current_manifest_digest,
            &grant,
            request.capability_id,
            request.input,
        )?;
        rpc_request
            .validate(
                &view.manifest,
                &view.current_manifest_digest,
                &grant,
                ownership,
            )
            .map_err(|error| BackendError::InvalidRequest(error.to_string()))?;
        self.lock()?
            .begin_extension_invocation(mealy_application::BeginExtensionInvocationCommit {
                ownership,
                extension_id,
                expected_extension_revision: view.revision,
                invocation_id,
                manifest_digest: view.current_manifest_digest.clone(),
                grant_id: grant.grant_id,
                grant_digest: grant_digest.clone(),
                capability_id: rpc_request.capability_id.clone(),
                input_digest: rpc_request.input_digest.clone(),
                event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                started_at: self.clock.now(),
            })
            .map_err(map_extension_store_error)?;

        let dispatch = ExtensionDispatchRequest {
            ownership,
            manifest: view.manifest,
            manifest_digest: view.current_manifest_digest,
            grant,
            capability_token: extension_capability_token(invocation_id),
            rpc_request,
        };
        let started = Instant::now();
        let result = LinuxBubblewrapExtensionHost::new(BUBBLEWRAP_PATH, package)
            .and_then(|host| host.invoke(&dispatch, &NeverCancelled));
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let terminal = match result {
            Ok(response) => ExtensionInvocationTerminal::Succeeded(response),
            Err(error) => {
                let (error_class, error_message) = extension_failure_evidence(&error);
                ExtensionInvocationTerminal::Failed {
                    error_class,
                    error_message,
                }
            }
        };
        let completed = self
            .lock()?
            .complete_extension_invocation(CompleteExtensionInvocationCommit {
                ownership,
                invocation_id,
                terminal,
                duration_ms,
                event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                completed_at: self.clock.now(),
            })
            .map_err(map_extension_store_error)?;
        Ok(extension_invocation_response(completed))
    }

    fn create_webhook_channel(
        &self,
        identity: AuthenticatedIdentity,
        request: CreateWebhookChannelRequest,
    ) -> Result<CreateWebhookChannelResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        validate_webhook_callback_url(&request.callback_url)?;
        let binding_id = self.ids.generate_channel_binding_id();
        let session_id = self.ids.generate_session_id();
        let mut secret = [0_u8; 32];
        getrandom::fill(&mut secret).map_err(|_| BackendError::Internal)?;
        let secret_digest = sha256_digest(&secret);
        validate_webhook_binding_fields(
            &request.external_subject,
            &request.callback_url,
            &secret_digest,
        )
        .map_err(|error| BackendError::InvalidRequest(error.to_string()))?;
        self.channel_secrets
            .put(binding_id, &secret)
            .map_err(|error| map_channel_secret_error(&error))?;
        let commit = RegisterWebhookChannelCommit {
            administrative_ownership: ownership,
            binding_id,
            session_id,
            external_subject: request.external_subject,
            callback_url: request.callback_url,
            secret_digest,
            session_event_id: self.ids.generate_event_id(),
            binding_event_id: self.ids.generate_event_id(),
            correlation_id: self.ids.generate_correlation_id(),
            created_at: self.clock.now(),
        };
        let view = match self.lock()?.register_webhook_channel(commit) {
            Ok(view) => view,
            Err(error) => {
                let _ = self.channel_secrets.remove(binding_id);
                return Err(map_webhook_store_error(error));
            }
        };
        Ok(CreateWebhookChannelResponse {
            channel: webhook_channel_response(view),
            signing_secret: URL_SAFE_NO_PAD.encode(secret),
            signature_version: WEBHOOK_SIGNATURE_VERSION.to_owned(),
            signature_algorithm: WEBHOOK_SIGNATURE_ALGORITHM.to_owned(),
        })
    }

    fn webhook_channels(
        &self,
        identity: AuthenticatedIdentity,
    ) -> Result<WebhookChannelsResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let channels = self
            .lock()?
            .webhook_channels(ownership)
            .map_err(map_webhook_store_error)?
            .into_iter()
            .map(webhook_channel_response)
            .collect();
        Ok(WebhookChannelsResponse {
            api_version: API_VERSION.to_owned(),
            channels,
        })
    }

    fn webhook_channel(
        &self,
        identity: AuthenticatedIdentity,
        binding_id: String,
    ) -> Result<WebhookChannelResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let view = self
            .lock()?
            .webhook_channel(ownership, parse_channel_binding(&binding_id)?)
            .map_err(map_webhook_store_error)?;
        Ok(webhook_channel_response(view))
    }

    fn revoke_webhook_channel(
        &self,
        identity: AuthenticatedIdentity,
        binding_id: String,
        request: RevokeWebhookChannelRequest,
    ) -> Result<WebhookChannelResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let binding_id = parse_channel_binding(&binding_id)?;
        let current = self
            .lock()?
            .webhook_channel(ownership, binding_id)
            .map_err(map_webhook_store_error)?;
        if current.status != WebhookChannelStatus::Active
            || current.revision != request.expected_revision
        {
            return Err(BackendError::Conflict);
        }
        self.channel_secrets
            .remove(binding_id)
            .map_err(|error| map_channel_secret_error(&error))?;
        let revoked = self
            .lock()?
            .revoke_webhook_channel(RevokeWebhookChannelCommit {
                administrative_ownership: ownership,
                binding_id,
                expected_revision: request.expected_revision,
                event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                revoked_at: self.clock.now(),
            })
            .map_err(map_webhook_store_error)?;
        Ok(webhook_channel_response(revoked))
    }

    fn receive_signed_webhook(
        &self,
        binding_id: String,
        envelope: SignedWebhookEnvelope,
    ) -> Result<InputAdmissionResponse, BackendError> {
        if self.safe_mode || !self.admission_open() {
            return Err(BackendError::Unavailable);
        }
        let binding_id =
            ChannelBindingId::from_str(&binding_id).map_err(|_| BackendError::Unauthorized)?;
        validate_webhook_timestamp(
            self.clock.now(),
            envelope.timestamp_ms,
            WEBHOOK_MAXIMUM_CLOCK_SKEW,
        )
        .map_err(|_| BackendError::Unauthorized)?;
        let binding = self
            .lock()?
            .webhook_channel_for_verification(binding_id)
            .map_err(|error| match error {
                WebhookChannelStoreError::Unavailable(_) => BackendError::Unavailable,
                WebhookChannelStoreError::InvariantViolation(_) => BackendError::Internal,
                _ => BackendError::Unauthorized,
            })?;
        if binding.status != WebhookChannelStatus::Active {
            return Err(BackendError::Unauthorized);
        }
        let secret = self
            .channel_secrets
            .read(binding_id)
            .map_err(|error| map_channel_secret_error(&error))?;
        if sha256_digest(&secret) != binding.secret_digest {
            return Err(BackendError::Internal);
        }
        verify_webhook_signature(
            &secret,
            binding_id,
            envelope.timestamp_ms,
            &envelope.nonce,
            &envelope.body,
            &envelope.signature,
        )
        .map_err(|_| BackendError::Unauthorized)?;
        let request =
            serde_json::from_slice::<SignedWebhookInputRequest>(&envelope.body).map_err(|_| {
                BackendError::InvalidRequest(
                    "signed webhook body does not match the versioned schema".to_owned(),
                )
            })?;
        if request.api_version != API_VERSION {
            return Err(BackendError::InvalidRequest(
                "signed webhook API version is unsupported".to_owned(),
            ));
        }
        if request.subject != binding.external_subject {
            return Err(BackendError::Unauthorized);
        }
        let dedupe_key = webhook_input_dedupe_key(binding_id, &request.delivery_id)
            .map_err(|error| BackendError::InvalidRequest(error.to_string()))?;
        let received_at = self.clock.now();
        self.lock()?
            .reserve_webhook_delivery(ReserveWebhookDeliveryCommit {
                binding_id,
                delivery_id: request.delivery_id.clone(),
                nonce: envelope.nonce,
                body_digest: sha256_digest(&envelope.body),
                signature_digest: webhook_signature_digest(&envelope.signature),
                received_at,
            })
            .map_err(map_webhook_store_error)?;
        let ownership = OwnershipContext::new(binding.principal_id, binding_id);
        let outcome = admit_input(
            &mut *self.lock()?,
            &self.clock,
            &self.ids,
            InputAdmissionLimits::new(256, 1024 * 1024, self.maximum_pending_inputs_per_session),
            AdmitInputCommand {
                session_id: binding.session_id,
                ownership,
                dedupe_key,
                delivery_mode: request.delivery_mode.into(),
                content: request.content,
            },
        )
        .map_err(map_session_error)?;
        let receipt = outcome.receipt().clone();
        self.lock()?
            .complete_webhook_delivery(CompleteWebhookDeliveryCommit {
                binding_id,
                delivery_id: request.delivery_id,
                admission: receipt.clone(),
                completed_at: self.clock.now(),
            })
            .map_err(map_webhook_store_error)?;
        input_admission_response(
            &receipt,
            matches!(outcome, InputAdmissionOutcome::Duplicate(_)),
        )
    }

    fn task(
        &self,
        identity: AuthenticatedIdentity,
        task_id: String,
    ) -> Result<TaskResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let task_id = parse_task(&task_id)?;
        let (task, criteria, validation) = {
            let store = self.lock()?;
            let task = store
                .agent_task(ownership, task_id)
                .map_err(|error| map_agent_error(&error))?;
            let criteria = store
                .task_success_criteria(ownership, task_id)
                .map_err(|error| map_agent_error(&error))?;
            let validation = store
                .task_validation(ownership, task_id)
                .map_err(|error| map_agent_error(&error))?;
            (task, criteria, validation)
        };
        Ok(TaskResponse {
            api_version: API_VERSION.to_owned(),
            task_id: task.task_id.to_string(),
            run_id: task.run_id.to_string(),
            status: parse_task_status(&task.status)?,
            revision: task.revision,
            final_response: task.final_response,
            final_digest: task.final_digest,
            usage: TaskBudgetUsage {
                used_model_calls: task.usage.used_model_calls,
                reserved_model_calls: task.usage.reserved_model_calls,
                used_tool_calls: task.usage.used_tool_calls,
                reserved_tool_calls: task.usage.reserved_tool_calls,
                used_delegated_runs: task.usage.used_delegated_runs,
                reserved_delegated_runs: task.usage.reserved_delegated_runs,
                used_retries: task.usage.used_retries,
                used_input_tokens: task.usage.used_input_tokens,
                reserved_input_tokens: task.usage.reserved_input_tokens,
                used_output_tokens: task.usage.used_output_tokens,
                reserved_output_tokens: task.usage.reserved_output_tokens,
                used_cost_microunits: task.usage.used_cost_microunits,
                reserved_cost_microunits: task.usage.reserved_cost_microunits,
                used_output_bytes: task.usage.used_output_bytes,
                reserved_output_bytes: task.usage.reserved_output_bytes,
            },
            success_criteria: TaskSuccessCriteriaResponse {
                objective: criteria.criteria.objective,
                criteria: criteria
                    .criteria
                    .criteria
                    .into_iter()
                    .map(|criterion| SuccessCriterionResponse {
                        criterion_id: criterion.criterion_id,
                        requirement: criterion.requirement,
                    })
                    .collect(),
                no_objective_criteria_reason: criteria.criteria.no_objective_criteria_reason,
                risk_class: TaskRiskClass::from(criteria.criteria.risk_class),
                policy_version: criteria.criteria.policy_version,
                criteria_digest: criteria.criteria_digest,
            },
            validation: validation.map(|validation| TaskValidationResponse {
                validation_id: validation.validation_id.to_string(),
                producer_run_id: validation.producer_run_id.to_string(),
                validator_run_id: validation.validator_run_id.map(|id| id.to_string()),
                context_manifest_id: validation.context_manifest_id.to_string(),
                method: validation_method_response(validation.method),
                outcome: validation_outcome_response(validation.outcome),
                rubric: validation.rubric,
                evidence: validation.evidence,
                policy_version: validation.policy_version,
                cursor: TimelineCursor(validation.cursor),
            }),
            model_attempts: task.model_attempts,
            tool_calls: task.tool_calls,
        })
    }

    fn cancel_task(
        &self,
        identity: AuthenticatedIdentity,
        task_id: String,
        request: CancelTaskRequest,
    ) -> Result<TaskCancellationReceipt, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let task_id = parse_task(&task_id)?;
        let receipt = self
            .lock()?
            .request_task_cancellation(RequestTaskCancellationCommit {
                ownership,
                task_id,
                idempotency_key: request.idempotency_key,
                reason: request.reason,
                event_id: self.ids.generate_event_id(),
                run_event_id: self.ids.generate_event_id(),
                approval_event_id: self.ids.generate_event_id(),
                effect_event_id: self.ids.generate_event_id(),
                requested_at: self.clock.now(),
            })
            .map_err(|error| map_agent_error(&error))?;
        Ok(TaskCancellationReceipt {
            api_version: API_VERSION.to_owned(),
            task_id: receipt.task_id.to_string(),
            status: TaskStatus::Cancelling,
            revision: receipt.revision,
            event_id: receipt.event_id.to_string(),
            cursor: TimelineCursor(receipt.cursor),
            duplicate: receipt.duplicate,
        })
    }

    fn pause_task(
        &self,
        identity: AuthenticatedIdentity,
        task_id: String,
        request: ControlTaskRequest,
    ) -> Result<TaskControlReceipt, BackendError> {
        self.control_task(&identity, &task_id, &request, TaskControlAction::Pause)
    }

    fn resume_task(
        &self,
        identity: AuthenticatedIdentity,
        task_id: String,
        request: ControlTaskRequest,
    ) -> Result<TaskControlReceipt, BackendError> {
        self.control_task(&identity, &task_id, &request, TaskControlAction::Resume)
    }

    fn task_replay(
        &self,
        identity: AuthenticatedIdentity,
        task_id: String,
    ) -> Result<TaskReplayResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let task_id = parse_task(&task_id)?;
        let (mut replay, artifact_descriptors) = {
            let store = self.lock()?;
            let replay = store
                .replay_agent_task(ownership, task_id)
                .map_err(|error| map_agent_error(&error))?;
            let descriptors = store.task_artifact_content_descriptors(ownership, task_id);
            (replay, descriptors)
        };
        match artifact_descriptors {
            Ok(descriptors) => {
                replay.evidence_complete &= descriptors
                    .iter()
                    .all(|descriptor| self.artifacts.read(descriptor.committed_blob()).is_ok());
            }
            Err(_) => replay.evidence_complete = false,
        }
        Ok(TaskReplayResponse {
            api_version: API_VERSION.to_owned(),
            task_id: replay.task_id.to_string(),
            run_id: replay.run_id.to_string(),
            mode: replay.mode,
            evidence_complete: replay.evidence_complete,
            final_response: replay.final_response,
            final_digest: replay.final_digest,
            model_attempts: replay.model_attempts,
            tool_calls: replay.tool_calls,
            live_provider_calls: replay.live_provider_calls,
            live_tool_calls: replay.live_tool_calls,
        })
    }

    fn pending_approvals(
        &self,
        identity: AuthenticatedIdentity,
    ) -> Result<PendingApprovalsResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let approvals = self
            .lock()?
            .pending_approval_requests(ownership)
            .map_err(map_effect_ledger_error)?
            .into_iter()
            .map(approval_response)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PendingApprovalsResponse {
            api_version: API_VERSION.to_owned(),
            approvals,
        })
    }

    fn resolve_approval(
        &self,
        identity: AuthenticatedIdentity,
        approval_id: String,
        request: ResolveApprovalRequest,
    ) -> Result<ApprovalResolutionReceipt, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let approval_id = parse_approval(&approval_id)?;
        let decision = match request.decision {
            ApprovalDecisionCommand::Approve => ApprovalDecision::Approve,
            ApprovalDecisionCommand::Deny => ApprovalDecision::Deny,
        };
        let receipt = self
            .lock()?
            .resolve_approval(ResolveApprovalCommit {
                approval_id,
                ownership,
                expected_subject_digest: request.expected_subject_digest,
                decision,
                idempotency_key: request.idempotency_key,
                approval_event_id: self.ids.generate_event_id(),
                effect_event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                decided_at: self.clock.now(),
            })
            .map_err(map_effect_ledger_error)?;
        Ok(ApprovalResolutionReceipt {
            api_version: API_VERSION.to_owned(),
            approval_id: receipt.approval_id.to_string(),
            effect_id: receipt.effect_id.to_string(),
            status: match receipt.decision {
                ApprovalDecision::Approve => ApprovalStatusResponse::Approved,
                ApprovalDecision::Deny => ApprovalStatusResponse::Denied,
            },
            decision: match receipt.decision {
                ApprovalDecision::Approve => ApprovalDecisionCommand::Approve,
                ApprovalDecision::Deny => ApprovalDecisionCommand::Deny,
            },
            effect_revision: receipt.effect_revision,
            approval_event_id: receipt.approval_event_id.to_string(),
            effect_event_id: receipt.effect_event_id.to_string(),
            cursor: TimelineCursor(receipt.cursor),
            duplicate: receipt.duplicate,
        })
    }

    fn effect(
        &self,
        identity: AuthenticatedIdentity,
        effect_id: String,
    ) -> Result<EffectResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let effect_id = parse_effect(&effect_id)?;
        let view = self
            .lock()?
            .effect_ledger_view(ownership, effect_id)
            .map_err(map_effect_ledger_error)?;
        effect_response(view)
    }

    fn effect_attempt(
        &self,
        identity: AuthenticatedIdentity,
        attempt_id: String,
    ) -> Result<EffectAttemptResponse, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let attempt_id = parse_attempt(&attempt_id)?;
        let view = self
            .lock()?
            .effect_attempt_view(ownership, attempt_id)
            .map_err(map_effect_ledger_error)?;
        effect_attempt_response(view)
    }

    fn reconcile_effect(
        &self,
        identity: AuthenticatedIdentity,
        effect_id: String,
        attempt_id: String,
        request: ReconcileEffectRequest,
    ) -> Result<EffectReconciliationReceipt, BackendError> {
        let ownership = parse_ownership(&identity)?;
        let effect_id = parse_effect(&effect_id)?;
        let attempt_id = parse_attempt(&attempt_id)?;
        let outcome = match request.outcome {
            ReconciliationOutcomeCommand::Succeeded => EffectReconciliationOutcome::Succeeded,
            ReconciliationOutcomeCommand::Failed => EffectReconciliationOutcome::Failed,
        };
        let receipt = self
            .lock()?
            .reconcile_effect_outcome(ReconcileEffectOutcomeCommit {
                effect_id,
                attempt_id,
                ownership,
                expected_effect_revision: request.expected_effect_revision,
                outcome,
                evidence_details: request.evidence,
                idempotency_key: request.idempotency_key,
                event_id: self.ids.generate_event_id(),
                correlation_id: self.ids.generate_correlation_id(),
                reconciled_at: self.clock.now(),
            })
            .map_err(map_effect_ledger_error)?;
        Ok(EffectReconciliationReceipt {
            api_version: API_VERSION.to_owned(),
            effect_id: receipt.effect_id.to_string(),
            attempt_id: receipt.attempt_id.to_string(),
            outcome: match receipt.outcome {
                EffectReconciliationOutcome::Succeeded => ReconciliationOutcomeCommand::Succeeded,
                EffectReconciliationOutcome::Failed => ReconciliationOutcomeCommand::Failed,
            },
            effect_revision: receipt.effect_revision,
            event_id: receipt.event_id.to_string(),
            cursor: TimelineCursor(receipt.cursor),
            duplicate: receipt.duplicate,
        })
    }
}

struct NeverCancelled;

impl CancellationProbe for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

fn input_admission_response(
    receipt: &InputAdmissionReceipt,
    duplicate: bool,
) -> Result<InputAdmissionResponse, BackendError> {
    Ok(InputAdmissionResponse {
        api_version: API_VERSION.to_owned(),
        session_id: receipt.session_id.to_string(),
        inbox_entry_id: receipt.inbox_entry_id.to_string(),
        inbox_sequence: receipt.inbox_sequence,
        delivery_mode: receipt.delivery_mode.into(),
        event_id: receipt.event_id.to_string(),
        outbox_id: receipt.outbox_id.to_string(),
        accepted_at_ms: epoch_milliseconds(receipt.accepted_at)?,
        duplicate,
        cursor: TimelineCursor(receipt.timeline_cursor),
    })
}

fn webhook_channel_response(view: WebhookChannelBindingView) -> WebhookChannelResponse {
    WebhookChannelResponse {
        api_version: API_VERSION.to_owned(),
        binding_id: view.binding_id.to_string(),
        session_id: view.session_id.to_string(),
        external_subject: view.external_subject,
        callback_url: view.callback_url,
        status: match view.status {
            WebhookChannelStatus::Active => WebhookChannelStatusResponse::Active,
            WebhookChannelStatus::Revoked => WebhookChannelStatusResponse::Revoked,
        },
        revision: view.revision,
        created_at_ms: view.created_at_ms,
        updated_at_ms: view.updated_at_ms,
    }
}

fn validate_webhook_callback_url(value: &str) -> Result<(), BackendError> {
    let url = reqwest::Url::parse(value)
        .map_err(|_| BackendError::InvalidRequest("webhook callback URL is invalid".to_owned()))?;
    let credentials_absent = url.username().is_empty() && url.password().is_none();
    let host_present = url.host_str().is_some();
    let scheme_allowed = match url.scheme() {
        "https" => true,
        "http" => url
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|address| address.is_loopback()),
        _ => false,
    };
    if url.cannot_be_a_base()
        || !credentials_absent
        || !host_present
        || !scheme_allowed
        || url.fragment().is_some()
    {
        return Err(BackendError::InvalidRequest(
            "webhook callbacks require HTTPS, or literal loopback HTTP for local development, without credentials or fragments"
                .to_owned(),
        ));
    }
    Ok(())
}

fn inspect_manifest_request(
    manifest_json: &str,
    manifest_digest: &str,
) -> Result<ExtensionManifestInspection, BackendError> {
    inspect_extension_manifest(manifest_json.as_bytes(), manifest_digest)
        .map_err(|error| BackendError::InvalidRequest(error.to_string()))
}

fn canonical_extension_root(package: &InstalledExtensionPackage) -> Result<String, BackendError> {
    package
        .installation_root()
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            BackendError::InvalidRequest(
                "extension installation root must be valid UTF-8".to_owned(),
            )
        })
}

fn inspect_current_extension_package(
    view: &ExtensionView,
) -> Result<InstalledExtensionPackage, BackendError> {
    let revision = view
        .manifest_history
        .iter()
        .rev()
        .find(|revision| revision.manifest_digest == view.current_manifest_digest)
        .ok_or(BackendError::Internal)?;
    inspect_extension_package(
        ExtensionManifestInspection {
            manifest: revision.manifest.clone(),
            manifest_json: revision.manifest_json.clone(),
            manifest_digest: revision.manifest_digest.clone(),
        },
        &revision.installation_root,
    )
    .map_err(map_extension_package_error)
}

fn build_extension_grant(
    ownership: OwnershipContext,
    extension_id: ExtensionId,
    manifest_digest: &str,
    request: EnableExtensionRequest,
    grant_id: ExtensionGrantId,
    issued_at_ms: i64,
) -> Result<ExtensionGrant, BackendError> {
    let mounts = request
        .mounts
        .into_iter()
        .map(|mount| ExtensionMountGrant {
            name: mount.name,
            access: match mount.access {
                ExtensionFilesystemAccessCommand::ReadOnly => ExtensionFilesystemAccess::ReadOnly,
                ExtensionFilesystemAccessCommand::ReadWrite => ExtensionFilesystemAccess::ReadWrite,
            },
            host_path: mount.host_path,
            sandbox_path: mount.sandbox_path,
        })
        .collect();
    let capability_ids = request.capability_ids.into_iter().collect::<BTreeSet<_>>();
    if capability_ids.is_empty() {
        return Err(BackendError::InvalidRequest(
            "extension grant must contain at least one capability".to_owned(),
        ));
    }
    Ok(ExtensionGrant {
        grant_id,
        extension_id,
        manifest_digest: manifest_digest.to_owned(),
        capability_ids,
        mounts,
        network_destinations: request.network_destinations.into_iter().collect(),
        secret_references: request.secret_references.into_iter().collect(),
        allow_process_spawn: request.allow_process_spawn,
        policy_version: EXTENSION_POLICY_VERSION.to_owned(),
        issued_by_principal_id: ownership.principal_id(),
        issued_at_ms,
    })
}

fn extension_rpc_request(
    invocation_id: ExtensionInvocationId,
    extension_id: ExtensionId,
    manifest_digest: &str,
    grant: &ExtensionGrant,
    capability_id: String,
    input: serde_json::Value,
) -> Result<ExtensionRpcRequest, BackendError> {
    let input_bytes = serde_json::to_vec(&input).map_err(|_| {
        BackendError::InvalidRequest("extension input could not be encoded".to_owned())
    })?;
    Ok(ExtensionRpcRequest {
        protocol_version: EXTENSION_RPC_VERSION.to_owned(),
        invocation_id,
        extension_id,
        manifest_digest: manifest_digest.to_owned(),
        grant_digest: extension_grant_digest(grant)
            .map_err(|_| BackendError::InvalidRequest("extension grant is invalid".to_owned()))?,
        capability_id,
        input,
        input_digest: sha256_digest(&input_bytes),
    })
}

fn extension_capability_token(invocation_id: ExtensionInvocationId) -> String {
    sha256_digest(format!("mealy.extension.capability.v1:{invocation_id}").as_bytes())
}

fn extension_response(view: ExtensionView) -> Result<ExtensionResponse, BackendError> {
    let active_grant = match (view.active_grant, view.active_grant_digest) {
        (Some(grant), Some(digest)) => Some(extension_grant_response(grant, digest)),
        (None, None) => None,
        _ => return Err(BackendError::Internal),
    };
    let manifest = serde_json::to_value(&view.manifest).map_err(|_| BackendError::Internal)?;
    Ok(ExtensionResponse {
        api_version: API_VERSION.to_owned(),
        extension_id: view.extension_id.to_string(),
        principal_id: view.principal_id.to_string(),
        status: extension_status_response(view.status),
        revision: view.revision,
        manifest_digest: view.current_manifest_digest,
        version: view.manifest.version,
        name: view.manifest.name,
        publisher: view.manifest.publisher,
        manifest,
        active_grant,
        manifest_history: view
            .manifest_history
            .into_iter()
            .map(|revision| ExtensionManifestRevisionResponse {
                manifest_digest: revision.manifest_digest,
                version: revision.manifest.version,
                installed_at_ms: revision.installed_at_ms,
            })
            .collect(),
        last_healthy_at_ms: view.last_healthy_at_ms,
        last_failure_at_ms: view.last_failure_at_ms,
    })
}

fn extension_grant_response(grant: ExtensionGrant, digest: String) -> ExtensionGrantResponse {
    ExtensionGrantResponse {
        grant_id: grant.grant_id.to_string(),
        grant_digest: digest,
        manifest_digest: grant.manifest_digest,
        capability_ids: grant.capability_ids.into_iter().collect(),
        mounts: grant
            .mounts
            .into_iter()
            .map(|mount| ExtensionMountGrantCommand {
                name: mount.name,
                access: match mount.access {
                    ExtensionFilesystemAccess::ReadOnly => {
                        ExtensionFilesystemAccessCommand::ReadOnly
                    }
                    ExtensionFilesystemAccess::ReadWrite => {
                        ExtensionFilesystemAccessCommand::ReadWrite
                    }
                },
                host_path: mount.host_path,
                sandbox_path: mount.sandbox_path,
            })
            .collect(),
        network_destinations: grant.network_destinations.into_iter().collect(),
        secret_references: grant.secret_references.into_iter().collect(),
        allow_process_spawn: grant.allow_process_spawn,
        policy_version: grant.policy_version,
        issued_at_ms: grant.issued_at_ms,
    }
}

const fn extension_status_response(status: ExtensionStatus) -> ExtensionStatusResponse {
    match status {
        ExtensionStatus::Installed => ExtensionStatusResponse::Installed,
        ExtensionStatus::Enabled => ExtensionStatusResponse::Enabled,
        ExtensionStatus::Disabled => ExtensionStatusResponse::Disabled,
        ExtensionStatus::Failed => ExtensionStatusResponse::Failed,
        ExtensionStatus::Revoked => ExtensionStatusResponse::Revoked,
    }
}

fn extension_invocation_response(view: ExtensionInvocationView) -> ExtensionInvocationResponse {
    let output = view.response.map(|response| response.output);
    ExtensionInvocationResponse {
        api_version: API_VERSION.to_owned(),
        invocation_id: view.invocation_id.to_string(),
        extension_id: view.extension_id.to_string(),
        capability_id: view.capability_id,
        status: match view.status {
            ExtensionInvocationStatus::Dispatching => {
                ExtensionInvocationStatusResponse::Dispatching
            }
            ExtensionInvocationStatus::Succeeded => ExtensionInvocationStatusResponse::Succeeded,
            ExtensionInvocationStatus::Failed => ExtensionInvocationStatusResponse::Failed,
            ExtensionInvocationStatus::Abandoned => ExtensionInvocationStatusResponse::Abandoned,
        },
        output,
        output_digest: view.output_digest,
        error_class: view.error_class,
        error_message: view.error_message,
        duration_ms: view.duration_ms,
        started_at_ms: view.started_at_ms,
        completed_at_ms: view.completed_at_ms,
    }
}

fn extension_failure_evidence(error: &ExtensionHostError) -> (String, String) {
    let (class, message) = match error {
        ExtensionHostError::InvalidDispatch => (
            "invalid_dispatch",
            "extension dispatch contract was rejected",
        ),
        ExtensionHostError::UnsupportedHost(_) => (
            "unsupported_host",
            "extension isolation boundary is unavailable",
        ),
        ExtensionHostError::IdentityMismatch => (
            "identity_mismatch",
            "extension executable or runtime identity changed",
        ),
        ExtensionHostError::TimedOut => ("timed_out", "extension invocation timed out"),
        ExtensionHostError::Cancelled => ("cancelled", "extension invocation was cancelled"),
        ExtensionHostError::OutputLimitExceeded => (
            "output_limit_exceeded",
            "extension output exceeded its declared bound",
        ),
        ExtensionHostError::ProcessFailure(_) => {
            ("process_failure", "extension worker process failed")
        }
        ExtensionHostError::WorkerFailure { .. } => {
            ("worker_failure", "extension capability reported failure")
        }
        ExtensionHostError::InvalidResponse => (
            "invalid_response",
            "extension response did not bind the authorized request",
        ),
    };
    (class.to_owned(), message.to_owned())
}

fn parse_ownership(identity: &AuthenticatedIdentity) -> Result<OwnershipContext, BackendError> {
    Ok(OwnershipContext::new(
        PrincipalId::from_str(&identity.principal_id).map_err(|_| BackendError::Internal)?,
        ChannelBindingId::from_str(&identity.channel_binding_id)
            .map_err(|_| BackendError::Internal)?,
    ))
}

fn parse_channel_binding(value: &str) -> Result<ChannelBindingId, BackendError> {
    ChannelBindingId::from_str(value)
        .map_err(|_| BackendError::InvalidRequest("invalid channel binding ID".to_owned()))
}

fn parse_extension(value: &str) -> Result<ExtensionId, BackendError> {
    ExtensionId::from_str(value)
        .map_err(|_| BackendError::InvalidRequest("invalid extension ID".to_owned()))
}

fn parse_session(value: &str) -> Result<SessionId, BackendError> {
    SessionId::from_str(value)
        .map_err(|_| BackendError::InvalidRequest("invalid session ID".to_owned()))
}

fn parse_task(value: &str) -> Result<TaskId, BackendError> {
    TaskId::from_str(value).map_err(|_| BackendError::InvalidRequest("invalid task ID".to_owned()))
}

fn parse_approval(value: &str) -> Result<ApprovalId, BackendError> {
    ApprovalId::from_str(value)
        .map_err(|_| BackendError::InvalidRequest("invalid approval ID".to_owned()))
}

fn parse_effect(value: &str) -> Result<EffectId, BackendError> {
    EffectId::from_str(value)
        .map_err(|_| BackendError::InvalidRequest("invalid effect ID".to_owned()))
}

fn parse_attempt(value: &str) -> Result<AttemptId, BackendError> {
    AttemptId::from_str(value)
        .map_err(|_| BackendError::InvalidRequest("invalid effect attempt ID".to_owned()))
}

fn parse_artifact(value: &str) -> Result<ArtifactId, BackendError> {
    ArtifactId::from_str(value)
        .map_err(|_| BackendError::InvalidRequest("invalid artifact ID".to_owned()))
}

fn parse_context_manifest(value: &str) -> Result<ContextManifestId, BackendError> {
    ContextManifestId::from_str(value)
        .map_err(|_| BackendError::InvalidRequest("invalid context manifest ID".to_owned()))
}

fn parse_memory(value: &str) -> Result<MemoryId, BackendError> {
    MemoryId::from_str(value)
        .map_err(|_| BackendError::InvalidRequest("invalid memory ID".to_owned()))
}

fn parse_memory_revision(value: &str) -> Result<MemoryRevisionId, BackendError> {
    MemoryRevisionId::from_str(value)
        .map_err(|_| BackendError::InvalidRequest("invalid memory revision ID".to_owned()))
}

fn parse_compaction(value: &str) -> Result<CompactionId, BackendError> {
    CompactionId::from_str(value)
        .map_err(|_| BackendError::InvalidRequest("invalid compaction ID".to_owned()))
}

fn approval_response(view: ApprovalRequestView) -> Result<ApprovalResponse, BackendError> {
    let subject = view.subject;
    Ok(ApprovalResponse {
        api_version: API_VERSION.to_owned(),
        approval_id: view.approval_id.to_string(),
        effect_id: view.effect_id.to_string(),
        subject: ApprovalSubjectResponse {
            effect_id: subject.effect_id.to_string(),
            principal_id: subject.principal_id.to_string(),
            task_id: subject.task_id.to_string(),
            tool_id: subject.tool_id,
            tool_version: subject.tool_version,
            canonical_arguments_digest: subject.canonical_arguments_digest,
            capability_scope: subject.capability_scope,
            target_resources: subject.target_resources,
            executable_identity_digest: subject.executable_identity_digest,
            policy_version: subject.policy_version,
            expires_at_ms: subject.expires_at_ms,
        },
        subject_digest: view.subject_digest,
        status: match view.status {
            ApprovalStatus::Pending => ApprovalStatusResponse::Pending,
            ApprovalStatus::Approved => ApprovalStatusResponse::Approved,
            ApprovalStatus::Denied => ApprovalStatusResponse::Denied,
            ApprovalStatus::Expired => ApprovalStatusResponse::Expired,
            ApprovalStatus::Revoked => ApprovalStatusResponse::Revoked,
        },
        decision: view.decision.map(|decision| match decision {
            ApprovalDecision::Approve => ApprovalDecisionCommand::Approve,
            ApprovalDecision::Deny => ApprovalDecisionCommand::Deny,
        }),
        requested_at_ms: epoch_milliseconds(view.requested_at)?,
        resolved_at_ms: view.resolved_at.map(epoch_milliseconds).transpose()?,
    })
}

fn effect_response(view: EffectLedgerView) -> Result<EffectResponse, BackendError> {
    let policy_decision = serde_json::to_value(view.policy_evaluation.decision)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(BackendError::Internal)?;
    let policy_obligations = serde_json::to_value(&view.policy_evaluation.obligations)
        .map_err(|_| BackendError::Internal)?;
    let approval = view.approval.map(approval_response).transpose()?;
    Ok(EffectResponse {
        api_version: API_VERSION.to_owned(),
        effect_id: view.effect_id.to_string(),
        task_id: view.task_id.to_string(),
        run_id: view.run_id.to_string(),
        status: match view.status {
            EffectStatus::Proposed => EffectStatusResponse::Proposed,
            EffectStatus::AwaitingApproval => EffectStatusResponse::AwaitingApproval,
            EffectStatus::Authorized => EffectStatusResponse::Authorized,
            EffectStatus::Dispatching => EffectStatusResponse::Dispatching,
            EffectStatus::Succeeded => EffectStatusResponse::Succeeded,
            EffectStatus::Failed => EffectStatusResponse::Failed,
            EffectStatus::OutcomeUnknown => EffectStatusResponse::OutcomeUnknown,
            EffectStatus::Compensated => EffectStatusResponse::Compensated,
            EffectStatus::Denied => EffectStatusResponse::Denied,
        },
        revision: view.revision,
        tool_id: view.policy_request.tool.tool_id.clone(),
        tool_version: view.policy_request.tool.version.clone(),
        descriptor_digest: view.policy_request.tool.descriptor_digest.clone(),
        normalized_arguments: view.policy_request.normalized_arguments.clone(),
        arguments_digest: canonical_arguments_digest(&view.policy_request.normalized_arguments),
        capability_scope: view.policy_request.requested_capability.clone(),
        target_resources: view.policy_request.target_resources.clone(),
        executable_identity_digest: view.policy_request.tool.executable_identity_digest.clone(),
        policy_decision,
        policy_version: view.policy_evaluation.policy_version,
        policy_explanation: view.policy_evaluation.explanation,
        policy_obligations,
        idempotency_key: view.idempotency_key,
        approval,
        created_at_ms: epoch_milliseconds(view.created_at)?,
        updated_at_ms: epoch_milliseconds(view.updated_at)?,
    })
}

fn effect_attempt_response(view: EffectAttemptView) -> Result<EffectAttemptResponse, BackendError> {
    let outcomes = view
        .outcomes
        .into_iter()
        .map(|outcome| {
            Ok(EffectOutcomeEvidenceResponse {
                sequence: outcome.sequence,
                outcome: match outcome.kind {
                    EffectOutcomeKind::Succeeded => EffectOutcomeResponse::Succeeded,
                    EffectOutcomeKind::Failed => EffectOutcomeResponse::Failed,
                    EffectOutcomeKind::OutcomeUnknown => EffectOutcomeResponse::OutcomeUnknown,
                    EffectOutcomeKind::Compensated => EffectOutcomeResponse::Compensated,
                },
                evidence: outcome.evidence,
                evidence_digest: outcome.evidence_digest,
                event_id: outcome.event_id.to_string(),
                recorded_at_ms: epoch_milliseconds(outcome.recorded_at)?,
            })
        })
        .collect::<Result<Vec<_>, BackendError>>()?;
    Ok(EffectAttemptResponse {
        api_version: API_VERSION.to_owned(),
        attempt_id: view.attempt_id.to_string(),
        effect_id: view.effect_id.to_string(),
        ordinal: view.ordinal,
        status: match view.state {
            EffectAttemptState::Prepared => EffectAttemptStatusResponse::Prepared,
            EffectAttemptState::Running => EffectAttemptStatusResponse::Running,
            EffectAttemptState::Succeeded => EffectAttemptStatusResponse::Succeeded,
            EffectAttemptState::Failed => EffectAttemptStatusResponse::Failed,
            EffectAttemptState::OutcomeUnknown => EffectAttemptStatusResponse::OutcomeUnknown,
            EffectAttemptState::InterruptedRetryable => {
                EffectAttemptStatusResponse::InterruptedRetryable
            }
            EffectAttemptState::InterruptedUndispatched => {
                EffectAttemptStatusResponse::InterruptedUndispatched
            }
        },
        idempotency_key: view.idempotency_key,
        fencing_token: view.fence.fencing_token().get(),
        prepared_at_ms: epoch_milliseconds(view.prepared_at)?,
        started_at_ms: view.started_at.map(epoch_milliseconds).transpose()?,
        completed_at_ms: view.completed_at.map(epoch_milliseconds).transpose()?,
        error_class: view.error_class,
        outcomes,
    })
}

fn artifact_metadata_response(
    metadata: ArtifactMetadata,
) -> Result<ArtifactMetadataResponse, BackendError> {
    Ok(ArtifactMetadataResponse {
        api_version: API_VERSION.to_owned(),
        artifact_id: metadata.artifact_id.to_string(),
        algorithm: metadata.algorithm,
        digest: metadata.digest,
        size_bytes: metadata.size_bytes,
        media_type: metadata.media_type,
        origin_kind: metadata.origin_kind,
        origin_id: metadata.origin_id,
        producer_kind: metadata.producer_kind,
        producer_id: metadata.producer_id,
        sensitivity: metadata.sensitivity,
        retention_class: metadata.retention_class,
        access_policy_digest: metadata.access_policy_digest,
        created_at_ms: epoch_milliseconds(metadata.created_at)?,
    })
}

fn context_manifest_response(evidence: ContextManifestEvidence) -> ContextManifestEvidenceResponse {
    ContextManifestEvidenceResponse {
        api_version: API_VERSION.to_owned(),
        manifest_id: evidence.manifest_id.to_string(),
        run_id: evidence.run_id.to_string(),
        turn_id: evidence.turn_id.to_string(),
        epoch_id: evidence.epoch_id.to_string(),
        iteration: evidence.iteration,
        compiler_version: evidence.compiler_version,
        provider_residency: evidence.provider_residency,
        token_budget: evidence.token_budget,
        total_token_estimate: evidence.total_token_estimate,
        tool_schema_set_digest: evidence.tool_schema_set_digest,
        policy_version: evidence.policy_version,
        projection_digest: evidence.projection_digest,
        items: evidence
            .items
            .into_iter()
            .map(|item| ContextManifestEvidenceItemResponse {
                item_id: item.item_id.to_string(),
                ordinal: item.ordinal,
                disposition: match item.disposition {
                    ContextDisposition::Included => ContextItemDisposition::Included,
                    ContextDisposition::Excluded => ContextItemDisposition::Excluded,
                    ContextDisposition::Redacted => ContextItemDisposition::Redacted,
                },
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
                content_artifact_id: item.content_artifact_id.map(|id| id.to_string()),
                memory_evidence: item.memory_evidence.map(|evidence| {
                    ContextMemoryEvidenceResponse {
                        memory_id: evidence.memory_id.to_string(),
                        revision_id: evidence.revision_id.to_string(),
                        sources: evidence
                            .sources
                            .into_iter()
                            .map(|source| ContextMemorySourceCitationResponse {
                                source_ordinal: source.source_ordinal,
                                source_digest: source.source_digest,
                            })
                            .collect(),
                    }
                }),
                compaction_id: item.compaction_id.map(|id| id.to_string()),
            })
            .collect(),
        created_at_ms: evidence.created_at_ms,
    }
}

fn memory_response(view: MemoryView) -> MemoryResponse {
    MemoryResponse {
        api_version: API_VERSION.to_owned(),
        memory_id: view.memory_id.to_string(),
        principal_id: view.principal_id.to_string(),
        workspace_identity: view.workspace_identity,
        status: MemoryStatusResponse::from(view.status),
        revision: view.revision,
        category: memory_category_response(view.category),
        confidence_basis_points: view.confidence.basis_points(),
        sensitivity: memory_sensitivity_response(view.sensitivity),
        retention: memory_retention_response(view.retention),
        created_at_ms: view.created_at_ms,
        last_verified_at_ms: view.last_verified_at_ms,
        revisions: view
            .revisions
            .into_iter()
            .map(|revision| MemoryRevisionResponse {
                revision_id: revision.revision_id.to_string(),
                ordinal: revision.ordinal,
                status: MemoryStatusResponse::from(revision.status),
                content: revision.content,
                content_digest: revision.content_digest,
                confidence_basis_points: revision.confidence.basis_points(),
                sensitivity: memory_sensitivity_response(revision.sensitivity),
                retention: memory_retention_response(revision.retention),
                supersedes_revision_id: revision.supersedes_revision_id.map(|id| id.to_string()),
                sources: revision
                    .sources
                    .into_iter()
                    .map(|source| MemorySourceResponse {
                        locator: source.locator,
                        digest: source.digest,
                    })
                    .collect(),
                created_at_ms: revision.created_at_ms,
                last_verified_at_ms: revision.last_verified_at_ms,
            })
            .collect(),
    }
}

fn compaction_response(view: CompactionView) -> Result<CompactionResponse, BackendError> {
    Ok(CompactionResponse {
        api_version: API_VERSION.to_owned(),
        compaction_id: view.record.compaction_id.to_string(),
        artifact_id: view.record.artifact_id.to_string(),
        source_first_cursor: view.record.source_range.first_cursor,
        source_last_cursor: view.record.source_range.last_cursor,
        prompt_version: view.record.prompt_version,
        config_digest: view.record.config_digest,
        artifact_digest: view.record.artifact_digest,
        summary_text: view.summary_text,
        carry_forward: serde_json::to_value(view.record.carry_forward)
            .map_err(|_| BackendError::Internal)?,
        cursor: TimelineCursor(view.cursor.0),
    })
}

const fn memory_category(value: MemoryCategoryCommand) -> MemoryCategory {
    match value {
        MemoryCategoryCommand::Preference => MemoryCategory::Preference,
        MemoryCategoryCommand::Fact => MemoryCategory::Fact,
        MemoryCategoryCommand::Goal => MemoryCategory::Goal,
        MemoryCategoryCommand::Decision => MemoryCategory::Decision,
        MemoryCategoryCommand::Constraint => MemoryCategory::Constraint,
        MemoryCategoryCommand::Identity => MemoryCategory::Identity,
        MemoryCategoryCommand::Credential => MemoryCategory::Credential,
        MemoryCategoryCommand::Health => MemoryCategory::Health,
        MemoryCategoryCommand::Financial => MemoryCategory::Financial,
        MemoryCategoryCommand::ThirdPartyPrivate => MemoryCategory::ThirdPartyPrivate,
    }
}

const fn memory_category_response(value: MemoryCategory) -> MemoryCategoryCommand {
    match value {
        MemoryCategory::Preference => MemoryCategoryCommand::Preference,
        MemoryCategory::Fact => MemoryCategoryCommand::Fact,
        MemoryCategory::Goal => MemoryCategoryCommand::Goal,
        MemoryCategory::Decision => MemoryCategoryCommand::Decision,
        MemoryCategory::Constraint => MemoryCategoryCommand::Constraint,
        MemoryCategory::Identity => MemoryCategoryCommand::Identity,
        MemoryCategory::Credential => MemoryCategoryCommand::Credential,
        MemoryCategory::Health => MemoryCategoryCommand::Health,
        MemoryCategory::Financial => MemoryCategoryCommand::Financial,
        MemoryCategory::ThirdPartyPrivate => MemoryCategoryCommand::ThirdPartyPrivate,
    }
}

const fn memory_sensitivity(value: MemorySensitivityCommand) -> MemorySensitivity {
    match value {
        MemorySensitivityCommand::Public => MemorySensitivity::Public,
        MemorySensitivityCommand::Internal => MemorySensitivity::Internal,
        MemorySensitivityCommand::Private => MemorySensitivity::Private,
        MemorySensitivityCommand::Restricted => MemorySensitivity::Restricted,
    }
}

const fn memory_sensitivity_response(value: MemorySensitivity) -> MemorySensitivityCommand {
    match value {
        MemorySensitivity::Public => MemorySensitivityCommand::Public,
        MemorySensitivity::Internal => MemorySensitivityCommand::Internal,
        MemorySensitivity::Private => MemorySensitivityCommand::Private,
        MemorySensitivity::Restricted => MemorySensitivityCommand::Restricted,
    }
}

const fn memory_retention(value: MemoryRetentionCommand) -> MemoryRetention {
    match value {
        MemoryRetentionCommand::Session => MemoryRetention::Session,
        MemoryRetentionCommand::Standard => MemoryRetention::Standard,
        MemoryRetentionCommand::Pinned => MemoryRetention::Pinned,
        MemoryRetentionCommand::PolicyHold => MemoryRetention::PolicyHold,
    }
}

const fn memory_retention_response(value: MemoryRetention) -> MemoryRetentionCommand {
    match value {
        MemoryRetention::Session => MemoryRetentionCommand::Session,
        MemoryRetention::Standard => MemoryRetentionCommand::Standard,
        MemoryRetention::Pinned => MemoryRetentionCommand::Pinned,
        MemoryRetention::PolicyHold => MemoryRetentionCommand::PolicyHold,
    }
}

fn memory_authorization(
    value: Option<MemoryPromotionAuthorizationCommand>,
    ids: &impl IdGenerator,
) -> Option<MemoryPromotionAuthorization> {
    value.map(|value| match value {
        MemoryPromotionAuthorizationCommand::OwnerPolicy => {
            MemoryPromotionAuthorization::OwnerPolicy {
                policy_version: MEMORY_POLICY_VERSION.to_owned(),
            }
        }
        MemoryPromotionAuthorizationCommand::OwnerApproval => {
            MemoryPromotionAuthorization::Approval {
                approval_id: ids.generate_approval_id(),
            }
        }
    })
}

fn parse_task_status(value: &str) -> Result<TaskStatus, BackendError> {
    match value {
        "queued" => Ok(TaskStatus::Queued),
        "running" => Ok(TaskStatus::Running),
        "waiting" => Ok(TaskStatus::Waiting),
        "paused" => Ok(TaskStatus::Paused),
        "cancelling" => Ok(TaskStatus::Cancelling),
        "succeeded" => Ok(TaskStatus::Succeeded),
        "failed" => Ok(TaskStatus::Failed),
        "cancelled" => Ok(TaskStatus::Cancelled),
        _ => Err(BackendError::Internal),
    }
}

const fn validation_method_response(value: ValidationMethod) -> ValidationMethodResponse {
    match value {
        ValidationMethod::Deterministic => ValidationMethodResponse::Deterministic,
        ValidationMethod::FreshContextModel => ValidationMethodResponse::FreshContextModel,
        ValidationMethod::Waiver => ValidationMethodResponse::Waiver,
    }
}

const fn validation_outcome_response(value: ValidationOutcome) -> ValidationOutcomeResponse {
    match value {
        ValidationOutcome::Passed => ValidationOutcomeResponse::Passed,
        ValidationOutcome::NeedsRevision => ValidationOutcomeResponse::NeedsRevision,
        ValidationOutcome::Failed => ValidationOutcomeResponse::Failed,
        ValidationOutcome::Inconclusive => ValidationOutcomeResponse::Inconclusive,
        ValidationOutcome::Waived => ValidationOutcomeResponse::Waived,
    }
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, BackendError> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| BackendError::Internal)?;
    i64::try_from(duration.as_millis()).map_err(|_| BackendError::Internal)
}

fn map_session_error(error: SessionUseCaseError) -> BackendError {
    match error {
        SessionUseCaseError::Store(SessionStoreError::SessionNotFound) => BackendError::NotFound,
        SessionUseCaseError::Store(SessionStoreError::Unauthorized) => BackendError::Unauthorized,
        SessionUseCaseError::Store(
            SessionStoreError::IdempotencyConflict | SessionStoreError::Conflict,
        ) => BackendError::Conflict,
        SessionUseCaseError::Store(SessionStoreError::Backpressure) => BackendError::Busy,
        SessionUseCaseError::Store(SessionStoreError::Unavailable(_)) => BackendError::Unavailable,
        SessionUseCaseError::Store(SessionStoreError::InvariantViolation(_)) => {
            BackendError::Internal
        }
        other => BackendError::InvalidRequest(other.to_string()),
    }
}

fn map_timeline_error(error: &TimelineUseCaseError) -> BackendError {
    match error {
        TimelineUseCaseError::Store(TimelineStoreError::SessionNotFound) => BackendError::NotFound,
        TimelineUseCaseError::Store(TimelineStoreError::Unauthorized) => BackendError::Unauthorized,
        TimelineUseCaseError::Store(TimelineStoreError::Gap { earliest }) => {
            BackendError::TimelineGap {
                earliest_cursor: earliest.0,
            }
        }
        TimelineUseCaseError::Store(TimelineStoreError::CursorAhead) => {
            BackendError::TimelineCursorAhead
        }
        TimelineUseCaseError::Store(TimelineStoreError::Unavailable(_)) => {
            BackendError::Unavailable
        }
        TimelineUseCaseError::Store(TimelineStoreError::InvariantViolation(_)) => {
            BackendError::Internal
        }
        TimelineUseCaseError::InvalidPageSize => {
            BackendError::InvalidRequest("invalid timeline page size".to_owned())
        }
    }
}

fn map_agent_error(error: &AgentStoreError) -> BackendError {
    match error {
        AgentStoreError::NotFound => BackendError::NotFound,
        AgentStoreError::Conflict
        | AgentStoreError::StaleFence
        | AgentStoreError::Cancelled
        | AgentStoreError::BudgetExceeded(_) => BackendError::Conflict,
        AgentStoreError::Unavailable(_) => BackendError::Unavailable,
        AgentStoreError::InvariantViolation(_) => BackendError::Internal,
    }
}

fn map_effect_ledger_error(error: EffectLedgerStoreError) -> BackendError {
    match error {
        EffectLedgerStoreError::NotFound => BackendError::NotFound,
        EffectLedgerStoreError::SubjectMismatch
        | EffectLedgerStoreError::ApprovalExpired
        | EffectLedgerStoreError::ExpiryNotReached
        | EffectLedgerStoreError::Conflict => BackendError::Conflict,
        EffectLedgerStoreError::InvalidEvidence(message) => BackendError::InvalidRequest(message),
        EffectLedgerStoreError::Unavailable(_) => BackendError::Unavailable,
        EffectLedgerStoreError::InvariantViolation(_) => BackendError::Internal,
    }
}

fn map_artifact_evidence_error(error: &ArtifactEvidenceStoreError) -> BackendError {
    match error {
        ArtifactEvidenceStoreError::NotFound => BackendError::NotFound,
        ArtifactEvidenceStoreError::Unavailable(_) => BackendError::Unavailable,
        ArtifactEvidenceStoreError::InvariantViolation(_) => BackendError::Internal,
    }
}

fn map_artifact_blob_error(error: &ArtifactBlobStoreError) -> BackendError {
    match error {
        ArtifactBlobStoreError::Io { .. } => BackendError::Unavailable,
        ArtifactBlobStoreError::SizeLimitExceeded { .. }
        | ArtifactBlobStoreError::InvalidDescriptor { .. }
        | ArtifactBlobStoreError::NotFound { .. }
        | ArtifactBlobStoreError::IntegrityMismatch { .. }
        | ArtifactBlobStoreError::UnsafeFileType { .. } => BackendError::Internal,
    }
}

fn map_context_evidence_error(error: &ContextManifestEvidenceStoreError) -> BackendError {
    match error {
        ContextManifestEvidenceStoreError::NotFound => BackendError::NotFound,
        ContextManifestEvidenceStoreError::Unavailable(_) => BackendError::Unavailable,
        ContextManifestEvidenceStoreError::InvariantViolation(_) => BackendError::Internal,
    }
}

fn map_memory_error(error: MemoryStoreError) -> BackendError {
    match error {
        MemoryStoreError::NotFound => BackendError::NotFound,
        MemoryStoreError::Conflict => BackendError::Conflict,
        MemoryStoreError::PolicyDenied => {
            BackendError::InvalidRequest("memory promotion requires owner authorization".to_owned())
        }
        MemoryStoreError::InvalidContract(message) => BackendError::InvalidRequest(message),
        MemoryStoreError::IndexDegraded(_) | MemoryStoreError::Unavailable(_) => {
            BackendError::Unavailable
        }
        MemoryStoreError::InvariantViolation(_) => BackendError::Internal,
    }
}

fn map_compaction_error(error: CompactionStoreError) -> BackendError {
    match error {
        CompactionStoreError::NotFound => BackendError::NotFound,
        CompactionStoreError::Conflict => BackendError::Conflict,
        CompactionStoreError::InvalidSourceRange => {
            BackendError::InvalidRequest("compaction source range is invalid".to_owned())
        }
        CompactionStoreError::InvalidContract(message) => BackendError::InvalidRequest(message),
        CompactionStoreError::Unavailable(_) => BackendError::Unavailable,
        CompactionStoreError::InvariantViolation(_) => BackendError::Internal,
    }
}

fn map_extension_store_error(error: ExtensionStoreError) -> BackendError {
    match error {
        ExtensionStoreError::NotFound => BackendError::NotFound,
        ExtensionStoreError::Conflict => BackendError::Conflict,
        ExtensionStoreError::InvalidContract(message) => BackendError::InvalidRequest(message),
        ExtensionStoreError::Unavailable(_) => BackendError::Unavailable,
        ExtensionStoreError::InvariantViolation(_) => BackendError::Internal,
    }
}

fn map_extension_package_error(_error: ExtensionHostError) -> BackendError {
    BackendError::InvalidRequest("extension package path or digest identity is invalid".to_owned())
}

fn map_extension_host_boundary_error(error: &ExtensionHostError) -> BackendError {
    match error {
        ExtensionHostError::UnsupportedHost(_) => BackendError::Unavailable,
        ExtensionHostError::IdentityMismatch => BackendError::Conflict,
        _ => BackendError::InvalidRequest("extension health probe failed".to_owned()),
    }
}

fn map_webhook_store_error(error: WebhookChannelStoreError) -> BackendError {
    match error {
        WebhookChannelStoreError::NotFound => BackendError::NotFound,
        WebhookChannelStoreError::Revoked
        | WebhookChannelStoreError::Replay
        | WebhookChannelStoreError::Conflict => BackendError::Conflict,
        WebhookChannelStoreError::InvalidContract(message) => BackendError::InvalidRequest(message),
        WebhookChannelStoreError::Unavailable(_) => BackendError::Unavailable,
        WebhookChannelStoreError::InvariantViolation(_) => BackendError::Internal,
    }
}

fn map_channel_secret_error(error: &ChannelSecretStoreError) -> BackendError {
    match error {
        ChannelSecretStoreError::Conflict => BackendError::Conflict,
        ChannelSecretStoreError::Io { .. } => BackendError::Unavailable,
        ChannelSecretStoreError::InvalidSecret
        | ChannelSecretStoreError::NotFound
        | ChannelSecretStoreError::UnsafeStorage => BackendError::Internal,
    }
}

fn map_operational_store_error(error: OperationalStoreError) -> BackendError {
    match error {
        OperationalStoreError::NotFound => BackendError::NotFound,
        OperationalStoreError::Conflict => BackendError::Conflict,
        OperationalStoreError::InvalidContract(message) => BackendError::InvalidRequest(message),
        OperationalStoreError::Unavailable(_) => BackendError::Unavailable,
        OperationalStoreError::InvariantViolation(_) => BackendError::Internal,
    }
}

fn validated_export_selector(
    kind: ExportKindRequest,
    selector: Option<String>,
) -> Result<Option<String>, BackendError> {
    match (kind, selector) {
        (ExportKindRequest::Complete | ExportKindRequest::Audit, None) => Ok(None),
        (ExportKindRequest::Complete | ExportKindRequest::Audit, Some(_)) => {
            Err(BackendError::InvalidRequest(
                "complete and audit exports do not accept a selector".to_owned(),
            ))
        }
        (_, Some(value))
            if !value.is_empty()
                && value.len() <= 4_096
                && value.trim() == value
                && !value.chars().any(char::is_control) =>
        {
            Ok(Some(value))
        }
        _ => Err(BackendError::InvalidRequest(
            "task, artifact, and memory exports require one valid selector".to_owned(),
        )),
    }
}

fn audit_export_payload(
    backend: &RuntimeBackend,
    identity: AuthenticatedIdentity,
) -> Result<serde_json::Value, BackendError> {
    const PAGE_SIZE: usize = 1_000;
    const MAXIMUM_AUDIT_EVENTS: usize = 100_000;
    let ownership = parse_ownership(&identity)?;
    let session_ids = backend
        .lock()?
        .operational_session_ids(ownership)
        .map_err(map_operational_store_error)?;
    let mut events = BTreeMap::<u64, TimelineEvent>::new();
    for session_id in &session_ids {
        let mut after = None;
        loop {
            let page = backend.timeline_page(
                identity.clone(),
                session_id.to_string(),
                after,
                PAGE_SIZE,
            )?;
            let next_after = page.events.last().map(|event| event.cursor);
            for event in page.events {
                events.insert(event.cursor.0, event);
            }
            if events.len() > MAXIMUM_AUDIT_EVENTS {
                return Err(BackendError::InvalidRequest(
                    "audit export exceeds the bounded event limit".to_owned(),
                ));
            }
            if !page.has_more {
                break;
            }
            let Some(cursor) = next_after else {
                return Err(BackendError::Internal);
            };
            after = Some(cursor);
        }
    }
    Ok(serde_json::json!({
        "status": backend.admin_status(identity)?,
        "sessionIds": session_ids.into_iter().map(|id| id.to_string()).collect::<Vec<_>>(),
        "events": events.into_values().collect::<Vec<_>>(),
    }))
}

fn map_maintenance_error(error: &MaintenanceError) -> BackendError {
    match error {
        MaintenanceError::InvalidName
        | MaintenanceError::InvalidManifest
        | MaintenanceError::InvalidConfiguration
        | MaintenanceError::InvalidPassphrase
        | MaintenanceError::PassphraseRequired
        | MaintenanceError::UnexpectedPassphrase
        | MaintenanceError::InvalidSecretArchive
        | MaintenanceError::CryptographicFailure
        | MaintenanceError::UnsafePath(_)
        | MaintenanceError::Integrity(_)
        | MaintenanceError::Json(_) => {
            BackendError::InvalidRequest("backup or maintenance evidence is invalid".to_owned())
        }
        MaintenanceError::AlreadyExists(_) => BackendError::Conflict,
        MaintenanceError::Io(_)
        | MaintenanceError::Store(_)
        | MaintenanceError::MissingComponent(_) => BackendError::Unavailable,
        MaintenanceError::Overflow
        | MaintenanceError::InvalidTime
        | MaintenanceError::InvalidMigrationVersion
        | MaintenanceError::RandomUnavailable => BackendError::Internal,
    }
}

fn denied_sandbox_profile(profile: &str, detail: &str) -> SandboxProfileResponse {
    SandboxProfileResponse {
        profile: profile.to_owned(),
        status: SandboxProfileStatusResponse::Denied,
        detail: detail.to_owned(),
    }
}

fn provider_routing_check() -> Result<String, BackendError> {
    let policy = ProviderRoutingPolicy {
        required_input_modalities: BTreeSet::from(["text".to_owned()]),
        tool_calling: CapabilityRequirement::Required,
        structured_output: CapabilityRequirement::Required,
        required_reasoning_control: Some("none".to_owned()),
        allowed_residencies: BTreeSet::from(["local".to_owned(), "trusted".to_owned()]),
        locality: ProviderLocality::Any,
        maximum_input_microunits_per_million_tokens: 100,
        maximum_output_microunits_per_million_tokens: 100,
        maximum_latency_ms: 1_000,
        minimum_trust_tier: 5,
        preferred_provider_ids: vec!["doctor-primary".to_owned()],
        fallback: ProviderFallbackPolicy::SameOrHigherTrust,
    };
    let primary = provider_doctor_candidate("doctor-primary", "local", true, 7, 10);
    let fallback = provider_doctor_candidate("doctor-fallback", "trusted", false, 7, 20);
    let weaker = provider_doctor_candidate("doctor-weaker", "trusted", false, 6, 5);
    let plan = route_provider(&policy, [weaker, fallback.clone(), primary.clone()])
        .map_err(|_| BackendError::Internal)?;
    if plan.primary != primary || plan.fallbacks != [fallback] {
        return Err(BackendError::Internal);
    }
    Ok(
        "ok: explicit fallback retained equal trust and excluded the lower-trust provider"
            .to_owned(),
    )
}

fn provider_doctor_candidate(
    provider_id: &str,
    residency: &str,
    local: bool,
    trust_tier: u8,
    latency_ms: u64,
) -> ProviderRouteCandidate {
    ProviderRouteCandidate {
        capabilities: ProviderCapabilities {
            contract_version: "mealy.provider.v1".to_owned(),
            provider_id: provider_id.to_owned(),
            model_id: "doctor-model".to_owned(),
            input_modalities: BTreeSet::from(["text".to_owned()]),
            context_tokens: 8_192,
            maximum_output_tokens: 1_024,
            tool_calling: true,
            structured_output: true,
            reasoning_controls: BTreeSet::from(["none".to_owned()]),
            streaming: false,
            residency: residency.to_owned(),
            local,
            pricing: ProviderPricing::default(),
            maximum_concurrent_requests: 1,
            requests_per_minute: 60,
            retry_after_hints: true,
        },
        available: true,
        estimated_latency_ms: latency_ms,
        trust_tier,
    }
}

#[cfg(unix)]
fn private_home_permissions(home: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(home).is_ok_and(|metadata| {
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode().trailing_zeros() >= 6
    })
}

#[cfg(not(unix))]
fn private_home_permissions(home: &std::path::Path) -> bool {
    std::fs::symlink_metadata(home)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
}

#[cfg(test)]
mod tests {
    use super::{
        ApiBackend, AuthenticatedIdentity, BackendError, DrainController, KeyedConcurrencyLimiter,
        RuntimeBackend, RuntimeOperationalConfig, map_artifact_blob_error,
    };
    use mealy_application::{
        ArtifactBlobStore, ArtifactBlobStoreError, estimate_tokens, sha256_digest,
    };
    use mealy_domain::{
        ArtifactId, ChannelBindingId, ContextEpochId, ContextItemId, ContextManifestId,
        CorrelationId, EventId, InboxEntryId, OutboxId, PrincipalId, RunId, SessionId, TaskId,
        TurnId,
    };
    use mealy_infrastructure::{FileArtifactBlobStore, FileChannelSecretStore, SqliteStore};
    use mealy_protocol::{
        ContextItemDisposition, CorrectMemoryRequest, MemoryCategoryCommand,
        MemoryLifecycleRequest, MemoryPromotionAuthorizationCommand, MemoryRetentionCommand,
        MemorySensitivityCommand, MemorySourceCommand, MemoryStatusResponse, PromoteMemoryRequest,
        ProposeMemoryRequest,
    };
    use rusqlite::params;
    use serde_json::json;
    use std::{
        fs, io,
        path::PathBuf,
        sync::{Arc, Mutex},
    };
    use tempfile::TempDir;

    const CONTENT: &[u8] = b"verified durable artifact";

    #[test]
    fn keyed_extension_capacity_is_released_by_scope_guard() {
        let limiter = KeyedConcurrencyLimiter::new(1);
        let first = limiter
            .try_acquire("extension-a".to_owned())
            .expect("first extension slot");
        assert!(limiter.try_acquire("extension-a".to_owned()).is_none());
        assert!(limiter.try_acquire("extension-b".to_owned()).is_some());
        drop(first);
        assert!(limiter.try_acquire("extension-a".to_owned()).is_some());
    }

    #[test]
    fn runtime_backend_returns_authorized_metadata_and_verified_content() {
        let fixture = Fixture::new();

        let metadata = fixture
            .backend
            .artifact_metadata(fixture.identity.clone(), fixture.artifact_id.to_string())
            .expect("authorized metadata");
        assert_eq!(metadata.artifact_id, fixture.artifact_id.to_string());
        assert_eq!(metadata.digest, sha256_digest(CONTENT));
        assert_eq!(metadata.media_type, "text/plain");
        assert_eq!(metadata.size_bytes, u64::try_from(CONTENT.len()).unwrap());

        let content = fixture
            .backend
            .artifact_content(fixture.identity.clone(), fixture.artifact_id.to_string())
            .expect("authorized verified content");
        assert_eq!(content.media_type, "text/plain");
        assert_eq!(content.bytes, CONTENT);
    }

    #[test]
    fn runtime_backend_hides_wrong_owners_and_fails_closed_on_corruption() {
        let fixture = Fixture::new();
        let wrong_principal = AuthenticatedIdentity {
            principal_id: PrincipalId::new().to_string(),
            channel_binding_id: fixture.identity.channel_binding_id.clone(),
        };
        let wrong_channel = AuthenticatedIdentity {
            principal_id: fixture.identity.principal_id.clone(),
            channel_binding_id: ChannelBindingId::new().to_string(),
        };
        for identity in [wrong_principal, wrong_channel] {
            assert_eq!(
                fixture
                    .backend
                    .artifact_metadata(identity.clone(), fixture.artifact_id.to_string()),
                Err(BackendError::NotFound)
            );
            assert_eq!(
                fixture
                    .backend
                    .artifact_content(identity, fixture.artifact_id.to_string()),
                Err(BackendError::NotFound)
            );
        }

        fs::write(&fixture.blob_path, b"tampered content").expect("tamper artifact blob");
        assert_eq!(
            fixture
                .backend
                .artifact_content(fixture.identity, fixture.artifact_id.to_string()),
            Err(BackendError::Internal)
        );
    }

    #[test]
    fn artifact_storage_errors_have_safe_public_classifications() {
        let unavailable = ArtifactBlobStoreError::Io {
            operation: "read artifact",
            source: io::Error::other("private storage detail"),
        };
        assert_eq!(
            map_artifact_blob_error(&unavailable),
            BackendError::Unavailable
        );

        let corrupt = ArtifactBlobStoreError::IntegrityMismatch {
            expected_digest: "a".repeat(64),
            actual_digest: "b".repeat(64),
            expected_size_bytes: 1,
            actual_size_bytes: 2,
        };
        assert_eq!(map_artifact_blob_error(&corrupt), BackendError::Internal);
    }

    #[test]
    fn runtime_backend_authorizes_context_and_withholds_unselected_content() {
        let fixture = Fixture::new();
        let evidence = fixture
            .backend
            .context_manifest(fixture.identity.clone(), fixture.manifest_id.to_string())
            .expect("authorized context evidence");
        assert_eq!(evidence.items.len(), 3);
        assert_eq!(
            evidence.items[0].disposition,
            ContextItemDisposition::Included
        );
        assert_eq!(evidence.items[0].content.as_deref(), Some("baseline"));
        assert_eq!(
            evidence.items[1].disposition,
            ContextItemDisposition::Excluded
        );
        assert!(evidence.items[1].content.is_none());
        assert_eq!(
            evidence.items[2].disposition,
            ContextItemDisposition::Redacted
        );
        assert!(evidence.items[2].content.is_none());

        let wrong_owners = [
            AuthenticatedIdentity {
                principal_id: PrincipalId::new().to_string(),
                channel_binding_id: fixture.identity.channel_binding_id.clone(),
            },
            AuthenticatedIdentity {
                principal_id: fixture.identity.principal_id.clone(),
                channel_binding_id: ChannelBindingId::new().to_string(),
            },
        ];
        for identity in wrong_owners {
            assert_eq!(
                fixture
                    .backend
                    .context_manifest(identity, fixture.manifest_id.to_string()),
                Err(BackendError::NotFound)
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn runtime_backend_exposes_the_governed_memory_lifecycle_and_search() {
        let fixture = Fixture::new();
        let proposed = fixture
            .backend
            .propose_memory(
                fixture.identity.clone(),
                ProposeMemoryRequest {
                    api_version: mealy_protocol::API_VERSION.to_owned(),
                    workspace_identity: "workspace".to_owned(),
                    content: "The release window is Wednesday".to_owned(),
                    category: MemoryCategoryCommand::Fact,
                    confidence_basis_points: 8_000,
                    sensitivity: MemorySensitivityCommand::Internal,
                    retention: MemoryRetentionCommand::Standard,
                    sources: vec![MemorySourceCommand {
                        locator: "event://release-window".to_owned(),
                        digest: "a".repeat(64),
                    }],
                },
            )
            .expect("propose memory through backend");
        assert_eq!(proposed.status, MemoryStatusResponse::Proposed);
        let rejected_proposal = fixture
            .backend
            .propose_memory(
                fixture.identity.clone(),
                ProposeMemoryRequest {
                    api_version: mealy_protocol::API_VERSION.to_owned(),
                    workspace_identity: "workspace".to_owned(),
                    content: "An unverified release rumor".to_owned(),
                    category: MemoryCategoryCommand::Fact,
                    confidence_basis_points: 2_000,
                    sensitivity: MemorySensitivityCommand::Internal,
                    retention: MemoryRetentionCommand::Standard,
                    sources: vec![MemorySourceCommand {
                        locator: "event://unverified-rumor".to_owned(),
                        digest: "d".repeat(64),
                    }],
                },
            )
            .expect("propose memory to reject");
        let rejected = fixture
            .backend
            .reject_memory(
                fixture.identity.clone(),
                rejected_proposal.memory_id.clone(),
                MemoryLifecycleRequest {
                    api_version: mealy_protocol::API_VERSION.to_owned(),
                    expected_revision: rejected_proposal.revision,
                },
            )
            .expect("reject proposed memory through backend");
        assert_eq!(rejected.status, MemoryStatusResponse::Rejected);
        assert_eq!(rejected.revision, 1);
        assert_eq!(rejected.revisions[0].status, MemoryStatusResponse::Rejected);
        assert_eq!(
            fixture.backend.promote_memory(
                fixture.identity.clone(),
                rejected.memory_id,
                PromoteMemoryRequest {
                    api_version: mealy_protocol::API_VERSION.to_owned(),
                    revision_id: rejected.revisions[0].revision_id.clone(),
                    authorization: None,
                },
            ),
            Err(BackendError::Conflict)
        );
        let active = fixture
            .backend
            .promote_memory(
                fixture.identity.clone(),
                proposed.memory_id.clone(),
                PromoteMemoryRequest {
                    api_version: mealy_protocol::API_VERSION.to_owned(),
                    revision_id: proposed.revisions[0].revision_id.clone(),
                    authorization: None,
                },
            )
            .expect("activate memory through backend");
        assert_eq!(active.status, MemoryStatusResponse::Active);
        let search = fixture
            .backend
            .search_memories(
                fixture.identity.clone(),
                "workspace".to_owned(),
                "release Wednesday".to_owned(),
                MemorySensitivityCommand::Private,
                10,
            )
            .expect("search memory through backend");
        assert_eq!(search.hits.len(), 1);
        assert_eq!(search.hits[0].memory.memory_id, active.memory_id);

        let corrected = fixture
            .backend
            .correct_memory(
                fixture.identity.clone(),
                active.memory_id.clone(),
                CorrectMemoryRequest {
                    api_version: mealy_protocol::API_VERSION.to_owned(),
                    expected_revision: active.revision,
                    content: "The release window is Thursday".to_owned(),
                    confidence_basis_points: 9_000,
                    sensitivity: MemorySensitivityCommand::Internal,
                    retention: MemoryRetentionCommand::Standard,
                    sources: vec![MemorySourceCommand {
                        locator: "event://release-window-correction".to_owned(),
                        digest: "b".repeat(64),
                    }],
                    authorization: None,
                },
            )
            .expect("correct memory through backend");
        assert_eq!(corrected.revisions.len(), 2);
        assert_eq!(corrected.revision, 2);

        let wrong_owner = AuthenticatedIdentity {
            principal_id: PrincipalId::new().to_string(),
            channel_binding_id: fixture.identity.channel_binding_id.clone(),
        };
        assert_eq!(
            fixture
                .backend
                .memory(wrong_owner, "workspace".to_owned(), active.memory_id,),
            Err(BackendError::NotFound)
        );

        let sensitive = fixture
            .backend
            .propose_memory(
                fixture.identity.clone(),
                ProposeMemoryRequest {
                    api_version: mealy_protocol::API_VERSION.to_owned(),
                    workspace_identity: "workspace".to_owned(),
                    content: "Owner-authorized health accommodation".to_owned(),
                    category: MemoryCategoryCommand::Health,
                    confidence_basis_points: 8_000,
                    sensitivity: MemorySensitivityCommand::Restricted,
                    retention: MemoryRetentionCommand::Standard,
                    sources: vec![MemorySourceCommand {
                        locator: "event://health".to_owned(),
                        digest: "c".repeat(64),
                    }],
                },
            )
            .expect("propose sensitive memory");
        assert!(
            fixture
                .backend
                .promote_memory(
                    fixture.identity.clone(),
                    sensitive.memory_id.clone(),
                    PromoteMemoryRequest {
                        api_version: mealy_protocol::API_VERSION.to_owned(),
                        revision_id: sensitive.revisions[0].revision_id.clone(),
                        authorization: None,
                    },
                )
                .is_err()
        );
        assert_eq!(
            fixture
                .backend
                .promote_memory(
                    fixture.identity,
                    sensitive.memory_id,
                    PromoteMemoryRequest {
                        api_version: mealy_protocol::API_VERSION.to_owned(),
                        revision_id: sensitive.revisions[0].revision_id.clone(),
                        authorization: Some(MemoryPromotionAuthorizationCommand::OwnerApproval),
                    },
                )
                .expect("explicit owner approval")
                .status,
            MemoryStatusResponse::Active
        );
    }

    struct Fixture {
        _home: TempDir,
        backend: RuntimeBackend,
        identity: AuthenticatedIdentity,
        artifact_id: ArtifactId,
        manifest_id: ContextManifestId,
        blob_path: PathBuf,
    }

    impl Fixture {
        #[allow(clippy::too_many_lines)]
        fn new() -> Self {
            let home = tempfile::tempdir().expect("temporary daemon home");
            let database_path = home.path().join("mealy.sqlite3");
            let store = SqliteStore::open(&database_path, 0).expect("open store");
            let artifacts = Arc::new(
                FileArtifactBlobStore::new(home.path().join("artifacts"), 1024)
                    .expect("open artifact store"),
            );
            let blob = artifacts.commit(CONTENT).expect("commit artifact content");
            let principal_id = PrincipalId::new();
            let channel_binding_id = ChannelBindingId::new();
            let session_id = SessionId::new();
            let artifact_id = ArtifactId::new();
            let access_policy_json = json!({
                "principalId": principal_id,
                "sessionId": session_id,
            })
            .to_string();
            let access_policy_digest = sha256_digest(access_policy_json.as_bytes());
            let connection = rusqlite::Connection::open(&database_path).expect("open seed store");
            connection
                .pragma_update(None, "foreign_keys", true)
                .expect("enable seed foreign keys");
            connection
                .execute(
                    "INSERT INTO session(\
                        id, principal_id, channel_binding_id, created_at_ms, updated_at_ms\
                     ) VALUES (?1, ?2, ?3, 0, 0)",
                    params![
                        session_id.to_string(),
                        principal_id.to_string(),
                        channel_binding_id.to_string(),
                    ],
                )
                .expect("seed session");
            connection
                .execute(
                    "INSERT INTO artifact_blob(\
                        algorithm, digest, size_bytes, relative_path, committed_at_ms\
                     ) VALUES (?1, ?2, ?3, ?4, 10)",
                    params![
                        blob.algorithm,
                        blob.digest,
                        i64::try_from(blob.size_bytes).expect("blob size fits SQLite"),
                        blob.relative_path,
                    ],
                )
                .expect("seed artifact blob");
            connection
                .execute(
                    "INSERT INTO artifact(\
                        id, blob_algorithm, blob_digest, principal_id, session_id, media_type, \
                        origin_kind, origin_id, producer_kind, producer_id, sensitivity, \
                        retention_class, access_policy_json, access_policy_digest, created_at_ms\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, 'text/plain', 'tool_call', 'tool-1', \
                               'builtin', 'read_text', 'private', 'task_history', ?6, ?7, 20)",
                    params![
                        artifact_id.to_string(),
                        blob.algorithm,
                        blob.digest,
                        principal_id.to_string(),
                        session_id.to_string(),
                        access_policy_json,
                        access_policy_digest,
                    ],
                )
                .expect("seed artifact metadata");
            let manifest_id = seed_context_manifest(&connection, session_id);
            drop(connection);
            let blob_path = home.path().join("artifacts").join(&blob.relative_path);
            let channel_secrets = Arc::new(
                FileChannelSecretStore::new(home.path().join("channel-secrets"))
                    .expect("open channel secret broker"),
            );
            let (drain_sender, _drain_receiver) = tokio::sync::watch::channel(false);
            let drain = Arc::new(DrainController::new(
                drain_sender,
                CorrelationId::new(),
                10_000,
            ));
            let backend_home = home.path().to_owned();
            Self {
                _home: home,
                backend: RuntimeBackend::new(
                    Arc::new(Mutex::new(store)),
                    artifacts,
                    channel_secrets,
                    RuntimeOperationalConfig {
                        home: backend_home,
                        artifact_gc_minimum_age_hours: 24,
                        maximum_pending_inputs_per_session: 1_024,
                        maximum_extension_invocations: 1,
                        sandbox_available: false,
                        safe_mode: false,
                    },
                    drain,
                ),
                identity: AuthenticatedIdentity {
                    principal_id: principal_id.to_string(),
                    channel_binding_id: channel_binding_id.to_string(),
                },
                artifact_id,
                manifest_id,
                blob_path,
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn seed_context_manifest(
        connection: &rusqlite::Connection,
        session_id: SessionId,
    ) -> ContextManifestId {
        let inbox_id = InboxEntryId::new();
        let task_id = TaskId::new();
        let run_id = RunId::new();
        let turn_id = TurnId::new();
        let epoch_id = ContextEpochId::new();
        let manifest_id = ContextManifestId::new();
        let correlation_id = CorrelationId::new();
        connection
            .execute(
                "INSERT INTO session_inbox(\
                    inbox_entry_id, session_id, sequence, dedupe_key, delivery_mode, content, \
                    admission_event_id, acknowledgement_outbox_id, correlation_id, accepted_at_ms\
                 ) VALUES (?1, ?2, 1, 'context-delivery', 'queue', 'hello', ?3, ?4, ?5, 0)",
                params![
                    inbox_id.to_string(),
                    session_id.to_string(),
                    EventId::new().to_string(),
                    OutboxId::new().to_string(),
                    correlation_id.to_string(),
                ],
            )
            .expect("seed context inbox");
        connection
            .execute(
                "INSERT INTO task(id, status, revision, validation_required) \
                 VALUES (?1, 'running', 0, 0)",
                [task_id.to_string()],
            )
            .expect("seed context task");
        connection
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
            .expect("seed context run");
        connection
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
            .expect("seed context turn");
        let baseline_digest = sha256_digest(b"baseline");
        connection
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
            .expect("seed context epoch");
        connection
            .execute(
                "UPDATE session SET current_context_epoch_id = ?1 WHERE id = ?2",
                params![epoch_id.to_string(), session_id.to_string()],
            )
            .expect("pin session context epoch");
        connection
            .execute(
                "UPDATE turn SET context_epoch_id = ?1 WHERE id = ?2",
                params![epoch_id.to_string(), turn_id.to_string()],
            )
            .expect("pin turn context epoch");
        let baseline_tokens = estimate_tokens("baseline");
        connection
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
            .expect("seed context manifest");
        let items = [
            (
                0_i64,
                "included",
                "baseline",
                "baseline://v1",
                Some("baseline"),
            ),
            (1, "excluded", "user", "inbox://entry", None),
            (2, "redacted", "memory", "memory://private", None),
        ];
        for (ordinal, disposition, source_type, source_locator, content) in items {
            let digest_source = content.unwrap_or("withheld content");
            let digest = sha256_digest(digest_source.as_bytes());
            connection
                .execute(
                    "INSERT INTO context_manifest_item(\
                        manifest_id, ordinal, item_id, disposition, source_type, source_locator, \
                        source_content_digest, rendered_content_digest, inclusion_reason, \
                        sensitivity, token_estimate, transformation, policy_decision, content_text\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 'fixture selection', \
                               'private', ?8, 'identity', 'fixture policy', ?9)",
                    params![
                        manifest_id.to_string(),
                        ordinal,
                        ContextItemId::new().to_string(),
                        disposition,
                        source_type,
                        source_locator,
                        digest,
                        if disposition == "included" {
                            i64::try_from(baseline_tokens).expect("token estimate fits SQLite")
                        } else {
                            10
                        },
                        content,
                    ],
                )
                .expect("seed context item");
        }
        manifest_id
    }
}
