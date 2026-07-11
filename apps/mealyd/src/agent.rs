use crate::effect_runtime::PhaseThreeRuntime;
use mealy_application::{
    AgentArtifactCommit, AgentEffectStore, AgentExecutionStore, AgentNextAction,
    ApprovalRequestDraft, ArtifactBlobStore, ArtifactEvidenceStore, CancellationProbe,
    CapabilityRequirement, Clock, ContextEpoch, DispatchModelAttemptCommit, DispatchReadToolCommit,
    EffectAttemptOutcome, EffectLedgerStore, EffectLedgerStoreError, ExecutorError,
    ExecutorTerminal, ExpireApprovalCommit, FinalMessageCommit, FixtureWriteDispatch, IdGenerator,
    LeaseClaimOutcome, LeaseConcurrencyLimits, LeaseLimits, MarkEffectAttemptRunningCommit,
    MessageRole, ModelProvider, ModelUsage, OwnershipContext, ParkAgentEffectRunCommit,
    PolicyDecision, PolicyRequest, PrepareEffectAttemptCommit, ProviderCapabilities, ProviderError,
    ProviderErrorClass, ProviderFallbackPolicy, ProviderLocality, ProviderOutput, ProviderPricing,
    ProviderRequest, ProviderResponse, ProviderRouteCandidate, ProviderRoutingPolicy,
    ProviderToolDefinition, ReadOnlyTool, ReadToolOutput, RecordAgentEffectObservationCommit,
    RecordAgentEffectProposalCommit, RecordEffectAttemptOutcomeCommit, RecordEffectProposalCommit,
    RecordModelResultCommit, RecordReadToolResultCommit, RecordValidationCommit,
    ResumeAgentEffectRunCommit, RunCompletionStatus, VALIDATION_POLICY_VERSION,
    ValidationContextDraft, ValidationStore, bounded_deadline,
    build_fixture_write_executor_request, canonical_arguments_digest,
    claim_next_work_with_concurrency, compile_context, complete_agent_run, complete_run,
    estimate_tokens, evaluate_fixture_write_policy, fixture_write_approval_subject,
    heartbeat_lease, normalize_fixture_write_file_arguments, route_provider, sha256_digest,
    validate_fixture_read_arguments,
};
use mealy_domain::{
    CapabilityGrant, EffectClass, EffectStatus, LeaseFence, PolicyProfile, RiskClass,
    ValidationMethod, ValidationOutcome, WorkerId,
};
use mealy_infrastructure::{
    FileArtifactBlobStore, FixtureReadTool, FixtureResource, SqliteStore, SystemClock,
    SystemIdGenerator,
};
use std::{
    collections::BTreeSet,
    error::Error,
    fmt::Write as _,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

const LEASE_TTL: Duration = Duration::from_secs(90);
const MAXIMUM_LOOP_STEPS: usize = 16;
const PROVIDER_OUTPUT_TOKENS: u64 = 512;
const PROVIDER_OUTPUT_BYTES_RESERVATION: u64 = 64 * 1024;
const PROVIDER_COST_RESERVATION: u64 = 1_000;
static TOOL_IN_FLIGHT: AtomicU64 = AtomicU64::new(0);

/// Effective worker-side scheduling and resource limits for one driver iteration.
#[derive(Clone, Copy, Debug)]
pub struct AgentDriverPolicy {
    boundary_delay: Duration,
    lease_concurrency_limits: LeaseConcurrencyLimits,
    maximum_resource_class_invocations: u32,
}

impl AgentDriverPolicy {
    /// Creates one validated daemon-configured worker policy.
    #[must_use]
    pub const fn new(
        boundary_delay: Duration,
        lease_concurrency_limits: LeaseConcurrencyLimits,
        maximum_resource_class_invocations: u32,
    ) -> Self {
        Self {
            boundary_delay,
            lease_concurrency_limits,
            maximum_resource_class_invocations,
        }
    }
}

struct InFlightGuard<'a> {
    count: &'a AtomicU64,
}

impl<'a> InFlightGuard<'a> {
    fn acquire(count: &'a AtomicU64, maximum: u64) -> Option<Self> {
        count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < maximum).then_some(current + 1)
            })
            .ok()
            .map(|_| Self { count })
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Release);
    }
}

/// Builds the fixed fixture-only read tool used by the Phase 2 vertical proof.
///
/// # Errors
///
/// Returns an error if the bounded fixture descriptor cannot be constructed.
pub fn phase_two_read_tool() -> Result<FixtureReadTool, Box<dyn Error + Send + Sync>> {
    let mut report = String::new();
    for index in 0..256 {
        writeln!(
            &mut report,
            "Phase 2 fixture row {index:03}: durable model, tool, artifact, and replay evidence."
        )?;
    }
    Ok(FixtureReadTool::new(
        [(
            "fixture://phase2/report".to_owned(),
            FixtureResource::new("text/plain", report.into_bytes()),
        )],
        4 * 1024 * 1024,
    )?)
}

/// Deterministic daemon-local provider for the Phase 2 proof.
#[derive(Debug)]
pub struct BuiltinPhaseTwoProvider {
    invocations: AtomicU64,
    in_flight: AtomicU64,
    maximum_concurrent_requests: u32,
    requests_per_minute: u32,
    rate_window: Mutex<ProviderRateWindow>,
    delay: Duration,
}

#[derive(Debug)]
struct ProviderRateWindow {
    minute: u64,
    requests: u32,
}

impl BuiltinPhaseTwoProvider {
    /// Creates the fixed provider with an optional bounded test delay.
    #[must_use]
    pub const fn new(
        delay: Duration,
        maximum_concurrent_requests: u32,
        requests_per_minute: u32,
    ) -> Self {
        Self {
            invocations: AtomicU64::new(0),
            in_flight: AtomicU64::new(0),
            maximum_concurrent_requests,
            requests_per_minute,
            rate_window: Mutex::new(ProviderRateWindow {
                minute: 0,
                requests: 0,
            }),
            delay,
        }
    }

    /// Number of actual provider-port calls in this daemon process.
    #[must_use]
    pub fn invocation_count(&self) -> u64 {
        self.invocations.load(Ordering::SeqCst)
    }

    fn reserve_rate_capacity(&self) -> bool {
        let Ok(elapsed) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) else {
            return false;
        };
        let minute = elapsed.as_secs() / 60;
        let Ok(mut window) = self.rate_window.lock() else {
            return false;
        };
        if window.minute != minute {
            window.minute = minute;
            window.requests = 0;
        }
        if window.requests >= self.requests_per_minute {
            return false;
        }
        window.requests += 1;
        true
    }
}

impl Default for BuiltinPhaseTwoProvider {
    fn default() -> Self {
        Self::new(Duration::ZERO, 1, 600)
    }
}

impl ModelProvider for BuiltinPhaseTwoProvider {
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            contract_version: "mealy.provider.v1".to_owned(),
            provider_id: "fake.builtin.phase2".to_owned(),
            model_id: "fake-read-loop-v1".to_owned(),
            input_modalities: BTreeSet::from(["text".to_owned()]),
            context_tokens: 32_768,
            maximum_output_tokens: PROVIDER_OUTPUT_TOKENS,
            tool_calling: true,
            structured_output: true,
            reasoning_controls: BTreeSet::from(["none".to_owned()]),
            streaming: false,
            residency: "local-fixture".to_owned(),
            local: true,
            pricing: ProviderPricing::default(),
            maximum_concurrent_requests: u64::from(self.maximum_concurrent_requests),
            requests_per_minute: u64::from(self.requests_per_minute),
            retry_after_hints: false,
        }
    }

    fn complete(
        &self,
        request: &ProviderRequest,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ProviderOutput, ProviderError> {
        let Some(_in_flight) =
            InFlightGuard::acquire(&self.in_flight, u64::from(self.maximum_concurrent_requests))
        else {
            return Err(ProviderError {
                class: ProviderErrorClass::Unavailable,
                message: "a previous provider dispatch is still stopping".to_owned(),
                retryable: true,
            });
        };
        if !self.reserve_rate_capacity() {
            return Err(ProviderError {
                class: ProviderErrorClass::RateLimited,
                message: "configured provider request-rate ceiling is exhausted".to_owned(),
                retryable: true,
            });
        }
        self.invocations.fetch_add(1, Ordering::SeqCst);
        if cancellation.is_cancelled() {
            return Err(ProviderError {
                class: ProviderErrorClass::Cancelled,
                message: "cancellation observed before fake provider dispatch".to_owned(),
                retryable: false,
            });
        }
        let delay_started = std::time::Instant::now();
        while delay_started.elapsed() < self.delay {
            if cancellation.is_cancelled() {
                return Err(ProviderError {
                    class: ProviderErrorClass::Cancelled,
                    message: "cancellation observed during fake provider dispatch".to_owned(),
                    retryable: false,
                });
            }
            std::thread::sleep(
                self.delay
                    .saturating_sub(delay_started.elapsed())
                    .min(Duration::from_millis(10)),
            );
        }
        let input_tokens = request
            .messages
            .iter()
            .map(|message| estimate_tokens(&message.content))
            .sum::<u64>();
        let response = if let Some(observation) = request
            .messages
            .iter()
            .rev()
            .find(|message| message.role == MessageRole::Tool)
        {
            final_from_tool_observation(observation)
        } else if let Some(arguments) = fixture_write_arguments(request) {
            ProviderResponse::ToolCall {
                tool_id: mealy_application::FIXTURE_WRITE_FILE_TOOL_ID.to_owned(),
                arguments,
            }
        } else {
            ProviderResponse::ToolCall {
                tool_id: "fixture.read".to_owned(),
                arguments: serde_json::json!({"resourceId": "fixture://phase2/report"}),
            }
        };
        let output_tokens = match &response {
            ProviderResponse::Final { text } => estimate_tokens(text).min(PROVIDER_OUTPUT_TOKENS),
            ProviderResponse::ToolCall { .. } => 8,
        };
        Ok(ProviderOutput {
            response,
            finish_reason: "stop".to_owned(),
            usage: ModelUsage {
                input_tokens,
                output_tokens,
                total_tokens: input_tokens.saturating_add(output_tokens),
                cost_microunits: 1,
            },
            provider_request_id: Some(format!("fake:{}", request.attempt_id)),
        })
    }
}

fn final_from_tool_observation(
    observation: &mealy_application::NormalizedMessage,
) -> ProviderResponse {
    if let Some(text) = serde_json::from_str::<serde_json::Value>(&observation.content)
        .ok()
        .and_then(|value| {
            (value
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                == Some(mealy_application::AGENT_EFFECT_OBSERVATION_CONTRACT_VERSION))
            .then(|| {
                let status = value
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                format!(
                    "Fixture write reached durable effect state {status}; recorded observation \
                     sha256:{}",
                    sha256_digest(observation.content.as_bytes())
                )
            })
        })
    {
        return ProviderResponse::Final { text };
    }
    let mut lines = observation.content.lines();
    let evidence_header = lines.next().unwrap_or("recorded tool evidence");
    let rows = lines
        .clone()
        .filter(|line| line.starts_with("Phase 2 fixture row "))
        .count();
    let first_row = lines
        .find(|line| line.starts_with("Phase 2 fixture row "))
        .unwrap_or("no fixture row");
    ProviderResponse::Final {
        text: format!(
            "Fixture read completed with durable evidence: {evidence_header}; observed {rows} \
             fixture rows; first row: {first_row}; rendered sha256:{}",
            sha256_digest(observation.content.as_bytes())
        ),
    }
}

fn fixture_write_arguments(request: &ProviderRequest) -> Option<serde_json::Value> {
    let declared = request
        .tools
        .iter()
        .any(|tool| tool.tool_id == mealy_application::FIXTURE_WRITE_FILE_TOOL_ID);
    if !declared {
        return None;
    }
    request.messages.iter().find_map(|message| {
        (message.role == MessageRole::User)
            .then(|| {
                message
                    .content
                    .strip_prefix(mealy_application::FIXTURE_WRITE_INPUT_PREFIX)
            })
            .flatten()
            .and_then(|json| serde_json::from_str(json).ok())
    })
}

struct DurableCancellationProbe {
    store: Arc<Mutex<SqliteStore>>,
    run_id: mealy_domain::RunId,
    local_timeout: Arc<AtomicBool>,
}

impl CancellationProbe for DurableCancellationProbe {
    fn is_cancelled(&self) -> bool {
        self.local_timeout.load(Ordering::Acquire)
            || self.store.lock().map_or(true, |store| {
                store
                    .agent_run_cancellation_requested(self.run_id)
                    .unwrap_or(true)
            })
    }
}

/// Claims and executes at most one runnable agent run.
///
/// The function holds the shared `SQLite` mutex only for a single durable transition at a time.
/// Provider, tool, and artifact I/O all run outside that mutex.
pub fn drive_one_agent_run(
    store: &Arc<Mutex<SqliteStore>>,
    worker_id: WorkerId,
    provider: &Arc<BuiltinPhaseTwoProvider>,
    tool: &Arc<FixtureReadTool>,
    effect_runtime: Option<&PhaseThreeRuntime>,
    artifacts: &FileArtifactBlobStore,
    policy: AgentDriverPolicy,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    resume_ready_effect_runs(store)?;
    let claim = {
        let mut guard = store.lock().map_err(|_| "agent store lock is poisoned")?;
        claim_next_work_with_concurrency(
            &mut *guard,
            &SystemClock,
            &SystemIdGenerator,
            worker_id,
            LEASE_TTL,
            LeaseLimits::default(),
            policy.lease_concurrency_limits,
        )?
    };
    let LeaseClaimOutcome::Claimed(receipt) = claim else {
        return Ok(false);
    };
    let fence = receipt.lease.fence();
    let trace = store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .load_agent_run(fence, SystemClock.now())?;
    let trace_span = tracing::info_span!(
        "agent_run",
        task_id = %trace.task_id,
        run_id = %trace.run_id,
        turn_id = %trace.turn_id,
        session_id = %trace.session_id,
        correlation_id = %trace.correlation_id,
        lease_id = %fence.lease_id(),
        worker_id = %worker_id,
    );
    let _entered = trace_span.enter();
    tracing::debug!(next_action = ?trace.next_action, "claimed durable agent run");
    if let Err(error) = execute_claimed_run(
        store,
        fence,
        provider,
        tool,
        effect_runtime,
        artifacts,
        policy,
    ) {
        tracing::warn!(%error, "durable agent run failed");
        let summary = format!("agent loop failed: {error}");
        let bounded = summary.chars().take(4_096).collect::<String>();
        if let Ok(mut guard) = store.lock() {
            let status = if guard
                .agent_run_cancellation_requested(fence.run_id())
                .unwrap_or(false)
            {
                RunCompletionStatus::Cancelled
            } else {
                RunCompletionStatus::Failed
            };
            complete_run(
                &mut *guard,
                &SystemClock,
                &SystemIdGenerator,
                fence,
                status,
                bounded,
            )
            .map_err(|completion_error| {
                std::io::Error::other(format!(
                    "agent loop error `{error}` could not commit its terminal boundary: \
                     {completion_error}"
                ))
            })?;
            if status == RunCompletionStatus::Cancelled {
                return Ok(true);
            }
        }
        return Err(error);
    }
    tracing::debug!("durable agent run reached a committed boundary");
    Ok(true)
}

fn execute_claimed_run(
    store: &Arc<Mutex<SqliteStore>>,
    fence: LeaseFence,
    provider: &Arc<BuiltinPhaseTwoProvider>,
    tool: &Arc<FixtureReadTool>,
    effect_runtime: Option<&PhaseThreeRuntime>,
    artifacts: &FileArtifactBlobStore,
    policy: AgentDriverPolicy,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    for _ in 0..MAXIMUM_LOOP_STEPS {
        let snapshot = {
            let guard = store.lock().map_err(|_| "agent store lock is poisoned")?;
            guard.load_agent_run(fence, SystemClock.now())?
        };
        if snapshot.cancellation_requested {
            let mut guard = store.lock().map_err(|_| "agent store lock is poisoned")?;
            complete_run(
                &mut *guard,
                &SystemClock,
                &SystemIdGenerator,
                fence,
                RunCompletionStatus::Cancelled,
                "cancelled at a durable agent-loop boundary".to_owned(),
            )?;
            return Ok(());
        }
        match snapshot.next_action {
            AgentNextAction::CompileContext | AgentNextAction::CompileAfterTool => {
                prepare_next_model(
                    store,
                    fence,
                    provider,
                    tool,
                    effect_runtime,
                    artifacts,
                    &snapshot,
                )?;
            }
            AgentNextAction::DispatchModel => {
                dispatch_model(store, fence, provider, &snapshot)?;
            }
            AgentNextAction::ConsumeModelResult => {
                if prepare_tool_call(store, fence, tool, effect_runtime, &snapshot)? {
                    return Ok(());
                }
            }
            AgentNextAction::DispatchReadTool => {
                dispatch_tool(
                    store,
                    fence,
                    tool,
                    artifacts,
                    &snapshot,
                    policy.maximum_resource_class_invocations,
                )?;
            }
            AgentNextAction::CommitFinal => {
                commit_final(store, artifacts, fence, &snapshot)?;
                return Ok(());
            }
            AgentNextAction::Terminal => return Ok(()),
        }
        if !policy.boundary_delay.is_zero() {
            std::thread::sleep(policy.boundary_delay);
        }
    }
    Err("agent loop exhausted its hard step guard".into())
}

#[allow(clippy::too_many_lines)]
fn prepare_next_model(
    store: &Arc<Mutex<SqliteStore>>,
    fence: LeaseFence,
    provider: &Arc<BuiltinPhaseTwoProvider>,
    tool: &Arc<FixtureReadTool>,
    effect_runtime: Option<&PhaseThreeRuntime>,
    artifacts: &FileArtifactBlobStore,
    snapshot: &mealy_application::AgentRunSnapshot,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let now = SystemClock.now();
    let now_ms = epoch_milliseconds(now)?;
    let write_mode = effect_runtime.is_some_and(|_| fixture_write_requested(snapshot));
    let new_epoch = snapshot.context_epoch.is_none();
    let epoch = snapshot.context_epoch.clone().unwrap_or_else(|| {
        let baseline = if write_mode {
            "You are Mealy's deterministic Phase 3 agent. Propose only the declared \
             fixture.write_file tool, wait for authenticated approval, and answer only from its \
             recorded effect observation."
                .to_owned()
        } else {
            "You are Mealy's deterministic Phase 2 agent. Use only the declared fixture.read \
             tool, then answer from its recorded observation."
                .to_owned()
        };
        ContextEpoch {
            epoch_id: SystemIdGenerator.generate_context_epoch_id(),
            session_id: snapshot.session_id,
            epoch_number: snapshot.next_context_epoch_number,
            baseline_version: if write_mode {
                "mealy.phase3.baseline.v1"
            } else {
                "mealy.phase2.baseline.v1"
            }
            .to_owned(),
            baseline_digest: sha256_digest(baseline.as_bytes()),
            baseline_text: baseline,
            agent_profile: serde_json::json!({
                "schemaVersion": "mealy.agent-profile.v1",
                "role": "assistant",
                "providerPolicy": if write_mode {
                    "fake.builtin.phase3"
                } else {
                    "fake.builtin.phase2"
                },
                "tools": if write_mode {
                    vec![mealy_application::FIXTURE_WRITE_FILE_TOOL_ID]
                } else {
                    vec!["fixture.read"]
                },
                "workspaceAccess": if write_mode { "approval_gated" } else { "none" },
                "memoryAccess": "governed_read_untrusted_evidence",
                "delegationPolicy": "disabled",
                "validationPolicy": "deterministic-evidence",
                "budgets": snapshot.limits,
            }),
            config_digest: sha256_digest(if write_mode {
                b"mealy.phase3.config.v1"
            } else {
                b"mealy.phase2.config.v1"
            }),
            policy_digest: sha256_digest(if write_mode {
                b"mealy.phase3.policy.v1"
            } else {
                b"mealy.phase2.policy.v1"
            }),
            workspace_identity: if write_mode {
                "fixture://phase3/workspace"
            } else {
                "fixture://phase2"
            }
            .to_owned(),
            created_at_ms: now_ms,
        }
    });
    let (provider_tool, schema_digest, compiler_version) = if write_mode {
        let descriptor = effect_runtime
            .ok_or("fixture write runtime became unavailable")?
            .descriptor();
        (
            ProviderToolDefinition {
                tool_id: descriptor.tool_id.clone(),
                version: descriptor.version.clone(),
                description: "Writes one bounded file inside an approval-gated sandbox workspace"
                    .to_owned(),
                input_schema: descriptor.input_schema.clone(),
                schema_digest: descriptor.input_schema_digest.clone(),
            },
            descriptor.input_schema_digest.clone(),
            "phase3.local.v1",
        )
    } else {
        let descriptor = tool.descriptor();
        (
            ProviderToolDefinition {
                tool_id: descriptor.tool_id.clone(),
                version: descriptor.version.clone(),
                description: "Reads one preconfigured logical fixture resource".to_owned(),
                input_schema: descriptor.input_schema.clone(),
                schema_digest: descriptor.schema_digest.clone(),
            },
            descriptor.schema_digest,
            "phase2.local.v1",
        )
    };
    let tool_schema_set_digest =
        sha256_digest(serde_json::to_string(&[schema_digest.as_str()])?.as_bytes());
    let configured_capabilities = provider.capabilities();
    let route = route_provider(
        &ProviderRoutingPolicy {
            required_input_modalities: BTreeSet::from(["text".to_owned()]),
            tool_calling: CapabilityRequirement::Required,
            structured_output: CapabilityRequirement::Required,
            required_reasoning_control: Some("none".to_owned()),
            allowed_residencies: BTreeSet::from([configured_capabilities.residency.clone()]),
            locality: ProviderLocality::LocalOnly,
            maximum_input_microunits_per_million_tokens: u64::MAX,
            maximum_output_microunits_per_million_tokens: u64::MAX,
            maximum_latency_ms: snapshot.limits.provider_timeout_ms,
            minimum_trust_tier: 10,
            preferred_provider_ids: vec![configured_capabilities.provider_id.clone()],
            fallback: ProviderFallbackPolicy::Disabled,
        },
        [ProviderRouteCandidate {
            capabilities: configured_capabilities,
            available: true,
            estimated_latency_ms: 1,
            trust_tier: 10,
        }],
    )?;
    let capabilities = route.primary.capabilities.clone();
    let routing_decision = serde_json::json!({
        "contractVersion": "mealy.provider.route.v1",
        "selected": {
            "providerId": capabilities.provider_id,
            "modelId": capabilities.model_id,
            "residency": capabilities.residency,
            "local": capabilities.local,
            "trustTier": route.primary.trust_tier,
        },
        "fallbackPolicy": "disabled",
        "fallbackProviderIds": route.fallbacks.iter().map(|candidate| {
            candidate.capabilities.provider_id.clone()
        }).collect::<Vec<_>>(),
        "explanation": route.explanation,
    });
    let token_budget = snapshot
        .limits
        .maximum_input_tokens
        .min(capabilities.context_tokens);
    let context_sources = hydrate_artifact_sources(store, artifacts, snapshot)?;
    let compiled = compile_context(
        &SystemIdGenerator,
        snapshot.run_id,
        snapshot.turn_id,
        &epoch,
        snapshot.next_iteration,
        &context_sources,
        token_budget,
        &capabilities.residency,
        &tool_schema_set_digest,
        compiler_version,
        now,
    )?;
    let attempt_id = SystemIdGenerator.generate_attempt_id();
    let deadline = bounded_deadline(now, snapshot.limits.provider_timeout_ms)?;
    let deadline_at_ms = epoch_milliseconds(deadline)?;
    let request = ProviderRequest {
        run_id: snapshot.run_id,
        attempt_id,
        context_manifest_id: compiled.manifest.manifest_id,
        provider_id: capabilities.provider_id.clone(),
        model_id: capabilities.model_id.clone(),
        messages: compiled.messages,
        tools: vec![provider_tool],
        maximum_output_tokens: PROVIDER_OUTPUT_TOKENS.min(capabilities.maximum_output_tokens),
        deadline_at_ms,
    };
    let capability_digest = sha256_digest(serde_json::to_string(&capabilities)?.as_bytes());
    let request_digest = sha256_digest(serde_json::to_string(&request)?.as_bytes());
    let commit = mealy_application::PrepareModelAttemptCommit {
        fence,
        context_epoch: new_epoch.then_some(epoch),
        manifest: compiled.manifest,
        attempt_id,
        request,
        capabilities,
        routing_decision,
        capability_digest,
        request_digest,
        reserved_cost_microunits: PROVIDER_COST_RESERVATION,
        reserved_output_bytes: PROVIDER_OUTPUT_BYTES_RESERVATION,
        limits: snapshot.limits,
        epoch_event_id: new_epoch.then(|| SystemIdGenerator.generate_event_id()),
        manifest_event_id: SystemIdGenerator.generate_event_id(),
        attempt_event_id: SystemIdGenerator.generate_event_id(),
        checkpoint_event_id: SystemIdGenerator.generate_event_id(),
        prepared_at: now,
        deadline_at: deadline,
    };
    store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .prepare_model_attempt(commit)?;
    Ok(())
}

fn hydrate_artifact_sources(
    store: &Arc<Mutex<SqliteStore>>,
    artifacts: &FileArtifactBlobStore,
    snapshot: &mealy_application::AgentRunSnapshot,
) -> Result<Vec<mealy_application::AgentContextSource>, Box<dyn Error + Send + Sync>> {
    let mut sources = snapshot.context_sources.clone();
    for source in &mut sources {
        let Some(artifact_id) = source.content_artifact_id else {
            continue;
        };
        let descriptor = store
            .lock()
            .map_err(|_| "agent store lock is poisoned")?
            .artifact_content_descriptor(
                OwnershipContext::new(snapshot.principal_id, snapshot.channel_binding_id),
                artifact_id,
            )?;
        if descriptor.metadata().size_bytes > snapshot.limits.maximum_artifact_bytes {
            return Err("recorded context artifact exceeds the effective run limit".into());
        }
        let content = String::from_utf8(artifacts.read(descriptor.committed_blob())?)?;
        source.message.content = format!("{}\n\n{content}", source.message.content);
    }
    Ok(sources)
}

fn dispatch_model(
    store: &Arc<Mutex<SqliteStore>>,
    fence: LeaseFence,
    provider: &Arc<BuiltinPhaseTwoProvider>,
    snapshot: &mealy_application::AgentRunSnapshot,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let attempt_id = snapshot
        .current_attempt_id
        .ok_or("dispatch_model has no current attempt")?;
    let trace_span = tracing::info_span!(
        "provider_attempt",
        task_id = %snapshot.task_id,
        run_id = %snapshot.run_id,
        attempt_id = %attempt_id,
        correlation_id = %snapshot.correlation_id,
        causation_id = %attempt_id,
    );
    let _entered = trace_span.enter();
    heartbeat(store, fence)?;
    {
        let mut guard = store.lock().map_err(|_| "agent store lock is poisoned")?;
        guard.dispatch_model_attempt(DispatchModelAttemptCommit {
            fence,
            attempt_id,
            event_id: SystemIdGenerator.generate_event_id(),
            dispatched_at: SystemClock.now(),
        })?;
    }
    let request = load_provider_request(store, attempt_id)?;
    let local_timeout = Arc::new(AtomicBool::new(false));
    let cancellation = DurableCancellationProbe {
        store: Arc::clone(store),
        run_id: fence.run_id(),
        local_timeout: Arc::clone(&local_timeout),
    };
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let provider = Arc::clone(provider);
    std::thread::Builder::new()
        .name("mealy-provider-attempt".to_owned())
        .spawn(move || {
            let _ = sender.send(provider.complete(&request, &cancellation));
        })?;
    let output =
        match receiver.recv_timeout(Duration::from_millis(snapshot.limits.provider_timeout_ms)) {
            Ok(output) => output?,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                local_timeout.store(true, Ordering::Release);
                return Err("provider attempt deadline elapsed".into());
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err("provider attempt worker disconnected".into());
            }
        };
    let response_json = serde_json::to_string(&output.response)?;
    let response_digest = sha256_digest(response_json.as_bytes());
    store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .record_model_result(RecordModelResultCommit {
            fence,
            attempt_id,
            output,
            response_json,
            response_digest,
            response_artifact: None,
            artifact_event_id: None,
            event_id: SystemIdGenerator.generate_event_id(),
            checkpoint_event_id: SystemIdGenerator.generate_event_id(),
            completed_at: SystemClock.now(),
        })?;
    Ok(())
}

fn prepare_tool_call(
    store: &Arc<Mutex<SqliteStore>>,
    fence: LeaseFence,
    tool: &Arc<FixtureReadTool>,
    effect_runtime: Option<&PhaseThreeRuntime>,
    snapshot: &mealy_application::AgentRunSnapshot,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let attempt_id = snapshot
        .current_attempt_id
        .ok_or("tool proposal has no current model attempt")?;
    let output = snapshot
        .current_model_output
        .as_ref()
        .ok_or("tool proposal has no committed model output")?;
    let ProviderResponse::ToolCall { tool_id, arguments } = &output.response else {
        return Err("consume_model_result did not contain a tool call".into());
    };
    if tool_id == mealy_application::FIXTURE_WRITE_FILE_TOOL_ID {
        let runtime = effect_runtime.ok_or("sandboxed fixture-write runtime is unavailable")?;
        return handle_fixture_write(store, fence, runtime, snapshot, attempt_id, arguments);
    }
    let descriptor = tool.descriptor();
    if tool_id != &descriptor.tool_id {
        return Err("model requested an undeclared read tool".into());
    }
    validate_fixture_read_arguments(arguments)?;
    let arguments_digest = sha256_digest(serde_json::to_string(arguments)?.as_bytes());
    store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .prepare_read_tool(mealy_application::PrepareReadToolCommit {
            fence,
            model_attempt_id: attempt_id,
            tool_attempt_id: SystemIdGenerator.generate_attempt_id(),
            tool_call_id: SystemIdGenerator.generate_tool_call_id(),
            descriptor,
            arguments: arguments.clone(),
            arguments_digest,
            event_id: SystemIdGenerator.generate_event_id(),
            prepared_at: SystemClock.now(),
        })?;
    Ok(false)
}

fn fixture_write_requested(snapshot: &mealy_application::AgentRunSnapshot) -> bool {
    snapshot.context_sources.iter().any(|source| {
        source.message.role == MessageRole::User
            && source
                .message
                .content
                .starts_with(mealy_application::FIXTURE_WRITE_INPUT_PREFIX)
    })
}

fn resume_ready_effect_runs(
    store: &Arc<Mutex<SqliteStore>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let now = SystemClock.now();
    let expired = store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .expired_agent_effect_approvals(now, 64)?;
    for approval_id in expired {
        let result = store
            .lock()
            .map_err(|_| "agent store lock is poisoned")?
            .expire_approval(ExpireApprovalCommit {
                approval_id,
                approval_event_id: SystemIdGenerator.generate_event_id(),
                effect_event_id: SystemIdGenerator.generate_event_id(),
                correlation_id: SystemIdGenerator.generate_correlation_id(),
                expired_at: now,
            });
        match result {
            Ok(_) | Err(EffectLedgerStoreError::NotFound | EffectLedgerStoreError::Conflict) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let candidates = store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .ready_agent_effects(now, 64)?;
    for effect_id in candidates {
        store
            .lock()
            .map_err(|_| "agent store lock is poisoned")?
            .resume_agent_effect_run(ResumeAgentEffectRunCommit {
                effect_id,
                run_event_id: SystemIdGenerator.generate_event_id(),
                task_event_id: SystemIdGenerator.generate_event_id(),
                correlation_id: SystemIdGenerator.generate_correlation_id(),
                resumed_at: now,
            })?;
    }
    Ok(())
}

fn handle_fixture_write(
    store: &Arc<Mutex<SqliteStore>>,
    fence: LeaseFence,
    runtime: &PhaseThreeRuntime,
    snapshot: &mealy_application::AgentRunSnapshot,
    model_attempt_id: mealy_domain::AttemptId,
    arguments: &serde_json::Value,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let invocation = store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .agent_effect_invocation(fence, model_attempt_id, SystemClock.now())?;
    if let Some(invocation) = invocation {
        return continue_fixture_write(store, fence, runtime, snapshot, invocation);
    }
    propose_fixture_write(store, fence, runtime, snapshot, model_attempt_id, arguments)?;
    Ok(true)
}

#[allow(clippy::too_many_lines)]
fn propose_fixture_write(
    store: &Arc<Mutex<SqliteStore>>,
    fence: LeaseFence,
    runtime: &PhaseThreeRuntime,
    snapshot: &mealy_application::AgentRunSnapshot,
    model_attempt_id: mealy_domain::AttemptId,
    arguments: &serde_json::Value,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let normalized_arguments = normalize_fixture_write_file_arguments(arguments)?;
    let relative_path = normalized_arguments
        .get("relativePath")
        .and_then(serde_json::Value::as_str)
        .ok_or("normalized fixture write path is absent")?;
    let now = SystemClock.now();
    let now_ms = epoch_milliseconds(now)?;
    let expires_at = now
        .checked_add(runtime.approval_ttl())
        .ok_or("fixture write approval expiry overflow")?;
    let expires_at_ms = epoch_milliseconds(expires_at)?;
    let target = format!("{}/{relative_path}", runtime.workspace_root());
    let request = PolicyRequest {
        principal_id: snapshot.principal_id,
        channel_binding_id: snapshot.channel_binding_id,
        task_id: snapshot.task_id,
        run_id: snapshot.run_id,
        agent_role: "assistant".to_owned(),
        task_risk: RiskClass::Medium,
        tool: runtime.descriptor().clone(),
        normalized_arguments,
        target_resources: vec![target.clone()],
        workspace_roots: vec![runtime.workspace_root().to_owned()],
        resource_claims: vec![format!("workspace-write:{target}")],
        secret_references: Vec::new(),
        network_destinations: Vec::new(),
        requested_capability: mealy_application::FIXTURE_WRITE_CAPABILITY.to_owned(),
        requested_profile: PolicyProfile::WorkspaceWrite,
        enforceable_profiles: vec![PolicyProfile::WorkspaceWrite],
        evaluated_at_ms: now_ms,
        policy_version: mealy_application::FIXTURE_POLICY_VERSION.to_owned(),
    };
    let grant = runtime.grant(
        snapshot.principal_id,
        snapshot.channel_binding_id,
        snapshot.task_id,
        snapshot.run_id,
        now_ms,
        expires_at_ms,
    );
    let evaluation = evaluate_fixture_write_policy(&request, &grant);
    if evaluation.decision != PolicyDecision::RequireApproval {
        return Err("fixture write policy did not produce the exact approval boundary".into());
    }
    let effect_id = SystemIdGenerator.generate_effect_id();
    let approval_id = SystemIdGenerator.generate_approval_id();
    let subject = fixture_write_approval_subject(effect_id, &request, expires_at_ms)?;
    let correlation_id = snapshot.correlation_id;
    store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .record_agent_effect_proposal(RecordAgentEffectProposalCommit {
            fence,
            model_attempt_id,
            tool_call_id: SystemIdGenerator.generate_tool_call_id(),
            proposal: RecordEffectProposalCommit {
                effect_id,
                ownership: OwnershipContext::new(
                    snapshot.principal_id,
                    snapshot.channel_binding_id,
                ),
                policy_request: request,
                policy_evaluation: evaluation,
                approval: Some(ApprovalRequestDraft {
                    approval_id,
                    subject,
                    requested_event_id: SystemIdGenerator.generate_event_id(),
                }),
                effect_event_id: SystemIdGenerator.generate_event_id(),
                correlation_id,
                proposed_at: now,
            },
            lease_event_id: SystemIdGenerator.generate_event_id(),
            run_event_id: SystemIdGenerator.generate_event_id(),
            task_event_id: SystemIdGenerator.generate_event_id(),
            checkpoint_event_id: SystemIdGenerator.generate_event_id(),
            parked_at: now,
        })?;
    Ok(())
}

fn continue_fixture_write(
    store: &Arc<Mutex<SqliteStore>>,
    fence: LeaseFence,
    runtime: &PhaseThreeRuntime,
    snapshot: &mealy_application::AgentRunSnapshot,
    invocation: mealy_application::AgentEffectInvocation,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let ownership = OwnershipContext::new(snapshot.principal_id, snapshot.channel_binding_id);
    let view = store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .effect_ledger_view(ownership, invocation.effect_id)?;
    match view.status {
        EffectStatus::Authorized => {
            dispatch_fixture_write(store, fence, runtime, snapshot, invocation, &view)
        }
        EffectStatus::Denied
        | EffectStatus::Succeeded
        | EffectStatus::Failed
        | EffectStatus::Compensated => {
            record_fixture_write_observation(store, fence, invocation)?;
            Ok(false)
        }
        EffectStatus::OutcomeUnknown => {
            park_unknown_fixture_write(
                store,
                fence,
                invocation.effect_id,
                snapshot.correlation_id,
            )?;
            Ok(true)
        }
        EffectStatus::Proposed | EffectStatus::AwaitingApproval | EffectStatus::Dispatching => {
            Err("agent effect was scheduled before its durable lifecycle became ready".into())
        }
    }
}

#[allow(clippy::too_many_lines)]
fn dispatch_fixture_write(
    store: &Arc<Mutex<SqliteStore>>,
    fence: LeaseFence,
    runtime: &PhaseThreeRuntime,
    snapshot: &mealy_application::AgentRunSnapshot,
    invocation: mealy_application::AgentEffectInvocation,
    view: &mealy_application::EffectLedgerView,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    heartbeat(store, fence)?;
    let attempt_id = SystemIdGenerator.generate_attempt_id();
    let prepared_at = SystemClock.now();
    store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .prepare_effect_attempt(PrepareEffectAttemptCommit {
            effect_id: invocation.effect_id,
            attempt_id,
            expected_effect_revision: view.revision,
            fence,
            event_id: SystemIdGenerator.generate_event_id(),
            correlation_id: snapshot.correlation_id,
            prepared_at,
        })?;
    let ownership = OwnershipContext::new(snapshot.principal_id, snapshot.channel_binding_id);
    let prepared_view = store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .effect_ledger_view(ownership, invocation.effect_id)?;
    let approval = prepared_view
        .approval
        .as_ref()
        .ok_or("authorized fixture write has no bound approval")?;
    let grant = runtime.grant(
        snapshot.principal_id,
        snapshot.channel_binding_id,
        snapshot.task_id,
        snapshot.run_id,
        prepared_view.policy_request.evaluated_at_ms,
        approval.subject.expires_at_ms,
    );
    let dispatched_at = SystemClock.now();
    let dispatched_at_ms = epoch_milliseconds(dispatched_at)?;
    let capability_token = format!(
        "mealy-fixture-capability:{}:{attempt_id}",
        invocation.effect_id
    );
    let request = build_fixture_write_executor_request(FixtureWriteDispatch {
        policy_request: &prepared_view.policy_request,
        policy_evaluation: &prepared_view.policy_evaluation,
        grant: &grant,
        approval,
        effect_id: invocation.effect_id,
        attempt_id,
        fencing_token: fence.fencing_token(),
        capability_token: &capability_token,
        dispatched_at_ms,
    })?;
    if !runtime.dispatch_commit_delay().is_zero() {
        std::thread::sleep(runtime.dispatch_commit_delay());
    }
    store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .mark_effect_attempt_running(MarkEffectAttemptRunningCommit {
            effect_id: invocation.effect_id,
            attempt_id,
            expected_effect_revision: prepared_view.revision,
            fence,
            event_id: SystemIdGenerator.generate_event_id(),
            correlation_id: snapshot.correlation_id,
            dispatched_at,
        })?;
    let running_revision = store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .effect_ledger_view(ownership, invocation.effect_id)?
        .revision;
    let request_evidence_digest = request.evidence_digest()?;
    let cancellation = DurableCancellationProbe {
        store: Arc::clone(store),
        run_id: fence.run_id(),
        local_timeout: Arc::new(AtomicBool::new(false)),
    };
    let result = runtime.executor().execute(&request, &cancellation);
    if !runtime.outcome_commit_delay().is_zero() {
        std::thread::sleep(runtime.outcome_commit_delay());
    }
    let completed_at = SystemClock.now();
    let (outcome, evidence_details, error_class) =
        executor_outcome_evidence(result, &request_evidence_digest);
    store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .record_effect_attempt_outcome(RecordEffectAttemptOutcomeCommit {
            effect_id: invocation.effect_id,
            attempt_id,
            expected_effect_revision: running_revision,
            fence,
            outcome,
            evidence_details,
            error_class,
            event_id: SystemIdGenerator.generate_event_id(),
            correlation_id: snapshot.correlation_id,
            completed_at,
        })?;
    if !runtime.observation_commit_delay().is_zero() {
        std::thread::sleep(runtime.observation_commit_delay());
    }
    if outcome == EffectAttemptOutcome::OutcomeUnknown {
        park_unknown_fixture_write(store, fence, invocation.effect_id, snapshot.correlation_id)?;
        return Ok(true);
    }
    record_fixture_write_observation(store, fence, invocation)?;
    Ok(false)
}

fn executor_outcome_evidence(
    result: Result<mealy_application::ExecutorResult, ExecutorError>,
    request_evidence_digest: &str,
) -> (EffectAttemptOutcome, serde_json::Value, Option<String>) {
    match result {
        Ok(result) => {
            let terminal = result.terminal.clone();
            let evidence = serde_json::json!({
                "durationMs": result.duration_ms,
                "frames": result.frames,
                "requestEvidenceDigest": request_evidence_digest,
                "terminal": terminal,
            });
            match terminal {
                ExecutorTerminal::Succeeded { .. } => {
                    (EffectAttemptOutcome::Succeeded, evidence, None)
                }
                ExecutorTerminal::Failed { error_class, .. } => {
                    (EffectAttemptOutcome::Failed, evidence, Some(error_class))
                }
            }
        }
        Err(error) => (
            EffectAttemptOutcome::OutcomeUnknown,
            serde_json::json!({
                "classification": "sandbox_result_unproven_after_dispatch",
                "executorError": error.to_string(),
                "requestEvidenceDigest": request_evidence_digest,
            }),
            Some("sandbox_dispatch_outcome_unknown".to_owned()),
        ),
    }
}

fn record_fixture_write_observation(
    store: &Arc<Mutex<SqliteStore>>,
    fence: LeaseFence,
    invocation: mealy_application::AgentEffectInvocation,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .record_agent_effect_observation(RecordAgentEffectObservationCommit {
            fence,
            effect_id: invocation.effect_id,
            model_attempt_id: invocation.model_attempt_id,
            tool_call_id: invocation.tool_call_id,
            message_id: SystemIdGenerator.generate_message_id(),
            event_id: SystemIdGenerator.generate_event_id(),
            checkpoint_event_id: SystemIdGenerator.generate_event_id(),
            observed_at: SystemClock.now(),
        })?;
    Ok(())
}

fn park_unknown_fixture_write(
    store: &Arc<Mutex<SqliteStore>>,
    fence: LeaseFence,
    effect_id: mealy_domain::EffectId,
    correlation_id: mealy_domain::CorrelationId,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .park_agent_effect_run(ParkAgentEffectRunCommit {
            fence,
            effect_id,
            lease_event_id: SystemIdGenerator.generate_event_id(),
            run_event_id: SystemIdGenerator.generate_event_id(),
            task_event_id: SystemIdGenerator.generate_event_id(),
            correlation_id,
            parked_at: SystemClock.now(),
        })?;
    Ok(())
}

fn dispatch_tool(
    store: &Arc<Mutex<SqliteStore>>,
    fence: LeaseFence,
    tool: &Arc<FixtureReadTool>,
    artifacts: &FileArtifactBlobStore,
    snapshot: &mealy_application::AgentRunSnapshot,
    maximum_resource_class_invocations: u32,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let tool_call_id = snapshot
        .current_tool_call_id
        .ok_or("dispatch_read_tool has no current tool call")?;
    let trace_span = tracing::info_span!(
        "tool_attempt",
        task_id = %snapshot.task_id,
        run_id = %snapshot.run_id,
        tool_call_id = %tool_call_id,
        correlation_id = %snapshot.correlation_id,
        causation_id = %tool_call_id,
    );
    let _entered = trace_span.enter();
    let arguments = snapshot
        .current_tool_arguments
        .as_ref()
        .ok_or("dispatch_read_tool has no committed arguments")?;
    heartbeat(store, fence)?;
    {
        let mut guard = store.lock().map_err(|_| "agent store lock is poisoned")?;
        guard.dispatch_read_tool(DispatchReadToolCommit {
            fence,
            tool_call_id,
            event_id: SystemIdGenerator.generate_event_id(),
            started_at: SystemClock.now(),
        })?;
    }
    let local_timeout = Arc::new(AtomicBool::new(false));
    let cancellation = DurableCancellationProbe {
        store: Arc::clone(store),
        run_id: fence.run_id(),
        local_timeout: Arc::clone(&local_timeout),
    };
    let timeout = tool
        .descriptor()
        .timeout
        .min(Duration::from_millis(snapshot.limits.tool_timeout_ms));
    let arguments = arguments.clone();
    let tool = Arc::clone(tool);
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let Some(tool_in_flight) = InFlightGuard::acquire(
        &TOOL_IN_FLIGHT,
        u64::from(maximum_resource_class_invocations),
    ) else {
        return Err("a previous read-tool dispatch is still stopping".into());
    };
    let spawn = std::thread::Builder::new()
        .name("mealy-read-tool-attempt".to_owned())
        .spawn(move || {
            let _tool_in_flight = tool_in_flight;
            let _ = sender.send(tool.execute(&arguments, &cancellation));
        });
    if let Err(error) = spawn {
        return Err(error.into());
    }
    let output = match receiver.recv_timeout(timeout) {
        Ok(output) => output?,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            local_timeout.store(true, Ordering::Release);
            return Err("read-tool deadline elapsed".into());
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            return Err("read-tool worker disconnected".into());
        }
    };
    record_tool_output(store, fence, tool_call_id, artifacts, snapshot, output)
}

fn record_tool_output(
    store: &Arc<Mutex<SqliteStore>>,
    fence: LeaseFence,
    tool_call_id: mealy_domain::ToolCallId,
    artifacts: &FileArtifactBlobStore,
    snapshot: &mealy_application::AgentRunSnapshot,
    output: ReadToolOutput,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let digest = sha256_digest(&output.bytes);
    let size = u64::try_from(output.bytes.len())?;
    if size > snapshot.limits.maximum_artifact_bytes || size > snapshot.limits.maximum_output_bytes
    {
        return Err("read-tool output exceeds the effective artifact/run bound".into());
    }
    let oversized = size > snapshot.limits.inline_output_bytes;
    let now = SystemClock.now();
    let artifact = if oversized {
        let blob = artifacts.commit(&output.bytes)?;
        Some(AgentArtifactCommit {
            artifact_id: SystemIdGenerator.generate_artifact_id(),
            algorithm: blob.algorithm,
            digest: blob.digest,
            size_bytes: blob.size_bytes,
            relative_path: blob.relative_path,
            committed_at: now,
            media_type: output.media_type.clone(),
            sensitivity: "internal".to_owned(),
        })
    } else {
        None
    };
    let inline = if oversized {
        None
    } else {
        Some(String::from_utf8(output.bytes)?)
    };
    let artifact_event_id = artifact
        .as_ref()
        .map(|_| SystemIdGenerator.generate_event_id());
    store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .record_read_tool_result(RecordReadToolResultCommit {
            fence,
            tool_call_id,
            output_inline: inline,
            output_artifact: artifact,
            artifact_event_id,
            output_digest: digest,
            output_size_bytes: size,
            output_media_type: output.media_type,
            source_locator: output.source_locator,
            event_id: SystemIdGenerator.generate_event_id(),
            checkpoint_event_id: SystemIdGenerator.generate_event_id(),
            completed_at: now,
        })?;
    Ok(())
}

fn commit_final(
    store: &Arc<Mutex<SqliteStore>>,
    artifacts: &FileArtifactBlobStore,
    fence: LeaseFence,
    snapshot: &mealy_application::AgentRunSnapshot,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let attempt_id = snapshot
        .current_attempt_id
        .ok_or("commit_final has no current attempt")?;
    let output = snapshot
        .current_model_output
        .as_ref()
        .ok_or("commit_final has no committed model output")?;
    let ProviderResponse::Final { text } = &output.response else {
        return Err("commit_final did not contain a final response".into());
    };
    ensure_task_validation(store, artifacts, fence, snapshot, text)?;
    let message = FinalMessageCommit {
        message_id: SystemIdGenerator.generate_message_id(),
        event_id: SystemIdGenerator.generate_event_id(),
        source_attempt_id: attempt_id,
        content: text.clone(),
        content_digest: sha256_digest(text.as_bytes()),
        byte_length: u64::try_from(text.len())?,
    };
    complete_agent_run(
        &mut *store.lock().map_err(|_| "agent store lock is poisoned")?,
        &SystemClock,
        &SystemIdGenerator,
        fence,
        message,
    )?;
    Ok(())
}

struct FreshValidatorDecision {
    outcome: ValidationOutcome,
    rubric: serde_json::Value,
    evidence: serde_json::Value,
}

fn ensure_task_validation(
    store: &Arc<Mutex<SqliteStore>>,
    artifacts: &FileArtifactBlobStore,
    fence: LeaseFence,
    snapshot: &mealy_application::AgentRunSnapshot,
    final_text: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let ownership = OwnershipContext::new(snapshot.principal_id, snapshot.channel_binding_id);
    let criteria = store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .task_success_criteria(ownership, snapshot.task_id)?;
    if let Some(existing) = store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .task_validation(ownership, snapshot.task_id)?
    {
        if existing.producer_run_id == snapshot.run_id
            && matches!(
                existing.outcome,
                ValidationOutcome::Passed | ValidationOutcome::Waived
            )
        {
            return Ok(());
        }
        return Err("the existing independent validation does not permit task success".into());
    }

    let independent = criteria.criteria.independent_validation_required();
    let (context, decision) = if independent {
        let context = build_fresh_fixture_validation_context(
            store,
            snapshot,
            &criteria.criteria,
            final_text,
        )?;
        let decision = run_fresh_fixture_validator(&context);
        (context, decision)
    } else {
        let context = build_deterministic_read_validation_context(
            store,
            artifacts,
            snapshot,
            &criteria.criteria,
            final_text,
        )?;
        let decision = run_deterministic_read_validator(&context);
        (context, decision)
    };
    let outcome = decision.outcome;
    store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .record_validation(RecordValidationCommit {
            producer_fence: fence,
            task_id: snapshot.task_id,
            validation_id: SystemIdGenerator.generate_validation_id(),
            validator_task_id: independent.then(|| SystemIdGenerator.generate_task_id()),
            validator_run_id: independent.then(|| SystemIdGenerator.generate_run_id()),
            context,
            method: if independent {
                ValidationMethod::FreshContextModel
            } else {
                ValidationMethod::Deterministic
            },
            outcome,
            rubric: decision.rubric,
            evidence: decision.evidence,
            responsible_principal_id: snapshot.principal_id,
            policy_version: VALIDATION_POLICY_VERSION.to_owned(),
            event_id: SystemIdGenerator.generate_event_id(),
            correlation_id: snapshot.correlation_id,
            recorded_at: SystemClock.now(),
        })?;
    if outcome != ValidationOutcome::Passed {
        return Err("validation did not establish the task success criteria".into());
    }
    Ok(())
}

fn build_deterministic_read_validation_context(
    store: &Arc<Mutex<SqliteStore>>,
    artifacts: &FileArtifactBlobStore,
    snapshot: &mealy_application::AgentRunSnapshot,
    criteria: &mealy_domain::TaskSuccessCriteria,
    final_text: &str,
) -> Result<ValidationContextDraft, Box<dyn Error + Send + Sync>> {
    let sources = hydrate_artifact_sources(store, artifacts, snapshot)?;
    let request_source = sources
        .iter()
        .find(|source| source.message.role == MessageRole::User)
        .ok_or("deterministic validation has no selected request")?;
    let observation_source = sources
        .iter()
        .rev()
        .find(|source| source.message.role == MessageRole::Tool)
        .ok_or("deterministic validation has no recorded read-tool observation")?;
    let request_content = request_source.message.content.clone();
    let observation_content = observation_source.message.content.clone();
    Ok(ValidationContextDraft {
        manifest_id: SystemIdGenerator.generate_context_manifest_id(),
        request: serde_json::json!({
            "content": request_content,
            "contentDigest": sha256_digest(request_content.as_bytes()),
            "runId": snapshot.run_id,
            "sourceLocator": request_source.source_locator,
            "taskId": snapshot.task_id,
        }),
        criteria: serde_json::to_value(criteria)?,
        outputs: serde_json::json!({
            "contentDigest": sha256_digest(final_text.as_bytes()),
            "finalResponse": final_text,
        }),
        evidence: serde_json::json!({
            "artifactId": observation_source.content_artifact_id,
            "contractVersion": "mealy.fixture-read-validation-evidence.v1",
            "observationContent": observation_content,
            "observationContentDigest": sha256_digest(observation_content.as_bytes()),
            "producerHiddenContextIncluded": false,
            "recordedSourceContentDigest": observation_source.source_content_digest,
            "sourceLocator": observation_source.source_locator,
            "toolCallId": observation_source.message.tool_call_id,
        }),
        capabilities: CapabilityGrant {
            tools: BTreeSet::from(["fixture.read".to_owned()]),
            effect_classes: BTreeSet::from([EffectClass::ReadOnly]),
            profiles: BTreeSet::from([PolicyProfile::Observe]),
            maximum_delegated_runs: 0,
            ..CapabilityGrant::default()
        },
    })
}

fn run_deterministic_read_validator(context: &ValidationContextDraft) -> FreshValidatorDecision {
    let request = context.request["content"].as_str();
    let observation = context.evidence["observationContent"].as_str();
    let observation_digest = observation.map(|content| sha256_digest(content.as_bytes()));
    let raw_observation =
        observation.map(|content| content.split_once("\n\n").map_or(content, |(_, raw)| raw));
    let source_digest = raw_observation.map(|content| sha256_digest(content.as_bytes()));
    let output = context.outputs["finalResponse"].as_str();
    let criteria_ids = context.criteria["criteria"].as_array();
    let criteria_contract = ["tool_evidence", "response_grounding"]
        .iter()
        .all(|expected| {
            criteria_ids.is_some_and(|criteria| {
                criteria
                    .iter()
                    .any(|criterion| criterion["criterionId"].as_str() == Some(expected))
            })
        });
    let read_only_authority = context.capabilities.network_destinations.is_empty()
        && context.capabilities.secret_references.is_empty()
        && context.capabilities.effect_classes == BTreeSet::from([EffectClass::ReadOnly])
        && context.capabilities.profiles == BTreeSet::from([PolicyProfile::Observe]);
    let observation_integrity = observation_digest.as_deref()
        == context.evidence["observationContentDigest"].as_str()
        && source_digest.as_deref() == context.evidence["recordedSourceContentDigest"].as_str();
    let request_integrity = request.is_some_and(|content| {
        context.request["contentDigest"].as_str()
            == Some(sha256_digest(content.as_bytes()).as_str())
    });
    let response_grounding = output.is_some_and(|output| {
        observation_digest
            .as_deref()
            .is_some_and(|digest| output.contains(&format!("rendered sha256:{digest}")))
    });
    let tool_evidence = raw_observation.is_some_and(|content| {
        content
            .lines()
            .filter(|line| line.starts_with("Phase 2 fixture row "))
            .count()
            == 256
    }) && context.evidence["toolCallId"].is_string();
    let findings = serde_json::json!({
        "criteriaContract": criteria_contract,
        "freshReadOnlyAuthority": read_only_authority,
        "observationIntegrity": observation_integrity,
        "requestIntegrity": request_integrity,
        "responseGrounding": response_grounding,
        "toolEvidence": tool_evidence,
    });
    let passed = findings
        .as_object()
        .is_some_and(|values| values.values().all(|value| value.as_bool() == Some(true)));
    FreshValidatorDecision {
        outcome: if passed {
            ValidationOutcome::Passed
        } else {
            ValidationOutcome::NeedsRevision
        },
        rubric: serde_json::json!({
            "contractVersion": "mealy.fixture-read-validation-rubric.v1",
            "decisionRule": "all deterministic checks must pass",
            "requiredCriteria": ["tool_evidence", "response_grounding"],
        }),
        evidence: serde_json::json!({
            "contractVersion": "mealy.fixture-read-validation-result.v1",
            "findings": findings,
            "producerHiddenContextUsed": false,
        }),
    }
}

#[allow(clippy::too_many_lines)]
fn build_fresh_fixture_validation_context(
    store: &Arc<Mutex<SqliteStore>>,
    snapshot: &mealy_application::AgentRunSnapshot,
    criteria: &mealy_domain::TaskSuccessCriteria,
    final_text: &str,
) -> Result<ValidationContextDraft, Box<dyn Error + Send + Sync>> {
    let request_source = snapshot
        .context_sources
        .iter()
        .find(|source| {
            source.message.role == MessageRole::User
                && source
                    .message
                    .content
                    .starts_with(mealy_application::FIXTURE_WRITE_INPUT_PREFIX)
        })
        .ok_or("fresh validation has no selected fixture-write request")?;
    let observation_source = snapshot
        .context_sources
        .iter()
        .rev()
        .find(|source| {
            source.message.role == MessageRole::Tool
                && serde_json::from_str::<serde_json::Value>(&source.message.content)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("contractVersion")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                    })
                    .as_deref()
                    == Some(mealy_application::AGENT_EFFECT_OBSERVATION_CONTRACT_VERSION)
        })
        .ok_or("fresh validation has no recorded governed-effect observation")?;
    let observation: serde_json::Value = serde_json::from_str(&observation_source.message.content)?;
    let effect_id: mealy_domain::EffectId = observation
        .get("effectId")
        .and_then(serde_json::Value::as_str)
        .ok_or("effect observation has no effect identity")?
        .parse()?;
    let ownership = OwnershipContext::new(snapshot.principal_id, snapshot.channel_binding_id);
    let (effect, attempts) = {
        let guard = store.lock().map_err(|_| "agent store lock is poisoned")?;
        (
            guard.effect_ledger_view(ownership, effect_id)?,
            guard.effect_attempt_views(ownership, effect_id)?,
        )
    };
    if effect.task_id != snapshot.task_id || effect.run_id != snapshot.run_id {
        return Err("validation effect is outside the producer task/run".into());
    }
    let approval = effect
        .approval
        .as_ref()
        .map(|approval| {
            Ok::<_, Box<dyn Error + Send + Sync>>(serde_json::json!({
                "approvalId": approval.approval_id,
                "decision": approval.decision,
                "effectId": approval.effect_id,
                "requestedAtMs": epoch_milliseconds(approval.requested_at)?,
                "resolvedAtMs": approval.resolved_at.map(epoch_milliseconds).transpose()?,
                "status": approval.status,
                "subject": &approval.subject,
                "subjectDigest": approval.subject_digest,
            }))
        })
        .transpose()?;
    let mut attempt_evidence = Vec::with_capacity(attempts.len());
    for attempt in attempts {
        let mut outcomes = Vec::with_capacity(attempt.outcomes.len());
        for outcome in attempt.outcomes {
            outcomes.push(serde_json::json!({
                "evidence": outcome.evidence,
                "evidenceDigest": outcome.evidence_digest,
                "eventId": outcome.event_id,
                "kind": outcome.kind,
                "recordedAtMs": epoch_milliseconds(outcome.recorded_at)?,
                "sequence": outcome.sequence,
            }));
        }
        attempt_evidence.push(serde_json::json!({
            "attemptId": attempt.attempt_id,
            "completedAtMs": attempt.completed_at.map(epoch_milliseconds).transpose()?,
            "effectId": attempt.effect_id,
            "errorClass": attempt.error_class,
            "fencingToken": attempt.fence.fencing_token(),
            "idempotencyKey": attempt.idempotency_key,
            "ordinal": attempt.ordinal,
            "outcomes": outcomes,
            "preparedAtMs": epoch_milliseconds(attempt.prepared_at)?,
            "startedAtMs": attempt.started_at.map(epoch_milliseconds).transpose()?,
            "state": attempt.state,
        }));
    }
    let request_content = request_source.message.content.clone();
    let observation_content = observation_source.message.content.clone();
    Ok(ValidationContextDraft {
        manifest_id: SystemIdGenerator.generate_context_manifest_id(),
        request: serde_json::json!({
            "content": request_content,
            "contentDigest": sha256_digest(request_content.as_bytes()),
            "runId": snapshot.run_id,
            "sourceLocator": request_source.source_locator,
            "taskId": snapshot.task_id,
        }),
        criteria: serde_json::to_value(criteria)?,
        outputs: serde_json::json!({
            "contentDigest": sha256_digest(final_text.as_bytes()),
            "finalResponse": final_text,
        }),
        evidence: serde_json::json!({
            "contractVersion": "mealy.fixture-validation-evidence.v1",
            "effect": {
                "approval": approval,
                "attempts": attempt_evidence,
                "effectId": effect.effect_id,
                "idempotencyKey": effect.idempotency_key,
                "policyEvaluation": effect.policy_evaluation,
                "policyRequest": effect.policy_request,
                "revision": effect.revision,
                "runId": effect.run_id,
                "status": effect.status,
                "taskId": effect.task_id,
            },
            "observation": observation,
            "observationContent": observation_content,
            "observationContentDigest": sha256_digest(observation_content.as_bytes()),
            "producerHiddenContextIncluded": false,
        }),
        capabilities: CapabilityGrant {
            effect_classes: BTreeSet::from([EffectClass::ReadOnly]),
            profiles: BTreeSet::from([PolicyProfile::Observe]),
            maximum_delegated_runs: 0,
            ..CapabilityGrant::default()
        },
    })
}

#[allow(clippy::too_many_lines)]
fn run_fresh_fixture_validator(context: &ValidationContextDraft) -> FreshValidatorDecision {
    let request_content = context
        .request
        .get("content")
        .and_then(serde_json::Value::as_str);
    let request_arguments = request_content
        .and_then(|content| content.strip_prefix(mealy_application::FIXTURE_WRITE_INPUT_PREFIX))
        .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok());
    let output = context
        .outputs
        .get("finalResponse")
        .and_then(serde_json::Value::as_str);
    let effect = &context.evidence["effect"];
    let observation = &context.evidence["observation"];
    let observation_content = context.evidence["observationContent"].as_str();
    let status = observation
        .get("status")
        .and_then(serde_json::Value::as_str);
    let observation_digest = observation_content.map(|content| sha256_digest(content.as_bytes()));
    let observation_integrity = observation_content
        .and_then(|content| serde_json::from_str::<serde_json::Value>(content).ok())
        .as_ref()
        == Some(observation)
        && observation_digest.as_deref() == context.evidence["observationContentDigest"].as_str()
        && observation["contractVersion"].as_str()
            == Some(mealy_application::AGENT_EFFECT_OBSERVATION_CONTRACT_VERSION)
        && observation["effectId"] == effect["effectId"]
        && observation["status"] == effect["status"];
    let policy_arguments = &effect["policyRequest"]["normalizedArguments"];
    let request_binding = request_arguments
        .as_ref()
        .is_some_and(|arguments| arguments == policy_arguments)
        && context.request["contentDigest"].as_str()
            == request_content
                .map(|content| sha256_digest(content.as_bytes()))
                .as_deref()
        && context.request["taskId"] == effect["taskId"]
        && context.request["runId"] == effect["runId"]
        && effect["policyRequest"]["tool"]["toolId"].as_str()
            == Some(mealy_application::FIXTURE_WRITE_FILE_TOOL_ID)
        && effect["policyEvaluation"]["decision"].as_str() == Some("require_approval");
    let approval_status = effect["approval"]["status"].as_str();
    let approval_binding = effect["approval"]["effectId"] == effect["effectId"]
        && effect["approval"]["subject"]["effectId"] == effect["effectId"]
        && effect["approval"]["subject"]["canonicalArgumentsDigest"].as_str()
            == Some(canonical_arguments_digest(policy_arguments).as_str())
        && match status {
            Some("denied") => matches!(approval_status, Some("denied" | "expired" | "revoked")),
            Some("succeeded" | "failed" | "compensated") => approval_status == Some("approved"),
            _ => false,
        };
    let attempts = effect["attempts"].as_array();
    let crossed_attempts = attempts.map_or(usize::MAX, |attempts| {
        attempts
            .iter()
            .filter(|attempt| !attempt["startedAtMs"].is_null())
            .count()
    });
    let outcome_consistency = match (status, attempts) {
        (Some("denied"), Some(attempts)) => attempts.is_empty() && observation["outcome"].is_null(),
        (Some(expected @ ("succeeded" | "failed" | "compensated")), Some(attempts)) => {
            let observation_attempt = observation["outcome"]["attemptId"].as_str();
            attempts.iter().any(|attempt| {
                attempt["attemptId"].as_str() == observation_attempt
                    && attempt["outcomes"]
                        .as_array()
                        .and_then(|outcomes| outcomes.last())
                        .is_some_and(|outcome| outcome["kind"].as_str() == Some(expected))
            })
        }
        _ => false,
    };
    let outcome_digests = attempts.is_some_and(|attempts| {
        attempts.iter().all(|attempt| {
            attempt["outcomes"].as_array().is_some_and(|outcomes| {
                outcomes.iter().all(|outcome| {
                    outcome["evidenceDigest"].as_str().is_some_and(|digest| {
                        digest == sha256_digest(outcome["evidence"].to_string().as_bytes())
                    })
                })
            })
        })
    });
    let response_grounding = status.is_some_and(|status| {
        output.is_some_and(|output| {
            output.contains(&format!("effect state {status}"))
                && observation_digest
                    .as_deref()
                    .is_some_and(|digest| output.contains(&format!("sha256:{digest}")))
        })
    });
    let criteria_ids = context.criteria["criteria"].as_array();
    let criteria_contract = ["authorization", "effect_outcome", "response_grounding"]
        .iter()
        .all(|expected| {
            criteria_ids.is_some_and(|criteria| {
                criteria
                    .iter()
                    .any(|criterion| criterion["criterionId"].as_str() == Some(expected))
            })
        });
    let fresh_authority = context.capabilities.network_destinations.is_empty()
        && context.capabilities.secret_references.is_empty()
        && context
            .capabilities
            .effect_classes
            .iter()
            .all(|class| *class == EffectClass::ReadOnly)
        && context
            .capabilities
            .profiles
            .iter()
            .all(|profile| *profile == PolicyProfile::Observe)
        && context.evidence["producerHiddenContextIncluded"].as_bool() == Some(false);
    let findings = serde_json::json!({
        "approvalBinding": approval_binding,
        "atMostOneDispatch": crossed_attempts <= 1,
        "criteriaContract": criteria_contract,
        "freshReadOnlyAuthority": fresh_authority,
        "observationIntegrity": observation_integrity,
        "outcomeConsistency": outcome_consistency,
        "outcomeEvidenceDigests": outcome_digests,
        "requestBinding": request_binding,
        "responseGrounding": response_grounding,
    });
    let passed = findings
        .as_object()
        .is_some_and(|values| values.values().all(|value| value.as_bool() == Some(true)));
    FreshValidatorDecision {
        outcome: if passed {
            ValidationOutcome::Passed
        } else {
            ValidationOutcome::NeedsRevision
        },
        rubric: serde_json::json!({
            "contractVersion": "mealy.fixture-validation-rubric.v1",
            "decisionRule": "all independent findings must be true",
            "requiredCriteria": ["authorization", "effect_outcome", "response_grounding"],
        }),
        evidence: serde_json::json!({
            "contractVersion": "mealy.fixture-validation-result.v1",
            "findings": findings,
            "producerHiddenContextUsed": false,
        }),
    }
}

fn heartbeat(
    store: &Arc<Mutex<SqliteStore>>,
    fence: LeaseFence,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    heartbeat_lease(
        &mut *store.lock().map_err(|_| "agent store lock is poisoned")?,
        &SystemClock,
        fence,
        LEASE_TTL,
        LeaseLimits::default(),
    )?;
    Ok(())
}

fn load_provider_request(
    store: &Arc<Mutex<SqliteStore>>,
    attempt_id: mealy_domain::AttemptId,
) -> Result<ProviderRequest, Box<dyn Error + Send + Sync>> {
    // The request is already stored before dispatch. Reload through a narrow infrastructure query
    // so the actual provider call cannot drift from recorded evidence.
    let request_json = store
        .lock()
        .map_err(|_| "agent store lock is poisoned")?
        .prepared_provider_request(attempt_id)?;
    Ok(serde_json::from_str(&request_json)?)
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, Box<dyn Error + Send + Sync>> {
    Ok(i64::try_from(
        time.duration_since(SystemTime::UNIX_EPOCH)?.as_millis(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::BuiltinPhaseTwoProvider;
    use mealy_application::ModelProvider;
    use std::time::Duration;

    #[test]
    fn builtin_provider_is_local_and_tool_capable() {
        let capabilities = BuiltinPhaseTwoProvider::default().capabilities();
        assert!(capabilities.local);
        assert!(capabilities.tool_calling);
        assert_eq!(capabilities.provider_id, "fake.builtin.phase2");
    }

    #[test]
    fn builtin_provider_enforces_its_declared_rate_capacity() {
        let provider = BuiltinPhaseTwoProvider::new(Duration::ZERO, 1, 2);
        assert!(provider.reserve_rate_capacity());
        assert!(provider.reserve_rate_capacity());
        assert!(!provider.reserve_rate_capacity());
        assert_eq!(provider.capabilities().requests_per_minute, 2);
    }
}
